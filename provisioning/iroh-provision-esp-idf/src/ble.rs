use std::sync::{mpsc, Arc};
use std::time::Duration;

use esp32_nimble::utilities::mutex::Mutex;
use esp32_nimble::utilities::BleUuid;
use esp32_nimble::{BLEAdvertisementData, BLECharacteristic, BLEDevice, NimbleProperties};
use iroh_provision::device::Transport;
use iroh_provision::{
    device_name, PublicKey, Status, CREDENTIALS_UUID, IDENTITY_UUID, SERVICE_UUID, STATUS_UUID,
};
use log::{info, warn};

use crate::Error;

/// How long BLE stays up after success, so the client sees the final status.
const LINGER: Duration = Duration::from_secs(3);

fn uuid(s: &str) -> BleUuid {
    BleUuid::from_uuid128_string(s).expect("valid UUID")
}

/// The provisioning GATT service, advertised as `iroh-<short endpoint id>`.
pub struct BleTransport {
    messages: mpsc::Receiver<Vec<u8>>,
    status: Arc<Mutex<BLECharacteristic>>,
}

impl BleTransport {
    /// Set up the GATT service and start advertising.
    pub fn start(identity: &PublicKey) -> Result<Self, Error> {
        let name = device_name(identity);
        let ble = BLEDevice::take();
        BLEDevice::set_device_name(&name)?;
        let server = ble.get_server();
        server.advertise_on_disconnect(true);

        let service = server.create_service(uuid(SERVICE_UUID));
        service
            .lock()
            .create_characteristic(uuid(IDENTITY_UUID), NimbleProperties::READ)
            .lock()
            .set_value(identity.as_bytes());
        let status = service.lock().create_characteristic(
            uuid(STATUS_UUID),
            NimbleProperties::READ | NimbleProperties::NOTIFY,
        );

        // The write callback runs on the NimBLE host task: just hand the
        // message over; opening it and joining WiFi happen on the caller's
        // task. One message in flight; writes while busy are rejected.
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(1);
        service
            .lock()
            .create_characteristic(uuid(CREDENTIALS_UUID), NimbleProperties::WRITE)
            .lock()
            .on_write(move |args| {
                if tx.try_send(args.recv_data().to_vec()).is_err() {
                    warn!("Busy, rejecting message");
                    args.reject();
                }
            });

        let advertising = ble.get_advertising();
        advertising.lock().set_data(
            BLEAdvertisementData::new()
                .name(&name)
                .add_service_uuid(uuid(SERVICE_UUID)),
        )?;
        advertising.lock().start()?;
        info!("Advertising as {name}");
        Ok(Self {
            messages: rx,
            status,
        })
    }

    /// Wait a moment so the client gets the last status, then shut BLE down
    /// to free its memory.
    pub fn shutdown(self) {
        std::thread::sleep(LINGER);
        let free_before = free_heap();
        // Not deinit_full(): in esp32-nimble 0.13 it resets the advertising
        // state after the host is gone, which reads freed memory (load access
        // fault). The extra reset only matters for restarting BLE.
        match BLEDevice::deinit() {
            Ok(()) => info!(
                "BLE shut down, free heap {free_before} -> {} bytes",
                free_heap()
            ),
            Err(e) => warn!("Failed to shut down BLE: {e}"),
        }
    }
}

impl Transport for BleTransport {
    fn recv(&mut self) -> Vec<u8> {
        self.messages.recv().expect("BLE callback dropped")
    }

    fn set_status(&mut self, status: Status) {
        self.status.lock().set_value(&status.encode()).notify();
    }
}

fn free_heap() -> u32 {
    unsafe { esp_idf_svc::sys::esp_get_free_heap_size() }
}
