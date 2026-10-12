//! Desktop BLE via btleplug.
//!
//! ```ignore
//! for device in native::discover(Duration::from_secs(5)).await? {
//!     let mut session = Session::connect(device.connect().await?).await?;
//!     let provisioned = session.provision(&networks, "lamp-1").await?;
//! }
//! ```

use std::pin::Pin;
use std::time::Duration;

use btleplug::api::{
    Central, Characteristic, Manager as _, Peripheral as _, ScanFilter, ValueNotification,
    WriteType,
};
use btleplug::platform::{Manager, Peripheral};
use futures::{FutureExt, Stream, StreamExt};
use iroh_provision::client::Transport;
use iroh_provision::{Status, CREDENTIALS_UUID, INFO_UUID, SERVICE_UUID, STATUS_UUID};
use n0_error::{e, stack_error};
use uuid::Uuid;

#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum Error {
    #[error("bluetooth")]
    Ble {
        #[error(std_err)]
        source: btleplug::Error,
    },
    #[error("no bluetooth adapter")]
    NoAdapter {},
    #[error("device lacks the {name} characteristic")]
    MissingCharacteristic { name: &'static str },
    #[error("device disconnected")]
    Disconnected {},
}

impl From<btleplug::Error> for Error {
    fn from(source: btleplug::Error) -> Self {
        e!(Error::Ble, source)
    }
}

fn uuid(s: &str) -> Uuid {
    Uuid::parse_str(s).expect("valid UUID")
}

/// A device in provisioning mode, found by [`discover`].
pub struct Discovered {
    /// The BLE name, `iroh-<short endpoint id>`.
    pub name: Option<String>,
    pub rssi: Option<i16>,
    peripheral: Peripheral,
}

/// Scan for `duration` and return the devices advertising the provisioning
/// service, strongest signal first.
pub async fn discover(duration: Duration) -> Result<Vec<Discovered>, Error> {
    let service = uuid(SERVICE_UUID);
    let adapter = Manager::new()
        .await?
        .adapters()
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| e!(Error::NoAdapter))?;
    adapter
        .start_scan(ScanFilter {
            services: vec![service],
        })
        .await?;
    tokio::time::sleep(duration).await;
    adapter.stop_scan().await?;
    let mut found = Vec::new();
    for peripheral in adapter.peripherals().await? {
        let Some(props) = peripheral.properties().await? else {
            continue;
        };
        // Some platforms report every peripheral seen, despite the filter.
        if !props.services.contains(&service) {
            continue;
        }
        found.push(Discovered {
            name: props.local_name,
            rssi: props.rssi,
            peripheral,
        });
    }
    found.sort_by_key(|d| std::cmp::Reverse(d.rssi));
    Ok(found)
}

impl Discovered {
    /// Connect and subscribe to the status.
    pub async fn connect(self) -> Result<NativeTransport, Error> {
        let peripheral = self.peripheral;
        peripheral.connect().await?;
        peripheral.discover_services().await?;
        let find = |name: &'static str, id: &str| {
            let id = uuid(id);
            peripheral
                .characteristics()
                .into_iter()
                .find(|c| c.uuid == id)
                .ok_or_else(|| e!(Error::MissingCharacteristic { name }))
        };
        let credentials = find("credentials", CREDENTIALS_UUID)?;
        let status = find("status", STATUS_UUID)?;
        let info = find("info", INFO_UUID)?;
        peripheral.subscribe(&status).await?;
        let notifications = peripheral.notifications().await?;
        Ok(NativeTransport {
            name: self.name,
            peripheral,
            credentials,
            status,
            info,
            notifications,
        })
    }
}

/// A connection to one device, implementing [`Transport`].
pub struct NativeTransport {
    pub name: Option<String>,
    peripheral: Peripheral,
    credentials: Characteristic,
    status: Characteristic,
    info: Characteristic,
    notifications: Pin<Box<dyn Stream<Item = ValueNotification> + Send>>,
}

impl NativeTransport {
    pub async fn disconnect(&self) -> Result<(), Error> {
        Ok(self.peripheral.disconnect().await?)
    }
}

impl Transport for NativeTransport {
    type Error = Error;

    async fn read_hello(&mut self) -> Result<Vec<u8>, Error> {
        Ok(self.peripheral.read(&self.info).await?)
    }

    async fn write_message(&mut self, sealed: &[u8]) -> Result<(), Error> {
        // Drop statuses that arrived before this message.
        while let Some(Some(_)) = self.notifications.next().now_or_never() {}
        self.peripheral
            .write(&self.credentials, sealed, WriteType::WithResponse)
            .await?;
        Ok(())
    }

    async fn next_status(&mut self) -> Result<Status, Error> {
        loop {
            let notification = self
                .notifications
                .next()
                .await
                .ok_or_else(|| e!(Error::Disconnected))?;
            if notification.uuid != self.status.uuid {
                continue;
            }
            // An unknown status is from a newer device; wait for one we know.
            if let Some(status) = Status::decode(&notification.value) {
                return Ok(status);
            }
        }
    }
}
