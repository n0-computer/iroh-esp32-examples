//! WiFi provisioning over BLE, with the credentials encrypted to the device's
//! iroh identity. See `../proto` for the protocol and `../web` for the client.
//!
//! On boot:
//!
//! 1. Load the ed25519 secret key from NVS, or generate and store one. This is
//!    the iroh endpoint identity; it survives reprovisioning.
//! 2. If networks are stored, join one: scan, then try the known networks in
//!    range, strongest first (and the rest, if a hidden network is around). If
//!    none works (3 rounds), fall through to provisioning mode, keeping the list
//!    until a new one arrives.
//! 3. Provisioning mode: advertise over BLE as `iroh-<short endpoint id>`
//!    (iroh's `fmt_short`), expose the public key, and wait for a sealed list of
//!    networks, a name and a pairing secret. Join one of the networks the same
//!    way; on success store all of it, report which network and IP, and shut
//!    BLE down.
//!
//! Holding the BOOT button for 5 seconds at any time wipes the networks, name
//! and pairing secret (not the identity) and restarts into provisioning mode.
//!
//! This example stops once WiFi is up: that's where the iroh endpoint would be
//! bound, using the same secret key.

use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::time::Duration;

use esp32_nimble::utilities::BleUuid;
use esp32_nimble::{BLEAdvertisementData, BLEDevice, NimbleProperties};
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::gpio::{AnyIOPin, PinDriver, Pull};
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};
use esp_idf_svc::wifi::config::ScanConfig;
use esp_idf_svc::wifi::{
    AccessPointInfo, AuthMethod, BlockingWifi, ClientConfiguration, Configuration, EspWifi,
};
use iroh_base::SecretKey;
use log::{info, warn};
use provisioning_proto::{Credentials, Error, Failure, Message, Network, Provisioning, Status};

/// NVS namespace for everything this example stores.
const NVS_NAMESPACE: &str = "prov";
const KEY_SECRET: &str = "secret";
/// The networks, in [`Credentials::to_bytes`] format (postcard).
const KEY_NETWORKS: &str = "networks";
/// The name given at provisioning (may be empty).
const KEY_NAME: &str = "name";
/// The unredeemed pairing secret, see [`provisioning_proto::PairingTicket`].
/// Redeeming it (over iroh, once the endpoint runs) deletes it and records the
/// client as an owner.
const KEY_PAIRING: &str = "pairing";
/// Largest encoded [`Credentials`]: count + per network 2 lengths + max SSID and
/// password.
const MAX_NETWORKS_LEN: usize = 1 + provisioning_proto::MAX_NETWORKS
    * (2 + provisioning_proto::MAX_SSID_LEN + provisioning_proto::MAX_PASSWORD_LEN);

/// Rounds over the stored networks before falling back to provisioning.
const JOIN_ATTEMPTS: usize = 3;
/// How long to hold BOOT to wipe the WiFi credentials.
const RESET_HOLD: Duration = Duration::from_secs(5);
/// How long BLE stays up after success, so the client sees the final status.
const LINGER: Duration = Duration::from_secs(3);

fn uuid(s: &str) -> BleUuid {
    BleUuid::from_uuid128_string(s).expect("valid UUID")
}

fn main() {
    // It is necessary to call this function once. Otherwise, some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    esp_idf_svc::sys::link_patches();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    let peripherals = Peripherals::take().expect("Failed to take peripherals");
    let sys_loop = EspSystemEventLoop::take().expect("Failed to take event loop");
    let nvs_partition = EspDefaultNvsPartition::take().expect("Failed to take NVS partition");
    let nvs = EspNvs::new(nvs_partition.clone(), NVS_NAMESPACE, true)
        .expect("Failed to open NVS namespace");

    // The ESP32-C61 DevKit's BOOT button is GPIO9. (XIAO ESP32-C5: GPIO28.)
    watch_reset_button(peripherals.pins.gpio9.into(), nvs_partition.clone());

    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(peripherals.modem, sys_loop.clone(), Some(nvs_partition))
            .expect("Failed to create EspWifi"),
        sys_loop,
    )
    .expect("Failed to create BlockingWifi");
    // The driver needs a mode before start(); the real config comes in join().
    // Auth threshold None, or the driver warns about the empty password.
    wifi.set_configuration(&Configuration::Client(ClientConfiguration {
        auth_method: AuthMethod::None,
        ..Default::default()
    }))
    .expect("Failed to set WiFi configuration");
    wifi.start().expect("Failed to start WiFi");

    // After wifi.start(): the RNG is only truly random with the radio on.
    let secret = load_or_create_secret(&nvs);
    // Print this prominently: comparing it with what the browser shows is how a
    // user rules out someone impersonating the device during provisioning.
    info!("Endpoint ID: {}", secret.public());
    if let Some(name) = load_name(&nvs) {
        info!("Name: {name:?}");
    }

    let ip = match load_credentials(&nvs) {
        Some(creds) => (1..=JOIN_ATTEMPTS)
            .find_map(|attempt| {
                info!("Joining a stored network (attempt {attempt}/{JOIN_ATTEMPTS})");
                join_any(&mut wifi, &creds)
                    .inspect_err(|failure| warn!("Join failed: {failure:?}"))
                    .ok()
            })
            .map(|(_, ip)| ip)
            .unwrap_or_else(|| {
                warn!("Stored networks don't work, entering provisioning mode");
                provision(&mut wifi, &nvs, &secret)
            }),
        None => {
            info!("No networks stored, entering provisioning mode");
            provision(&mut wifi, &nvs, &secret)
        }
    };

    info!("WiFi up, IP {ip}. This is where the iroh endpoint would start.");
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

/// The endpoint's secret key, generated on first boot: 32 bytes from the
/// hardware RNG, which is a true RNG while WiFi or BLE is running.
fn load_or_create_secret(nvs: &EspNvs<NvsDefault>) -> SecretKey {
    let mut seed = [0u8; 32];
    match nvs.get_blob(KEY_SECRET, &mut seed) {
        Ok(Some(stored)) if stored.len() == 32 => return SecretKey::from_bytes(&seed),
        Ok(_) => info!("No identity yet, generating one"),
        // Don't paper over this with a fresh key: that silently changes the
        // endpoint id, and every peer that knew the device loses it.
        Err(e) => panic!("Failed to read identity: {e}"),
    }
    unsafe { esp_idf_svc::sys::esp_fill_random(seed.as_mut_ptr().cast(), seed.len()) };
    nvs.set_blob(KEY_SECRET, &seed)
        .expect("Failed to store identity");
    SecretKey::from_bytes(&seed)
}

fn load_credentials(nvs: &EspNvs<NvsDefault>) -> Option<Credentials> {
    let mut buf = [0u8; MAX_NETWORKS_LEN];
    let bytes = nvs.get_blob(KEY_NETWORKS, &mut buf).ok()??;
    Credentials::from_bytes(bytes)
        .inspect_err(|e| warn!("Ignoring stored networks: {e}"))
        .ok()
}

fn load_name(nvs: &EspNvs<NvsDefault>) -> Option<String> {
    let mut buf = [0u8; provisioning_proto::MAX_NAME_LEN + 1];
    let name = nvs.get_str(KEY_NAME, &mut buf).ok()??;
    (!name.is_empty()).then(|| name.to_owned())
}

/// Store everything from a provisioning message that worked. A new pairing
/// secret replaces an unredeemed one.
fn store_provisioning(nvs: &EspNvs<NvsDefault>, provisioning: &Provisioning) {
    let networks = provisioning
        .credentials
        .to_bytes()
        .expect("validated when opened");
    nvs.set_blob(KEY_NETWORKS, &networks)
        .and_then(|_| nvs.set_str(KEY_NAME, &provisioning.name))
        .and_then(|_| nvs.set_blob(KEY_PAIRING, &provisioning.pairing_secret.0))
        .expect("Failed to store provisioning");
}

/// Join one of the networks: scan, then try the ones in range strongest first.
/// A hidden network shows up in the scan without its SSID, so the networks not
/// seen are tried too, but only if a hidden network is around: each failed
/// attempt costs the full connect timeout. Returns the index of the network
/// that worked.
fn join_any(
    wifi: &mut BlockingWifi<EspWifi<'static>>,
    creds: &Credentials,
) -> Result<(u8, Ipv4Addr), Failure> {
    // A previous failed attempt can leave the driver mid-connect, which makes
    // the scan fail.
    let _ = wifi.disconnect();
    let visible = scan(wifi).unwrap_or_else(|e| {
        warn!("Scan failed: {e}");
        Vec::new()
    });
    let hidden_nearby = visible.iter().any(|ap| ap.ssid.is_empty());
    let signal = |network: &Network| {
        visible
            .iter()
            .filter(|ap| ap.ssid.as_str() == network.ssid)
            .map(|ap| ap.signal_strength)
            .max()
    };
    let mut candidates: Vec<(usize, Option<i8>)> = creds
        .networks
        .iter()
        .enumerate()
        .map(|(i, network)| (i, signal(network)))
        .collect();
    // In range first, strongest first; `None` (not seen) sorts last.
    candidates.sort_by_key(|&(_, signal)| std::cmp::Reverse(signal));

    let mut failure = Failure::NotFound;
    for (i, signal) in candidates {
        let network = &creds.networks[i];
        match signal {
            Some(rssi) => info!("Trying {:?} ({rssi} dBm)", network.ssid),
            None if hidden_nearby => info!("Trying {:?} (maybe hidden)", network.ssid),
            None => {
                info!("Skipping {:?}: not in range", network.ssid);
                continue;
            }
        }
        match join(wifi, network) {
            Ok(ip) => return Ok((i as u8, ip)),
            // Only a network that's actually there makes "wrong password" (or
            // DHCP trouble) the better explanation than "not found".
            Err(f) if signal.is_some() => failure = f,
            Err(_) => {}
        }
    }
    Err(failure)
}

fn scan(
    wifi: &mut BlockingWifi<EspWifi<'static>>,
) -> Result<Vec<AccessPointInfo>, esp_idf_svc::sys::EspError> {
    let config = ScanConfig {
        show_hidden: true,
        ..Default::default()
    };
    wifi.wifi_mut().start_scan(&config, true)?;
    wifi.wifi_mut().get_scan_result()
}

/// Try to join one network: associate, then wait for DHCP.
fn join(wifi: &mut BlockingWifi<EspWifi<'static>>, network: &Network) -> Result<Ipv4Addr, Failure> {
    let config = Configuration::Client(ClientConfiguration {
        // Lengths are checked by the protocol, so these can't fail.
        ssid: network
            .ssid
            .as_str()
            .try_into()
            .map_err(|_| Failure::BadMessage)?,
        password: network
            .password
            .as_str()
            .try_into()
            .map_err(|_| Failure::BadMessage)?,
        auth_method: if network.password.is_empty() {
            AuthMethod::None
        } else {
            AuthMethod::WPA2Personal
        },
        ..Default::default()
    });
    let _ = wifi.disconnect();
    wifi.set_configuration(&config)
        .map_err(|_| Failure::WifiConnect)?;
    wifi.connect().map_err(|_| Failure::WifiConnect)?;
    if wifi.wait_netif_up().is_err() {
        let _ = wifi.disconnect();
        return Err(Failure::NoIp);
    }
    let ip = wifi
        .wifi()
        .sta_netif()
        .get_ip_info()
        .map_err(|_| Failure::NoIp)?
        .ip;
    Ok(ip)
}

/// Run the BLE provisioning service until a list with a working network arrives.
fn provision(
    wifi: &mut BlockingWifi<EspWifi<'static>>,
    nvs: &EspNvs<NvsDefault>,
    secret: &SecretKey,
) -> Ipv4Addr {
    let identity = secret.public();
    let name = provisioning_proto::device_name(&identity);

    let ble = BLEDevice::take();
    BLEDevice::set_device_name(&name).expect("Failed to set BLE device name");
    let server = ble.get_server();
    server.advertise_on_disconnect(true);

    let service = server.create_service(uuid(provisioning_proto::SERVICE_UUID));
    service
        .lock()
        .create_characteristic(
            uuid(provisioning_proto::IDENTITY_UUID),
            NimbleProperties::READ,
        )
        .lock()
        .set_value(identity.as_bytes());
    let status = service.lock().create_characteristic(
        uuid(provisioning_proto::STATUS_UUID),
        NimbleProperties::READ | NimbleProperties::NOTIFY,
    );
    status.lock().set_value(&Status::Unprovisioned.encode());

    // The write callback runs on the NimBLE host task: just hand the message
    // over. Decrypting and joining WiFi happen here on the main task. One
    // message in flight; writes while busy are rejected.
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(1);
    service
        .lock()
        .create_characteristic(
            uuid(provisioning_proto::CREDENTIALS_UUID),
            NimbleProperties::WRITE,
        )
        .lock()
        .on_write(move |args| {
            if tx.try_send(args.recv_data().to_vec()).is_err() {
                warn!("Busy, rejecting credentials write");
                args.reject();
            }
        });

    let advertising = ble.get_advertising();
    advertising
        .lock()
        .set_data(
            BLEAdvertisementData::new()
                .name(&name)
                .add_service_uuid(uuid(provisioning_proto::SERVICE_UUID)),
        )
        .expect("Failed to set advertisement data");
    advertising
        .lock()
        .start()
        .expect("Failed to start advertising");
    info!("Advertising as {name}, waiting for credentials");

    let set_status = |s: Status| {
        info!("Status: {s:?}");
        status.lock().set_value(&s.encode()).notify();
    };

    let ip = loop {
        let message = rx.recv().expect("BLE callback dropped");
        let provisioning = match provisioning_proto::open(secret, &message) {
            Ok(Message::Provision(provisioning)) => provisioning,
            Err(e) => {
                warn!("Rejected credentials message: {e}");
                set_status(Status::Failed(match e {
                    Error::Unsupported => Failure::Unsupported,
                    _ => Failure::BadMessage,
                }));
                continue;
            }
        };
        let creds = &provisioning.credentials;
        let ssids: Vec<&str> = creds.networks.iter().map(|n| n.ssid.as_str()).collect();
        info!("Received {:?} with networks {ssids:?}", provisioning.name);
        set_status(Status::Connecting);
        match join_any(wifi, creds) {
            Ok((network, ip)) => {
                store_provisioning(nvs, &provisioning);
                set_status(Status::Connected {
                    network,
                    ip: ip.octets(),
                });
                break ip;
            }
            Err(failure) => set_status(Status::Failed(failure)),
        }
    };

    std::thread::sleep(LINGER);
    // Free the controller and host memory for the iroh endpoint. Not
    // deinit_full(): in esp32-nimble 0.13 it resets the advertising state after
    // the host is gone, which reads freed memory (load access fault). The extra
    // reset only matters for restarting BLE, which we never do.
    let free_before = free_heap();
    match BLEDevice::deinit() {
        Ok(()) => info!(
            "BLE shut down, free heap {} -> {} bytes",
            free_before,
            free_heap()
        ),
        Err(e) => warn!("Failed to shut down BLE: {e}"),
    }
    ip
}

fn free_heap() -> u32 {
    unsafe { esp_idf_svc::sys::esp_get_free_heap_size() }
}

/// Hold BOOT for [`RESET_HOLD`] to forget the networks, name and pairing
/// secret (and, once there are any, the owners), and restart.
/// The identity is kept, so the endpoint id stays the same.
fn watch_reset_button(pin: AnyIOPin<'static>, nvs_partition: EspDefaultNvsPartition) {
    std::thread::Builder::new()
        .stack_size(4096)
        .spawn(move || {
            let button = PinDriver::input(pin, Pull::Up).expect("Failed to configure BOOT button");
            let tick = Duration::from_millis(100);
            let mut held = Duration::ZERO;
            loop {
                std::thread::sleep(tick);
                held = if button.is_low() {
                    held + tick
                } else {
                    Duration::ZERO
                };
                if held >= RESET_HOLD {
                    warn!("BOOT held, forgetting networks, name and pairing");
                    let nvs = EspNvs::new(nvs_partition, NVS_NAMESPACE, true)
                        .expect("Failed to open NVS namespace");
                    for key in [KEY_NETWORKS, KEY_NAME, KEY_PAIRING] {
                        let _ = nvs.remove(key);
                    }
                    unsafe { esp_idf_svc::sys::esp_restart() };
                }
            }
        })
        .expect("Failed to spawn reset button thread");
}
