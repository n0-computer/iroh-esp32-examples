//! WiFi provisioning over BLE for an ESP32-C61, with the credentials encrypted
//! to the device's iroh identity. The logic is in `iroh-provision` (device
//! side) and `iroh-provision-esp-idf` (NimBLE, NVS, WiFi); see `../web` and
//! `iroh-provision-ble` for clients.
//!
//! On boot: load or create the identity. With stored networks, join one of
//! them, retrying until it works, and keep rejoining whichever is available
//! when the connection drops. Without, run BLE provisioning until a working set
//! arrives. Holding BOOT for 5 seconds
//! forgets networks, name and pairing secret (not the identity) and restarts
//! into provisioning mode.
//!
//! This example stops once WiFi is up: that's where the iroh endpoint would be
//! bound, using the same secret key.

use std::time::Duration;

use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use iroh_provision::{device, DeviceInfo};
use iroh_provision_esp_idf::{
    fill_random, join_or_provision, keep_connected, watch_reset_button, NvsStorage, StationWifi,
};
use log::info;

/// What this device is. Clients show it, name new devices after it (`demo-1`,
/// `demo-2`, ...), and it's the start of the BLE name. A CO2 monitor would say
/// `co2`, a lamp `lamp`.
const KIND: &str = "demo";

mod rgb_led;

fn main() {
    // It is necessary to call this function once. Otherwise, some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    esp_idf_svc::sys::link_patches();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    let peripherals = Peripherals::take().expect("Failed to take peripherals");
    let sys_loop = EspSystemEventLoop::take().expect("Failed to take event loop");
    let nvs_partition = EspDefaultNvsPartition::take().expect("Failed to take NVS partition");

    // The ESP32-C61 DevKit's BOOT button is GPIO9. (XIAO ESP32-C5: GPIO28.)
    watch_reset_button(peripherals.pins.gpio9.into(), nvs_partition.clone());

    let mut wifi = StationWifi::start(peripherals.modem, sys_loop, nvs_partition.clone())
        .expect("Failed to start WiFi");
    let mut storage = NvsStorage::new(nvs_partition).expect("Failed to open NVS");

    // After starting WiFi: the RNG is only truly random with the radio on.
    let secret = device::load_or_create_identity(&mut storage, fill_random)
        .expect("Failed to load identity");
    // Comparing this with what the client shows rules out someone
    // impersonating the device during provisioning.
    info!("Endpoint ID: {}", secret.public());
    if let Some(name) = device::load_name(&mut storage) {
        info!("Name: {name:?}");
    }

    // The RGB LED (GPIO8) shows the state: blinking yellow while waiting for
    // provisioning, yellow/green while joining WiFi, green once joined. On a
    // board with a plain LED, use the library's `BlinkingLed` instead, e.g. the
    // XIAO ESP32-C5: `BlinkingLed::new(peripherals.pins.gpio27.into(), true)`
    // (active low).
    let mut led = rgb_led::RgbIndicator::new(peripherals.spi2, peripherals.pins.gpio8)
        .expect("Failed to set up the LED");
    let info = DeviceInfo { kind: KIND.into() };
    let joined = join_or_provision(&mut storage, &mut wifi, &secret, &info, &mut led)
        .expect("Failed to provision");
    info!(
        "Joined {:?}, IP {}. This is where the iroh endpoint would start.",
        joined.ssid, joined.ip
    );
    // From now on, rejoin whichever stored network is there if the connection
    // drops (LED yellow/green meanwhile).
    keep_connected(wifi, &mut storage, led);
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
