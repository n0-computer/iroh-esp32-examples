//! WiFi provisioning over BLE for an ESP32-C61, with the credentials encrypted
//! to the device's iroh identity. The logic is in `iroh-provision` (device
//! side) and `iroh-provision-esp-idf` (NimBLE, NVS, WiFi); see `../web` and
//! `iroh-provision-ble` for clients.
//!
//! On boot: load or create the identity, join a stored network, or else run
//! BLE provisioning until a working network arrives. Holding BOOT for 5 seconds
//! forgets networks, name and pairing secret (not the identity) and restarts
//! into provisioning mode.
//!
//! This example stops once WiFi is up: that's where the iroh endpoint would be
//! bound, using the same secret key.

use std::time::Duration;

use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use iroh_provision::device;
use iroh_provision_esp_idf::{
    fill_random, join_or_provision, watch_reset_button, NvsStorage, StationWifi,
};
use log::info;

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

    let joined = join_or_provision(&mut storage, &mut wifi, &secret).expect("Failed to provision");
    info!(
        "Joined {:?}, IP {}. This is where the iroh endpoint would start.",
        joined.ssid, joined.ip
    );
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
