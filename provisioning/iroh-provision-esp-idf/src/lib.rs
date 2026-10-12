//! ESP-IDF glue for the device side of [`iroh_provision`]: a NimBLE GATT
//! service as the [`Transport`](iroh_provision::device::Transport), NVS as the
//! [`Storage`](iroh_provision::device::Storage), and `EspWifi` as the
//! [`Wifi`](iroh_provision::device::Wifi).
//!
//! A complete boot, up to WiFi:
//!
//! ```ignore
//! let nvs_partition = EspDefaultNvsPartition::take()?;
//! watch_reset_button(peripherals.pins.gpio9.into(), nvs_partition.clone());
//! let mut wifi = StationWifi::start(peripherals.modem, sys_loop, nvs_partition.clone())?;
//! let mut storage = NvsStorage::new(nvs_partition)?;
//! let secret = device::load_or_create_identity(&mut storage, fill_random)?;
//! // XIAO ESP32-C5: user LED on GPIO27, active low.
//! let mut led = BlinkingLed::new(peripherals.pins.gpio27.into(), true)?;
//! let joined = join_or_provision(&mut storage, &mut wifi, &secret, &mut led)?;
//! keep_connected(wifi, &mut storage, led);
//! ```
//!
//! Needs NimBLE in the app's `sdkconfig.defaults`:
//!
//! ```text
//! CONFIG_BT_ENABLED=y
//! CONFIG_BT_BLE_ENABLED=y
//! CONFIG_BT_BLUEDROID_ENABLED=n
//! CONFIG_BT_NIMBLE_ENABLED=y
//! ```

#[cfg(not(esp_idf_bt_nimble_enabled))]
compile_error!(
    "iroh-provision-esp-idf needs NimBLE. Add to sdkconfig.defaults: \
     CONFIG_BT_ENABLED=y, CONFIG_BT_BLE_ENABLED=y, CONFIG_BT_BLUEDROID_ENABLED=n, \
     CONFIG_BT_NIMBLE_ENABLED=y"
);

mod ble;
mod indicator;
mod storage;
mod wifi;

use std::time::Duration;

use esp_idf_svc::hal::gpio::{AnyIOPin, PinDriver, Pull};
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::sys::EspError;
use iroh_provision::device::{self, Joined};
use iroh_provision::SecretKey;
use log::{info, warn};
use n0_error::stack_error;

pub use ble::BleTransport;

#[stack_error(derive, add_meta, from_sources)]
#[non_exhaustive]
pub enum Error {
    #[error("ESP-IDF")]
    Esp {
        #[error(std_err)]
        source: EspError,
    },
    #[error("BLE")]
    Ble {
        #[error(std_err)]
        source: esp32_nimble::BLEError,
    },
}
pub use indicator::{animate, BlinkingLed, SharedState};
pub use iroh_provision::device::{DeviceState, Indicator};
pub use storage::NvsStorage;
pub use wifi::StationWifi;

/// How long to hold the reset button to forget the provisioned state.
const RESET_HOLD: Duration = Duration::from_secs(5);

/// Fill `buf` from the hardware RNG. A true RNG only while WiFi or BLE is
/// running, so generate keys after starting WiFi.
pub fn fill_random(buf: &mut [u8]) {
    unsafe { esp_idf_svc::sys::esp_fill_random(buf.as_mut_ptr().cast(), buf.len()) };
}

/// With stored networks, join one of them, retrying until it works (never
/// provisioning mode). Without, run BLE provisioning until a working set
/// arrives, then shut BLE down to free its memory. `indicator` shows the
/// [`DeviceState`] along the way (pass `&mut ()` for none).
pub fn join_or_provision(
    storage: &mut NvsStorage,
    wifi: &mut StationWifi,
    secret: &SecretKey,
    indicator: &mut impl Indicator,
) -> Result<Joined, Error> {
    if let Some(creds) = device::load_credentials(storage) {
        return Ok(device::connect(wifi, &creds, indicator, std::thread::sleep));
    }
    info!("No networks stored, provisioning over BLE");
    let mut ble = BleTransport::start(&secret.public())?;
    let mut transport = device::Indicating {
        transport: &mut ble,
        indicator,
    };
    let joined = device::provision(storage, wifi, secret, &mut transport)?;
    ble.shutdown();
    Ok(joined)
}

/// After [`join_or_provision`]: watch the connection on a thread, and when it
/// drops, rejoin whichever stored network is available, retrying with growing
/// pauses. The indicator shows [`DeviceState::Connecting`] meanwhile.
pub fn keep_connected(
    mut wifi: StationWifi,
    storage: &mut NvsStorage,
    mut indicator: impl Indicator + Send + 'static,
) {
    let Some(creds) = device::load_credentials(storage) else {
        warn!("No networks stored, nothing to keep connected to");
        return;
    };
    std::thread::Builder::new()
        .stack_size(8192)
        .spawn(move || {
            device::stay_connected(&mut wifi, &creds, &mut indicator, std::thread::sleep)
        })
        .expect("Failed to spawn WiFi watchdog thread");
}

/// Watch a button (active low, e.g. BOOT) on a thread: held for
/// 5 seconds, it [forgets](device::forget) the provisioned state and
/// restarts into provisioning mode. The identity stays.
///
/// BOOT is a strapping pin: held during reset it enters download mode, so
/// this only works while the firmware runs.
pub fn watch_reset_button(pin: AnyIOPin<'static>, nvs_partition: EspDefaultNvsPartition) {
    std::thread::Builder::new()
        .stack_size(4096)
        .spawn(move || {
            let button = PinDriver::input(pin, Pull::Up).expect("Failed to configure button");
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
                    warn!("Reset button held, forgetting networks, name and pairing");
                    match NvsStorage::new(nvs_partition.clone()) {
                        Ok(mut storage) => {
                            if let Err(e) = device::forget(&mut storage) {
                                warn!("Failed to forget: {e}");
                            }
                        }
                        Err(e) => warn!("Failed to open NVS: {e}"),
                    }
                    unsafe { esp_idf_svc::sys::esp_restart() };
                }
            }
        })
        .expect("Failed to spawn reset button thread");
}
