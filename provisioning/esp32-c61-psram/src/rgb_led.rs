//! The C61 DevKit's addressable RGB LED (WS2812 on GPIO8) as a provisioning
//! [`Indicator`]: blinking yellow while waiting to be provisioned, yellow and
//! green alternating while joining WiFi, solid green once joined.
//!
//! Driven over SPI, from iroh-co2-monitor: the ESP32-C61 has no RMT peripheral,
//! the usual WS2812 path. At 2.4 MHz each SPI bit is ~417 ns, and each WS2812 bit
//! becomes three SPI bits: `110` for a '1' (long high), `100` for a '0' (short
//! high). 24 GRB bits → 72 SPI bits → 9 bytes per pixel. No SCLK or CS pin; the
//! line idles low between updates, longer than the >50 µs reset, so the pixel
//! latches on its own.
//!
//! Boards with a plain LED (like the XIAO ESP32-C5) use
//! `iroh_provision_esp_idf::BlinkingLed` instead.

use esp_idf_svc::hal::gpio::{AnyIOPin, Gpio8};
use esp_idf_svc::hal::spi::config::{Config, DriverConfig};
use esp_idf_svc::hal::spi::{SpiDeviceDriver, SpiDriver, SPI2};
use esp_idf_svc::hal::units::FromValueType;
use esp_idf_svc::sys::EspError;
use iroh_provision_esp_idf::{animate, DeviceState, Indicator, SharedState};

// Dim: a WS2812 at full brightness is blinding.
const OFF: (u8, u8, u8) = (0, 0, 0);
const YELLOW: (u8, u8, u8) = (40, 28, 0);
const GREEN: (u8, u8, u8) = (0, 40, 0);

pub struct RgbIndicator {
    state: SharedState,
}

impl RgbIndicator {
    pub fn new(spi: SPI2<'static>, data_pin: Gpio8<'static>) -> Result<Self, EspError> {
        let mut led = RgbLed::new(spi, data_pin)?;
        led.set(OFF)?;
        let mut shown = OFF;
        let state = animate(3072, move |state, tick| {
            // Ticks are 125 ms: `tick / 2 % 2` toggles at 2 Hz.
            let even = tick / 2 % 2 == 0;
            let color = match state {
                DeviceState::Idle => OFF,
                DeviceState::Provisioning if even => YELLOW,
                DeviceState::Provisioning => OFF,
                DeviceState::Connecting if even => YELLOW,
                DeviceState::Connecting => GREEN,
                DeviceState::Connected => GREEN,
            };
            if color != shown {
                let _ = led.set(color);
                shown = color;
            }
        });
        Ok(Self { state })
    }
}

impl Indicator for RgbIndicator {
    fn show(&mut self, state: DeviceState) {
        self.state.set(state);
    }
}

struct RgbLed<'d> {
    spi: SpiDeviceDriver<'d, SpiDriver<'d>>,
}

impl<'d> RgbLed<'d> {
    fn new(spi: SPI2<'d>, data_pin: Gpio8<'d>) -> Result<Self, EspError> {
        // MOSI = GPIO8, no SCLK, no MISO. 2.4 MHz → ~417 ns/bit, 3 bits per WS2812 bit.
        let driver = SpiDriver::new_without_sclk(
            spi,
            data_pin,
            Option::<AnyIOPin>::None,
            &DriverConfig::new(),
        )?;
        let spi = SpiDeviceDriver::new(
            driver,
            Option::<AnyIOPin>::None, // no chip-select
            &Config::new().baudrate(2_400_u32.kHz().into()),
        )?;
        Ok(Self { spi })
    }

    /// Set the single pixel. WS2812 expects GRB, MSB first.
    fn set(&mut self, (r, g, b): (u8, u8, u8)) -> Result<(), EspError> {
        let grb: u32 = ((g as u32) << 16) | ((r as u32) << 8) | b as u32;
        self.spi.write(&encode(grb))
    }
}

/// Expand 24 WS2812 bits into 72 SPI bits (9 bytes), MSB first: '1' → 0b110,
/// '0' → 0b100 (each three SPI bits ≈ one 1.25 µs WS2812 bit at 2.4 MHz).
fn encode(grb: u32) -> [u8; 9] {
    let mut buf = [0u8; 9];
    let mut pos = 0usize; // SPI bit index across the 9 bytes, MSB first
    for i in (0..24).rev() {
        let pattern: u8 = if (grb >> i) & 1 == 1 { 0b110 } else { 0b100 };
        for k in (0..3).rev() {
            if (pattern >> k) & 1 == 1 {
                buf[pos / 8] |= 0x80 >> (pos % 8);
            }
            pos += 1;
        }
    }
    buf
}
