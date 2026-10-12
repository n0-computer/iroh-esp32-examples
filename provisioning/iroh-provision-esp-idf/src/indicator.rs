use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use esp_idf_svc::hal::gpio::{AnyOutputPin, PinDriver};
use esp_idf_svc::sys::EspError;
use iroh_provision::device::{DeviceState, Indicator};

/// A [`DeviceState`] shared with an animation thread.
#[derive(Clone, Default)]
pub struct SharedState(Arc<AtomicU8>);

impl SharedState {
    pub fn get(&self) -> DeviceState {
        DeviceState::from_u8(self.0.load(Ordering::Relaxed))
    }

    pub fn set(&self, state: DeviceState) {
        self.0.store(state as u8, Ordering::Relaxed);
    }
}

/// Run `frame(state, tick)` every 125 ms on a new thread, for animating an
/// indicator. At 125 ms a tick, `tick / 2 % 2` toggles at 2 Hz and `tick % 2`
/// at 4 Hz.
pub fn animate(
    stack_size: usize,
    mut frame: impl FnMut(DeviceState, u32) + Send + 'static,
) -> SharedState {
    let state = SharedState::default();
    let thread_state = state.clone();
    std::thread::Builder::new()
        .stack_size(stack_size)
        .spawn(move || {
            let mut tick = 0u32;
            loop {
                frame(thread_state.get(), tick);
                tick = tick.wrapping_add(1);
                std::thread::sleep(Duration::from_millis(125));
            }
        })
        .expect("Failed to spawn indicator thread");
    state
}

/// A plain LED on a GPIO: blinks at 2 Hz while provisioning, at 4 Hz while
/// connecting, and is off otherwise (free for the app once connected).
pub struct BlinkingLed {
    state: SharedState,
}

impl BlinkingLed {
    /// `active_low`: the LED lights when the pin is low (common for LEDs
    /// wired from 3.3 V to the pin).
    pub fn new(pin: AnyOutputPin<'static>, active_low: bool) -> Result<Self, EspError> {
        let mut led = PinDriver::output(pin)?;
        let state = animate(2048, move |state, tick| {
            let on = match state {
                DeviceState::Provisioning => tick / 2 % 2 == 0,
                DeviceState::Connecting => tick % 2 == 0,
                DeviceState::Idle | DeviceState::Connected => false,
            };
            let _ = if on != active_low {
                led.set_high()
            } else {
                led.set_low()
            };
        });
        Ok(Self { state })
    }
}

impl Indicator for BlinkingLed {
    fn show(&mut self, state: DeviceState) {
        self.state.set(state);
    }
}
