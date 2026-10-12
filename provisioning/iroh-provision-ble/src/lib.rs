//! BLE transports for [`iroh_provision::client::Session`].
//!
//! - [`native`] (feature `native`): desktop BLE via btleplug.
//! - [`web`] (feature `web`): Web Bluetooth, for wasm.
//!
//! Both talk to the GATT service described in [`iroh_provision`]: read the
//! identity characteristic, write sealed messages to the credentials
//! characteristic, and subscribe to the status characteristic.

#[cfg(feature = "native")]
pub mod native;

#[cfg(feature = "web")]
pub mod web;
