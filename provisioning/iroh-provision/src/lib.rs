//! Provisioning WiFi credentials to an iroh device, encrypted to its endpoint id.
//!
//! The device generates an ed25519 key on first boot (its iroh endpoint id) and
//! exposes the public half over some transport, typically BLE. The client seals
//! the WiFi credentials to that key with HPKE (RFC 9180, DHKEM(X25519,
//! HKDF-SHA256) + ChaCha20Poly1305), using the X25519 form of the ed25519 key.
//! So the password never travels in the clear, and only the holder of the
//! endpoint's secret key can open it — the same key that later authenticates
//! every iroh connection to the device.
//!
//! The same message carries a name for the device and a pairing secret chosen
//! by the client. The client combines the secret with the endpoint id into a
//! single-use [`PairingTicket`]: the endpoint id alone is public, so it can't
//! be what authorizes control. Whoever redeems the ticket over iroh first
//! becomes an owner, authenticated from then on by their own endpoint id.
//!
//! This defeats passive sniffing. It does not, by itself, defeat an active
//! attacker impersonating the device during provisioning: for that, compare
//! the endpoint id the client shows with the one the device prints.
//!
//! The crate is platform independent; transports and platform glue live in
//! `iroh-provision-ble` (client side) and `iroh-provision-esp-idf` (device
//! side). See the README for the workflow.
//!
//! - [`protocol`] (always): formats, [`open`], tickets, status.
//! - [`client`] (feature `client`): [`seal`], and a [`client::Session`] that
//!   provisions one device over a [`client::Transport`].
//! - [`device`] (feature `device`): the device side, over [`device::Storage`],
//!   [`device::Wifi`] and [`device::Transport`].
//!
//! # GATT layout
//!
//! For BLE transports: one primary service ([`SERVICE_UUID`]) with three
//! characteristics:
//!
//! - [`IDENTITY_UUID`] (read): the 32 byte ed25519 public key.
//! - [`CREDENTIALS_UUID`] (write): a sealed [`Message`].
//! - [`STATUS_UUID`] (read, notify): the encoded [`Status`].

pub mod protocol;
pub use protocol::*;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "device")]
pub mod device;

#[cfg(all(test, feature = "client", feature = "device"))]
mod end_to_end;

/// Re-exported so users name the same key types this crate uses.
pub use iroh_base::{PublicKey, SecretKey};
