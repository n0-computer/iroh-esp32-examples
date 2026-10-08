//! The ESP32-C6 firmware's noq server, compiled for the host.

#[path = "../../noq-esp32-c6/src/echo.rs"]
pub mod echo;
#[path = "../../noq-esp32-c6/src/keys.rs"]
mod keys;
#[path = "../../noq-esp32-c6/src/quic_crypto_provider.rs"]
pub mod quic_crypto_provider;
#[path = "../../noq-esp32-c6/src/tls.rs"]
pub mod tls;
