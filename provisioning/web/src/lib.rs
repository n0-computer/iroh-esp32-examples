//! The crypto half of the provisioning client. Web Bluetooth itself is driven
//! from `public/main.js`; this module seals the credentials to the device's
//! identity using the same `provisioning-proto` crate the device opens them with.

use iroh_base::PublicKey;
use provisioning_proto::{
    Credentials, Failure, Network, PairingSecret, PairingTicket, Provisioning, Status,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
fn start() {
    console_error_panic_hook::set_once();
}

/// GATT UUIDs, exported so the protocol has exactly one definition.
#[wasm_bindgen]
pub fn service_uuid() -> String {
    provisioning_proto::SERVICE_UUID.into()
}

#[wasm_bindgen]
pub fn identity_uuid() -> String {
    provisioning_proto::IDENTITY_UUID.into()
}

#[wasm_bindgen]
pub fn credentials_uuid() -> String {
    provisioning_proto::CREDENTIALS_UUID.into()
}

#[wasm_bindgen]
pub fn status_uuid() -> String {
    provisioning_proto::STATUS_UUID.into()
}

/// The endpoint id, in iroh's display format, for the bytes read from the
/// identity characteristic.
#[wasm_bindgen]
pub fn endpoint_id(identity: &[u8]) -> Result<String, JsError> {
    Ok(public_key(identity)?.to_string())
}

/// The most networks [`provision`] accepts.
#[wasm_bindgen]
pub fn max_networks() -> usize {
    provisioning_proto::MAX_NETWORKS
}

/// The longest device name [`provision`] accepts, in bytes.
#[wasm_bindgen]
pub fn max_name_len() -> usize {
    provisioning_proto::MAX_NAME_LEN
}

/// A sealed provisioning message, and the pairing ticket it makes valid once
/// the device accepts it.
#[wasm_bindgen(getter_with_clone)]
pub struct Sealed {
    /// Write this to the credentials characteristic.
    pub message: Vec<u8>,
    /// `pair…`: endpoint id + the fresh pairing secret in `message`.
    pub ticket: String,
}

/// Seal networks, a name and a fresh pairing secret to the device's identity.
/// `ssids[i]` goes with `passwords[i]`; the device replaces its stored state
/// with this. Every call generates a new secret, so only the ticket of the
/// message the device accepted is valid.
#[wasm_bindgen]
pub fn provision(
    identity: &[u8],
    ssids: Vec<String>,
    passwords: Vec<String>,
    name: String,
) -> Result<Sealed, JsError> {
    if ssids.len() != passwords.len() {
        return Err(JsError::new("one password per network"));
    }
    let networks = ssids
        .into_iter()
        .zip(passwords)
        .map(|(ssid, password)| Network { ssid, password })
        .collect();
    let endpoint = public_key(identity)?;
    let pairing_secret = PairingSecret::generate();
    let provisioning = Provisioning {
        credentials: Credentials { networks },
        name,
        pairing_secret: pairing_secret.clone(),
    };
    let message = provisioning_proto::seal(&endpoint, &provisioning).map_err(js_err)?;
    let ticket = PairingTicket {
        endpoint,
        secret: pairing_secret,
    };
    Ok(Sealed {
        message,
        ticket: ticket.to_string(),
    })
}

/// A decoded status notification, for display.
#[wasm_bindgen(getter_with_clone)]
pub struct StatusView {
    /// `unprovisioned`, `connecting`, `connected`, `failed` or `unknown`.
    pub state: String,
    /// Human readable detail: the IP, or why it failed.
    pub detail: String,
    /// For `connected`: the index of the network that joined.
    pub network: Option<u8>,
}

#[wasm_bindgen]
pub fn decode_status(bytes: &[u8]) -> StatusView {
    let mut network = None;
    let (state, detail) = match Status::decode(bytes) {
        Some(Status::Unprovisioned) => ("unprovisioned", "waiting for credentials".to_owned()),
        Some(Status::Connecting) => ("connecting", "joining a network…".to_owned()),
        Some(Status::Connected {
            network: index,
            ip: [a, b, c, d],
        }) => {
            network = Some(index);
            ("connected", format!("IP {a}.{b}.{c}.{d}"))
        }
        Some(Status::Failed(failure)) => (
            "failed",
            match failure {
                Failure::BadMessage => "device could not open the credentials",
                Failure::WifiConnect => "could not join: probably a wrong password",
                Failure::NoIp => "joined, but got no IP address",
                Failure::NotFound => "none of the networks is in range",
                Failure::Unsupported => "device firmware is too old for this page",
            }
            .to_owned(),
        ),
        None => ("unknown", format!("unrecognized status {bytes:02x?}")),
    };
    StatusView {
        state: state.into(),
        detail,
        network,
    }
}

fn public_key(identity: &[u8]) -> Result<PublicKey, JsError> {
    PublicKey::try_from(identity).map_err(js_err)
}

fn js_err(err: impl std::fmt::Display) -> JsError {
    JsError::new(&err.to_string())
}
