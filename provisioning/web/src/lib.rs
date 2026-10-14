//! The provisioning page's wasm module: a thin JS binding over
//! [`iroh_provision::client::Session`] with the Web Bluetooth transport from
//! `iroh-provision-ble`. All BLE and protocol logic is in those crates; the JS
//! in `public/main.js` only does the UI.

use std::cell::RefCell;
use std::rc::Rc;

use iroh_provision::client::Session;
use iroh_provision::{Network, PairingTicket, Status};
use iroh_provision_ble::web::WebTransport;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
fn start() {
    console_error_panic_hook::set_once();
}

/// The most networks a device takes.
#[wasm_bindgen]
pub fn max_networks() -> usize {
    iroh_provision::MAX_NETWORKS
}

/// Show the browser's Bluetooth picker and connect to the chosen device. Call
/// from a click handler. Rejects with "no device picked" if the picker was
/// closed.
#[wasm_bindgen]
pub async fn connect_device() -> Result<Device, JsError> {
    let transport = WebTransport::request().await.map_err(js_err)?;
    let ble_name = transport.name().unwrap_or_default();
    let browser_device = transport.device().clone();
    let session = Session::connect(transport).await.map_err(js_err)?;
    Ok(Device {
        endpoint_id: session.endpoint().to_string(),
        kind: session.info().kind.clone(),
        ble_name,
        browser_device,
        session: Rc::new(RefCell::new(Some(session))),
    })
}

/// A device in provisioning mode, connected over Web Bluetooth.
#[wasm_bindgen]
pub struct Device {
    endpoint_id: String,
    kind: String,
    ble_name: String,
    browser_device: web_sys::BluetoothDevice,
    /// Taken out while a `provision` call runs.
    session: Rc<RefCell<Option<Session<WebTransport>>>>,
}

/// What a successful `provision` resolves to.
#[wasm_bindgen(getter_with_clone)]
pub struct Provisioned {
    /// `pair…`: single-use, endpoint id + the pairing secret the device holds.
    pub ticket: String,
    /// The network it joined.
    pub ssid: String,
    pub ip: String,
}

#[wasm_bindgen]
impl Device {
    /// Compare with the endpoint id the device prints.
    #[wasm_bindgen(getter)]
    pub fn endpoint_id(&self) -> String {
        self.endpoint_id.clone()
    }

    /// What kind of device it is, e.g. `co2`; empty if it doesn't say.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        self.kind.clone()
    }

    /// `<kind>-<short endpoint id>`.
    #[wasm_bindgen(getter)]
    pub fn ble_name(&self) -> String {
        self.ble_name.clone()
    }

    /// Send networks (`ssids[i]` with `passwords[i]`) and a name; resolve once
    /// the device joined one, reject with the reason otherwise. `ticket`:
    /// `null` for a new pairing secret, or the device's existing ticket to keep
    /// it valid (reprovisioning). `on_status(state, detail)` gets the steps in
    /// between. Can be called again after a failure.
    pub async fn provision(
        &self,
        ssids: Vec<String>,
        passwords: Vec<String>,
        name: String,
        ticket: Option<String>,
        on_status: js_sys::Function,
    ) -> Result<Provisioned, JsError> {
        if ssids.len() != passwords.len() {
            return Err(JsError::new("one password per network"));
        }
        let networks: Vec<Network> = ssids
            .into_iter()
            .zip(passwords)
            .map(|(ssid, password)| Network { ssid, password })
            .collect();
        let ticket: Option<PairingTicket> =
            ticket.map(|t| t.parse()).transpose().map_err(js_err)?;
        let mut session = self
            .session
            .borrow_mut()
            .take()
            .ok_or_else(|| JsError::new("already provisioning"))?;
        let result = session
            .provision_with(&networks, &name, ticket.as_ref(), |status| {
                let (state, detail) = describe(status);
                let _ = on_status.call2(&JsValue::NULL, &state.into(), &detail.into());
            })
            .await;
        *self.session.borrow_mut() = Some(session);
        let provisioned = result.map_err(js_err)?;
        Ok(Provisioned {
            ticket: provisioned.ticket.to_string(),
            ssid: provisioned.ssid,
            ip: provisioned.ip.to_string(),
        })
    }

    /// Call `callback()` when the Bluetooth connection drops. After success,
    /// the device turns Bluetooth off itself.
    pub fn on_disconnect(&self, callback: js_sys::Function) {
        let closure = Closure::<dyn FnMut()>::new(move || {
            let _ = callback.call0(&JsValue::NULL);
        });
        let _ = self.browser_device.add_event_listener_with_callback(
            "gattserverdisconnected",
            closure.as_ref().unchecked_ref(),
        );
        // Lives as long as the page; there's one per device.
        closure.forget();
    }

    pub fn disconnect(&self) {
        if let Some(gatt) = self.browser_device.gatt() {
            gatt.disconnect();
        }
    }
}

/// `(state, detail)` for the UI.
fn describe(status: &Status) -> (&'static str, String) {
    match status {
        Status::Unprovisioned => ("unprovisioned", "waiting for credentials".into()),
        Status::Connecting => ("connecting", "joining a network…".into()),
        Status::Connected { ip, .. } => {
            let [a, b, c, d] = ip;
            ("connected", format!("IP {a}.{b}.{c}.{d}"))
        }
        Status::Failed(failure) => ("failed", failure.describe().into()),
    }
}

/// The whole error chain, e.g. "transport failed: device disconnected".
fn js_err(err: impl std::fmt::Display) -> JsError {
    JsError::new(&format!("{err:#}"))
}
