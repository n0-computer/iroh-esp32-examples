//! Web Bluetooth via web-sys, for clients compiled to wasm.
//!
//! web-sys only exposes Web Bluetooth with `--cfg=web_sys_unstable_apis` in
//! `RUSTFLAGS` (e.g. in the app's `.cargo/config.toml`). Works in Chrome and
//! Edge on desktop and Android; not in Firefox, nor in any browser on iOS.
//!
//! ```ignore
//! // In a click handler: the browser only shows its picker on a user gesture.
//! let transport = WebTransport::request().await?;
//! let mut session = Session::connect(transport).await?;
//! ```

use futures::channel::mpsc;
use futures::StreamExt;
use iroh_provision::client::Transport;
use iroh_provision::{Status, CREDENTIALS_UUID, INFO_UUID, SERVICE_UUID, STATUS_UUID};
use js_sys::{DataView, JsString, Uint8Array};
use n0_error::{e, stack_error};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::convert::FromWasmAbi;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    BluetoothDevice, BluetoothLeScanFilterInit, BluetoothRemoteGattCharacteristic,
    RequestDeviceOptions,
};

#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum Error {
    #[error("this browser has no Web Bluetooth")]
    Unavailable {},
    #[error("no device picked")]
    Cancelled {},
    #[error("{message}")]
    Js { message: String },
    #[error("device disconnected")]
    Disconnected {},
}

impl From<JsValue> for Error {
    fn from(value: JsValue) -> Self {
        if let Some(err) = value.dyn_ref::<js_sys::Error>() {
            // The picker closed without a choice.
            if err.name() == "NotFoundError" {
                return e!(Error::Cancelled);
            }
            return e!(Error::Js {
                message: String::from(err.message()),
            });
        }
        e!(Error::Js {
            message: value.as_string().unwrap_or_else(|| format!("{value:?}")),
        })
    }
}

async fn wait<T: FromWasmAbi + 'static>(promise: js_sys::Promise<T>) -> Result<T, Error> {
    Ok(JsFuture::from(promise).await?)
}

fn bytes(view: &DataView) -> Vec<u8> {
    Uint8Array::new_with_byte_offset_and_length(
        &view.buffer(),
        view.byte_offset() as u32,
        view.byte_length() as u32,
    )
    .to_vec()
}

/// A connection to one device, implementing [`Transport`].
pub struct WebTransport {
    device: BluetoothDevice,
    credentials: BluetoothRemoteGattCharacteristic,
    info: BluetoothRemoteGattCharacteristic,
    /// `None` marks a disconnect.
    statuses: mpsc::UnboundedReceiver<Option<Status>>,
    // Kept alive as long as the transport: the browser calls them.
    _on_status: Closure<dyn FnMut(web_sys::Event)>,
    _on_disconnect: Closure<dyn FnMut(web_sys::Event)>,
}

impl WebTransport {
    /// Show the browser's picker, filtered to devices in provisioning mode,
    /// then connect and subscribe to the status. Call it from a user gesture
    /// (e.g. a click handler); browsers refuse the picker otherwise.
    pub async fn request() -> Result<Self, Error> {
        let bluetooth = web_sys::window()
            .and_then(|w| w.navigator().bluetooth())
            .ok_or_else(|| e!(Error::Unavailable))?;
        let filter = BluetoothLeScanFilterInit::new();
        filter.set_services(&[JsString::from(SERVICE_UUID)]);
        let options = RequestDeviceOptions::new();
        options.set_filters(&[filter]);
        let device = wait(bluetooth.request_device(&options)).await?;

        let gatt = device.gatt().ok_or_else(|| e!(Error::Disconnected))?;
        let server = wait(gatt.connect()).await?;
        let service = wait(server.get_primary_service_with_str(SERVICE_UUID)).await?;
        let credentials = wait(service.get_characteristic_with_str(CREDENTIALS_UUID)).await?;
        let status = wait(service.get_characteristic_with_str(STATUS_UUID)).await?;
        let info = wait(service.get_characteristic_with_str(INFO_UUID)).await?;

        let (tx, rx) = mpsc::unbounded();
        let status_tx = tx.clone();
        let on_status = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
            let Some(characteristic) = event
                .target()
                .and_then(|t| t.dyn_into::<BluetoothRemoteGattCharacteristic>().ok())
            else {
                return;
            };
            // An unknown status is from a newer device; wait for one we know.
            if let Some(status) = characteristic
                .value()
                .and_then(|v| Status::decode(&bytes(&v)))
            {
                let _ = status_tx.unbounded_send(Some(status));
            }
        });
        status.add_event_listener_with_callback(
            "characteristicvaluechanged",
            on_status.as_ref().unchecked_ref(),
        )?;
        let on_disconnect = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
            let _ = tx.unbounded_send(None);
        });
        device.add_event_listener_with_callback(
            "gattserverdisconnected",
            on_disconnect.as_ref().unchecked_ref(),
        )?;
        wait(status.start_notifications()).await?;

        Ok(Self {
            device,
            credentials,
            info,
            statuses: rx,
            _on_status: on_status,
            _on_disconnect: on_disconnect,
        })
    }

    /// The BLE name, `iroh-<short endpoint id>`.
    pub fn name(&self) -> Option<String> {
        self.device.name()
    }

    /// The browser's device object, e.g. to watch for disconnects.
    pub fn device(&self) -> &BluetoothDevice {
        &self.device
    }
}

impl Transport for WebTransport {
    type Error = Error;

    async fn read_hello(&mut self) -> Result<Vec<u8>, Error> {
        Ok(bytes(&wait(self.info.read_value()).await?))
    }

    async fn write_message(&mut self, sealed: &[u8]) -> Result<(), Error> {
        // Drop statuses that arrived before this message, but keep a
        // disconnect: it's still true.
        while let Ok(item) = self.statuses.try_recv() {
            if item.is_none() {
                return Err(e!(Error::Disconnected));
            }
        }
        // Up to 508 bytes: longer than the default 20 byte ATT payload, which
        // the browser handles (larger MTU, or a long write) transparently.
        let promise = self
            .credentials
            .write_value_with_response_with_u8_slice(&mut sealed.to_vec())?;
        wait(promise).await?;
        Ok(())
    }

    async fn next_status(&mut self) -> Result<Status, Error> {
        match self.statuses.next().await {
            Some(Some(status)) => Ok(status),
            _ => Err(e!(Error::Disconnected)),
        }
    }
}
