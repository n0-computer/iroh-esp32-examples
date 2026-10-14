//! The client [`Session`] against the device's [`provision`] loop, connected by
//! channels instead of BLE, with a scripted WiFi.

use std::sync::mpsc;
use std::thread;

use futures::channel::mpsc as async_mpsc;
use futures::executor::block_on;
use futures::StreamExt;
use n0_error::{e, stack_error};

use crate::client::{ProvisionError, Session, Transport as ClientTransport};
use crate::device::testing::{network, FakeWifi, MemStorage};
use crate::device::{self, Joined, Transport as DeviceTransport};
use crate::{DeviceInfo, Failure, Hello, PairingTicket, PublicKey, SecretKey, Status};

struct DeviceEnd {
    messages: mpsc::Receiver<Vec<u8>>,
    statuses: async_mpsc::UnboundedSender<Status>,
}

impl DeviceTransport for DeviceEnd {
    fn recv(&mut self) -> Vec<u8> {
        self.messages.recv().expect("client gone")
    }

    fn set_status(&mut self, status: Status) {
        let _ = self.statuses.unbounded_send(status);
    }
}

struct ClientEnd {
    identity: [u8; 32],
    messages: mpsc::Sender<Vec<u8>>,
    statuses: async_mpsc::UnboundedReceiver<Status>,
}

#[stack_error(derive, add_meta)]
#[error("device gone")]
struct Gone {}

impl ClientTransport for ClientEnd {
    type Error = Gone;

    async fn read_hello(&mut self) -> Result<Vec<u8>, Gone> {
        let hello = Hello {
            endpoint: PublicKey::from_bytes(&self.identity).unwrap(),
            info: DeviceInfo {
                kind: "lamp".into(),
            },
        };
        Ok(hello.encode())
    }

    async fn write_message(&mut self, sealed: &[u8]) -> Result<(), Gone> {
        // Drop statuses from before this message, as the trait requires.
        while self.statuses.try_recv().is_ok() {}
        self.messages.send(sealed.to_vec()).map_err(|_| e!(Gone))
    }

    async fn next_status(&mut self) -> Result<Status, Gone> {
        self.statuses.next().await.ok_or_else(|| e!(Gone))
    }
}

/// Start a device in provisioning mode on a thread; returns the client end and
/// the device's result (joined network, storage, WiFi attempts).
fn device(
    wifi: FakeWifi,
) -> (
    ClientEnd,
    SecretKey,
    thread::JoinHandle<(Joined, MemStorage, FakeWifi)>,
) {
    let mut storage = MemStorage::default();
    let secret = device::load_or_create_identity(&mut storage, |b| b.fill(42)).unwrap();
    let (msg_tx, msg_rx) = mpsc::channel();
    let (status_tx, status_rx) = async_mpsc::unbounded();
    let client = ClientEnd {
        identity: *secret.public().as_bytes(),
        messages: msg_tx,
        statuses: status_rx,
    };
    let device_secret = secret.clone();
    let handle = thread::spawn(move || {
        let mut wifi = wifi;
        let mut transport = DeviceEnd {
            messages: msg_rx,
            statuses: status_tx,
        };
        let joined =
            device::provision(&mut storage, &mut wifi, &device_secret, &mut transport).unwrap();
        (joined, storage, wifi)
    });
    (client, secret, handle)
}

#[test]
fn provision_retry_and_ticket() {
    let (client, secret, device) = device(FakeWifi::new(vec![("home", -50, "right")]));
    block_on(async {
        let mut session = Session::connect(client).await.unwrap();
        assert_eq!(session.endpoint(), secret.public());
        assert_eq!(session.info().kind, "lamp");

        // Wrong password: the device reports it, the session stays usable.
        let mut seen = Vec::new();
        let err = session
            .provision_with(&[network("home", "wrong")], "lamp-1", None, |s| {
                seen.push(*s)
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ProvisionError::Device {
                failure: Failure::WifiConnect,
                ..
            }
        ));
        assert_eq!(
            seen,
            [Status::Connecting, Status::Failed(Failure::WifiConnect)]
        );

        // Fixed, over the same session.
        let provisioned = session
            .provision(&[network("home", "right")], "lamp-1")
            .await
            .unwrap();
        assert_eq!(provisioned.ssid, "home");
        assert_eq!(provisioned.ticket.endpoint, secret.public());

        let (joined, mut storage, _) = device.join().unwrap();
        assert_eq!(joined.ssid, "home");
        // The device holds exactly the secret in the ticket we got back.
        let stored = device::load_pairing_secret(&mut storage).unwrap();
        assert_eq!(stored, provisioned.ticket.secret);
        assert_eq!(device::load_name(&mut storage).as_deref(), Some("lamp-1"));
        // And comes back on its own after a reboot.
        let mut wifi = FakeWifi::new(vec![("home", -50, "right")]);
        let creds = device::load_credentials(&mut storage).unwrap();
        let rejoined = device::connect(&mut wifi, &creds, &mut (), |_| panic!("no retry needed"));
        assert_eq!(rejoined.ssid, "home");
    });
}

#[test]
fn not_in_range_then_another_network() {
    let (client, _, device) = device(FakeWifi::new(vec![("office", -60, "pw")]));
    block_on(async {
        let mut session = Session::connect(client).await.unwrap();
        let err = session
            .provision(&[network("home", "pw")], "")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ProvisionError::Device {
                failure: Failure::NotFound,
                ..
            }
        ));
        let provisioned = session
            .provision(&[network("home", "pw"), network("office", "pw")], "")
            .await
            .unwrap();
        assert_eq!(provisioned.ssid, "office");
    });
    let (_, _, wifi) = device.join().unwrap();
    // "home" was never in range, so never tried.
    assert_eq!(wifi.attempts, ["office"]);
}

#[test]
fn reprovision_keeps_ticket() {
    let (client, _, device) = device(FakeWifi::new(vec![("home", -50, "pw")]));
    let first = block_on(async {
        let mut session = Session::connect(client).await.unwrap();
        session
            .provision(&[network("home", "pw")], "lamp-1")
            .await
            .unwrap()
    });
    let (_, mut storage, _) = device.join().unwrap();

    // Later: the device moved, and gets its new network with the old ticket.
    let secret = device::load_or_create_identity(&mut storage, |_| panic!()).unwrap();
    let (msg_tx, msg_rx) = mpsc::channel();
    let (status_tx, status_rx) = async_mpsc::unbounded();
    let device = thread::spawn(move || {
        let mut wifi = FakeWifi::new(vec![("office", -50, "pw2")]);
        let mut transport = DeviceEnd {
            messages: msg_rx,
            statuses: status_tx,
        };
        device::provision(&mut storage, &mut wifi, &secret, &mut transport).unwrap();
        storage
    });
    let client = ClientEnd {
        identity: *first.ticket.endpoint.as_bytes(),
        messages: msg_tx,
        statuses: status_rx,
    };
    let second = block_on(async {
        let mut session = Session::connect(client).await.unwrap();
        let other = PairingTicket {
            endpoint: SecretKey::from_bytes(&[7; 32]).public(),
            secret: first.ticket.secret.clone(),
        };
        let err = session
            .reprovision(&[network("office", "pw2")], "lamp-1", &other)
            .await
            .unwrap_err();
        assert!(matches!(err, ProvisionError::WrongTicket { .. }));
        session
            .reprovision(&[network("office", "pw2")], "lamp-1", &first.ticket)
            .await
            .unwrap()
    });
    assert_eq!(second.ticket, first.ticket);
    let mut storage = device.join().unwrap();
    assert_eq!(
        device::load_pairing_secret(&mut storage),
        Some(first.ticket.secret.clone())
    );
    assert_eq!(device::load_name(&mut storage).as_deref(), Some("lamp-1"));
}
