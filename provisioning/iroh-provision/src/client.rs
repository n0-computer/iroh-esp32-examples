//! The client side: provision one device over some [`Transport`].
//!
//! ```ignore
//! let mut session = Session::connect(transport).await?;
//! println!("compare with the device's console: {}", session.endpoint());
//! let provisioned = session.provision(&networks, "lamp-1").await?;
//! println!("joined {}, ticket {}", provisioned.ssid, provisioned.ticket);
//! ```
//!
//! To provision many devices with the same networks, call
//! [`Session::provision`] with the same list on one session per device.
//!
//! To give a device new networks later (after a reset, or when it can't join
//! its old ones), use [`Session::reprovision`] with its existing ticket: only
//! the networks change, so the ticket stays valid.

use std::net::Ipv4Addr;

use iroh_base::PublicKey;
use n0_error::{e, stack_error, AnyError, StackError};

use crate::protocol::{
    seal, Credentials, Error, Failure, Message, Network, PairingSecret, PairingTicket,
    Provisioning, Status,
};

/// How a [`Session`] talks to one device. For BLE, these map to the identity,
/// credentials and status characteristics.
#[allow(async_fn_in_trait)]
pub trait Transport {
    type Error: StackError + 'static;

    /// The device's 32 byte ed25519 public key.
    async fn read_identity(&mut self) -> Result<[u8; 32], Self::Error>;

    /// Send a sealed message. Statuses from before this call must not be
    /// returned by [`Transport::next_status`] afterwards: a stale `Failed` would
    /// be taken as the answer to this message.
    async fn write_message(&mut self, sealed: &[u8]) -> Result<(), Self::Error>;

    /// Wait for the next status the device reports.
    async fn next_status(&mut self) -> Result<Status, Self::Error>;
}

/// A device that accepted a provisioning message.
#[derive(Debug, Clone)]
pub struct Provisioned {
    /// Single-use: endpoint id + the pairing secret the device now holds.
    pub ticket: PairingTicket,
    /// The network it joined, as given to [`Session::provision`].
    pub ssid: String,
    pub ip: Ipv4Addr,
}

#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum ProvisionError {
    /// The device rejected the message or couldn't join any network. The
    /// session stays usable: fix the networks and call `provision` again.
    #[error("{failure}")]
    Device { failure: Failure },
    /// Invalid input (no networks, too many, too long), or the device's
    /// identity isn't a valid key.
    #[error("invalid input")]
    Invalid { source: Error },
    /// [`Session::reprovision`] got a ticket for a different device.
    #[error("ticket is for another device")]
    WrongTicket {},
    /// The transport failed, e.g. the connection dropped.
    #[error("transport failed")]
    Transport { source: AnyError },
}

fn transport_error(err: impl StackError + 'static) -> ProvisionError {
    e!(ProvisionError::Transport, AnyError::from_stack(err))
}

/// A connection to one device in provisioning mode.
pub struct Session<T> {
    transport: T,
    endpoint: PublicKey,
}

impl<T: Transport> Session<T> {
    /// Read the device's identity.
    pub async fn connect(mut transport: T) -> Result<Self, ProvisionError> {
        let identity = transport.read_identity().await.map_err(transport_error)?;
        let endpoint = PublicKey::from_bytes(&identity)
            .map_err(|_| e!(ProvisionError::Invalid, e!(Error::InvalidIdentity)))?;
        Ok(Self {
            transport,
            endpoint,
        })
    }

    /// The device's endpoint id. Compare it with what the device prints, to
    /// rule out someone impersonating it.
    pub fn endpoint(&self) -> PublicKey {
        self.endpoint
    }

    /// Seal the networks, the name and a fresh pairing secret to the device,
    /// send them, and wait until it joined a network or failed.
    pub async fn provision(
        &mut self,
        networks: &[Network],
        name: &str,
    ) -> Result<Provisioned, ProvisionError> {
        self.provision_with(networks, name, None, |_| {}).await
    }

    /// Give a provisioned device new networks, keeping its `name` and the
    /// pairing secret of its `ticket`, so the ticket stays valid.
    pub async fn reprovision(
        &mut self,
        networks: &[Network],
        name: &str,
        ticket: &PairingTicket,
    ) -> Result<Provisioned, ProvisionError> {
        self.provision_with(networks, name, Some(ticket), |_| {})
            .await
    }

    /// [`Session::provision`] (`ticket` is `None`) or
    /// [`Session::reprovision`], reporting every status on the way (e.g.
    /// [`Status::Connecting`]) to `on_status`.
    pub async fn provision_with(
        &mut self,
        networks: &[Network],
        name: &str,
        ticket: Option<&PairingTicket>,
        mut on_status: impl FnMut(&Status),
    ) -> Result<Provisioned, ProvisionError> {
        let secret = match ticket {
            Some(ticket) if ticket.endpoint != self.endpoint => {
                return Err(e!(ProvisionError::WrongTicket));
            }
            Some(ticket) => ticket.secret.clone(),
            None => PairingSecret::generate(),
        };
        let message = Message::Provision(Provisioning {
            credentials: Credentials {
                networks: networks.to_vec(),
            },
            name: name.to_owned(),
            pairing_secret: secret.clone(),
        });
        let sealed =
            seal(&self.endpoint, &message).map_err(|err| e!(ProvisionError::Invalid, err))?;
        self.transport
            .write_message(&sealed)
            .await
            .map_err(transport_error)?;
        loop {
            let status = self
                .transport
                .next_status()
                .await
                .map_err(transport_error)?;
            on_status(&status);
            match status {
                Status::Unprovisioned | Status::Connecting => continue,
                Status::Failed(failure) => return Err(e!(ProvisionError::Device { failure })),
                Status::Connected { network, ip } => {
                    let ssid = networks
                        .get(network as usize)
                        .map(|n| n.ssid.clone())
                        .unwrap_or_default();
                    return Ok(Provisioned {
                        ticket: PairingTicket {
                            endpoint: self.endpoint,
                            secret,
                        },
                        ssid,
                        ip: Ipv4Addr::from(ip),
                    });
                }
            }
        }
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}
