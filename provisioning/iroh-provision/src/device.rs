//! The device side, independent of the platform: keeping the identity and the
//! provisioned state in a [`Storage`], joining one of the networks over a
//! [`Wifi`], and receiving messages over a [`Transport`].
//!
//! A typical boot:
//!
//! ```ignore
//! let secret = device::load_or_create_identity(&mut storage, fill_random)?;
//! let joined = match device::join_stored(&mut storage, &mut wifi, 3) {
//!     Some(joined) => joined,
//!     None => device::provision(&mut storage, &mut wifi, &secret, &mut transport)?,
//! };
//! ```

use std::net::Ipv4Addr;

use iroh_base::SecretKey;
use log::{info, warn};

use crate::protocol::{
    open, Credentials, Error, Failure, Message, Network, PairingSecret, Provisioning, Status,
    MAX_NAME_LEN, MAX_NETWORKS, MAX_PASSWORD_LEN, MAX_SSID_LEN, PAIRING_SECRET_LEN,
};

/// The endpoint's secret key (32 bytes). Survives [`forget`].
pub const KEY_SECRET: &str = "secret";
/// The networks, in [`Credentials::to_bytes`] format.
pub const KEY_NETWORKS: &str = "networks";
/// The name given at provisioning, UTF-8 (may be empty).
pub const KEY_NAME: &str = "name";
/// The unredeemed pairing secret (32 bytes).
pub const KEY_PAIRING: &str = "pairing";

/// Largest stored [`Credentials`]: count + per network two lengths and the
/// maximum SSID and password.
const MAX_NETWORKS_LEN: usize = 1 + MAX_NETWORKS * (2 + MAX_SSID_LEN + MAX_PASSWORD_LEN);

/// Small persistent key-value storage, e.g. an NVS namespace.
pub trait Storage {
    type Error: std::fmt::Display;

    /// Read `key` into `buf`; `None` if it's not there.
    fn get<'a>(&mut self, key: &str, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Self::Error>;
    fn set(&mut self, key: &str, value: &[u8]) -> Result<(), Self::Error>;
    /// Removing a key that's not there is not an error.
    fn remove(&mut self, key: &str) -> Result<(), Self::Error>;
}

/// A network seen in a scan.
#[derive(Debug, Clone)]
pub struct AccessPoint {
    /// Empty for a hidden network.
    pub ssid: String,
    /// Signal strength in dBm.
    pub rssi: i8,
}

/// The WiFi driver, in station mode.
pub trait Wifi {
    /// Scan, including hidden networks. A failed scan is an empty result.
    fn scan(&mut self) -> Vec<AccessPoint>;
    /// Join one network and wait for an IP address.
    fn join(&mut self, network: &Network) -> Result<Ipv4Addr, Failure>;
}

/// How provisioning messages reach the device, e.g. a BLE GATT service.
pub trait Transport {
    /// Block until the next sealed message arrives.
    fn recv(&mut self) -> Vec<u8>;
    /// Report the current status to the client.
    fn set_status(&mut self, status: Status);
}

/// A network the device joined.
#[derive(Debug, Clone)]
pub struct Joined {
    /// Index in the list of networks.
    pub network: u8,
    pub ssid: String,
    pub ip: Ipv4Addr,
}

/// Load the endpoint's secret key, or generate and store one.
///
/// `fill_random` must be a cryptographic RNG; on an ESP32 the hardware RNG is
/// one only while WiFi or BLE is running. A storage error is returned rather
/// than papered over with a fresh key: that would silently change the endpoint
/// id, and every peer that knew the device would lose it.
pub fn load_or_create_identity<S: Storage>(
    storage: &mut S,
    fill_random: impl FnOnce(&mut [u8]),
) -> Result<SecretKey, S::Error> {
    let mut seed = [0u8; 32];
    if let Some(stored) = storage.get(KEY_SECRET, &mut seed)? {
        if stored.len() == 32 {
            return Ok(SecretKey::from_bytes(&seed));
        }
        warn!("Stored identity has the wrong length, generating a new one");
    } else {
        info!("No identity yet, generating one");
    }
    fill_random(&mut seed);
    storage.set(KEY_SECRET, &seed)?;
    Ok(SecretKey::from_bytes(&seed))
}

pub fn load_credentials<S: Storage>(storage: &mut S) -> Option<Credentials> {
    let mut buf = [0u8; MAX_NETWORKS_LEN];
    let bytes = storage.get(KEY_NETWORKS, &mut buf).ok()??;
    Credentials::from_bytes(bytes)
        .inspect_err(|e| warn!("Ignoring stored networks: {e}"))
        .ok()
}

/// The name, if one was given.
pub fn load_name<S: Storage>(storage: &mut S) -> Option<String> {
    let mut buf = [0u8; MAX_NAME_LEN];
    let bytes = storage.get(KEY_NAME, &mut buf).ok()??;
    let name = std::str::from_utf8(bytes).ok()?;
    (!name.is_empty()).then(|| name.to_owned())
}

/// The pairing secret, if one was provisioned and not redeemed yet.
pub fn load_pairing_secret<S: Storage>(storage: &mut S) -> Option<PairingSecret> {
    let mut buf = [0u8; PAIRING_SECRET_LEN];
    let bytes = storage.get(KEY_PAIRING, &mut buf).ok()??;
    Some(PairingSecret(bytes.try_into().ok()?))
}

/// Store everything from a provisioning message. A new pairing secret replaces
/// an unredeemed one.
pub fn store<S: Storage>(storage: &mut S, provisioning: &Provisioning) -> Result<(), S::Error> {
    let networks = provisioning
        .credentials
        .to_bytes()
        .expect("validated when opened");
    storage.set(KEY_NETWORKS, &networks)?;
    storage.set(KEY_NAME, provisioning.name.as_bytes())?;
    storage.set(KEY_PAIRING, &provisioning.pairing_secret.0)
}

/// Forget networks, name and pairing secret, e.g. on a long press of a reset
/// button. The identity stays, so the endpoint id doesn't change.
pub fn forget<S: Storage>(storage: &mut S) -> Result<(), S::Error> {
    for key in [KEY_NETWORKS, KEY_NAME, KEY_PAIRING] {
        storage.remove(key)?;
    }
    Ok(())
}

/// Join one of the networks: scan, then try the ones in range strongest first.
///
/// A hidden network shows up in the scan without its SSID, so the networks not
/// seen are tried too, but only if a hidden network is around: each failed
/// attempt costs the driver's full connect timeout.
pub fn join_any<W: Wifi>(wifi: &mut W, creds: &Credentials) -> Result<Joined, Failure> {
    let visible = wifi.scan();
    let hidden_nearby = visible.iter().any(|ap| ap.ssid.is_empty());
    let signal = |network: &Network| {
        visible
            .iter()
            .filter(|ap| ap.ssid == network.ssid)
            .map(|ap| ap.rssi)
            .max()
    };
    let mut candidates: Vec<(usize, Option<i8>)> = creds
        .networks
        .iter()
        .enumerate()
        .map(|(i, network)| (i, signal(network)))
        .collect();
    // In range first, strongest first; `None` (not seen) sorts last.
    candidates.sort_by_key(|&(_, signal)| std::cmp::Reverse(signal));

    let mut failure = Failure::NotFound;
    for (i, signal) in candidates {
        let network = &creds.networks[i];
        match signal {
            Some(rssi) => info!("Trying {:?} ({rssi} dBm)", network.ssid),
            None if hidden_nearby => info!("Trying {:?} (maybe hidden)", network.ssid),
            None => {
                info!("Skipping {:?}: not in range", network.ssid);
                continue;
            }
        }
        match wifi.join(network) {
            Ok(ip) => {
                return Ok(Joined {
                    network: i as u8,
                    ssid: network.ssid.clone(),
                    ip,
                })
            }
            // Only a network that's actually there makes "wrong password" (or
            // DHCP trouble) the better explanation than "not found".
            Err(f) if signal.is_some() => failure = f,
            Err(_) => {}
        }
    }
    Err(failure)
}

/// Join one of the stored networks, trying up to `rounds` times. `None` if
/// nothing is stored or nothing worked: time to [`provision`].
pub fn join_stored<S: Storage, W: Wifi>(
    storage: &mut S,
    wifi: &mut W,
    rounds: usize,
) -> Option<Joined> {
    let Some(creds) = load_credentials(storage) else {
        info!("No networks stored");
        return None;
    };
    (1..=rounds).find_map(|round| {
        info!("Joining a stored network (attempt {round}/{rounds})");
        join_any(wifi, &creds)
            .inspect_err(|failure| warn!("Join failed: {failure:?}"))
            .ok()
    })
}

/// Receive messages until one opens and one of its networks joins. Then store
/// it and return. Every step is reported over the transport.
pub fn provision<S: Storage, W: Wifi, T: Transport>(
    storage: &mut S,
    wifi: &mut W,
    secret: &SecretKey,
    transport: &mut T,
) -> Result<Joined, S::Error> {
    let set_status = |transport: &mut T, status: Status| {
        info!("Status: {status:?}");
        transport.set_status(status);
    };
    set_status(transport, Status::Unprovisioned);
    loop {
        let sealed = transport.recv();
        let provisioning = match open(secret, &sealed) {
            Ok(Message::Provision(provisioning)) => provisioning,
            Err(e) => {
                warn!("Rejected message: {e}");
                let failure = match e {
                    Error::Unsupported { .. } => Failure::Unsupported,
                    _ => Failure::BadMessage,
                };
                set_status(transport, Status::Failed(failure));
                continue;
            }
        };
        let ssids: Vec<&str> = provisioning
            .credentials
            .networks
            .iter()
            .map(|n| n.ssid.as_str())
            .collect();
        info!("Received {:?} with networks {ssids:?}", provisioning.name);
        set_status(transport, Status::Connecting);
        match join_any(wifi, &provisioning.credentials) {
            Ok(joined) => {
                store(storage, &provisioning)?;
                set_status(
                    transport,
                    Status::Connected {
                        network: joined.network,
                        ip: joined.ip.octets(),
                    },
                );
                return Ok(joined);
            }
            Err(failure) => set_status(transport, Status::Failed(failure)),
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! In-memory [`Storage`] and a scripted [`Wifi`], for tests.

    use std::collections::HashMap;

    use super::*;

    #[derive(Default)]
    pub struct MemStorage(pub HashMap<String, Vec<u8>>);

    impl Storage for MemStorage {
        type Error = std::convert::Infallible;

        fn get<'a>(
            &mut self,
            key: &str,
            buf: &'a mut [u8],
        ) -> Result<Option<&'a [u8]>, Self::Error> {
            Ok(self.0.get(key).map(|v| {
                buf[..v.len()].copy_from_slice(v);
                &buf[..v.len()]
            }))
        }

        fn set(&mut self, key: &str, value: &[u8]) -> Result<(), Self::Error> {
            self.0.insert(key.to_owned(), value.to_vec());
            Ok(())
        }

        fn remove(&mut self, key: &str) -> Result<(), Self::Error> {
            self.0.remove(key);
            Ok(())
        }
    }

    /// Networks around: `(ssid, rssi, password)`; an empty SSID is hidden but
    /// joinable under its real name, given as `hidden_as`.
    pub struct FakeWifi {
        pub around: Vec<(&'static str, i8, &'static str)>,
        pub hidden_as: Option<&'static str>,
        pub attempts: Vec<String>,
    }

    impl FakeWifi {
        pub fn new(around: Vec<(&'static str, i8, &'static str)>) -> Self {
            Self {
                around,
                hidden_as: None,
                attempts: Vec::new(),
            }
        }
    }

    impl Wifi for FakeWifi {
        fn scan(&mut self) -> Vec<AccessPoint> {
            self.around
                .iter()
                .map(|&(ssid, rssi, _)| AccessPoint {
                    ssid: ssid.into(),
                    rssi,
                })
                .collect()
        }

        fn join(&mut self, network: &Network) -> Result<Ipv4Addr, Failure> {
            self.attempts.push(network.ssid.clone());
            let found = self.around.iter().find(|&&(ssid, _, _)| {
                ssid == network.ssid || (ssid.is_empty() && self.hidden_as == Some(&network.ssid))
            });
            match found {
                Some(&(_, _, password)) if password == network.password => {
                    Ok(Ipv4Addr::new(192, 168, 0, 10))
                }
                _ => Err(Failure::WifiConnect),
            }
        }
    }

    pub fn network(ssid: &str, password: &str) -> Network {
        Network {
            ssid: ssid.into(),
            password: password.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    fn creds(networks: Vec<Network>) -> Credentials {
        Credentials { networks }
    }

    #[test]
    fn identity_is_created_once() {
        let mut storage = MemStorage::default();
        let a = load_or_create_identity(&mut storage, |b| b.fill(1)).unwrap();
        let b = load_or_create_identity(&mut storage, |_| panic!("must not regenerate")).unwrap();
        assert_eq!(a.public(), b.public());
    }

    #[test]
    fn strongest_known_network_first() {
        let mut wifi = FakeWifi::new(vec![("weak", -80, "pw"), ("strong", -40, "pw")]);
        let joined = join_any(
            &mut wifi,
            &creds(vec![network("weak", "pw"), network("strong", "pw")]),
        )
        .unwrap();
        assert_eq!(joined.ssid, "strong");
        assert_eq!(joined.network, 1);
        assert_eq!(wifi.attempts, ["strong"]);
    }

    #[test]
    fn not_in_range_is_skipped() {
        let mut wifi = FakeWifi::new(vec![("other", -50, "pw")]);
        let result = join_any(&mut wifi, &creds(vec![network("absent", "pw")]));
        assert_eq!(result.unwrap_err(), Failure::NotFound);
        assert!(wifi.attempts.is_empty(), "no slow blind attempts");
    }

    #[test]
    fn wrong_password_beats_not_found() {
        let mut wifi = FakeWifi::new(vec![("home", -50, "right")]);
        let result = join_any(
            &mut wifi,
            &creds(vec![network("home", "wrong"), network("absent", "x")]),
        );
        assert_eq!(result.unwrap_err(), Failure::WifiConnect);
    }

    #[test]
    fn hidden_network_is_tried_when_one_is_around() {
        let mut wifi = FakeWifi::new(vec![("", -60, "pw")]);
        wifi.hidden_as = Some("secret-net");
        let joined = join_any(&mut wifi, &creds(vec![network("secret-net", "pw")])).unwrap();
        assert_eq!(joined.ssid, "secret-net");
    }

    #[test]
    fn forget_keeps_identity() {
        let mut storage = MemStorage::default();
        let id = load_or_create_identity(&mut storage, |b| b.fill(3)).unwrap();
        let provisioning = Provisioning {
            credentials: creds(vec![network("home", "pw")]),
            name: "lamp-1".into(),
            pairing_secret: PairingSecret([5; 32]),
        };
        store(&mut storage, &provisioning).unwrap();
        assert_eq!(load_name(&mut storage).as_deref(), Some("lamp-1"));
        assert_eq!(
            load_pairing_secret(&mut storage),
            Some(PairingSecret([5; 32]))
        );
        forget(&mut storage).unwrap();
        assert!(load_credentials(&mut storage).is_none());
        assert!(load_name(&mut storage).is_none());
        assert!(load_pairing_secret(&mut storage).is_none());
        let again = load_or_create_identity(&mut storage, |_| panic!()).unwrap();
        assert_eq!(again.public(), id.public());
    }
}
