//! Provisioning WiFi credentials to an ESP32 over BLE, encrypted to the device's
//! iroh identity.
//!
//! The device generates an ed25519 key on first boot (its iroh endpoint id) and
//! exposes the public half over BLE. The provisioning client seals the WiFi
//! credentials to that key with HPKE (RFC 9180, DHKEM(X25519, HKDF-SHA256) +
//! ChaCha20Poly1305), using the X25519 form of the ed25519 key. So the password
//! never crosses the air in the clear, and only the holder of the endpoint's
//! secret key can open it — the same key that later authenticates every iroh
//! connection to the device.
//!
//! The same message carries a name for the device and a pairing secret chosen
//! by the client. The client combines the secret with the endpoint id into a
//! single-use [`PairingTicket`]: the endpoint id alone is public, so it can't
//! be what authorizes control. Whoever redeems the ticket over iroh first
//! becomes an owner, authenticated from then on by their own endpoint id.
//!
//! This defeats passive sniffing. It does not, by itself, defeat an active
//! attacker impersonating the device during provisioning: for that, compare the
//! endpoint id the client shows with the one the device prints on its serial
//! console.
//!
//! # GATT layout
//!
//! One primary service ([`SERVICE_UUID`]) with three characteristics:
//!
//! - [`IDENTITY_UUID`] (read): the 32 byte ed25519 public key.
//! - [`CREDENTIALS_UUID`] (write): a sealed [`Provisioning`] message, see [`seal`].
//! - [`STATUS_UUID`] (read, notify): the encoded [`Status`].

use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, OpModeR,
};
use iroh_base::{PublicKey, SecretKey};

pub const SERVICE_UUID: &str = "08c6b3c5-8a57-40af-8eec-45a746f70d3f";
pub const IDENTITY_UUID: &str = "18969798-f386-44a1-94bc-e1d98ae283bf";
pub const CREDENTIALS_UUID: &str = "bca33919-6200-4574-9c7d-04d5b20237f9";
pub const STATUS_UUID: &str = "2484ca31-949d-4bbe-a7b0-b2f4016532f6";

/// Prefix of the BLE device name; the device appends iroh's short form of its
/// endpoint id, so several boards in one room can be told apart.
pub const NAME_PREFIX: &str = "iroh-";

/// Version byte at the start of a sealed credentials message.
const VERSION: u8 = 1;
/// HPKE `info`: domain separation, so a ciphertext for this protocol can't be
/// replayed into any other use of the same key.
const INFO: &[u8] = b"iroh-esp32-provisioning/v1";

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

/// Length of the HPKE encapsulated key (an X25519 public key).
const ENC_LEN: usize = 32;
/// Length of the ChaCha20Poly1305 tag.
const TAG_LEN: usize = 16;

pub const MAX_SSID_LEN: usize = 32;
pub const MAX_PASSWORD_LEN: usize = 64;
/// Networks per message. Even at the maximum SSID, password and name lengths,
/// a sealed message with 4 networks (508 bytes) stays under the 512 byte limit
/// of a BLE characteristic value, so it's always a single write.
pub const MAX_NETWORKS: usize = 4;
pub const MAX_NAME_LEN: usize = 32;
pub const PAIRING_SECRET_LEN: usize = 32;

/// What a message does with the device's stored state. It's the
/// first byte of the plaintext, so it's authenticated along with the rest.
///
/// Only [`Op::Replace`] exists so far. The byte leaves room for spreading a list
/// over several messages later (appending networks, or chunks of one large
/// message) without breaking existing devices: they answer an unknown op with
/// [`Failure::Unsupported`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Op {
    /// Replace the stored networks, name and pairing secret with the ones in
    /// this message. Owners who already redeemed a ticket stay.
    Replace = 0,
}

/// One WiFi network.
#[derive(Clone, PartialEq, Eq)]
pub struct Network {
    pub ssid: String,
    pub password: String,
}

impl std::fmt::Debug for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Network")
            .field("ssid", &self.ssid)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// The networks the device may join, as carried inside the sealed message. A
/// new message replaces the whole list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub networks: Vec<Network>,
}

/// A random secret that, with the endpoint id, makes a [`PairingTicket`].
#[derive(Clone, PartialEq, Eq)]
pub struct PairingSecret(pub [u8; PAIRING_SECRET_LEN]);

impl std::fmt::Debug for PairingSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingSecret(<redacted>)")
    }
}

impl PairingSecret {
    /// A fresh secret from the OS RNG (`crypto.getRandomValues` in a browser).
    #[cfg(feature = "seal")]
    pub fn generate() -> Self {
        let mut secret = [0u8; PAIRING_SECRET_LEN];
        getrandom::fill(&mut secret).expect("no system RNG");
        Self(secret)
    }

    /// Constant-time comparison, for checking a presented secret.
    pub fn matches(&self, presented: &[u8]) -> bool {
        presented.len() == PAIRING_SECRET_LEN
            && self
                .0
                .iter()
                .zip(presented)
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    }
}

/// Everything a provisioning message carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provisioning {
    pub credentials: Credentials,
    /// A human readable name for the device. May be empty.
    pub name: String,
    pub pairing_secret: PairingSecret,
}

impl Provisioning {
    /// `credentials | len(name) | name | pairing secret (32)`.
    #[cfg_attr(not(feature = "seal"), allow(dead_code))]
    fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidCredentials);
        }
        let mut out = self.credentials.encode()?;
        out.push(self.name.len() as u8);
        out.extend_from_slice(self.name.as_bytes());
        out.extend_from_slice(&self.pairing_secret.0);
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (credentials, rest) = Credentials::decode_prefix(bytes)?;
        let (name, rest) = string_field(rest)?;
        if name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidCredentials);
        }
        let pairing_secret = rest.try_into().map_err(|_| Error::InvalidCredentials)?;
        Ok(Provisioning {
            credentials,
            name,
            pairing_secret: PairingSecret(pairing_secret),
        })
    }
}

/// A single-use ticket to become an owner of a device: its endpoint id, plus
/// the pairing secret it was provisioned with.
///
/// Formatted as `pair` + lowercase base32 of `version (0) | endpoint id (32) |
/// secret (32)`. The version byte leaves room for adding e.g. relay hints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingTicket {
    pub endpoint: PublicKey,
    pub secret: PairingSecret,
}

const TICKET_PREFIX: &str = "pair";
const TICKET_VERSION: u8 = 0;

impl std::fmt::Display for PairingTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut bytes = Vec::with_capacity(1 + 32 + PAIRING_SECRET_LEN);
        bytes.push(TICKET_VERSION);
        bytes.extend_from_slice(self.endpoint.as_bytes());
        bytes.extend_from_slice(&self.secret.0);
        let encoded = data_encoding::BASE32_NOPAD.encode(&bytes);
        write!(f, "{TICKET_PREFIX}{}", encoded.to_ascii_lowercase())
    }
}

impl std::str::FromStr for PairingTicket {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let encoded = s.strip_prefix(TICKET_PREFIX).ok_or(Error::Malformed)?;
        let bytes = data_encoding::BASE32_NOPAD
            .decode(encoded.to_ascii_uppercase().as_bytes())
            .map_err(|_| Error::Malformed)?;
        match bytes.split_first() {
            Some((&TICKET_VERSION, rest)) if rest.len() == 32 + PAIRING_SECRET_LEN => {
                let (endpoint, secret) = rest.split_at(32);
                Ok(PairingTicket {
                    endpoint: PublicKey::try_from(endpoint).map_err(|_| Error::InvalidIdentity)?,
                    secret: PairingSecret(secret.try_into().expect("checked length")),
                })
            }
            Some(_) => Err(Error::Unsupported),
            None => Err(Error::Malformed),
        }
    }
}

/// `len | bytes`, as UTF-8, with the length as one byte.
fn string_field(bytes: &[u8]) -> Result<(String, &[u8]), Error> {
    let (&len, rest) = bytes.split_first().ok_or(Error::InvalidCredentials)?;
    if rest.len() < len as usize {
        return Err(Error::InvalidCredentials);
    }
    let (value, rest) = rest.split_at(len as usize);
    let value = std::str::from_utf8(value).map_err(|_| Error::InvalidCredentials)?;
    Ok((value.to_owned(), rest))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Not a message this version understands, or truncated.
    Malformed,
    /// HPKE open failed: sealed to a different key, or tampered with.
    Decrypt,
    /// Decrypted fine, but no networks, too many, an SSID, password or name out
    /// of range or not UTF-8, or no pairing secret.
    InvalidCredentials,
    /// The given identity is not a valid ed25519 public key.
    InvalidIdentity,
    /// Decrypted fine, but asks for an operation this version doesn't support.
    Unsupported,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::Malformed => "malformed message",
            Error::Decrypt => "decryption failed",
            Error::InvalidCredentials => "invalid credentials",
            Error::InvalidIdentity => "invalid identity",
            Error::Unsupported => "unsupported operation",
        })
    }
}

impl std::error::Error for Error {}

impl Network {
    fn validate(&self) -> Result<(), Error> {
        // Empty password is an open network. WPA2 needs 8..=63 chars or 64 hex
        // digits, but that's for the WiFi driver to reject, with a better error.
        if self.ssid.is_empty()
            || self.ssid.len() > MAX_SSID_LEN
            || self.password.len() > MAX_PASSWORD_LEN
        {
            return Err(Error::InvalidCredentials);
        }
        Ok(())
    }
}

impl Credentials {
    /// `count | (len(ssid) | ssid | len(password) | password)*`, counts and
    /// lengths as one byte each. Also the format the device stores them in.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = vec![self.networks.len() as u8];
        for network in &self.networks {
            out.push(network.ssid.len() as u8);
            out.extend_from_slice(network.ssid.as_bytes());
            out.push(network.password.len() as u8);
            out.extend_from_slice(network.password.as_bytes());
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        match Self::decode_prefix(bytes)? {
            (creds, []) => Ok(creds),
            _ => Err(Error::InvalidCredentials),
        }
    }

    /// Decode from the start of `bytes`, returning the rest.
    fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (&count, mut rest) = bytes.split_first().ok_or(Error::InvalidCredentials)?;
        let mut networks = Vec::with_capacity(count.min(MAX_NETWORKS as u8) as usize);
        for _ in 0..count {
            let (ssid, r) = string_field(rest)?;
            let (password, r) = string_field(r)?;
            networks.push(Network { ssid, password });
            rest = r;
        }
        let creds = Credentials { networks };
        creds.validate()?;
        Ok((creds, rest))
    }

    fn validate(&self) -> Result<(), Error> {
        if self.networks.is_empty() || self.networks.len() > MAX_NETWORKS {
            return Err(Error::InvalidCredentials);
        }
        self.networks.iter().try_for_each(Network::validate)
    }
}

/// The X25519 public key HPKE seals to, derived from the ed25519 endpoint id.
#[cfg_attr(not(feature = "seal"), allow(dead_code))]
fn kem_public_key(identity: &PublicKey) -> Result<<Kem as hpke::Kem>::PublicKey, Error> {
    let montgomery = identity.as_verifying_key().to_montgomery();
    <Kem as hpke::Kem>::PublicKey::from_bytes(&montgomery.to_bytes())
        .map_err(|_| Error::InvalidIdentity)
}

/// The matching X25519 private key: the ed25519 secret scalar.
fn kem_private_key(secret: &SecretKey) -> <Kem as hpke::Kem>::PrivateKey {
    <Kem as hpke::Kem>::PrivateKey::from_bytes(&secret.as_signing_key().to_scalar_bytes())
        .expect("any 32 bytes are a valid X25519 private key")
}

/// Seal `provisioning` to the device with endpoint id `identity`.
///
/// Wire format: `VERSION | enc (32) | ciphertext | tag (16)`, with the
/// endpoint id as associated data. The plaintext is `op | credentials |
/// len(name) | name | pairing secret (32)`, see [`Op`] and
/// [`Credentials::encode`].
#[cfg(feature = "seal")]
pub fn seal(identity: &PublicKey, provisioning: &Provisioning) -> Result<Vec<u8>, Error> {
    use hpke::Serializable;
    let pk = kem_public_key(identity)?;
    let mut plaintext = vec![Op::Replace as u8];
    plaintext.extend(provisioning.encode()?);
    let (enc, ciphertext) = hpke::single_shot_seal::<Aead, Kdf, Kem>(
        &hpke::OpModeS::Base,
        &pk,
        INFO,
        &plaintext,
        identity.as_bytes(),
    )
    .map_err(|_| Error::InvalidIdentity)?;
    let mut out = Vec::with_capacity(1 + ENC_LEN + ciphertext.len());
    out.push(VERSION);
    out.extend_from_slice(&enc.to_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a message produced by [`seal`], on the device holding `secret`.
pub fn open(secret: &SecretKey, message: &[u8]) -> Result<Provisioning, Error> {
    let (&version, rest) = message.split_first().ok_or(Error::Malformed)?;
    if version != VERSION || rest.len() < ENC_LEN + TAG_LEN {
        return Err(Error::Malformed);
    }
    let (enc, ciphertext) = rest.split_at(ENC_LEN);
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(enc).map_err(|_| Error::Malformed)?;
    let plaintext = hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &kem_private_key(secret),
        &enc,
        INFO,
        ciphertext,
        secret.public().as_bytes(),
    )
    .map_err(|_| Error::Decrypt)?;
    match plaintext.split_first() {
        Some((&op, rest)) if op == Op::Replace as u8 => Provisioning::decode(rest),
        Some(_) => Err(Error::Unsupported),
        None => Err(Error::InvalidCredentials),
    }
}

/// Why the last provisioning attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Failure {
    /// The credentials message didn't open, see [`Error`].
    BadMessage = 1,
    /// A network was in range, but joining failed: usually a wrong password.
    WifiConnect = 2,
    /// Associated, but no IP address (DHCP) in time.
    NoIp = 3,
    /// None of the networks showed up in a scan, and blind attempts (for hidden
    /// networks) failed too.
    NotFound = 4,
    /// The message asked for an [`Op`] this firmware doesn't know.
    Unsupported = 5,
}

/// Device state, as exposed on the status characteristic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Waiting for credentials.
    Unprovisioned,
    /// Got credentials, trying to join the network.
    Connecting,
    /// Joined the network at this index of the list, with this IPv4 address.
    /// The whole list is stored.
    Connected { network: u8, ip: [u8; 4] },
    /// The last attempt failed; still waiting for (new) credentials.
    Failed(Failure),
}

impl Status {
    /// `state` byte, followed by the network index and IPv4 address for
    /// `Connected`, or the failure code for `Failed`.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Status::Unprovisioned => vec![0],
            Status::Connecting => vec![1],
            Status::Connected { network, ip } => vec![2, *network, ip[0], ip[1], ip[2], ip[3]],
            Status::Failed(failure) => vec![3, *failure as u8],
        }
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        Some(match bytes {
            [0] => Status::Unprovisioned,
            [1] => Status::Connecting,
            [2, network, a, b, c, d] => Status::Connected {
                network: *network,
                ip: [*a, *b, *c, *d],
            },
            [3, 1] => Status::Failed(Failure::BadMessage),
            [3, 2] => Status::Failed(Failure::WifiConnect),
            [3, 3] => Status::Failed(Failure::NoIp),
            [3, 4] => Status::Failed(Failure::NotFound),
            [3, 5] => Status::Failed(Failure::Unsupported),
            _ => return None,
        })
    }
}

/// The BLE device name for an identity, e.g. `iroh-1a2b3c4d5e`.
pub fn device_name(identity: &PublicKey) -> String {
    format!("{NAME_PREFIX}{}", identity.fmt_short())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::Serializable;

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn x25519_conversion_matches() {
        // The public key we seal to must be the one the private scalar opens.
        let sk = key(7);
        let from_secret = <Kem as hpke::Kem>::sk_to_pk(&kem_private_key(&sk));
        let from_public = kem_public_key(&sk.public()).unwrap();
        assert_eq!(from_secret.to_bytes(), from_public.to_bytes());
    }

    #[cfg(feature = "seal")]
    mod sealed {
        use super::*;

        fn network(ssid: &str, password: &str) -> Network {
            Network {
                ssid: ssid.into(),
                password: password.into(),
            }
        }

        fn provisioning(networks: Vec<Network>, name: &str) -> Provisioning {
            Provisioning {
                credentials: Credentials { networks },
                name: name.into(),
                pairing_secret: PairingSecret([9; PAIRING_SECRET_LEN]),
            }
        }

        fn prov() -> Provisioning {
            provisioning(
                vec![
                    network("iroh-workshop", "correct horse battery staple"),
                    network("home", ""),
                ],
                "lamp-1",
            )
        }

        #[test]
        fn roundtrip() {
            let sk = key(1);
            let msg = seal(&sk.public(), &prov()).unwrap();
            // version + enc + op + count + networks + name + secret + tag
            assert_eq!(
                msg.len(),
                1 + 32 + 1 + 1 + (2 + 13 + 28) + (2 + 4) + (1 + 6) + 32 + 16
            );
            assert_eq!(open(&sk, &msg).unwrap(), prov());
        }

        #[test]
        fn worst_case_fits_one_characteristic() {
            let longest = network(&"s".repeat(MAX_SSID_LEN), &"p".repeat(MAX_PASSWORD_LEN));
            let prov = provisioning(vec![longest; MAX_NETWORKS], &"n".repeat(MAX_NAME_LEN));
            let msg = seal(&key(1).public(), &prov).unwrap();
            assert_eq!(msg.len(), 508);
            assert!(msg.len() <= 512);
        }

        #[test]
        fn ticket_roundtrip() {
            let ticket = PairingTicket {
                endpoint: key(1).public(),
                secret: PairingSecret::generate(),
            };
            let s = ticket.to_string();
            assert!(s.starts_with("pair"));
            assert_eq!(s, s.to_ascii_lowercase());
            assert_eq!(s.parse::<PairingTicket>().unwrap(), ticket);
            assert!("pairxyz".parse::<PairingTicket>().is_err());
            assert!(s[4..].parse::<PairingTicket>().is_err());
        }

        #[test]
        fn secret_matching() {
            let secret = PairingSecret::generate();
            assert!(secret.matches(&secret.0));
            assert!(!secret.matches(&[0; PAIRING_SECRET_LEN]));
            assert!(!secret.matches(&secret.0[..31]));
            assert_ne!(PairingSecret::generate(), secret);
        }

        #[test]
        fn unknown_op() {
            use hpke::Serializable;
            let sk = key(1);
            let mut plaintext = vec![7];
            plaintext.extend(prov().encode().unwrap());
            let pk = kem_public_key(&sk.public()).unwrap();
            let (enc, ct) = hpke::single_shot_seal::<Aead, Kdf, Kem>(
                &hpke::OpModeS::Base,
                &pk,
                INFO,
                &plaintext,
                sk.public().as_bytes(),
            )
            .unwrap();
            let msg = [&[VERSION][..], &enc.to_bytes(), &ct].concat();
            assert_eq!(open(&sk, &msg), Err(Error::Unsupported));
        }

        #[test]
        fn wrong_key() {
            let msg = seal(&key(1).public(), &prov()).unwrap();
            assert_eq!(open(&key(2), &msg), Err(Error::Decrypt));
        }

        #[test]
        fn tampered() {
            let sk = key(1);
            let mut msg = seal(&sk.public(), &prov()).unwrap();
            *msg.last_mut().unwrap() ^= 1;
            assert_eq!(open(&sk, &msg), Err(Error::Decrypt));
            msg[0] = 2;
            assert_eq!(open(&sk, &msg), Err(Error::Malformed));
            assert_eq!(open(&sk, &msg[..10]), Err(Error::Malformed));
        }

        #[test]
        fn rejects_bad_credentials() {
            let id = key(1).public();
            let bad = |networks| seal(&id, &provisioning(networks, "x"));
            assert_eq!(bad(vec![]), Err(Error::InvalidCredentials));
            assert_eq!(bad(vec![network("", "")]), Err(Error::InvalidCredentials));
            assert_eq!(
                bad(vec![network(&"x".repeat(33), "")]),
                Err(Error::InvalidCredentials)
            );
            assert_eq!(
                bad(vec![network("a", ""); MAX_NETWORKS + 1]),
                Err(Error::InvalidCredentials)
            );
            let long_name = provisioning(vec![network("a", "")], &"n".repeat(MAX_NAME_LEN + 1));
            assert_eq!(seal(&id, &long_name), Err(Error::InvalidCredentials));
        }
    }

    #[test]
    fn status_roundtrip() {
        for status in [
            Status::Unprovisioned,
            Status::Connecting,
            Status::Connected {
                network: 1,
                ip: [192, 168, 1, 23],
            },
            Status::Failed(Failure::BadMessage),
            Status::Failed(Failure::WifiConnect),
            Status::Failed(Failure::NoIp),
            Status::Failed(Failure::NotFound),
            Status::Failed(Failure::Unsupported),
        ] {
            assert_eq!(Status::decode(&status.encode()), Some(status));
        }
        assert_eq!(Status::decode(&[9]), None);
    }

    #[test]
    fn names() {
        let id = key(1).public();
        let name = device_name(&id);
        assert_eq!(name.len(), NAME_PREFIX.len() + 10);
        assert!(id.to_string().starts_with(&name[NAME_PREFIX.len()..]));
    }
}
