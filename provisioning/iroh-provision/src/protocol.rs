//! Wire and storage formats, and sealing to the device's identity.

use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, OpModeR,
};
use iroh_base::{PublicKey, SecretKey};
use n0_error::{e, stack_error};
use serde::{Deserialize, Serialize};

pub const SERVICE_UUID: &str = "08c6b3c5-8a57-40af-8eec-45a746f70d3f";
pub const IDENTITY_UUID: &str = "18969798-f386-44a1-94bc-e1d98ae283bf";
pub const CREDENTIALS_UUID: &str = "bca33919-6200-4574-9c7d-04d5b20237f9";
pub const STATUS_UUID: &str = "2484ca31-949d-4bbe-a7b0-b2f4016532f6";

/// Prefix of the BLE device name; the device appends iroh's short form of its
/// endpoint id, so several boards in one room can be told apart.
pub const NAME_PREFIX: &str = "iroh-";

/// Version byte at the start of a sealed message, outside the encryption.
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

/// One WiFi network.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl Network {
    fn validate(&self) -> Result<(), Error> {
        // Empty password is an open network. WPA2 needs 8..=63 chars or 64 hex
        // digits, but that's for the WiFi driver to reject, with a better error.
        if self.ssid.is_empty()
            || self.ssid.len() > MAX_SSID_LEN
            || self.password.len() > MAX_PASSWORD_LEN
        {
            return Err(e!(Error::InvalidCredentials));
        }
        Ok(())
    }
}

/// The networks the device may join. Also what the device stores.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    pub networks: Vec<Network>,
}

impl Credentials {
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        Ok(postcard::to_allocvec(self).expect("serializing to a Vec can't fail"))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let creds: Self = postcard::from_bytes(bytes).map_err(|_| e!(Error::InvalidCredentials))?;
        creds.validate()?;
        Ok(creds)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.networks.is_empty() || self.networks.len() > MAX_NETWORKS {
            return Err(e!(Error::InvalidCredentials));
        }
        self.networks.iter().try_for_each(Network::validate)
    }
}

/// A random secret that, with the endpoint id, makes a [`PairingTicket`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingSecret(pub [u8; PAIRING_SECRET_LEN]);

impl std::fmt::Debug for PairingSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingSecret(<redacted>)")
    }
}

impl PairingSecret {
    /// A fresh secret from the OS RNG (`crypto.getRandomValues` in a browser).
    #[cfg(feature = "client")]
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

/// Networks, name and pairing secret for one device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provisioning {
    pub credentials: Credentials,
    /// A human readable name for the device. May be empty.
    pub name: String,
    pub pairing_secret: PairingSecret,
}

impl Provisioning {
    fn validate(&self) -> Result<(), Error> {
        if self.name.len() > MAX_NAME_LEN {
            return Err(e!(Error::InvalidCredentials));
        }
        self.credentials.validate()
    }
}

/// The sealed plaintext. Postcard writes the variant index first, so new kinds
/// of messages (appending networks, chunks of a larger one, ...) can be added
/// later; a device that doesn't know one answers [`Failure::Unsupported`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    /// Replace the stored networks, name and pairing secret. Owners who
    /// already redeemed a ticket stay.
    Provision(Provisioning),
}

impl Message {
    /// Number of variants; a higher variant index is a newer kind of message.
    const KINDS: u32 = 1;

    fn validate(&self) -> Result<(), Error> {
        match self {
            Message::Provision(p) => p.validate(),
        }
    }
}

/// A single-use ticket to become an owner of a device: its endpoint id, plus
/// the pairing secret it was provisioned with.
///
/// Formatted as `pair` + lowercase base32 of the postcard encoded payload. The
/// payload is an enum, so its first byte is a version, leaving room for adding
/// e.g. relay hints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingTicket {
    pub endpoint: PublicKey,
    pub secret: PairingSecret,
}

const TICKET_PREFIX: &str = "pair";

#[derive(Serialize, Deserialize)]
enum TicketPayload {
    V0 {
        endpoint: PublicKey,
        secret: PairingSecret,
    },
}

impl TicketPayload {
    /// Number of versions; a higher variant index is a newer ticket.
    const VERSIONS: u32 = 1;
}

/// Decode a postcard enum, telling a variant from a newer version (index
/// `>= known`, so [`Error::Unsupported`]) apart from garbage (`invalid`).
fn decode_enum<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    known: u32,
    invalid: Error,
) -> Result<T, Error> {
    // Postcard writes the variant index as a varint u32.
    match postcard::take_from_bytes::<u32>(bytes) {
        Ok((index, _)) if index >= known => Err(e!(Error::Unsupported)),
        _ => postcard::from_bytes(bytes).map_err(|_| invalid),
    }
}

impl std::fmt::Display for PairingTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let payload = TicketPayload::V0 {
            endpoint: self.endpoint,
            secret: self.secret.clone(),
        };
        let bytes = postcard::to_allocvec(&payload).expect("serializing to a Vec can't fail");
        let encoded = data_encoding::BASE32_NOPAD.encode(&bytes);
        write!(f, "{TICKET_PREFIX}{}", encoded.to_ascii_lowercase())
    }
}

impl std::str::FromStr for PairingTicket {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let encoded = s.strip_prefix(TICKET_PREFIX).ok_or(e!(Error::Malformed))?;
        let bytes = data_encoding::BASE32_NOPAD
            .decode(encoded.to_ascii_uppercase().as_bytes())
            .map_err(|_| e!(Error::Malformed))?;
        match decode_enum(&bytes, TicketPayload::VERSIONS, e!(Error::Malformed))? {
            TicketPayload::V0 { endpoint, secret } => Ok(PairingTicket { endpoint, secret }),
        }
    }
}

#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum Error {
    /// Not a message this version understands, or truncated.
    #[error("malformed message")]
    Malformed {},
    /// HPKE open failed: sealed to a different key, or tampered with.
    #[error("decryption failed")]
    Decrypt {},
    /// Decrypted fine, but doesn't decode, or no networks, too many, or an
    /// SSID, password or name out of range.
    #[error("invalid credentials")]
    InvalidCredentials {},
    /// The given identity is not a valid ed25519 public key.
    #[error("invalid identity")]
    InvalidIdentity {},
    /// Decrypted fine, but is a kind of message (or ticket) this version
    /// doesn't know.
    #[error("unsupported message")]
    Unsupported {},
}

/// The X25519 public key HPKE seals to, derived from the ed25519 endpoint id.
#[cfg_attr(not(feature = "client"), allow(dead_code))]
fn kem_public_key(identity: &PublicKey) -> Result<<Kem as hpke::Kem>::PublicKey, Error> {
    let montgomery = identity.as_verifying_key().to_montgomery();
    <Kem as hpke::Kem>::PublicKey::from_bytes(&montgomery.to_bytes())
        .map_err(|_| e!(Error::InvalidIdentity))
}

/// The matching X25519 private key: the ed25519 secret scalar.
fn kem_private_key(secret: &SecretKey) -> <Kem as hpke::Kem>::PrivateKey {
    <Kem as hpke::Kem>::PrivateKey::from_bytes(&secret.as_signing_key().to_scalar_bytes())
        .expect("any 32 bytes are a valid X25519 private key")
}

/// Seal `message` to the device with endpoint id `identity`.
///
/// Wire format: `VERSION | enc (32) | ciphertext | tag (16)`, with the
/// endpoint id as associated data. The plaintext is the postcard encoded
/// [`Message`].
#[cfg(feature = "client")]
pub fn seal(identity: &PublicKey, message: &Message) -> Result<Vec<u8>, Error> {
    use hpke::Serializable;
    message.validate()?;
    let pk = kem_public_key(identity)?;
    let plaintext = postcard::to_allocvec(message).expect("serializing to a Vec can't fail");
    let (enc, ciphertext) = hpke::single_shot_seal::<Aead, Kdf, Kem>(
        &hpke::OpModeS::Base,
        &pk,
        INFO,
        &plaintext,
        identity.as_bytes(),
    )
    .map_err(|_| e!(Error::InvalidIdentity))?;
    let mut out = Vec::with_capacity(1 + ENC_LEN + ciphertext.len());
    out.push(VERSION);
    out.extend_from_slice(&enc.to_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a message produced by [`seal`], on the device holding `secret`.
pub fn open(secret: &SecretKey, sealed: &[u8]) -> Result<Message, Error> {
    let (&version, rest) = sealed.split_first().ok_or(e!(Error::Malformed))?;
    if version != VERSION || rest.len() < ENC_LEN + TAG_LEN {
        return Err(e!(Error::Malformed));
    }
    let (enc, ciphertext) = rest.split_at(ENC_LEN);
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(enc).map_err(|_| e!(Error::Malformed))?;
    let plaintext = hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &kem_private_key(secret),
        &enc,
        INFO,
        ciphertext,
        secret.public().as_bytes(),
    )
    .map_err(|_| e!(Error::Decrypt))?;
    let message: Message = decode_enum(&plaintext, Message::KINDS, e!(Error::InvalidCredentials))?;
    message.validate()?;
    Ok(message)
}

/// Why the last provisioning attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Failure {
    /// The message didn't open, see [`Error`].
    BadMessage,
    /// A network was in range, but joining failed: usually a wrong password.
    WifiConnect,
    /// Associated, but no IP address (DHCP) in time.
    NoIp,
    /// None of the networks showed up in a scan, and blind attempts (for hidden
    /// networks) failed too.
    NotFound,
    /// A kind of [`Message`] this firmware doesn't know.
    Unsupported,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.describe())
    }
}

impl Failure {
    /// A short explanation for users.
    pub fn describe(&self) -> &'static str {
        match self {
            Failure::BadMessage => "the device could not open the message",
            Failure::WifiConnect => "could not join: probably a wrong password",
            Failure::NoIp => "joined, but got no IP address",
            Failure::NotFound => "none of the networks is in range",
            Failure::Unsupported => "the device's firmware is too old for this client",
        }
    }
}

/// Device state, as exposed on the status characteristic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    /// Waiting for credentials.
    Unprovisioned,
    /// Got credentials, trying to join the network.
    Connecting,
    /// Joined the network at this index of the list, with this IPv4 address.
    /// Everything from the message is stored.
    Connected { network: u8, ip: [u8; 4] },
    /// The last attempt failed; still waiting for a (new) message.
    Failed(Failure),
}

impl Status {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("serializing to a Vec can't fail")
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok()
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

    fn network(ssid: &str, password: &str) -> Network {
        Network {
            ssid: ssid.into(),
            password: password.into(),
        }
    }

    #[test]
    fn x25519_conversion_matches() {
        // The public key we seal to must be the one the private scalar opens.
        let sk = key(7);
        let from_secret = <Kem as hpke::Kem>::sk_to_pk(&kem_private_key(&sk));
        let from_public = kem_public_key(&sk.public()).unwrap();
        assert_eq!(from_secret.to_bytes(), from_public.to_bytes());
    }

    #[test]
    fn credentials_storage_roundtrip() {
        let creds = Credentials {
            networks: vec![network("home", "hunter22")],
        };
        let bytes = creds.to_bytes().unwrap();
        // count | len | ssid | len | password: what the device stores in NVS.
        assert_eq!(bytes, b"\x01\x04home\x08hunter22");
        assert_eq!(Credentials::from_bytes(&bytes).unwrap(), creds);
        assert!(Credentials::from_bytes(b"\x00").is_err());
    }

    #[cfg(feature = "client")]
    mod sealed {
        use super::*;

        fn provision(networks: Vec<Network>, name: &str) -> Message {
            Message::Provision(Provisioning {
                credentials: Credentials { networks },
                name: name.into(),
                pairing_secret: PairingSecret([9; PAIRING_SECRET_LEN]),
            })
        }

        fn msg() -> Message {
            provision(
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
            let sealed = seal(&sk.public(), &msg()).unwrap();
            // version + enc + tag + count + networks + name + secret + tag
            assert_eq!(
                sealed.len(),
                1 + 32 + 1 + 1 + (2 + 13 + 28) + (2 + 4) + (1 + 6) + 32 + 16
            );
            assert_eq!(open(&sk, &sealed).unwrap(), msg());
        }

        #[test]
        fn worst_case_fits_one_characteristic() {
            let longest = network(&"s".repeat(MAX_SSID_LEN), &"p".repeat(MAX_PASSWORD_LEN));
            let msg = provision(vec![longest; MAX_NETWORKS], &"n".repeat(MAX_NAME_LEN));
            let sealed = seal(&key(1).public(), &msg).unwrap();
            assert_eq!(sealed.len(), 508);
            assert!(sealed.len() <= 512);
        }

        #[test]
        fn unknown_message_kind() {
            let sk = key(1);
            // Variant index 7, then whatever.
            let plaintext = [7, 0, 0];
            let pk = kem_public_key(&sk.public()).unwrap();
            let (enc, ct) = hpke::single_shot_seal::<Aead, Kdf, Kem>(
                &hpke::OpModeS::Base,
                &pk,
                INFO,
                &plaintext,
                sk.public().as_bytes(),
            )
            .unwrap();
            let sealed = [&[VERSION][..], &enc.to_bytes(), &ct].concat();
            assert!(matches!(open(&sk, &sealed), Err(Error::Unsupported { .. })));
        }

        #[test]
        fn wrong_key() {
            let sealed = seal(&key(1).public(), &msg()).unwrap();
            assert!(matches!(open(&key(2), &sealed), Err(Error::Decrypt { .. })));
        }

        #[test]
        fn tampered() {
            let sk = key(1);
            let mut sealed = seal(&sk.public(), &msg()).unwrap();
            *sealed.last_mut().unwrap() ^= 1;
            assert!(matches!(open(&sk, &sealed), Err(Error::Decrypt { .. })));
            sealed[0] = 2;
            assert!(matches!(open(&sk, &sealed), Err(Error::Malformed { .. })));
            assert!(matches!(
                open(&sk, &sealed[..10]),
                Err(Error::Malformed { .. })
            ));
        }

        #[test]
        fn rejects_bad_credentials() {
            let id = key(1).public();
            let bad = |networks| seal(&id, &provision(networks, "x"));
            assert!(matches!(bad(vec![]), Err(Error::InvalidCredentials { .. })));
            assert!(matches!(
                bad(vec![network("", "")]),
                Err(Error::InvalidCredentials { .. })
            ));
            assert!(matches!(
                bad(vec![network(&"x".repeat(33), "")]),
                Err(Error::InvalidCredentials { .. })
            ));
            assert!(matches!(
                bad(vec![network("a", ""); MAX_NETWORKS + 1]),
                Err(Error::InvalidCredentials { .. })
            ));
            let long_name = provision(vec![network("a", "")], &"n".repeat(MAX_NAME_LEN + 1));
            assert!(matches!(
                seal(&id, &long_name),
                Err(Error::InvalidCredentials { .. })
            ));
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
            let newer = format!(
                "pair{}",
                data_encoding::BASE32_NOPAD
                    .encode(&[1; 65])
                    .to_ascii_lowercase()
            );
            assert!(matches!(
                newer.parse::<PairingTicket>(),
                Err(Error::Unsupported { .. })
            ));
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
