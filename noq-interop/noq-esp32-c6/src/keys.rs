//! The two endpoint keys noq takes from ring/aws-lc by default, built from RustCrypto
//! instead: an HMAC key for stateless resets and an AEAD key for handshake tokens
//! (Retry and NEW_TOKEN).

use aes_gcm::aead::{AeadInPlace as _, KeyInit as _};
use hmac::{KeyInit as _, Mac as _};
use noq::crypto::{CryptoError, HandshakeTokenKey, HmacKey};

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

fn random<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("no system RNG");
    buf
}

/// HMAC-SHA256 with a random key, used to derive stateless reset tokens.
pub struct ResetKey([u8; 64]);

impl ResetKey {
    pub fn random() -> Self {
        Self(random())
    }

    fn mac(&self) -> HmacSha256 {
        HmacSha256::new_from_slice(&self.0).expect("HMAC takes any key length")
    }
}

impl HmacKey for ResetKey {
    fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
        let mut mac = self.mac();
        mac.update(data);
        signature_out.copy_from_slice(&mac.finalize().into_bytes());
    }

    fn signature_len(&self) -> usize {
        32
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let mut mac = self.mac();
        mac.update(data);
        mac.verify_slice(signature).map_err(|_| CryptoError)
    }
}

/// AES-128-GCM with a random key, used to seal handshake tokens. noq hands us a
/// fresh random 128 bit nonce per token; the first 96 bits are the GCM nonce.
pub struct TokenKey(aes_gcm::Aes128Gcm);

impl TokenKey {
    pub fn random() -> Self {
        Self(aes_gcm::Aes128Gcm::new(&random::<16>().into()))
    }
}

fn nonce(token_nonce: u128) -> aes_gcm::Nonce<aes_gcm::aead::consts::U12> {
    let bytes = token_nonce.to_le_bytes();
    *aes_gcm::Nonce::from_slice(&bytes[..12])
}

impl HandshakeTokenKey for TokenKey {
    fn seal(&self, token_nonce: u128, data: &mut Vec<u8>) -> Result<(), CryptoError> {
        self.0
            .encrypt_in_place(&nonce(token_nonce), &[], data)
            .map_err(|_| CryptoError)
    }

    fn open<'a>(&self, token_nonce: u128, data: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
        let len = data.len().checked_sub(16).ok_or(CryptoError)?;
        let (msg, tag) = data.split_at_mut(len);
        self.0
            .decrypt_in_place_detached(&nonce(token_nonce), &[], msg, aes_gcm::Tag::from_slice(tag))
            .map_err(|_| CryptoError)?;
        Ok(msg)
    }
}
