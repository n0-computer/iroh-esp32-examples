//! Custom CryptoProvider that wraps rustls-rustcrypto with QUIC support.
//!
//! rustls-rustcrypto provides TLS 1.3 cipher suites but leaves `quic: None`.
//! This module adds QUIC header protection and packet encryption for
//! AES-128-GCM (required for QUIC initial handshake).
//! Stripped down for ESP32: AES-128-GCM only, X25519 only — no ChaCha20, no NIST curves.

use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
use aes_gcm::aead::AeadInPlace as _;
use rustls::crypto::cipher::{AeadKey, Iv};
use rustls::crypto::{CipherSuiteCommon, CryptoProvider};
use rustls::{quic, CipherSuite, SupportedCipherSuite, Tls13CipherSuite};

/// Build a CryptoProvider based on rustls-rustcrypto with QUIC support.
///
/// Only offers AES-128-GCM (no ChaCha20-Poly1305) to minimize binary size.
pub fn provider() -> CryptoProvider {
    let base = rustls_rustcrypto::provider();

    // Only keep AES-128-GCM with our QUIC implementation — drop all other cipher suites
    // to save binary size (ChaCha20-Poly1305 adds ~14KB+).
    let cipher_suites: Vec<SupportedCipherSuite> = base
        .cipher_suites
        .iter()
        .filter_map(|suite| match suite {
            SupportedCipherSuite::Tls13(tls13)
                if tls13.common.suite == CipherSuite::TLS13_AES_128_GCM_SHA256 =>
            {
                Some(SupportedCipherSuite::Tls13(QUIC_AES_128_GCM))
            }
            _ => None,
        })
        .collect();

    // Keep only X25519 — drop P-256 and P-384 to save binary size.
    // iroh uses ed25519/X25519 for node identity, no need for NIST curves.
    let kx_groups = base
        .kx_groups
        .into_iter()
        .filter(|g| g.name() == rustls::NamedGroup::X25519)
        .collect();

    CryptoProvider {
        cipher_suites,
        kx_groups,
        ..base
    }
}

// --- AES-128-GCM with QUIC support ---

static QUIC_AES_128_GCM: &Tls13CipherSuite = {
    #[allow(unreachable_patterns)]
    match &rustls_rustcrypto::TLS13_AES_128_GCM_SHA256 {
        SupportedCipherSuite::Tls13(inner) => &Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: inner.common.suite,
                hash_provider: inner.common.hash_provider,
                confidentiality_limit: inner.common.confidentiality_limit,
            },
            hkdf_provider: inner.hkdf_provider,
            aead_alg: inner.aead_alg,
            quic: Some(&Aes128GcmQuic),
        },
        _ => unreachable!(),
    }
};

struct Aes128GcmQuic;

impl quic::Algorithm for Aes128GcmQuic {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        Box::new(Aes128GcmPacketKey::new(key, iv))
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        Box::new(AesHeaderProtectionKey(key))
    }

    fn aead_key_len(&self) -> usize {
        16 // AES-128 key size
    }
}

/// QUIC Header Protection using AES-ECB (RFC 9001, Section 5.4.3)
struct AesHeaderProtectionKey(AeadKey);

impl quic::HeaderProtectionKey for AesHeaderProtectionKey {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), rustls::Error> {
        let mask = self.mask(sample)?;
        apply_header_mask(&mask, first, packet_number, false);
        Ok(())
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), rustls::Error> {
        let mask = self.mask(sample)?;
        apply_header_mask(&mask, first, packet_number, true);
        Ok(())
    }

    #[inline]
    fn sample_len(&self) -> usize {
        16
    }
}

impl AesHeaderProtectionKey {
    fn mask(&self, sample: &[u8]) -> Result<[u8; 5], rustls::Error> {
        // RFC 9001, Section 5.4.3:
        // mask = AES-ECB(hp_key, sample)
        use aes::cipher::generic_array::GenericArray;

        let cipher = aes::Aes128::new(GenericArray::from_slice(self.0.as_ref()));
        let mut block = GenericArray::clone_from_slice(sample);
        cipher.encrypt_block(&mut block);

        let mut mask = [0u8; 5];
        mask.copy_from_slice(&block[..5]);
        Ok(mask)
    }
}

/// QUIC Packet Key using AES-128-GCM AEAD
struct Aes128GcmPacketKey {
    iv: Iv,
    key: aes_gcm::Aes128Gcm,
}

impl Aes128GcmPacketKey {
    fn new(key: AeadKey, iv: Iv) -> Self {
        use aes_gcm::KeyInit;
        let cipher = aes_gcm::Aes128Gcm::new_from_slice(key.as_ref()).expect("key should be valid");
        Self { iv, key: cipher }
    }
}

impl quic::PacketKey for Aes128GcmPacketKey {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        aad: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, rustls::Error> {
        use aes_gcm::Nonce;

        let nonce_bytes = rustls::crypto::cipher::Nonce::new(&self.iv, packet_number).0;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let tag = self
            .key
            .encrypt_in_place_detached(nonce, aad, payload)
            .map_err(|_| rustls::Error::EncryptError)?;
        Ok(quic::Tag::from(tag.as_ref()))
    }

    fn encrypt_in_place_for_path(
        &self,
        path_id: u32,
        packet_number: u64,
        aad: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, rustls::Error> {
        use aes_gcm::Nonce;

        let nonce_bytes =
            rustls::crypto::cipher::Nonce::for_path(path_id, &self.iv, packet_number).0;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let tag = self
            .key
            .encrypt_in_place_detached(nonce, aad, payload)
            .map_err(|_| rustls::Error::EncryptError)?;
        Ok(quic::Tag::from(tag.as_ref()))
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        aad: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], rustls::Error> {
        use aes_gcm::{Nonce, Tag};

        let nonce_bytes = rustls::crypto::cipher::Nonce::new(&self.iv, packet_number).0;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let tag_len = self.tag_len();
        let payload_len = payload
            .len()
            .checked_sub(tag_len)
            .ok_or(rustls::Error::DecryptError)?;

        let (msg, tag_bytes) = payload.split_at_mut(payload_len);
        let tag = Tag::from_slice(tag_bytes);

        self.key
            .decrypt_in_place_detached(nonce, aad, msg, tag)
            .map_err(|_| rustls::Error::DecryptError)?;

        Ok(&payload[..payload_len])
    }

    fn decrypt_in_place_for_path<'a>(
        &self,
        path_id: u32,
        packet_number: u64,
        aad: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], rustls::Error> {
        use aes_gcm::{Nonce, Tag};

        let nonce_bytes =
            rustls::crypto::cipher::Nonce::for_path(path_id, &self.iv, packet_number).0;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let tag_len = self.tag_len();
        let payload_len = payload
            .len()
            .checked_sub(tag_len)
            .ok_or(rustls::Error::DecryptError)?;

        let (msg, tag_bytes) = payload.split_at_mut(payload_len);
        let tag = Tag::from_slice(tag_bytes);

        self.key
            .decrypt_in_place_detached(nonce, aad, msg, tag)
            .map_err(|_| rustls::Error::DecryptError)?;

        Ok(&payload[..payload_len])
    }

    #[inline]
    fn tag_len(&self) -> usize {
        16 // GCM tag is 16 bytes
    }

    fn integrity_limit(&self) -> u64 {
        // RFC 9001, Section 6.6
        1 << 52
    }

    fn confidentiality_limit(&self) -> u64 {
        // RFC 9001, Section 6.6
        1 << 23
    }
}

// --- Shared helpers ---

/// Apply header protection following RFC 9001, Section 5.4.1.
///
/// `masked` indicates whether the first byte is currently HP-masked:
/// - `false` for encrypt (first byte is plaintext, about to be masked)
/// - `true` for decrypt (first byte is masked, about to be unmasked)
///
/// This determines `pn_len` from the plaintext first byte and only XORs
/// that many packet-number bytes, matching ring's behavior.
fn apply_header_mask(mask: &[u8; 5], first: &mut u8, packet_number: &mut [u8], masked: bool) {
    let bits = if *first & 0x80 == 0x80 {
        0x0f // Long header: mask lower 4 bits
    } else {
        0x1f // Short header: mask lower 5 bits
    };

    // Determine the plaintext first byte to read pn_len
    let first_plain = if masked {
        *first ^ (mask[0] & bits) // Unmask to read pn_len
    } else {
        *first // Already plaintext
    };
    let pn_len = (first_plain & 0x03) as usize + 1;

    // Apply mask to first byte
    *first ^= mask[0] & bits;

    // Apply mask only to the actual packet number bytes
    for (b, m) in packet_number.iter_mut().zip(&mask[1..]).take(pn_len) {
        *b ^= m;
    }
}
