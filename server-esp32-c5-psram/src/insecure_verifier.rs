//! A no-op TLS server-certificate verifier for relay / pkarr connections.
//!
//! The ESP32 build uses a deliberately minimal pure-Rust crypto provider
//! (AES-128-GCM + X25519, no RSA) that cannot verify the relay's RSA certificate
//! chain. iroh authenticates peers at the QUIC layer via their ed25519 node keys,
//! so relay/pkarr TLS only needs an encrypted channel, not a verified one — we
//! skip certificate verification here.
//!
//! This is injected through the public
//! [`iroh::tls::CaTlsConfig::custom_server_cert_verifier`] API, so it needs **no
//! patch to iroh-relay**. When relays serve an ed25519 certificate chain, replace
//! the no-op bodies below with real verification against a shipped trust anchor.

use std::sync::Arc;

use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};

/// Builds the callback for [`CaTlsConfig::custom_server_cert_verifier`] that
/// installs a [`NoCertVerifier`].
///
/// [`CaTlsConfig::custom_server_cert_verifier`]: iroh::tls::CaTlsConfig::custom_server_cert_verifier
pub fn skip_verify() -> iroh_relay::tls::ServerCertVerifierBuilder {
    Arc::new(|crypto_provider| {
        Ok(Arc::new(NoCertVerifier { crypto_provider }) as Arc<dyn ServerCertVerifier>)
    })
}

/// Accepts any server certificate without verification.
#[derive(Debug)]
struct NoCertVerifier {
    crypto_provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
