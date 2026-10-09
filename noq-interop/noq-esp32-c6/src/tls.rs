//! iroh-compatible TLS for a plain noq endpoint: TLS 1.3 with raw public keys
//! ([RFC 7250]) on both sides, identities are ed25519 keys.
//!
//! This is everything iroh's handshake needs from the peer; there is no iroh code
//! involved. An iroh endpoint dialing us
//! - offers only the `RawPublicKey` certificate type and checks that the key we
//!   present is the endpoint ID it dialed,
//! - does not send SNI,
//! - presents its own endpoint ID as a raw public key when we ask for client auth.
//!
//! [RFC 7250]: https://datatracker.ietf.org/doc/html/rfc7250

use std::sync::Arc;

use iroh_base::{PublicKey, SecretKey};
use rustls::{
    client::danger::HandshakeSignatureValid,
    crypto::{verify_tls13_signature_with_raw_key, CryptoProvider, WebPkiSupportedAlgorithms},
    pki_types::{alg_id, CertificateDer, SubjectPublicKeyInfoDer, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
    sign::{CertifiedKey, SigningKey},
    CertificateError, DigitallySignedStruct, DistinguishedName, SignatureAlgorithm,
    SignatureScheme,
};

/// Builds a QUIC server config that speaks iroh's TLS profile on the given ALPNs.
pub fn server_config(
    secret: &SecretKey,
    provider: Arc<CryptoProvider>,
    alpns: &[&[u8]],
) -> Result<noq::crypto::rustls::QuicServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let algs = provider.signature_verification_algorithms;
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(RawKeyClientVerifier { algs }))
        .with_cert_resolver(Arc::new(RawKeyResolver::new(secret)));
    crypto.alpn_protocols = alpns.iter().map(|a| a.to_vec()).collect();
    // No resumption: no ticket cache, no session store. Every handshake is a full one,
    // which costs nothing here and saves the RAM for the caches.
    crypto.send_tls13_tickets = 0;
    crypto.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Ok(noq::crypto::rustls::QuicServerConfig::try_from(crypto)?)
}

/// The remote's iroh endpoint ID (its ed25519 public key), from a handshaken connection.
pub fn remote_id(conn: &noq::Connection) -> Option<PublicKey> {
    let certs = conn
        .peer_identity()?
        .downcast::<Vec<CertificateDer<'static>>>()
        .ok()?;
    ed25519_key_from_spki(certs.first()?.as_ref())
}

/// DER SubjectPublicKeyInfo of an ed25519 key: a fixed 12 byte prefix + the 32 key bytes.
fn ed25519_spki(public: &PublicKey) -> SubjectPublicKeyInfoDer<'static> {
    rustls::sign::public_key_to_spki(&alg_id::ED25519, public.as_bytes())
}

fn ed25519_key_from_spki(spki: &[u8]) -> Option<PublicKey> {
    let key = PublicKey::from_bytes(spki.get(12..)?.try_into().ok()?).ok()?;
    (ed25519_spki(&key).as_ref() == spki).then_some(key)
}

/// Presents our ed25519 key as a raw public key.
#[derive(Debug)]
struct RawKeyResolver(Arc<CertifiedKey>);

impl RawKeyResolver {
    fn new(secret: &SecretKey) -> Self {
        let spki = ed25519_spki(&secret.public());
        let key = Ed25519Key(secret.clone());
        Self(Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(spki.to_vec())],
            Arc::new(key),
        )))
    }
}

impl rustls::server::ResolvesServerCert for RawKeyResolver {
    fn resolve(&self, _hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone)]
struct Ed25519Key(SecretKey);

impl SigningKey for Ed25519Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        offered
            .contains(&SignatureScheme::ED25519)
            .then(|| Box::new(self.clone()) as Box<dyn rustls::sign::Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(ed25519_spki(&self.0.public()))
    }
}

impl rustls::sign::Signer for Ed25519Key {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Ok(self.0.sign(message).to_bytes().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// Requires the client to authenticate with an ed25519 raw public key (its iroh
/// endpoint ID). Any key is accepted; the TLS signature check proves possession.
#[derive(Debug)]
struct RawKeyClientVerifier {
    algs: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for RawKeyClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if !intermediates.is_empty() || ed25519_key_from_spki(end_entity).is_none() {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.algs,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}
