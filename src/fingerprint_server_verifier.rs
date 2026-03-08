use rustls::client::danger::{ServerCertVerifier, HandshakeSignatureValid};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{Error, SignatureScheme, DigitallySignedStruct};
use std::sync::Arc;

use crate::get_cert_fingerprint;

#[derive(Debug)]
pub struct FingerprintServerVerifier {
    expected_hex_hash: String,
    // We keep the default crypto provider to handle the complex math
    // of proving the server actually owns the private key.
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
}

impl FingerprintServerVerifier {
    pub fn new(expected_hex_hash: String) -> Self {
        Self {
            expected_hex_hash,
            crypto_provider: rustls::crypto::CryptoProvider::get_default()
                .expect("Default crypto provider not set").clone(),
        }
    }
}

impl ServerCertVerifier for FingerprintServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, Error> {

        // 1. Hash the certificate we just received
        let computed_hash = get_cert_fingerprint(end_entity);

        // 2. Compare it to the hash we were given out-of-band
        if computed_hash == self.expected_hex_hash {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(Error::General(format!(
                "Pinning failed! Expected {}, got {}",
                self.expected_hex_hash, computed_hash
            )))
        }
    }

    // You also must implement the signature verification methods.
    // We delegate these to the default Rustls cryptography provider so
    // nobody can spoof the certificate without having the private key!
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.crypto_provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.crypto_provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto_provider.signature_verification_algorithms.supported_schemes()
    }
}