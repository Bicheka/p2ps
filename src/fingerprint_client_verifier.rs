use rustls::server::danger::{ClientCertVerifier, ClientCertVerified};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::{Error, SignatureScheme, DigitallySignedStruct};
use std::sync::Arc;

use crate::get_cert_fingerprint;

#[derive(Debug)]
pub struct FingerprintClientVerifier {
    expected_hex_hash: String,
    crypto_provider: Arc<rustls::crypto::CryptoProvider>, 
}

impl FingerprintClientVerifier {
    pub fn new(expected_hex_hash: String) -> Self {
        Self {
            expected_hex_hash,
            crypto_provider: rustls::crypto::CryptoProvider::get_default()
                .expect("Default crypto provider not set").clone(),
        }
    }
}

impl ClientCertVerifier for FingerprintClientVerifier {
    // 1. Tell the client we want them to send a certificate
    fn offer_client_auth(&self) -> bool {
        true 
    }

    // 2. Enforce that the client MUST send a certificate (mTLS)
    fn client_auth_mandatory(&self) -> bool {
        true 
    }

    // 3. We have no Root CAs to give the client as a "hint"
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[] 
    }

    // 4. Verify the client's certificate hash
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        
        // Use the same hashing helper from the client example
        let computed_hash = get_cert_fingerprint(end_entity);

        if computed_hash == self.expected_hex_hash {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(Error::General(format!(
                "Client Pinning failed! Expected {}, got {}", 
                self.expected_hex_hash, computed_hash
            )))
        }
    }

    // 5. Delegate signature validation to the default cryptography provider 
    // to ensure the client actually holds the private key for this certificate.
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