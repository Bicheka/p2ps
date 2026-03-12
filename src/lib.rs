use std::sync::Arc;
use rcgen::generate_simple_self_signed;
use rustls::{ClientConfig, ServerConfig};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
pub use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::fingerprint_client_verifier::FingerprintClientVerifier;
use crate::fingerprint_server_verifier::FingerprintServerVerifier;
pub mod fingerprint_server_verifier;
pub mod fingerprint_client_verifier;

pub fn get_cert_fingerprint(cert: &CertificateDer<'_>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert.as_ref()); // Hash the raw DER bytes
    let result = hasher.finalize();
    hex::encode(result) // Returns a string like "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}

pub struct SecureConn {
    pub stream: TlsStream<TcpStream>
}

impl SecureConn {
    pub fn new(stream: TlsStream<TcpStream>) -> Self {
        Self { stream }
    }
}

pub fn generate_identity() -> anyhow::Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let cert = generate_simple_self_signed(vec!["p2ps".into()])?;
    Ok((cert.cert.into(), cert.signing_key.into()))
}

// 1. Server-side: Now requires client_root to verify the incoming client cert
pub async fn accept(
    listener: &TcpListener,
    server_cert: CertificateDer<'static>,
    server_key: PrivateKeyDer<'static>,
    expected_client_hash: String, // Added: The string hash we expect from the client
) -> anyhow::Result<SecureConn> {

    // Build our custom verifier using the expected string hash
    let verifier = Arc::new(FingerprintClientVerifier::new(expected_client_hash));

    // Configure the server to use it
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier) // Enforce our custom mTLS hash check
        .with_single_cert(vec![server_cert], server_key)?;

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let (socket, _) = listener.accept().await?;
    let tls_stream = acceptor.accept(socket).await?;

    Ok(SecureConn::new(tokio_rustls::TlsStream::Server(tls_stream)))
}

// 2. Client-side: Now provides its own identity to the server
pub async fn connect(
    addr: &str,
    expected_server_hash: String,
    client_cert: CertificateDer<'static>,      // Added: Client's identity
    client_key: PrivateKeyDer<'static>,        // Added: Client's key
) -> anyhow::Result<SecureConn> {

    // Use our custom verifier
    let verifier = Arc::new(FingerprintServerVerifier::new(expected_server_hash));

    let config = ClientConfig::builder()
        .dangerous() // Required to use custom verifiers
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![client_cert], client_key)?;

    let connector = TlsConnector::from(Arc::new(config));
    let domain = "p2ps".try_into()?;
    let stream = TcpStream::connect(addr).await?;
    let tls_stream = connector.connect(domain, stream).await?;

    Ok(SecureConn::new(tokio_rustls::TlsStream::Client(tls_stream)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_mtls_connection() -> anyhow::Result<()> {

        // This tells rustls to use 'ring' for all the heavy lifting (signing/verifying)
        let _ = rustls::crypto::ring::default_provider().install_default();

        // 1. Generate separate identities for Server and Client
        let (server_cert, server_key) = generate_identity()?;
        let (client_cert, client_key) = generate_identity()?;

        // 2. Calculate the fingerprints (the "signatures" we will share)
        let server_hash = get_cert_fingerprint(&server_cert);
        let client_hash = get_cert_fingerprint(&client_cert);

        // 3. Setup the Listener on a random local port
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        // 4. Spawn the Server Task
        let server_handle = tokio::spawn(async move {
            let mut secure_conn = accept(
                &listener,
                server_cert,
                server_key,
                client_hash, // The server only needs the string hash of the client
            ).await.expect("Server failed to accept");

            // Read message from client
            let mut buf = [0u8; 12];
            secure_conn.stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"Hello Server");

            // Write response
            secure_conn.stream.write_all(b"Hello Client").await.unwrap();
        });

        // 5. Run the Client Task
        let mut client_conn = connect(
            &addr.to_string(),
            server_hash, // The client only needs the string hash of the server
            client_cert,
            client_key,
        ).await?;

        // Write to server
        client_conn.stream.write_all(b"Hello Server").await?;

        // Read response
        let mut buf = [0u8; 12];
        client_conn.stream.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"Hello Client");

        // 6. Clean up
        server_handle.await?;
        Ok(())
    }
}