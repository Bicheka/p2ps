use std::sync::Arc;
use rcgen::generate_simple_self_signed;
use rustls::{ClientConfig, ServerConfig, RootCertStore};
use rustls::server::WebPkiClientVerifier;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

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
    client_root_cert: CertificateDer<'static>, // Added: Who the server trusts
) -> anyhow::Result<SecureConn> {

    // Create a RootCertStore for the server to verify the client
    let mut client_roots = RootCertStore::empty();
    client_roots.add(client_root_cert)?;

    // Build the verifier
    let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots)).build()?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier) // Enforce mTLS
        .with_single_cert(vec![server_cert], server_key)?;

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let (socket, _) = listener.accept().await?;
    let tls_stream = acceptor.accept(socket).await?;

    Ok(SecureConn::new(tokio_rustls::TlsStream::Server(tls_stream)))
}

// 2. Client-side: Now provides its own identity to the server
pub async fn connect(
    addr: &str,
    server_root_cert: CertificateDer<'static>, // Who the client trusts
    client_cert: CertificateDer<'static>,      // Added: Client's identity
    client_key: PrivateKeyDer<'static>,        // Added: Client's key
) -> anyhow::Result<SecureConn> {

    let mut roots = RootCertStore::empty();
    roots.add(server_root_cert)?;

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(vec![client_cert], client_key)?; // Provide identity

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
        // 1. Generate separate identities for Server and Client
        let (server_cert, server_key) = generate_identity()?;
        let (client_cert, client_key) = generate_identity()?;

        // We clone these because the server/client tasks will need to own them
        let server_cert_for_client = server_cert.clone();
        let client_cert_for_server = client_cert.clone();

        // 2. Setup the Listener on a random local port
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        // 3. Spawn the Server Task
        let server_handle = tokio::spawn(async move {
            let mut secure_conn = accept(
                &listener,
                server_cert,
                server_key,
                client_cert_for_server
            ).await.expect("Server failed to accept");

            // Read message from client
            let mut buf = [0u8; 12];
            secure_conn.stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"Hello Server");

            // Write response
            secure_conn.stream.write_all(b"Hello Client").await.unwrap();
        });

        // 4. Run the Client Task
        let mut client_conn = connect(
            &addr.to_string(),
            server_cert_for_client,
            client_cert,
            client_key,
        ).await?;

        // Write to server
        client_conn.stream.write_all(b"Hello Server").await?;

        // Read response
        let mut buf = [0u8; 12];
        client_conn.stream.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"Hello Client");

        // 5. Clean up
        server_handle.await?;
        Ok(())
    }
}