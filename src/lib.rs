//!  P2psConn Library Usage Example (Sync)
//! This example demonstrates how to use the `P2psConn` struct for peer-to-peer communication. Using `P2psConnAsync` should be pretty much the same but the functions would be async so you would have to await them.

//! # Example
//!
//! This example demonstrates how to set up a secure peer-to-peer TCP connection. It involves starting a server that waits for an incoming
//! connection and a client that initiates a secure handshake, sends data, and reads it.
//! back securely.
//!
//!#### Server
//! ```rust
//!#  use p2ps::{Seconn, Result};
//!#  use tokio::{
//!#      sync::oneshot,
//!#      task,
//!#  };
//!#
//!# async fn start_server(addr: &str, tx: oneshot::Sender<()>) -> Result<()> {
//!#     let addr = addr.to_string();
//!#    task::spawn(async move {
//!    let listener = tokio::net::TcpListener::bind(&addr).await.expect(&format!("Could not bind TcpListener to address {}", &addr));
//!
//!#         // Notify the client that the server is ready
//!#         tx.send(()).expect("Failed to send readiness signal");
//!    // Accept incoming Tcp connection
//!    while let Ok((stream, _)) = listener.accept().await {
//!        task::spawn(async move {
//!            // Listen for a secure connection (Seconn) handshake
//!            let mut p2ps_conn = Seconn::listen_handshake(stream).await?;
//!
//!            let data = b"Hello there!";
//!
//!            // Since secure connection is stablished it can be use to send data securely
//!            p2ps_conn.write(data).await?;
//!            Ok::<(), p2ps::Error>(())
//!        });
//!    }
//!#    });
//!#     Ok(())
//!# }
//!```
//!#### Client
//!```
//!#  #[tokio::test]
//!#  async fn transfer_data() -> Result<()> {
//!#     let addr = "127.0.0.1:7777";
//!#     // Create a oneshot channel for server readiness notification
//!#     let (tx, rx) = oneshot::channel::<()>();
//!#     // Start the server and pass the sender end of the oneshot channel
//!#     start_server(addr, tx).await;
//!#     // Wait for the server to signal that it is ready
//!#     rx.await.expect("Server failed to start");
//!    // Now try connecting the server
//!    let stream = tokio::net::TcpStream::connect(addr).await?;
//!
//!    // Client and Server are now connected through a TCP stream
//!
//!    // Client sends a handshake to stablish a secure connection
//!    let mut p2ps_conn = Seconn::send_handshake(stream).await?;
//!
//!    // Read data from the encripted connection
//!    let decrypted_data = p2ps_conn.read().await?;
//!
//!    assert_eq!(decrypted_data, b"Hello there!");
//!#    Ok(())
//!# }
//! ```

mod secure_conn;
mod errors;

// Flatten
pub use errors::{Error, Result};
pub use secure_conn::Seconn;
