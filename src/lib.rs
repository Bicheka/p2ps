//! # P2psConn Library Usage Example (Sync)
//! This example demonstrates how to use the `P2psConn` struct for peer-to-peer communication. Using `P2psConnAsync` should be pretty much the same but the functions would be async so you would have to await them.
//!
//! Peer A listens for an incoming connection and receives a handshake.
//!
//! ```rust,ignore
//! // -- Peer A --
//! use std::net::TcpListener;
//! use p2ps::P2psConn;
//!
//! let listener = TcpListener::bind("peer_a_address:port")?;
//! let (mut stream, _) = listener.accept()?; // Accept the incoming connection.
//!
//! let mut p2ps_conn = P2psConn::listen_handshake(stream)?;
//! ```
//!
//! Peer B connects to Peer A and sends a handshake.
//!
//! ```rust,ignore
//! // -- Peer B --
//! use std::net::TcpStream;
//! use p2p_secure::P2psConn;
//!
//! let stream = TcpStream::connect("peer_a_address:port")?;
//!
//! let mut p2ps_conn = P2psConn::send_handshake(&mut stream)?;
//! ```
//!
//! After the handshake, both peers can use their `p2ps_conn` instance to share data.
//!
//! Peer A writes encrypted data to Peer B.
//!
//! ```rust,ignore
//! // -- Peer A --
//! let data = b"Hello, peer B!"; // Data to send to Peer B.
//! p2ps_conn.write(data)?;
//! ```
//!
//! Peer B reads and decrypts the data sent by Peer A.
//!
//! ```rust,ignore
//! // -- Peer B --
//! let decrypted_data = p2ps_conn.read()?; // Read and decrypt the data from Peer A.
//! println!("Received data: {}", String::from_utf8_lossy(&decrypted_data)); // Print the decrypted data as a string.
//! ```

// Synchronous implementation of P2ps
mod p2p_sync;

// Asynchronous implementation of P2ps
mod p2p_async;

mod common;

mod errors;

mod p2ps_conn_common;

// Flatten
pub use errors::{Error, Result};
pub use p2p_async::P2psConnAsync;
pub use p2p_sync::P2psConn;
