// Synchronous implementation of P2ps
mod p2p_sync;

// Asynchronous implementation of P2ps
mod p2p_async;

mod common;

// Flatten
pub use p2p_async::P2psConnAsync;
pub use p2p_sync::P2psConn;
