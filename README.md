# P2P-Secure-Conn 🦀

A lightweight, async-first Rust library for establishing **Mutual TLS (mTLS)** connections. Built on top of `tokio-rustls` and `rustls`, it simplifies the process of generating self-signed identities and enforcing strict two-way authentication between peers.



## Features

* **Mutual Authentication (mTLS):** Both the client and the server must present valid certificates to establish a connection.
* **Self-Signed Friendly:** Built-in utility to generate x509 identities on the fly using `rcgen`.
* **Async Ready:** Designed specifically for the `tokio` ecosystem.
* **Simple API:** Wraps complex `rustls` configurations into straightforward `accept` and `connect` functions.

