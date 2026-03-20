# P2P-Secure-Conn 🦀
[<img alt="crates.io" src="https://img.shields.io/crates/v/p2ps.svg?style=for-the-badge&color=fc8d62&logo=rust" height="20">](https://crates.io/crates/p2ps)


A lightweight, async-first Rust library for establishing **Mutual TLS (mTLS)** connections. Built on top of `tokio-rustls` and `rustls`, it simplifies the process of generating self-signed identities and enforcing strict two-way authentication between peers.

## Features

* **Mutual Authentication (mTLS):** Both the client and the server must present valid certificates to establish a connection.
* **Self-Signed Friendly:** Built-in utility to generate x509 identities on the fly using `rcgen`.
* **Async Ready:** Designed specifically for the `tokio` ecosystem.
* **Simple API:** Wraps complex `rustls` configurations into straightforward `accept` and `connect` functions.

## Add it to your project
```bash
cargo add p2ps
```

## Usage example (to see a full working example in action check out [file-express](https://github.com/Bicheka/file-express))

Set up crypto provider
```rusthttps://github.com/Bicheka/file-express
    let _ = ring::default_provider().install_default();
```

Peer A generates identity meaning cert and key, and generate fingerprint
```rust
    let (cert, key) = generate_identity()?;
    let hash = get_cert_fingerprint(&cert);
```

Peer B does the same
```rust
    let (cert, key) = generate_identity()?;
    let hash = get_cert_fingerprint(&cert);
```

**The hash must then be shared between them**

Peer A
```rust
let listener = TcpListener::bind("127.0.0.1:0").await?;
let addr = listener.local_addr()?;

let mut secure_conn: SecureConn = accept(
    &listener,
    server_cert,
    server_key,
    client_hash,
).await.expect("Server failed to accept");
```

Peer B
```rust
let mut secure_conn: SecureConn = connect(
    &addr.to_string(),
    server_hash,
    client_cert,
    client_key,
).await?;
```

SecureConnection is a Tls wrapper
```rust
pub struct SecureConn {
    pub stream: TlsStream<TcpStream>
}
```

So you can use **secure_conn** variable like this for example
```rust
    secure_conn.stream.write_all(b"Hello Server").await?;

    let mut buf = [0u8; 12];
    secure_conn.stream.read_exact(&mut buf).await?;
```

License

This project is licensed under the MIT License, see the [LICENSE](LICENSE) file for details.
