# p2ps
<div align="center">
  <a href="https://crates.io/crates/p2ps">
    <img src="https://img.shields.io/crates/v/p2ps.svg" alt="crates.io Latest Release"/>
  </a>
</div>

**p2ps** is a Rust library designed to make it easy to establish a secure connection between two peers using the [Diffie-Hellman algorithm](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange).

## Usage example (see tests for better understanding)

#### Peer A
```rust
use tokio::net::TcpListener;
use p2ps::Seconn;

let listener = TcpListener::bind("127.0.0.1:7777").await?;
let (stream, _) = listener.accept().await?;
let mut p2ps_conn = Seconn::listen_handshake(stream).await?;
```

#### Peer B
```rust
use tokio::net::TcpStream;
use p2ps::Seconn;

let stream = TcpStream::connect("127.0.0.1:7777").await?;
let mut p2ps_conn = Seconn::send_handshake(stream).await?;
```

now both peers can use their p2ps_conn to share data

#### Peer A
``` rust
let data = b"Hello, peer B!";
p2ps_conn.write(data).await?;
```

#### Peer B
```rust
let decrypted_data = p2ps_conn.read().await?;
println!("Received: {}", String::from_utf8_lossy(&decrypted_data));
```

## Loking for Contributors & Ideas
This project is in active development, and I need help! Contributions are welcome, whether it's improving the implementation, fixing bugs, or adding new features. Feel free to open issues, submit pull requests, and share any new ideas that could improve the project.

## License
This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.
