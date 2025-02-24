# p2ps

**p2ps** is a Rust library designed to make it easy to establish a secure connection between two peers using the [Diffie-Hellman algorithm](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange).

## Usage example (Sync)

#### Peer A
```rust
use std::net::TcpListener;
use p2ps::P2psConn;

let listener = TcpListener::bind("peer_a_address:port")?;
let (mut stream, _) = listener.accept()?;
let mut p2ps_conn = P2psConn::listen_handshake(stream)?;
```

#### Peer B
```rust
use std::net::TcpStream;
use p2p_secure::P2psConn;

let stream = TcpStream::connect("peer_a_address:port")?;
let mut p2ps_conn = P2psConn::send_handshake(&mut stream)?;

```

now both peers can use their p2ps_conn to share data

#### Peer A
``` rust
let data = b"Hello, peer B!";
p2ps_conn.write(data)?;
```

#### Peer B
```rust
let decrypted_data = p2ps_conn.read()?;
println!("Received data: {}", String::from_utf8_lossy(&decrypted_data));
```

## Loking for Contributors & Ideas
This project is in active development, and I need help! Contributions are welcome, whether it's improving the implementation, fixing bugs, or adding new features. Feel free to open issues, submit pull requests, and share any new ideas that could improve the project.

## License
This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.
