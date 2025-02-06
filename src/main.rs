use std::net::TcpStream;

use p2p_tls::Stream;

fn main() {

    let tcp = std::net::TcpStream::connect("127.23.232.1").unwrap();

    let stream = Stream::SyncTCP(tcp);
    let p2p_tls = p2p_tls::P2pTlsStream::new(stream);
}