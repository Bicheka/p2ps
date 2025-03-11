use p2ps::{self, P2psConn};
use std::net::{TcpListener, TcpStream};
use std::thread;
#[test]
fn transfer_data_sync() {
    let ip = "127.0.0.1:7878";
    start_test_server(ip);

    let stream = TcpStream::connect(ip).expect(&format!("Could not connect to ip {}", ip));
    let mut p2ps_conn = P2psConn::send_handshake(stream).expect("Could not establish handshake");
    let decrypted_data = p2ps_conn.read().expect("Error reading encrypted data");

    assert_eq!(decrypted_data, b"Hello there!");
}

fn start_test_server(address: &str) {
    let listener =
        TcpListener::bind(address).expect(&format!("Failed to bind server to address {}", address));

    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let mut p2ps_conn = P2psConn::listen_handshake(stream)
                        .expect("Error listening stream for incoming handshake");
                    let data = b"Hello there!";
                    p2ps_conn.write(data).expect("Error writing data to peer");
                }
                Err(e) => eprintln!("Connection failed: {}", e),
            }
        }
    });
}
