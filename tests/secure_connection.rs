use p2ps::Seconn;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task,
};

#[tokio::test]
async fn transfer_data() {
    let addr = "127.0.0.1:7777";

    // Create a oneshot channel for server readiness notification
    let (tx, rx) = oneshot::channel::<()>();

    // Start the server and pass the sender end of the oneshot channel
    start_server(addr, tx).await;

    // Wait for the server to signal that it is ready
    rx.await.expect("Server failed to start");

    // Now try connecting the server
    let stream = TcpStream::connect(addr)
        .await
        .expect(&format!("Could not connect to address {}", addr));

    // Client and Server are now connected through a TCP stream

    // Client sends a handshake to stablish a secure connection
    let mut p2ps_conn = Seconn::send_handshake(stream)
        .await
        .expect("Handshake failed!");

    // Read data from the encripted connection
    let decrypted_data = p2ps_conn
        .read()
        .await
        .expect("Could not read data sent by peer");

    assert_eq!(decrypted_data, b"Hello there!");
}

async fn start_server(addr: &str, tx: oneshot::Sender<()>) {
    let addr = addr.to_string();

    task::spawn(async move {
        let listener = TcpListener::bind(&addr)
            .await
            .expect(&format!("Could not bind TcpListener to address {}", &addr));

        // Notify the client that the server is ready
        tx.send(()).expect("Failed to send readiness signal");

        while let Ok((stream, _)) = listener.accept().await {
            task::spawn(async move {
                let mut p2ps_conn = Seconn::listen_handshake(stream)
                    .await
                    .expect("Error listening for handshake");

                let data = b"Hello there!";
                p2ps_conn
                    .write(data)
                    .await
                    .expect("Error writing data to peer");
            });
        }
    });
}
