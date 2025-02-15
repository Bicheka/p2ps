use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

pub enum Stream {
    SyncTCP(std::net::TcpStream),
    AsyncTCP(tokio::net::TcpStream)
}

pub struct P2pTlsStream {
    stream: Stream
}

impl P2pTlsStream {
    pub fn new(stream: Stream) -> Self {
        Self {
            stream
        }
    }
}

pub struct Keys {
    pub secret: EphemeralSecret,
    pub public: PublicKey
}

impl Keys {
    pub fn generate_keys() -> Self{
        let rng = rand::thread_rng();
        let secret = EphemeralSecret::random_from_rng(rng);
        Self {
            public: PublicKey::from(&secret),
            secret,
        }
    }

    pub fn generate_secret(secret: EphemeralSecret, their_public: &PublicKey) -> SharedSecret{
        secret.diffie_hellman(their_public)
    }
}

pub trait SharePublicKey<T, E> {
    fn send_public_key(&self) -> Result<T, E>;
    fn recieve_public_key();
}

// Todo implement functionality to share public secret through tokio TcpStream
impl <T, E> SharePublicKey<T, E> for P2pTlsStream {
    fn send_public_key(&self) -> Result<T, E> {
        todo!()
    }

    fn recieve_public_key() {
        todo!()
    }
}