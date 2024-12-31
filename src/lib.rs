use std::{clone, net::TcpStream};
use tokio::io::{AsyncRead, AsyncWrite};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
struct P2pTlsStream<T> {
    inner: T
}

impl<T> P2pTlsStream<T> {
    pub fn new(inner: T, shared_secret: &[u8]) {
        todo!()
    }
    fn encrypt() {
        todo!()
    }
    fn decrypt() {
        todo!()
    }
}

pub trait SharePublicKey<T, E> {
    fn send_public_key(&self) -> Result<T, E>;
    fn recieve_public_key();
}

pub struct DhaKeys {
    pub secret: EphemeralSecret,
    pub public: PublicKey
}

impl DhaKeys {
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

// Todo implement functionality to share public secret through tokio TcpStream
impl <T, E, S> SharePublicKey<T, E> for P2pTlsStream<S> 

    where S: // some 

{
    fn send_public_key(&self) -> Result<T, E> {
        todo!()
    }

    fn recieve_public_key() {
        todo!()
    }
}