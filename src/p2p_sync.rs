#![allow(dead_code)]

use crate::common::{Encryption, Keys};
use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use std::io::{Read, Write};

/// A struct for handling encrypted P2P communication.
pub struct P2psConn<T: Write + Read> {
    stream: T,
    key: Key<Aes256Gcm>,
}

impl<T> Encryption for P2psConn<T>
where
    T: Read + Write,
{
    fn encrypt(&self, input_data: &[u8]) -> (Vec<u8>, [u8; 12]) {
        let nonce = [0u8; 12];
        let cipher = Aes256Gcm::new(&self.key);
        let encrypted_data = cipher
            .encrypt(&nonce.into(), input_data)
            .expect("Error encrypting data");
        (encrypted_data, nonce)
    }

    fn decrypt(&self, encrypted_data: &[u8], nonce: &[u8; 12]) -> Vec<u8> {
        let cipher = Aes256Gcm::new(&self.key);
        cipher
            .decrypt(Nonce::from_slice(nonce), encrypted_data)
            .expect("decryption failed")
    }
}

impl<T> P2psConn<T>
where
    T: Read + Write,
{
    pub fn listen_handshake(mut stream: T) -> std::io::Result<Self> {
        // recieve their public key
        let mut buffer = [0u8; 32];
        stream.read(&mut buffer)?;

        // generate private and public keys
        let keys = Keys::generate_keys();

        // send public generated public key
        stream.write_all(&keys.get_public_key_bytes())?;

        // create encryption key with private key and their public key
        let encryption_key = keys.generate_encryption_key(&Keys::public_key_from_bytes(buffer)?);
        // create P2ps
        Ok(Self::new(stream, encryption_key))
    }

    pub fn send_handshake(mut stream: T) -> std::io::Result<Self> {
        todo!()
    }

    pub fn new(stream: T, key: Key<Aes256Gcm>) -> Self {
        todo!()
    }

    pub fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        todo!()
    }

    pub fn read(&mut self) -> std::io::Result<Vec<u8>> {
        todo!()
    }
}
