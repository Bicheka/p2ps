#![allow(dead_code)]

use std::io::{Read, Write};

use aes_gcm::{Aes256Gcm, Key};

use crate::{Keys, P2ps};

pub trait P2psSync<T>: Sized
where
    T: Read + Write,
{
    fn listen_handshake(stream: T) -> std::io::Result<Self>;
    fn send_handshake(stream: T) -> std::io::Result<Self>;
    fn new(stream: T, key: Key<Aes256Gcm>) -> Self;
    fn write(&mut self, data: &[u8]) -> std::io::Result<()>;
    fn read(&mut self) -> std::io::Result<Vec<u8>>;
}

impl<T> P2psSync<T> for P2ps<T>
where
    T: Read + Write,
{
    fn listen_handshake(mut stream: T) -> std::io::Result<Self> {
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

    fn send_handshake(mut stream: T) -> std::io::Result<Self> {
        todo!()
    }

    fn new(stream: T, key: Key<Aes256Gcm>) -> Self {
        todo!()
    }

    fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        todo!()
    }

    fn read(&mut self) -> std::io::Result<Vec<u8>> {
        todo!()
    }
}
