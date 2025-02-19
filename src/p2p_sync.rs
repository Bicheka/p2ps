use std::io::{Read, Write};

use aes_gcm::{Aes256Gcm, Key};

use crate::P2ps;

pub trait P2psSync<T>: Sized
where
    T: Read + Write,
{
    fn listen_handshake(mut stream: T) -> std::io::Result<Self>;
    fn send_handshake(mut stream: T) -> std::io::Result<Self>;
    fn new(stream: T, key: Key<Aes256Gcm>) -> Self;
    fn write(&mut self, data: &[u8]) -> std::io::Result<()>;
    fn read(&mut self) -> std::io::Result<Vec<u8>>;
}

impl<T> P2psSync<T> for P2ps<T>
where
    T: Read + Write,
{
    fn listen_handshake(mut stream: T) -> std::io::Result<Self> {
        todo!()
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
