use std::io::{Read, Write};

use aes_gcm::{Aes256Gcm, Key};

use crate::P2pTls;

impl<T: Read + Write> P2pTls<T> {
    fn new(stream: T, key: Key<Aes256Gcm>) -> Self {
        Self { stream, key }
    }

    pub fn send_encrypted(&mut self, data: &[u8]) -> std::io::Result<()> {
        todo!()
    }

    pub fn recieve_encrypted(&mut self) -> std::io::Result<Vec<u8>> {
        todo!()
    }
}
