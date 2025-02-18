use std::io::{Read, Write};

use aes_gcm::{Aes256Gcm, Key};

use crate::P2ps;

impl<T: Read + Write> P2ps<T> {
    fn new_sync(stream: T, key: Key<Aes256Gcm>) -> Self {
        Self { stream, key }
    }

    pub fn send_encrypted(&mut self, data: &[u8]) -> std::io::Result<()> {
        todo!()
    }

    pub fn recieve_encrypted(&mut self) -> std::io::Result<Vec<u8>> {
        todo!()
    }
}
