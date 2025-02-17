use std::io::{Read, Write};

use crate::P2pTls;

impl<T: Read + Write> P2pTls<T> {
    pub fn new(stream: T, shared_key: [u8; 32]) -> Self {
        Self { stream, shared_key }
    }

    pub fn send_encrypted(&mut self, data: &[u8]) -> std::io::Result<()> {
        todo!()
    }

    pub fn recieve_encrypted(&mut self) -> std::io::Result<Vec<u8>> {
        todo!()
    }
}
