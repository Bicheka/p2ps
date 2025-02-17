use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{encrypt, P2pTls};

impl<T: AsyncRead + AsyncWrite + Unpin> P2pTls<T> {
    pub fn new_async(stream: T, shared_key: [u8; 32]) -> Self {
        Self { stream, shared_key }
    }

    // TODO:Handshake function to send and recieve public keys throught tcp

    /// Takes data, encrypts it, and then writes a nonce, the length of the data and the actual data
    /// to the stream
    pub async fn write_async(&mut self, data: &[u8]) -> std::io::Result<()> {
        let (encrypted_data, nonce) = encrypt(&self.shared_key, data);
        // send nonce
        self.stream.write_all(&nonce).await?;

        // send encrypted data length as u32
        let length = (encrypted_data.len() as u32).to_be_bytes();
        self.stream.write_all(&length).await?;

        // send encrypted data
        self.stream.write_all(&encrypted_data).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn recieve_encrypted_async(&mut self) -> std::io::Result<Vec<u8>> {
        todo!()
    }
}
