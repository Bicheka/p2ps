use aes_gcm::{Aes256Gcm, Key};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::P2pTls;

impl<T: AsyncRead + AsyncWrite + Unpin> P2pTls<T> {
    pub fn new_async(stream: T, key: Key<Aes256Gcm>) -> Self {
        Self { stream, key }
    }

    // TODO:Handshake function to send and recieve public keys throught tcp

    /// Takes data, encrypts it, and then writes a nonce, the length of the data and the actual data
    /// to the stream
    pub async fn write_async(&mut self, data: &[u8]) -> std::io::Result<()> {
        let (encrypted_data, nonce) = self.encrypt(data);
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
        // Read nonce
        let mut nonce_buf = [0u8; 12];
        self.stream.read_exact(&mut nonce_buf).await?;
        //
        // u32 = 8*4
        let mut length_buf = [0u8; 4];
        self.stream.read_exact(&mut length_buf).await?;
        let length = u32::from_be_bytes(length_buf) as usize;

        // Read data
        let mut encrypted_data = vec![0u8; length];
        self.stream.read_exact(&mut encrypted_data).await?;

        let data = self.decrypt(&encrypted_data, &nonce_buf);

        Ok(data)
    }
}
