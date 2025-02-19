use aes_gcm::{Aes256Gcm, Key};
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Keys, P2ps};

#[async_trait]
pub trait P2psAsync<T>: Sized
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn listen_handshake(stream: T) -> std::io::Result<Self>;
    async fn send_handshake(stream: T) -> std::io::Result<Self>;
    fn new(stream: T, key: Key<Aes256Gcm>) -> Self;
    async fn write(&mut self, data: &[u8]) -> std::io::Result<()>;
    async fn read(&mut self) -> std::io::Result<Vec<u8>>;
}

#[async_trait]
impl<T> P2psAsync<T> for P2ps<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn listen_handshake(mut stream: T) -> std::io::Result<Self> {
        // recieve their public key
        let mut buffer = [0u8; 32];
        stream.read(&mut buffer).await?;

        // generate private and public keys
        let keys = Keys::generate_keys();

        // send public generated public key
        stream.write_all(&keys.get_public_key_bytes()).await?;

        // create encryption key with private key and their public key
        let encryption_key = keys.generate_encryption_key(&Keys::public_key_from_bytes(buffer)?);
        // create P2ps
        Ok(Self::new(stream, encryption_key))
    }

    async fn send_handshake(mut stream: T) -> std::io::Result<Self> {
        // generate private and public keys
        let keys = Keys::generate_keys();

        // send public key,
        stream.write_all(&keys.get_public_key_bytes()).await?;

        // listen for response with their public key
        let mut buffer = [0u8; 32];
        stream.read(&mut buffer).await?;

        // generate encryption key with private key and their public key
        let encryption_key = keys.generate_encryption_key(&Keys::public_key_from_bytes(buffer)?);

        // create P2ps
        Ok(Self::new(stream, encryption_key))
    }

    fn new(stream: T, key: Key<Aes256Gcm>) -> Self {
        Self { stream, key }
    }

    /// Takes data, encrypts it, and then writes a nonce, the length of the data and the actual data
    /// to the stream
    async fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
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

    async fn read(&mut self) -> std::io::Result<Vec<u8>> {
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
