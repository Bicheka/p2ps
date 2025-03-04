use crate::common::{Encryption, Keys};
use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Handles encrypted P2P communication asynchronously.
pub struct P2psConnAsync<T: AsyncRead + AsyncWrite + Unpin + Send> {
    stream: T,
    key: Key<Aes256Gcm>,
}

impl<T> Encryption for P2psConnAsync<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
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

impl<T: AsyncRead + AsyncWrite + Unpin + Send> P2psConnAsync<T> {
    /// Listens for an incoming handshake asynchronously and sends back a public key and creates a P2psConnAsync
    pub async fn listen_handshake(mut stream: T) -> std::io::Result<Self> {
        // receive their public key
        let mut buffer = [0u8; 32];
        stream.read(&mut buffer).await?;

        // generate private and public keys
        let keys = Keys::generate_keys();

        // send public generated public key
        stream.write_all(&keys.get_public_key_bytes()).await?;

        // create encryption key with private key and their public key
        let key = keys.generate_encryption_key(&Keys::public_key_from_bytes(buffer)?);
        // create P2ps
        Ok(Self { stream, key })
    }

    /// Sends handshake to a peer and uses peer response to construct a P2psConnAsync
    pub async fn send_handshake(mut stream: T) -> std::io::Result<Self> {
        // generate private and public keys
        let keys = Keys::generate_keys();

        // send public key,
        stream.write_all(&keys.get_public_key_bytes()).await?;

        // listen for response with their public key
        let mut buffer = [0u8; 32];
        stream.read(&mut buffer).await?;

        // generate encryption key with private key and their public key
        let key = keys.generate_encryption_key(&Keys::public_key_from_bytes(buffer)?);

        // create P2ps
        Ok(Self { stream, key })
    }

    /// Takes data, encrypts it, and sends it to the peer
    pub async fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
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

    /// Reads data from a stream decrypts it returning the data
    pub async fn read(&mut self) -> std::io::Result<Vec<u8>> {
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
