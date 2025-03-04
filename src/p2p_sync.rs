use crate::common::{Encryption, Keys};
use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use std::io::{Read, Write};

/// Handles encrypted P2P communication.
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
    /// Listens for an incoming handshake and sends back a public key and creates a P2psConnAsync
    pub fn listen_handshake(mut stream: T) -> std::io::Result<Self> {
        // receive their public key
        let mut buffer = [0u8; 32];
        stream.read(&mut buffer)?;

        // generate private and public keys
        let keys = Keys::generate_keys();

        // send public generated public key
        stream.write_all(&keys.get_public_key_bytes())?;

        // create encryption key with private key and their public key
        let key = keys.generate_encryption_key(&Keys::public_key_from_bytes(buffer)?);
        // create P2ps
        Ok(Self { stream, key })
    }

    /// Sends handshake to a peer and uses peer response to construct a P2psConn
    pub fn send_handshake(mut stream: T) -> std::io::Result<Self> {
        // generate public and private keys
        let keys = Keys::generate_keys();

        // send public key
        stream.write_all(&keys.get_public_key_bytes())?;

        // listen for response with their public key
        let mut buffer = [0u8; 32];
        stream.read(&mut buffer)?;

        // generate encryption key with the private key and their public key
        let key = keys.generate_encryption_key(&Keys::public_key_from_bytes(buffer)?);

        // Create a P2psConn
        Ok(Self { stream, key })
    }

    /// takes data, encrypts it and sends it to the peer
    pub fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        let (encrypted_data, nonce) = self.encrypt(data);

        self.stream.write_all(&nonce)?;

        let length = (encrypted_data.len() as u32).to_be_bytes();
        self.stream.write_all(&length)?;

        self.stream.write_all(&encrypted_data)?;
        self.stream.flush()?;

        Ok(())
    }

    /// Reads data sent from peer and decrypts it
    pub fn read(&mut self) -> std::io::Result<Vec<u8>> {
        let mut nonce_buf = [0u8; 12];
        self.stream.read_exact(&mut nonce_buf)?;

        let mut length_buf = [0u8; 4];

        self.stream.read_exact(&mut length_buf)?;
        let length = u32::from_be_bytes(length_buf) as usize;

        let mut encrypted_data = vec![0u8; length];
        self.stream.read_exact(&mut encrypted_data)?;

        let data = self.decrypt(&encrypted_data, &nonce_buf);

        Ok(data)
    }
}
