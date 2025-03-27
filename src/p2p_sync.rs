use crate::common::{Encryption, Keys};
use crate::{Error, Result};
use aes_gcm::{Aes256Gcm, Key};
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
    fn encrypt(&self, input_data: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
        crate::p2ps_conn_common::encrypt(&self.key, input_data)
    }

    fn decrypt(&self, encrypted_data: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        crate::p2ps_conn_common::decrypt(&self.key, encrypted_data, nonce)
    }
}

impl<T> P2psConn<T>
where
    T: Read + Write,
{
    /// Listens for an incoming handshake and sends back a public key and creates a P2psConnAsync
    pub fn listen_handshake(mut stream: T) -> Result<Self> {
        // receive their public key
        let mut buffer = [0u8; 32];
        stream.read_exact(&mut buffer)?;

        // generate private and public keys
        let keys = Keys::generate_keys();

        // send public generated public key
        stream.write_all(&keys.get_public_key_bytes())?;

        // create encryption key with private key and their public key
        let key = keys.generate_encryption_key(&Keys::public_key_from_bytes(buffer))?;
        // create P2ps
        Ok(Self { stream, key })
    }

    /// Sends handshake to a peer and uses peer response to construct a P2psConn
    pub fn send_handshake(mut stream: T) -> Result<Self> {
        // generate public and private keys
        let keys = Keys::generate_keys();

        // send public key
        stream.write_all(&keys.get_public_key_bytes())?;

        // listen for response with their public key
        let mut buffer = [0u8; 32];
        stream.read_exact(&mut buffer)?;

        // generate encryption key with the private key and their public key
        let key = keys.generate_encryption_key(&Keys::public_key_from_bytes(buffer))?;

        // Create a P2psConn
        Ok(Self { stream, key })
    }

    /// takes data, encrypts it and sends it to the peer
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        let (encrypted_data, nonce) = self.encrypt(data)?;

        self.stream.write_all(&nonce)?;

        let length = (encrypted_data.len() as u32).to_be_bytes();
        self.stream.write_all(&length)?;

        self.stream.write_all(&encrypted_data)?;
        self.stream.flush()?;

        Ok(())
    }

    /// Reads data from a stream decrypts it returning the data and len
    fn read_len(&mut self) -> Result<(Vec<u8>, usize)> {
        // Read nonce
        let mut nonce_buf = [0u8; 12];
        self.stream.read_exact(&mut nonce_buf)?;
        //
        // u32 = 8*4
        let mut length_buf = [0u8; 4];
        self.stream.read_exact(&mut length_buf)?;
        let length = u32::from_be_bytes(length_buf) as usize;

        // Read data
        let mut encrypted_data = vec![0u8; length];
        self.stream.read_exact(&mut encrypted_data)?;

        let data = self.decrypt(&encrypted_data, &nonce_buf)?;

        Ok((data, length))
    }

    /// Reads data from a stream decrypts it returning the data and len
    pub fn read(&mut self) -> Result<Vec<u8>> {
        let (data, _) = self.read_len()?;
        Ok(data)
    }

    /// Reads data from a stream decrypts it then writes it to a provided slice.
    /// The slice will remain unmodified if any error occurs.
    pub fn read_to_slice(&mut self, slice: &mut [u8]) -> Result<()> {
        let (data, len) = self.read_len()?;
        if len <= slice.len() {
            slice[..len].copy_from_slice(&data[..len]);
            Ok(())
        } else {
            Err(Error::Other(
                "Provided slice cannot fit data from read".to_string(),
            ))
        }
    }

    /// Reads data from a stream decrypts it then writes it to a Vec
    pub fn read_to_buf(&mut self, buf: &mut Vec<u8>) -> Result<()> {
        let (data, _) = self.read_len()?;
        buf.extend(data);
        Ok(())
    }
}
