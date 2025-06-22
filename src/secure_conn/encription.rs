use crate::{Error, Result};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;

pub(crate) trait Encryption {
    fn encrypt(&self, input_data: &[u8]) -> Result<(Vec<u8>, [u8; 12])>;
    fn decrypt(&self, encrypted_data: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>>;
}

pub(crate) fn encrypt(
    key: &Key<Aes256Gcm>,
    input_data: &[u8],
) -> crate::Result<(Vec<u8>, [u8; 12])> {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new(key);
    let encrypted_data = cipher
        .encrypt(Nonce::from_slice(&nonce), input_data)
        .map_err(Error::CryptError)?;
    Ok((encrypted_data, nonce))
}

pub(crate) fn decrypt(
    key: &Key<Aes256Gcm>,
    encrypted_data: &[u8],
    nonce: &[u8; 12],
) -> crate::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(&key);
    Ok(
        match cipher.decrypt(Nonce::from_slice(nonce), encrypted_data) {
            Ok(v) => v,
            Err(e) => return Err(Error::CryptError(e)),
        },
    )
}
