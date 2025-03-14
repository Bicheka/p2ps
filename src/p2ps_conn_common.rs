use crate::Error;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};

pub(crate) fn encrypt(
    key: &Key<Aes256Gcm>,
    input_data: &[u8],
) -> crate::Result<(Vec<u8>, [u8; 12])> {
    let nonce = [0u8; 12];
    let cipher = Aes256Gcm::new(&key);
    let encrypted_data = match cipher.encrypt(&nonce.into(), input_data) {
        Ok(v) => v,
        Err(e) => return Err(Error::CryptError(e)),
    };
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
