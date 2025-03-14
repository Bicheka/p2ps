use aes_gcm::aead;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Key error: {0}")]
    KDFError(hkdf::InvalidLength),
    #[error("Cryptography error: {0}")]
    CryptError(aead::Error),
    #[error("Other error: {0}")]
    Other(String),
}
