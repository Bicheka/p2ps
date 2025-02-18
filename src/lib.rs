use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

/// Synchronous implementation of P2pTls
pub mod p2p_sync;

/// Asynchronous implementation of P2pTls
pub mod p2p_async;

pub struct P2pTls<T> {
    stream: T,
    key: Key<Aes256Gcm>,
}

pub struct Keys {
    secret: EphemeralSecret,
    pub public: PublicKey,
}

impl Keys {
    pub fn generate_keys() -> Self {
        let rng = rand::thread_rng();
        let secret = EphemeralSecret::random_from_rng(rng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn generate_encryption_key(self, their_public: &PublicKey) -> Key<Aes256Gcm> {
        let shared_secret = self.secret.diffie_hellman(their_public).to_bytes();
        let hk = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut key = [0u8; 32];
        hk.expand(b"encryption key", &mut key).expect("HDKF failed");
        Key::<Aes256Gcm>::from_slice(&key).to_owned()
    }
}

pub(crate) fn encrypt(key: &Key<Aes256Gcm>, input_data: &[u8]) -> (Vec<u8>, [u8; 12]) {
    let nonce = [0u8; 12];
    let cipher = Aes256Gcm::new(key);
    let encrypted_data = cipher
        .encrypt(&nonce.into(), input_data)
        .expect("Error encrypting data");
    (encrypted_data, nonce)
}

pub(crate) fn decrypt(key: &Key<Aes256Gcm>, encrypted_data: &[u8], nonce: &[u8; 12]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key);
    cipher
        .decrypt(Nonce::from_slice(nonce), encrypted_data)
        .expect("decryption failed")
}
