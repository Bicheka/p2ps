use aes_gcm::{Aes256Gcm, Key};
use hkdf::Hkdf;
use sha2::Sha256;
use std::io;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub(crate) trait Encryption {
    fn encrypt(&self, input_data: &[u8]) -> (Vec<u8>, [u8; 12]);
    fn decrypt(&self, encrypted_data: &[u8], nonce: &[u8; 12]) -> Vec<u8>;
}

/// Keys needed for Diffie-Hellman key exchange
pub struct Keys {
    secret: EphemeralSecret,
    pub public: PublicKey,
}

impl Keys {
    pub(crate) fn generate_keys() -> Self {
        let rng = rand::thread_rng();
        let secret = EphemeralSecret::random_from_rng(rng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub(crate) fn generate_encryption_key(self, their_public: &PublicKey) -> Key<Aes256Gcm> {
        let shared_secret = self.secret.diffie_hellman(their_public).to_bytes();
        let hk = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut key = [0u8; 32];
        hk.expand(b"encryption key", &mut key).expect("HDKF failed");
        Key::<Aes256Gcm>::from_slice(&key).to_owned()
    }

    pub(crate) fn public_key_from_bytes(public_key: [u8; 32]) -> io::Result<PublicKey> {
        Ok(PublicKey::try_from(public_key)
            .expect("Could not convert from byte array into PublicKey"))
    }

    pub(crate) fn get_public_key_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }
}
