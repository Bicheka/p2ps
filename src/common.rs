use crate::{Error, Result};
use aes_gcm::{Aes256Gcm, Key};
use hkdf::Hkdf;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub(crate) trait Encryption {
    fn encrypt(&self, input_data: &[u8]) -> Result<(Vec<u8>, [u8; 12])>;
    fn decrypt(&self, encrypted_data: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>>;
}
/// Keys needed for Diffie-Hellman key exchange
pub struct Keys {
    secret: EphemeralSecret,
    pub public: PublicKey,
    srng: Option<ChaCha20Rng>,
}

impl Keys {
    pub(crate) fn generate_keys() -> Self {
        let rng = rand::thread_rng();
        let secret = EphemeralSecret::random_from_rng(rng);
        let public = PublicKey::from(&secret);
        Self {
            secret,
            public,
            srng: None,
        }
    }

    pub(crate) fn generate_encryption_key(
        mut self,
        their_public: &PublicKey,
    ) -> Result<Key<Aes256Gcm>> {
        let shared_secret = self.secret.diffie_hellman(their_public).to_bytes();
        let rng = ChaCha20Rng::from_seed(shared_secret);
        self.srng = Some(rng);
        let hk = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut key = [0u8; 32];
        let mut salt = [0u8; 16];
        self.srng.unwrap().fill_bytes(&mut salt);
        if let Err(e) = hk.expand(&salt, &mut key) {
            return Err(Error::KDFError(e));
        }
        Ok(Key::<Aes256Gcm>::from_slice(&key).to_owned())
    }

    pub(crate) fn public_key_from_bytes(public_key: [u8; 32]) -> PublicKey {
        PublicKey::from(public_key)
    }

    pub(crate) fn get_public_key_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }
}
