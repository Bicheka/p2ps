use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use sha2::Sha256;
use hkdf::Hkdf;
use aes_gcm::{Aes256Gcm, Key};
pub struct Keys {
    secret: EphemeralSecret,
    pub public: PublicKey
}

impl Keys {
    pub fn generate_keys() -> Self{
        let rng = rand::thread_rng();
        let secret = EphemeralSecret::random_from_rng(rng);
        let public = PublicKey::from(&secret);
        Self {
            secret,
            public
        }
    }

    pub fn generate_shared_secret(self, their_public: &PublicKey) -> SharedSecret{
        self.secret.diffie_hellman(their_public)
    }
}

fn derive_keys(shared_secret: &[u8]) -> (Key<Aes256Gcm>, [u8; 12]) {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    hk.expand(b"encryption key", &mut key).expect("HDKF failed");
    hk.expand(b"nonce", &mut nonce).expect("HKDF failed");
    (Key::<Aes256Gcm>::from_slice(&key).to_owned(), nonce)
}

fn encrypt() {
    todo!()
}

fn decrypt() {
    todo!()
}