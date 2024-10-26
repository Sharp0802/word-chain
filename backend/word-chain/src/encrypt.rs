use std::fmt::{Debug, Display, Formatter};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use aes_gcm::aead::{Aead, OsRng};


struct Error {
    message: String
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for Error {}

impl Error {
    fn from(msg: &str) -> Self {
        Self { message: msg.to_string() }
    }
}


use rand::distributions::{Alphanumeric, DistString};

pub struct Salt {
    value: String
}

impl Salt
{
    pub fn new() -> Self {
        Self {
            value: Alphanumeric.sample_string(&mut rand::thread_rng(), 32)
        }
    }

    pub fn from(salt: &str) -> Self {
        Self {
            value: salt.to_string()
        }
    }

    pub fn salt(&self, key: &str) -> String {
        Sha256::hash(&(self.value.clone() + key))
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}


use sha3::Digest;

pub struct Sha256;

impl Sha256 {
    pub fn hash(key: &str) -> String {
        hex::encode(&Self::hash_raw(key))
    }

    fn hash_raw(key: &str) -> Vec<u8> {
        sha3::Sha3_256::digest(key.as_bytes()).to_vec()
    }
}


pub struct Aes256;

impl Aes256 {
    pub fn encrypt(key_str: &str, plaintext: &str) -> Result<String, Box<dyn std::error::Error>> {
        let key_hash = Sha256::hash_raw(key_str);
        let key = Key::<Aes256Gcm>::from_slice(&key_hash);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let cipher = Aes256Gcm::new(key);

        let ciphered_data = match cipher.encrypt(&nonce, plaintext.as_bytes()) {
            Ok(v) => v,
            Err(e) => return Err(Box::new(Error::from(&e.to_string())))
        };

        // combining nonce and encrypted data together for storage purpose
        let mut encrypted_data: Vec<u8> = nonce.to_vec();
        encrypted_data.extend_from_slice(&ciphered_data);

        Ok(hex::encode(&encrypted_data))
    }

    pub fn decrypt(key_str: &str, encrypted_data: &str) -> Result<String, Box<dyn std::error::Error>> {
        let encrypted_data = hex::decode(encrypted_data.as_bytes())?;

        let key_hash = Sha256::hash_raw(key_str);
        let key = Key::<Aes256Gcm>::from_slice(&key_hash);

        let (nonce_arr, ciphered_data) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_arr);

        let cipher = Aes256Gcm::new(key);

        let plaintext = match cipher.decrypt(nonce, ciphered_data) {
            Ok(v) => v,
            Err(e) => return Err(Box::new(Error::from(&e.to_string())))
        };

        String::from_utf8(plaintext).map_err(|e| e.into())
    }
}
