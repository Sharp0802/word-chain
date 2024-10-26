use crate::encrypt::{Aes256, Salt};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::error::Error;

struct JwtKey {
    value: String
}

impl JwtKey {
    fn new() -> Self {
        let jwt_key = match std::env::var("JWT_KEY") {
            Ok(key) => key,
            Err(_) => panic!("JWT_KEY not initialized")
        };

        Self { value: jwt_key }
    }
}

lazy_static! {
    static ref JWT_KEY: JwtKey = JwtKey::new();
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Jwt {
    account_id: String,
    timestamp: i64,
    nonce: String
}

impl Jwt {
    pub fn new(account: &str) -> Self {
        let timestamp = chrono::offset::Utc::now().timestamp();
        Self {
            account_id: account.to_string(),
            timestamp,
            nonce: Salt::new().value().to_string()
        }
    }

    pub fn from(data: &str) -> Result<Self, Box<dyn Error>> {
        let jwt = match Aes256::decrypt(&JWT_KEY.value, data) {
            Ok(decrypted) => decrypted,
            Err(error) => return Err(error)
        };

        serde_json::from_str::<Jwt>(jwt.as_str()).map_err(|error| error.into())
    }

    pub fn to_string(&self) -> Result<String, Box<dyn std::error::Error>> {
        let raw = serde_json::to_string::<Jwt>(self)?;

        Aes256::encrypt(&JWT_KEY.value, &raw)
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }
}
