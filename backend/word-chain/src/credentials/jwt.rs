use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use crate::encrypt::Aes256;
use crate::response::new_response;

struct JwtKey {
    value: String
}

impl JwtKey {
    fn new() -> Self {
        let jwt_key = match std::env::var("JWT_KEY") {
            Ok(key) => key,
            Err(_) => panic!("JWT_KEY not initialized")
        };

        Self{ value: jwt_key }
    }
}

lazy_static! {
    static ref JWT_KEY: JwtKey = JwtKey::new();
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Jwt {
    account_id: String,
    timestamp: i64
}

impl Jwt {
    pub fn new(account: &str) -> Self {
        let timestamp = chrono::offset::Utc::now().timestamp();
        Self{ account_id: account.to_string(), timestamp }
    }

    pub fn from(bearer: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let jwt = match Aes256::decrypt(&JWT_KEY.value, bearer) {
            Ok(decrypted) => decrypted,
            Err(error) => return Err(error)
        };

        serde_json::from_str::<Jwt>(jwt.as_str()).map_err(|error| error.into())
    }

    pub fn to_string(&self) -> Result<String, Box<dyn std::error::Error>> {

        let raw = serde_json::to_string::<Jwt>(self)?;

        Aes256::encrypt(&JWT_KEY.value, &raw)
    }

    pub fn has_expired(&self) -> bool {

        let diff_sec = chrono::offset::Utc::now().timestamp() - self.timestamp;

        (diff_sec / 60) > 15
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }


    pub fn authorize(id: &str, req: &Request<Incoming>) -> Result<(), Response<Full<Bytes>>>
    {
        // - RFC7235 4.1 :
        // A server generating a 401 (Unauthorized) response MUST send a
        // WWW-Authenticate header field containing at least one challenge

        let auth = match req.headers().get(AUTHORIZATION) {
            Some(auth) => auth,
            None => return Err(new_response()
                .status(StatusCode::UNAUTHORIZED)
                .header(WWW_AUTHENTICATE, "Bearer error=\"missing\"")
                .body(Full::from(Bytes::new()))
                .unwrap())
        };

        let terms = match auth.to_str() {
            Ok(auth) => auth.split(' ').collect::<Vec<&str>>(),
            Err(_) => return Err(new_response()
                .status(StatusCode::UNAUTHORIZED)
                .header(WWW_AUTHENTICATE, "Bearer error=\"malformed\"")
                .body(Full::from(Bytes::new()))
                .unwrap())
        };

        if terms.len() != 2 {
            return Err(new_response()
                .status(StatusCode::UNAUTHORIZED)
                .header(WWW_AUTHENTICATE, "Bearer error=\"malformed\"")
                .body(Full::from(Bytes::new()))
                .unwrap())
        }

        if terms[0] != "Bearer" {
            return Err(new_response()
                .status(StatusCode::UNAUTHORIZED)
                .header(WWW_AUTHENTICATE, "Bearer error=\"unsupported\"")
                .body(Full::from(Bytes::new()))
                .unwrap())
        }

        let jwt = match Jwt::from(terms[1]) {
            Ok(jwt) => jwt,
            Err(_) => return Err(new_response()
                .status(StatusCode::UNAUTHORIZED)
                .header(WWW_AUTHENTICATE, "Bearer error=\"unparsable\"")
                .body(Full::from(Bytes::from("Bad bearer")))
                .unwrap())
        };

        if jwt.has_expired() {
            return Err(new_response()
                .status(StatusCode::UNAUTHORIZED)
                .header(WWW_AUTHENTICATE, "Bearer error=\"expired\"")
                .body(Full::from(Bytes::new()))
                .unwrap())
        }

        if jwt.account_id() != id {
            return Err(new_response()
                .status(StatusCode::FORBIDDEN)
                .body(Full::from(Bytes::new()))
                .unwrap())
        };

        Ok(())
    }
}
