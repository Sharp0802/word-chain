use crate::credentials::jwt::Jwt;
use crate::response::new_response;
use crate::routes::account::AccountRow;
use chrono::TimeDelta;
use cookie::Cookie;
use headers::HeaderMapExt;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{SET_COOKIE, WWW_AUTHENTICATE};
use hyper::{Request, Response, StatusCode};
use lazy_static::lazy_static;
use std::error::Error;
use tokio_postgres::Client;

static ACCESS_TOKEN_EXPIRES: TimeDelta = TimeDelta::minutes(15);
static REFRESH_TOKEN_EXPIRES: TimeDelta = TimeDelta::days(90);


struct TokenConfig {
    secure: bool,
}

impl TokenConfig {
    fn new() -> Self {
        Self {
            secure: std::env::var("COOKIE_SECURE")
                .map(|v| v == "true")
                .unwrap_or(true)
        }
    }
}

lazy_static! {
    static ref TOKEN_CONFIG: TokenConfig = TokenConfig::new();
}


pub trait Token {
    fn new(who: &str) -> Self;
    fn from_request(req: &Request<Incoming>) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized;
    fn who(&self) -> &str;
    fn expired(&self) -> bool;
}

pub struct AccessToken {
    token: Jwt,
}

pub struct RefreshToken {
    token: Jwt,
}

fn get_token_from(name: &str, req: &Request<Incoming>) -> Option<String> {
    match req.headers()
        .typed_get::<headers::Cookie>()
        .map(|cookie| cookie.get(name).map(|v| v.to_string())) {
        Some(Some(token)) => Some(token),
        _ => None
    }
}

fn get_elapsed(jwt: &Jwt) -> TimeDelta {
    let timestamp = chrono::DateTime::from_timestamp(jwt.timestamp(), 0).unwrap();
    chrono::offset::Utc::now() - timestamp
}

impl Token for AccessToken {
    fn new(who: &str) -> Self {
        Self {
            token: Jwt::new(who)
        }
    }

    fn from_request(req: &Request<Incoming>) -> Result<Self, Box<dyn Error>> {
        let encrypted_jwt = match get_token_from("access_token", req) {
            None => return Err("missing access-token".into()),
            Some(token) => token
        };

        let jwt = match Jwt::from(&encrypted_jwt) {
            Ok(jwt) => jwt,
            Err(e) => return Err(e)
        };

        Ok(Self { token: jwt })
    }

    fn who(&self) -> &str {
        &self.token.account_id()
    }

    fn expired(&self) -> bool {
        get_elapsed(&self.token) > ACCESS_TOKEN_EXPIRES
    }
}

impl AccessToken {
    pub async fn validate_authorization(req: &Request<Incoming>, client: &Client) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
        fn unauthorized(msg: Option<String>) -> Response<Full<Bytes>> {
            new_response()
                .status(StatusCode::UNAUTHORIZED)
                .header(WWW_AUTHENTICATE, "Cookie")
                .body(Full::from(Bytes::from(msg.unwrap_or(String::new()))))
                .unwrap()
        }

        let access_token = match AccessToken::from_request(&req) {
            Ok(access_token) => access_token,
            Err(e) => return Err(unauthorized(Some(e.to_string())))
        };


        let refresh;
        if access_token.expired() {
            // Automatically refresh tokens
            let refresh_token = match RefreshToken::from_request(&req) {
                Ok(refresh_token) => refresh_token,
                Err(e) => return Err(unauthorized(Some(e.to_string())))
            };
            if refresh_token.expired() || access_token.who() != refresh_token.who() {
                return Err(unauthorized(None));
            }

            // TODO: Refresh token should be used only once

            refresh = true;
        } else {
            refresh = false;
        }

        let account = match client.query_one(
            "SELECT * FROM accounts WHERE id = $1",
            &[&access_token.who()]).await {
            Ok(account) => AccountRow::from(account),
            Err(_) => return Err(unauthorized(None))
        };
        if account.id() != access_token.who() {
            return Err(unauthorized(None));
        };

        let mut response = Response::new(Full::from(Bytes::new()));
        if refresh {
            let new_refresh_token = match RefreshToken::new(account.id()).token.to_string() {
                Ok(refresh_token) => refresh_token,
                Err(e) => return Err(new_response()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::from(Bytes::from(e.to_string())))
                    .unwrap())
            };

            let new_access_token = match AccessToken::new(account.id()).token.to_string() {
                Ok(access_token) => access_token,
                Err(e) => return Err(new_response()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::from(Bytes::from(e.to_string())))
                    .unwrap())
            };

            response.headers_mut().append(
                SET_COOKIE,
                Cookie::build(("refresh_token", new_refresh_token))
                    .http_only(true)
                    .secure(TOKEN_CONFIG.secure)
                    .to_string()
                    .parse()
                    .unwrap());
            response.headers_mut().append(
                SET_COOKIE,
                Cookie::build(("access_token", new_access_token))
                    .http_only(true)
                    .secure(TOKEN_CONFIG.secure)
                    .to_string()
                    .parse()
                    .unwrap());
        }

        Ok(response)
    }

    pub async fn authorize(who: &str) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
        let new_refresh_token = match RefreshToken::new(who).token.to_string() {
            Ok(refresh_token) => refresh_token,
            Err(e) => return Err(new_response()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::from(Bytes::from(e.to_string())))
                .unwrap())
        };

        let new_access_token = match AccessToken::new(who).token.to_string() {
            Ok(access_token) => access_token,
            Err(e) => return Err(new_response()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::from(Bytes::from(e.to_string())))
                .unwrap())
        };

        let mut response = Response::new(Full::from(Bytes::new()));

        response.headers_mut().append(
            SET_COOKIE,
            Cookie::build(("refresh_token", new_refresh_token))
                .http_only(true)
                .secure(TOKEN_CONFIG.secure)
                .to_string()
                .parse()
                .unwrap());
        response.headers_mut().append(
            SET_COOKIE,
            Cookie::build(("access_token", new_access_token))
                .http_only(true)
                .secure(TOKEN_CONFIG.secure)
                .to_string()
                .parse()
                .unwrap());

        Ok(response)
    }
}

impl Token for RefreshToken {
    fn new(who: &str) -> Self {
        Self {
            token: Jwt::new(who)
        }
    }

    fn from_request(req: &Request<Incoming>) -> Result<Self, Box<dyn Error>> {
        let encrypted_jwt = match get_token_from("refresh_token", req) {
            None => return Err("missing refresh-token".into()),
            Some(token) => token
        };

        let jwt = match Jwt::from(&encrypted_jwt) {
            Ok(jwt) => jwt,
            Err(e) => return Err(e)
        };

        Ok(Self { token: jwt })
    }

    fn who(&self) -> &str {
        &self.token.account_id()
    }

    fn expired(&self) -> bool {
        get_elapsed(&self.token) > REFRESH_TOKEN_EXPIRES
    }
}