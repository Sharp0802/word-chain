use crate::credentials::basic::BasicAuth;
use crate::credentials::tokens::AccessToken;
use crate::response::new_response;
use crate::route::{FutureAction, FuturePreparation, Route};
use crate::routes::account::AccountRow;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use hyper::{Method, Request, StatusCode};
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use tokio_postgres::Client;

pub struct LoginRoute {
    client: Arc<Client>
}

impl LoginRoute {
    pub fn new(client: Arc<Client>) -> Self {
        Self { client }
    }
}

impl Display for LoginRoute {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "word_chain::routes::login::LoginRoute")
    }
}

impl Route for LoginRoute {
    fn name(&self) -> &str {
        "login"
    }

    fn children(&self) -> Vec<&dyn Route> {
        vec![]
    }

    fn up(&self) -> FuturePreparation {
        Box::pin(async { Ok({}) })
    }

    fn down(&self) -> FuturePreparation {
        Box::pin(async { Ok({}) })
    }

    fn map(&self, req: Request<Incoming>) -> FutureAction {
        Box::pin(async move {
            match req.method() {
                &Method::POST => {
                    let auth_str = match req.headers().get(AUTHORIZATION).map(|v| v.to_str()) {
                        Some(Ok(s)) => s,
                        _ => return Ok(new_response()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Full::from(Bytes::new()))
                            .unwrap())
                    };

                    let auth = match BasicAuth::from(auth_str) {
                        Some(auth) => auth,
                        None => return Ok(new_response()
                            .status(StatusCode::UNAUTHORIZED)
                            .header(WWW_AUTHENTICATE, "Basic realm=\"malformed\"")
                            .body(Full::from(Bytes::new()))
                            .unwrap())
                    };

                    let account = match self.client.query_one(
                        "SELECT * FROM accounts WHERE id = $1",
                        &[&auth.id()]).await {
                        Ok(row) => AccountRow::from(row),
                        Err(_) => return Ok(new_response()
                            .status(StatusCode::UNAUTHORIZED)
                            .header(WWW_AUTHENTICATE, "Basic realm=\"account not found\"")
                            .body(Full::from(Bytes::new()))
                            .unwrap())
                    };

                    let passhash = account.salt().salt(auth.password());
                    if account.passhash() != passhash {
                        return Ok(new_response()
                            .status(StatusCode::UNAUTHORIZED)
                            .header(WWW_AUTHENTICATE, "Basic realm=\"password mismatched\"")
                            .body(Full::from(Bytes::new()))
                            .unwrap())
                    };

                    let response = match AccessToken::authorize(account.id()).await {
                        Ok(response) => response,
                        Err(e) => return Ok(e)
                    };

                    Ok(response)
                }

                _ => Ok(new_response()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Full::from(Bytes::new()))
                    .unwrap()),
            }
        })
    }
}
