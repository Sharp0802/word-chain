use crate::credentials::basic::BasicAuth;
use crate::credentials::jwt::Jwt;
use crate::encrypt::Salt;
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

                    let auth = match req.headers().get(AUTHORIZATION) {
                        Some(header) => header,
                        None => return Ok(new_response()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Full::from(Bytes::new()))
                            .unwrap())
                    };

                    let auth_str = match auth.to_str() {
                        Ok(auth_str) => auth_str,
                        Err(_) => return Ok(new_response()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Full::from(Bytes::new()))
                            .unwrap())
                    };

                    let login = match BasicAuth::from(auth_str) {
                        Some(login) => login,
                        None => return Ok(new_response()
                            .status(StatusCode::UNAUTHORIZED)
                            .header(WWW_AUTHENTICATE, "Basic realm=\"malformed\"")
                            .body(Full::from(Bytes::new()))
                            .unwrap())
                    };

                    let account = match self.client.query_one(r#"
                        SELECT * FROM accounts WHERE id = $1;
                        "#, &[&login.id()]).await {
                        Ok(account) => AccountRow::from(account),
                        Err(_) => return Ok(new_response()
                            .status(StatusCode::NOT_FOUND)
                            .body(Full::from(Bytes::new()))
                            .unwrap())
                    };

                    let passhash = Salt::from(account.salt()).salt(&login.password());
                    if account.passhash() != passhash {
                        return Ok(new_response()
                            .status(StatusCode::UNAUTHORIZED)
                            .header(WWW_AUTHENTICATE, "Basic realm=\"password-mismatch\"")
                            .body(Full::from(Bytes::new()))
                            .unwrap())
                    }

                    let jwt = match Jwt::new(account.id()).to_string() {
                        Ok(jwt) => jwt,
                        Err(e) => return Ok(new_response()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Full::from(Bytes::from(e.to_string())))
                            .unwrap())
                    };

                    Ok(new_response()
                        .body(Full::from(Bytes::from(jwt)))
                        .unwrap())
                },

                _ => Ok(new_response()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Full::from(Bytes::new()))
                    .unwrap()),
            }
        })
    }
}
