use crate::credentials::tokens::AccessToken;
use crate::encrypt::Salt;
use crate::request::read_body;
use crate::response::new_response;
use crate::route::{FutureAction, FuturePreparation, Route};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::LOCATION;
use hyper::{Method, Request, StatusCode};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use tokio_postgres::{Client, Row};

pub struct AccountRoute {
    info_route: AccountInfoRoute,
    client: Arc<Client>,
}

pub struct AccountInfoRoute {
    client: Arc<Client>,
}

#[derive(Debug, Deserialize)]
struct AccountCreationDTO {
    id: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct AccountViewDTO {
    id: String
}

pub struct AccountRow {
    id: String,
    salt: String,
    passhash: String
}

impl AccountRow {
    pub fn from(row: Row) -> Self {
        Self{
            id: row.get(0),
            salt: row.get(1),
            passhash: row.get(2)
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn salt(&self) -> &str {
        &self.salt
    }

    pub fn passhash(&self) -> &str {
        &self.passhash
    }
}

impl AccountViewDTO {
    fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl AccountRoute {
    pub fn new(client: Arc<Client>) -> Self {
        Self { info_route: AccountInfoRoute::new(client.clone()), client }
    }
}

impl AccountInfoRoute {
    pub fn new(client: Arc<Client>) -> Self {
        Self { client }
    }
}

impl Display for AccountRoute {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "word_chain::routes::account::AccountRoute")
    }
}

impl Route for AccountRoute {
    fn name(&self) -> &str {
        "account"
    }

    fn children(&self) -> Vec<&dyn Route> {
        vec![&self.info_route]
    }

    fn up(&self) -> FuturePreparation
    {
        Box::pin(async move {
            self.client.execute(r#"
            CREATE TABLE IF NOT EXISTS accounts (
                id       TEXT PRIMARY KEY,
                salt     TEXT,
                password TEXT
            );
            "#, &[]).await?;

            Ok(())
        })
    }

    fn down(&self) -> FuturePreparation
    {
        Box::pin(async move {
            self.client.execute(r#"
                DROP TABLE accounts;
                "#, &[]).await?;

            Ok(())
        })
    }

    fn map(&self, req: Request<Incoming>) -> FutureAction
    {
        Box::pin(async move {
            if req.method() != Method::POST {
                return Ok(new_response()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Full::from(Bytes::new()))
                    .unwrap())
            }

            let body = match read_body(req.into_body()).await {
                Ok(body) => body,
                Err(e) => return Ok(e)
            };

            let creation = match serde_urlencoded::from_bytes::<AccountCreationDTO>(&body) {
                Ok(creation) => creation,
                Err(error) => return Ok(new_response()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::from(Bytes::from(error.to_string())))
                    .unwrap())
            };

            let salt = Salt::new();

            if let Err(error) = self.client.execute(
                "INSERT INTO accounts (id, salt, password) VALUES ($1, $2, $3);",
                &[&creation.id, &salt.value(), &salt.salt(&creation.password)]).await {

                // NOTE: Failed to insert row: Maybe duplicated identifier?
                return Ok(new_response()
                    .status(StatusCode::CONFLICT)
                    .body(Full::from(Bytes::from(error.to_string())))
                    .unwrap());
            }

            Ok(new_response()
                .status(StatusCode::CREATED)
                .header(LOCATION, format!("/account/{}", creation.id))
                .body(Full::from(Bytes::new()))
                .unwrap())
        })
    }
}

impl Display for AccountInfoRoute {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "word_chain::routes::account::AccountInfoRoute")
    }
}

impl Route for AccountInfoRoute {
    fn name(&self) -> &str { "*" }

    fn children(&self) -> Vec<&dyn Route> { vec![] }

    fn up(&self) -> FuturePreparation
    { Box::pin(async move { Ok(()) }) }

    fn down(&self) -> FuturePreparation
    { Box::pin(async move { Ok(()) }) }

    fn map(&self, req: Request<Incoming>) -> FutureAction
    {
        Box::pin(async move {
            let id = req.uri().path().split('/').last().unwrap();

            if req.method() == Method::DELETE {
                let _ = match AccessToken::validate_authorization(&req, &self.client).await {
                    Ok(response) => response,
                    Err(e) => return Ok(e)
                };

                if let Err(_) = self.client.execute(r#"
                DELETE FROM accounts WHERE id = $1;
                "#, &[&id]).await {

                    // Q: WHY DON'T WE HANDLE ERROR?
                    // A: IT'S SAFE TO IGNORE

                    // Although an authorized account should exist,
                    // If deleting the account failed, It may be a race-condition.
                    // But, we don't have to lock function to prevent it.
                    // If the account is authorized in any way,
                    // The expected result (account deleted) will be occurred
                }

                // NOTE: If user uses access-token after account deleted,
                // User can access to account that user doesn't own
                Ok(new_response().body(Full::from(Bytes::new())).unwrap())
            }
            else if req.method() == Method::GET {
                let row = match self.client.query_one(r#"
                    SELECT * FROM accounts WHERE id = $1;
                    "#, &[&id]).await {
                    Ok(row) => row,
                    Err(_) => return Ok(new_response()
                        .status(StatusCode::NOT_FOUND)
                        .body(Full::from(Bytes::new()))
                        .unwrap())
                };

                let dto = AccountViewDTO::new(AccountRow::from(row).id());

                let json = match serde_json::to_string::<AccountViewDTO>(&dto) {
                    Ok(json) => json,
                    Err(e) => return Err(e.into())
                };

                Ok(new_response().body(Full::from(Bytes::from(json))).unwrap())
            }
            else {
                Ok(new_response()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Full::from(Bytes::new()))
                    .unwrap())
            }
        })
    }
}
