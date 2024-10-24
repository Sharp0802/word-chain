use std::fmt::{Display, Formatter};
use std::sync::Arc;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, StatusCode};
use tokio_postgres::Client;
use crate::routes::account::AccountRoute;
use crate::response::new_response;
use crate::route::{FutureAction, FuturePreparation, Route};


pub struct RootRoute {
    account_route: AccountRoute
}

impl RootRoute {
    pub fn new(client: &Arc<Client>) -> RootRoute {
        Self { account_route: AccountRoute::new(client.clone()) }
    }
}

impl Display for RootRoute {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "word_chain::routes::root::RootRoute")
    }
}

impl Route for RootRoute {
    fn name(&self) -> &str { "" }
    fn children(&self) -> Vec<&dyn Route> {
        vec![
            &self.account_route
        ]
    }

    fn up(&self) -> FuturePreparation
    { Box::pin(async { Ok(()) }) }

    fn down(&self) -> FuturePreparation
    { Box::pin(async { Ok(()) }) }

    fn map(&self, _req: Request<Incoming>) -> FutureAction
    {
        Box::pin(async move {
            Ok(new_response()
                .status(StatusCode::NOT_FOUND)
                .body(Full::from(Bytes::new()))
                .unwrap())
        })
    }
}
