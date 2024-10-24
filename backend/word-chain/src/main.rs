mod response;
mod route;
mod account;
mod encrypt;
mod jwt;

use crate::account::AccountRoute;
use crate::response::{new_response, set_response_option, ResponseOption};
use crate::route::{down_all, match_route, up_all, FutureAction, FuturePreparation, Route};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper::StatusCode;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;
use tokio_postgres::{Client, NoTls};

struct RootRoute {
    account_route: AccountRoute
}

impl RootRoute {
    fn new(client: &Arc<Client>) -> RootRoute {
        Self { account_route: AccountRoute::new(client.clone()) }
    }
}

impl Display for RootRoute {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "word_chain::main::RootRoute")
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



struct GlobalData {
    root: Arc<RootRoute>
}

impl GlobalData {
    fn new(database: Arc<Client>) -> Self {
        Self {
            root: Arc::new(RootRoute::new(&database))
        }
    }
}

static GLOBAL : RwLock<Option<GlobalData>> = RwLock::new(None);



async fn map(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {

    let root_arc = GLOBAL.read().unwrap().as_ref().unwrap().root.clone();

    let route = match match_route(req.uri().path(), root_arc.as_ref()) {
        Some(route) => route,
        None => return Ok(new_response()
            .status(StatusCode::NOT_FOUND)
            .body(Full::from(Bytes::new()))
            .unwrap())
    };

    let res = match route.map(req).await {
        Ok(resp) => Ok(resp),
        Err(e) => Ok(new_response()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Full::from(Bytes::from(e.to_string())))
            .unwrap())
    };

    // root-route should be alive until scope has closed
    let _ = root_arc;

    res
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

    dotenvy::dotenv().ok();

    // Connect to postgres
    let database_url = std::env::var("DATABASE")
        .expect("environment variable `DATABASE` must be set`");
    let (client, conn) = tokio_postgres::connect(&database_url, NoTls).await
        .expect(&format!("Could not connect to `{}`", database_url));
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("Error occurs on connection with database: {}", e);
        }
    });

    set_response_option(ResponseOption::AllowCors);

    GLOBAL.write().unwrap().replace(GlobalData::new(Arc::new(client)));

    // INITIALISE ALL ROUTES
    let root_arc = GLOBAL.read().unwrap().as_ref().unwrap().root.clone();
    if let Err(e) = up_all(root_arc.as_ref()).await {
        panic!("Failed to initialize routes: {}", e);
    }

    let local = tokio::task::LocalSet::new();
    local.spawn_local(async move {
        tokio::signal::ctrl_c().await.unwrap();

        // FINALISE ALL ROUTES
        // Critical section: If finalisation doesn't work properly,
        // It will remain permanent sub-effect on system (especially, for DATABASE)
        let root_arc = GLOBAL.read().unwrap().as_ref().unwrap().root.clone();
        if let Err(e) = down_all(root_arc.as_ref()).await {
            eprintln!("Failed to initialize routes: {}", e);
        }
        let _ = root_arc;
    });

    let addr = SocketAddr::from(([127, 0, 0, 1], 5000));
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(map))
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}

