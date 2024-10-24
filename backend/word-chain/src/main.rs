mod response;
mod route;
mod encrypt;
mod jwt;
mod routes;

use crate::response::{new_response, set_response_option, ResponseOption};
use routes::root::RootRoute;
use crate::route::{down_all, match_route, up_all};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::StatusCode;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::io::{stdout, Write};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;
use tokio_postgres::{Client, NoTls};


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

static GLOBAL: RwLock<Option<GlobalData>> = RwLock::new(None);


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

async fn configure() {
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
    let _ = root_arc;
}

async fn shutdown() {
    eprintln!("Shutting down...");

    // FINALISE ALL ROUTES
    // Critical section: If finalisation doesn't work properly,
    // It will leave permanent sub-effect on system (especially, for DATABASE)
    let root_arc = GLOBAL.read().unwrap().as_ref().unwrap().root.clone();
    if let Err(e) = down_all(root_arc.as_ref()).await {
        eprintln!("Failed to initialize routes: {}", e);
    }
    let _ = root_arc;

    stdout().flush().ok();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

    configure().await;

    let addr = SocketAddr::from(([127, 0, 0, 1], 5000));
    let listener = TcpListener::bind(addr).await?;

    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let mut signal = std::pin::pin!(async {
        tokio::signal::ctrl_c().await
            .expect("failed to install SIGINT handler");
    });

    loop {
        tokio::select! {
            Ok((stream, _)) = listener.accept() => {
                let io = TokioIo::new(stream);

                tokio::task::spawn(async move {
                    if let Err(err) = http1::Builder::new()
                        .serve_connection(io, service_fn(map))
                        .await
                    {
                        eprintln!("Error serving connection: {:?}", err);
                    }
                });
            },

            _ = &mut signal => {
                shutdown().await;
                break;
            }
        }
    }

    tokio::select! {
        _ = graceful.shutdown() => {
            eprintln!("All connections gracefully closed");
        },
        _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
            eprintln!("Timed out waiting for connection");
        }
    }

    Ok(())
}

