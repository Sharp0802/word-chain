use http_body_util::Full;
use hyper::body::{Body, Bytes, Incoming};
use hyper::{Response, StatusCode};
use http_body_util::BodyExt;
use crate::response::new_response;

pub async fn read_body(body: Incoming) -> Result<Vec<u8>, Response<Full<Bytes>>> {
    if body.size_hint().upper().unwrap_or(u64::MAX) > 1024 * 64 {
        return Err(new_response()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .body(Full::from(Bytes::new()))
            .unwrap());
    }

    match body.collect().await {
        Ok(body) => Ok(body.to_bytes().to_vec()),
        Err(e) => Err(new_response()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Full::from(Bytes::from(e.to_string())))
            .unwrap())
    }
}
