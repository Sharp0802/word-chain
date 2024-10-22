use std::error::Error;
use http_body_util::Full;
use hyper::{Method, Request, Response};
use hyper::body::{Bytes, Incoming};

pub trait Route {
    fn name(&self) -> &str;
    fn method(&self) -> Vec<Method>;
    fn children(&self) -> Vec<&dyn Route>;
    async fn map(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Box<dyn Error>> where Self: Sized;
}

pub fn match_route<'a>(path: &'a str, root: &'a dyn Route) -> Option<&'a dyn Route> {
    let segments = path.split('/').skip(1).collect::<Vec<&str>>();

    let mut current = root;

    for segment in segments {
        if current.children().len() == 0 {
            return None;
        }

        let next = current
            .children().into_iter()
            .filter(|child| child.name() == segment || child.name() == "*")
            .collect::<Vec<&dyn Route>>();

        current = next[0];
    }

    Some(current)
}

#[cfg(test)]
mod tests {
    use std::vec;
    use super::*;

    struct RootRoute {}
    struct RouteA {}
    struct RouteAB {}

    impl Route for RootRoute {
        fn name(&self) -> &str { "" }

        fn method(&self) -> Vec<Method> {
            vec![
                Method::GET, Method::POST, Method::PUT, Method::PATCH,
                Method::HEAD, Method::OPTIONS, Method::TRACE
            ]
        }

        fn children(&self) -> Vec<&dyn Route> {
            vec![&RouteA {}]
        }

        async fn map(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Box<dyn Error>> {
            Ok(Response::builder().body(Full::from(Bytes::new())).unwrap())
        }
    }

    impl Route for RouteA {
        fn name(&self) -> &str {
            "a"
        }

        fn method(&self) -> Vec<Method> {
            vec![
                Method::GET, Method::POST, Method::PUT, Method::PATCH,
                Method::HEAD, Method::OPTIONS, Method::TRACE
            ]
        }

        fn children(&self) -> Vec<&dyn Route> {
            vec![&RouteAB {}]
        }

        async fn map(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Box<dyn Error>> {
            Ok(Response::builder().body(Full::from(Bytes::new())).unwrap())
        }
    }

    impl Route for RouteAB {
        fn name(&self) -> &str {
            "b"
        }

        fn method(&self) -> Vec<Method> {
            vec![
                Method::GET, Method::POST, Method::PUT, Method::PATCH,
                Method::HEAD, Method::OPTIONS, Method::TRACE
            ]
        }

        fn children(&self) -> Vec<&dyn Route> {
            Vec::new()
        }

        async fn map(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Box<dyn Error>> {
            Ok(Response::builder().body(Full::from(Bytes::new())).unwrap())
        }
    }

    #[test]
    fn test_route_a() {
        let req = match_route("/a", &RootRoute {}).unwrap();
        assert_eq!(req.name(), "a");
    }

    #[test]
    fn test_route_ab() {
        let req = match_route("/a/b", &RootRoute {}).unwrap();
        assert_eq!(req.name(), "b");
    }
}
