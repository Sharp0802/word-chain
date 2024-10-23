use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use std::error::Error;
use std::future::Future;
use std::pin::Pin;

pub type FuturePreparation<'a> = Pin<Box<dyn Future<Output=Result<(), Box<dyn Error + 'a>>> + Send + 'a>>;
pub type FutureAction<'a> = Pin<Box<dyn Future<Output=Result<Response<Full<Bytes>>, Box<dyn Error + 'a>>> + Send + 'a>>;

pub trait Route {
    fn name(&self) -> &str;
    fn children(&self) -> Vec<&dyn Route>;
    fn up(&self) -> FuturePreparation;
    fn down(&self) -> FuturePreparation;
    fn map(&self, req: Request<Incoming>) -> FutureAction;
}

pub fn match_route<'a>(path: &str, root: &'a dyn Route) -> Option<&'a dyn Route> {
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

pub fn up_all<'a>(root: &'a dyn Route) -> Pin<Box<dyn Future<Output=Result<(), Box<dyn Error + 'a>>> + 'a>> {
    Box::pin(async move {
        root.up().await?;

        for child in root.children() {
            up_all(child).await?;
        }

        return Ok(())
    })
}

pub fn down_all<'a>(root: &'a dyn Route) -> Pin<Box<dyn Future<Output=Result<(), Box<dyn Error + 'a>>> + 'a>> {
    Box::pin(async move {
        root.down().await?;

        for child in root.children() {
            down_all(child).await?;
        }

        return Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    struct RootRoute {}
    struct RouteA {}
    struct RouteAB {}

    impl Route for RootRoute {
        fn name(&self) -> &str { "" }

        fn children(&self) -> Vec<&dyn Route> {
            vec![&RouteA {}]
        }

        fn up(&mut self) -> FuturePreparation
        {
            Box::pin(async { Ok(()) })
        }

        fn down(&mut self) -> FuturePreparation
        {
            Box::pin(async { Ok(()) })
        }

        fn map(&self, req: Request<Incoming>) -> FutureAction {
            Box::pin(async {
                Ok(Response::builder().body(Full::from(Bytes::new())).unwrap())
            })
        }
    }

    impl Route for RouteA {
        fn name(&self) -> &str {
            "a"
        }

        fn children(&self) -> Vec<&dyn Route> {
            vec![&RouteAB {}]
        }

        async fn up(&mut self) -> Result<(), Box<dyn Error>>
        where
            Self: Sized
        {
            Ok(())
        }

        async fn down(&mut self) -> Result<(), Box<dyn Error>>
        where
            Self: Sized
        {
            Ok(())
        }

        async fn map(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Box<dyn Error>> {
            Ok(Response::builder().body(Full::from(Bytes::new())).unwrap())
        }
    }

    impl Route for RouteAB {
        fn name(&self) -> &str {
            "b"
        }

        fn children(&self) -> Vec<&dyn Route> {
            Vec::new()
        }

        fn up(&mut self) -> FuturePreparation {
            Box::pin(async { Ok(()) })
        }

        fn down(&mut self) -> FuturePreparation {
            Box::pin(async { Ok(()) })
        }

        fn map(&self, req: Request<Incoming>) -> FutureAction {
            Box::pin(async { Ok(Response::builder().body(Full::from(Bytes::new())).unwrap()) })
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
