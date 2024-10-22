use bitflags::bitflags;
use hyper::http::response::Builder;
use hyper::Response;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ResponseOption: u32 {
        const None = 0;
        const AllowCors = 1 << 0;
    }
}

static mut OPTIONS: ResponseOption = ResponseOption::None;

pub fn set_response_option(option: ResponseOption) {
    unsafe {
        OPTIONS = option;
    }
}

pub fn new_response() -> Builder {

    let mut builder = Response::builder();

    let options = unsafe { OPTIONS };

    if (options & ResponseOption::AllowCors) != ResponseOption::AllowCors {
        builder = builder
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "*")
            .header("Access-Control-Allow-Headers", "*");
    }

    builder
}
