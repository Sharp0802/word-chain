use base64::Engine;

pub struct BasicAuth {
    id: String,
    password: String
}

impl BasicAuth {
    pub fn from(header: &str) -> Option<BasicAuth> {
        let terms = header.split(" ").collect::<Vec<&str>>();
        if terms.len() != 2 || terms[0] != "Basic" {
            return None;
        }

        let credential = match base64::prelude::BASE64_STANDARD
            .decode(terms[1].as_bytes())
            .map(|bytes| String::from_utf8(bytes)) {
            Ok(Ok(credential)) => credential,
            _ => return None
        };

        let props = credential.split(":").collect::<Vec<&str>>();
        if props.len() != 2 {
            return None;
        }

        Some(BasicAuth{
            id: props[0].to_string(),
            password: props[1].to_string()
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}
