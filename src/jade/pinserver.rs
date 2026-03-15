use super::api;

pub struct PinServerClient {
    pub client: ureq::Agent,
}

impl Default for PinServerClient {
    fn default() -> Self {
        Self::new()
    }
}

impl PinServerClient {
    pub fn new() -> Self {
        Self {
            client: ureq::Agent::new_with_defaults(),
        }
    }

    pub fn request<D>(&self, req: api::PinServerRequestParams) -> Result<D, Error>
    where
        D: serde::de::DeserializeOwned,
    {
        let url = match &req.urls {
            api::PinServerUrls::Array(urls) => urls.first().ok_or(Error::NoUrlProvided)?,
            api::PinServerUrls::Object { url, .. } => url,
        };

        let mut res = self.client.post(url).send_json(&req.data)?;
        res.body_mut().read_json().map_err(Error::from)
    }
}

#[derive(Debug)]
pub enum Error {
    NoUrlProvided,
    Client(ureq::Error),
    Server(String),
}

impl From<ureq::Error> for Error {
    fn from(e: ureq::Error) -> Self {
        Self::Client(e)
    }
}
