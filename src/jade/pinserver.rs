use super::api;

pub struct PinServerClient {
    pub client: reqwest::Client,
}

impl Default for PinServerClient {
    fn default() -> Self {
        Self::new()
    }
}

impl PinServerClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    pub async fn request<D>(&self, req: api::PinServerRequestParams) -> Result<D, Error>
    where
        D: serde::de::DeserializeOwned,
    {
        let url = match &req.urls {
            api::PinServerUrls::Array(urls) => urls.first().ok_or(Error::NoUrlProvided)?,
            api::PinServerUrls::Object { url, .. } => url,
        };

        let res = self.client.post(url).json(&req.data).send().await?;

        if res.status().is_success() {
            res.json().await.map_err(Error::from)
        } else {
            Err(Error::Server(format!("{:?}", res)))
        }
    }
}

#[derive(Debug)]
pub enum Error {
    NoUrlProvided,
    Client(reqwest::Error),
    Server(String),
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Self::Client(e)
    }
}
