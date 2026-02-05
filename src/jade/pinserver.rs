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
        // Match Python behavior: use first non-onion URL
        let urls = match &req.urls {
            api::PinServerUrls::Array(urls) => {
                if urls.is_empty() {
                    return Err(Error::NoUrlProvided);
                }
                urls.clone()
            }
            api::PinServerUrls::Object { url, .. } => vec![url.clone()],
        };

        // Filter out .onion URLs and use the first one, matching Python behavior
        let url = urls
            .iter()
            .find(|url| !url.ends_with(".onion"))
            .ok_or(Error::NoUrlProvided)?;

        // Match Python: use_json = params.get('accept') in ['json', 'application/json']
        let use_json = req.accept == "json" || req.accept == "application/json";

        let res = if req.method == "POST" {
            if use_json {
                // Send as JSON like Python: json.dumps(params['data'])
                self.client.post(url).json(&req.data).send().await
            } else {
                // Send as form data like Python: requests.post(url, data)
                self.client.post(url).form(&req.data).send().await
            }
        } else {
            return Err(Error::UnsupportedMethod(req.method.clone()));
        };

        match res {
            Ok(response) if response.status().is_success() => {
                response.json().await.map_err(Error::from)
            }
            Ok(response) => Err(Error::Server(format!(
                "HTTP {} from {}: {:?}",
                response.status(),
                url,
                response
            ))),
            Err(e) => Err(Error::Client(e)),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    NoUrlProvided,
    UnsupportedMethod(String),
    Client(reqwest::Error),
    Server(String),
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Self::Client(e)
    }
}
