use reqwest::{header::HeaderMap, Error, Method, Response};

use fi_common::logger;

pub async fn send_request(
    url: String,
    method: Method,
    body: Option<String>,
    params: Option<&[(String, String)]>,
    headers: Option<HeaderMap>,
) -> Result<Response, Error> {
    let client = reqwest::Client::new();

    let mut builder = match method {
        Method::GET => client.get(url),
        Method::POST => client.post(url),
        Method::PUT => client.put(url),
        Method::HEAD => client.head(url),
        Method::PATCH => client.patch(url),
        Method::DELETE => client.delete(url),
        _ => {
            logger::error("Unidentified request method");
            panic!()
        }
    };

    if body.is_some() {
        builder = builder.body(body.unwrap());
    }

    if params.is_some() {
        builder = builder.query(&params.unwrap());
    }

    if headers.is_some() {
        builder = builder.headers(headers.unwrap());
    }

    builder.send().await
}
