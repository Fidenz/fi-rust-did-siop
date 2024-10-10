use async_trait::async_trait;
use fi_common::did::DidDocument;
use fi_common::error::Error;
use reqwest::Method;
use serde_json::Value;

use crate::http_request;

use super::did::DidResolver;

pub struct UniResolver {}

#[async_trait]
impl DidResolver for UniResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocument, fi_common::error::Error> {
        let res = match http_request::send_request(
            format!("https://dev.uniresolver.io/1.0/identifiers/{}", did),
            Method::GET,
            None,
            None,
            None,
        )
        .await
        {
            Ok(val) => val,
            Err(error) => {
                return Err(Error::new(error.to_string().as_str()));
            }
        };

        let res_text = match res.text().await {
            Ok(val) => val,

            Err(error) => {
                return Err(Error::new(error.to_string().as_str()));
            }
        };

        println!("{:#?}", res_text);

        let mut response_value: Value = match serde_json::from_str(res_text.as_str()) {
            Ok(val) => val,
            Err(error) => {
                return Err(Error::new(error.to_string().as_str()));
            }
        };

        if response_value["didDocument"].is_null() {
            return Err(Error::new("Did document couldn't be found"));
        }

        let did_doc: DidDocument =
            match serde_json::from_value(response_value["didDocument"].take()) {
                Ok(val) => val,
                Err(error) => {
                    return Err(Error::new(error.to_string().as_str()));
                }
            };

        return Ok(did_doc);
    }
}
