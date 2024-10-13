#[cfg(feature = "wasm")]
use std::cell::RefCell;
#[cfg(feature = "wasm")]
use std::future::Future;
#[cfg(feature = "wasm")]
use std::pin::Pin;
#[cfg(feature = "wasm")]
use std::rc::Rc;

use async_trait::async_trait;
use fi_common::did::DidDocument;
use fi_common::error::Error;
use reqwest::Method;
use serde_json::Value;

use crate::http_request;

use super::did::DidResolver;

pub struct UniResolver {}

#[cfg(not(feature = "wasm"))]
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

#[cfg(feature = "wasm")]
impl DidResolver for UniResolver {
    fn resolve(&self, did: &str) -> Rc<RefCell<Result<DidDocument, fi_common::error::Error>>> {
        let result_state: Rc<RefCell<Result<DidDocument, fi_common::error::Error>>> =
            Rc::new(RefCell::new(Err(Error::new("Error"))));
        let result_state_clone = Rc::clone(&result_state);
        let res_r = http_request::send_request(
            format!("https://dev.uniresolver.io/1.0/identifiers/{}", did),
            Method::GET,
            None,
            None,
            None,
        );

        wasm_bindgen_futures::spawn_local(async move {
            let res = match res_r.await {
                Ok(val) => val,
                Err(error) => {
                    *result_state_clone.borrow_mut() = Err(Error::new(error.to_string().as_str()));
                    return;
                }
            };

            let res_text = match res.text().await {
                Ok(val) => val,
                Err(error) => {
                    *result_state_clone.borrow_mut() = Err(Error::new(error.to_string().as_str()));
                    return;
                }
            };

            let mut response_value: Value = match serde_json::from_str(res_text.as_str()) {
                Ok(val) => val,
                Err(error) => {
                    *result_state_clone.borrow_mut() = Err(Error::new(error.to_string().as_str()));
                    return;
                }
            };

            if response_value["didDocument"].is_null() {
                *result_state_clone.borrow_mut() =
                    Err(Error::new("Did document couldn't be found"));
                return;
            }

            let did_doc: DidDocument =
                match serde_json::from_value(response_value["didDocument"].take()) {
                    Ok(val) => val,
                    Err(error) => {
                        *result_state_clone.borrow_mut() =
                            Err(Error::new(error.to_string().as_str()));
                        return;
                    }
                };

            *result_state_clone.borrow_mut() = Ok(did_doc);
        });

        result_state
    }
}
