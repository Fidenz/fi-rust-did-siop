use async_trait::async_trait;
use fi_common::{did::DidDocument, error::Error};
#[cfg(feature = "wasm")]
use std::cell::RefCell;
#[cfg(feature = "wasm")]
use std::rc::Rc;

use super::did::DidResolver;

pub struct EthrResolver {}

#[cfg(not(feature = "wasm"))]
#[async_trait]
impl DidResolver for EthrResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocument, Error> {
        fi_ethr_resolver::resolve(
            did,
            "https://mainnet.infura.io/v3/f2bba3f37f194541b054b2a14d6719ef",
            "application/did+ld+json",
        )
        .await
    }
}

#[cfg(feature = "wasm")]
impl DidResolver for EthrResolver {
    fn resolve(&self, did: &str) -> Rc<RefCell<Result<DidDocument, Error>>> {
        let result_state: Rc<RefCell<Result<DidDocument, Error>>> =
            Rc::new(RefCell::new(Err(Error::new("Error"))));
        let result_state_clone = Rc::clone(&result_state);

        let fut = fi_ethr_resolver::resolve(
            String::from(did).leak(),
            "https://mainnet.infura.io/v3/f2bba3f37f194541b054b2a14d6719ef",
            "application/did+ld+json",
        );

        wasm_bindgen_futures::spawn_local(async move {
            match fut.await {
                Ok(data) => *result_state_clone.borrow_mut() = Ok(data),
                Err(error) => *result_state_clone.borrow_mut() = Err(Error::new("Request failed")),
            };
        });

        result_state
    }
}
