use async_trait::async_trait;
use fi_common::error::Error;
use fi_common::{did::DidDocument, keys::VerificationKey};
use fi_key_resolver::ed25519_verification_key2020::Ed25519VerificationKey2020;
#[cfg(feature = "wasm")]
use std::cell::RefCell;
#[cfg(feature = "wasm")]
use std::future::Future;
#[cfg(feature = "wasm")]
use std::pin::Pin;
#[cfg(feature = "wasm")]
use std::rc::Rc;

use super::did::DidResolver;

pub struct KeyResolver {}

#[cfg(not(feature = "wasm"))]
#[async_trait]
impl DidResolver for KeyResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocument, Error> {
        match fi_key_resolver::resolve_did(did, Ed25519VerificationKey2020::get_suite_id()) {
            Ok((did, _)) => {
                if did.is_some() {
                    return Ok(did.unwrap());
                } else {
                    return Err(Error::new("Did document couldn't be found"));
                }
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(feature = "wasm")]
impl DidResolver for KeyResolver {
    fn resolve(&self, did: &str) -> Rc<RefCell<Result<DidDocument, fi_common::error::Error>>> {
        let result_state: Rc<RefCell<Result<DidDocument, fi_common::error::Error>>> =
            Rc::new(RefCell::new(Err(Error::new("Error"))));
        let result_state_clone = Rc::clone(&result_state);
        match fi_key_resolver::resolve_did(did, Ed25519VerificationKey2020::get_suite_id()) {
            Ok((did, _)) => {
                if did.is_some() {
                    *result_state_clone.borrow_mut() = Ok(did.unwrap());
                } else {
                    *result_state_clone.borrow_mut() =
                        Err(Error::new("Did document couldn't be found"));
                }
            }
            Err(error) => *result_state_clone.borrow_mut() = Err(error),
        };
        result_state
    }
}
