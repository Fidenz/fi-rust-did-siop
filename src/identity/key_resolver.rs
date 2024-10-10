use async_trait::async_trait;
use fi_common::error::Error;
use fi_common::{did::DidDocument, keys::VerificationKey};
use fi_key_resolver::ed25519_verification_key2020::Ed25519VerificationKey2020;

use super::did::DidResolver;

pub struct KeyResolver {}

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
