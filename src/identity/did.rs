use async_trait::async_trait;
use fi_common::did::DidDocument;
use std::cell::RefCell;
use std::future::Future;
use std::ops::Deref;
use std::rc::Rc;

#[cfg(not(feature = "wasm"))]
#[async_trait]
pub trait DidResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocument, fi_common::error::Error>;
}

#[cfg(feature = "wasm")]
pub trait DidResolver {
    fn resolve(&self, did: &str) -> Rc<RefCell<Result<DidDocument, fi_common::error::Error>>>;
}

#[cfg(not(feature = "wasm"))]
pub async fn get_did_doc(
    did: String,
    resolvers: &Vec<Box<dyn DidResolver>>,
) -> Option<DidDocument> {
    for resolver in resolvers {
        match resolver.resolve(did.as_str()).await {
            Ok(val) => return Some(val),
            Err(error) => {}
        };
    }

    None
}

#[cfg(feature = "wasm")]
pub fn get_did_doc(did: String, resolvers: &Vec<Box<dyn DidResolver>>) -> Option<DidDocument> {
    for resolver in resolvers {
        let k = resolver.resolve(did.as_str());
        match k.borrow().deref() {
            Ok(val) => return Some(val.clone()),
            Err(error) => {}
        };
    }

    None
}
