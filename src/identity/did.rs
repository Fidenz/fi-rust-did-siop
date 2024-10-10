use async_trait::async_trait;
use fi_common::did::DidDocument;

#[async_trait]
pub trait DidResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocument, fi_common::error::Error>;
}

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
