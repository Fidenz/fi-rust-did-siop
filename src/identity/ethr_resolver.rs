use async_trait::async_trait;
use fi_common::did::DidDocument;

use super::did::DidResolver;

pub struct EthrResolver {}

#[async_trait]
impl DidResolver for EthrResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocument, fi_common::error::Error> {
        fi_ethr_resolver::resolve(
            did,
            "https://mainnet.infura.io/v3/f2bba3f37f194541b054b2a14d6719ef",
            "application/did+ld+json",
        )
        .await
    }
}
