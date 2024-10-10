use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::siop::SiopMetadataSupported;

#[derive(Serialize, Deserialize)]
pub struct RPInfo {
    pub redirect_uri: String,
    pub did: String,
    pub registration: Value,
    pub did_doc: Option<fi_common::did::DidDocument>,
    pub request_uri: Option<String>,
    pub op_metadata: Option<SiopMetadataSupported>,
}
