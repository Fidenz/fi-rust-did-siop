use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, Clone)]
#[cfg(not(feature = "wasm"))]
pub struct VPData {
    pub vp_token: Value,
    pub _vp_token: Value,
}
