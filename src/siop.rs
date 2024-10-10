use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct SiopMetadataSupported {
    pub authorization_endpoint: Option<String>,
    pub issuer: Option<String>,
    pub response_types: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub subject_types: Option<Vec<String>>,
    pub id_token_signing_alg_values: Option<Vec<String>>,
    pub request_object_signing_alg_values: Option<Vec<String>>,
    pub subject_syntax_types: Option<Vec<String>>,
    pub id_token_types: Option<Vec<String>>,
}

pub fn get_metadata_supported() -> SiopMetadataSupported {
    SiopMetadataSupported {
        authorization_endpoint: Some(String::from("openid")),
        issuer: Some(String::from("https://self-issued.me/v2")),
        response_types: Some(Vec::from([String::from("id_token")])),
        scopes: Some(Vec::from([String::from("id_token")])),
        subject_types: Some(Vec::from([String::from("id_token")])),
        id_token_signing_alg_values: Some(Vec::from([String::from("id_token")])),
        request_object_signing_alg_values: Some(Vec::from([String::from("id_token")])),
        subject_syntax_types: Some(Vec::from([String::from("id_token")])),
        id_token_types: Some(Vec::from([String::from("id_token")])),
    }
}
