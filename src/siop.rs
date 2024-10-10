use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::jwt::JWT;

pub struct SIOPTokensEcoded {
    id_token: String, // Base64 encoded JWT
    vp_token: String, // Base64 encoded JWT
}

impl SIOPTokensEcoded {
    pub fn new(id_token: String, vp_token: String) -> SIOPTokensEcoded {
        SIOPTokensEcoded { id_token, vp_token }
    }

    pub fn get_id_token(&self) -> &String {
        &self.id_token
    }
    pub fn get_vp_token(&self) -> &String {
        &self.vp_token
    }
}

pub struct SIOPTokenObjects {
    id_token: JWT, // Decoded Object
    vp_token: JWT, // Decoded Object
}

impl SIOPTokenObjects {
    pub fn new(id_token: JWT, vp_token: JWT) -> SIOPTokenObjects {
        SIOPTokenObjects { id_token, vp_token }
    }

    pub fn get_id_token(&self) -> &JWT {
        &self.id_token
    }
    pub fn get_vp_token(&self) -> &JWT {
        &self.vp_token
    }
}

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
