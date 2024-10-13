use crate::jwt::JWT;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
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

#[wasm_bindgen]
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

#[derive(Serialize, Deserialize, Clone)]
#[wasm_bindgen]
pub struct SiopMetadataSupported {
    authorization_endpoint: Option<String>,
    issuer: Option<String>,
    response_types: Option<Vec<String>>,
    scopes: Option<Vec<String>>,
    subject_types: Option<Vec<String>>,
    id_token_signing_alg_values: Option<Vec<String>>,
    request_object_signing_alg_values: Option<Vec<String>>,
    subject_syntax_types: Option<Vec<String>>,
    id_token_types: Option<Vec<String>>,
}

#[wasm_bindgen]
impl SiopMetadataSupported {
    #[wasm_bindgen(getter = authorization_endpoint)]
    pub fn authorization_endpoint(&self) -> Option<String> {
        self.authorization_endpoint.clone()
    }

    #[wasm_bindgen(setter = authorization_endpoint)]
    pub fn set_authorization_endpoint(&mut self, authorization_endpoint: Option<String>) {
        self.authorization_endpoint = authorization_endpoint;
    }
    #[wasm_bindgen(getter = issuer)]
    pub fn issuer(&self) -> Option<String> {
        self.issuer.clone()
    }

    #[wasm_bindgen(setter = issuer)]
    pub fn set_issuer(&mut self, issuer: Option<String>) {
        self.issuer = issuer;
    }
    #[wasm_bindgen(getter = response_types)]
    pub fn response_types(&self) -> Option<Vec<String>> {
        self.response_types.clone()
    }

    #[wasm_bindgen(setter = response_types)]
    pub fn set_response_types(&mut self, response_types: Option<Vec<String>>) {
        self.response_types = response_types;
    }
    #[wasm_bindgen(getter = scopes)]
    pub fn scopes(&self) -> Option<Vec<String>> {
        self.scopes.clone()
    }

    #[wasm_bindgen(setter = scopes)]
    pub fn set_scopes(&mut self, scopes: Option<Vec<String>>) {
        self.scopes = scopes;
    }
    #[wasm_bindgen(getter = subject_types)]
    pub fn subject_types(&self) -> Option<Vec<String>> {
        self.subject_types.clone()
    }

    #[wasm_bindgen(setter = subject_types)]
    pub fn set_subject_types(&mut self, subject_types: Option<Vec<String>>) {
        self.subject_types = subject_types;
    }
    #[wasm_bindgen(getter = id_token_signing_alg_values)]
    pub fn id_token_signing_alg_values(&self) -> Option<Vec<String>> {
        self.id_token_signing_alg_values.clone()
    }

    #[wasm_bindgen(setter = id_token_signing_alg_values)]
    pub fn set_id_token_signing_alg_values(
        &mut self,
        id_token_signing_alg_values: Option<Vec<String>>,
    ) {
        self.id_token_signing_alg_values = id_token_signing_alg_values;
    }
    #[wasm_bindgen(getter = request_object_signing_alg_values)]
    pub fn request_object_signing_alg_values(&self) -> Option<Vec<String>> {
        self.request_object_signing_alg_values.clone()
    }

    #[wasm_bindgen(setter = request_object_signing_alg_values)]
    pub fn set_request_object_signing_alg_values(
        &mut self,
        request_object_signing_alg_values: Option<Vec<String>>,
    ) {
        self.request_object_signing_alg_values = request_object_signing_alg_values;
    }
    #[wasm_bindgen(getter = subject_syntax_types)]
    pub fn subject_syntax_types(&self) -> Option<Vec<String>> {
        self.subject_syntax_types.clone()
    }

    #[wasm_bindgen(setter = subject_syntax_types)]
    pub fn set_subject_syntax_types(&mut self, subject_syntax_types: Option<Vec<String>>) {
        self.subject_syntax_types = subject_syntax_types;
    }
    #[wasm_bindgen(getter = id_token_types)]
    pub fn id_token_types(&self) -> Option<Vec<String>> {
        self.id_token_types.clone()
    }

    #[wasm_bindgen(setter = id_token_types)]
    pub fn set_id_token_types(&mut self, id_token_types: Option<Vec<String>>) {
        self.id_token_types = id_token_types;
    }
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
