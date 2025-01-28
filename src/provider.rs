use crate::{
    identity::{did::DidResolver, Identity},
    jwt::{get_signing_key, get_verifying_key, SigningInfo, JWT},
    siop::SiopMetadataSupported,
    siop_request::DidSiopRequest,
    siop_response::DidSiopResponse,
    vp::VPData,
};
use fi_common::{did::DidDocument, error::Error, keys::KeyPair, logger};
use fi_digital_signatures::algorithms::Algorithm;
use rand::Rng;
use serde_json::Value;
use wasm_bindgen::prelude::wasm_bindgen;
#[cfg(feature = "wasm")]
use wasm_bindgen::JsValue;

#[wasm_bindgen]
pub struct Provider {
    identity: Identity,
    signing_info_set: Vec<SigningInfo>,
}

impl Provider {
    #[cfg(not(feature = "wasm"))]
    pub async fn get_provider(
        did: String,
        doc: Option<DidDocument>,
        resolvers: Option<Vec<Box<dyn DidResolver>>>,
    ) -> Provider {
        let mut provider = Provider {
            identity: Identity::new(),
            signing_info_set: Vec::new(),
        };

        provider.set_user(did, doc, resolvers).await;

        provider
    }

    #[cfg(not(feature = "wasm"))]
    pub async fn set_user(
        &mut self,
        did: String,
        doc: Option<DidDocument>,
        resolvers: Option<Vec<Box<dyn DidResolver>>>,
    ) {
        if doc.is_some() {
            self.identity.set_document(doc.unwrap(), did);
        } else {
            if resolvers.as_ref().is_some_and(|f| f.len() > 0) {
                self.identity.add_resolvers(resolvers.unwrap());
            }

            self.identity.resolve(did).await;
        }
    }

    #[cfg(not(feature = "wasm"))]
    pub async fn generate_response(
        &mut self,
        request_payload: Value,
        expires_in: u32,
    ) -> Result<String, Error> {
        if self.signing_info_set.len() > 0 {
            let num = rand::thread_rng().gen_range(0..self.signing_info_set.len());
            let signing_info = &self.signing_info_set[num];

            if self.identity.is_resolved() {
                return DidSiopResponse::generate_response(
                    request_payload,
                    signing_info,
                    &mut self.identity,
                    expires_in,
                    None,
                );
            }

            return Err(Error::new("Unresolved did document"));
        } else {
            return Err(Error::new("No signing info instance found"));
        }
    }

    #[cfg(not(feature = "wasm"))]
    pub async fn generate_response_with_vpdata(
        &mut self,
        request_payload: Value,
        expires_in: u32,
        vps: VPData,
    ) -> Result<String, Error> {
        if self.signing_info_set.len() > 0 {
            let num = rand::thread_rng().gen_range(0..self.signing_info_set.len());
            let signing_info = &self.signing_info_set[num];

            if self.identity.is_resolved() {
                return DidSiopResponse::generate_response(
                    request_payload,
                    signing_info,
                    &mut self.identity,
                    expires_in,
                    Some(vps),
                );
            }

            return Err(Error::new("Unresolved did document"));
        } else {
            return Err(Error::new("No signing info instance found"));
        }
    }

    pub async fn validate_request(
        &self,
        request: String,
        op_metadata: Option<SiopMetadataSupported>,
        resolvers: Option<Vec<Box<dyn DidResolver>>>,
    ) -> Result<JWT, Error> {
        DidSiopRequest::validate_request(request, op_metadata, resolvers).await
    }
}

#[wasm_bindgen]
impl Provider {
    #[wasm_bindgen(method, js_name = "setUser")]
    #[cfg(feature = "wasm")]
    pub fn set_user(&mut self, did: String, doc: Option<DidDocument>) {
        use crate::identity::get_resolvers;

        if doc.is_some() {
            self.identity.set_document(doc.unwrap(), did);
        } else {
            self.identity.add_resolvers(get_resolvers());

            self.identity.resolve(did);
        }
    }

    #[cfg(feature = "wasm")]
    #[wasm_bindgen(method, js_name = "getProvider")]
    pub fn get_provider(did: String, doc: Option<DidDocument>) -> Provider {
        let mut provider = Provider {
            identity: Identity::new(),
            signing_info_set: Vec::new(),
        };
        provider.set_user(did, doc);
        provider
    }

    #[wasm_bindgen(method, js_name = "removeSigningParams")]
    pub fn remove_signing_params(&mut self, kid: String) {
        let filtered: Vec<SigningInfo> = self
            .signing_info_set
            .clone()
            .into_iter()
            .filter(|x| x.kid.ne(&kid))
            .collect();
        self.signing_info_set = filtered;
    }

    #[wasm_bindgen(method, js_name = "addSigningParams")]
    pub fn add_signing_params(
        &mut self,
        key: KeyPair,
        alg: Option<Algorithm>,
    ) -> Result<String, Error> {
        let mut keys = match self.identity.extract_authentication_keys(match alg {
            Some(val) => val,
            None => fi_digital_signatures::algorithms::Algorithm::ES256K,
        }) {
            Ok(val) => val.to_owned(),
            Err(error) => return Err(error),
        };

        let key_content = match crate::key_extractors::get_key(key) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        for _key in keys.iter_mut() {
            let alg = _key.alg;
            let signing_info = SigningInfo {
                alg,
                kid: _key.id.clone(),
                key: key_content.clone(),
            };

            let signing_key = match get_signing_key(&signing_info) {
                Ok(val) => val,
                Err(error) => {
                    logger::error(error.to_string().as_str());
                    continue;
                }
            };

            let verifying_key = match get_verifying_key(_key) {
                Ok(val) => val,
                Err(error) => {
                    logger::error(error.to_string().as_str());
                    continue;
                }
            };

            let content = "signing and verifying test";
            let sig = match signing_key.sign(String::from(content), alg) {
                Ok(val) => val,
                Err(error) => {
                    logger::error(error.to_string().as_str());
                    continue;
                }
            };

            let verified = match verifying_key.verify(String::from(content), sig, alg) {
                Ok(val) => val,
                Err(error) => {
                    logger::error(error.to_string().as_str());
                    continue;
                }
            };

            if verified {
                self.signing_info_set.push(signing_info);
                return Ok(_key.id.clone());
            }
        }

        return Err(Error::new("No public key found"));
    }

    #[cfg(feature = "wasm")]
    #[wasm_bindgen(method, js_name = "generateResponseWithVPData")]
    pub fn generate_response_with_vpdata(
        &mut self,
        request_payload: JsValue,
        expires_in: u32,
        vps: VPData,
    ) -> Result<String, Error> {
        if self.signing_info_set.len() > 0 {
            let num = rand::thread_rng().gen_range(0..self.signing_info_set.len());
            let signing_info = &self.signing_info_set[num];

            if self.identity.is_resolved() {
                return DidSiopResponse::generate_response(
                    match serde_wasm_bindgen::from_value(request_payload) {
                        Ok(val) => val,
                        Err(error) => return Err(Error::new(error.to_string().as_str())),
                    },
                    signing_info,
                    &mut self.identity,
                    expires_in,
                    Some(vps),
                );
            }

            return Err(Error::new("Unresolved did document"));
        } else {
            return Err(Error::new("No signing info instance found"));
        }
    }

    #[cfg(feature = "wasm")]
    #[wasm_bindgen(method, js_name = "generateResponse")]
    pub async fn generate_response(
        &mut self,
        request_payload: JsValue,
        expires_in: u32,
    ) -> Result<String, Error> {
        if self.signing_info_set.len() > 0 {
            let num = rand::thread_rng().gen_range(0..self.signing_info_set.len());
            let signing_info = &self.signing_info_set[num];

            if self.identity.is_resolved() {
                return DidSiopResponse::generate_response(
                    match serde_wasm_bindgen::from_value(request_payload) {
                        Ok(val) => val,
                        Err(error) => return Err(Error::new(error.to_string().as_str())),
                    },
                    signing_info,
                    &mut self.identity,
                    expires_in,
                    None,
                );
            }

            return Err(Error::new("Unresolved did document"));
        } else {
            return Err(Error::new("No signing info instance found"));
        }
    }
}
