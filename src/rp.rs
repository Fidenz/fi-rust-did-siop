use fi_common::{did::DidDocument, error::Error, keys::KeyPair, logger};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use crate::{
    identity::{did::DidResolver, get_resolvers, Identity},
    jwt::{get_signing_key, get_verifying_key, SigningInfo, JWT},
    siop::{SIOPTokenObjects, SIOPTokensEcoded, SiopMetadataSupported},
    siop_request::DidSiopRequest,
    siop_response::{CheckParams, DidSiopResponse},
};

#[derive(Serialize, Deserialize)]
#[wasm_bindgen]
pub struct RPInfo {
    #[wasm_bindgen(skip)]
    pub redirect_uri: String,
    #[wasm_bindgen(skip)]
    pub did: String,
    #[wasm_bindgen(skip)]
    pub registration: Value,
    #[wasm_bindgen(skip)]
    pub did_doc: Option<fi_common::did::DidDocument>,
    #[wasm_bindgen(skip)]
    pub request_uri: Option<String>,
    #[wasm_bindgen(skip)]
    pub op_metadata: Option<SiopMetadataSupported>,
}

#[wasm_bindgen]
impl RPInfo {
    #[wasm_bindgen(getter = redirect_uri)]
    pub fn redirect_uri(&self) -> String {
        self.redirect_uri.clone()
    }

    #[wasm_bindgen(setter = redirect_uri)]
    pub fn set_redirect_uri(&mut self, redirect_uri: String) {
        self.redirect_uri = redirect_uri;
    }
    #[wasm_bindgen(getter = did)]
    pub fn did(&self) -> String {
        self.did.clone()
    }

    #[wasm_bindgen(setter = did)]
    pub fn set_did(&mut self, did: String) {
        self.did = did;
    }
    #[wasm_bindgen(getter = registration)]
    pub fn registration(&self) -> JsValue {
        match serde_wasm_bindgen::to_value(&self.registration) {
            Ok(val) => val,
            Err(_error) => JsValue::NULL,
        }
    }

    #[wasm_bindgen(setter = registration)]
    pub fn set_registration(&mut self, registration: JsValue) {
        match serde_wasm_bindgen::from_value(registration) {
            Ok(val) => self.registration = val,
            Err(_error) => self.registration = Value::Null,
        };
    }
    #[wasm_bindgen(getter = did_doc)]
    pub fn did_doc(&self) -> Option<fi_common::did::DidDocument> {
        self.did_doc.clone()
    }

    #[wasm_bindgen(setter = did_doc)]
    pub fn set_did_doc(&mut self, did_doc: Option<fi_common::did::DidDocument>) {
        self.did_doc = did_doc;
    }
    #[wasm_bindgen(getter = request_uri)]
    pub fn request_uri(&self) -> Option<String> {
        self.request_uri.clone()
    }

    #[wasm_bindgen(setter = request_uri)]
    pub fn set_request_uri(&mut self, request_uri: Option<String>) {
        self.request_uri = request_uri;
    }
    #[wasm_bindgen(getter = op_metadata)]
    pub fn op_metadata(&self) -> Option<SiopMetadataSupported> {
        self.op_metadata.clone()
    }

    #[wasm_bindgen(setter = op_metadata)]
    pub fn set_op_metadata(&mut self, op_metadata: Option<SiopMetadataSupported>) {
        self.op_metadata = op_metadata;
    }
}

#[wasm_bindgen]
pub struct RP {
    info: RPInfo,
    identity: Identity,
    signing_info_set: Vec<SigningInfo>,
    resolvers: Vec<Box<dyn DidResolver>>,
}

impl RP {
    fn new(
        redirect_uri: String,
        request_uri: Option<String>,
        did: String,
        registration: Value,
        did_doc: Option<DidDocument>,
        op_metadata: Option<SiopMetadataSupported>,
    ) -> RP {
        RP {
            info: RPInfo {
                redirect_uri,
                did,
                registration,
                did_doc,
                request_uri,
                op_metadata,
            },
            identity: Identity::new(),
            signing_info_set: Vec::new(),
            resolvers: get_resolvers(),
        }
    }

    #[cfg(not(feature = "wasm"))]
    pub async fn get_rp(
        redirect_uri: String,
        request_uri: Option<String>,
        did: String,
        registration: Value,
        did_doc: Option<DidDocument>,
        op_metadata: Option<SiopMetadataSupported>,
        resolvers: Option<Vec<Box<dyn DidResolver>>>,
    ) -> RP {
        let mut rp = RP::new(
            redirect_uri,
            request_uri,
            did.clone(),
            registration,
            did_doc.clone(),
            op_metadata,
        );
        if did_doc.is_some() {
            rp.identity.doc = did_doc;
        } else {
            if resolvers.is_some() {
                let res = resolvers.unwrap();
                rp.identity.add_resolvers(res);
            }

            rp.identity.resolve(did).await;
        }

        rp
    }

    #[cfg(not(feature = "wasm"))]
    pub async fn validate_response(
        &self,
        response: String,
        check_params: &mut CheckParams,
        resolvers: Option<Vec<Box<dyn DidResolver>>>,
    ) -> Result<JWT, Error> {
        check_params.redirect_uri = self.info.redirect_uri.clone();
        DidSiopResponse::validate_response(response, check_params.clone(), resolvers).await
    }

    #[cfg(not(feature = "wasm"))]
    pub async fn validate_response_with_vpdata(
        &self,
        tokens_encoded: SIOPTokensEcoded,
        check_params: &mut CheckParams,
        resolvers: Option<Vec<Box<dyn DidResolver>>>,
    ) -> Result<SIOPTokenObjects, Error> {
        check_params.redirect_uri = self.info.redirect_uri.clone();
        DidSiopResponse::validate_response_with_vpdata(
            tokens_encoded,
            check_params.clone(),
            resolvers,
        )
        .await
    }

    #[cfg(not(feature = "wasm"))]
    pub async fn generate_request(&self, options: Value) -> Result<String, Error> {
        if self.signing_info_set.len() > 0 {
            let num = rand::thread_rng().gen_range(0..self.signing_info_set.len());
            let signing_info = &self.signing_info_set[num];

            DidSiopRequest::generate_request(&self.info, signing_info, options).await
        } else {
            return Err(Error::new("No signing info instance found"));
        }
    }

    #[cfg(not(feature = "wasm"))]
    pub async fn generate_uri_request(
        &mut self,
        request_uri: String,
        options: Value,
    ) -> Result<String, Error> {
        self.info.request_uri = Some(request_uri);
        self.generate_request(options).await
    }
}

#[wasm_bindgen]
impl RP {
    #[cfg(feature = "wasm")]
    #[wasm_bindgen(method, js_name = "getRP")]
    pub fn get_rp(
        redirect_uri: String,
        request_uri: Option<String>,
        did: String,
        registration: JsValue,
        did_doc: Option<DidDocument>,
        op_metadata: Option<SiopMetadataSupported>,
    ) -> RP {
        let mut rp = RP::new(
            redirect_uri,
            request_uri,
            did.clone(),
            match serde_wasm_bindgen::from_value(registration) {
                Ok(val) => val,
                Err(error) => {
                    logger::error("Registration field is invalid");
                    Value::Null
                }
            },
            did_doc.clone(),
            op_metadata,
        );
        if did_doc.is_some() {
            rp.identity.doc = did_doc;
        } else {
            rp.identity.add_resolvers(get_resolvers());

            rp.identity.resolve(did);
        }

        rp
    }

    #[wasm_bindgen(method, js_name = "removeSigningParms")]
    pub fn remove_signing_params(&mut self, kid: String) {
        let filtered: Vec<SigningInfo> = self
            .signing_info_set
            .clone()
            .into_iter()
            .filter(|x| x.kid.ne(&kid))
            .collect();
        self.signing_info_set = filtered;
    }

    #[wasm_bindgen(method, js_name = "removeResolvers")]
    pub fn remove_resolvers(&mut self) {
        self.resolvers.clear();
    }

    // base 58 or multibase key
    #[wasm_bindgen(method, js_name = "addSigningParms")]
    pub fn add_signing_params(&mut self, key: KeyPair) -> Result<String, Error> {
        let mut keys = match self
            .identity
            .extract_authentication_keys(fi_digital_signatures::algorithms::Algorithm::EdDSA)
        {
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
    #[wasm_bindgen(method, js_name = "generateRequest")]
    pub async fn generate_request(&self, options: JsValue) -> Result<String, Error> {
        if self.signing_info_set.len() > 0 {
            let num = rand::thread_rng().gen_range(0..self.signing_info_set.len());
            let signing_info = &self.signing_info_set[num];

            DidSiopRequest::generate_request(
                &self.info,
                signing_info,
                match serde_wasm_bindgen::from_value(options) {
                    Ok(val) => val,
                    Err(error) => return Err(Error::new("Invalid value for options field")),
                },
            )
            .await
        } else {
            return Err(Error::new("No signing info instance found"));
        }
    }

    #[cfg(feature = "wasm")]
    #[wasm_bindgen(method, js_name = "generateURIRequest")]
    pub async fn generate_uri_request(
        &mut self,
        request_uri: String,
        options: JsValue,
    ) -> Result<String, Error> {
        self.info.request_uri = Some(request_uri);
        self.generate_request(options).await
    }

    #[cfg(feature = "wasm")]
    #[wasm_bindgen(method, js_name = "validateResponse")]
    pub async fn validate_response(
        &self,
        response: String,
        check_params: &mut CheckParams,
    ) -> Result<JWT, Error> {
        check_params.redirect_uri = self.info.redirect_uri.clone();
        DidSiopResponse::validate_response(response, check_params.clone(), Some(get_resolvers()))
            .await
    }

    #[cfg(feature = "wasm")]
    #[wasm_bindgen(method, js_name = "validateResponseWithVPData")]
    pub async fn validate_response_with_vpdata(
        &self,
        tokens_encoded: SIOPTokensEcoded,
        check_params: &mut CheckParams,
    ) -> Result<SIOPTokenObjects, Error> {
        check_params.redirect_uri = self.info.redirect_uri.clone();
        DidSiopResponse::validate_response_with_vpdata(
            tokens_encoded,
            check_params.clone(),
            Some(get_resolvers()),
        )
        .await
    }
}

/*
fn is_multibase_pvt_key(key: &String) -> bool {
    let decoded = match bs58::decode(&key[1..]).into_vec() {
        Ok(val) => val,
        Err(error) => return false,
    };

    if key.starts_with("z") && // MULTIBASE_BASE58BTC_HEADER
            decoded[0] == 0x80 && // MULTICODEC_ED25519_PRIV_HEADER 1st byte
            decoded[1] == 0x26
    {
        return true;
    }

    return false;
}

fn get_base58from_multibase(key: String) -> Result<String, Error> {
    let x = match bs58::decode(&key[1..]).into_vec() {
        Ok(val) => val,
        Err(error) => return Err(Error::new(error.to_string().as_str())),
    }; // Drop z and convert to Uint8Array
    return Ok(bs58::encode(&x[2..]).into_string()); // return Uint8Array after dropping Multibase Header bytes, encode in base58 and rerurn
}
 */
