use std::ops::DerefMut;

use ethers::core::rand::{rngs::ThreadRng, seq::SliceRandom, thread_rng, Rng};
use fi_common::{did::DidDocument, error::Error, keys::KeyPair, logger};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    identity::{did::DidResolver, get_resolvers, Identity},
    jwt::{get_signing_key, get_verifying_key, SigningInfo, JWT},
    siop::{SIOPTokenObjects, SIOPTokensEcoded, SiopMetadataSupported},
    siop_request::DidSiopRequest,
    siop_response::{CheckParams, DidSiopResponse},
};

#[derive(Serialize, Deserialize)]
pub struct RPInfo {
    pub redirect_uri: String,
    pub did: String,
    pub registration: Value,
    pub did_doc: Option<fi_common::did::DidDocument>,
    pub request_uri: Option<String>,
    pub op_metadata: Option<SiopMetadataSupported>,
}

pub struct RP {
    info: RPInfo,
    identity: Identity,
    signing_info_set: Vec<SigningInfo>,
    resolvers: Vec<Box<dyn DidResolver>>,
}

impl RP {
    fn new(
        redirect_uri: String,
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
                request_uri: None,
                op_metadata,
            },
            identity: Identity::new(),
            signing_info_set: Vec::new(),
            resolvers: get_resolvers(),
        }
    }

    pub async fn get_rp(
        redirect_uri: String,
        did: String,
        registration: Value,
        did_doc: Option<DidDocument>,
        op_metadata: Option<SiopMetadataSupported>,
        resolvers: Option<Vec<Box<dyn DidResolver>>>,
    ) -> RP {
        let mut rp = RP::new(
            redirect_uri,
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

    // base 58 or multibase key
    pub fn add_signing_params(&mut self, key: KeyPair) -> Result<String, Error> {
        let mut keys = match self
            .identity
            .extract_authentication_keys(fi_digital_signatures::algorithms::Algorithm::EdDSA)
        {
            Ok(val) => val.to_owned(),
            Err(error) => return Err(error),
        };

        let key_content = match crate::key_extractors::get_verifying_key(key) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        for key in keys.iter_mut() {
            let alg = key.alg;

            let signing_info = SigningInfo {
                alg,
                kid: key.id.clone(),
                key: key_content.clone(),
            };

            let signing_key = match get_signing_key(&signing_info) {
                Ok(val) => val,
                Err(error) => {
                    logger::error(error.to_string().as_str());
                    continue;
                }
            };

            let verifying_key = match get_verifying_key(key) {
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

                return Ok(key.id.clone());
            }
        }

        return Err(Error::new("No public key found"));
    }

    pub fn remove_signing_params(&mut self, kid: String) {
        let filtered: Vec<SigningInfo> = self
            .signing_info_set
            .clone()
            .into_iter()
            .filter(|x| x.kid.ne(&kid))
            .collect();
        self.signing_info_set = filtered;
    }

    pub fn remove_resolvers(&mut self) {
        self.resolvers.clear();
    }

    pub async fn generate_request(&self, options: Value) -> Result<String, Error> {
        if self.signing_info_set.len() > 0 {
            let mut rng = thread_rng();
            let signing_info = self.signing_info_set.choose(&mut rng).unwrap();

            DidSiopRequest::generate_request(&self.info, signing_info, options).await
        } else {
            return Err(Error::new("No signing info instance found"));
        }
    }

    pub async fn generate_uri_request(
        &mut self,
        request_uri: String,
        options: Value,
    ) -> Result<String, Error> {
        self.info.request_uri = Some(request_uri);
        self.generate_request(options).await
    }

    pub fn validate_response(
        &self,
        response: String,
        check_params: &mut CheckParams,
        resolvers: Option<Vec<Box<dyn DidResolver>>>,
    ) -> Result<JWT, Error> {
        check_params.redirect_uri = self.info.redirect_uri.clone();
        DidSiopResponse::validate_response(response, check_params.clone(), resolvers)
    }

    pub fn validate_response_with_vpdata(
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
    }
}

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
