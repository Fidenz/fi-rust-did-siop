use crate::{
    identity::{did::DidResolver, Identity},
    jwt::{get_signing_key, get_verifying_key, SigningInfo},
    siop_response::DidSiopResponse,
    vp::VPData,
};
use ethers::core::rand::{seq::SliceRandom, thread_rng};
use fi_common::{did::DidDocument, error::Error, keys::KeyPair, logger};
use serde_json::Value;

pub struct Provider {
    identity: Identity,
    signing_info_set: Vec<SigningInfo>,
    resolvers: Vec<Box<dyn DidResolver>>,
}

impl Provider {
    pub async fn get_provider(
        did: String,
        doc: Option<DidDocument>,
        resolvers: Option<Vec<Box<dyn DidResolver>>>,
    ) -> Provider {
        let mut provider = Provider {
            identity: Identity::new(),
            resolvers: Vec::new(),
            signing_info_set: Vec::new(),
        };

        provider.set_user(did, doc, resolvers).await;

        provider
    }

    async fn set_user(
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

    pub async fn generate_response(
        &mut self,
        request_payload: Value,
        expires_in: u32,
    ) -> Result<String, Error> {
        if self.signing_info_set.len() > 0 {
            let mut rng = thread_rng();
            let signing_info = self.signing_info_set.choose(&mut rng).unwrap();

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

    pub async fn generate_response_with_vpdata(
        &mut self,
        request_payload: Value,
        expires_in: u32,
        vps: VPData,
    ) -> Result<String, Error> {
        if self.signing_info_set.len() > 0 {
            let mut rng = thread_rng();
            let signing_info = self.signing_info_set.choose(&mut rng).unwrap();

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
}
