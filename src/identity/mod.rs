use did::{get_did_doc, DidResolver};
use fi_common::{did::DidDocument, error::Error, logger};
use fi_digital_signatures::algorithms::Algorithm;
use serde::{Deserialize, Serialize};

use crate::key_extractors::get_verifying_key;

pub mod did;
mod ethr_resolver;
mod key_resolver;
mod uni_resolver;

pub fn get_resolvers() -> Vec<Box<dyn DidResolver>> {
    let mut resolvers = Vec::<Box<dyn DidResolver>>::new();
    resolvers.push(Box::new(uni_resolver::UniResolver {}));
    resolvers.push(Box::new(key_resolver::KeyResolver {}));
    resolvers.push(Box::new(ethr_resolver::EthrResolver {}));

    return resolvers;
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DidKey {
    pub id: String,
    pub alg: Algorithm,
    pub public_key: (Option<Vec<u8>>, Option<String>),
}

pub struct Identity {
    pub doc: Option<DidDocument>,
    key_set: Vec<DidKey>,
    resolvers: Vec<Box<dyn DidResolver>>,
}

impl Identity {
    pub fn new() -> Identity {
        Identity {
            doc: None,
            key_set: Vec::new(),
            resolvers: get_resolvers(),
        }
    }

    pub fn add_resolvers(&mut self, mut resolvers: Vec<Box<dyn DidResolver>>) {
        self.resolvers.append(&mut resolvers);
    }

    pub fn get_resolvers(&self) -> &Vec<Box<dyn DidResolver>> {
        self.resolvers.as_ref()
    }

    pub fn remove_resolvers(&mut self) {
        self.resolvers = Vec::new();
    }

    pub fn get_resolvers_mut(&mut self) -> &mut Vec<Box<dyn DidResolver>> {
        self.resolvers.as_mut()
    }

    pub async fn resolve(&mut self, did: String) {
        let doc = get_did_doc(did, &self.resolvers).await;
        self.doc = doc;
    }

    pub fn extract_authentication_keys(
        &mut self,
        algorithm: Algorithm,
    ) -> Result<&Vec<DidKey>, Error> {
        if self.doc.is_some() {
            let doc = self.doc.as_ref().unwrap();
            if doc.verification_method.is_some() {
                let verification_methods = doc.verification_method.as_ref().unwrap();
                verification_methods.iter().for_each(|verification_method| {
                    let key = match get_verifying_key(verification_method.clone()) {
                        Ok(val) => val,
                        Err(error) => {
                            logger::error(error.to_string().as_str());
                            (None, None)
                        }
                    };

                    self.key_set.push(DidKey {
                        alg: match verification_method._type.as_str() {
                            "Ed25519VerificationKey2018" => Algorithm::EdDSA,
                            "EcdsaSecp256k1VerificationKey2019" => Algorithm::ES256K,
                            "RsaVerificationKey2018" => Algorithm::RS256,
                            "X25519KeyAgreementKey2019" => Algorithm::EdDSA,
                            _ => algorithm,
                        },
                        id: match verification_method.controller.as_ref() {
                            Some(val) => {
                                String::from(val.clone().split("#").collect::<Vec<&str>>()[0])
                            }
                            None => self.doc.as_ref().unwrap().id.clone(),
                        },
                        public_key: key,
                    });
                });
            }
        }

        Ok(&self.key_set)
    }

    pub fn get_document(&self) -> Option<DidDocument> {
        self.doc.clone()
    }

    pub fn get_document_ref(&self) -> &Option<DidDocument> {
        &self.doc
    }

    pub fn set_document(&mut self, doc: DidDocument, did: String) {
        if doc.id == did && doc.authentication.as_ref().is_some_and(|a| a.len() > 0) {
            self.doc = Some(doc);
        }
    }

    pub fn is_resolved(&self) -> bool {
        return self.doc.is_some();
    }
}
