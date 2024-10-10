use fi_common::error::Error;
use fi_digital_signatures::{
    algorithms::Algorithm,
    crypto::VerifyFromKey,
    jwt::{Header, Payload},
};
use serde::{Deserialize, Serialize};

use crate::identity::DidVerificationKey;

#[derive(Serialize, Deserialize)]
pub struct SigningInfo {
    pub alg: Algorithm,
    pub kid: String,
    pub key: (Option<Vec<u8>>, Option<String>),
}

#[derive(Serialize, Deserialize)]
pub struct JWT {
    pub header: Header,
    pub payload: Payload,
    pub signature: Option<String>,
}

impl JWT {
    pub fn sign(&mut self, signing_info: &SigningInfo) {
        todo!()
    }
    pub fn verify(
        content: String,
        signature: String,
        signing_info: &mut DidVerificationKey,
    ) -> Result<bool, Error> {
        let verifying_key: Box<dyn VerifyFromKey> = match signing_info.alg {
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => {
                if signing_info.public_key.0.is_some() {
                    match fi_digital_signatures::crypto::rsa::RsaVerifyingKey::from_bytes(
                        signing_info.public_key.0.as_ref().unwrap().as_slice(),
                    ) {
                        Ok(val) => Box::new(val),
                        Err(error) => return Err(Error::new(error.to_string().as_str())),
                    }
                } else if signing_info.public_key.1.is_some() {
                    match fi_digital_signatures::crypto::rsa::RsaVerifyingKey::from_pem(
                        signing_info.public_key.1.as_ref().unwrap().as_str(),
                    ) {
                        Ok(val) => Box::new(val),
                        Err(error) => return Err(Error::new(error.to_string().as_str())),
                    }
                } else {
                    return Err(Error::new("public key content unknown"));
                }
            }
            Algorithm::EdDSA => {
                if signing_info.public_key.0.is_some() {
                    match fi_digital_signatures::crypto::eddsa::EDDSAVerifyingKey::from_bytes(
                        signing_info.public_key.0.clone().unwrap().as_mut_slice(),
                    ) {
                        Ok(val) => Box::new(val),
                        Err(error) => return Err(Error::new(error.to_string().as_str())),
                    }
                } else if signing_info.public_key.1.is_some() {
                    match fi_digital_signatures::crypto::eddsa::EDDSAVerifyingKey::from_pem(
                        signing_info.public_key.1.as_ref().unwrap().as_str(),
                    ) {
                        Ok(val) => Box::new(val),
                        Err(error) => return Err(Error::new(error.to_string().as_str())),
                    }
                } else {
                    return Err(Error::new("public key content unknown"));
                }
            }
            Algorithm::ES256 => {
                if signing_info.public_key.0.is_some() {
                    match fi_digital_signatures::crypto::ecdsa::_256::P256VerifyingKey::from_bytes(
                        signing_info.public_key.0.clone().unwrap().as_mut_slice(),
                    ) {
                        Ok(val) => Box::new(val),
                        Err(error) => return Err(Error::new(error.to_string().as_str())),
                    }
                } else if signing_info.public_key.1.is_some() {
                    match fi_digital_signatures::crypto::ecdsa::_256::P256VerifyingKey::from_pem(
                        signing_info.public_key.1.as_ref().unwrap().as_str(),
                    ) {
                        Ok(val) => Box::new(val),
                        Err(error) => return Err(Error::new(error.to_string().as_str())),
                    }
                } else {
                    return Err(Error::new("public key content unknown"));
                }
            }
            Algorithm::ES384 => {
                if signing_info.public_key.0.is_some() {
                    match fi_digital_signatures::crypto::ecdsa::_384::P384VerifyingKey::from_bytes(
                        signing_info.public_key.0.clone().unwrap().as_mut_slice(),
                    ) {
                        Ok(val) => Box::new(val),
                        Err(error) => return Err(Error::new(error.to_string().as_str())),
                    }
                } else if signing_info.public_key.1.is_some() {
                    match fi_digital_signatures::crypto::ecdsa::_384::P384VerifyingKey::from_pem(
                        signing_info.public_key.1.as_ref().unwrap().as_str(),
                    ) {
                        Ok(val) => Box::new(val),
                        Err(error) => return Err(Error::new(error.to_string().as_str())),
                    }
                } else {
                    return Err(Error::new("public key content unknown"));
                }
            }
            Algorithm::ES512 => {
                if signing_info.public_key.0.is_some() {
                    match fi_digital_signatures::crypto::ecdsa::_512::P512VerifyingKey::from_bytes(
                        signing_info.public_key.0.clone().unwrap().as_mut_slice(),
                    ) {
                        Ok(val) => Box::new(val),
                        Err(error) => return Err(Error::new(error.to_string().as_str())),
                    }
                } else if signing_info.public_key.1.is_some() {
                    match fi_digital_signatures::crypto::ecdsa::_512::P512VerifyingKey::from_pem(
                        signing_info.public_key.1.as_ref().unwrap().as_str(),
                    ) {
                        Ok(val) => Box::new(val),
                        Err(error) => return Err(Error::new(error.to_string().as_str())),
                    }
                } else {
                    return Err(Error::new("public key content unknown"));
                }
            }
            Algorithm::ES256K => {
                if signing_info.public_key.0.is_some() {
                    match fi_digital_signatures::crypto::ecdsa::_256k::P256kVerifyingKey::from_bytes(
                        signing_info.public_key.0.clone().unwrap().as_mut_slice(),
                    ) {
                        Ok(val) => Box::new(val),
                        Err(error) => return Err(Error::new(error.to_string().as_str())),
                    }
                } else if signing_info.public_key.1.is_some() {
                    match fi_digital_signatures::crypto::ecdsa::_256k::P256kVerifyingKey::from_pem(
                        signing_info.public_key.1.as_ref().unwrap().as_str(),
                    ) {
                        Ok(val) => Box::new(val),
                        Err(error) => return Err(Error::new(error.to_string().as_str())),
                    }
                } else {
                    return Err(Error::new("public key content unknown"));
                }
            }
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                if signing_info.public_key.0.is_some() {
                    Box::new(fi_digital_signatures::crypto::hmac::HMACKey::new(
                        String::from(String::from_utf8_lossy(
                            &signing_info.public_key.0.clone().unwrap(),
                        )),
                    ))
                } else if signing_info.public_key.1.is_some() {
                    Box::new(fi_digital_signatures::crypto::hmac::HMACKey::new(
                        signing_info.public_key.1.clone().unwrap(),
                    ))
                } else {
                    return Err(Error::new("public key content unknown"));
                }
            }
        };

        match verifying_key.verify(content, signature, signing_info.alg) {
            Ok(val) => Ok(val),
            Err(error) => Err(Error::new(error.to_string().as_str())),
        }
    }
}
