use std::str::FromStr;

use fi_common::error::Error;
use fi_digital_signatures::{
    algorithms::Algorithm,
    crypto::{SignFromKey, VerifyFromKey},
    jwt::{Header, Payload},
};
use reqwest::header;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::identity::DidKey;

#[derive(Serialize, Deserialize, Clone)]
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

impl FromStr for JWT {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let content: Vec<&str> = s.split(".").collect();
        if content.len() < 2 {
            return Err(Error::new("Invalid JWT content"));
        }

        let header: Header = match base64::decode(content[0]) {
            Ok(val) => match serde_json::from_slice(val.as_slice()) {
                Ok(v) => v,
                Err(error) => return Err(Error::new(error.to_string().as_str())),
            },
            Err(error) => return Err(Error::new(error.to_string().as_str())),
        };

        let payload: Value = match base64::decode(content[1]) {
            Ok(val) => match serde_json::from_slice(val.as_slice()) {
                Ok(v) => v,
                Err(error) => return Err(Error::new(error.to_string().as_str())),
            },
            Err(error) => return Err(Error::new(error.to_string().as_str())),
        };

        Ok(JWT {
            header,
            payload: Payload(payload),
            signature: match content.len() > 2 {
                true => Some(String::from(content[2])),
                false => None,
            },
        })
    }
}

impl JWT {
    pub fn sign(&mut self, signing_info: &SigningInfo) -> Result<(), Error> {
        let signing_key = match get_signing_key(signing_info) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        match signing_key.sign(
            format!(
                "{}.{}",
                base64::encode(&serde_json::to_string(&self.header).unwrap()),
                base64::encode(&serde_json::to_string(&self.payload).unwrap())
            ),
            signing_info.alg,
        ) {
            Ok(_) => Ok(()),
            Err(error) => Err(Error::new(error.to_string().as_str())),
        }
    }

    pub fn verify(
        content: String,
        signature: String,
        signing_info: &mut DidKey,
    ) -> Result<bool, Error> {
        let verifying_key = match get_verifying_key(signing_info) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        match verifying_key.verify(content, signature, signing_info.alg) {
            Ok(val) => Ok(val),
            Err(error) => Err(Error::new(error.to_string().as_str())),
        }
    }
}

pub fn get_signing_key(signing_info: &SigningInfo) -> Result<Box<dyn SignFromKey>, Error> {
    let signing_key: Box<dyn SignFromKey> = match signing_info.alg {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            if signing_info.key.0.is_some() {
                match fi_digital_signatures::crypto::rsa::RsaSigningKey::from_bytes(
                    signing_info.key.0.as_ref().unwrap().as_slice(),
                ) {
                    Ok(val) => Box::new(val),
                    Err(error) => return Err(Error::new(error.to_string().as_str())),
                }
            } else if signing_info.key.1.is_some() {
                match fi_digital_signatures::crypto::rsa::RsaSigningKey::from_pem(
                    signing_info.key.1.as_ref().unwrap().as_str(),
                ) {
                    Ok(val) => Box::new(val),
                    Err(error) => return Err(Error::new(error.to_string().as_str())),
                }
            } else {
                return Err(Error::new("public key content unknown"));
            }
        }
        Algorithm::EdDSA => {
            if signing_info.key.0.is_some() {
                match fi_digital_signatures::crypto::eddsa::EDDSASigningKey::from_bytes(
                    signing_info.key.0.clone().unwrap().as_mut_slice(),
                ) {
                    Ok(val) => Box::new(val),
                    Err(error) => return Err(Error::new(error.to_string().as_str())),
                }
            } else if signing_info.key.1.is_some() {
                match fi_digital_signatures::crypto::eddsa::EDDSASigningKey::from_pem(
                    signing_info.key.1.as_ref().unwrap().as_str(),
                ) {
                    Ok(val) => Box::new(val),
                    Err(error) => return Err(Error::new(error.to_string().as_str())),
                }
            } else {
                return Err(Error::new("public key content unknown"));
            }
        }
        Algorithm::ES256 => {
            if signing_info.key.0.is_some() {
                match fi_digital_signatures::crypto::ecdsa::_256::P256SigningKey::from_bytes(
                    signing_info.key.0.clone().unwrap().as_mut_slice(),
                ) {
                    Ok(val) => Box::new(val),
                    Err(error) => return Err(Error::new(error.to_string().as_str())),
                }
            } else if signing_info.key.1.is_some() {
                match fi_digital_signatures::crypto::ecdsa::_256::P256SigningKey::from_pem(
                    signing_info.key.1.as_ref().unwrap().as_str(),
                ) {
                    Ok(val) => Box::new(val),
                    Err(error) => return Err(Error::new(error.to_string().as_str())),
                }
            } else {
                return Err(Error::new("public key content unknown"));
            }
        }
        Algorithm::ES384 => {
            if signing_info.key.0.is_some() {
                match fi_digital_signatures::crypto::ecdsa::_384::P384SigningKey::from_bytes(
                    signing_info.key.0.clone().unwrap().as_mut_slice(),
                ) {
                    Ok(val) => Box::new(val),
                    Err(error) => return Err(Error::new(error.to_string().as_str())),
                }
            } else if signing_info.key.1.is_some() {
                match fi_digital_signatures::crypto::ecdsa::_384::P384SigningKey::from_pem(
                    signing_info.key.1.as_ref().unwrap().as_str(),
                ) {
                    Ok(val) => Box::new(val),
                    Err(error) => return Err(Error::new(error.to_string().as_str())),
                }
            } else {
                return Err(Error::new("public key content unknown"));
            }
        }
        Algorithm::ES512 => {
            if signing_info.key.0.is_some() {
                match fi_digital_signatures::crypto::ecdsa::_512::P512SigningKey::from_bytes(
                    signing_info.key.0.clone().unwrap().as_mut_slice(),
                ) {
                    Ok(val) => Box::new(val),
                    Err(error) => return Err(Error::new(error.to_string().as_str())),
                }
            } else if signing_info.key.1.is_some() {
                match fi_digital_signatures::crypto::ecdsa::_512::P512SigningKey::from_pem(
                    signing_info.key.1.as_ref().unwrap().as_str(),
                ) {
                    Ok(val) => Box::new(val),
                    Err(error) => return Err(Error::new(error.to_string().as_str())),
                }
            } else {
                return Err(Error::new("public key content unknown"));
            }
        }
        Algorithm::ES256K => {
            if signing_info.key.0.is_some() {
                match fi_digital_signatures::crypto::ecdsa::_256k::P256kSigningKey::from_bytes(
                    signing_info.key.0.clone().unwrap().as_mut_slice(),
                ) {
                    Ok(val) => Box::new(val),
                    Err(error) => return Err(Error::new(error.to_string().as_str())),
                }
            } else if signing_info.key.1.is_some() {
                match fi_digital_signatures::crypto::ecdsa::_256k::P256kSigningKey::from_pem(
                    signing_info.key.1.as_ref().unwrap().as_str(),
                ) {
                    Ok(val) => Box::new(val),
                    Err(error) => return Err(Error::new(error.to_string().as_str())),
                }
            } else {
                return Err(Error::new("public key content unknown"));
            }
        }
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            if signing_info.key.0.is_some() {
                Box::new(fi_digital_signatures::crypto::hmac::HMACKey::new(
                    String::from(String::from_utf8_lossy(
                        &signing_info.key.0.clone().unwrap(),
                    )),
                ))
            } else if signing_info.key.1.is_some() {
                Box::new(fi_digital_signatures::crypto::hmac::HMACKey::new(
                    signing_info.key.1.clone().unwrap(),
                ))
            } else {
                return Err(Error::new("public key content unknown"));
            }
        }
    };

    Ok(signing_key)
}

pub fn get_verifying_key(signing_info: &mut DidKey) -> Result<Box<dyn VerifyFromKey>, Error> {
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

    Ok(verifying_key)
}
