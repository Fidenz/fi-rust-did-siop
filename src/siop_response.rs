use core::error;
use std::{ops::Deref, str::FromStr};

use chrono::{TimeZone, Timelike, Utc};
use fi_common::error::Error;
use fi_digital_signatures::{
    algorithms::Algorithm,
    jwt::{Header, Payload},
};
use serde_json::{json, Value};

use crate::{
    identity::{did::DidResolver, Identity},
    jwt::{SigningInfo, JWT},
    siop::{SIOPTokenObjects, SIOPTokensEcoded},
    vp::VPData,
};

pub struct CheckParams {
    redirect_uri: String,
    nonce: Option<String>,
    valid_before: Option<i64>,
    is_expirable: bool,
}

struct DidSiopResponse {}

impl DidSiopResponse {
    pub fn generate_response(
        request_payload: Value,
        signing_info: &SigningInfo,
        user: &mut Identity,
        expires_in: u32,
        vps: Option<VPData>,
    ) -> Result<String, fi_common::error::Error> {
        let alg = signing_info.alg;

        let did_key_opt = match user.extract_authentication_keys(alg) {
            Ok(val) => val.iter().find(|e| e.id == signing_info.kid),
            Err(error) => return Err(error),
        };

        let header = Header {
            alg,
            kid: signing_info.kid.clone(),
            typ: String::from("JWT"),
        };

        let mut payload = json!({
            "iss": "https://self-issued.me"
        });

        if user.doc.is_none() {
            return Err(Error::new("DID not found"));
        }

        payload["did"] = match serde_json::to_value(user.doc.clone().unwrap()) {
            Ok(val) => val,
            Err(error) => return Err(Error::new(error.to_string().as_str())),
        };

        if request_payload["redirect_uri"].as_str().is_some() {
            payload["aud"] = request_payload["redirect_uri"].clone(); // Changed as per SIOPV2
        }
        if request_payload["nonce"].as_str().is_some() {
            payload["nonce"] = request_payload["nonce"].clone(); // Changed as per SIOPV2
        }
        if request_payload["state"].as_str().is_some() {
            payload["state"] = request_payload["state"].clone(); // Changed as per SIOPV2
        }
        if request_payload["claims"].as_str().is_some() {
            payload["claims"] = request_payload["claims"].clone(); // Changed as per SIOPV2
        }

        // add public key

        payload["iat"] = match serde_json::to_value(chrono::Utc::now()) {
            Ok(val) => val,
            Err(error) => return Err(Error::new(error.to_string().as_str())),
        };
        payload["exp"] = match serde_json::to_value(chrono::Utc::now().with_second(expires_in)) {
            Ok(val) => val,
            Err(error) => return Err(Error::new(error.to_string().as_str())),
        };

        if vps.as_ref().is_some_and(|vp| !vp._vp_token.is_null()) {
            payload["_vp_token"] = match serde_json::to_value(vps.unwrap()._vp_token) {
                Ok(val) => val,
                Err(error) => return Err(Error::new(error.to_string().as_str())),
            };
        }

        let mut jwt = JWT {
            header,
            payload: Payload(payload),
            signature: None,
        };

        match jwt.sign(signing_info) {
            Ok(_) => {}
            Err(error) => return Err(error),
        };

        let header_content = match serde_json::to_string(&jwt.header) {
            Ok(val) => val,
            Err(error) => return Err(Error::new(error.to_string().as_str())),
        };

        let payload_content = match serde_json::to_string(&jwt.payload) {
            Ok(val) => val,
            Err(error) => return Err(Error::new(error.to_string().as_str())),
        };

        Ok(format!(
            "{}.{}.{}",
            base64::encode(&header_content),
            base64::encode(&payload_content),
            jwt.signature.unwrap()
        ))
    }

    pub fn generate_response_with_vpdata(
        request_payload: Value,
        signing_info: &SigningInfo,
        user: &mut Identity,
        expires_in: u32,
        vps: Option<VPData>,
    ) -> Result<SIOPTokensEcoded, fi_common::error::Error> {
        let mut id_token_s = String::from("");
        let mut vp_token_s = String::from("");

        id_token_s = match Self::generate_response(
            request_payload.clone(),
            signing_info,
            user,
            expires_in,
            vps.clone(),
        ) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        if vps.as_ref().is_some_and(|vp| !vp._vp_token.is_null()) {
            vp_token_s =
                match Self::generate_response_with_vptoken(request_payload, signing_info, vps) {
                    Ok(val) => val,
                    Err(error) => return Err(error),
                };
        }

        Ok(SIOPTokensEcoded::new(id_token_s, vp_token_s))
    }

    pub fn generate_response_with_vptoken(
        request_payload: Value,
        signing_info: &SigningInfo,
        vps: Option<VPData>,
    ) -> Result<String, fi_common::error::Error> {
        if request_payload["registration"]["id_token_signed_response_alg"].is_null() {
            return Err(Error::new(
                "id_token_signed_response_alg field not found in registration",
            ));
        }

        let id_token_signed_response_alg: Vec<String> = match serde_json::from_value(
            request_payload["registration"]["id_token_signed_response_alg"].clone(),
        ) {
            Ok(val) => val,
            Err(error) => return Err(Error::new(error.to_string().as_str())),
        };

        if !id_token_signed_response_alg
            .iter()
            .any(|f| Algorithm::from_str(f.as_str()).unwrap() == signing_info.alg)
        {
            return Err(Error::new("Unsupported algorithm"));
        }

        let header = Header {
            alg: signing_info.alg,
            kid: signing_info.kid.clone(),
            typ: String::from("JWT"),
        };

        let mut payload = Value::Null;

        if vps.as_ref().is_some_and(|vp| !vp.vp_token.is_null()) {
            payload = vps.unwrap().vp_token;
        }

        let mut jwt = JWT {
            header,
            payload: Payload(payload),
            signature: None,
        };

        match jwt.sign(signing_info) {
            Ok(_) => {}
            Err(error) => return Err(error),
        };
        let header_content = match serde_json::to_string(&jwt.header) {
            Ok(val) => val,
            Err(error) => return Err(Error::new(error.to_string().as_str())),
        };

        let payload_content = match serde_json::to_string(&jwt.payload) {
            Ok(val) => val,
            Err(error) => return Err(Error::new(error.to_string().as_str())),
        };

        Ok(format!(
            "{}.{}.{}",
            base64::encode(&header_content),
            base64::encode(&payload_content),
            jwt.signature.unwrap()
        ))
    }

    pub fn validate_response(
        response: String,
        check_params: CheckParams,
        resolvers: Option<Vec<Box<dyn DidResolver>>>,
    ) -> Result<JWT, Error> {
        let content: Vec<&str> = response.split(".").collect();
        if content.len() != 3 {
            return Err(Error::new("Invalid JWT string"));
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

        let iss = payload["iss"].as_str();
        let aud = payload["aud"].as_str();
        let did = payload["did"].as_str();
        let sub = payload["sub"].as_str();
        let sub_jwk = payload["sub_jwk"].clone();

        if header.kid.contains(" ")
            && iss.is_some_and(|e| !e.contains(" "))
            && aud.is_some_and(|e| !e.contains(" "))
            && did.is_some_and(|e| !e.contains(" "))
            && sub.is_some_and(|e| !e.contains(" "))
            && serde_json::to_string(&sub_jwk).is_ok_and(|e| !e.contains(" "))
        {
            if iss.is_some_and(|e| e.ne("https://self-issued.me")) {
                return Err(Error::new("Is not compatible with the SIOP flow"));
            }

            if aud.is_some_and(|e| e.ne(&check_params.redirect_uri)) {
                return Err(Error::new("Incorrect audience"));
            }

            if !payload["none"].as_str().is_none()
                || iss.is_some_and(|e| e.ne("https://self-issued.me"))
            {
                return Err(Error::new("Is not compatible with the SIOP flow"));
            }

            if check_params.valid_before.is_some() {
                let valid_before = check_params.valid_before.unwrap();
                if payload["iat"].is_null() {
                    return Err(Error::new("No issued time"));
                } else {
                    let iat = match payload["iat"].as_number() {
                        Some(val) => val,
                        None => return Err(Error::new("Parsing 'iat' failed")),
                    };

                    match chrono::Utc.timestamp_millis_opt(iat.as_i64().unwrap() + valid_before) {
                        chrono::offset::LocalResult::Single(val) => {
                            if val < Utc::now() {
                                return Err(Error::new("Expired"));
                            }
                        }
                        chrono::offset::LocalResult::None => {}
                        chrono::offset::LocalResult::Ambiguous(val, e) => {
                            if val < Utc::now() {
                                return Err(Error::new("Expired"));
                            }
                        }
                    };

                    let jwt_thumbprint = match calculate_thumbprint(sub_jwk) {
                        Ok(val) => val,
                        Err(error) => return Err(error),
                    };
                    if jwt_thumbprint.ne(&sub.unwrap()) {
                        return Err(Error::new("Invalid jwk thumbprint"));
                    }

                    let mut identity = Identity::new();
                    if resolvers.is_some() {
                        identity.add_resolvers(resolvers.unwrap());
                    }

                    let mut key = match identity.extract_authentication_keys(header.alg) {
                        Ok(val) => match val.iter().find(|x| x.id.eq(&header.kid)) {
                            Some(v) => v.clone(),
                            None => return Err(Error::new("Public key not found")),
                        },
                        Err(error) => return Err(error),
                    };

                    let valid = match JWT::verify(
                        format!("{}.{}", content[0], content[1]),
                        String::from(content[2]),
                        &mut key,
                    ) {
                        Ok(val) => val,
                        Err(error) => return Err(error),
                    };

                    if valid {
                        return Ok(JWT {
                            header,
                            payload: Payload(payload),
                            signature: Some(String::from(content[2])),
                        });
                    } else {
                        return Err(Error::new("JWT invalid"));
                    }
                }
            }
        }
        return Err(Error::new("Invalid jwt content"));
    }

    pub fn validate_response_with_vpdata(
        tokens_encoded: SIOPTokensEcoded,
        check_params: CheckParams,
        resolvers: Option<Vec<Box<dyn DidResolver>>>,
    ) -> Result<SIOPTokenObjects, Error> {
        let decoded_id_token = match DidSiopResponse::validate_response(
            tokens_encoded.get_id_token().clone(),
            check_params,
            resolvers,
        ) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        let decoded_vp_token = match JWT::from_str(tokens_encoded.get_vp_token().as_str()) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        Ok(SIOPTokenObjects::new(decoded_id_token, decoded_vp_token))
    }
}

fn calculate_thumbprint(sub_jwk: Value) -> Result<String, Error> {
    Ok(sha256::digest(match serde_json::to_string(&sub_jwk) {
        Ok(val) => val,
        Err(error) => return Err(Error::new(error.to_string().as_str())),
    }))
}
