use std::str::FromStr;

use crate::{
    http_request::send_request,
    identity::{did::DidResolver, DidKey, Identity},
    jwt::{SigningInfo, JWT},
    rp::RPInfo,
    siop::{get_metadata_supported, SiopMetadataSupported},
};
use fi_common::error::Error;
use fi_digital_signatures::jwt::{Header, Payload};
use json_value_merge::Merge;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

const REQUIRED_SCOPES: [&str; 1] = ["openid"];

#[derive(Serialize, Deserialize)]
struct Query {
    response_type: Value,
    client_id: Value,
    redirect_uri: Option<Value>,
    scope: Value,
    request: Option<Value>,
    request_uri: Option<Value>,
}

#[wasm_bindgen]
pub struct DidSiopRequest {}

impl DidSiopRequest {
    #[cfg(not(feature = "wasm"))]
    pub async fn validate_request(
        request: String,
        mut op_metadata: Option<SiopMetadataSupported>,
        resolvers: Option<Vec<Box<dyn DidResolver>>>,
    ) -> Result<JWT, Error> {
        if op_metadata.is_none() {
            op_metadata = Some(get_metadata_supported())
        }

        let request_jwt =
            match DidSiopRequest::validate_request_params(request, op_metadata.unwrap()).await {
                Ok(val) => val,
                Err(error) => return Err(error),
            };
        DidSiopRequest::validate_request_jwt(request_jwt, resolvers).await
    }

    #[cfg(feature = "wasm")]
    pub async fn validate_request(
        request: String,
        mut op_metadata: Option<SiopMetadataSupported>,
        resolvers: Option<Vec<Box<dyn DidResolver>>>,
    ) -> Result<JWT, Error> {
        if op_metadata.is_none() {
            op_metadata = Some(get_metadata_supported())
        }

        let request_jwt =
            match DidSiopRequest::validate_request_params(request, op_metadata.unwrap()).await {
                Ok(val) => val,
                Err(error) => return Err(error),
            };
        DidSiopRequest::validate_request_jwt(request_jwt, resolvers)
    }

    pub async fn generate_request(
        rp: &RPInfo,
        signing_info: &SigningInfo,
        options: Value,
    ) -> Result<String, Error> {
        let url = "openid://";
        let mut query = json!({ "response_type": "id_token",
            "client_id": rp.did,  
            "redirect_uri": rp.redirect_uri, 
            "scope": "openid"});

        if rp.request_uri.is_some() {
            query["request_uri"] = Value::from(rp.request_uri.clone().unwrap());
        } else {
            let header = Header {
                alg: signing_info.alg,
                kid: signing_info.kid.clone(),
                typ: String::from("JWT"),
            };

            let mut payload = json!({
                "iss": rp.did,
                "response_type": "id_token",
                "scope": "openid",
                "client_id": rp.redirect_uri,
                "registration": rp.registration,
            });
            payload.merge(&options);

            let mut jwt = JWT {
                header,
                payload: Payload(payload),
                signature: None,
            };

            match jwt.sign(signing_info) {
                Ok(_) => {}
                Err(error) => return Err(error),
            }

            query["request"] = match jwt.to_string() {
                Ok(val) => json!(val.as_str()),
                Err(error) => return Err(Error::new(error.to_string().as_str())),
            };
        }

        Ok(format!(
            "{}{}",
            url,
            match serde_qs::to_string(&query) {
                Ok(val) => val,
                Err(error) => return Err(Error::new(error.to_string().as_str())),
            }
        ))
    }

    pub async fn validate_request_params(
        request: String,
        op_metadata: SiopMetadataSupported,
    ) -> Result<String, Error> {
        if !request.starts_with("openid://") {
            return Err(Error::new("Invalid request url"));
        }

        let obj_str = &request["openid://".len()..];

        let query: Query = match serde_qs::from_str(obj_str) {
            Ok(val) => val,
            Err(error) => return Err(Error::new(error.to_string().as_str())),
        };

        if query.client_id.is_null() || query.response_type.is_null() {
            return Err(Error::new("Invalid request"));
        }

        let client_id_opt = query.client_id.as_str();
        let response_type_opt = query.response_type.as_str();

        if client_id_opt.is_none() || response_type_opt.is_none() {
            return Err(Error::new("Invalid request"));
        }

        let client_id = client_id_opt.unwrap();
        let response_type = response_type_opt.unwrap();

        if client_id.contains(" ") || response_type.contains(" ") {
            return Err(Error::new(
                "Invalid request fields: client_id, response_type",
            ));
        }

        let scope_opt = query.scope.as_str();
        if scope_opt.is_some() {
            let scope = scope_opt.unwrap();
            let requested_scopes: Vec<&str> = scope.split(" ").collect();
            if !requested_scopes.iter().all(|s| {
                op_metadata
                    .scopes()
                    .as_ref()
                    .is_some_and(|op| op.contains(&String::from(*s)))
            }) || !REQUIRED_SCOPES.iter().all(|s| requested_scopes.contains(s))
            {
                return Err(Error::new("Invalid scopes"));
            }
        } else {
            return Err(Error::new("Invalid request fields: scope"));
        }

        if op_metadata.response_types().is_some() {
            if !op_metadata
                .response_types()
                .unwrap()
                .contains(&String::from(response_type))
            {
                return Err(Error::new("Unsupported request"));
            }
        } else {
            return Err(Error::new("Invalid op_metadata fields: response_types"));
        }

        if query.request.is_none() {
            if query.request_uri.is_none() {
                return Err(Error::new("Invalid request fields: request_uri"));
            }

            let req = query.request_uri.unwrap();
            let request_uri = req.as_str().unwrap();
            if request_uri.contains(" ") {
                return Err(Error::new("Invalid request uri"));
            }

            match send_request(String::from(request_uri), Method::GET, None, None, None).await {
                Ok(val) => match val.text().await {
                    Ok(val) => return Ok(val),
                    Err(error) => return Err(Error::new(error.to_string().as_str())),
                },
                Err(error) => {
                    return Err(Error::new(error.to_string().as_str()));
                }
            }
        } else {
            let rq = query.request.unwrap();
            let request = rq.as_str();
            if request.is_some_and(|f| !f.contains(" ")) {
                Ok(String::from(request.unwrap()))
            } else {
                return Err(Error::new("Invalid request"));
            }
        }
    }

    #[cfg(not(feature = "wasm"))]
    pub async fn validate_request_jwt(
        jwt: String,
        resolvers: Option<Vec<Box<dyn DidResolver>>>,
    ) -> Result<JWT, Error> {
        let content: Vec<&str> = jwt.split(".").collect();
        if content.len() != 3 {
            return Err(Error::new("Invalid JWT string"));
        }

        let header: Header = match base64::decode(content[0]) {
            Ok(val) => match serde_json::from_str(String::from_utf8(val).unwrap().as_str()) {
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

        if header.kid.contains(" ")
            || payload["iss"].as_str().is_none()
            || payload["scope"].is_null()
        {
            let scopes: Vec<String> = match serde_json::from_value(payload["scope"].clone()) {
                Ok(val) => val,
                Err(error) => return Err(Error::new(error.to_string().as_str())),
            };

            if !scopes.contains(&String::from("openid")) {
                return Err(Error::new("Invalid request"));
            }
        }

        let did = payload["iss"].as_str().unwrap();

        let mut public_key_info: Option<DidKey> = None;

        let mut identity = Identity::new();
        if resolvers.is_some() {
            identity.add_resolvers(resolvers.unwrap());
        }
        identity.resolve(String::from(did)).await;

        public_key_info = match identity.extract_authentication_keys(header.alg) {
            Ok(val) => match val.iter().find(|x| x.id.eq(&header.kid)) {
                Some(v) => Some(v.clone()),
                None => None,
            },
            Err(error) => return Err(error),
        };

        if public_key_info.is_none() {
            return Err(Error::new(
                "No public key found in the remote did documents",
            ));
        }

        if public_key_info.is_some() {
            if !payload["jwks"].is_null() {}
        }

        // internal keys

        // validate jwt claims
        match JWT::verify(
            format!("{}.{}", content[0], content[1]),
            String::from(content[2]),
            &mut public_key_info.unwrap(),
        ) {
            Ok(val) => match val {
                true => Ok(JWT {
                    header,
                    payload: Payload(payload),
                    signature: Some(String::from(content[2])),
                }),
                false => Err(Error::new("JWT verification failed")),
            },
            Err(error) => return Err(error),
        }
    }

    #[cfg(feature = "wasm")]
    pub fn validate_request_jwt(
        jwt: String,
        resolvers: Option<Vec<Box<dyn DidResolver>>>,
    ) -> Result<JWT, Error> {
        let content: Vec<&str> = jwt.split(".").collect();
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

        if header.kid.contains(" ")
            || payload["iss"].as_str().is_none()
            || payload["scope"].is_null()
        {
            let scopes: Vec<String> = match serde_json::from_value(payload["scope"].clone()) {
                Ok(val) => val,
                Err(error) => return Err(Error::new(error.to_string().as_str())),
            };

            if !scopes.contains(&String::from("openid")) {
                return Err(Error::new("Invalid request"));
            }
        }

        let did = payload["iss"].as_str().unwrap();

        let mut public_key_info: Option<DidKey> = None;

        let mut identity = Identity::new();
        if resolvers.is_some() {
            identity.add_resolvers(resolvers.unwrap());
        }
        identity.resolve(String::from(did));

        public_key_info = match identity.extract_authentication_keys(header.alg) {
            Ok(val) => match val.iter().find(|x| x.id.eq(&header.kid)) {
                Some(v) => Some(v.clone()),
                None => None,
            },
            Err(error) => return Err(error),
        };

        if public_key_info.is_none() {
            return Err(Error::new(
                "No public key found in the remote did documents",
            ));
        }

        if public_key_info.is_some() {
            if !payload["jwks"].is_null() {}
        }

        // internal keys

        // validate jwt claims

        match JWT::verify(
            format!("{}.{}", content[0], content[1]),
            String::from(content[2]),
            &mut public_key_info.unwrap(),
        ) {
            Ok(val) => match val {
                true => Ok(JWT {
                    header,
                    payload: Payload(payload),
                    signature: Some(String::from(content[2])),
                }),
                false => Err(Error::new("JWT verification failed")),
            },
            Err(error) => return Err(error),
        }
    }
}
