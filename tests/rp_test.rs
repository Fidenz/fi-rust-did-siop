use fi_did_siop::{provider::Provider, rp::RP, siop_request::DidSiopRequest};
use serde_json::{json, Value};

#[tokio::test]
pub async fn rp_test_1() {
    let did = String::from(
        "did:ethr:mainnet:0x0345dd0c781893a801588a36051e3bdc61f15f0dd51aa716915e763bd2a2f613f6",
    );
    let redirect_uri = "https://me.com/callback";
    let mut rp = RP::get_rp(
        did.clone(),
        None,
        did.clone(),
        serde_json::Value::Null,
        None,
        None,
        None,
    )
    .await;

    match rp.add_signing_params(fi_common::keys::KeyPair {
        id: None,
        _type: "JWT".to_string(),
        context: None,
        public_key_base58: None,
        private_key_base58: None,
        public_key_multibase: None,
        private_key_multibase: None,
        revoked: None,
        controller: None,
        blockchain_account_id: None,
        public_key_hex: None,
        ethereum_address: None,
        public_key_base64: None,
        public_key_pem: None,
        public_key_jwk: None,
        private_key_hex: Some(String::from(
            "2d0651990af6802bf1509cafe5784f98ec35932cb57ee2d8ef7ab0f8f43cf83e",
        )),
        private_key_base64: None,
        private_key_pem: None,
        value: None,
        private_key_jwk: None,
    }) {
        Ok(_) => {}
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };

    let req = match rp
        .generate_request(json!({"redirect_uri": redirect_uri, "request_uri": redirect_uri, "id_token_signed_response_alg": ["ES256K", "ES256K-R", "EdDSA", "RS256"] }))
        .await
    {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };

    let provider = Provider::get_provider(did, None, None).await;
    let k = match provider.validate_request(req, None, None).await {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };
    println!("{}", serde_json::to_string(&k).unwrap());
}

#[tokio::test]
pub async fn rp_test_2() {
    let did = String::from(
        "did:ethr:mainnet:0x02be73dcaa2013a714b6745f54ff8576df151f8226cc3923538bfbfb9a014584fe",
    );
    let redirect_uri = "https://me.com/callback";
    let mut rp = RP::get_rp(
        did.clone(),
        None,
        did.clone(),
        serde_json::Value::Null,
        None,
        None,
        None,
    )
    .await;

    match rp.add_signing_params(fi_common::keys::KeyPair {
        id: None,
        _type: "JWT".to_string(),
        context: None,
        public_key_base58: None,
        private_key_base58: None,
        public_key_multibase: None,
        private_key_multibase: None,
        revoked: None,
        controller: None,
        blockchain_account_id: None,
        public_key_hex: None,
        ethereum_address: None,
        public_key_base64: None,
        public_key_pem: None,
        public_key_jwk: None,
        private_key_hex: Some(String::from(
            "c4873e901915343baf7302b0b87bae70bf5726e9280d415b3f7fc85908cc9d5a",
        )),
        private_key_base64: None,
        private_key_pem: None,
        value: None,
        private_key_jwk: None,
    }) {
        Ok(_) => {}
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };

    let req = match rp
        .generate_request(json!({"redirect_uri": redirect_uri, "request_uri": redirect_uri, "id_token_signed_response_alg": ["ES256K", "ES256K-R", "EdDSA", "RS256"] }))
        .await
    {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };

    let provider = Provider::get_provider(did, None, None).await;
    let k = match provider.validate_request(req, None, None).await {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };
    println!("{}", serde_json::to_string(&k).unwrap());
}
