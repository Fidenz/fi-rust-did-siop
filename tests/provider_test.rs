use fi_did_siop::{provider::Provider, rp::RP, siop_response::CheckParams};
use serde_json::json;

#[tokio::test]
pub async fn provider_test_1() {
    let did = String::from(
        "did:ethr:mainnet:0x0345dd0c781893a801588a36051e3bdc61f15f0dd51aa716915e763bd2a2f613f6",
    );
    let mut provider = Provider::get_provider(did.clone(), None, None).await;

    match provider.add_signing_params(
        fi_common::keys::KeyPair {
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
        },
        None,
    ) {
        Ok(_) => {}
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };

    let redirect_uri = "https://me.com/callback";

    let jwt = match provider
        .generate_response(
            json!({"redirect_uri": redirect_uri, "iss": "https://self-issued.me", }),
            4000,
        )
        .await
    {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };

    println!("{}", jwt);

    let rp = RP::get_rp(
        String::from(redirect_uri),
        Some(String::from(redirect_uri)),
        did,
        serde_json::Value::Null,
        None,
        None,
        None,
    )
    .await;

    let jwt_obj = match rp
        .validate_response(
            jwt,
            &mut CheckParams {
                redirect_uri: String::from(redirect_uri),
                nonce: None,
                valid_before: Some(10000),
                is_expirable: true,
            },
            None,
        )
        .await
    {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };

    println!("{}", serde_json::to_string(&jwt_obj).unwrap());
}

#[tokio::test]
pub async fn provider_test_2() {
    let did = String::from(
        "did:ethr:mainnet:0x02be73dcaa2013a714b6745f54ff8576df151f8226cc3923538bfbfb9a014584fe",
    );
    let mut provider = Provider::get_provider(did.clone(), None, None).await;

    match provider.add_signing_params(
        fi_common::keys::KeyPair {
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
        },
        Some(fi_digital_signatures::algorithms::Algorithm::EdDSA),
    ) {
        Ok(_) => {}
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };

    let redirect_uri = "https://me.com/callback";

    let jwt = match provider
        .generate_response(
            json!({"redirect_uri": redirect_uri, "iss": "https://self-issued.me", }),
            4000,
        )
        .await
    {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };

    println!("{}", jwt);

    let rp = RP::get_rp(
        String::from(redirect_uri),
        Some(String::from(redirect_uri)),
        did,
        serde_json::Value::Null,
        None,
        None,
        None,
    )
    .await;

    let jwt_obj = match rp
        .validate_response(
            jwt,
            &mut CheckParams {
                redirect_uri: String::from(redirect_uri),
                nonce: None,
                valid_before: Some(10000),
                is_expirable: true,
            },
            None,
        )
        .await
    {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };

    println!("{:#?}", serde_json::to_string(&jwt_obj).unwrap());
}
