use fi_common::did::DidDocument;
use fi_did_siop::http_request;
use reqwest::Method;
use serde_json::Value;

#[tokio::test]
pub async fn test_uni_resolver() {
    let res = match http_request::send_request(
        format!(
            "https://dev.uniresolver.io/1.0/identifiers/{}",
            "did:ethr:mainnet:0x3b0bc51ab9de1e5b7b6e34e5b960285805c41736"
        ),
        Method::GET,
        None,
        None,
        None,
    )
    .await
    {
        Ok(val) => val,
        Err(error) => {
            println!("{}", error);
            assert!(false);
            return;
        }
    };

    let res_text = match res.text().await {
        Ok(val) => val,

        Err(error) => {
            println!("{}", error);
            assert!(false);
            return;
        }
    };

    println!("{:#?}", res_text);

    let mut response_value: Value = match serde_json::from_str(res_text.as_str()) {
        Ok(val) => val,
        Err(error) => {
            println!("{}", error);
            assert!(false);
            return;
        }
    };

    let did_doc: DidDocument = match serde_json::from_value(response_value["didDocument"].take()) {
        Ok(val) => val,
        Err(error) => {
            println!("{}", error);
            assert!(false);
            return;
        }
    };

    println!("{:#?}", serde_json::to_string(&did_doc).unwrap());
    assert!(false)
}
