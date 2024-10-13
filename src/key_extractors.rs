use base64::{decode_config, URL_SAFE_NO_PAD};
use fi_common::{error::Error, keys::KeyPair};
use keccak_hash::keccak256;
use regex::Regex;
use serde_json::Value;

pub fn get_verifying_key(key_pair: KeyPair) -> Result<(Option<Vec<u8>>, Option<String>), Error> {
    if key_pair.public_key_jwk.is_some() {
        let jwk = key_pair.public_key_jwk.unwrap();

        match jwk_to_key_bytes(jwk.to_string()) {
            Ok(val) => return Ok((Some(val), None)),
            Err(error) => return Err(error),
        };
    }

    if key_pair.public_key_hex.is_some() {
        let bytes = match hex::decode(key_pair.public_key_hex.unwrap()) {
            Ok(val) => val,
            Err(error) => return Err(Error::new(error.to_string().as_str())),
        };

        return Ok((Some(bytes), None));
    }

    if key_pair.public_key_base58.is_some() {
        let bytes = match bs58::decode(key_pair.public_key_base58.unwrap()).into_vec() {
            Ok(val) => val,
            Err(error) => return Err(Error::new(error.to_string().as_str())),
        };

        return Ok((Some(bytes), None));
    }

    if key_pair.public_key_base64.is_some() {
        let bytes = match base64::decode(&key_pair.public_key_base64.unwrap()) {
            Ok(val) => val,
            Err(error) => return Err(Error::new(error.to_string().as_str())),
        };

        return Ok((Some(bytes), None));
    }

    if key_pair.public_key_multibase.is_some() {
        let bytes = match multibase::decode(key_pair.public_key_multibase.unwrap()) {
            Ok((_, val)) => val,
            Err(error) => return Err(Error::new(error.to_string().as_str())),
        };

        return Ok((Some(bytes), None));
    }

    if key_pair.public_key_pem.is_some() {
        let pem = key_pair.public_key_pem.unwrap();

        return Ok((None, Some(pem)));
    }

    if key_pair.blockchain_account_id.is_some() || key_pair.ethereum_address.is_some() {
        let mut address = String::from("");
        if key_pair.blockchain_account_id.is_some() {
            address = String::from(
                key_pair
                    .blockchain_account_id
                    .unwrap()
                    .split(":")
                    .last()
                    .unwrap(),
            );
        }

        if key_pair.ethereum_address.is_some() {
            address = key_pair.ethereum_address.unwrap();
        }

        match to_checksum_address(address, None) {
            Ok(val) => return Ok((Some(val.as_bytes().to_vec()), None)),
            Err(error) => return Err(error),
        }
    }

    return Err(Error::new("Public key data couldn't be found"));
}

fn jwk_to_key_bytes(jwk_str: String) -> Result<Vec<u8>, Error> {
    // Parse the JWK JSON string
    let jwk: Value = match serde_json::from_str(jwk_str.as_str()) {
        Ok(val) => val,
        Err(error) => return Err(Error::new(error.to_string().as_str())),
    };

    // Extract the key type (kty)
    let kty = match jwk.get("kty").ok_or("Missing 'kty' field") {
        Ok(val) => match val.as_str() {
            Some(val) => val,
            None => return Err(Error::new("Invalid 'kty' field")),
        },
        Err(error) => return Err(Error::new(error)),
    };

    match kty {
        "RSA" => {
            // RSA key: Extract 'n' (modulus) and 'e' (exponent)

            let n = match jwk.get("n").ok_or("Missing 'n' field") {
                Ok(val) => match val.as_str() {
                    Some(val) => val,
                    None => return Err(Error::new("Invalid 'n' field")),
                },
                Err(error) => return Err(Error::new(error)),
            };
            let e = match jwk.get("e").ok_or("Missing 'e' field") {
                Ok(val) => match val.as_str() {
                    Some(val) => val,
                    None => return Err(Error::new("Invalid 'e' field")),
                },
                Err(error) => return Err(Error::new(error)),
            };

            // Decode base64url-encoded 'n' and 'e'
            let n_bytes = decode_config(n, URL_SAFE_NO_PAD).unwrap();
            let e_bytes = decode_config(e, URL_SAFE_NO_PAD).unwrap();

            // Concatenate modulus and exponent bytes
            let key_bytes = [n_bytes, e_bytes].concat();
            return Ok(key_bytes);
        }
        "EC" => {
            // EC key: Extract 'crv', 'x', and 'y'
            let x = match jwk.get("x").ok_or("Missing 'x' field") {
                Ok(val) => match val.as_str() {
                    Some(val) => val,
                    None => return Err(Error::new("Invalid 'x' field")),
                },
                Err(error) => return Err(Error::new(error)),
            };
            let y = match jwk.get("y").ok_or("Missing 'y' field") {
                Ok(val) => match val.as_str() {
                    Some(val) => val,
                    None => return Err(Error::new("Invalid 'y' field")),
                },
                Err(error) => return Err(Error::new(error)),
            };

            // Decode base64url-encoded 'x' and 'y' coordinates
            let x_bytes = decode_config(x, URL_SAFE_NO_PAD).unwrap();
            let y_bytes = decode_config(y, URL_SAFE_NO_PAD).unwrap();

            // Handle P-256, P-384, P-512 curves
            let key_bytes = [x_bytes, y_bytes].concat();
            return Ok(key_bytes);
        }
        "OKP" => {
            // OKP key (e.g., Ed25519): Extract 'crv' and 'x'
            let crv = match jwk.get("crv").ok_or("Missing 'crv' field") {
                Ok(val) => match val.as_str() {
                    Some(val) => val,
                    None => return Err(Error::new("Invalid 'crv' field")),
                },
                Err(error) => return Err(Error::new(error)),
            };
            if crv == "Ed25519" {
                let x = match jwk.get("x").ok_or("Missing 'x' field") {
                    Ok(val) => match val.as_str() {
                        Some(val) => val,
                        None => return Err(Error::new("Invalid 'x' field")),
                    },
                    Err(error) => return Err(Error::new(error)),
                };
                let x_bytes = decode_config(x, URL_SAFE_NO_PAD).unwrap();
                return Ok(x_bytes);
            } else {
                Err(Error::new("Unsupported OKP curve"))
            }
        }
        _ => Err(Error::new("Unsupported key type")),
    }
}

fn to_checksum_address(address: String, chain_id: Option<String>) -> Result<String, Error> {
    let regex = match Regex::new("/^(0x)?[0-9a-f]{40}$/i") {
        Ok(val) => val,
        Err(error) => {
            return Err(Error::new(error.to_string().as_str()));
        }
    };
    if !regex.is_match(address.as_str()) {
        return Err(Error::new("Not a block chain address"));
    }

    let strip_address = match address.starts_with("0x") {
        true => String::from(&address[2..]),
        false => address,
    };

    let prefix = match chain_id {
        Some(val) => val + "0x",
        None => String::from(""),
    };

    let mut data_content = format!("{}{}", prefix, strip_address);
    let mut data = unsafe { data_content.as_bytes_mut() };
    keccak256(&mut data);
    let keccak_hash = hex::encode(data);
    let mut checksum_address = String::from("0x");
    for i in 0..strip_address.len() {
        checksum_address = format!(
            "{}{}",
            checksum_address,
            match hex::decode(&keccak_hash[i..i]).unwrap()[0] >= 8 {
                true => String::from(&strip_address[i..i]).to_uppercase(),
                false => String::from(&strip_address[i..i]),
            }
        );
    }
    Ok(checksum_address)
}
