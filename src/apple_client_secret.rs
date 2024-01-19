use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use jsonwebtoken::{encode, EncodingKey, Header,Algorithm};
use serde::{Deserialize, Serialize};
use hmac::{Hmac, Mac};
use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey};

use crate::apple_config::{AppleConfig, PrivateKeyLocation};
use crate::apple_error::AppleAuthError;
#[derive(Debug, Serialize, Deserialize)]
struct Claims<'a> {
    iss: &'a str,
    iat: u64,
    exp: u64,
    aud:&'a str,
    sub: &'a str,
}


#[derive(Debug, Clone)]
pub struct AppleClientSecret{
    config: AppleConfig,
    priv_key:PrivateKeyLocation
}
impl AppleClientSecret{
    pub fn new(config: AppleConfig,priv_key:PrivateKeyLocation) -> AppleClientSecret{
        AppleClientSecret{
            config,
            priv_key
        }
    }
    pub fn generate(&self) -> Result<String, AppleAuthError> {
        let exp = ((chrono::Utc::now().timestamp_millis() / 1000) + ( 86400 * 180 )) as u64; 
        match &self.priv_key{
            PrivateKeyLocation::File(path) => {
                let key = std::fs::read_to_string(path).unwrap();
                return Ok(self.generate_token(&self.config.client_id, &self.config.team_id,&key,exp, &self.config.key_id)?);

            },
            PrivateKeyLocation::Text(key) => {
                return Ok(self.generate_token(&self.config.client_id, &self.config.team_id,key,exp, &self.config.key_id)?);
            },
        }
        
    }

    fn generate_token(&self,client_id: &str,team_id:&str,private_key: &str,expiration:u64,key_id: &str) -> Result<String,jsonwebtoken::errors::Error>{
        let claims = Claims{
            iss: team_id,
            iat: (chrono::Utc::now().timestamp_millis()/1000) as u64,
            exp: expiration,
            aud: "https://appleid.apple.com",
            sub: client_id,
        };
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(key_id.to_string());
        let token = encode(&header, &claims, &EncodingKey::from_ec_pem(private_key.as_bytes()).unwrap()).unwrap();

        
        return Ok(token);
    }
}