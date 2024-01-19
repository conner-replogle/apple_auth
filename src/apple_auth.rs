use std::{fmt::LowerHex, path::{Path, PathBuf}};
use serde::{Deserialize, Serialize};
use url::Url;
use jwt::{algorithm::rust_crypto, ToBase64};
use openssl::rand::rand_bytes;

use crate::{apple_client_secret::{AppleClientSecret, PrivateKeyLocation}, apple_config::AppleConfig, apple_error::AppleAuthError};

#[derive(Serialize)]
struct AppleRequestPayload<'a>{
    grant_type: &'a str,
    code:  &'a str,
    redirect_uri:  &'a str,
    client_id:  &'a str,
    client_secret:  &'a str,
}

#[derive(Deserialize,Debug)]
struct AppleResponsePayload{
    access_token: String,
    expires_in: u64,
    id_token: String,
    refresh_token: String,
    token_type: String,
}


pub struct AppleAuth{
    config: AppleConfig,
    state: String,
    client: AppleClientSecret
}

impl AppleAuth{

    pub fn new(config: AppleConfig,priv_key:PrivateKeyLocation) -> Self{  
 
        let client = AppleClientSecret::new(config.clone(), priv_key);
    
        Self{
            config,
            state: String::new(),
            client
        }
    }
    

    pub fn login_url(&mut self) -> Url{
        let mut buf: [u8; 5] = [0u8; 5];
        rand_bytes(&mut buf).unwrap();
        self.state = hex::encode(buf);
        let mut url = Url::parse("https://appleid.apple.com/auth/authorize").unwrap();
        url.query_pairs_mut()
            .append_pair("response_type", "code id_token")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("state", &self.state)
            .append_pair("scope", &self.config.scope)
            .append_pair("response_mode", "form_post");
        return url;
    }

    pub async fn accessToken(&mut self,code:String) -> Result<AppleResponsePayload, AppleAuthError>{
        let token = self.client.generate()?;
      
        let payload = AppleRequestPayload{
            grant_type: "authorization_code",
            code: &code,
            redirect_uri: &self.config.redirect_uri,
            client_id: &self.config.client_id,
            client_secret: &token,
        };
        
        let client = reqwest::Client::new();
        let res:AppleResponsePayload = client.post("https://appleid.apple.com/auth/token")
            .form(&payload)
            .send().await?
            .json().await?;

        return Ok(res);
        
    
    }
}
