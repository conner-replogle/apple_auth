A port of the js library (apple_auth)[https://github.com/ananay/apple-auth] into rust.

Used for sign in with apple. 

Api is the same as the JS version besides some diffrences with the config and private key. Any contributions are welcome

(Setup)[https://github.com/ananay/apple-auth/blob/master/SETUP.md]
```
    //check the apple-auth js docs for getting this
    let config = AppleConfig{ 
        client_id: "".to_string(), 
        team_id: "".to_string(), 
        redirect_uri: "".to_string(), 
        key_id: "".to_string(), 
        scope: "email".to_string(), 
    };
    let key = PrivateKeyLocation::Text("-----BEGIN PRIVATE KEY-----
    priv_key data
    -----END PRIVATE KEY-----".to_string());
    
    let apple_auth = apple_auth::apple_auth::AppleAuth::new(config,key);
    let token = apple_auth.access_token(code).await.unwrap();

    let mut no_validation = Validation::new(Algorithm::RS256);
    no_validation.insecure_disable_signature_validation();
    no_validation.set_audience(&[apple_auth.config.client_id.as_str()]);
    let dummy_decoding_key = DecodingKey::from_rsa_components("", "").unwrap();
    let tokenID:TokenData<IdToken> = jsonwebtoken::decode(&token.id_token,&dummy_decoding_key,&no_validation).unwrap();

    let user_id = tokenID.claims.sub;
    let email = tokenID.claims.email;
   
    if let (Some(first_name),Some(last_name),Some(email)) = (first_name,last_name,email){
        //Create user
        println!("Create user: {} {} {}",first_name,last_name,email);
    }

```
