use std::path::PathBuf;


#[derive(Debug, Clone)]
pub struct AppleConfig{
    pub client_id: String,
    pub team_id: String,
    pub redirect_uri: String,
    pub key_id: String,
    pub scope: String
}

#[derive(Clone,Debug)]
pub enum PrivateKeyLocation{
    File(PathBuf),
    Text(String)
}