

#[derive(thiserror::Error, Debug)]
pub enum AppleAuthError{
    #[error("Error loading private key {0}")]
    FilePath(#[from] std::io::Error),
    #[error("Error with private key {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),
    #[error("Error with request {0}")]
    RequestError(#[from] reqwest::Error),


}