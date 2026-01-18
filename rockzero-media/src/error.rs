use thiserror::Error;

#[derive(Error, Debug)]
pub enum HlsError {
    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Session expired: {0}")]
    SessionExpired(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("SAE error: {0}")]
    SaeError(#[from] rockzero_sae::SaeError),
}

pub type Result<T> = std::result::Result<T, HlsError>;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Bad request: {0}")]
    BadRequest(String),
    
    #[error("Internal error")]
    InternalError,
    
    #[error("Not found: {0}")]
    NotFound(String),
}
