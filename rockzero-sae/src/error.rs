use thiserror::Error;

#[derive(Error, Debug)]
pub enum SaeError {
    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Invalid commit: {0}")]
    InvalidCommit(String),

    #[error("Unsupported group: {0}")]
    UnsupportedGroup(u16),

    #[error("Confirm verification failed")]
    ConfirmVerificationFailed,

    #[error("Maximum sync attempts reached")]
    MaxSyncReached,

    #[error("IO error: {0}")]
    IoError(String),

    #[error("Invalid password or credentials")]
    InvalidCredentials,

    #[error("Commit verification failed")]
    CommitVerificationFailed,

    #[error("Invalid scalar value")]
    InvalidScalar,

    #[error("Invalid point on curve")]
    InvalidPoint,

    #[error("Protocol state error: {0}")]
    ProtocolState(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Key derivation error: {0}")]
    KeyDerivationError(String),
}

pub type Result<T> = std::result::Result<T, SaeError>;
