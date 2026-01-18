use thiserror::Error;

#[derive(Error, Debug)]
pub enum SaeError {
    #[error("Invalid password or credentials")]
    InvalidCredentials,

    #[error("Commit verification failed")]
    CommitVerificationFailed,

    #[error("Confirm verification failed")]
    ConfirmVerificationFailed,

    #[error("Invalid scalar value")]
    InvalidScalar,

    #[error("Invalid point on curve")]
    InvalidPoint,

    #[error("Protocol state error: {0}")]
    ProtocolState(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Key derivation error: {0}")]
    KeyDerivationError(String),
}

pub type Result<T> = std::result::Result<T, SaeError>;
