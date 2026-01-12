use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use serde::Serialize;
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    // Authentication errors
    Unauthorized(String),
    InvalidCredentials,
    TokenExpired,
    InvalidToken,
    Forbidden(String),
    
    // Request errors
    BadRequest(String),
    ValidationError(String),
    NotFound(String),
    Conflict(String),
    PreconditionFailed(String),
    RangeNotSatisfiable(u64),
    
    // Server errors
    InternalError,
    DatabaseError(String),
    CryptoError(String),
    IoError(String),
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            Self::InvalidCredentials => write!(f, "Invalid credentials"),
            Self::TokenExpired => write!(f, "Token expired"),
            Self::InvalidToken => write!(f, "Invalid token"),
            Self::Forbidden(msg) => write!(f, "Forbidden: {}", msg),
            Self::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            Self::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            Self::NotFound(msg) => write!(f, "Not found: {}", msg),
            Self::Conflict(msg) => write!(f, "Conflict: {}", msg),
            Self::PreconditionFailed(msg) => write!(f, "Precondition failed: {}", msg),
            Self::RangeNotSatisfiable(size) => write!(f, "Range not satisfiable, file size: {}", size),
            Self::InternalError => write!(f, "Internal error"),
            Self::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            Self::CryptoError(msg) => write!(f, "Crypto error: {}", msg),
            Self::IoError(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Unauthorized(_) | Self::InvalidCredentials | 
            Self::TokenExpired | Self::InvalidToken => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::BadRequest(_) | Self::ValidationError(_) => StatusCode::BAD_REQUEST,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::PreconditionFailed(_) => StatusCode::PRECONDITION_FAILED,
            Self::RangeNotSatisfiable(_) => StatusCode::RANGE_NOT_SATISFIABLE,
            Self::InternalError | Self::DatabaseError(_) | 
            Self::CryptoError(_) | Self::IoError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let error_type = match self {
            Self::Unauthorized(_) => "UNAUTHORIZED",
            Self::InvalidCredentials => "INVALID_CREDENTIALS",
            Self::TokenExpired => "TOKEN_EXPIRED",
            Self::InvalidToken => "INVALID_TOKEN",
            Self::Forbidden(_) => "FORBIDDEN",
            Self::BadRequest(_) => "BAD_REQUEST",
            Self::ValidationError(_) => "VALIDATION_ERROR",
            Self::NotFound(_) => "NOT_FOUND",
            Self::Conflict(_) => "CONFLICT",
            Self::PreconditionFailed(_) => "PRECONDITION_FAILED",
            Self::RangeNotSatisfiable(_) => "RANGE_NOT_SATISFIABLE",
            Self::InternalError => "INTERNAL_ERROR",
            Self::DatabaseError(_) => "DATABASE_ERROR",
            Self::CryptoError(_) => "CRYPTO_ERROR",
            Self::IoError(_) => "IO_ERROR",
        };

        let response = ErrorResponse {
            error: error_type.to_string(),
            message: self.to_string(),
            details: None,
        };

        HttpResponse::build(self.status_code()).json(response)
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        tracing::error!("Database error: {:?}", err);
        Self::DatabaseError(err.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        tracing::error!("JWT error: {:?}", err);
        match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => Self::TokenExpired,
            _ => Self::InvalidToken,
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        tracing::error!("IO error: {:?}", err);
        Self::IoError(err.to_string())
    }
}
