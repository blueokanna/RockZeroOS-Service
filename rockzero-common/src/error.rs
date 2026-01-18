use thiserror::Error;

#[derive(Error, Debug)]
pub enum CommonError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Internal error: {0}")]
    Internal(String),
}

#[derive(Error, Debug, Clone)]
pub enum AppError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Precondition failed: {0}")]
    PreconditionFailed(String),

    #[error("Cryptography error: {0}")]
    CryptoError(String),

    #[error("Invalid token")]
    InvalidToken,

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("IO error: {0}")]
    IoError(String),

    #[error("Internal server error: {0}")]
    InternalServerError(String),

    #[error("Internal error")]
    InternalError,
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::IoError(err.to_string())
    }
}

#[cfg(feature = "actix")]
impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(_err: jsonwebtoken::errors::Error) -> Self {
        AppError::InvalidToken
    }
}

#[cfg(feature = "actix")]
impl From<actix_multipart::MultipartError> for AppError {
    fn from(err: actix_multipart::MultipartError) -> Self {
        AppError::BadRequest(err.to_string())
    }
}

#[cfg(feature = "actix")]
impl actix_web::ResponseError for AppError {
    fn error_response(&self) -> actix_web::HttpResponse {
        use actix_web::HttpResponse;
        match self {
            AppError::NotFound(msg) => HttpResponse::NotFound().json(serde_json::json!({
                "error": "Not Found",
                "message": msg
            })),
            AppError::BadRequest(msg) => HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Bad Request",
                "message": msg
            })),
            AppError::Unauthorized(msg) => HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized",
                "message": msg
            })),
            AppError::Forbidden(msg) => HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Forbidden",
                "message": msg
            })),
            AppError::Conflict(msg) => HttpResponse::Conflict().json(serde_json::json!({
                "error": "Conflict",
                "message": msg
            })),
            AppError::PreconditionFailed(msg) => HttpResponse::PreconditionFailed().json(serde_json::json!({
                "error": "Precondition Failed",
                "message": msg
            })),
            AppError::CryptoError(msg) | AppError::DatabaseError(msg) | AppError::IoError(msg) | AppError::InternalServerError(msg) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Internal Server Error",
                    "message": msg
                }))
            }
            AppError::InvalidToken => HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized",
                "message": "Invalid or expired token"
            })),
            AppError::ValidationError(msg) => HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Validation Error",
                "message": msg
            })),
            AppError::InternalError => HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal Server Error",
                "message": "An internal error occurred"
            })),
        }
    }
}

pub type Result<T> = std::result::Result<T, CommonError>;
