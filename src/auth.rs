use blake3;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};

use crate::config::AppConfig;
use crate::error::AppError;
use crate::models::TokenResponse;

const HASH_ITERATIONS: u32 = 100_000;
const SALT_LENGTH: usize = 32;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub role: String,
    pub token_type: String,
    pub exp: i64,
    pub iat: i64,
}

pub struct JwtHandler {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    access_expiration_hours: i64,
    refresh_expiration_days: i64,
}

impl JwtHandler {
    pub fn new(config: &AppConfig) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(config.jwt_secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(config.jwt_secret.as_bytes()),
            access_expiration_hours: config.jwt_expiration_hours,
            refresh_expiration_days: config.refresh_token_expiration_days,
        }
    }

    pub fn generate_tokens(
        &self,
        user_id: &str,
        email: &str,
        role: &str,
    ) -> Result<TokenResponse, AppError> {
        let now = Utc::now();

        let access_claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            token_type: "access".to_string(),
            exp: (now + Duration::hours(self.access_expiration_hours)).timestamp(),
            iat: now.timestamp(),
        };

        let access_token = encode(&Header::default(), &access_claims, &self.encoding_key)?;

        let refresh_claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            token_type: "refresh".to_string(),
            exp: (now + Duration::days(self.refresh_expiration_days)).timestamp(),
            iat: now.timestamp(),
        };

        let refresh_token = encode(&Header::default(), &refresh_claims, &self.encoding_key)?;

        Ok(TokenResponse {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.access_expiration_hours * 3600,
        })
    }

    pub fn verify_access_token(&self, token: &str) -> Result<Claims, AppError> {
        let token_data = self.decode_token(token)?;
        
        if token_data.claims.token_type != "access" {
            return Err(AppError::InvalidToken);
        }
        
        Ok(token_data.claims)
    }

    pub fn verify_refresh_token(&self, token: &str) -> Result<Claims, AppError> {
        let token_data = self.decode_token(token)?;
        
        if token_data.claims.token_type != "refresh" {
            return Err(AppError::InvalidToken);
        }
        
        Ok(token_data.claims)
    }

    fn decode_token(&self, token: &str) -> Result<TokenData<Claims>, AppError> {
        let validation = Validation::default();
        decode::<Claims>(token, &self.decoding_key, &validation).map_err(|e| e.into())
    }

    pub fn extract_token_from_header(auth_header: &str) -> Result<&str, AppError> {
        auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("Invalid authorization header format".to_string()))
    }
}

/// Hash password with salt using BLAKE3 key derivation
pub fn hash_password(password: &str) -> Result<String, AppError> {
    use rand::RngCore;
    
    let mut salt = [0u8; SALT_LENGTH];
    rand::thread_rng().fill_bytes(&mut salt);
    
    let hash = derive_key_with_salt(password.as_bytes(), &salt);
    
    // Format: salt$hash (both hex encoded)
    Ok(format!("{}${}", hex::encode(salt), hex::encode(hash)))
}

/// Verify password against stored hash
pub fn verify_password(password: &str, stored: &str) -> Result<bool, AppError> {
    let parts: Vec<&str> = stored.split('$').collect();
    if parts.len() != 2 {
        return Err(AppError::CryptoError("Invalid hash format".to_string()));
    }
    
    let salt = hex::decode(parts[0])
        .map_err(|_| AppError::CryptoError("Invalid salt".to_string()))?;
    let stored_hash = hex::decode(parts[1])
        .map_err(|_| AppError::CryptoError("Invalid hash".to_string()))?;
    
    let computed_hash = derive_key_with_salt(password.as_bytes(), &salt);
    
    Ok(constant_time_compare(&computed_hash, &stored_hash))
}

/// Derive key using BLAKE3 with iterations for added security
fn derive_key_with_salt(password: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut result = [password, salt].concat();
    
    for _ in 0..HASH_ITERATIONS {
        let hash = blake3::hash(&result);
        result = hash.as_bytes().to_vec();
    }
    
    result
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
