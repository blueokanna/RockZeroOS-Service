#![allow(dead_code)]

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

use rockzero_common::{AppConfig, AppError, TokenResponse};
use rockzero_crypto::{blake3_hash, constant_time_compare};
use rockzero_crypto::{EnhancedPasswordProof, PasswordProofData, ZkpContext};

const HASH_ITERATIONS: u32 = 100_000;
const SALT_LENGTH: usize = 32;
const NONCE_EXPIRY_SECONDS: i64 = 300;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub role: String,
    pub token_type: String,
    pub exp: i64,
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

pub struct JwtHandler {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    access_expiration_hours: i64,
    refresh_expiration_days: i64,
    revoked_tokens: Arc<RwLock<HashSet<String>>>,
}

impl JwtHandler {
    pub fn new(config: &AppConfig) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(config.jwt_secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(config.jwt_secret.as_bytes()),
            access_expiration_hours: config.jwt_expiration_hours,
            refresh_expiration_days: config.refresh_token_expiration_days,
            revoked_tokens: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub fn generate_tokens(
        &self,
        user_id: &str,
        email: &str,
        role: &str,
    ) -> Result<TokenResponse, AppError> {
        let now = Utc::now();

        let access_jti = generate_token_id()?;
        let refresh_jti = generate_token_id()?;

        let access_claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            token_type: "access".to_string(),
            exp: (now + Duration::hours(self.access_expiration_hours)).timestamp(),
            iat: now.timestamp(),
            jti: Some(access_jti),
        };

        let access_token = encode(&Header::default(), &access_claims, &self.encoding_key)?;

        let refresh_claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            token_type: "refresh".to_string(),
            exp: (now + Duration::days(self.refresh_expiration_days)).timestamp(),
            iat: now.timestamp(),
            jti: Some(refresh_jti),
        };

        let refresh_token = encode(&Header::default(), &refresh_claims, &self.encoding_key)?;

        Ok(TokenResponse {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.access_expiration_hours * 3600,
        })
    }

    pub async fn verify_access_token(&self, token: &str) -> Result<Claims, AppError> {
        let token_data = self.decode_token(token)?;

        if token_data.claims.token_type != "access" {
            return Err(AppError::InvalidToken);
        }

        if let Some(jti) = &token_data.claims.jti {
            let revoked = self.revoked_tokens.read().await;
            if revoked.contains(jti) {
                return Err(AppError::InvalidToken);
            }
        }

        Ok(token_data.claims)
    }

    pub async fn verify_refresh_token(&self, token: &str) -> Result<Claims, AppError> {
        let token_data = self.decode_token(token)?;

        if token_data.claims.token_type != "refresh" {
            return Err(AppError::InvalidToken);
        }

        if let Some(jti) = &token_data.claims.jti {
            let revoked = self.revoked_tokens.read().await;
            if revoked.contains(jti) {
                return Err(AppError::InvalidToken);
            }
        }

        Ok(token_data.claims)
    }

    pub async fn revoke_token(&self, jti: &str) {
        let mut revoked = self.revoked_tokens.write().await;
        revoked.insert(jti.to_string());
    }

    fn decode_token(&self, token: &str) -> Result<TokenData<Claims>, AppError> {
        let validation = Validation::default();
        decode::<Claims>(token, &self.decoding_key, &validation).map_err(|e| e.into())
    }

    pub fn extract_token_from_header(auth_header: &str) -> Result<&str, AppError> {
        auth_header.strip_prefix("Bearer ").ok_or_else(|| {
            AppError::Unauthorized("Invalid authorization header format".to_string())
        })
    }
}

pub struct SecurePasswordHandler {
    pub zkp_context: ZkpContext,
    used_nonces: Arc<RwLock<Vec<(String, i64)>>>,
}

impl SecurePasswordHandler {
    pub fn new() -> Self {
        Self {
            zkp_context: ZkpContext::new(),
            used_nonces: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn create_password_credentials(
        &self,
        password: &str,
    ) -> Result<PasswordCredentials, AppError> {
        let password_hash = hash_password(password)?;
        let (commitment, _blinding) = self.zkp_context.generate_commitment(password)?;

        Ok(PasswordCredentials {
            password_hash,
            zkp_commitment: commitment,
        })
    }

    pub fn verify_password(&self, password: &str, stored_hash: &str) -> Result<bool, AppError> {
        verify_password(password, stored_hash)
    }

    pub fn verify_zkp_proof(
        &self,
        proof: &PasswordProofData,
        stored_commitment: &str,
    ) -> Result<bool, AppError> {
        self.zkp_context
            .verify_password_proof(proof, stored_commitment)
    }

    pub async fn verify_enhanced_proof(
        &self,
        proof: &EnhancedPasswordProof,
        stored_commitment: &str,
    ) -> Result<bool, AppError> {
        {
            let nonces = self.used_nonces.read().await;
            if nonces.iter().any(|(n, _)| n == &proof.nonce) {
                return Err(AppError::BadRequest("Proof already used".to_string()));
            }
        }

        let result = self.zkp_context.verify_enhanced_proof(
            proof,
            stored_commitment,
            NONCE_EXPIRY_SECONDS,
        )?;

        if result {
            let mut nonces = self.used_nonces.write().await;
            nonces.push((proof.nonce.clone(), proof.timestamp));

            let now = Utc::now().timestamp();
            nonces.retain(|(_, ts)| now - ts < NONCE_EXPIRY_SECONDS * 2);
        }

        Ok(result)
    }

    pub fn generate_proof(&self, password: &str) -> Result<PasswordProofData, AppError> {
        self.zkp_context.generate_password_proof(password)
    }

    pub fn generate_enhanced_proof(
        &self,
        password: &str,
    ) -> Result<EnhancedPasswordProof, AppError> {
        self.zkp_context.generate_enhanced_proof(password)
    }

    pub fn derive_encryption_key(&self, password: &str, context: &str) -> [u8; 32] {
        let password_bytes = password.as_bytes();
        let context_bytes = context.as_bytes();
        
        blake3_hash(&[password_bytes, context_bytes])
    }

    pub fn calculate_password_entropy(password: &str) -> u64 {
        ZkpContext::calculate_password_entropy(password)
    }
}

impl Default for SecurePasswordHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct PasswordCredentials {
    pub password_hash: String,
    pub zkp_commitment: String,
}

pub fn hash_password(password: &str) -> Result<String, AppError> {
    use rand::RngCore;

    let mut salt = [0u8; SALT_LENGTH];
    rand::thread_rng().fill_bytes(&mut salt);

    let hash = derive_key_with_salt(password.as_bytes(), &salt);

    Ok(format!("{}${}", hex::encode(salt), hex::encode(hash)))
}

pub fn verify_password(password: &str, stored: &str) -> Result<bool, AppError> {
    let parts: Vec<&str> = stored.split('$').collect();
    if parts.len() != 2 {
        return Err(AppError::CryptoError("Invalid hash format".to_string()));
    }

    let salt =
        hex::decode(parts[0]).map_err(|_| AppError::CryptoError("Invalid salt".to_string()))?;
    let stored_hash =
        hex::decode(parts[1]).map_err(|_| AppError::CryptoError("Invalid hash".to_string()))?;

    let computed_hash = derive_key_with_salt(password.as_bytes(), &salt);

    Ok(constant_time_compare(&computed_hash, &stored_hash))
}

fn derive_key_with_salt(password: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut result = blake3_hash(&[password, salt]).to_vec();

    for i in 0..HASH_ITERATIONS {
        let i_bytes = i.to_le_bytes();
        result = blake3_hash(&[&result, &i_bytes, salt]).to_vec();
    }

    result
}

fn generate_token_id() -> Result<String, AppError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| AppError::CryptoError("Failed to generate token ID".to_string()))?;
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash_verify() {
        let password = "SecurePassword123!@#";
        let hash = hash_password(password).unwrap();

        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("WrongPassword", &hash).unwrap());
    }

    #[test]
    fn test_secure_password_handler() {
        let handler = SecurePasswordHandler::new();
        let password = "SecurePassword123!@#";

        let credentials = handler.create_password_credentials(password).unwrap();

        assert!(handler
            .verify_password(password, &credentials.password_hash)
            .unwrap());

        let proof = handler.generate_proof(password).unwrap();
        
        assert!(handler
            .verify_zkp_proof(&proof, &proof.commitment)
            .unwrap());
    }

    #[test]
    fn test_wrong_password_zkp() {
        let handler = SecurePasswordHandler::new();
        let password = "SecurePassword123!@#";
        let wrong_password = "WrongPassword456!@#";

        let credentials = handler.create_password_credentials(password).unwrap();

        let proof = handler.generate_proof(wrong_password).unwrap();

        assert!(!handler
            .verify_zkp_proof(&proof, &credentials.zkp_commitment)
            .unwrap());
    }

    #[test]
    fn test_key_derivation() {
        let handler = SecurePasswordHandler::new();
        let password = "test-password";

        let key1 = handler.derive_encryption_key(password, "context1");
        let key2 = handler.derive_encryption_key(password, "context2");
        let key3 = handler.derive_encryption_key(password, "context1");

        assert_eq!(key1, key3);
        assert_ne!(key1, key2);
    }
}

// HTTP Request/Response structures
use actix_web::{web, HttpResponse, Responder};
use sqlx::SqlitePool;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub invite_code: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens: Option<TokenResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserInfo>,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub email: String,
    pub role: String,
}

/// Register a new user
pub async fn register(
    pool: web::Data<SqlitePool>,
    body: web::Json<RegisterRequest>,
) -> Result<impl Responder, AppError> {
    // Validate input
    if body.username.is_empty() || body.email.is_empty() || body.password.is_empty() {
        return Err(AppError::BadRequest("All fields are required".to_string()));
    }

    if body.password.len() < 8 {
        return Err(AppError::BadRequest(
            "Password must be at least 8 characters".to_string(),
        ));
    }

    // Check if username already exists
    if let Some(_) = crate::db::find_user_by_username(&pool, &body.username).await? {
        return Err(AppError::BadRequest("Username already exists".to_string()));
    }

    // Check if email already exists
    if let Some(_) = crate::db::find_user_by_email(&pool, &body.email).await? {
        return Err(AppError::BadRequest("Email already exists".to_string()));
    }

    // Create password credentials
    let password_handler = SecurePasswordHandler::new();
    let credentials = password_handler.create_password_credentials(&body.password)?;

    // Create user
    let user = crate::db::create_user(
        &pool,
        &body.username,
        &body.email,
        &credentials.password_hash,
        &credentials.zkp_commitment,
        "user",
    )
    .await?;

    // Generate JWT tokens
    let jwt_config = AppConfig::from_env();
    let jwt_handler = JwtHandler::new(&jwt_config);
    let tokens = jwt_handler.generate_tokens(&user.id, &user.email, &user.role)?;

    Ok(HttpResponse::Ok().json(AuthResponse {
        success: true,
        message: "Registration successful".to_string(),
        tokens: Some(tokens),
        user: Some(UserInfo {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
        }),
    }))
}

/// Login with username and password
pub async fn login(
    pool: web::Data<SqlitePool>,
    body: web::Json<LoginRequest>,
) -> Result<impl Responder, AppError> {
    // Find user
    let user = crate::db::find_user_by_username(&pool, &body.username)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;

    // Verify password
    let password_handler = SecurePasswordHandler::new();
    if !password_handler.verify_password(&body.password, &user.password_hash)? {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    // Generate JWT tokens
    let jwt_config = AppConfig::from_env();
    let jwt_handler = JwtHandler::new(&jwt_config);
    let tokens = jwt_handler.generate_tokens(&user.id, &user.email, &user.role)?;

    Ok(HttpResponse::Ok().json(AuthResponse {
        success: true,
        message: "Login successful".to_string(),
        tokens: Some(tokens),
        user: Some(UserInfo {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
        }),
    }))
}

/// Get current user info (requires authentication)
pub async fn me(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
) -> Result<impl Responder, AppError> {
    let user = crate::db::find_user_by_id(&pool, &claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    Ok(HttpResponse::Ok().json(UserInfo {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
    }))
}
