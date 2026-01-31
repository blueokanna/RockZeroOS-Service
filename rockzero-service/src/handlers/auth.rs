use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use rockzero_common::{AppConfig, AppError, TokenResponse};
use rockzero_crypto::{blake3_hash, constant_time_compare};
use rockzero_crypto::{EnhancedPasswordProof, JwtEncoder, PasswordRegistration, ZkpContext};

const HASH_ITERATIONS: u32 = 100_000;
const SALT_LENGTH: usize = 32;
#[allow(dead_code)]
const NONCE_EXPIRY_SECONDS: i64 = 300;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub role: String,
    #[serde(default)]
    pub token_type: String,
    pub exp: i64,
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

pub struct JwtHandler {
    access_encoder: JwtEncoder,
    refresh_encoder: JwtEncoder,
    access_expiration_hours: i64,
    refresh_expiration_days: i64,
    revoked_tokens: Arc<RwLock<HashSet<String>>>,
}

impl JwtHandler {
    pub fn new(config: &AppConfig) -> Self {
        let access_secret = format!("{}-access", config.jwt_secret);
        let refresh_secret = format!("{}-refresh", config.jwt_secret);

        Self {
            access_encoder: JwtEncoder::from_password(&access_secret),
            refresh_encoder: JwtEncoder::from_password(&refresh_secret),
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
        let access_jti = generate_token_id()?;
        let refresh_jti = generate_token_id()?;

        let access_claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            token_type: "access".to_string(),
            exp: Utc::now().timestamp() + self.access_expiration_hours * 3600,
            iat: Utc::now().timestamp(),
            jti: Some(access_jti),
        };

        let access_token = self.access_encoder.encode(&access_claims)?;

        let refresh_claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            token_type: "refresh".to_string(),
            exp: Utc::now().timestamp() + self.refresh_expiration_days * 86400,
            iat: Utc::now().timestamp(),
            jti: Some(refresh_jti),
        };

        let refresh_token = self.refresh_encoder.encode(&refresh_claims)?;

        Ok(TokenResponse {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.access_expiration_hours * 3600,
        })
    }

    pub async fn verify_access_token(&self, token: &str) -> Result<Claims, AppError> {
        let claims: Claims = self.access_encoder.decode(token)?;

        if claims.token_type != "access" {
            return Err(AppError::InvalidToken);
        }

        if claims.exp < Utc::now().timestamp() {
            return Err(AppError::Unauthorized("Token expired".to_string()));
        }

        if let Some(jti) = &claims.jti {
            let revoked = self.revoked_tokens.read().await;
            if revoked.contains(jti) {
                return Err(AppError::InvalidToken);
            }
        }

        Ok(claims)
    }

    pub async fn verify_refresh_token(&self, token: &str) -> Result<Claims, AppError> {
        let claims: Claims = self.refresh_encoder.decode(token)?;

        if claims.token_type != "refresh" {
            return Err(AppError::InvalidToken);
        }

        if claims.exp < Utc::now().timestamp() {
            return Err(AppError::Unauthorized("Token expired".to_string()));
        }

        if let Some(jti) = &claims.jti {
            let revoked = self.revoked_tokens.read().await;
            if revoked.contains(jti) {
                return Err(AppError::InvalidToken);
            }
        }

        Ok(claims)
    }

    #[allow(dead_code)]
    pub async fn revoke_token(&self, jti: &str) {
        let mut revoked = self.revoked_tokens.write().await;
        revoked.insert(jti.to_string());
    }

    pub fn extract_token_from_header(auth_header: &str) -> Result<&str, AppError> {
        auth_header.strip_prefix("Bearer ").ok_or_else(|| {
            AppError::Unauthorized("Invalid authorization header format".to_string())
        })
    }

    #[allow(dead_code)]
    pub fn get_access_public_key(&self) -> String {
        self.access_encoder.get_public_key_base64()
    }
}

pub struct SecurePasswordHandler {
    pub zkp_context: ZkpContext,
    #[allow(dead_code)]
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
        let registration = self.zkp_context.register_password(password)?;

        Ok(PasswordCredentials {
            password_hash,
            zkp_registration: registration,
        })
    }

    pub fn verify_password(&self, password: &str, stored_hash: &str) -> Result<bool, AppError> {
        verify_password(password, stored_hash)
    }

    #[allow(dead_code)]
    pub async fn verify_enhanced_proof(
        &self,
        proof: &EnhancedPasswordProof,
        registration: &PasswordRegistration,
        context: &str,
    ) -> Result<bool, AppError> {
        {
            let nonces = self.used_nonces.read().await;
            if nonces.iter().any(|(n, _)| n == &proof.nonce) {
                return Err(AppError::BadRequest("Proof already used".to_string()));
            }
        }

        let result = self.zkp_context.verify_enhanced_proof(
            proof,
            registration,
            context,
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

    #[allow(dead_code)]
    pub fn generate_enhanced_proof(
        &self,
        password: &str,
        registration: &PasswordRegistration,
        context: &str,
    ) -> Result<EnhancedPasswordProof, AppError> {
        self.zkp_context
            .generate_enhanced_proof(password, registration, context)
    }

    #[allow(dead_code)]
    pub fn derive_encryption_key(&self, password: &str, context: &str) -> [u8; 32] {
        let password_bytes = password.as_bytes();
        let context_bytes = context.as_bytes();
        blake3_hash(&[password_bytes, context_bytes])
    }

    #[allow(dead_code)]
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
    pub zkp_registration: PasswordRegistration,
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

pub fn compute_sae_secret(password: &str) -> String {
    // Use Blake3 for SAE secret computation
    let hash = blake3::hash(password.as_bytes());
    hex::encode(hash.as_bytes())
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

        let proof = handler
            .generate_enhanced_proof(password, &credentials.zkp_registration, "login")
            .unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt
            .block_on(handler.verify_enhanced_proof(&proof, &credentials.zkp_registration, "login"))
            .unwrap();
        assert!(result);
    }

    #[test]
    fn test_wrong_password_zkp() {
        let handler = SecurePasswordHandler::new();
        let password = "SecurePassword123!@#";
        let wrong_password = "WrongPassword456!@#";

        let credentials = handler.create_password_credentials(password).unwrap();

        let result =
            handler.generate_enhanced_proof(wrong_password, &credentials.zkp_registration, "login");
        assert!(result.is_err());
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

    #[test]
    fn test_jwt_eddsa() {
        use base64::Engine;
        
        let config = AppConfig {
            jwt_secret: "test-secret".to_string(),
            jwt_expiration_hours: 24,
            refresh_token_expiration_days: 7,
            ..Default::default()
        };

        let handler = JwtHandler::new(&config);
        let tokens = handler
            .generate_tokens("user123", "test@example.com", "user")
            .unwrap();

        assert!(!tokens.access_token.is_empty());
        assert!(!tokens.refresh_token.is_empty());

        let parts: Vec<&str> = tokens.access_token.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header_json =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "JWT");
    }
}

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

pub async fn register(
    pool: web::Data<SqlitePool>,
    body: web::Json<RegisterRequest>,
) -> Result<impl Responder, AppError> {
    if body.username.len() > 50 || body.email.len() > 100 || body.password.len() > 128 {
        return Err(AppError::BadRequest("Input fields too long".to_string()));
    }

    let username = body.username.trim();
    let email = body.email.trim();

    if username.is_empty() || email.is_empty() || body.password.is_empty() {
        return Err(AppError::BadRequest("All fields are required".to_string()));
    }

    if !username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err(AppError::BadRequest(
            "Username can only contain letters, numbers, underscores and hyphens".to_string(),
        ));
    }

    if !email.contains('@') || !email.contains('.') || email.len() < 5 {
        return Err(AppError::BadRequest("Invalid email format".to_string()));
    }

    if body.password.len() < 8 {
        return Err(AppError::BadRequest(
            "Password must be at least 8 characters".to_string(),
        ));
    }

    let has_uppercase = body.password.chars().any(|c| c.is_uppercase());
    let has_lowercase = body.password.chars().any(|c| c.is_lowercase());
    let has_digit = body.password.chars().any(|c| c.is_numeric());

    if !has_uppercase || !has_lowercase || !has_digit {
        return Err(AppError::BadRequest(
            "Password must contain uppercase, lowercase and numbers".to_string(),
        ));
    }

    let user_count = crate::db::count_users(&pool).await?;
    let is_first_user = user_count == 0;
    let role = if is_first_user { "admin" } else { "user" };

    if !is_first_user {
        match &body.invite_code {
            None => {
                return Err(AppError::BadRequest(
                    "Invite code is required for registration".to_string(),
                ));
            }
            Some(code) => {
                let code = code.trim();
                if code.is_empty() {
                    return Err(AppError::BadRequest(
                        "Invite code is required for registration".to_string(),
                    ));
                }

                let is_valid = crate::db::validate_invite_code(&pool, code).await?;
                if !is_valid {
                    return Err(AppError::BadRequest(
                        "Invalid or expired invite code".to_string(),
                    ));
                }

                crate::db::use_invite_code(&pool, code).await?;
            }
        }
    }

    if (crate::db::find_user_by_username(&pool, username).await?).is_some() {
        return Err(AppError::BadRequest(
            "Username or email already exists".to_string(),
        ));
    }

    if (crate::db::find_user_by_email(&pool, email).await?).is_some() {
        return Err(AppError::BadRequest(
            "Username or email already exists".to_string(),
        ));
    }

    let password_handler = SecurePasswordHandler::new();
    let credentials = password_handler.create_password_credentials(&body.password)?;

    let sae_secret = compute_sae_secret(&body.password);

    let zkp_registration_json =
        serde_json::to_string(&credentials.zkp_registration).map_err(|e| {
            AppError::InternalServerError(format!("Failed to serialize ZKP registration: {}", e))
        })?;

    let user = crate::db::create_user(
        &pool,
        username,
        email,
        &credentials.password_hash,
        Some(&sae_secret),
        Some(&zkp_registration_json),
        role,
    )
    .await?;

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

pub async fn login(
    pool: web::Data<SqlitePool>,
    body: web::Json<LoginRequest>,
) -> Result<impl Responder, AppError> {
    if body.username.len() > 100 || body.password.len() > 128 {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    let username = body.username.trim();

    let user = if username.contains('@') {
        crate::db::find_user_by_email(&pool, username).await?
    } else {
        crate::db::find_user_by_username(&pool, username).await?
    };

    let user = user.ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;

    let password_handler = SecurePasswordHandler::new();
    if !password_handler.verify_password(&body.password, &user.password_hash)? {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    // Update sae_secret if not set or different from current password hash
    let sae_secret = compute_sae_secret(&body.password);
    if user.sae_secret.as_ref() != Some(&sae_secret) {
        if let Err(e) = crate::db::update_user_sae_secret(&pool, &user.id, &sae_secret).await {
            warn!("Failed to update sae_secret for user {}: {}", user.id, e);
        } else {
            info!("Updated sae_secret for user {}", user.id);
        }
    }

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

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

pub async fn refresh_token(
    pool: web::Data<SqlitePool>,
    body: web::Json<RefreshTokenRequest>,
) -> Result<impl Responder, AppError> {
    let jwt_config = AppConfig::from_env();
    let jwt_handler = JwtHandler::new(&jwt_config);

    let claims = jwt_handler
        .verify_refresh_token(&body.refresh_token)
        .await?;

    let user = crate::db::find_user_by_id(&pool, &claims.sub)
        .await?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;

    let tokens = jwt_handler.generate_tokens(&user.id, &user.email, &user.role)?;

    Ok(HttpResponse::Ok().json(tokens))
}

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
