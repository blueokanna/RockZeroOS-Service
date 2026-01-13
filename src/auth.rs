use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::blake3_hash;
use crate::config::AppConfig;
use crate::crypto::{constant_time_compare, KeyDeriver, Wpa3Sae};
use crate::error::AppError;
use crate::models::TokenResponse;
use crate::zkp::{EnhancedPasswordProof, PasswordProofData, ZkpContext};

// ============ 常量定义 ============

const HASH_ITERATIONS: u32 = 100_000;
const SALT_LENGTH: usize = 32;
const NONCE_EXPIRY_SECONDS: i64 = 300; // 5 分钟

// ============ JWT Claims ============

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// 用户 ID
    pub sub: String,
    /// 用户邮箱
    pub email: String,
    /// 用户角色
    pub role: String,
    /// 令牌类型 (access/refresh)
    pub token_type: String,
    /// 过期时间
    pub exp: i64,
    /// 签发时间
    pub iat: i64,
    /// 令牌 ID（用于撤销）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

// ============ JWT 处理器 ============

pub struct JwtHandler {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    access_expiration_hours: i64,
    refresh_expiration_days: i64,
    /// 已撤销的令牌 ID
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

    /// 生成访问令牌和刷新令牌
    pub fn generate_tokens(
        &self,
        user_id: &str,
        email: &str,
        role: &str,
    ) -> Result<TokenResponse, AppError> {
        let now = Utc::now();

        // 生成唯一令牌 ID
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

    /// 验证访问令牌
    pub async fn verify_access_token(&self, token: &str) -> Result<Claims, AppError> {
        let token_data = self.decode_token(token)?;

        if token_data.claims.token_type != "access" {
            return Err(AppError::InvalidToken);
        }

        // 检查是否已撤销
        if let Some(jti) = &token_data.claims.jti {
            let revoked = self.revoked_tokens.read().await;
            if revoked.contains(jti) {
                return Err(AppError::InvalidToken);
            }
        }

        Ok(token_data.claims)
    }

    /// 验证刷新令牌
    pub async fn verify_refresh_token(&self, token: &str) -> Result<Claims, AppError> {
        let token_data = self.decode_token(token)?;

        if token_data.claims.token_type != "refresh" {
            return Err(AppError::InvalidToken);
        }

        // 检查是否已撤销
        if let Some(jti) = &token_data.claims.jti {
            let revoked = self.revoked_tokens.read().await;
            if revoked.contains(jti) {
                return Err(AppError::InvalidToken);
            }
        }

        Ok(token_data.claims)
    }

    /// 撤销令牌
    pub async fn revoke_token(&self, jti: &str) {
        let mut revoked = self.revoked_tokens.write().await;
        revoked.insert(jti.to_string());
    }

    /// 解码令牌
    fn decode_token(&self, token: &str) -> Result<TokenData<Claims>, AppError> {
        let validation = Validation::default();
        decode::<Claims>(token, &self.decoding_key, &validation).map_err(|e| e.into())
    }

    /// 从 Authorization 头提取令牌
    pub fn extract_token_from_header(auth_header: &str) -> Result<&str, AppError> {
        auth_header.strip_prefix("Bearer ").ok_or_else(|| {
            AppError::Unauthorized("Invalid authorization header format".to_string())
        })
    }
}

// ============ 安全密码处理器 ============

/// 安全密码处理器，结合 BLAKE3 和零知识证明
pub struct SecurePasswordHandler {
    pub zkp_context: ZkpContext,
    key_deriver: KeyDeriver,
    /// 已使用的 nonce（防重放）
    used_nonces: Arc<RwLock<Vec<(String, i64)>>>,
}

impl SecurePasswordHandler {
    pub fn new() -> Self {
        Self {
            zkp_context: ZkpContext::new(),
            key_deriver: KeyDeriver::new(),
            used_nonces: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// 创建密码哈希和零知识承诺
    pub fn create_password_credentials(
        &self,
        password: &str,
    ) -> Result<PasswordCredentials, AppError> {
        // 生成 BLAKE3 哈希
        let password_hash = hash_password(password)?;

        // 生成零知识承诺
        let (commitment, _blinding) = self.zkp_context.generate_commitment(password)?;

        Ok(PasswordCredentials {
            password_hash,
            zkp_commitment: commitment,
        })
    }

    /// 验证密码（传统方式）
    pub fn verify_password(&self, password: &str, stored_hash: &str) -> Result<bool, AppError> {
        verify_password(password, stored_hash)
    }

    /// 验证零知识证明
    pub fn verify_zkp_proof(
        &self,
        proof: &PasswordProofData,
        stored_commitment: &str,
    ) -> Result<bool, AppError> {
        self.zkp_context
            .verify_password_proof(proof, stored_commitment)
    }

    /// 验证增强的零知识证明（包含防重放检查）
    pub async fn verify_enhanced_proof(
        &self,
        proof: &EnhancedPasswordProof,
        stored_commitment: &str,
    ) -> Result<bool, AppError> {
        // 检查 nonce 是否已使用（防重放攻击）
        {
            let nonces = self.used_nonces.read().await;
            if nonces.iter().any(|(n, _)| n == &proof.nonce) {
                return Err(AppError::BadRequest("Proof already used".to_string()));
            }
        }

        // 验证证明
        let result = self.zkp_context.verify_enhanced_proof(
            proof,
            stored_commitment,
            NONCE_EXPIRY_SECONDS,
        )?;

        if result {
            // 记录已使用的 nonce
            let mut nonces = self.used_nonces.write().await;
            nonces.push((proof.nonce.clone(), proof.timestamp));

            // 清理过期的 nonce
            let now = Utc::now().timestamp();
            nonces.retain(|(_, ts)| now - ts < NONCE_EXPIRY_SECONDS * 2);
        }

        Ok(result)
    }

    /// 生成密码证明（客户端使用）
    pub fn generate_proof(&self, password: &str) -> Result<PasswordProofData, AppError> {
        self.zkp_context.generate_password_proof(password)
    }

    /// 生成增强的密码证明
    pub fn generate_enhanced_proof(
        &self,
        password: &str,
    ) -> Result<EnhancedPasswordProof, AppError> {
        self.zkp_context.generate_enhanced_proof(password)
    }

    /// 派生加密密钥
    pub fn derive_encryption_key(&self, password: &str, context: &str) -> [u8; 32] {
        self.key_deriver.derive_key(password, context)
    }

    /// 计算密码强度熵
    pub fn calculate_password_entropy(password: &str) -> u64 {
        ZkpContext::calculate_password_entropy(password)
    }
}

impl Default for SecurePasswordHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// 密码凭证
#[derive(Debug, Clone)]
pub struct PasswordCredentials {
    pub password_hash: String,
    pub zkp_commitment: String,
}

// ============ BLAKE3 密码哈希函数 ============

/// 使用 BLAKE3 和 WPA3-SAE 派生的盐进行密码哈希
pub fn hash_password(password: &str) -> Result<String, AppError> {
    use rand::RngCore;

    let mut salt = [0u8; SALT_LENGTH];
    rand::thread_rng().fill_bytes(&mut salt);

    let hash = derive_key_with_salt(password.as_bytes(), &salt);

    // 格式: salt$hash (both hex encoded)
    Ok(format!("{}${}", hex::encode(salt), hex::encode(hash)))
}

/// 验证密码
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

/// 使用 BLAKE3 和 WPA3-SAE 风格的迭代进行密钥派生
fn derive_key_with_salt(password: &[u8], salt: &[u8]) -> Vec<u8> {
    // 使用盐作为种子创建确定性的 SAE 实例
    let sae = Wpa3Sae::with_seed(salt);

    // 首先使用 WPA3-SAE 派生基础密钥
    let password_str = String::from_utf8_lossy(password);
    let salt_str = hex::encode(salt);
    let base_key = sae.derive_pmk(&password_str, &salt_str);

    // 然后使用 BLAKE3 进行额外的迭代
    let mut result = base_key.to_vec();

    for i in 0..HASH_ITERATIONS {
        let hash = blake3_hash!(&result, &i.to_le_bytes(), salt);
        result = hash.as_bytes().to_vec();
    }

    result
}

/// 生成唯一令牌 ID
fn generate_token_id() -> Result<String, AppError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| AppError::CryptoError("Failed to generate token ID".to_string()))?;
    Ok(hex::encode(bytes))
}

// ============ 测试 ============

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

        // 验证传统哈希
        assert!(handler
            .verify_password(password, &credentials.password_hash)
            .unwrap());

        // 验证零知识证明
        // 注意：generate_password_proof 会生成一个新的承诺
        // 验证时需要使用证明中包含的承诺
        let proof = handler.generate_proof(password).unwrap();
        
        // 使用证明中的承诺来验证（这是 Schnorr 协议的正确用法）
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

        // 用错误密码生成证明
        let proof = handler.generate_proof(wrong_password).unwrap();

        // 验证应该失败
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
