use actix_web::{web, HttpResponse, Responder};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use rockzero_common::AppError;
use rockzero_crypto::{EnhancedPasswordProof, PasswordRegistration, ZkpContext};

use crate::handlers::auth::{Claims, JwtHandler, UserInfo};
use rockzero_common::{AppConfig, TokenResponse};

pub struct ZkpAuthManager {
    zkp_context: ZkpContext,
    search_tokens: Arc<RwLock<HashMap<String, SearchToken>>>,
    share_proofs: Arc<RwLock<HashMap<String, ShareProof>>>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SearchToken {
    user_id: String,
    token_hash: [u8; 32],
    created_at: i64,
    expires_at: i64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ShareProof {
    user_id: String,
    file_id: String,
    permission_level: String,
    proof_hash: [u8; 32],
    created_at: i64,
    expires_at: i64,
}

impl ZkpAuthManager {
    pub fn new() -> Self {
        Self {
            zkp_context: ZkpContext::new(),
            search_tokens: Arc::new(RwLock::new(HashMap::new())),
            share_proofs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn verify_password_proof(
        &self,
        proof: &EnhancedPasswordProof,
        registration: &PasswordRegistration,
        context: &str,
    ) -> Result<bool, AppError> {
        self.zkp_context
            .verify_enhanced_proof(proof, registration, context, 300)
    }

    pub async fn generate_search_token(
        &self,
        user_id: &str,
        keyword_hash: [u8; 32],
    ) -> Result<String, AppError> {
        let now = Utc::now().timestamp();
        let token_id = generate_random_id()?;

        let token = SearchToken {
            user_id: user_id.to_string(),
            token_hash: keyword_hash,
            created_at: now,
            expires_at: now + 3600,
        };

        let mut tokens = self.search_tokens.write().await;
        tokens.insert(token_id.clone(), token);
        tokens.retain(|_, t| t.expires_at > now);

        Ok(token_id)
    }

    pub async fn verify_search_token(
        &self,
        token_id: &str,
        user_id: &str,
    ) -> Result<[u8; 32], AppError> {
        let tokens = self.search_tokens.read().await;
        let token = tokens
            .get(token_id)
            .ok_or_else(|| AppError::NotFound("Search token not found".to_string()))?;

        if token.user_id != user_id {
            return Err(AppError::Unauthorized("Token owner mismatch".to_string()));
        }

        let now = Utc::now().timestamp();
        if token.expires_at < now {
            return Err(AppError::Unauthorized("Search token expired".to_string()));
        }

        Ok(token.token_hash)
    }

    pub async fn generate_share_proof(
        &self,
        user_id: &str,
        file_id: &str,
        permission_level: &str,
    ) -> Result<String, AppError> {
        let now = Utc::now().timestamp();
        let proof_id = generate_random_id()?;

        let proof_data = format!("{}:{}:{}:{}", user_id, file_id, permission_level, now);
        let proof_hash = blake3::hash(proof_data.as_bytes());
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(proof_hash.as_bytes());

        let proof = ShareProof {
            user_id: user_id.to_string(),
            file_id: file_id.to_string(),
            permission_level: permission_level.to_string(),
            proof_hash: hash_bytes,
            created_at: now,
            expires_at: now + 86400,
        };

        let mut proofs = self.share_proofs.write().await;
        proofs.insert(proof_id.clone(), proof);
        proofs.retain(|_, p| p.expires_at > now);

        Ok(proof_id)
    }

    pub async fn verify_share_proof(
        &self,
        proof_id: &str,
        file_id: &str,
        required_permission: &str,
    ) -> Result<String, AppError> {
        let proofs = self.share_proofs.read().await;
        let proof = proofs
            .get(proof_id)
            .ok_or_else(|| AppError::NotFound("Share proof not found".to_string()))?;

        if proof.file_id != file_id {
            return Err(AppError::Unauthorized("File ID mismatch".to_string()));
        }

        let now = Utc::now().timestamp();
        if proof.expires_at < now {
            return Err(AppError::Unauthorized("Share proof expired".to_string()));
        }

        let has_permission = match required_permission {
            "read" => ["read", "write", "admin"].contains(&proof.permission_level.as_str()),
            "write" => ["write", "admin"].contains(&proof.permission_level.as_str()),
            "admin" => proof.permission_level == "admin",
            _ => false,
        };

        if !has_permission {
            return Err(AppError::Unauthorized("Insufficient permission".to_string()));
        }

        Ok(proof.user_id.clone())
    }
}

impl Default for ZkpAuthManager {
    fn default() -> Self {
        Self::new()
    }
}

fn generate_random_id() -> Result<String, AppError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| AppError::CryptoError("Failed to generate random ID".to_string()))?;
    Ok(hex::encode(bytes))
}

#[derive(Debug, Deserialize)]
pub struct ZkpLoginRequest {
    pub username: String,
    pub proof: EnhancedPasswordProof,
}

#[derive(Debug, Serialize)]
pub struct ZkpLoginResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens: Option<TokenResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserInfo>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct EncryptedSearchRequest {
    pub keyword_hash: String,
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EncryptedSearchResponse {
    pub success: bool,
    pub token_id: String,
    pub encrypted_results: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ExecuteSearchRequest {
    pub token_id: String,
}

#[derive(Debug, Deserialize)]
pub struct ShareProofRequest {
    pub file_id: String,
    pub permission_level: String,
}

#[derive(Debug, Serialize)]
pub struct ShareProofResponse {
    pub success: bool,
    pub proof_id: String,
    pub expires_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct VerifyShareRequest {
    pub proof_id: String,
    pub file_id: String,
    pub required_permission: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyShareResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized_user_id: Option<String>,
}

pub async fn zkp_login(
    pool: web::Data<SqlitePool>,
    zkp_manager: web::Data<Arc<ZkpAuthManager>>,
    body: web::Json<ZkpLoginRequest>,
) -> Result<impl Responder, AppError> {
    let username = body.username.trim();

    let user = if username.contains('@') {
        crate::db::find_user_by_email(&pool, username).await?
    } else {
        crate::db::find_user_by_username(&pool, username).await?
    };

    let user = user.ok_or_else(|| {
        warn!("ZKP login failed: user not found - {}", username);
        AppError::Unauthorized("Authentication failed".to_string())
    })?;

    let zkp_registration_json = user.zkp_registration.as_ref().ok_or_else(|| {
        warn!("ZKP login failed: user not registered for ZKP - {}", username);
        AppError::Unauthorized("Authentication failed".to_string())
    })?;

    let registration: PasswordRegistration =
        serde_json::from_str(zkp_registration_json).map_err(|e| {
            warn!("ZKP login failed: ZKP registration parse error - {}: {}", username, e);
            AppError::InternalServerError("Authentication configuration error".to_string())
        })?;

    let is_valid = zkp_manager
        .verify_password_proof(&body.proof, &registration, "login")
        .map_err(|e| {
            warn!("ZKP login failed: proof verification error - {}: {}", username, e);
            AppError::Unauthorized("Authentication failed".to_string())
        })?;

    if !is_valid {
        warn!("ZKP login failed: invalid proof - {}", username);
        return Err(AppError::Unauthorized("Authentication failed".to_string()));
    }

    info!("ZKP login successful: {}", username);

    let jwt_config = AppConfig::from_env();
    let jwt_handler = JwtHandler::new(&jwt_config);
    let tokens = jwt_handler.generate_tokens(&user.id, &user.email, &user.role)?;

    Ok(HttpResponse::Ok().json(ZkpLoginResponse {
        success: true,
        message: "ZKP authentication successful".to_string(),
        tokens: Some(tokens),
        user: Some(UserInfo {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
        }),
    }))
}

pub async fn create_search_token(
    zkp_manager: web::Data<Arc<ZkpAuthManager>>,
    claims: web::ReqData<Claims>,
    body: web::Json<EncryptedSearchRequest>,
) -> Result<impl Responder, AppError> {
    let keyword_hash_bytes = hex::decode(&body.keyword_hash)
        .map_err(|_| AppError::BadRequest("Invalid keyword hash format".to_string()))?;

    if keyword_hash_bytes.len() != 32 {
        return Err(AppError::BadRequest("Keyword hash must be 32 bytes".to_string()));
    }

    let mut keyword_hash = [0u8; 32];
    keyword_hash.copy_from_slice(&keyword_hash_bytes);

    let token_id = zkp_manager
        .generate_search_token(&claims.sub, keyword_hash)
        .await?;

    info!("Search token generated: user {} - token {}", claims.sub, token_id);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "token_id": token_id,
        "message": "Search token generated",
        "expires_in": 3600
    })))
}

pub async fn execute_encrypted_search(
    pool: web::Data<SqlitePool>,
    zkp_manager: web::Data<Arc<ZkpAuthManager>>,
    claims: web::ReqData<Claims>,
    body: web::Json<ExecuteSearchRequest>,
) -> Result<impl Responder, AppError> {
    let keyword_hash = zkp_manager
        .verify_search_token(&body.token_id, &claims.sub)
        .await?;

    let matching_files = search_files_by_hash(&pool, &claims.sub, &keyword_hash).await?;

    info!("Encrypted search completed: user {} - found {} files", claims.sub, matching_files.len());

    Ok(HttpResponse::Ok().json(EncryptedSearchResponse {
        success: true,
        token_id: body.token_id.clone(),
        encrypted_results: matching_files,
    }))
}

async fn search_files_by_hash(
    pool: &SqlitePool,
    user_id: &str,
    keyword_hash: &[u8; 32],
) -> Result<Vec<String>, AppError> {
    let files: Vec<(String, String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT id, file_name, tags
        FROM files
        WHERE user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let mut matching_ids = Vec::new();

    for (id, file_name, tags) in files {
        let name_hash = blake3::hash(file_name.to_lowercase().as_bytes());

        if constant_time_compare(name_hash.as_bytes(), keyword_hash) {
            matching_ids.push(id.clone());
            continue;
        }

        if let Some(tags_str) = &tags {
            for tag in tags_str.split(',') {
                let tag_hash = blake3::hash(tag.trim().to_lowercase().as_bytes());
                if constant_time_compare(tag_hash.as_bytes(), keyword_hash) {
                    matching_ids.push(id.clone());
                    break;
                }
            }
        }
    }

    Ok(matching_ids)
}

fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

pub async fn create_share_proof(
    pool: web::Data<SqlitePool>,
    zkp_manager: web::Data<Arc<ZkpAuthManager>>,
    claims: web::ReqData<Claims>,
    body: web::Json<ShareProofRequest>,
) -> Result<impl Responder, AppError> {
    let has_permission =
        verify_user_file_permission(&pool, &claims.sub, &body.file_id, &body.permission_level)
            .await?;

    if !has_permission {
        return Err(AppError::Forbidden("You don't have the specified permission for this file".to_string()));
    }

    let proof_id = zkp_manager
        .generate_share_proof(&claims.sub, &body.file_id, &body.permission_level)
        .await?;

    let expires_at = Utc::now().timestamp() + 86400;

    info!("Share proof generated: user {} - file {} - permission {}", claims.sub, body.file_id, body.permission_level);

    Ok(HttpResponse::Ok().json(ShareProofResponse {
        success: true,
        proof_id,
        expires_at,
    }))
}

async fn verify_user_file_permission(
    pool: &SqlitePool,
    user_id: &str,
    file_id: &str,
    permission_level: &str,
) -> Result<bool, AppError> {
    let file: Option<(String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT user_id, shared_with
        FROM files
        WHERE id = ?
        "#,
    )
    .bind(file_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let (file_user_id, shared_with) = match file {
        Some(f) => f,
        None => return Ok(false),
    };

    if file_user_id == user_id {
        return Ok(true);
    }

    if let Some(shared_with_json) = &shared_with {
        if let Ok(shares) = serde_json::from_str::<Vec<ShareEntry>>(shared_with_json) {
            for share in shares {
                if share.user_id == user_id {
                    return Ok(match permission_level {
                        "read" => {
                            ["read", "write", "admin"].contains(&share.permission.as_str())
                        }
                        "write" => ["write", "admin"].contains(&share.permission.as_str()),
                        "admin" => share.permission == "admin",
                        _ => false,
                    });
                }
            }
        }
    }

    Ok(false)
}

#[derive(Debug, Deserialize)]
struct ShareEntry {
    user_id: String,
    permission: String,
}

pub async fn verify_share_proof(
    zkp_manager: web::Data<Arc<ZkpAuthManager>>,
    body: web::Json<VerifyShareRequest>,
) -> Result<impl Responder, AppError> {
    let result = zkp_manager
        .verify_share_proof(&body.proof_id, &body.file_id, &body.required_permission)
        .await;

    match result {
        Ok(user_id) => {
            info!("Share proof verified: file {} - user {}", body.file_id, user_id);
            Ok(HttpResponse::Ok().json(VerifyShareResponse {
                success: true,
                message: "Permission verified".to_string(),
                authorized_user_id: Some(user_id),
            }))
        }
        Err(e) => {
            warn!("Share proof verification failed: file {} - {}", body.file_id, e);
            Ok(HttpResponse::Ok().json(VerifyShareResponse {
                success: false,
                message: e.to_string(),
                authorized_user_id: None,
            }))
        }
    }
}

pub async fn get_zkp_registration(
    pool: web::Data<SqlitePool>,
    body: web::Json<GetZkpRegistrationRequest>,
) -> Result<impl Responder, AppError> {
    let username = body.username.trim();

    let user = if username.contains('@') {
        crate::db::find_user_by_email(&pool, username).await?
    } else {
        crate::db::find_user_by_username(&pool, username).await?
    };

    let user = user.ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let zkp_registration = user
        .zkp_registration
        .ok_or_else(|| AppError::NotFound("User not registered for ZKP authentication".to_string()))?;

    let registration: PasswordRegistration =
        serde_json::from_str(&zkp_registration).map_err(|_| {
            AppError::InternalServerError("ZKP registration parse error".to_string())
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "commitment": registration.commitment,
        "salt": registration.salt
    })))
}

#[derive(Debug, Deserialize)]
pub struct GetZkpRegistrationRequest {
    pub username: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkp_auth_manager_creation() {
        let manager = ZkpAuthManager::new();
        assert!(manager.search_tokens.try_read().is_ok());
        assert!(manager.share_proofs.try_read().is_ok());
    }

    #[test]
    fn test_constant_time_compare() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];

        assert!(constant_time_compare(&a, &b));
        assert!(!constant_time_compare(&a, &c));
    }
}

use rockzero_crypto::{BulletproofsContext, BulletproofsRangeProof, VideoStreamProof};

#[derive(Debug, Deserialize)]
pub struct CreateRangeProofRequest {
    pub value: u64,
}

#[derive(Debug, Serialize)]
pub struct CreateRangeProofResponse {
    pub success: bool,
    pub proof: Option<BulletproofsRangeProof>,
    pub error: Option<String>,
}

pub async fn create_range_proof(
    _claims: web::ReqData<Claims>,
    body: web::Json<CreateRangeProofRequest>,
) -> Result<impl Responder, AppError> {
    let ctx = BulletproofsContext::new();

    match ctx.create_range_proof(body.value) {
        Ok(proof) => Ok(HttpResponse::Ok().json(CreateRangeProofResponse {
            success: true,
            proof: Some(proof),
            error: None,
        })),
        Err(e) => Ok(HttpResponse::Ok().json(CreateRangeProofResponse {
            success: false,
            proof: None,
            error: Some(e.to_string()),
        })),
    }
}

#[derive(Debug, Deserialize)]
pub struct VerifyRangeProofRequest {
    pub proof: String,
    pub commitment: String,
    pub value_blinding: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyRangeProofResponse {
    pub valid: bool,
    pub error: Option<String>,
}

pub async fn verify_range_proof(
    _claims: web::ReqData<Claims>,
    body: web::Json<VerifyRangeProofRequest>,
) -> Result<impl Responder, AppError> {
    let ctx = BulletproofsContext::new();

    let proof_data = BulletproofsRangeProof {
        proof: body.proof.clone(),
        commitment: body.commitment.clone(),
        value_blinding: body.value_blinding.clone(),
    };

    match ctx.verify_range_proof(&proof_data) {
        Ok(result) => Ok(HttpResponse::Ok().json(VerifyRangeProofResponse {
            valid: result.valid,
            error: result.error_message,
        })),
        Err(e) => Ok(HttpResponse::Ok().json(VerifyRangeProofResponse {
            valid: false,
            error: Some(e.to_string()),
        })),
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateVideoStreamProofRequest {
    pub session_id: String,
    pub segment_index: u64,
    pub content_hash: String,
}

pub async fn create_video_stream_proof(
    claims: web::ReqData<Claims>,
    body: web::Json<CreateVideoStreamProofRequest>,
) -> Result<impl Responder, AppError> {
    let ctx = BulletproofsContext::new();

    let content = base64::engine::general_purpose::STANDARD
        .decode(&body.content_hash)
        .map_err(|_| AppError::BadRequest("Invalid content hash encoding".to_string()))?;

    let signing_key = derive_signing_key(&claims.sub, &body.session_id);

    match ctx.create_video_stream_proof(
        &body.session_id,
        body.segment_index,
        &content,
        &signing_key,
    ) {
        Ok(proof) => Ok(HttpResponse::Ok().json(proof)),
        Err(e) => Err(AppError::CryptoError(e.to_string())),
    }
}

#[derive(Debug, Deserialize)]
pub struct VerifyVideoStreamProofRequest {
    pub session_id: String,
    pub segment_index: u64,
    pub timestamp: i64,
    pub range_proof: BulletproofsRangeProof,
    pub content_hash: String,
    pub signature: String,
}

pub async fn verify_video_stream_proof(
    claims: web::ReqData<Claims>,
    body: web::Json<VerifyVideoStreamProofRequest>,
) -> Result<impl Responder, AppError> {
    let ctx = BulletproofsContext::new();

    let signing_key = derive_signing_key(&claims.sub, &body.session_id);

    let proof = VideoStreamProof {
        session_id: body.session_id.clone(),
        segment_index: body.segment_index,
        timestamp: body.timestamp,
        range_proof: body.range_proof.clone(),
        content_hash: body.content_hash.clone(),
        signature: body.signature.clone(),
    };

    match ctx.verify_video_stream_proof(&proof, &body.session_id, &signing_key, 300) {
        Ok(valid) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "valid": valid
        }))),
        Err(e) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "valid": false,
            "error": e.to_string()
        }))),
    }
}

fn derive_signing_key(user_id: &str, session_id: &str) -> [u8; 32] {
    let data = format!("{}:{}", user_id, session_id);
    let hash = blake3::hash(data.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(hash.as_bytes());
    key
}

use base64::Engine;

#[derive(Debug, Deserialize)]
pub struct GenerateProofRequest {
    #[allow(dead_code)]
    pub username: String,
    pub password: String,
    pub registration: PasswordRegistration,
    pub context: String,
}

pub async fn generate_zkp_proof(
    body: web::Json<GenerateProofRequest>,
) -> Result<impl Responder, AppError> {
    let zkp_context = ZkpContext::new();

    match zkp_context.generate_enhanced_proof(&body.password, &body.registration, &body.context) {
        Ok(proof) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "proof": proof
        }))),
        Err(e) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": false,
            "error": e.to_string()
        }))),
    }
}
