//! 认证处理器 - 注册、登录、令牌管理
//!
//! 支持多种认证方式：
//! - 传统密码认证
//! - 零知识证明认证
//! - 增强的零知识证明认证（包含防重放保护）

use actix_web::{web, HttpResponse, Responder};
use sqlx::SqlitePool;
use std::sync::Arc;
use tracing::{info, warn};
use validator::Validate;

use crate::auth::{verify_password, JwtHandler, SecurePasswordHandler};
use crate::config::AppConfig;
use crate::db;
use crate::error::AppError;
use crate::invite::InviteCodeManager;
use crate::models::{
    AuthResponse, InviteCodeResponse, LoginRequest, RefreshTokenRequest, RegisterRequest,
    User, UserResponse, ZkpLoginRequest,
};
use crate::zkp::{EnhancedPasswordProof, ZkpContext};

/// 用户注册
pub async fn register(
    pool: web::Data<SqlitePool>,
    config: web::Data<AppConfig>,
    _zkp: web::Data<Arc<ZkpContext>>,
    invite_manager: web::Data<Arc<InviteCodeManager>>,
    body: web::Json<RegisterRequest>,
) -> Result<impl Responder, AppError> {
    body.validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    // 检查邮箱是否已注册
    if db::find_user_by_email(&pool, &body.email).await?.is_some() {
        return Err(AppError::Conflict("Email already registered".to_string()));
    }

    let user_count = db::count_users(&pool).await?;
    let is_first_user = user_count == 0;

    // 非首个用户需要邀请码
    if !is_first_user {
        let invite_code = body.invite_code.as_ref()
            .ok_or_else(|| AppError::Unauthorized("Invite code required".to_string()))?;

        let invite = db::find_invite_code(&pool, invite_code).await?
            .ok_or_else(|| AppError::Unauthorized("Invalid invite code".to_string()))?;

        if !invite_manager.validate_code(&invite)? {
            warn!("Invite code validation failed: {}", invite_code);
            return Err(AppError::Unauthorized("Invite code expired or used".to_string()));
        }

        db::mark_invite_code_used(&pool, invite_code, &body.email).await?;
    }

    // 使用安全密码处理器创建凭证
    let password_handler = SecurePasswordHandler::new();
    let credentials = password_handler.create_password_credentials(&body.password)?;

    let user = User::new(
        body.username.clone(),
        body.email.clone(),
        credentials.password_hash,
        credentials.zkp_commitment,
        is_first_user,
    );

    db::create_user(&pool, &user).await?;

    info!(
        "User registered: {} ({}) - Super admin: {}",
        user.username, user.email, is_first_user
    );

    let jwt_handler = JwtHandler::new(config.get_ref());
    let tokens = jwt_handler.generate_tokens(&user.id, &user.email, &user.role)?;

    Ok(HttpResponse::Created().json(AuthResponse {
        user: UserResponse::from(user),
        tokens,
    }))
}

/// 生成邀请码（仅超级管理员）
pub async fn generate_invite_code(
    pool: web::Data<SqlitePool>,
    invite_manager: web::Data<Arc<InviteCodeManager>>,
    claims: web::ReqData<crate::auth::Claims>,
) -> Result<impl Responder, AppError> {
    let user = db::find_user_by_id(&pool, &claims.sub).await?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;

    if !user.is_super_admin {
        return Err(AppError::Forbidden("Only super admin can generate invite codes".to_string()));
    }

    // 检查是否有未使用的有效邀请码
    if let Some(existing) = db::get_latest_valid_invite(&pool, &user.id).await? {
        if invite_manager.validate_code(&existing)? {
            let remaining = invite_manager.get_remaining_seconds(&existing)?;
            return Ok(HttpResponse::Ok().json(InviteCodeResponse {
                code: existing.code,
                expires_in_seconds: remaining,
            }));
        }
    }

    let invite = invite_manager.create_invite_code(&user.id)?;
    db::create_invite_code(&pool, &invite).await?;

    info!("Super admin {} generated invite code: {}", user.username, invite.code);

    Ok(HttpResponse::Created().json(InviteCodeResponse {
        code: invite.code,
        expires_in_seconds: 3600,
    }))
}

/// 传统密码登录
pub async fn login(
    pool: web::Data<SqlitePool>,
    config: web::Data<AppConfig>,
    body: web::Json<LoginRequest>,
) -> Result<impl Responder, AppError> {
    body.validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    let user = db::find_user_by_email(&pool, &body.email)
        .await?
        .ok_or(AppError::InvalidCredentials)?;

    if !user.is_active {
        return Err(AppError::Unauthorized("Account disabled".to_string()));
    }

    if !verify_password(&body.password, &user.password_hash)? {
        return Err(AppError::InvalidCredentials);
    }

    info!("User logged in: {} ({})", user.username, user.email);

    let jwt_handler = JwtHandler::new(config.get_ref());
    let tokens = jwt_handler.generate_tokens(&user.id, &user.email, &user.role)?;

    Ok(HttpResponse::Ok().json(AuthResponse {
        user: UserResponse::from(user),
        tokens,
    }))
}

/// 零知识证明登录
pub async fn login_zkp(
    pool: web::Data<SqlitePool>,
    config: web::Data<AppConfig>,
    _zkp: web::Data<Arc<ZkpContext>>,
    body: web::Json<ZkpLoginRequest>,
) -> Result<impl Responder, AppError> {
    let user = db::find_user_by_email(&pool, &body.email)
        .await?
        .ok_or(AppError::InvalidCredentials)?;

    if !user.is_active {
        return Err(AppError::Unauthorized("Account disabled".to_string()));
    }

    let stored_commitment = user.password_commitment.as_ref()
        .ok_or_else(|| AppError::Unauthorized("ZKP login not enabled".to_string()))?;

    // 使用 SecurePasswordHandler 验证 ZKP 证明
    let password_handler = SecurePasswordHandler::new();
    let is_valid = password_handler.verify_zkp_proof(&body.proof, stored_commitment)?;
    
    if !is_valid {
        return Err(AppError::InvalidCredentials);
    }

    info!("User logged in via ZKP: {} ({})", user.username, user.email);

    let jwt_handler = JwtHandler::new(config.get_ref());
    let tokens = jwt_handler.generate_tokens(&user.id, &user.email, &user.role)?;

    Ok(HttpResponse::Ok().json(AuthResponse {
        user: UserResponse::from(user),
        tokens,
    }))
}

/// 增强的零知识证明登录请求
#[derive(Debug, serde::Deserialize)]
pub struct EnhancedZkpLoginRequest {
    pub email: String,
    pub proof: EnhancedPasswordProof,
}

/// 增强的零知识证明登录（包含防重放保护）
pub async fn login_zkp_enhanced(
    pool: web::Data<SqlitePool>,
    config: web::Data<AppConfig>,
    body: web::Json<EnhancedZkpLoginRequest>,
) -> Result<impl Responder, AppError> {
    let user = db::find_user_by_email(&pool, &body.email)
        .await?
        .ok_or(AppError::InvalidCredentials)?;

    if !user.is_active {
        return Err(AppError::Unauthorized("Account disabled".to_string()));
    }

    let stored_commitment = user.password_commitment.as_ref()
        .ok_or_else(|| AppError::Unauthorized("ZKP login not enabled".to_string()))?;

    // 使用安全密码处理器验证增强证明
    let password_handler = SecurePasswordHandler::new();
    let is_valid = password_handler.verify_enhanced_proof(&body.proof, stored_commitment).await?;
    
    if !is_valid {
        return Err(AppError::InvalidCredentials);
    }

    info!("User logged in via Enhanced ZKP: {} ({})", user.username, user.email);

    let jwt_handler = JwtHandler::new(config.get_ref());
    let tokens = jwt_handler.generate_tokens(&user.id, &user.email, &user.role)?;

    Ok(HttpResponse::Ok().json(AuthResponse {
        user: UserResponse::from(user),
        tokens,
    }))
}

/// 刷新令牌
pub async fn refresh_token(
    pool: web::Data<SqlitePool>,
    config: web::Data<AppConfig>,
    body: web::Json<RefreshTokenRequest>,
) -> Result<impl Responder, AppError> {
    let jwt_handler = JwtHandler::new(config.get_ref());
    let claims = jwt_handler.verify_refresh_token(&body.refresh_token).await?;

    let user = db::find_user_by_id(&pool, &claims.sub)
        .await?
        .ok_or(AppError::Unauthorized("User not found".to_string()))?;

    if !user.is_active {
        return Err(AppError::Unauthorized("Account disabled".to_string()));
    }

    let tokens = jwt_handler.generate_tokens(&user.id, &user.email, &user.role)?;

    info!("Token refreshed: {} ({})", user.username, user.email);

    Ok(HttpResponse::Ok().json(tokens))
}

#[derive(Debug, serde::Deserialize)]
pub struct VerifyPasswordRequest {
    pub password: String,
}

/// 验证密码（用于敏感操作）
pub async fn verify_password_endpoint(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
    body: web::Json<VerifyPasswordRequest>,
) -> Result<impl Responder, AppError> {
    let user = db::find_user_by_id(&pool, &claims.sub)
        .await?
        .ok_or(AppError::Unauthorized("User not found".to_string()))?;

    if !user.is_active {
        return Err(AppError::Unauthorized("Account disabled".to_string()));
    }

    let password_handler = SecurePasswordHandler::new();
    if !password_handler.verify_password(&body.password, &user.password_hash)? {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    info!("Password verified for user: {} ({})", user.username, user.email);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Password verified successfully"
    })))
}

// ============ ZKP 工具 API ============

/// 生成 ZKP 证明请求
#[derive(Debug, serde::Deserialize)]
pub struct GenerateProofRequest {
    pub password: String,
}

/// 生成 ZKP 证明响应
#[derive(Debug, serde::Serialize)]
pub struct GenerateProofResponse {
    pub proof: crate::zkp::PasswordProofData,
}

/// 生成增强 ZKP 证明响应
#[derive(Debug, serde::Serialize)]
pub struct GenerateEnhancedProofResponse {
    pub proof: EnhancedPasswordProof,
}

/// 生成 ZKP 密码证明（客户端工具）
pub async fn generate_zkp_proof(
    _zkp: web::Data<Arc<ZkpContext>>,
    body: web::Json<GenerateProofRequest>,
) -> Result<impl Responder, AppError> {
    let handler = SecurePasswordHandler::new();
    let proof = handler.generate_proof(&body.password)?;
    
    Ok(HttpResponse::Ok().json(GenerateProofResponse { proof }))
}

/// 生成增强的 ZKP 密码证明（客户端工具）
pub async fn generate_enhanced_zkp_proof(
    _zkp: web::Data<Arc<ZkpContext>>,
    body: web::Json<GenerateProofRequest>,
) -> Result<impl Responder, AppError> {
    let handler = SecurePasswordHandler::new();
    let proof = handler.generate_enhanced_proof(&body.password)?;
    
    Ok(HttpResponse::Ok().json(GenerateEnhancedProofResponse { proof }))
}

/// 密码强度检查请求
#[derive(Debug, serde::Deserialize)]
pub struct PasswordStrengthRequest {
    pub password: String,
}

/// 密码强度检查响应
#[derive(Debug, serde::Serialize)]
pub struct PasswordStrengthResponse {
    pub entropy: u64,
    pub entropy_bits: f64,
    pub strength: String,
    pub suggestions: Vec<String>,
}

/// 检查密码强度
pub async fn check_password_strength(
    body: web::Json<PasswordStrengthRequest>,
) -> Result<impl Responder, AppError> {
    let entropy = SecurePasswordHandler::calculate_password_entropy(&body.password);
    let entropy_bits = entropy as f64 / 100.0;
    
    let (strength, suggestions) = if entropy_bits < 28.0 {
        ("very_weak", vec![
            "Add more characters".to_string(),
            "Use uppercase letters".to_string(),
            "Use numbers".to_string(),
            "Use special characters".to_string(),
        ])
    } else if entropy_bits < 36.0 {
        ("weak", vec![
            "Add more characters".to_string(),
            "Mix different character types".to_string(),
        ])
    } else if entropy_bits < 60.0 {
        ("moderate", vec![
            "Consider adding more characters for better security".to_string(),
        ])
    } else if entropy_bits < 80.0 {
        ("strong", vec![])
    } else {
        ("very_strong", vec![])
    };
    
    Ok(HttpResponse::Ok().json(PasswordStrengthResponse {
        entropy,
        entropy_bits,
        strength: strength.to_string(),
        suggestions,
    }))
}

/// 范围证明请求
#[derive(Debug, serde::Deserialize)]
pub struct RangeProofRequest {
    pub value: u64,
    pub n_bits: usize,
}

/// 范围证明响应
#[derive(Debug, serde::Serialize)]
pub struct RangeProofResponse {
    pub proof: crate::zkp::RangeProofData,
}

/// 生成范围证明
pub async fn generate_range_proof(
    zkp: web::Data<Arc<ZkpContext>>,
    body: web::Json<RangeProofRequest>,
) -> Result<impl Responder, AppError> {
    if body.n_bits > 64 {
        return Err(AppError::BadRequest("n_bits must be <= 64".to_string()));
    }
    
    let proof = zkp.generate_range_proof(body.value, body.n_bits)?;
    
    Ok(HttpResponse::Ok().json(RangeProofResponse { proof }))
}

/// 验证范围证明请求
#[derive(Debug, serde::Deserialize)]
pub struct VerifyRangeProofRequest {
    pub proof: crate::zkp::RangeProofData,
}

/// 验证范围证明
pub async fn verify_range_proof(
    zkp: web::Data<Arc<ZkpContext>>,
    body: web::Json<VerifyRangeProofRequest>,
) -> Result<impl Responder, AppError> {
    let is_valid = zkp.verify_range_proof(&body.proof)?;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "valid": is_valid
    })))
}

/// 登出（撤销令牌）
pub async fn logout(
    config: web::Data<AppConfig>,
    claims: web::ReqData<crate::auth::Claims>,
) -> Result<impl Responder, AppError> {
    if let Some(jti) = &claims.jti {
        let jwt_handler = JwtHandler::new(config.get_ref());
        jwt_handler.revoke_token(jti).await;
        info!("Token revoked for user: {}", claims.email);
    }
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Logged out successfully"
    })))
}

/// 派生加密密钥请求
#[derive(Debug, serde::Deserialize)]
pub struct DeriveKeyRequest {
    pub password: String,
    pub context: String,
}

/// 派生加密密钥响应
#[derive(Debug, serde::Serialize)]
pub struct DeriveKeyResponse {
    pub key: String,
}

/// 派生加密密钥（用于客户端加密）
pub async fn derive_encryption_key(
    body: web::Json<DeriveKeyRequest>,
) -> Result<impl Responder, AppError> {
    let handler = SecurePasswordHandler::new();
    let key = handler.derive_encryption_key(&body.password, &body.context);
    
    Ok(HttpResponse::Ok().json(DeriveKeyResponse {
        key: hex::encode(key),
    }))
}
