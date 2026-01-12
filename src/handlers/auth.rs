use actix_web::{web, HttpResponse, Responder};
use sqlx::SqlitePool;
use std::sync::Arc;
use tracing::{info, warn};
use validator::Validate;

use crate::auth::{hash_password, verify_password, JwtHandler};
use crate::config::AppConfig;
use crate::db;
use crate::error::AppError;
use crate::invite::InviteCodeManager;
use crate::models::{
    AuthResponse, InviteCodeResponse, LoginRequest, RefreshTokenRequest, RegisterRequest,
    User, UserResponse, ZkpLoginRequest,
};
use crate::zkp::ZkpContext;

pub async fn register(
    pool: web::Data<SqlitePool>,
    config: web::Data<AppConfig>,
    zkp: web::Data<Arc<ZkpContext>>,
    invite_manager: web::Data<Arc<InviteCodeManager>>,
    body: web::Json<RegisterRequest>,
) -> Result<impl Responder, AppError> {
    body.validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    if db::find_user_by_email(&pool, &body.email).await?.is_some() {
        return Err(AppError::Conflict("Email already registered".to_string()));
    }

    let user_count = db::count_users(&pool).await?;
    let is_first_user = user_count == 0;

    if !is_first_user {
        let invite_code = body.invite_code.as_ref()
            .ok_or_else(|| AppError::Unauthorized("Invite code required for registration".to_string()))?;

        let invite = db::find_invite_code(&pool, invite_code).await?
            .ok_or_else(|| AppError::Unauthorized("Invalid invite code".to_string()))?;

        if !invite_manager.validate_code(&invite)? {
            warn!("Invite code validation failed: {}", invite_code);
            return Err(AppError::Unauthorized("Invite code expired or already used".to_string()));
        }

        db::mark_invite_code_used(&pool, invite_code, &body.email).await?;
    }

    let password_hash = hash_password(&body.password)?;
    let password_proof = zkp.generate_password_proof(&body.password)?;

    let user = User::new(
        body.username.clone(),
        body.email.clone(),
        password_hash,
        password_proof.commitment.clone(),
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

pub async fn login_zkp(
    pool: web::Data<SqlitePool>,
    config: web::Data<AppConfig>,
    zkp: web::Data<Arc<ZkpContext>>,
    body: web::Json<ZkpLoginRequest>,
) -> Result<impl Responder, AppError> {
    let user = db::find_user_by_email(&pool, &body.email)
        .await?
        .ok_or(AppError::InvalidCredentials)?;

    if !user.is_active {
        return Err(AppError::Unauthorized("Account disabled".to_string()));
    }

    let stored_commitment = user.password_commitment.as_ref()
        .ok_or_else(|| AppError::Unauthorized("ZKP login not enabled for user".to_string()))?;

    let is_valid = zkp.verify_password_proof(&body.proof, stored_commitment)?;
    
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

pub async fn refresh_token(
    pool: web::Data<SqlitePool>,
    config: web::Data<AppConfig>,
    body: web::Json<RefreshTokenRequest>,
) -> Result<impl Responder, AppError> {
    let jwt_handler = JwtHandler::new(config.get_ref());
    let claims = jwt_handler.verify_refresh_token(&body.refresh_token)?;

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
