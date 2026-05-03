use actix_web::{web, HttpResponse, Responder};
use chrono::Utc;
use rand::Rng;
use serde::Deserialize;
use serde_json::json;
use sqlx::SqlitePool;

use crate::handlers::auth::Claims;
use rockzero_common::AppError;

#[derive(Debug, Deserialize)]
pub struct InviteCodePayload {
    pub code: String,
}

fn generate_invite_code() -> String {
    let mut rng = rand::thread_rng();
    format!("{:08}", rng.gen_range(10000000..100000000))
}

fn ensure_admin(claims: &Claims) -> Result<(), AppError> {
    if claims.role.eq_ignore_ascii_case("admin") {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "Administrator access is required to create invite codes".to_string(),
        ))
    }
}

pub async fn create_invite(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
) -> Result<impl Responder, AppError> {
    ensure_admin(&claims)?;

    let code = generate_invite_code();
    let expires_at = Utc::now() + chrono::Duration::hours(1);

    crate::db::create_invite_code(&pool, &code, &claims.sub, 1, Some(expires_at)).await?;
    let remaining = crate::db::get_invite_remaining_seconds(&pool, &code)
        .await?
        .unwrap_or(0);

    Ok(HttpResponse::Ok().json(json!({
        "code": code,
        "expires_in_seconds": remaining
    })))
}

pub async fn validate_invite(
    pool: web::Data<SqlitePool>,
    code: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let valid = crate::db::validate_invite_code(&pool, &code).await?;
    let remaining_seconds = crate::db::get_invite_remaining_seconds(&pool, &code)
        .await?
        .unwrap_or(0);

    Ok(HttpResponse::Ok().json(json!({
        "code": code.into_inner(),
        "valid": valid,
        "remaining_seconds": remaining_seconds
    })))
}

pub async fn invite_remaining_time(
    pool: web::Data<SqlitePool>,
    body: web::Json<InviteCodePayload>,
) -> Result<impl Responder, AppError> {
    let remaining_seconds = crate::db::get_invite_remaining_seconds(&pool, &body.code)
        .await?
        .unwrap_or(0);

    Ok(HttpResponse::Ok().json(json!({
        "code": body.code,
        "remaining_seconds": remaining_seconds
    })))
}
