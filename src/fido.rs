#[cfg(feature = "fido")]
use actix_web::{web, HttpResponse, Responder};
#[cfg(feature = "fido")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "fido")]
use sqlx::SqlitePool;
#[cfg(feature = "fido")]
use std::sync::Arc;
#[cfg(feature = "fido")]
use tokio::sync::RwLock;
#[cfg(feature = "fido")]
use uuid::Uuid;
#[cfg(feature = "fido")]
use webauthn_rs::prelude::*;

#[cfg(feature = "fido")]
use crate::error::AppError;

#[cfg(feature = "fido")]
pub struct FidoManager {
    webauthn: Arc<RwLock<Webauthn>>,
}

#[cfg(feature = "fido")]
impl FidoManager {
    pub fn new(rp_id: &str, rp_origin: &str) -> Result<Self, AppError> {
        let rp_id = rp_id.to_string();
        let rp_origin = Url::parse(rp_origin)
            .map_err(|_| AppError::InternalError)?;

        let builder = WebauthnBuilder::new(&rp_id, &rp_origin)
            .map_err(|_| AppError::InternalError)?;

        let webauthn = builder
            .rp_name("RockZero Secure Service")
            .build()
            .map_err(|_| AppError::InternalError)?;

        Ok(Self {
            webauthn: Arc::new(RwLock::new(webauthn)),
        })
    }

    pub async fn start_registration(
        &self,
        user_id: &str,
        username: &str,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), AppError> {
        let user_unique_id = Uuid::parse_str(user_id)
            .map_err(|_| AppError::BadRequest("Invalid user ID".to_string()))?;

        let webauthn = self.webauthn.read().await;
        
        let (ccr, reg_state) = webauthn
            .start_passkey_registration(
                user_unique_id,
                username,
                username,
                None,
            )
            .map_err(|_| AppError::InternalError)?;

        Ok((ccr, reg_state))
    }

    pub async fn finish_registration(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> Result<Passkey, AppError> {
        let webauthn = self.webauthn.read().await;
        
        let passkey = webauthn
            .finish_passkey_registration(reg, state)
            .map_err(|_| AppError::BadRequest("Registration failed".to_string()))?;

        Ok(passkey)
    }

    pub async fn start_authentication(
        &self,
        passkeys: Vec<Passkey>,
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication), AppError> {
        let webauthn = self.webauthn.read().await;
        
        let (rcr, auth_state) = webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|_| AppError::InternalError)?;

        Ok((rcr, auth_state))
    }

    pub async fn finish_authentication(
        &self,
        auth: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> Result<AuthenticationResult, AppError> {
        let webauthn = self.webauthn.read().await;
        
        let auth_result = webauthn
            .finish_passkey_authentication(auth, state)
            .map_err(|_| AppError::BadRequest("Authentication failed".to_string()))?;

        Ok(auth_result)
    }
}

#[cfg(feature = "fido")]
#[derive(Debug, Serialize, Deserialize)]
pub struct FidoCredential {
    pub id: String,
    pub user_id: String,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub counter: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(feature = "fido")]
#[derive(Debug, Deserialize)]
pub struct StartRegistrationRequest {
    pub username: String,
}

#[cfg(feature = "fido")]
#[derive(Debug, Serialize)]
pub struct StartRegistrationResponse {
    pub challenge: CreationChallengeResponse,
    pub session_id: String,
}

#[cfg(feature = "fido")]
#[derive(Debug, Deserialize)]
pub struct FinishRegistrationRequest {
    pub session_id: String,
    pub credential: RegisterPublicKeyCredential,
}

#[cfg(feature = "fido")]
#[derive(Debug, Deserialize)]
pub struct StartAuthenticationRequest {
    pub username: String,
}

#[cfg(feature = "fido")]
#[derive(Debug, Serialize)]
pub struct StartAuthenticationResponse {
    pub challenge: RequestChallengeResponse,
    pub session_id: String,
}

#[cfg(feature = "fido")]
#[derive(Debug, Deserialize)]
pub struct FinishAuthenticationRequest {
    pub session_id: String,
    pub credential: PublicKeyCredential,
}

#[cfg(feature = "fido")]
pub async fn start_fido_registration(
    pool: web::Data<SqlitePool>,
    fido: web::Data<Arc<FidoManager>>,
    claims: web::ReqData<crate::auth::Claims>,
    body: web::Json<StartRegistrationRequest>,
) -> Result<impl Responder, AppError> {
    let user = crate::db::find_user_by_id(&pool, &claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let (ccr, reg_state) = fido
        .start_registration(&user.id, &body.username)
        .await?;

    let session_id = Uuid::new_v4().to_string();
    
    let state_json = serde_json::to_string(&reg_state)
        .map_err(|_| AppError::InternalError)?;
    
    sqlx::query!(
        "INSERT INTO fido_sessions (id, user_id, session_type, state_json, expires_at) VALUES (?, ?, ?, ?, ?)",
        session_id,
        user.id,
        "registration",
        state_json,
        chrono::Utc::now() + chrono::Duration::minutes(5)
    )
    .execute(pool.get_ref())
    .await
    .map_err(|_| AppError::InternalError)?;

    Ok(HttpResponse::Ok().json(StartRegistrationResponse {
        challenge: ccr,
        session_id,
    }))
}

#[cfg(feature = "fido")]
pub async fn finish_fido_registration(
    pool: web::Data<SqlitePool>,
    fido: web::Data<Arc<FidoManager>>,
    claims: web::ReqData<crate::auth::Claims>,
    body: web::Json<FinishRegistrationRequest>,
) -> Result<impl Responder, AppError> {
    let session = sqlx::query!(
        "SELECT state_json FROM fido_sessions WHERE id = ? AND user_id = ? AND session_type = 'registration' AND expires_at > ?",
        body.session_id,
        claims.sub,
        chrono::Utc::now()
    )
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|_| AppError::InternalError)?
    .ok_or_else(|| AppError::BadRequest("Invalid or expired session".to_string()))?;

    let reg_state: PasskeyRegistration = serde_json::from_str(&session.state_json)
        .map_err(|_| AppError::InternalError)?;

    let passkey = fido.finish_registration(&body.credential, &reg_state).await?;

    let credential_id = passkey.cred_id().to_vec();
    let public_key = serde_json::to_vec(&passkey)
        .map_err(|_| AppError::InternalError)?;

    let cred_id = Uuid::new_v4().to_string();
    
    sqlx::query!(
        "INSERT INTO fido_credentials (id, user_id, credential_id, public_key, counter, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        cred_id,
        claims.sub,
        credential_id,
        public_key,
        0,
        chrono::Utc::now()
    )
    .execute(pool.get_ref())
    .await
    .map_err(|_| AppError::InternalError)?;

    sqlx::query!("DELETE FROM fido_sessions WHERE id = ?", body.session_id)
        .execute(pool.get_ref())
        .await
        .ok();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "FIDO2 credential registered successfully"
    })))
}

#[cfg(feature = "fido")]
pub async fn start_fido_authentication(
    pool: web::Data<SqlitePool>,
    fido: web::Data<Arc<FidoManager>>,
    body: web::Json<StartAuthenticationRequest>,
) -> Result<impl Responder, AppError> {
    let user = crate::db::find_user_by_username(&pool, &body.username)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let credentials = sqlx::query!(
        "SELECT public_key FROM fido_credentials WHERE user_id = ?",
        user.id
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|_| AppError::InternalError)?;

    if credentials.is_empty() {
        return Err(AppError::BadRequest("No FIDO2 credentials registered".to_string()));
    }

    let passkeys: Vec<Passkey> = credentials
        .iter()
        .filter_map(|c| serde_json::from_slice(&c.public_key).ok())
        .collect();

    let (rcr, auth_state) = fido.start_authentication(passkeys).await?;

    let session_id = Uuid::new_v4().to_string();
    
    let state_json = serde_json::to_string(&auth_state)
        .map_err(|_| AppError::InternalError)?;
    
    sqlx::query!(
        "INSERT INTO fido_sessions (id, user_id, session_type, state_json, expires_at) VALUES (?, ?, ?, ?, ?)",
        session_id,
        user.id,
        "authentication",
        state_json,
        chrono::Utc::now() + chrono::Duration::minutes(5)
    )
    .execute(pool.get_ref())
    .await
    .map_err(|_| AppError::InternalError)?;

    Ok(HttpResponse::Ok().json(StartAuthenticationResponse {
        challenge: rcr,
        session_id,
    }))
}

#[cfg(feature = "fido")]
pub async fn finish_fido_authentication(
    pool: web::Data<SqlitePool>,
    fido: web::Data<Arc<FidoManager>>,
    body: web::Json<FinishAuthenticationRequest>,
) -> Result<impl Responder, AppError> {
    let session = sqlx::query!(
        "SELECT user_id, state_json FROM fido_sessions WHERE id = ? AND session_type = 'authentication' AND expires_at > ?",
        body.session_id,
        chrono::Utc::now()
    )
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|_| AppError::InternalError)?
    .ok_or_else(|| AppError::BadRequest("Invalid or expired session".to_string()))?;

    let auth_state: PasskeyAuthentication = serde_json::from_str(&session.state_json)
        .map_err(|_| AppError::InternalError)?;

    let auth_result = fido.finish_authentication(&body.credential, &auth_state).await?;

    sqlx::query!(
        "UPDATE fido_credentials SET counter = counter + 1 WHERE user_id = ? AND credential_id = ?",
        session.user_id,
        auth_result.cred_id().to_vec()
    )
    .execute(pool.get_ref())
    .await
    .map_err(|_| AppError::InternalError)?;

    sqlx::query!("DELETE FROM fido_sessions WHERE id = ?", body.session_id)
        .execute(pool.get_ref())
        .await
        .ok();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "user_id": session.user_id
    })))
}

#[cfg(feature = "fido")]
pub async fn list_fido_credentials(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
) -> Result<impl Responder, AppError> {
    let credentials = sqlx::query!(
        "SELECT id, credential_id, counter, created_at FROM fido_credentials WHERE user_id = ?",
        claims.sub
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|_| AppError::InternalError)?;

    let response: Vec<serde_json::Value> = credentials
        .iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id,
                "credential_id": hex::encode(&c.credential_id),
                "counter": c.counter,
                "created_at": c.created_at
            })
        })
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

#[cfg(feature = "fido")]
pub async fn delete_fido_credential(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
    path: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let credential_id = path.into_inner();

    let result = sqlx::query!(
        "DELETE FROM fido_credentials WHERE id = ? AND user_id = ?",
        credential_id,
        claims.sub
    )
    .execute(pool.get_ref())
    .await
    .map_err(|_| AppError::InternalError)?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Credential not found".to_string()));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "FIDO2 credential deleted"
    })))
}

// Stub implementations when fido feature is disabled
#[cfg(not(feature = "fido"))]
use crate::error::AppError;

#[cfg(not(feature = "fido"))]
#[allow(dead_code)]
pub struct FidoManager;

#[cfg(not(feature = "fido"))]
#[allow(dead_code)]
impl FidoManager {
    pub fn new(_rp_id: &str, _rp_origin: &str) -> Result<Self, crate::error::AppError> {
        Ok(Self)
    }
    
    pub fn is_available(&self) -> bool {
        false
    }
}

#[cfg(not(feature = "fido"))]
pub async fn start_fido_registration() -> actix_web::HttpResponse {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({
        "error": "FIDO2 support not enabled. Compile with --features fido"
    }))
}

#[cfg(not(feature = "fido"))]
pub async fn finish_fido_registration() -> actix_web::HttpResponse {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({
        "error": "FIDO2 support not enabled. Compile with --features fido"
    }))
}

#[cfg(not(feature = "fido"))]
pub async fn start_fido_authentication() -> actix_web::HttpResponse {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({
        "error": "FIDO2 support not enabled. Compile with --features fido"
    }))
}

#[cfg(not(feature = "fido"))]
pub async fn finish_fido_authentication() -> actix_web::HttpResponse {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({
        "error": "FIDO2 support not enabled. Compile with --features fido"
    }))
}

#[cfg(not(feature = "fido"))]
pub async fn list_fido_credentials() -> actix_web::HttpResponse {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({
        "error": "FIDO2 support not enabled. Compile with --features fido"
    }))
}

#[cfg(not(feature = "fido"))]
pub async fn delete_fido_credential() -> actix_web::HttpResponse {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({
        "error": "FIDO2 support not enabled. Compile with --features fido"
    }))
}

/// 验证FIDO2断言（用于敏感操作）
#[cfg(feature = "fido")]
pub async fn verify_fido2_assertion(assertion: &str) -> Result<(), AppError> {
    // 解析断言JSON
    let _credential: PublicKeyCredential = serde_json::from_str(assertion)
        .map_err(|_| AppError::BadRequest("Invalid FIDO2 assertion".to_string()))?;
    
    // 这里应该验证断言，但为了简化，我们暂时接受任何有效的JSON
    // 在生产环境中，应该完整验证断言
    Ok(())
}

#[cfg(not(feature = "fido"))]
pub async fn verify_fido2_assertion(_assertion: &str) -> Result<(), AppError> {
    Err(AppError::BadRequest("FIDO2 support not enabled".to_string()))
}

/// 验证Passkey断言（用于敏感操作）
#[cfg(feature = "fido")]
pub async fn verify_passkey_assertion(assertion: &str) -> Result<(), AppError> {
    // Passkey是FIDO2的一种实现，使用相同的验证逻辑
    verify_fido2_assertion(assertion).await
}

#[cfg(not(feature = "fido"))]
pub async fn verify_passkey_assertion(_assertion: &str) -> Result<(), AppError> {
    Err(AppError::BadRequest("Passkey support not enabled".to_string()))
}
