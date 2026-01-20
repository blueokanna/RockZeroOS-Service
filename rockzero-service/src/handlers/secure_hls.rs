use actix_web::{web, HttpResponse, Responder};
use rockzero_common::AppError;
use rockzero_crypto::{EnhancedPasswordProof, ZkpContext};
use rockzero_media::{HlsSession, HlsSessionManager};
use rockzero_sae::{SaeCommit, SaeConfirm};
use serde::Deserialize;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

// ============ 辅助函数：错误转换 ============

fn convert_hls_error(err: rockzero_media::HlsError) -> AppError {
    match err {
        rockzero_media::HlsError::SessionNotFound(msg) => AppError::NotFound(msg),
        rockzero_media::HlsError::SessionExpired(msg) => AppError::Unauthorized(msg),
        rockzero_media::HlsError::EncryptionError(msg) => AppError::CryptoError(msg),
        rockzero_media::HlsError::DecryptionError(msg) => AppError::CryptoError(msg),
        rockzero_media::HlsError::InvalidKey(msg) => AppError::CryptoError(msg),
        rockzero_media::HlsError::SaeError(e) => AppError::CryptoError(e.to_string()),
        rockzero_media::HlsError::IoError(e) => AppError::IoError(e.to_string()),
        rockzero_media::HlsError::SerializationError(msg) => AppError::InternalServerError(msg),
    }
}

// ============ 数据结构 ============

#[derive(Debug, Deserialize)]
pub struct InitSaeRequest {
    pub file_id: String,
}



#[derive(Debug, Deserialize)]
pub struct CompleteSaeRequest {
    pub temp_session_id: String,
    pub client_commit: SaeCommit,
    pub client_confirm: SaeConfirm,
}



#[derive(Debug, Deserialize)]
pub struct SecureSegmentRequest {
    pub zkp_proof: String, // Base64 编码的 ZKP 证明
}



// ============ SAE 握手处理 ============

/// 步骤 1: 初始化 SAE 握手
/// 
/// 客户端调用此接口开始 SAE 握手流程
pub async fn init_sae_handshake(
    pool: web::Data<SqlitePool>,
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<InitSaeRequest>,
) -> Result<impl Responder, AppError> {
    let user_id = claims.sub.clone();
    
    // 验证文件访问权限
    let _file = crate::db::find_file_by_id(&pool, &body.file_id, &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("File not found".to_string()))?;
    
    // 从数据库获取用户的密码哈希（用于 SAE）
    let user = crate::db::find_user_by_id(&pool, &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    
    // 使用用户密码哈希作为 SAE 的共享密钥
    // 注意：这里使用密码哈希而不是明文密码
    let password = user.password_hash.as_bytes().to_vec();
    
    // 初始化 SAE 握手
    let manager = hls_manager.read().await;
    let temp_session_id = manager.init_sae_handshake(user_id.clone(), password)
        .map_err(convert_hls_error)?;
    
    // 获取 SAE 服务器的 commit（需要先处理客户端的 commit）
    // 这里我们返回 temp_session_id，客户端需要发送 commit
    
    info!("Initialized SAE handshake for user {} - temp session {}", user_id, temp_session_id);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "temp_session_id": temp_session_id,
        "message": "SAE handshake initialized, send client commit next"
    })))
}

/// 步骤 2: 完成 SAE 握手
/// 
/// 客户端发送 commit 和 confirm，服务器验证并返回 server confirm
pub async fn complete_sae_handshake(
    _pool: web::Data<SqlitePool>,
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<CompleteSaeRequest>,
) -> Result<impl Responder, AppError> {
    let user_id = claims.sub.clone();
    
    // 获取 SAE 服务器实例并处理握手
    let (server_commit, server_confirm) = {
        let manager = hls_manager.read().await;
        let mut servers = manager.sae_servers.lock().unwrap();
        let sae_server = servers
            .get_mut(&body.temp_session_id)
            .ok_or_else(|| AppError::NotFound("SAE session not found".to_string()))?;
        
        // 处理客户端的 commit 并生成服务器的 commit 和 confirm
        let (server_commit, server_confirm) = sae_server
            .process_client_commit(&body.client_commit)
            .map_err(|e| AppError::CryptoError(format!("SAE commit failed: {}", e)))?;
        
        // 验证客户端的 confirm
        sae_server
            .verify_client_confirm(&body.client_confirm)
            .map_err(|e| AppError::CryptoError(format!("SAE confirm failed: {}", e)))?;
        
        (server_commit, server_confirm)
    };
    
    info!("Completed SAE handshake for user {} - temp session {}", user_id, body.temp_session_id);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "server_commit": server_commit,
        "server_confirm": server_confirm,
        "message": "SAE handshake completed, call create_session next"
    })))
}

/// 步骤 3: 创建 HLS 会话
/// 
/// SAE 握手完成后，创建实际的 HLS 会话
#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    pub temp_session_id: String,
    pub file_id: String,
}

pub async fn create_hls_session(
    pool: web::Data<SqlitePool>,
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<CreateSessionRequest>,
) -> Result<impl Responder, AppError> {
    let user_id = claims.sub.clone();
    
    // 获取文件信息
    let file = crate::db::find_file_by_id(&pool, &body.file_id, &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("File not found".to_string()))?;
    
    // 完成 SAE 握手并创建会话
    let manager = hls_manager.read().await;
    let session_id = manager.complete_sae_handshake(
        &body.temp_session_id,
        user_id.clone(),
        file.file_path.clone(),
    ).map_err(convert_hls_error)?;
    
    // 获取会话信息
    let session = manager.get_session(&session_id).map_err(convert_hls_error)?;
    
    info!("Created HLS session {} for user {} - file {}", session_id, user_id, file.file_path);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "session_id": session_id,
        "expires_at": session.expires_at.timestamp(),
        "playlist_url": format!("/api/v1/secure-hls/{}/playlist.m3u8", session_id),
    })))
}

// ============ 安全播放列表和段获取 ============

/// 获取安全的 M3U8 播放列表（不包含密钥 URL）
pub async fn get_secure_playlist(
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    path: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let session_id = path.into_inner();
    
    // 验证会话
    let manager = hls_manager.read().await;
    let _session = manager.get_session(&session_id).map_err(convert_hls_error)?;
    
    // 生成不包含密钥 URL 的播放列表
    let playlist = generate_secure_m3u8(100, 10.0);
    
    info!("Serving secure playlist for session {}", session_id);
    
    Ok(HttpResponse::Ok()
        .content_type("application/vnd.apple.mpegurl")
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("X-Encryption-Method", "AES-256-GCM"))
        .insert_header(("X-Requires-ZKP", "true"))
        .body(playlist))
}

/// 获取加密的 TS 段（需要 ZKP 证明）
pub async fn get_secure_segment(
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    path: web::Path<(String, String)>,
    body: web::Json<SecureSegmentRequest>,
) -> Result<impl Responder, AppError> {
    let (session_id, segment_name) = path.into_inner();
    
    // 1. 验证会话
    let manager = hls_manager.read().await;
    let session = manager.get_session(&session_id).map_err(convert_hls_error)?;
    
    // 2. 验证 ZKP 证明
    if !verify_zkp_proof(&session, &body.zkp_proof)? {
        warn!("Invalid ZKP proof for session {} segment {}", session_id, segment_name);
        return Err(AppError::Unauthorized("Invalid ZKP proof".to_string()));
    }
    
    // 3. 读取原始 TS 段（这里需要实际的视频段）
    // 注意：这是简化版本，实际需要从 FFmpeg 转码输出读取
    let segment_data = read_video_segment(&session.file_path, &segment_name)?;
    
    // 4. 使用会话密钥加密段
    let encrypted_segment = session.encrypt_segment(&segment_data).map_err(convert_hls_error)?;
    
    info!("Serving encrypted segment {} for session {}", segment_name, session_id);
    
    Ok(HttpResponse::Ok()
        .content_type("application/octet-stream")
        .insert_header(("X-Encrypted", "true"))
        .insert_header(("X-Encryption-Method", "AES-256-GCM"))
        .body(encrypted_segment))
}

// ============ 辅助函数 ============

/// 生成安全的 M3U8 播放列表（不包含 #EXT-X-KEY）
fn generate_secure_m3u8(segment_count: usize, segment_duration: f32) -> String {
    let mut playlist = String::from("#EXTM3U\n");
    playlist.push_str("#EXT-X-VERSION:3\n");
    playlist.push_str(&format!(
        "#EXT-X-TARGETDURATION:{}\n",
        segment_duration.ceil() as u32
    ));
    playlist.push_str("#EXT-X-MEDIA-SEQUENCE:0\n");
    
    // ❌ 不包含 #EXT-X-KEY（密钥通过 SAE 握手获得）
    // ✅ 客户端已经拥有解密密钥（AES-256-GCM）
    
    playlist.push_str("# Encrypted with AES-256-GCM\n");
    playlist.push_str("# Requires ZKP proof for segment access\n\n");
    
    for i in 0..segment_count {
        playlist.push_str(&format!("#EXTINF:{:.3},\n", segment_duration));
        playlist.push_str(&format!("segment_{}.ts\n", i));
    }
    
    playlist.push_str("#EXT-X-ENDLIST\n");
    playlist
}

/// 验证客户端的 ZKP 证明
fn verify_zkp_proof(session: &HlsSession, proof_base64: &str) -> Result<bool, AppError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    
    // 解码 ZKP 证明
    let proof_bytes = BASE64
        .decode(proof_base64)
        .map_err(|_| AppError::BadRequest("Invalid proof format".to_string()))?;
    
    // 解析 ZKP 证明
    let proof: EnhancedPasswordProof = serde_json::from_slice(&proof_bytes)
        .map_err(|_| AppError::BadRequest("Invalid proof structure".to_string()))?;
    
    // 验证证明
    let zkp_context = ZkpContext::new();
    
    // 使用会话的 PMK 生成 commitment
    let pmk_hex = hex::encode(session.pmk);
    
    // 验证增强证明（300秒有效期）
    zkp_context.verify_enhanced_proof(&proof, &pmk_hex, 300)
        .map_err(|e| AppError::CryptoError(format!("ZKP verification failed: {}", e)))
}

/// 读取视频段数据
/// 
/// 注意：这是简化版本，实际应该从 FFmpeg 转码输出读取
fn read_video_segment(file_path: &str, segment_name: &str) -> Result<Vec<u8>, AppError> {
    use std::fs;
    use std::path::PathBuf;
    
    // 解析段索引
    let segment_index: usize = segment_name
        .trim_start_matches("segment_")
        .trim_end_matches(".ts")
        .parse()
        .map_err(|_| AppError::BadRequest("Invalid segment name".to_string()))?;
    
    // 构建段文件路径（假设已经转码）
    // 实际应该从 HLS 缓存目录读取
    let segment_path = PathBuf::from(file_path)
        .parent()
        .ok_or(AppError::InternalError)?
        .join(format!("segment_{}.ts", segment_index));
    
    // 如果段不存在，需要实时转码
    if !segment_path.exists() {
        // TODO: 实时转码逻辑
        // 这里返回模拟数据
        warn!("Segment {} not found, returning mock data", segment_name);
        return Ok(vec![0u8; 1024 * 64]); // 64KB 模拟数据
    }
    
    // 读取段文件
    fs::read(&segment_path)
        .map_err(|e| AppError::IoError(format!("Failed to read segment: {}", e)))
}

// ============ 会话管理扩展 ============

// 注意：不能为外部类型实现方法，这些方法已经在 rockzero-media/src/session.rs 中实现

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_playlist_generation() {
        let playlist = generate_secure_m3u8(5, 10.0);
        
        assert!(playlist.contains("#EXTM3U"));
        assert!(playlist.contains("segment_0.ts"));
        assert!(playlist.contains("segment_4.ts"));
        assert!(!playlist.contains("#EXT-X-KEY")); // 不应该包含密钥 URL
        assert!(playlist.contains("AES-256-GCM"));
    }
}
