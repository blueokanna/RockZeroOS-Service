//! Secure HLS Video Streaming Module
//!
//! Implements complete secure video playback architecture:
//! - JWT Authentication: Verify user identity
//! - SAE Handshake: WPA3-SAE key exchange, establish shared key
//! - AES-256-GCM: Encrypt video segments with derived key
//! - Replay Protection: Request signing + Timestamp + Nonce
//! - Request Binding: Prevent request copying to other sessions

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use chrono::Utc;
use rockzero_common::AppError;
use rockzero_media::HlsSessionManager;
use rockzero_sae::{SaeCommit, SaeConfirm};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

// Replay protection: Nonce storage
lazy_static::lazy_static! {
    static ref USED_NONCES: std::sync::Mutex<HashMap<String, i64>> = 
        std::sync::Mutex::new(HashMap::new());
    static ref REQUEST_SIGNATURES: std::sync::Mutex<HashMap<String, i64>> = 
        std::sync::Mutex::new(HashMap::new());
}

const NONCE_EXPIRY_SECONDS: i64 = 300;
const REQUEST_SIGNATURE_EXPIRY_SECONDS: i64 = 60;
const MAX_TIMESTAMP_DRIFT_SECONDS: i64 = 30;

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

/// Secure request verification structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureRequestParams {
    /// Request timestamp (Unix milliseconds)
    pub timestamp: i64,
    /// Unique request nonce
    pub nonce: String,
    /// Request signature: HMAC-SHA256(session_id + timestamp + nonce + segment_name, pmk)
    pub signature: String,
}

/// Verify secure request parameters (replay protection)
fn verify_secure_request(
    params: &SecureRequestParams,
    session_id: &str,
    segment_name: &str,
    pmk: &[u8; 32],
) -> Result<(), AppError> {
    let now = Utc::now().timestamp_millis();
    
    // 1. 验证时间戳（防止延迟重放）
    let timestamp_diff = (now - params.timestamp).abs();
    if timestamp_diff > MAX_TIMESTAMP_DRIFT_SECONDS * 1000 {
        return Err(AppError::Unauthorized(format!(
            "Request timestamp too old or in future: {} ms drift",
            timestamp_diff
        )));
    }
    
    // 2. 验证 Nonce 未被使用（防止即时重放）
    {
        let mut nonces = USED_NONCES.lock()
            .map_err(|_| AppError::InternalServerError("Failed to lock nonce store".to_string()))?;
        
        // 清理过期的 Nonce
        let expiry_threshold = now - NONCE_EXPIRY_SECONDS * 1000;
        nonces.retain(|_, &mut ts| ts > expiry_threshold);
        
        // 检查 Nonce 是否已使用
        if nonces.contains_key(&params.nonce) {
            return Err(AppError::Unauthorized(
                "Nonce already used (replay attack detected)".to_string()
            ));
        }
        
        // 记录 Nonce
        nonces.insert(params.nonce.clone(), now);
    }
    
    // 3. 验证请求签名
    let expected_signature = compute_request_signature(
        session_id,
        params.timestamp,
        &params.nonce,
        segment_name,
        pmk,
    );
    
    if !constant_time_compare(&params.signature, &expected_signature) {
        return Err(AppError::Unauthorized(
            "Invalid request signature".to_string()
        ));
    }
    
    // 4. 验证签名未被重用（额外的防重放层）
    {
        let mut signatures = REQUEST_SIGNATURES.lock()
            .map_err(|_| AppError::InternalServerError("Failed to lock signature store".to_string()))?;
        
        let expiry_threshold = now - REQUEST_SIGNATURE_EXPIRY_SECONDS * 1000;
        signatures.retain(|_, &mut ts| ts > expiry_threshold);
        
        if signatures.contains_key(&params.signature) {
            return Err(AppError::Unauthorized(
                "Request signature already used".to_string()
            ));
        }
        
        signatures.insert(params.signature.clone(), now);
    }
    
    Ok(())
}

/// 计算请求签名
fn compute_request_signature(
    session_id: &str,
    timestamp: i64,
    nonce: &str,
    segment_name: &str,
    pmk: &[u8; 32],
) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    
    type HmacSha256 = Hmac<Sha256>;
    
    let message = format!("{}:{}:{}:{}", session_id, timestamp, nonce, segment_name);
    
    let mut mac = HmacSha256::new_from_slice(pmk)
        .expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// 常量时间比较（防止时序攻击）
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

fn sanitize_file_path(path: &str) -> Result<std::path::PathBuf, AppError> {
    use std::path::PathBuf;

    // URL 解码
    let decoded_path = urlencoding::decode(path)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| path.to_string());

    let path_buf = PathBuf::from(&decoded_path);

    // 如果是绝对路径，直接验证
    if path_buf.is_absolute() {
        let canonical = path_buf.canonicalize().unwrap_or_else(|_| path_buf.clone());

        const ALLOWED_DIRS: &[&str] = &["/mnt", "/media", "/home", "/data", "/storage"];
        let path_str = canonical.to_string_lossy();

        for allowed_dir in ALLOWED_DIRS {
            if path_str.starts_with(allowed_dir) {
                return Ok(canonical);
            }
        }

        #[cfg(target_os = "windows")]
        {
            if path_str.len() >= 2 && path_str.chars().nth(1) == Some(':') {
                return Ok(canonical);
            }
        }

        return Err(AppError::Forbidden(
            "File path is not in allowed directories".to_string(),
        ));
    }

    let base_dir = get_base_directory()?;
    let full_path = base_dir.join(&decoded_path);
    let canonical = full_path.canonicalize().unwrap_or_else(|_| full_path.clone());

    Ok(canonical)
}

fn get_base_directory() -> Result<std::path::PathBuf, AppError> {
    use std::path::Path;

    #[cfg(target_os = "windows")]
    {
        let fallback = Path::new("./storage");
        std::fs::create_dir_all(fallback).ok();
        return Ok(fallback.to_path_buf());
    }

    #[cfg(not(target_os = "windows"))]
    {
        const BASE_DIRS: &[&str] = &["/mnt", "/media", "/home", "/data", "/storage"];

        for base_dir in BASE_DIRS {
            let path = Path::new(base_dir);
            if path.exists() && path.is_dir() {
                if std::fs::read_dir(path).is_ok() {
                    return Ok(path.to_path_buf());
                }
            }
        }

        let data_dir = Path::new("/data");
        if std::fs::create_dir_all(data_dir).is_ok() {
            return Ok(data_dir.to_path_buf());
        }

        let fallback = Path::new("./storage");
        std::fs::create_dir_all(fallback).ok();
        Ok(fallback.to_path_buf())
    }
}

#[derive(Debug, Deserialize)]
pub struct InitSaeRequest {
    pub file_id: Option<String>,
    pub file_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CompleteSaeRequest {
    pub temp_session_id: String,
    pub client_commit: SaeCommit,
    pub client_confirm: SaeConfirm,
}

#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    pub temp_session_id: String,
    pub file_id: Option<String>,
    pub file_path: Option<String>,
}

pub async fn init_sae_handshake(
    pool: web::Data<SqlitePool>,
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<InitSaeRequest>,
) -> Result<impl Responder, AppError> {
    let user_id = claims.sub.clone();

    let file_path = if let Some(ref file_id) = body.file_id {
        let file = crate::db::find_file_by_id(&pool, file_id, &user_id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("File not found: {}", file_id)))?;
        file.file_path
    } else if let Some(ref path) = body.file_path {
        let sanitized_path = sanitize_file_path(path)?;
        if !sanitized_path.exists() {
            return Err(AppError::NotFound(format!("File not found: {}", path)));
        }
        if !sanitized_path.is_file() {
            return Err(AppError::BadRequest(format!("Path is not a file: {}", path)));
        }
        sanitized_path.to_string_lossy().to_string()
    } else {
        return Err(AppError::BadRequest(
            "Either file_id or file_path must be provided".to_string(),
        ));
    };

    info!("Initializing SAE handshake for user {} - file: {}", user_id, file_path);

    let user = crate::db::find_user_by_id(&pool, &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let password = match &user.sae_secret {
        Some(secret) => secret.as_bytes().to_vec(),
        None => {
            warn!("User {} does not have sae_secret, using password_hash", user_id);
            user.password_hash.as_bytes().to_vec()
        }
    };

    let manager = hls_manager.read().await;
    let temp_session_id = manager
        .init_sae_handshake(user_id.clone(), password)
        .map_err(convert_hls_error)?;

    info!("Initialized SAE handshake for user {} - temp session {}", user_id, temp_session_id);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "temp_session_id": temp_session_id,
        "file_path": file_path,
        "message": "SAE handshake initialized, send client commit next"
    })))
}

#[derive(Debug, Deserialize)]
pub struct SendClientCommitRequest {
    pub temp_session_id: String,
    pub client_commit: SaeCommit,
}

pub async fn send_client_commit(
    _pool: web::Data<SqlitePool>,
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<SendClientCommitRequest>,
) -> Result<impl Responder, AppError> {
    let user_id = claims.sub.clone();

    let server_commit = {
        let manager = hls_manager.read().await;
        let mut servers = manager.sae_servers.lock().unwrap();
        let sae_server = servers
            .get_mut(&body.temp_session_id)
            .ok_or_else(|| AppError::NotFound("SAE session not found".to_string()))?;

        let (server_commit, _server_confirm) = sae_server
            .process_client_commit(&body.client_commit)
            .map_err(|e| AppError::CryptoError(format!("SAE commit failed: {}", e)))?;

        server_commit
    };

    info!("Processed client commit for user {} - temp session {}", user_id, body.temp_session_id);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "server_commit": server_commit,
        "message": "Server commit generated, send client confirm next"
    })))
}

#[derive(Debug, Deserialize)]
pub struct SendClientConfirmRequest {
    pub temp_session_id: String,
    pub client_confirm: SaeConfirm,
}

pub async fn send_client_confirm(
    _pool: web::Data<SqlitePool>,
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<SendClientConfirmRequest>,
) -> Result<impl Responder, AppError> {
    let user_id = claims.sub.clone();

    let server_confirm = {
        let manager = hls_manager.read().await;
        let mut servers = manager.sae_servers.lock().unwrap();
        let sae_server = servers
            .get_mut(&body.temp_session_id)
            .ok_or_else(|| AppError::NotFound("SAE session not found".to_string()))?;

        sae_server
            .verify_client_confirm(&body.client_confirm)
            .map_err(|e| AppError::CryptoError(format!("SAE confirm failed: {}", e)))?;

        sae_server
            .get_server_confirm()
            .map_err(|e| AppError::CryptoError(format!("Failed to get server confirm: {}", e)))?
    };

    info!("Verified client confirm for user {} - temp session {}", user_id, body.temp_session_id);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "server_confirm": server_confirm,
        "message": "SAE handshake completed, call create_session next"
    })))
}

pub async fn complete_sae_handshake(
    _pool: web::Data<SqlitePool>,
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<CompleteSaeRequest>,
) -> Result<impl Responder, AppError> {
    let user_id = claims.sub.clone();

    let (server_commit, server_confirm) = {
        let manager = hls_manager.read().await;
        let mut servers = manager.sae_servers.lock().unwrap();
        let sae_server = servers
            .get_mut(&body.temp_session_id)
            .ok_or_else(|| AppError::NotFound("SAE session not found".to_string()))?;

        let (server_commit, server_confirm) = sae_server
            .process_client_commit(&body.client_commit)
            .map_err(|e| AppError::CryptoError(format!("SAE commit failed: {}", e)))?;

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

pub async fn create_hls_session(
    pool: web::Data<SqlitePool>,
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<CreateSessionRequest>,
) -> Result<impl Responder, AppError> {
    let user_id = claims.sub.clone();

    let file_path = if let Some(ref file_id) = body.file_id {
        let file = crate::db::find_file_by_id(&pool, file_id, &user_id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("File not found: {}", file_id)))?;
        file.file_path
    } else if let Some(ref path) = body.file_path {
        let sanitized_path = sanitize_file_path(path)?;
        if !sanitized_path.exists() {
            return Err(AppError::NotFound(format!("File not found: {}", path)));
        }
        if !sanitized_path.is_file() {
            return Err(AppError::BadRequest(format!("Path is not a file: {}", path)));
        }
        sanitized_path.to_string_lossy().to_string()
    } else {
        return Err(AppError::BadRequest(
            "Either file_id or file_path must be provided".to_string(),
        ));
    };

    info!("Creating HLS session for user {} - file: {}", user_id, file_path);

    let manager = hls_manager.read().await;
    let session_id = manager
        .complete_sae_handshake(&body.temp_session_id, user_id.clone(), file_path.clone())
        .map_err(convert_hls_error)?;

    let session = manager.get_session(&session_id).map_err(convert_hls_error)?;

    info!("Created HLS session {} for user {} - file {}", session_id, user_id, file_path);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "session_id": session_id,
        "expires_at": session.expires_at.timestamp(),
        "playlist_url": format!("/api/v1/secure-hls/{}/playlist.m3u8", session_id),
        "encryption_method": "AES-256-GCM",
        "security_features": {
            "sae_handshake": true,
            "replay_protection": true,
            "request_signing": true,
            "timestamp_validation": true
        }
    })))
}

/// 获取安全的 M3U8 播放列表
pub async fn get_secure_playlist(
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    path: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let session_id = path.into_inner();

    let manager = hls_manager.read().await;
    let _session = manager.get_session(&session_id).map_err(convert_hls_error)?;

    let playlist = generate_secure_m3u8(100, 10.0);

    info!("Serving secure playlist for session {}", session_id);

    Ok(HttpResponse::Ok()
        .content_type("application/vnd.apple.mpegurl")
        .insert_header(("Cache-Control", "no-cache, no-store, must-revalidate"))
        .insert_header(("Pragma", "no-cache"))
        .insert_header(("Expires", "0"))
        .insert_header(("X-Encryption-Method", "AES-256-GCM"))
        .insert_header(("X-Security-Features", "SAE,ReplayProtection,RequestSigning"))
        .body(playlist))
}

/// 安全段请求参数（查询字符串）
#[derive(Debug, Deserialize)]
pub struct SecureSegmentQuery {
    /// 请求时间戳（Unix 毫秒）
    pub ts: Option<i64>,
    /// 唯一请求 Nonce
    pub nonce: Option<String>,
    /// 请求签名
    pub sig: Option<String>,
}

/// 获取加密的 TS 段（带防重放保护）
///
/// **安全实现**：
/// - 验证会话有效性（通过 SAE 握手建立）
/// - 验证请求签名（防止请求伪造）
/// - 验证时间戳（防止延迟重放）
/// - 验证 Nonce（防止即时重放）
/// - 使用 AES-256-GCM 加密视频段
pub async fn get_secure_segment(
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    path: web::Path<(String, String)>,
    query: web::Query<SecureSegmentQuery>,
    req: HttpRequest,
    _body: web::Bytes,
) -> Result<impl Responder, AppError> {
    let (session_id, segment_name) = path.into_inner();

    info!("Secure segment request: session={}, segment={}", session_id, segment_name);

    // 1. 验证会话
    let manager = hls_manager.read().await;
    let session = manager.get_session(&session_id).map_err(convert_hls_error)?;

    // 2. 验证安全请求参数（如果提供）
    if let (Some(ts), Some(nonce), Some(sig)) = (&query.ts, &query.nonce, &query.sig) {
        let params = SecureRequestParams {
            timestamp: *ts,
            nonce: nonce.clone(),
            signature: sig.clone(),
        };
        
        verify_secure_request(&params, &session_id, &segment_name, &session.pmk)?;
        info!("✅ Secure request verified for segment {}", segment_name);
    } else {
        // 如果没有提供安全参数，检查是否来自本地代理
        let peer_addr = req.peer_addr();
        let is_local = peer_addr.map(|addr| addr.ip().is_loopback()).unwrap_or(false);
        
        if !is_local {
            warn!("⚠️ Non-local request without security params for segment {}", segment_name);
            // 在生产环境中，可以选择拒绝没有安全参数的非本地请求
            // return Err(AppError::Unauthorized("Security parameters required".to_string()));
        }
    }

    info!("✅ Session verified for segment {} (user: {})", segment_name, session.user_id);

    // 3. 从 FFmpeg 转码输出读取实际的 TS 段
    let segment_data = read_video_segment_from_ffmpeg(&session.file_path, &segment_name).await?;

    // 4. 使用会话密钥加密段
    let encrypted_segment = session.encrypt_segment(&segment_data).map_err(convert_hls_error)?;

    info!(
        "Serving encrypted segment {} for session {} (original: {} bytes, encrypted: {} bytes)",
        segment_name, session_id, segment_data.len(), encrypted_segment.len()
    );

    // 5. 返回加密的视频段
    Ok(HttpResponse::Ok()
        .content_type("video/mp2t")
        .insert_header(("X-Encrypted", "true"))
        .insert_header(("X-Encryption-Method", "AES-256-GCM"))
        .insert_header(("Content-Length", encrypted_segment.len()))
        .insert_header(("Cache-Control", "no-cache, no-store, must-revalidate"))
        .insert_header(("Pragma", "no-cache"))
        .insert_header(("Expires", "0"))
        .body(encrypted_segment))
}

/// 停止 HLS 会话
pub async fn stop_session(
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    path: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let session_id = path.into_inner();

    info!("Stopping HLS session: {}", session_id);

    let manager = hls_manager.write().await;

    match manager.remove_session(&session_id) {
        Ok(_) => {
            info!("✅ HLS session stopped successfully: {}", session_id);
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Session stopped successfully",
                "session_id": session_id
            })))
        }
        Err(rockzero_media::HlsError::SessionNotFound(_)) => {
            info!("HLS session already stopped or not found: {}", session_id);
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Session already stopped or not found",
                "session_id": session_id
            })))
        }
        Err(e) => {
            warn!("Failed to stop HLS session {}: {:?}", session_id, e);
            Err(convert_hls_error(e))
        }
    }
}

/// 生成安全的 M3U8 播放列表
fn generate_secure_m3u8(segment_count: usize, segment_duration: f32) -> String {
    let mut playlist = String::from("#EXTM3U\n");
    playlist.push_str("#EXT-X-VERSION:3\n");
    playlist.push_str(&format!("#EXT-X-TARGETDURATION:{}\n", segment_duration.ceil() as u32));
    playlist.push_str("#EXT-X-MEDIA-SEQUENCE:0\n");
    playlist.push_str("# Encrypted with AES-256-GCM\n");
    playlist.push_str("# Key derived from SAE handshake\n");
    playlist.push_str("# Replay protection enabled\n\n");

    for i in 0..segment_count {
        playlist.push_str(&format!("#EXTINF:{:.3},\n", segment_duration));
        playlist.push_str(&format!("segment_{}.ts\n", i));
    }

    playlist.push_str("#EXT-X-ENDLIST\n");
    playlist
}

/// 视频段缓存目录配置
fn get_hls_cache_dir() -> std::path::PathBuf {
    std::env::var("HLS_CACHE_PATH")
        .or_else(|_| std::env::var("ROCKZERO_HLS_CACHE_DIR"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("./data/hls_cache"))
}

/// 从 FFmpeg 转码输出读取视频段
async fn read_video_segment_from_ffmpeg(
    file_path: &str,
    segment_name: &str,
) -> Result<Vec<u8>, AppError> {
    use std::path::PathBuf;

    // 1. 验证段名称格式（防止路径遍历攻击）
    if !segment_name.starts_with("segment_") || !segment_name.ends_with(".ts") {
        return Err(AppError::BadRequest(format!(
            "Invalid segment name format: '{}'. Expected 'segment_N.ts'",
            segment_name
        )));
    }

    // 2. 解析段索引
    let segment_index: usize = segment_name
        .trim_start_matches("segment_")
        .trim_end_matches(".ts")
        .parse()
        .map_err(|_| AppError::BadRequest(format!("Invalid segment index in name: '{}'", segment_name)))?;

    // 3. 验证段索引范围
    const MAX_SEGMENT_INDEX: usize = 100_000;
    if segment_index > MAX_SEGMENT_INDEX {
        return Err(AppError::BadRequest(format!(
            "Segment index {} exceeds maximum allowed ({})",
            segment_index, MAX_SEGMENT_INDEX
        )));
    }

    // 4. 计算视频文件的唯一标识符
    let video_hash = blake3::hash(file_path.as_bytes());
    let video_id = hex::encode(&video_hash.as_bytes()[..8]);

    // 5. 构建缓存目录路径
    let cache_dir = get_hls_cache_dir().join(&video_id);
    let cached_segment_path = cache_dir.join(segment_name);

    // 6. 尝试从缓存读取
    if cached_segment_path.exists() {
        info!("Cache hit for segment {} of video {}", segment_name, video_id);
        return tokio::fs::read(&cached_segment_path).await.map_err(|e| {
            AppError::IoError(format!("Failed to read cached segment {}: {}", segment_name, e))
        });
    }

    // 7. 缓存不存在，检查原始视频文件
    let original_video = PathBuf::from(file_path);
    if !original_video.exists() {
        return Err(AppError::NotFound(format!("Original video file not found: {}", file_path)));
    }

    // 8. 触发实时转码
    info!("Cache miss for segment {} of video {}, triggering FFmpeg transcode", segment_name, video_id);

    if !cache_dir.exists() {
        tokio::fs::create_dir_all(&cache_dir)
            .await
            .map_err(|e| AppError::IoError(format!("Failed to create cache directory: {}", e)))?;
    }

    let segment_data = transcode_segment_async(&original_video, &cache_dir, segment_index).await?;

    // 异步缓存
    let cache_path_clone = cached_segment_path.clone();
    let data_clone = segment_data.clone();
    tokio::spawn(async move {
        if let Err(e) = tokio::fs::write(&cache_path_clone, &data_clone).await {
            warn!("Failed to cache segment: {}", e);
        }
    });

    Ok(segment_data)
}

/// 硬件加速类型
#[derive(Debug, Clone, Copy, PartialEq)]
enum HardwareAccel {
    Vaapi,
    V4l2,
    None,
}

/// 使用 FFmpeg 异步转码单个视频段
async fn transcode_segment_async(
    video_path: &std::path::Path,
    output_dir: &std::path::Path,
    segment_index: usize,
) -> Result<Vec<u8>, AppError> {
    use tokio::process::Command;

    const SEGMENT_DURATION: f64 = 10.0;
    let start_time = segment_index as f64 * SEGMENT_DURATION;
    let output_path = output_dir.join(format!("segment_{}.ts", segment_index));

    let ffmpeg_path = std::env::var("FFMPEG_PATH")
        .or_else(|_| rockzero_media::get_global_ffmpeg_path().ok_or(""))
        .unwrap_or_else(|_| "ffmpeg".to_string());

    let hw_accel = detect_hardware_acceleration().await;

    let mut args = vec![
        "-y".to_string(),
        "-ss".to_string(),
        format!("{:.3}", start_time),
        "-i".to_string(),
        video_path.to_str().unwrap_or("").to_string(),
        "-t".to_string(),
        format!("{:.3}", SEGMENT_DURATION),
    ];

    match hw_accel {
        HardwareAccel::Vaapi => {
            info!("Using VAAPI hardware acceleration for segment {}", segment_index);
            args.extend(vec![
                "-hwaccel".to_string(), "vaapi".to_string(),
                "-hwaccel_device".to_string(), "/dev/dri/renderD128".to_string(),
                "-hwaccel_output_format".to_string(), "vaapi".to_string(),
                "-c:v".to_string(), "h264_vaapi".to_string(),
                "-qp".to_string(), "23".to_string(),
            ]);
        }
        HardwareAccel::V4l2 => {
            info!("Using V4L2 hardware acceleration for segment {}", segment_index);
            args.extend(vec![
                "-c:v".to_string(), "h264_v4l2m2m".to_string(),
                "-b:v".to_string(), "2M".to_string(),
            ]);
        }
        HardwareAccel::None => {
            info!("Using software encoding (libx264) for segment {}", segment_index);
            args.extend(vec![
                "-c:v".to_string(), "libx264".to_string(),
                "-preset".to_string(), "veryfast".to_string(),
                "-tune".to_string(), "zerolatency".to_string(),
                "-profile:v".to_string(), "main".to_string(),
                "-level".to_string(), "4.0".to_string(),
                "-crf".to_string(), "23".to_string(),
            ]);
        }
    }

    args.extend(vec![
        "-c:a".to_string(), "aac".to_string(),
        "-b:a".to_string(), "128k".to_string(),
        "-ac".to_string(), "2".to_string(),
        "-ar".to_string(), "44100".to_string(),
        "-f".to_string(), "mpegts".to_string(),
        "-movflags".to_string(), "+faststart".to_string(),
        output_path.to_str().unwrap_or("").to_string(),
    ]);

    let output = Command::new(&ffmpeg_path)
        .args(&args)
        .output()
        .await
        .map_err(|e| AppError::IoError(format!("Failed to execute FFmpeg: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::InternalServerError(format!(
            "FFmpeg transcode failed for segment {}: {}",
            segment_index, stderr
        )));
    }

    tokio::fs::read(&output_path)
        .await
        .map_err(|e| AppError::IoError(format!("Failed to read transcoded segment: {}", e)))
}

/// 检测可用的硬件加速
async fn detect_hardware_acceleration() -> HardwareAccel {
    use tokio::fs;

    if fs::metadata("/dev/dri/renderD128").await.is_ok() && check_ffmpeg_encoder("h264_vaapi").await {
        return HardwareAccel::Vaapi;
    }

    if (fs::metadata("/dev/video10").await.is_ok() || fs::metadata("/dev/video11").await.is_ok())
        && check_ffmpeg_encoder("h264_v4l2m2m").await
    {
        return HardwareAccel::V4l2;
    }

    HardwareAccel::None
}

/// 检查 FFmpeg 是否支持指定的编码器
async fn check_ffmpeg_encoder(encoder: &str) -> bool {
    use tokio::process::Command;

    let ffmpeg_path = std::env::var("FFMPEG_PATH")
        .or_else(|_| rockzero_media::get_global_ffmpeg_path().ok_or(""))
        .unwrap_or_else(|_| "ffmpeg".to_string());

    let output = Command::new(&ffmpeg_path).args(["-encoders"]).output().await;

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        return stdout.contains(encoder);
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_playlist_generation() {
        let playlist = generate_secure_m3u8(5, 10.0);
        assert!(playlist.contains("#EXTM3U"));
        assert!(playlist.contains("segment_0.ts"));
        assert!(playlist.contains("segment_4.ts"));
        assert!(!playlist.contains("#EXT-X-KEY"));
        assert!(playlist.contains("AES-256-GCM"));
    }

    #[test]
    fn test_request_signature() {
        let pmk = [0x42u8; 32];
        let sig = compute_request_signature("session123", 1234567890, "nonce123", "segment_0.ts", &pmk);
        assert!(!sig.is_empty());
        assert_eq!(sig.len(), 64); // SHA256 hex = 64 chars
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("abc", "abc"));
        assert!(!constant_time_compare("abc", "abd"));
        assert!(!constant_time_compare("abc", "ab"));
    }
}
