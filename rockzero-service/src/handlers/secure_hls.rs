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

lazy_static::lazy_static! {
    static ref USED_NONCES: std::sync::Mutex<HashMap<String, i64>> =
        std::sync::Mutex::new(HashMap::new());
    static ref REQUEST_SIGNATURES: std::sync::Mutex<HashMap<String, i64>> =
        std::sync::Mutex::new(HashMap::new());
}

/// Cached hardware acceleration detection result (detected once, reused for all segments)
static CACHED_HW_ACCEL: tokio::sync::OnceCell<HardwareAccel> =
    tokio::sync::OnceCell::const_new();

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureRequestParams {
    pub timestamp: i64,
    pub nonce: String,
    pub signature: String,
}

fn verify_secure_request(
    params: &SecureRequestParams,
    session_id: &str,
    segment_name: &str,
    pmk: &[u8; 32],
) -> Result<(), AppError> {
    let now = Utc::now().timestamp_millis();

    let timestamp_diff = (now - params.timestamp).abs();
    if timestamp_diff > MAX_TIMESTAMP_DRIFT_SECONDS * 1000 {
        return Err(AppError::Unauthorized(format!(
            "Request timestamp too old or in future: {} ms drift",
            timestamp_diff
        )));
    }

    {
        let mut nonces = USED_NONCES
            .lock()
            .map_err(|_| AppError::InternalServerError("Failed to lock nonce store".to_string()))?;

        let expiry_threshold = now - NONCE_EXPIRY_SECONDS * 1000;
        nonces.retain(|_, &mut ts| ts > expiry_threshold);

        if nonces.contains_key(&params.nonce) {
            return Err(AppError::Unauthorized(
                "Nonce already used (replay attack detected)".to_string(),
            ));
        }

        nonces.insert(params.nonce.clone(), now);
    }

    let expected_signature = compute_request_signature(
        session_id,
        params.timestamp,
        &params.nonce,
        segment_name,
        pmk,
    );

    if !constant_time_compare(&params.signature, &expected_signature) {
        return Err(AppError::Unauthorized(
            "Invalid request signature".to_string(),
        ));
    }

    {
        let mut signatures = REQUEST_SIGNATURES.lock().map_err(|_| {
            AppError::InternalServerError("Failed to lock signature store".to_string())
        })?;

        let expiry_threshold = now - REQUEST_SIGNATURE_EXPIRY_SECONDS * 1000;
        signatures.retain(|_, &mut ts| ts > expiry_threshold);

        if signatures.contains_key(&params.signature) {
            return Err(AppError::Unauthorized(
                "Request signature already used".to_string(),
            ));
        }

        signatures.insert(params.signature.clone(), now);
    }

    Ok(())
}

fn compute_request_signature(
    session_id: &str,
    timestamp: i64,
    nonce: &str,
    segment_name: &str,
    pmk: &[u8; 32],
) -> String {
    let message = format!("{}:{}:{}:{}", session_id, timestamp, nonce, segment_name);

    let mut input = Vec::with_capacity(32 + message.len());
    input.extend_from_slice(pmk);
    input.extend_from_slice(message.as_bytes());

    let hash = blake3::hash(&input);
    hex::encode(hash.as_bytes())
}

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

    let decoded_path = urlencoding::decode(path)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| path.to_string());

    let path_buf = PathBuf::from(&decoded_path);

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
    let canonical = full_path
        .canonicalize()
        .unwrap_or_else(|_| full_path.clone());

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
            return Err(AppError::BadRequest(format!(
                "Path is not a file: {}",
                path
            )));
        }
        sanitized_path.to_string_lossy().to_string()
    } else {
        return Err(AppError::BadRequest(
            "Either file_id or file_path must be provided".to_string(),
        ));
    };

    info!(
        "Initializing SAE handshake for user {} - file: {}",
        user_id, file_path
    );

    let user = crate::db::find_user_by_id(&pool, &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let password = match &user.sae_secret {
        Some(secret) => secret.as_bytes().to_vec(),
        None => {
            warn!(
                "User {} does not have sae_secret, using password_hash",
                user_id
            );
            user.password_hash.as_bytes().to_vec()
        }
    };

    let manager = hls_manager.read().await;
    let temp_session_id = manager
        .init_sae_handshake(user_id.clone(), password)
        .map_err(convert_hls_error)?;

    info!(
        "Initialized SAE handshake for user {} - temp session {}",
        user_id, temp_session_id
    );

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

    info!(
        "Processed client commit for user {} - temp session {}",
        user_id, body.temp_session_id
    );

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

    info!(
        "Verified client confirm for user {} - temp session {}",
        user_id, body.temp_session_id
    );

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

    info!(
        "Completed SAE handshake for user {} - temp session {}",
        user_id, body.temp_session_id
    );

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
            return Err(AppError::BadRequest(format!(
                "Path is not a file: {}",
                path
            )));
        }
        sanitized_path.to_string_lossy().to_string()
    } else {
        return Err(AppError::BadRequest(
            "Either file_id or file_path must be provided".to_string(),
        ));
    };

    info!(
        "Creating HLS session for user {} - file: {}",
        user_id, file_path
    );

    let manager = hls_manager.read().await;
    let session_id = manager
        .complete_sae_handshake(&body.temp_session_id, user_id.clone(), file_path.clone())
        .map_err(convert_hls_error)?;

    let session = manager
        .get_session(&session_id)
        .map_err(convert_hls_error)?;

    info!(
        "Created HLS session {} for user {} - file {}",
        session_id, user_id, file_path
    );

    // Generate a key verification hash (hash of encryption key + session_id)
    // This allows the client to verify their derived key matches without exposing the key
    let key_verification = {
        let mut input = Vec::with_capacity(32 + session_id.len());
        input.extend_from_slice(&session.encryption_key);
        input.extend_from_slice(session_id.as_bytes());
        let hash = blake3::hash(&input);
        hex::encode(&hash.as_bytes()[..16]) // First 16 bytes as hex
    };

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "session_id": session_id,
        "expires_at": session.expires_at.timestamp(),
        "playlist_url": format!("/api/v1/secure-hls/{}/playlist.m3u8", session_id),
        "encryption_method": "AES-256-GCM",
        "key_verification": key_verification,
        "security_features": {
            "sae_handshake": true,
            "replay_protection": true,
            "request_signing": true,
            "timestamp_validation": true
        }
    })))
}

pub async fn get_secure_playlist(
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    path: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let session_id = path.into_inner();

    let manager = hls_manager.read().await;
    let session = manager
        .get_session(&session_id)
        .map_err(convert_hls_error)?;

    // Get actual video duration
    let video_path = std::path::Path::new(&session.file_path);
    let video_info = probe_video_info(video_path).await.ok();

    let duration = video_info.as_ref().map(|i| i.duration).unwrap_or(600.0);
    let segment_duration = 6.0f64;
    let segment_count = ((duration / segment_duration).ceil() as usize).max(1);

    let playlist = generate_secure_m3u8(segment_count, segment_duration as f32, duration);

    info!(
        "Serving secure playlist for session {} (duration: {:.1}s, segments: {})",
        session_id, duration, segment_count
    );

    Ok(HttpResponse::Ok()
        .content_type("application/vnd.apple.mpegurl")
        .insert_header(("Cache-Control", "private, max-age=60"))
        .insert_header(("X-Encryption-Method", "AES-256-GCM"))
        .insert_header(("X-Security-Features", "SAE,ReplayProtection,RequestSigning"))
        .body(playlist))
}

#[derive(Debug, Deserialize)]
pub struct SecureSegmentQuery {
    pub ts: Option<i64>,
    pub nonce: Option<String>,
    pub sig: Option<String>,
}

pub async fn get_secure_segment(
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    path: web::Path<(String, String)>,
    query: web::Query<SecureSegmentQuery>,
    req: HttpRequest,
    _body: web::Bytes,
) -> Result<impl Responder, AppError> {
    let (session_id, segment_name) = path.into_inner();

    let manager = hls_manager.read().await;
    let session = manager
        .get_session(&session_id)
        .map_err(convert_hls_error)?;

    if let (Some(ts), Some(nonce), Some(sig)) = (&query.ts, &query.nonce, &query.sig) {
        let params = SecureRequestParams {
            timestamp: *ts,
            nonce: nonce.clone(),
            signature: sig.clone(),
        };

        verify_secure_request(&params, &session_id, &segment_name, &session.pmk)?;
    } else {
        let peer_addr = req.peer_addr();
        let is_local = peer_addr
            .map(|addr| addr.ip().is_loopback())
            .unwrap_or(false);

        if !is_local {
            warn!(
                "Non-local request without security params for segment {}",
                segment_name
            );
        }
    }

    let segment_data = read_video_segment_from_ffmpeg(&session.file_path, &segment_name).await?;

    // Validate segment data before encryption
    if segment_data.len() < 188 {
        return Err(AppError::InternalServerError(format!(
            "Invalid segment data: only {} bytes",
            segment_data.len()
        )));
    }

    let encrypted_segment = session
        .encrypt_segment(&segment_data)
        .map_err(convert_hls_error)?;

    // Spawn background pre-transcoding for nearby segments (more aggressive for 4K)
    let file_path = session.file_path.clone();
    let seg_name = segment_name.clone();
    tokio::spawn(async move {
        let _ = prefetch_nearby_segments(&file_path, &seg_name).await;
    });

    let encrypted_len = encrypted_segment.len();

    Ok(HttpResponse::Ok()
        .content_type("video/mp2t")
        .insert_header(("X-Encrypted", "true"))
        .insert_header(("X-Encryption-Method", "AES-256-GCM"))
        .insert_header(("Content-Length", encrypted_len))
        .insert_header(("Cache-Control", "private, max-age=300"))
        .insert_header(("Connection", "keep-alive"))
        .insert_header(("X-Segment-Size", encrypted_len.to_string()))
        .body(encrypted_segment))
}

/// Pre-transcode nearby segments in the background so seeks are instant
async fn prefetch_nearby_segments(file_path: &str, current_segment: &str) -> Result<(), AppError> {
    let segment_index: usize = current_segment
        .trim_start_matches("segment_")
        .trim_end_matches(".ts")
        .parse()
        .unwrap_or(0);

    let video_hash = blake3::hash(file_path.as_bytes());
    let video_id = hex::encode(&video_hash.as_bytes()[..8]);
    let cache_dir = get_hls_cache_dir().join(&video_id);

    if !cache_dir.exists() {
        tokio::fs::create_dir_all(&cache_dir).await.ok();
    }

    // Pre-transcode next 10 segments ahead, 5 at a time (aggressive for 4K)
    let mut tasks = Vec::new();
    for offset in 1..=10 {
        let idx = segment_index + offset;
        let seg_path = cache_dir.join(format!("segment_{}.ts", idx));

        // Skip if already cached and valid
        if seg_path.exists() {
            if let Ok(meta) = tokio::fs::metadata(&seg_path).await {
                if meta.len() >= 188 {
                    continue;
                }
                // Remove invalid cache
                let _ = tokio::fs::remove_file(&seg_path).await;
            }
        }

        let video_path = std::path::PathBuf::from(file_path);
        let dir = cache_dir.clone();
        tasks.push(tokio::spawn(async move {
            let _ = transcode_segment_with_seek(&video_path, &dir, idx).await;
        }));

        // Limit concurrency: wait for batch of 5 before spawning more
        if tasks.len() >= 5 {
            for t in tasks.drain(..) {
                let _ = t.await;
            }
        }
    }

    // Await remaining tasks
    for t in tasks {
        let _ = t.await;
    }

    Ok(())
}

pub async fn stop_session(
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    path: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let session_id = path.into_inner();

    info!("Stopping HLS session: {}", session_id);

    let manager = hls_manager.write().await;

    match manager.remove_session(&session_id) {
        Ok(_) => {
            info!("HLS session stopped successfully: {}", session_id);
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

pub async fn prebuffer_segment(
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    path: web::Path<(String, String)>,
) -> Result<impl Responder, AppError> {
    let (session_id, segment_name) = path.into_inner();

    let manager = hls_manager.read().await;
    let session = manager
        .get_session(&session_id)
        .map_err(convert_hls_error)?;

    // Pre-transcode the requested segment and nearby ones in background
    let file_path = session.file_path.clone();
    let seg_name = segment_name.clone();
    tokio::spawn(async move {
        // Transcode the target segment first
        let _ = read_video_segment_from_ffmpeg(&file_path, &seg_name).await;
        // Then prefetch nearby
        let _ = prefetch_nearby_segments(&file_path, &seg_name).await;
    });

    Ok(HttpResponse::Ok()
        .insert_header(("X-Prebuffered", "true"))
        .finish())
}

fn generate_secure_m3u8(
    segment_count: usize,
    segment_duration: f32,
    total_duration: f64,
) -> String {
    let mut playlist = String::from("#EXTM3U\n");
    playlist.push_str("#EXT-X-VERSION:3\n");
    playlist.push_str("#EXT-X-PLAYLIST-TYPE:VOD\n");
    playlist.push_str(&format!(
        "#EXT-X-TARGETDURATION:{}\n",
        segment_duration.ceil() as u32
    ));
    playlist.push_str("#EXT-X-MEDIA-SEQUENCE:0\n");
    playlist.push_str("# Encrypted with AES-256-GCM\n\n");

    for i in 0..segment_count {
        let segment_start = i as f64 * segment_duration as f64;
        let remaining = total_duration - segment_start;
        let actual_duration = if remaining < segment_duration as f64 {
            remaining.max(0.1)
        } else {
            segment_duration as f64
        };

        // 使用整数秒，兼容性更好
        playlist.push_str(&format!("#EXTINF:{:.3},\n", actual_duration));
        playlist.push_str(&format!("segment_{}.ts\n", i));
    }

    playlist.push_str("#EXT-X-ENDLIST\n");
    playlist
}

fn get_hls_cache_dir() -> std::path::PathBuf {
    // 优先使用环境变量指定的 HLS 缓存路径
    // 然后使用外部存储路径（用户选择的外部存储设备，不是 eMMC）
    // 最后使用默认路径
    std::env::var("HLS_CACHE_PATH")
        .or_else(|_| std::env::var("ROCKZERO_HLS_CACHE_DIR"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            if let Ok(ext) = std::env::var("EXTERNAL_STORAGE_PATH") {
                std::path::PathBuf::from(ext).join("hls_cache")
            } else {
                std::path::PathBuf::from("/mnt/external/hls_cache")
            }
        })
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum HardwareAccel {
    AmlogicV4l2,       // Amlogic A311D/S905/S922 - V4L2 M2M 硬件编码
    AmlogicDecodeOnly, // Amlogic 仅硬件解码 (meson_vdec)，软件编码
    Vaapi,             // Intel/AMD GPU
    V4l2Generic,       // 通用 V4L2
    RockchipRga,       // Rockchip RK3588 等
    None,              // 纯软件编解码
}

struct VideoInfo {
    duration: f64,
    has_audio: bool,
    height: u32,
}

async fn probe_video_info(video_path: &std::path::Path) -> Result<VideoInfo, AppError> {
    use tokio::process::Command;
    use tokio::time::{timeout, Duration};

    let ffprobe_path = get_ffprobe_path();

    let output = timeout(
        Duration::from_secs(30),
        Command::new(&ffprobe_path)
            .args([
                "-v",
                "quiet",
                "-print_format",
                "json",
                "-show_format",
                "-show_streams",
                video_path.to_str().unwrap_or(""),
            ])
            .output(),
    )
    .await
    .map_err(|_| AppError::InternalServerError("FFprobe timeout".to_string()))?
    .map_err(|e| {
        AppError::IoError(format!(
            "Failed to probe video: {}. FFprobe path: {}",
            e, ffprobe_path
        ))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::InternalServerError(format!(
            "FFprobe failed: {}",
            stderr
        )));
    }

    let json_str = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| AppError::InternalServerError(format!("Failed to parse ffprobe: {}", e)))?;

    let duration = json["format"]["duration"]
        .as_str()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);

    let streams = json["streams"].as_array();
    let mut has_audio = false;
    let mut height = 0u32;

    if let Some(streams) = streams {
        for stream in streams {
            let codec_type = stream["codec_type"].as_str().unwrap_or("");
            if codec_type == "video" {
                height = stream["height"].as_u64().unwrap_or(0) as u32;
            } else if codec_type == "audio" {
                has_audio = true;
            }
        }
    }

    Ok(VideoInfo {
        duration,
        has_audio,
        height,
    })
}

#[allow(dead_code)]
async fn detect_hardware_acceleration() -> HardwareAccel {
    use tokio::fs;
    use tokio::time::{timeout, Duration};

    // 1. 首先检测 Amlogic 设备 (A311D, S905, S922 等)
    // Amlogic 设备有 /dev/dri/renderD128 (Mali GPU) 但不支持 VAAPI
    // 必须在 VAAPI 检测之前处理，避免误判
    if is_amlogic_device().await {
        info!("Detected Amlogic device (A311D/S905/S922)");

        // 检查是否有 meson_vdec 模块（硬件解码支持）
        let has_meson_vdec = check_meson_vdec_available().await;

        // 检查 V4L2 编码器是否可用 - 使用更短的超时
        let has_v4l2_encoder = timeout(
            Duration::from_secs(3),
            check_ffmpeg_encoder_available("h264_v4l2m2m"),
        )
        .await
        .unwrap_or(false);

        if has_v4l2_encoder {
            // 使用更短的超时检测 V4L2 M2M
            let v4l2_works = timeout(Duration::from_secs(5), check_v4l2m2m_actually_works())
                .await
                .unwrap_or(false);

            if v4l2_works {
                info!("Amlogic V4L2 M2M hardware encoding available");
                return HardwareAccel::AmlogicV4l2;
            } else {
                warn!("V4L2 M2M test timeout or failed, falling back to software encoding");
            }
        }

        if has_meson_vdec {
            info!("Amlogic meson_vdec detected - using hardware decode + software encode");
            return HardwareAccel::AmlogicDecodeOnly;
        }

        // Amlogic 设备不支持 VAAPI (Mali GPU 不是 Intel/AMD)
        info!("Amlogic device: using pure software encoding (libx264)");
        return HardwareAccel::None;
    }

    // 2. 检测 Rockchip 设备 (RK3588, RK3399 等)
    // Rockchip 设备也可能有 /dev/dri 但不支持 VAAPI
    if is_rockchip_device().await {
        info!("Detected Rockchip device, checking MPP support...");
        if fs::metadata("/dev/rga").await.is_ok() || fs::metadata("/dev/mpp_service").await.is_ok()
        {
            if check_ffmpeg_encoder_available("h264_rkmpp").await {
                info!("Rockchip MPP hardware acceleration available");
                return HardwareAccel::RockchipRga;
            }
        }
        // Rockchip 设备不支持 VAAPI，直接返回软件编码
        info!("Rockchip device: using software encoding - MPP not available");
        return HardwareAccel::None;
    }

    // 3. 检测 VAAPI (仅限 Intel/AMD GPU)
    // 只有在确认是 Intel/AMD GPU 时才尝试 VAAPI
    if fs::metadata("/dev/dri/renderD128").await.is_ok() {
        if check_for_intel_amd_gpu().await {
            if check_vaapi_actually_works().await {
                if check_ffmpeg_encoder_available("h264_vaapi").await {
                    info!("VAAPI hardware acceleration available and verified (Intel/AMD GPU)");
                    return HardwareAccel::Vaapi;
                }
            } else {
                info!("VAAPI device exists but initialization failed");
            }
        } else {
            info!("/dev/dri/renderD128 exists but no Intel/AMD GPU detected - skipping VAAPI");
        }
    }

    // 4. 通用 V4L2 检测（最后尝试，用于其他 ARM 设备）
    if fs::metadata("/dev/video10").await.is_ok() || fs::metadata("/dev/video11").await.is_ok() {
        if check_ffmpeg_encoder_available("h264_v4l2m2m").await {
            if check_v4l2m2m_actually_works().await {
                info!("Generic V4L2 M2M hardware acceleration available");
                return HardwareAccel::V4l2Generic;
            }
        }
    }

    info!("No hardware acceleration available, using software encoding (libx264)");
    HardwareAccel::None
}

#[allow(dead_code)]
async fn is_rockchip_device() -> bool {
    if let Ok(content) = tokio::fs::read_to_string("/proc/cpuinfo").await {
        let content_lower = content.to_lowercase();
        if content_lower.contains("rockchip")
            || content_lower.contains("rk3588")
            || content_lower.contains("rk3399")
            || content_lower.contains("rk3568")
            || content_lower.contains("rk3566")
        {
            return true;
        }
    }

    // 检查设备树
    if let Ok(content) = tokio::fs::read_to_string("/sys/firmware/devicetree/base/compatible").await
    {
        let content_lower = content.to_lowercase();
        if content_lower.contains("rockchip") {
            return true;
        }
    }

    false
}

#[allow(dead_code)]
async fn check_vaapi_actually_works() -> bool {
    use tokio::process::Command;
    use tokio::time::{timeout, Duration};

    let has_intel_amd_gpu = check_for_intel_amd_gpu().await;
    if !has_intel_amd_gpu {
        info!(
            "No Intel/AMD GPU detected, VAAPI not applicable (Mali/ARM GPU does not support VAAPI)"
        );
        return false;
    }

    let ffmpeg_path = get_ffmpeg_path();

    // 检查 FFmpeg 是否存在
    if !std::path::Path::new(&ffmpeg_path).exists() && ffmpeg_path != "ffmpeg" {
        warn!("FFmpeg not found at {}, cannot verify VAAPI", ffmpeg_path);
        return false;
    }

    info!("Testing VAAPI initialization with FFmpeg...");

    // 尝试初始化 VAAPI 设备
    let result = timeout(
        Duration::from_secs(5),
        Command::new(&ffmpeg_path)
            .args([
                "-hide_banner",
                "-loglevel",
                "error",
                "-init_hw_device",
                "vaapi=va:/dev/dri/renderD128",
                "-f",
                "lavfi",
                "-i",
                "nullsrc=s=64x64:d=0.1",
                "-frames:v",
                "1",
                "-f",
                "null",
                "-",
            ])
            .output(),
    )
    .await;

    match result {
        Ok(Ok(output)) => {
            if output.status.success() {
                info!("VAAPI device initialization successful");
                return true;
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            // 检查常见的 VAAPI 错误
            if stderr.contains("Failed to initialise VAAPI")
                || stderr.contains("libva error")
                || stderr.contains("Device creation failed")
                || stderr.contains("unknown libva error")
                || stderr.contains("No device available")
            {
                info!("VAAPI device initialization failed: {}", stderr.trim());
                return false;
            }
            warn!("VAAPI test returned error: {}", stderr.trim());
            false
        }
        Ok(Err(e)) => {
            warn!("Failed to execute VAAPI test: {}", e);
            false
        }
        Err(_) => {
            warn!("VAAPI test timeout (5s)");
            false
        }
    }
}

#[allow(dead_code)]
async fn check_for_intel_amd_gpu() -> bool {
    if let Ok(mut entries) = tokio::fs::read_dir("/sys/class/drm").await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let device_path = path.join("device/vendor");
            if let Ok(vendor) = tokio::fs::read_to_string(&device_path).await {
                let vendor = vendor.trim();
                // Intel: 0x8086, AMD: 0x1002
                if vendor == "0x8086" || vendor == "0x1002" {
                    info!("Found Intel/AMD GPU: vendor {}", vendor);
                    return true;
                }
                if !vendor.is_empty() && vendor != "0x0000" {
                    info!("Found GPU with vendor {}, not Intel/AMD", vendor);
                }
            }
        }
    }

    // 方法 2: 检查 lspci 输出
    if let Ok(output) = tokio::process::Command::new("lspci")
        .args(["-n"])
        .output()
        .await
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("0300") || line.contains("0302") {
                    if line.contains("8086:") {
                        info!("Found Intel GPU via lspci: {}", line);
                        return true;
                    }
                    if line.contains("1002:") {
                        info!("Found AMD GPU via lspci: {}", line);
                        return true;
                    }
                }
            }
        }
    }

    if tokio::fs::metadata("/proc/driver/nvidia").await.is_ok() {
        info!("NVIDIA GPU detected - VAAPI not supported, use NVENC instead");
        return false;
    }

    if tokio::fs::metadata("/sys/class/misc/mali0").await.is_ok()
        || tokio::fs::metadata("/dev/mali0").await.is_ok()
        || tokio::fs::metadata("/dev/mali").await.is_ok()
    {
        info!("Mali GPU detected - VAAPI not supported on ARM GPUs");
        return false;
    }

    info!("No Intel/AMD GPU found");
    false
}

#[allow(dead_code)]
async fn check_v4l2m2m_actually_works() -> bool {
    use tokio::process::Command;
    use tokio::time::{timeout, Duration};

    let ffmpeg_path = get_ffmpeg_path();

    let result = timeout(
        Duration::from_secs(3),
        Command::new(&ffmpeg_path)
            .args([
                "-hide_banner",
                "-loglevel",
                "error",
                "-f",
                "lavfi",
                "-i",
                "nullsrc=s=64x64:d=0.1",
                "-c:v",
                "h264_v4l2m2m",
                "-frames:v",
                "1",
                "-f",
                "null",
                "-",
            ])
            .output(),
    )
    .await;

    match result {
        Ok(Ok(output)) => {
            if output.status.success() {
                info!("V4L2 M2M encoder test successful");
                return true;
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("V4L2 M2M encoder test failed: {}", stderr.trim());
            false
        }
        Ok(Err(e)) => {
            warn!("Failed to test V4L2 M2M: {}", e);
            false
        }
        Err(_) => {
            warn!("V4L2 M2M test timeout (5s) - hardware encoder not responding");
            false
        }
    }
}

#[allow(dead_code)]
async fn is_amlogic_device() -> bool {
    if let Ok(content) = tokio::fs::read_to_string("/proc/cpuinfo").await {
        let content_lower = content.to_lowercase();
        if content_lower.contains("amlogic")
            || content_lower.contains("a311d")
            || content_lower.contains("s905")
            || content_lower.contains("s922")
            || content_lower.contains("meson")
        {
            info!("Amlogic device detected via /proc/cpuinfo");
            return true;
        }
    }

    if let Ok(content) = tokio::fs::read_to_string("/sys/firmware/devicetree/base/compatible").await
    {
        let content_lower = content.to_lowercase();
        if content_lower.contains("amlogic") || content_lower.contains("meson") {
            info!("Amlogic device detected via device tree");
            return true;
        }
    }

    if tokio::fs::metadata("/sys/class/amhdmitx").await.is_ok() {
        info!("Amlogic device detected via /sys/class/amhdmitx");
        return true;
    }

    if tokio::fs::metadata("/dev/amvideo").await.is_ok() {
        info!("Amlogic device detected via /dev/amvideo");
        return true;
    }

    false
}

#[allow(dead_code)]
async fn check_meson_vdec_available() -> bool {
    if tokio::fs::metadata("/dev/video0").await.is_ok() {
        if let Ok(content) = tokio::fs::read_to_string("/sys/class/video4linux/video0/name").await {
            if content.to_lowercase().contains("meson")
                || content.to_lowercase().contains("vdec")
                || content.to_lowercase().contains("amlogic")
            {
                info!("meson_vdec device found: {}", content.trim());
                return true;
            }
        }
    }

    if let Ok(content) = tokio::fs::read_to_string("/proc/modules").await {
        if content.contains("meson_vdec") {
            info!("meson_vdec kernel module is loaded");
            return true;
        }
    }

    if check_ffmpeg_decoder_available("h264_v4l2m2m").await {
        if tokio::fs::metadata("/dev/video0").await.is_ok() {
            info!("V4L2 M2M decoder available with /dev/video0");
            return true;
        }
    }

    false
}

#[allow(dead_code)]
async fn check_ffmpeg_decoder_available(decoder: &str) -> bool {
    use tokio::process::Command;
    use tokio::time::{timeout, Duration};

    let ffmpeg_path = get_ffmpeg_path();

    let result = timeout(
        Duration::from_secs(10),
        Command::new(&ffmpeg_path).args(["-decoders"]).output(),
    )
    .await;

    match result {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let has_decoder = stdout.contains(decoder);
            if has_decoder {
                info!("FFmpeg decoder '{}' is available", decoder);
            }
            has_decoder
        }
        _ => false,
    }
}

#[allow(dead_code)]
async fn check_ffmpeg_encoder_available(encoder: &str) -> bool {
    use tokio::process::Command;
    use tokio::time::{timeout, Duration};

    let ffmpeg_path = get_ffmpeg_path();

    let result = timeout(
        Duration::from_secs(10),
        Command::new(&ffmpeg_path).args(["-encoders"]).output(),
    )
    .await;

    match result {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let has_encoder = stdout.contains(encoder);
            if has_encoder {
                info!("FFmpeg encoder '{}' is compiled in", encoder);
            } else {
                warn!("FFmpeg encoder '{}' is NOT available", encoder);
            }
            has_encoder
        }
        Ok(Err(e)) => {
            warn!("Failed to check FFmpeg encoder: {}", e);
            false
        }
        Err(_) => {
            warn!("Timeout checking FFmpeg encoder");
            false
        }
    }
}

fn get_ffmpeg_path() -> String {
    if let Ok(path) = std::env::var("FFMPEG_PATH") {
        if std::path::Path::new(&path).exists() {
            return path;
        }
    }

    if let Some(path) = rockzero_media::get_global_ffmpeg_path() {
        if std::path::Path::new(&path).exists() {
            return path;
        }
    }

    let data_dir = std::env::var("DATA_DIR").unwrap_or_else(|_| "./data".to_string());
    let candidates = [
        format!("{}/ffmpeg/ffmpeg", data_dir),
        "./data/ffmpeg/ffmpeg".to_string(),
        "/usr/bin/ffmpeg".to_string(),
        "/usr/local/bin/ffmpeg".to_string(),
        "/opt/ffmpeg/bin/ffmpeg".to_string(),
        "ffmpeg".to_string(),
    ];

    for candidate in &candidates {
        if std::path::Path::new(candidate).exists() {
            return candidate.clone();
        }
    }

    if let Ok(output) = std::process::Command::new("which").arg("ffmpeg").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return path;
            }
        }
    }

    "ffmpeg".to_string()
}

fn get_ffprobe_path() -> String {
    if let Ok(path) = std::env::var("FFPROBE_PATH") {
        if std::path::Path::new(&path).exists() {
            return path;
        }
    }

    if let Some(path) = rockzero_media::get_global_ffprobe_path() {
        if std::path::Path::new(&path).exists() {
            return path;
        }
    }

    let data_dir = std::env::var("DATA_DIR").unwrap_or_else(|_| "./data".to_string());
    let candidates = [
        format!("{}/ffmpeg/ffprobe", data_dir),
        "./data/ffmpeg/ffprobe".to_string(),
        "/usr/bin/ffprobe".to_string(),
        "/usr/local/bin/ffprobe".to_string(),
        "/opt/ffmpeg/bin/ffprobe".to_string(),
        "ffprobe".to_string(),
    ];

    for candidate in &candidates {
        if std::path::Path::new(candidate).exists() {
            return candidate.clone();
        }
    }

    if let Ok(output) = std::process::Command::new("which").arg("ffprobe").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return path;
            }
        }
    }

    "ffprobe".to_string()
}

async fn read_video_segment_from_ffmpeg(
    file_path: &str,
    segment_name: &str,
) -> Result<Vec<u8>, AppError> {
    use std::path::PathBuf;

    if !segment_name.starts_with("segment_") || !segment_name.ends_with(".ts") {
        return Err(AppError::BadRequest(format!(
            "Invalid segment name: '{}'",
            segment_name
        )));
    }

    let segment_index: usize = segment_name
        .trim_start_matches("segment_")
        .trim_end_matches(".ts")
        .parse()
        .map_err(|_| AppError::BadRequest(format!("Invalid segment index: '{}'", segment_name)))?;

    if segment_index > 100_000 {
        return Err(AppError::BadRequest("Segment index too large".to_string()));
    }

    let video_hash = blake3::hash(file_path.as_bytes());
    let video_id = hex::encode(&video_hash.as_bytes()[..8]);
    let cache_dir = get_hls_cache_dir().join(&video_id);
    let cached_segment_path = cache_dir.join(segment_name);

    if cached_segment_path.exists() {
        // Validate cached segment - must be at least 188 bytes (one TS packet)
        if let Ok(metadata) = tokio::fs::metadata(&cached_segment_path).await {
            if metadata.len() >= 188 {
                return tokio::fs::read(&cached_segment_path).await.map_err(|e| {
                    AppError::IoError(format!("Failed to read cached segment: {}", e))
                });
            } else {
                // Invalid cached segment, delete and re-transcode
                warn!(
                    "Invalid cached segment {} ({} bytes), removing",
                    segment_name,
                    metadata.len()
                );
                let _ = tokio::fs::remove_file(&cached_segment_path).await;
            }
        }
    }

    let original_video = PathBuf::from(file_path);
    if !original_video.exists() {
        return Err(AppError::NotFound(format!(
            "Video not found: {}",
            file_path
        )));
    }

    info!(
        "Cache miss for segment {} of video {}, transcoding",
        segment_name, video_id
    );

    if !cache_dir.exists() {
        tokio::fs::create_dir_all(&cache_dir)
            .await
            .map_err(|e| AppError::IoError(format!("Failed to create cache dir: {}", e)))?;
    }

    let segment_data =
        transcode_segment_with_seek(&original_video, &cache_dir, segment_index).await?;

    Ok(segment_data)
}

async fn transcode_segment_with_seek(
    video_path: &std::path::Path,
    output_dir: &std::path::Path,
    segment_index: usize,
) -> Result<Vec<u8>, AppError> {
    use tokio::process::Command;
    use tokio::time::{timeout, Duration};

    const SEGMENT_DURATION: f64 = 6.0;
    const TRANSCODE_TIMEOUT_SECS: u64 = 180; // 180s for re-encoding (4K needs more time)

    let start_time = segment_index as f64 * SEGMENT_DURATION;
    let output_path = output_dir.join(format!("segment_{}.ts", segment_index));

    // Use a temp file to avoid serving incomplete segments
    let temp_path = output_dir.join(format!(".segment_{}.ts.tmp", segment_index));

    // If final output already exists and is valid, return it
    if output_path.exists() {
        if let Ok(meta) = tokio::fs::metadata(&output_path).await {
            if meta.len() >= 188 {
                return tokio::fs::read(&output_path).await.map_err(|e| {
                    AppError::IoError(format!("Failed to read segment: {}", e))
                });
            }
        }
        let _ = tokio::fs::remove_file(&output_path).await;
    }

    // Remove any stale temp file
    let _ = tokio::fs::remove_file(&temp_path).await;

    // Check if we're beyond video duration
    let video_info = probe_video_info(video_path).await.ok();
    if let Some(ref info) = video_info {
        if start_time >= info.duration {
            return Err(AppError::BadRequest(format!(
                "Segment {} starts at {:.1}s but video is only {:.1}s long",
                segment_index, start_time, info.duration
            )));
        }
    }

    let ffmpeg_path = get_ffmpeg_path();

    let ffmpeg_exists = std::path::Path::new(&ffmpeg_path).exists();
    if !ffmpeg_exists && ffmpeg_path != "ffmpeg" {
        return Err(AppError::InternalServerError(format!(
            "FFmpeg not found at: {}",
            ffmpeg_path
        )));
    }

    let hw_accel = *CACHED_HW_ACCEL
        .get_or_init(|| async { detect_hardware_acceleration().await })
        .await;
    info!("Using hardware acceleration: {:?}", hw_accel);

    let video_path_str = video_path.to_str().unwrap_or("");
    let temp_path_str = temp_path.to_str().unwrap_or("");

    // 首先尝试精确 seek 模式（-ss 在 -i 之后，更精确但更慢）
    // 对于非零段落，使用两阶段 seek：先快速跳到附近关键帧，再精确定位
    let args = build_ffmpeg_args_optimized(
        hw_accel,
        video_path_str,
        temp_path_str,
        start_time,
        SEGMENT_DURATION,
        &video_info,
    );

    let output_result = timeout(
        Duration::from_secs(TRANSCODE_TIMEOUT_SECS),
        Command::new(&ffmpeg_path).args(&args).output(),
    )
    .await;

    let output = match output_result {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(AppError::IoError(format!(
                "FFmpeg execution failed for segment {}: {}",
                segment_index, e
            )));
        }
        Err(_) => {
            let _ = tokio::fs::remove_file(&temp_path).await;
            // 超时后尝试使用更快的 stream copy 模式作为 fallback
            warn!(
                "FFmpeg timeout for segment {} ({}s), trying fast fallback",
                segment_index, TRANSCODE_TIMEOUT_SECS
            );
            return transcode_segment_fast_fallback(
                video_path, output_dir, segment_index, start_time, SEGMENT_DURATION,
            )
            .await;
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let _ = tokio::fs::remove_file(&temp_path).await;
        warn!("FFmpeg failed for segment {}: {}", segment_index, stderr);

        // 如果 re-encode 失败，尝试 stream copy fallback
        if stderr.contains("Error") || stderr.contains("error") {
            warn!("Trying fast fallback for segment {}", segment_index);
            return transcode_segment_fast_fallback(
                video_path, output_dir, segment_index, start_time, SEGMENT_DURATION,
            )
            .await;
        }

        return Err(AppError::InternalServerError(format!(
            "Transcode failed for segment {}: {}",
            segment_index, stderr
        )));
    }

    // Wait briefly for filesystem sync
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

    if !temp_path.exists() {
        return Err(AppError::InternalServerError(format!(
            "Transcoded segment {} not found",
            segment_index
        )));
    }

    let segment_data = tokio::fs::read(&temp_path)
        .await
        .map_err(|e| AppError::IoError(format!("Failed to read segment: {}", e)))?;

    if segment_data.len() < 188 {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(AppError::InternalServerError(format!(
            "Segment {} too small: {} bytes",
            segment_index,
            segment_data.len()
        )));
    }

    // Atomically rename temp -> final (prevents serving partial files)
    if let Err(e) = tokio::fs::rename(&temp_path, &output_path).await {
        // Fallback: copy + delete
        warn!("Rename failed, using copy: {}", e);
        let _ = tokio::fs::write(&output_path, &segment_data).await;
        let _ = tokio::fs::remove_file(&temp_path).await;
    }

    info!(
        "Segment {} transcoded: {} bytes",
        segment_index,
        segment_data.len()
    );

    Ok(segment_data)
}

/// Fast fallback: 使用 stream copy 模式快速生成段落
/// 当 re-encode 超时或失败时使用，牺牲精确性换取速度
async fn transcode_segment_fast_fallback(
    video_path: &std::path::Path,
    output_dir: &std::path::Path,
    segment_index: usize,
    start_time: f64,
    duration: f64,
) -> Result<Vec<u8>, AppError> {
    use tokio::process::Command;
    use tokio::time::{timeout, Duration};

    let output_path = output_dir.join(format!("segment_{}.ts", segment_index));
    let temp_path = output_dir.join(format!(".segment_{}.ts.fast_tmp", segment_index));
    let _ = tokio::fs::remove_file(&temp_path).await;

    let ffmpeg_path = get_ffmpeg_path();
    let video_path_str = video_path.to_str().unwrap_or("");
    let temp_path_str = temp_path.to_str().unwrap_or("");

    // Stream copy 模式：不重新编码，直接复制流
    // 使用 -ss 在 -i 之前（input seeking）快速跳到关键帧
    // 然后 -ss 在 -i 之后做精确裁剪（output seeking）
    // 这种两阶段 seek 比纯 re-encode 快得多
    let coarse_seek = if start_time > 10.0 {
        start_time - 10.0 // 粗略跳到目标前 10 秒
    } else {
        0.0
    };
    let fine_seek = start_time - coarse_seek;

    let mut args = vec![
        "-y".to_string(),
        "-hide_banner".to_string(),
        "-loglevel".to_string(),
        "warning".to_string(),
    ];

    // 粗略 seek（在 -i 之前，快速跳到关键帧）
    if coarse_seek > 0.0 {
        args.extend(["-ss".to_string(), format!("{:.3}", coarse_seek)]);
    }

    args.extend(["-i".to_string(), video_path_str.to_string()]);

    // 精确 seek（在 -i 之后，精确定位）
    if fine_seek > 0.1 {
        args.extend(["-ss".to_string(), format!("{:.3}", fine_seek)]);
    }

    args.extend([
        "-t".to_string(),
        format!("{:.3}", duration),
        "-c:v".to_string(),
        "copy".to_string(),
        "-c:a".to_string(),
        "aac".to_string(),
        "-b:a".to_string(),
        "192k".to_string(),
        "-f".to_string(),
        "mpegts".to_string(),
        "-mpegts_copyts".to_string(),
        "0".to_string(),
        "-avoid_negative_ts".to_string(),
        "make_zero".to_string(),
        "-fflags".to_string(),
        "+genpts+discardcorrupt".to_string(),
        temp_path_str.to_string(),
    ]);

    let output = timeout(
        Duration::from_secs(30), // stream copy 应该很快
        Command::new(&ffmpeg_path).args(&args).output(),
    )
    .await
    .map_err(|_| {
        AppError::InternalServerError(format!(
            "Fast fallback timeout for segment {}",
            segment_index
        ))
    })?
    .map_err(|e| {
        AppError::IoError(format!(
            "Fast fallback failed for segment {}: {}",
            segment_index, e
        ))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(AppError::InternalServerError(format!(
            "Fast fallback transcode failed for segment {}: {}",
            segment_index, stderr
        )));
    }

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    let segment_data = tokio::fs::read(&temp_path)
        .await
        .map_err(|e| AppError::IoError(format!("Failed to read fast segment: {}", e)))?;

    if segment_data.len() < 188 {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(AppError::InternalServerError(format!(
            "Fast segment {} too small: {} bytes",
            segment_index,
            segment_data.len()
        )));
    }

    if let Err(e) = tokio::fs::rename(&temp_path, &output_path).await {
        let _ = tokio::fs::write(&output_path, &segment_data).await;
        let _ = tokio::fs::remove_file(&temp_path).await;
        warn!("Fast fallback rename failed: {}", e);
    }

    info!(
        "Segment {} fast-fallback: {} bytes (stream copy)",
        segment_index,
        segment_data.len()
    );

    Ok(segment_data)
}

fn build_ffmpeg_args_optimized(
    hw_accel: HardwareAccel,
    input_path: &str,
    output_path: &str,
    start_time: f64,
    duration: f64,
    video_info: &Option<VideoInfo>,
) -> Vec<String> {
    let mut args = Vec::new();

    args.extend([
        "-y".to_string(),
        "-hide_banner".to_string(),
        "-loglevel".to_string(),
        "warning".to_string(),
    ]);

    // 两阶段 seek 策略：
    // 1. -ss 在 -i 之前：快速跳到目标附近的关键帧（input seeking）
    // 2. -ss 在 -i 之后：精确定位到目标时间（output seeking）
    // 这比纯 output seeking 快得多，同时保持精确性
    let coarse_seek = if start_time > 15.0 {
        start_time - 15.0 // 粗略跳到目标前 15 秒（确保包含关键帧）
    } else {
        0.0
    };
    let fine_seek = start_time - coarse_seek;

    match hw_accel {
        HardwareAccel::Vaapi => {
            args.extend([
                "-hwaccel".to_string(),
                "vaapi".to_string(),
                "-hwaccel_device".to_string(),
                "/dev/dri/renderD128".to_string(),
                "-hwaccel_output_format".to_string(),
                "vaapi".to_string(),
            ]);
        }
        HardwareAccel::RockchipRga => {
            args.extend(["-hwaccel".to_string(), "rkmpp".to_string()]);
        }
        HardwareAccel::AmlogicDecodeOnly => {
            if std::path::Path::new("/dev/video0").exists() {
                args.extend([
                    "-hwaccel".to_string(),
                    "v4l2m2m".to_string(),
                ]);
            }
        }
        _ => {}
    }

    // 阶段 1: 粗略 seek（在 -i 之前，跳到关键帧）
    if coarse_seek > 0.0 {
        args.extend(["-ss".to_string(), format!("{:.3}", coarse_seek)]);
    }

    args.extend(["-i".to_string(), input_path.to_string()]);

    // 阶段 2: 精确 seek（在 -i 之后，精确定位）
    if fine_seek > 0.1 {
        args.extend(["-ss".to_string(), format!("{:.3}", fine_seek)]);
    }

    // 精确持续时间
    args.extend(["-t".to_string(), format!("{:.3}", duration)]);

    // 视频编码 - 必须 re-encode 以保证精确的段落边界
    match hw_accel {
        HardwareAccel::AmlogicV4l2 => {
            args.extend([
                "-c:v".to_string(),
                "h264_v4l2m2m".to_string(),
                "-b:v".to_string(),
                "4M".to_string(),
                "-g".to_string(),
                "60".to_string(),
            ]);
        }
        HardwareAccel::Vaapi => {
            args.extend([
                "-vf".to_string(),
                "format=nv12|vaapi,hwupload".to_string(),
                "-c:v".to_string(),
                "h264_vaapi".to_string(),
                "-qp".to_string(),
                "24".to_string(),
                "-g".to_string(),
                "60".to_string(),
            ]);
        }
        HardwareAccel::RockchipRga => {
            args.extend([
                "-c:v".to_string(),
                "h264_rkmpp".to_string(),
                "-b:v".to_string(),
                "4M".to_string(),
                "-g".to_string(),
                "60".to_string(),
            ]);
        }
        _ => {
            let height = video_info.as_ref().map(|i| i.height).unwrap_or(0);

            let scale_filter = if height > 1080 {
                Some("scale=-2:1080:flags=fast_bilinear".to_string())
            } else {
                None
            };

            if let Some(filter) = scale_filter {
                args.extend(["-vf".to_string(), filter]);
            }

            args.extend([
                "-c:v".to_string(),
                "libx264".to_string(),
                "-preset".to_string(),
                "ultrafast".to_string(),
                "-tune".to_string(),
                "zerolatency".to_string(),
                "-profile:v".to_string(),
                "high".to_string(),
                "-level".to_string(),
                "4.1".to_string(),
                "-crf".to_string(),
                "23".to_string(),
                "-g".to_string(),
                "150".to_string(),
                "-keyint_min".to_string(),
                "25".to_string(),
                "-sc_threshold".to_string(),
                "0".to_string(),
                "-bf".to_string(),
                "0".to_string(),
                "-threads".to_string(),
                "0".to_string(),
            ]);
        }
    }

    // 音频编码
    if video_info.as_ref().map(|i| i.has_audio).unwrap_or(true) {
        args.extend([
            "-c:a".to_string(),
            "aac".to_string(),
            "-b:a".to_string(),
            "192k".to_string(),
            "-ac".to_string(),
            "2".to_string(),
            "-ar".to_string(),
            "48000".to_string(),
        ]);
    } else {
        args.push("-an".to_string());
    }

    // MPEG-TS 输出参数
    args.extend([
        "-f".to_string(),
        "mpegts".to_string(),
        "-mpegts_copyts".to_string(),
        "0".to_string(),
        "-avoid_negative_ts".to_string(),
        "make_zero".to_string(),
        "-output_ts_offset".to_string(),
        "0".to_string(),
        "-max_muxing_queue_size".to_string(),
        "2048".to_string(),
        "-fflags".to_string(),
        "+genpts+discardcorrupt".to_string(),
    ]);

    args.push(output_path.to_string());
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_playlist_generation() {
        let playlist = generate_secure_m3u8(5, 10.0, 50.0);
        assert!(playlist.contains("#EXTM3U"));
        assert!(playlist.contains("segment_0.ts"));
        assert!(playlist.contains("segment_4.ts"));
        assert!(!playlist.contains("#EXT-X-KEY"));
        assert!(playlist.contains("AES-256-GCM"));
    }

    #[test]
    fn test_request_signature() {
        let pmk = [0x42u8; 32];
        let sig =
            compute_request_signature("session123", 1234567890, "nonce123", "segment_0.ts", &pmk);
        assert!(!sig.is_empty());
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("abc", "abc"));
        assert!(!constant_time_compare("abc", "abd"));
        assert!(!constant_time_compare("abc", "ab"));
    }
}
