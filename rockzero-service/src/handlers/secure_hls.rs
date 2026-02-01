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
    let segment_duration = 10.0f64;
    let segment_count = ((duration / segment_duration).ceil() as usize).max(1);

    let playlist = generate_secure_m3u8(segment_count, segment_duration as f32, duration);

    info!(
        "Serving secure playlist for session {} (duration: {:.1}s, segments: {})",
        session_id, duration, segment_count
    );

    Ok(HttpResponse::Ok()
        .content_type("application/vnd.apple.mpegurl")
        .insert_header(("Cache-Control", "no-cache, no-store, must-revalidate"))
        .insert_header(("Pragma", "no-cache"))
        .insert_header(("Expires", "0"))
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

    info!(
        "Secure segment request: session={}, segment={}",
        session_id, segment_name
    );

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
        info!("Secure request verified for segment {}", segment_name);
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

    info!(
        "Session verified for segment {} (user: {})",
        segment_name, session.user_id
    );

    let segment_data = read_video_segment_from_ffmpeg(&session.file_path, &segment_name).await?;

    // Validate segment data before encryption
    if segment_data.len() < 1024 {
        return Err(AppError::InternalServerError(format!(
            "Invalid segment data: only {} bytes (expected at least 1KB)",
            segment_data.len()
        )));
    }

    let encrypted_segment = session
        .encrypt_segment(&segment_data)
        .map_err(convert_hls_error)?;

    info!(
        "Serving encrypted segment {} for session {} (original: {} bytes, encrypted: {} bytes)",
        segment_name,
        session_id,
        segment_data.len(),
        encrypted_segment.len()
    );

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

    info!(
        "Prebuffer request: session={}, segment={}",
        session_id, segment_name
    );

    let manager = hls_manager.read().await;
    let session = manager
        .get_session(&session_id)
        .map_err(convert_hls_error)?;

    let segment_data = read_video_segment_from_ffmpeg(&session.file_path, &segment_name).await?;

    info!(
        "Prebuffered segment {} for session {} ({} bytes)",
        segment_name,
        session_id,
        segment_data.len()
    );

    Ok(HttpResponse::Ok()
        .insert_header(("X-Prebuffered", "true"))
        .insert_header(("X-Segment-Size", segment_data.len()))
        .finish())
}

fn generate_secure_m3u8(
    segment_count: usize,
    segment_duration: f32,
    total_duration: f64,
) -> String {
    let mut playlist = String::from("#EXTM3U\n");
    playlist.push_str("#EXT-X-VERSION:6\n");
    playlist.push_str("#EXT-X-PLAYLIST-TYPE:VOD\n");
    playlist.push_str(&format!(
        "#EXT-X-TARGETDURATION:{}\n",
        segment_duration.ceil() as u32
    ));
    playlist.push_str("#EXT-X-MEDIA-SEQUENCE:0\n");
    playlist.push_str("#EXT-X-INDEPENDENT-SEGMENTS\n");
    playlist.push_str("# Encrypted with AES-256-GCM (custom implementation)\n");
    playlist.push_str("# Key derived from SAE handshake\n");
    playlist.push_str("# Replay protection enabled\n\n");

    for i in 0..segment_count {
        // Calculate actual duration for this segment
        let segment_start = i as f64 * segment_duration as f64;
        let remaining = total_duration - segment_start;
        let actual_duration = if remaining < segment_duration as f64 {
            remaining.max(0.1)
        } else {
            segment_duration as f64
        };

        playlist.push_str(&format!("#EXTINF:{:.6},\n", actual_duration));
        playlist.push_str(&format!("segment_{}.ts\n", i));
    }

    playlist.push_str("#EXT-X-ENDLIST\n");
    playlist
}

fn get_hls_cache_dir() -> std::path::PathBuf {
    std::env::var("HLS_CACHE_PATH")
        .or_else(|_| std::env::var("ROCKZERO_HLS_CACHE_DIR"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("./data/hls_cache"))
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum HardwareAccel {
    AmlogicV4l2,
    Vaapi,
    V4l2Generic,
    None,
}

struct VideoInfo {
    duration: f64,
    has_video: bool,
    has_audio: bool,
    video_codec: String,
    width: u32,
    height: u32,
}

async fn probe_video_info(video_path: &std::path::Path) -> Result<VideoInfo, AppError> {
    use tokio::process::Command;

    let ffprobe_path = std::env::var("FFPROBE_PATH").unwrap_or_else(|_| "ffprobe".to_string());

    let output = Command::new(&ffprobe_path)
        .args([
            "-v",
            "quiet",
            "-print_format",
            "json",
            "-show_format",
            "-show_streams",
            video_path.to_str().unwrap_or(""),
        ])
        .output()
        .await
        .map_err(|e| AppError::IoError(format!("Failed to probe video: {}", e)))?;

    if !output.status.success() {
        return Err(AppError::InternalServerError("FFprobe failed".to_string()));
    }

    let json_str = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| AppError::InternalServerError(format!("Failed to parse ffprobe: {}", e)))?;

    let duration = json["format"]["duration"]
        .as_str()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);

    let streams = json["streams"].as_array();
    let mut has_video = false;
    let mut has_audio = false;
    let mut video_codec = String::new();
    let mut width = 0u32;
    let mut height = 0u32;

    if let Some(streams) = streams {
        for stream in streams {
            let codec_type = stream["codec_type"].as_str().unwrap_or("");
            if codec_type == "video" {
                has_video = true;
                video_codec = stream["codec_name"].as_str().unwrap_or("").to_string();
                width = stream["width"].as_u64().unwrap_or(0) as u32;
                height = stream["height"].as_u64().unwrap_or(0) as u32;
            } else if codec_type == "audio" {
                has_audio = true;
            }
        }
    }

    Ok(VideoInfo {
        duration,
        has_video,
        has_audio,
        video_codec,
        width,
        height,
    })
}

async fn detect_hardware_acceleration() -> HardwareAccel {
    use tokio::fs;

    if is_amlogic_device().await {
        if check_ffmpeg_encoder("h264_v4l2m2m").await {
            return HardwareAccel::AmlogicV4l2;
        }
    }

    if fs::metadata("/dev/dri/renderD128").await.is_ok() {
        if check_ffmpeg_encoder("h264_vaapi").await {
            return HardwareAccel::Vaapi;
        }
    }

    if fs::metadata("/dev/video10").await.is_ok() || fs::metadata("/dev/video11").await.is_ok() {
        if check_ffmpeg_encoder("h264_v4l2m2m").await {
            return HardwareAccel::V4l2Generic;
        }
    }

    HardwareAccel::None
}

async fn is_amlogic_device() -> bool {
    if let Ok(content) = tokio::fs::read_to_string("/proc/cpuinfo").await {
        if content.contains("Amlogic")
            || content.contains("A311D")
            || content.contains("S905")
            || content.contains("S922")
        {
            return true;
        }
    }
    if let Ok(content) = tokio::fs::read_to_string("/sys/firmware/devicetree/base/compatible").await
    {
        if content.contains("amlogic") || content.contains("meson") {
            return true;
        }
    }
    false
}

async fn check_ffmpeg_encoder(encoder: &str) -> bool {
    use tokio::process::Command;

    let ffmpeg_path = std::env::var("FFMPEG_PATH")
        .or_else(|_| rockzero_media::get_global_ffmpeg_path().ok_or(""))
        .unwrap_or_else(|_| "ffmpeg".to_string());

    if let Ok(output) = Command::new(&ffmpeg_path)
        .args(["-encoders"])
        .output()
        .await
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        return stdout.contains(encoder);
    }
    false
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
        // Validate cached segment - must be at least 1KB for a valid TS segment
        if let Ok(metadata) = tokio::fs::metadata(&cached_segment_path).await {
            if metadata.len() >= 1024 {
                info!(
                    "Cache hit for segment {} of video {} ({} bytes)",
                    segment_name,
                    video_id,
                    metadata.len()
                );
                return tokio::fs::read(&cached_segment_path).await.map_err(|e| {
                    AppError::IoError(format!("Failed to read cached segment: {}", e))
                });
            } else {
                // Invalid cached segment, delete and re-transcode
                warn!(
                    "Invalid cached segment {} ({} bytes), removing and re-transcoding",
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

    // Write to cache synchronously to avoid race conditions
    if let Err(e) = tokio::fs::write(&cached_segment_path, &segment_data).await {
        warn!("Failed to cache segment {}: {}", segment_name, e);
    } else {
        info!(
            "Cached segment {} ({} bytes)",
            segment_name,
            segment_data.len()
        );
    }

    Ok(segment_data)
}

async fn transcode_segment_with_seek(
    video_path: &std::path::Path,
    output_dir: &std::path::Path,
    segment_index: usize,
) -> Result<Vec<u8>, AppError> {
    use tokio::process::Command;

    const SEGMENT_DURATION: f64 = 10.0;
    let start_time = segment_index as f64 * SEGMENT_DURATION;
    let output_path = output_dir.join(format!("segment_{}.ts", segment_index));

    // Remove any existing output file first
    let _ = tokio::fs::remove_file(&output_path).await;

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

    let ffmpeg_path = std::env::var("FFMPEG_PATH")
        .or_else(|_| rockzero_media::get_global_ffmpeg_path().ok_or(""))
        .unwrap_or_else(|_| "ffmpeg".to_string());

    let hw_accel = detect_hardware_acceleration().await;
    let video_path_str = video_path.to_str().unwrap_or("");
    let output_path_str = output_path.to_str().unwrap_or("");

    // Always transcode for HLS compatibility
    let needs_transcode = true;

    info!(
        "Transcoding segment {} at {:.2}s with {:?}",
        segment_index, start_time, hw_accel
    );

    let args = build_ffmpeg_args(
        hw_accel,
        video_path_str,
        output_path_str,
        start_time,
        SEGMENT_DURATION,
        needs_transcode,
        &video_info,
    );

    info!("FFmpeg command: {} {}", ffmpeg_path, args.join(" "));

    let output = Command::new(&ffmpeg_path)
        .args(&args)
        .output()
        .await
        .map_err(|e| AppError::IoError(format!("FFmpeg execution failed: {}", e)))?;

    let mut transcode_success = output.status.success();

    if !transcode_success {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("FFmpeg failed with {:?}: {}", hw_accel, stderr);

        if hw_accel != HardwareAccel::None {
            info!("Retrying segment {} with software encoding", segment_index);

            // Remove any partial output
            let _ = tokio::fs::remove_file(&output_path).await;

            let fallback_args = build_ffmpeg_args(
                HardwareAccel::None,
                video_path_str,
                output_path_str,
                start_time,
                SEGMENT_DURATION,
                true,
                &video_info,
            );

            info!(
                "FFmpeg fallback command: {} {}",
                ffmpeg_path,
                fallback_args.join(" ")
            );

            let fallback_output = Command::new(&ffmpeg_path)
                .args(&fallback_args)
                .output()
                .await
                .map_err(|e| AppError::IoError(format!("FFmpeg fallback failed: {}", e)))?;

            if fallback_output.status.success() {
                transcode_success = true;
                info!(
                    "Fallback transcoding succeeded for segment {}",
                    segment_index
                );
            } else {
                let fallback_stderr = String::from_utf8_lossy(&fallback_output.stderr);
                return Err(AppError::InternalServerError(format!(
                    "Transcode failed for segment {}: {}",
                    segment_index, fallback_stderr
                )));
            }
        } else {
            return Err(AppError::InternalServerError(format!(
                "Transcode failed for segment {}: {}",
                segment_index, stderr
            )));
        }
    }

    if !transcode_success {
        return Err(AppError::InternalServerError(format!(
            "Transcode failed for segment {}",
            segment_index
        )));
    }

    // Wait a bit for file system to sync
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Read the transcoded segment
    let segment_data = tokio::fs::read(&output_path)
        .await
        .map_err(|e| AppError::IoError(format!("Failed to read transcoded segment: {}", e)))?;

    if segment_data.is_empty() {
        return Err(AppError::InternalServerError(format!(
            "Transcoded segment {} is empty",
            segment_index
        )));
    }

    if segment_data.len() < 1000 {
        warn!(
            "Segment {} is suspiciously small: {} bytes",
            segment_index,
            segment_data.len()
        );
    }

    info!(
        "✅ Segment {} transcoded successfully: {} bytes",
        segment_index,
        segment_data.len()
    );

    Ok(segment_data)
}

fn build_ffmpeg_args(
    hw_accel: HardwareAccel,
    input_path: &str,
    output_path: &str,
    start_time: f64,
    duration: f64,
    needs_transcode: bool,
    video_info: &Option<VideoInfo>,
) -> Vec<String> {
    let mut args = Vec::new();

    args.extend(
        ["-y", "-hide_banner", "-loglevel", "warning"]
            .iter()
            .map(|s| s.to_string()),
    );

    args.push("-ss".to_string());
    args.push(format!("{:.3}", start_time));

    match hw_accel {
        HardwareAccel::AmlogicV4l2 => {
            if std::path::Path::new("/dev/video10").exists() {
                args.extend(
                    ["-hwaccel", "v4l2m2m", "-c:v", "h264_v4l2m2m"]
                        .iter()
                        .map(|s| s.to_string()),
                );
            }
        }
        HardwareAccel::Vaapi => {
            args.extend(
                [
                    "-hwaccel",
                    "vaapi",
                    "-hwaccel_device",
                    "/dev/dri/renderD128",
                    "-hwaccel_output_format",
                    "vaapi",
                ]
                .iter()
                .map(|s| s.to_string()),
            );
        }
        HardwareAccel::V4l2Generic => {
            if std::path::Path::new("/dev/video10").exists() {
                args.extend(["-hwaccel", "v4l2m2m"].iter().map(|s| s.to_string()));
            }
        }
        HardwareAccel::None => {}
    }

    args.push("-i".to_string());
    args.push(input_path.to_string());

    args.push("-t".to_string());
    args.push(format!("{:.3}", duration));

    args.extend(
        ["-force_key_frames", "expr:gte(t,0)"]
            .iter()
            .map(|s| s.to_string()),
    );

    if needs_transcode {
        match hw_accel {
            HardwareAccel::AmlogicV4l2 => {
                args.extend(
                    [
                        "-c:v",
                        "h264_v4l2m2m",
                        "-b:v",
                        "4M",
                        "-maxrate",
                        "6M",
                        "-bufsize",
                        "8M",
                        "-g",
                        "30",
                        "-keyint_min",
                        "15",
                        "-num_output_buffers",
                        "32",
                        "-num_capture_buffers",
                        "16",
                    ]
                    .iter()
                    .map(|s| s.to_string()),
                );
            }
            HardwareAccel::Vaapi => {
                args.extend(
                    [
                        "-vf",
                        "format=nv12|vaapi,hwupload",
                        "-c:v",
                        "h264_vaapi",
                        "-qp",
                        "23",
                        "-g",
                        "30",
                        "-keyint_min",
                        "30",
                    ]
                    .iter()
                    .map(|s| s.to_string()),
                );
            }
            HardwareAccel::V4l2Generic => {
                args.extend(
                    [
                        "-c:v",
                        "h264_v4l2m2m",
                        "-b:v",
                        "3M",
                        "-maxrate",
                        "4M",
                        "-bufsize",
                        "6M",
                        "-g",
                        "30",
                        "-keyint_min",
                        "30",
                    ]
                    .iter()
                    .map(|s| s.to_string()),
                );
            }
            HardwareAccel::None => {
                args.extend(
                    [
                        "-c:v",
                        "libx264",
                        "-preset",
                        "fast",
                        "-tune",
                        "zerolatency",
                        "-profile:v",
                        "high",
                        "-level",
                        "4.1",
                        "-crf",
                        "22",
                        "-g",
                        "30",
                        "-keyint_min",
                        "30",
                        "-sc_threshold",
                        "0",
                        "-bf",
                        "2",
                        "-refs",
                        "3",
                    ]
                    .iter()
                    .map(|s| s.to_string()),
                );
            }
        }

        let target_height = video_info
            .as_ref()
            .map(|info| {
                if info.height > 1080 {
                    1080
                } else if info.height > 720 {
                    720
                } else {
                    info.height
                }
            })
            .unwrap_or(720);

        if video_info
            .as_ref()
            .map(|i| i.height > target_height)
            .unwrap_or(false)
        {
            match hw_accel {
                HardwareAccel::Vaapi => {}
                _ => {
                    args.push("-vf".to_string());
                    args.push(format!("scale=-2:{}", target_height));
                }
            }
        }
    } else {
        args.extend(["-c:v", "copy"].iter().map(|s| s.to_string()));
    }

    if video_info.as_ref().map(|i| i.has_audio).unwrap_or(true) {
        args.extend(
            [
                "-c:a",
                "aac",
                "-b:a",
                "192k",
                "-ac",
                "2",
                "-ar",
                "48000",
                "-async",
                "1",
                "-af",
                "aresample=async=1:first_pts=0",
            ]
            .iter()
            .map(|s| s.to_string()),
        );
    } else {
        args.push("-an".to_string());
    }

    args.extend(
        [
            "-f",
            "mpegts",
            "-mpegts_copyts",
            "0",
            "-output_ts_offset",
            "0",
            "-avoid_negative_ts",
            "make_zero",
            "-start_at_zero",
            "-max_muxing_queue_size",
            "2048",
            "-muxdelay",
            "0",
            "-muxpreload",
            "0",
        ]
        .iter()
        .map(|s| s.to_string()),
    );

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
