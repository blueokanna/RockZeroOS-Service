use actix_web::{web, HttpResponse, Responder};
use rand::RngCore;
use rockzero_common::AppError;
use rockzero_crypto::{EnhancedPasswordProof, PasswordRegistration, ZkpContext};
use rockzero_media::{HlsSession, HlsSessionManager};
use rockzero_sae::{SaeCommit, SaeConfirm};
use serde::Deserialize;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use tokio::sync::RwLock;
use tracing::{info, warn};

static SAE_ANTI_CLOGGING_KEY: OnceLock<[u8; 32]> = OnceLock::new();
static SESSION_NO_DISK_MODE: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
static NO_DISK_SEGMENT_CACHE: OnceLock<Mutex<HashMap<String, NoDiskSegmentCacheEntry>>> =
    OnceLock::new();
static NO_DISK_SEGMENT_LOCKS: OnceLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> =
    OnceLock::new();
static NO_DISK_FALLBACK_WARNED: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
static HW_ACCEL_DETECTION_CACHE: OnceLock<HardwareAccel> = OnceLock::new();
static VIDEO_CODEC_CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
static EXTERNAL_CACHE_STARTUP_GUARD: OnceLock<Mutex<ExternalCacheStartupGuard>> =
    OnceLock::new();

const NO_DISK_SEGMENT_TTL_SECS: u64 = 300;
const NO_DISK_SEGMENT_MAX_ENTRIES: usize = 512;

#[derive(Clone)]
struct NoDiskSegmentCacheEntry {
    data: Vec<u8>,
    created_at: std::time::Instant,
}

#[derive(Clone)]
struct ExternalCacheStartupGuard {
    checked: bool,
    ready: bool,
    message: String,
}

fn no_disk_mode_registry() -> &'static Mutex<HashMap<String, bool>> {
    SESSION_NO_DISK_MODE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn set_session_no_disk_mode(session_id: &str, enabled: bool) {
    let mut modes = no_disk_mode_registry().lock().unwrap_or_else(|e| e.into_inner());
    modes.insert(session_id.to_string(), enabled);
}

fn clear_session_no_disk_mode(session_id: &str) {
    let mut modes = no_disk_mode_registry().lock().unwrap_or_else(|e| e.into_inner());
    modes.remove(session_id);

    // 清理 no-disk 告警去重键，防止长期运行造成无界增长。
    let mut warned = no_disk_fallback_warned_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    warned.remove(session_id);
}

pub fn get_no_disk_playback_status() -> (bool, usize) {
    let modes = no_disk_mode_registry().lock().unwrap_or_else(|e| e.into_inner());
    let count = modes.values().filter(|&&enabled| enabled).count();
    (count > 0, count)
}

fn no_disk_segment_cache() -> &'static Mutex<HashMap<String, NoDiskSegmentCacheEntry>> {
    NO_DISK_SEGMENT_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn no_disk_segment_locks() -> &'static Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>> {
    NO_DISK_SEGMENT_LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn no_disk_fallback_warned_registry() -> &'static Mutex<HashMap<String, bool>> {
    NO_DISK_FALLBACK_WARNED.get_or_init(|| Mutex::new(HashMap::new()))
}

fn video_codec_cache() -> &'static Mutex<HashMap<String, Option<String>>> {
    VIDEO_CODEC_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn external_cache_startup_guard() -> &'static Mutex<ExternalCacheStartupGuard> {
    EXTERNAL_CACHE_STARTUP_GUARD.get_or_init(|| {
        Mutex::new(ExternalCacheStartupGuard {
            checked: false,
            ready: false,
            message: "external cache guard has not been initialized".to_string(),
        })
    })
}

fn is_strict_external_cache_required() -> bool {
    if cfg!(test) {
        return false;
    }

    std::env::var("ROCKZERO_STRICT_EXTERNAL_HLS_CACHE")
        .ok()
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

pub fn initialize_external_cache_startup_guard() -> bool {
    let strict = is_strict_external_cache_required();

    let mut guard = external_cache_startup_guard()
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    if !strict {
        guard.checked = true;
        guard.ready = true;
        guard.message =
            "strict external HLS cache guard is disabled by ROCKZERO_STRICT_EXTERNAL_HLS_CACHE"
                .to_string();
        return true;
    }

    match ensure_external_hls_cache_root() {
        Ok(path) => {
            guard.checked = true;
            guard.ready = true;
            guard.message = format!(
                "external HLS cache validated at startup: {}",
                path.display()
            );
            true
        }
        Err(e) => {
            guard.checked = true;
            guard.ready = false;
            guard.message = format!(
                "external HLS cache startup validation failed: {}",
                e
            );
            false
        }
    }
}

fn get_cached_no_disk_segment(cache_key: &str) -> Option<Vec<u8>> {
    let mut cache = no_disk_segment_cache().lock().unwrap_or_else(|e| e.into_inner());
    cache.retain(|_, entry| {
        entry.created_at.elapsed() < std::time::Duration::from_secs(NO_DISK_SEGMENT_TTL_SECS)
    });
    cache.get(cache_key).map(|entry| entry.data.clone())
}

fn put_cached_no_disk_segment(cache_key: String, data: Vec<u8>) {
    let mut cache = no_disk_segment_cache().lock().unwrap_or_else(|e| e.into_inner());
    cache.retain(|_, entry| {
        entry.created_at.elapsed() < std::time::Duration::from_secs(NO_DISK_SEGMENT_TTL_SECS)
    });

    if cache.len() >= NO_DISK_SEGMENT_MAX_ENTRIES {
        let oldest_key = cache
            .iter()
            .min_by_key(|(_, entry)| entry.created_at)
            .map(|(k, _)| k.clone());
        if let Some(key) = oldest_key {
            cache.remove(&key);
        }
    }

    cache.insert(
        cache_key,
        NoDiskSegmentCacheEntry {
            data,
            created_at: std::time::Instant::now(),
        },
    );
}

fn get_no_disk_segment_lock(cache_key: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = no_disk_segment_locks().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(existing) = locks.get(cache_key) {
        return existing.clone();
    }

    let created = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(cache_key.to_string(), created.clone());
    created
}

fn release_no_disk_segment_lock(cache_key: &str) {
    let mut locks = no_disk_segment_locks().lock().unwrap_or_else(|e| e.into_inner());
    locks.remove(cache_key);
}

fn warn_no_disk_fallback_once(session_id: Option<&str>, segment_name: &str) {
    let Some(session_id) = session_id else {
        warn!(
            "External HLS cache unavailable, using no-disk transcoding for {}",
            segment_name
        );
        return;
    };

    let mut warned = no_disk_fallback_warned_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    if warned.contains_key(session_id) {
        return;
    }

    warned.insert(session_id.to_string(), true);
    warn!(
        "External HLS cache unavailable for session {}, switching to no-disk transcoding path (first segment: {})",
        session_id, segment_name
    );
}

fn parse_segment_index_from_name(segment_name: &str) -> Option<usize> {
    if !segment_name.starts_with("segment_") || !segment_name.ends_with(".ts") {
        return None;
    }

    segment_name
        .trim_start_matches("segment_")
        .trim_end_matches(".ts")
        .parse::<usize>()
        .ok()
}

fn prewarm_no_disk_segments(file_path: String, session_id: String, current_idx: usize) {
    tokio::spawn(async move {
        const PREWARM_WINDOW: usize = 2;
        for next in 1..=PREWARM_WINDOW {
            let idx = current_idx.saturating_add(next);
            let segment_name = format!("segment_{}.ts", idx);
            let _ = read_video_segment_from_ffmpeg(&file_path, &segment_name, Some(&session_id)).await;
        }
    });
}

fn get_sae_anti_clogging_key() -> &'static [u8; 32] {
    SAE_ANTI_CLOGGING_KEY.get_or_init(|| {
        if let Ok(secret_hex) = std::env::var("SAE_ANTI_CLOGGING_SECRET") {
            if let Ok(bytes) = hex::decode(secret_hex) {
                if bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    return key;
                }
            }
        }

        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        key
    })
}

fn compute_anti_clogging_token(temp_session_id: &str, user_id: &str) -> String {
    let key = get_sae_anti_clogging_key();
    let mut payload = Vec::with_capacity(32 + temp_session_id.len() + user_id.len());
    payload.extend_from_slice(key);
    payload.extend_from_slice(temp_session_id.as_bytes());
    payload.extend_from_slice(user_id.as_bytes());
    hex::encode(blake3::hash(&payload).as_bytes())
}

fn verify_anti_clogging_token(temp_session_id: &str, user_id: &str, token: &str) -> bool {
    let expected = compute_anti_clogging_token(temp_session_id, user_id);
    expected == token
}

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
        Ok(fallback.to_path_buf())
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
    pub anti_clogging_token: String,
}

#[derive(Debug, Deserialize)]
pub struct SecureSegmentRequest {
    pub zkp_proof: String,
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
            tracing::warn!(
                "User {} does not have sae_secret, SAE handshake may fail. Please re-register.",
                user_id
            );
            user.password_hash.as_bytes().to_vec()
        }
    };

    let manager = hls_manager.read().await;
    let temp_session_id = manager
        .init_sae_handshake(user_id.clone(), password)
        .map_err(convert_hls_error)?;
    let anti_clogging_token = compute_anti_clogging_token(&temp_session_id, &user_id);

    info!(
        "Initialized SAE handshake for user {} - temp session {}",
        user_id, temp_session_id
    );

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "temp_session_id": temp_session_id,
        "anti_clogging_token": anti_clogging_token,
        "supported_groups": [19],
        "selected_group": 19,
        "file_path": file_path,
        "message": "SAE handshake initialized, send client commit next"
    })))
}

#[derive(Debug, Deserialize)]
pub struct SendClientCommitRequest {
    pub temp_session_id: String,
    pub client_commit: SaeCommit,
    pub anti_clogging_token: String,
}

pub async fn send_client_commit(
    _pool: web::Data<SqlitePool>,
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<SendClientCommitRequest>,
) -> Result<impl Responder, AppError> {
    let user_id = claims.sub.clone();

    if !verify_anti_clogging_token(
        &body.temp_session_id,
        &user_id,
        &body.anti_clogging_token,
    ) {
        return Err(AppError::Unauthorized(
            "Invalid anti-clogging token".to_string(),
        ));
    }

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
    pub anti_clogging_token: String,
}

pub async fn send_client_confirm(
    _pool: web::Data<SqlitePool>,
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<SendClientConfirmRequest>,
) -> Result<impl Responder, AppError> {
    let user_id = claims.sub.clone();

    if !verify_anti_clogging_token(
        &body.temp_session_id,
        &user_id,
        &body.anti_clogging_token,
    ) {
        return Err(AppError::Unauthorized(
            "Invalid anti-clogging token".to_string(),
        ));
    }

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

    if !verify_anti_clogging_token(
        &body.temp_session_id,
        &user_id,
        &body.anti_clogging_token,
    ) {
        return Err(AppError::Unauthorized(
            "Invalid anti-clogging token".to_string(),
        ));
    }

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

#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    pub temp_session_id: String,
    pub file_id: Option<String>,
    pub file_path: Option<String>,
    pub zkp_registration: Option<String>,

    #[serde(default)]
    pub direct_mode: bool,
}

pub async fn create_hls_session(
    pool: web::Data<SqlitePool>,
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<CreateSessionRequest>,
) -> Result<impl Responder, AppError> {
    let user_id = claims.sub.clone();

    let file_path = if let Some(ref file_id) = body.file_id {
        // 通过文件 ID 查找
        let file = crate::db::find_file_by_id(&pool, file_id, &user_id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("File not found: {}", file_id)))?;
        file.file_path
    } else if let Some(ref path) = body.file_path {
        // 直接使用文件路径（验证路径是否存在）
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

    let zkp_registration: Option<PasswordRegistration> = match get_user_zkp_registration(
        &pool, &user_id,
    )
    .await
    {
        Ok(Some(reg)) => Some(reg),
        Ok(None) => {
            if let Some(ref reg_json) = body.zkp_registration {
                warn!(
                    "User {} does not have stored ZKP registration, falling back to request payload",
                    user_id
                );
                Some(serde_json::from_str(reg_json).map_err(|e| {
                    AppError::BadRequest(format!("Invalid ZKP registration format: {}", e))
                })?)
            } else {
                warn!(
                    "User {} does not have ZKP registration data stored",
                    user_id
                );
                None
            }
        }
        Err(e) => {
            warn!("Failed to get ZKP registration for user {}: {}", user_id, e);
            if let Some(ref reg_json) = body.zkp_registration {
                warn!(
                    "Falling back to request ZKP registration for user {} due to DB lookup error",
                    user_id
                );
                Some(serde_json::from_str(reg_json).map_err(|parse_err| {
                    AppError::BadRequest(format!("Invalid ZKP registration format: {}", parse_err))
                })?)
            } else {
                None
            }
        }
    };

    let manager = hls_manager.read().await;
    let invalidated = manager.invalidate_sessions_for_user_file(&user_id, &file_path);
    if invalidated > 0 {
        info!(
            "Invalidated {} stale HLS sessions for user {} file {}",
            invalidated, user_id, file_path
        );
    }

    let session_id = manager
        .complete_sae_handshake_with_registration(
            &body.temp_session_id,
            user_id.clone(),
            file_path.clone(),
            zkp_registration.clone(),
        )
        .map_err(convert_hls_error)?;

    // 安全策略：所有 segment 必须 AES-256-GCM 加密传输，不允许明文模式。
    // direct_mode 字段被忽略，始终为 false。
    if body.direct_mode {
        warn!(
            "Client requested direct_mode for session {}, but it is disabled by security policy. \
             All segments will be AES-256-GCM encrypted.",
            session_id
        );
    }

    let session = manager
        .get_session(&session_id)
        .map_err(convert_hls_error)?;

    let has_zkp = zkp_registration.is_some();

    // Debug: verify session is stored and count total sessions
    {
        let sessions = manager.sessions.lock().unwrap();
        let total = sessions.len();
        let exists = sessions.contains_key(&session_id);
        info!(
            "✅ Created HLS session {} for user {} - file {} (ZKP: {}, encrypted: true, verified_stored: {}, total_sessions: {})",
            session_id, user_id, file_path, has_zkp, exists, total
        );
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "session_id": session_id,
        "expires_at": session.expires_at.timestamp(),
        "playlist_url": format!("/api/v1/secure-hls/{}/playlist.m3u8", session_id),
        "zkp_enabled": has_zkp,
        "direct_mode": false,
        "encryption_method": "AES-256-GCM",
    })))
}

async fn get_user_zkp_registration(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Option<PasswordRegistration>, AppError> {
    let user = crate::db::find_user_by_id(pool, user_id).await?;

    match user {
        Some(u) => {
            if let Some(zkp_reg_json) = u.zkp_registration {
                let registration: PasswordRegistration = serde_json::from_str(&zkp_reg_json)
                    .map_err(|e| {
                        AppError::InternalServerError(format!(
                            "Invalid ZKP registration data in database: {}",
                            e
                        ))
                    })?;
                Ok(Some(registration))
            } else {
                Ok(None)
            }
        }
        None => Ok(None),
    }
}

// ============ 安全播放列表和段获取 ============

/// 使用 ffmpeg 对视频进行 HLS 分片（渐进式 — 不等待完成）
///
/// 关键优化：
/// 1. 后台启动 ffmpeg (spawn, 不 await 完成)
/// 2. 使用 `-hls_playlist_type event` + `-hls_flags append_list` 实现渐进式分片
/// 3. 等待第一个 segment 生成后立即返回 playlist
/// 4. 对于 stream copy 场景（大多数情况），首个 segment 在 1-2 秒内可用
/// 5. 播放器一边播放，ffmpeg 一边继续生成后续 segments
///
/// 结果缓存在 `hls_cache/{video_hash}/` 目录中。
async fn ensure_hls_segments(file_path: &str) -> Result<(std::path::PathBuf, String), AppError> {
    use std::path::PathBuf;

    let video_hash = blake3::hash(file_path.as_bytes());
    let video_id = hex::encode(&video_hash.as_bytes()[..8]);
    let cache_root = ensure_external_hls_cache_root()?;
    let cache_dir = cache_root.join(&video_id);
    let playlist_path = cache_dir.join("playlist.m3u8");
    // 标记文件表示分片完成 (包含 #EXT-X-ENDLIST)
    let done_marker = cache_dir.join(".done");
    // 锁文件防止并发 ffmpeg 进程
    let lock_file = cache_dir.join(".lock");

    // 清理过期锁文件（崩溃的 ffmpeg 进程可能遗留锁文件，阻笜后续转码）
    if lock_file.exists() {
        if let Ok(metadata) = tokio::fs::metadata(&lock_file).await {
            if let Ok(modified) = metadata.modified() {
                if modified
                    .elapsed()
                    .is_ok_and(|d| d > std::time::Duration::from_secs(300))
                {
                    warn!(
                        "Removing stale HLS lock file (older than 5 minutes) for {}",
                        video_id
                    );
                    let _ = tokio::fs::remove_file(&lock_file).await;
                    // 同时清理残留的不完整分片
                    if let Ok(mut entries) = tokio::fs::read_dir(&cache_dir).await {
                        while let Ok(Some(entry)) = entries.next_entry().await {
                            let path = entry.path();
                            if path
                                .extension()
                                .is_some_and(|e| e == "ts" || e == "m3u8" || e == "enc")
                            {
                                let _ = tokio::fs::remove_file(&path).await;
                            }
                        }
                    }
                }
            }
        }
    }

    // 如果已完成分片，优先复用缓存；但要校验 playlist 引用的分片是否都存在
    if done_marker.exists() && playlist_path.exists() {
        let content = tokio::fs::read_to_string(&playlist_path)
            .await
            .map_err(|e| AppError::IoError(format!("Failed to read cached playlist: {}", e)))?;

        if playlist_segments_exist_on_disk(&cache_dir, &content) {
            return Ok((cache_dir, content));
        }

        warn!(
            "Detected stale HLS cache for {}, playlist references missing segments; regenerating",
            video_id
        );
        let _ = tokio::fs::remove_file(&done_marker).await;
    }

    // 如果有播放列表且至少有一个 segment，说明上一次分片正在进行中或中断
    // 如果 ffmpeg 正在运行（lock 文件存在），直接返回当前 playlist
    if playlist_path.exists() && lock_file.exists() {
        let content = tokio::fs::read_to_string(&playlist_path).await.ok();
        if let Some(content) = content {
            if content.contains("#EXTINF") && playlist_segments_exist_on_disk(&cache_dir, &content)
            {
                info!(
                    "FFmpeg still running for {}, returning progressive playlist",
                    video_id
                );
                return Ok((cache_dir, content));
            }
        }
    }

    // 创建缓存目录
    tokio::fs::create_dir_all(&cache_dir)
        .await
        .map_err(|e| AppError::IoError(format!("Failed to create cache dir: {}", e)))?;

    // 验证源文件存在
    let original = PathBuf::from(file_path);
    if !original.exists() {
        return Err(AppError::NotFound(format!(
            "Video file not found: {}",
            file_path
        )));
    }

    let ffmpeg_path = std::env::var("FFMPEG_PATH")
        .or_else(|_| rockzero_media::get_global_ffmpeg_path().ok_or(""))
        .unwrap_or_else(|_| "ffmpeg".to_string());

    // 预检测视频编码格式，用于调整首段超时策略和传递给转码流程
    let video_codec = detect_video_codec(&ffmpeg_path, file_path).await;
    let needs_transcode = !matches!(
        video_codec.as_deref(),
        Some("h264" | "avc" | "avc1" | "hevc" | "h265" | "hev1" | "hvc1")
    );
    if needs_transcode {
        info!(
            "Video codec {:?} requires transcode, using extended timeouts",
            video_codec
        );
    }

    let segment_pattern = cache_dir.join("segment_%d.ts");
    let seg_pattern_str = segment_pattern.to_str().unwrap_or("").to_string();
    let playlist_str = playlist_path.to_str().unwrap_or("").to_string();

    info!(
        "🎬 Starting progressive segmentation: {} → {}",
        file_path,
        cache_dir.display()
    );

    // 清理之前的部分输出（如果有）
    if !lock_file.exists() {
        for entry in std::fs::read_dir(&cache_dir)
            .into_iter()
            .flatten()
            .flatten()
        {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "ts" || e == "m3u8") {
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    // 创建 lock 文件
    let _ = tokio::fs::write(&lock_file, b"").await;

    // 后台启动 ffmpeg - stream copy（渐进模式）
    let file_path_owned = file_path.to_string();
    let cache_dir_clone = cache_dir.clone();
    let done_marker_clone = done_marker.clone();
    let lock_file_clone = lock_file.clone();
    let ffmpeg_path_clone = ffmpeg_path.clone();
    let video_codec_clone = video_codec.clone();

    tokio::spawn(async move {
        let result = run_ffmpeg_progressive(
            &ffmpeg_path_clone,
            &file_path_owned,
            &seg_pattern_str,
            &playlist_str,
            &cache_dir_clone,
            &done_marker_clone,
            &lock_file_clone,
            video_codec_clone,
        )
        .await;

        match result {
            Ok(_) => info!("✅ Video segmented successfully: {}", video_id),
            Err(e) => warn!("❌ FFmpeg segmentation failed: {}", e),
        }

        // 清理 lock 文件
        let _ = tokio::fs::remove_file(&lock_file_clone).await;
    });

    // 等待第一个 segment 生成
    // AV1/VP9 等需要软件转码的格式，首个 segment 生成较慢，给予 120 秒超时
    let first_segment = cache_dir.join("segment_0.ts");
    let mut waited = 0;
    let max_wait_ms: u64 = if needs_transcode { 120_000 } else { 30_000 };
    let poll_interval_ms: u64 = 200;

    while waited < max_wait_ms {
        if first_segment.exists() && playlist_path.exists() {
            // 等待 playlist 至少包含一个可播放段；对于长视频尽量等待 2 段，降低 segment_1 早到 404
            if let Ok(content) = tokio::fs::read_to_string(&playlist_path).await {
                let is_done = done_marker.exists();
                let min_segments = if is_done { 1 } else { 2 };
                if playlist_has_min_segments(&content, min_segments)
                    && playlist_segments_exist_on_disk(&cache_dir, &content)
                {
                    info!("First segment ready after {}ms, returning playlist", waited);
                    return Ok((cache_dir, content));
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval_ms)).await;
        waited += poll_interval_ms;
    }

    // 超时检查 — 可能 ffmpeg 失败了
    if playlist_path.exists() {
        let content = tokio::fs::read_to_string(&playlist_path)
            .await
            .map_err(|e| AppError::IoError(format!("Failed to read playlist: {}", e)))?;
        if playlist_has_min_segments(&content, 1)
            && playlist_segments_exist_on_disk(&cache_dir, &content)
        {
            return Ok((cache_dir, content));
        }
    }

    Err(AppError::InternalServerError(
        "视频分片超时，请检查 ffmpeg 是否正确安装".to_string(),
    ))
}

fn extract_playlist_segment_names(playlist_content: &str) -> Vec<String> {
    playlist_content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let no_query = line.split('?').next().unwrap_or(line);
            let file_name = no_query.rsplit('/').next().unwrap_or(no_query);
            if file_name.starts_with("segment_") && file_name.ends_with(".ts") {
                Some(file_name.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn playlist_has_min_segments(playlist_content: &str, min_segments: usize) -> bool {
    extract_playlist_segment_names(playlist_content).len() >= min_segments
}

fn playlist_segments_exist_on_disk(cache_dir: &std::path::Path, playlist_content: &str) -> bool {
    let segments = extract_playlist_segment_names(playlist_content);
    if segments.is_empty() {
        return false;
    }

    segments.into_iter().all(|segment| {
        let ts_path = cache_dir.join(&segment);
        let enc_path = ts_path.with_extension("ts.enc");
        ts_path.exists() || enc_path.exists()
    })
}

/// 探测视频文件的视频编码格式
///
/// 使用 ffprobe 获取视频编码格式，用于决定是否需要添加 bitstream filter。
/// 这是解决 HLS mpegts 黑屏的关键 — H.264/HEVC 的 MP4 封装使用 length-prefixed NALUs，
/// 而 mpegts 要求 Annex B 格式的 start codes，必须通过 bitstream filter 转换。
async fn detect_video_codec(ffmpeg_path: &str, file_path: &str) -> Option<String> {
    // 从 ffmpeg 路径推导 ffprobe 路径
    let ffprobe_path = if let Some(dir) = std::path::Path::new(ffmpeg_path).parent() {
        let probe = dir.join("ffprobe");
        if tokio::fs::metadata(&probe).await.is_ok() {
            probe.to_string_lossy().to_string()
        } else {
            std::env::var("FFPROBE_PATH").unwrap_or_else(|_| "ffprobe".to_string())
        }
    } else {
        std::env::var("FFPROBE_PATH").unwrap_or_else(|_| "ffprobe".to_string())
    };

    let output = tokio::process::Command::new(&ffprobe_path)
        .args([
            "-v",
            "quiet",
            "-select_streams",
            "v:0",
            "-show_entries",
            "stream=codec_name",
            "-of",
            "csv=p=0",
            file_path,
        ])
        .output()
        .await
        .ok()?;

    if output.status.success() {
        let codec = String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_lowercase();
        if !codec.is_empty() {
            return Some(codec);
        }
    }

    None
}

/// 从 ffmpeg 路径推导 ffprobe 路径
async fn get_ffprobe_path(ffmpeg_path: &str) -> String {
    if let Some(dir) = std::path::Path::new(ffmpeg_path).parent() {
        let probe = dir.join("ffprobe");
        if tokio::fs::metadata(&probe).await.is_ok() {
            return probe.to_string_lossy().to_string();
        }
    }
    std::env::var("FFPROBE_PATH").unwrap_or_else(|_| "ffprobe".to_string())
}

/// 探测视频文件的 start_time（秒）
///
/// MKV 等容器的 PTS 时间戳可能不从 0 开始（例如 26:28:10）。
/// stream copy 到 HLS 时这些时间戳会被保留，导致播放器显示错误的时间。
/// 通过检测 start_time 并使用 -output_ts_offset 将输出时间戳归零。
async fn detect_video_start_time(ffmpeg_path: &str, file_path: &str) -> f64 {
    let ffprobe_path = get_ffprobe_path(ffmpeg_path).await;

    let output = tokio::process::Command::new(&ffprobe_path)
        .args([
            "-v",
            "quiet",
            "-show_entries",
            "format=start_time",
            "-of",
            "csv=p=0",
            file_path,
        ])
        .output()
        .await;

    match output {
        Ok(o) if o.status.success() => {
            let raw = String::from_utf8_lossy(&o.stdout);
            raw.trim().parse::<f64>().unwrap_or(0.0)
        }
        _ => 0.0,
    }
}

/// 派生用于缓存分片文件静态加密的存储密钥
///
/// 使用 Blake3 从固定上下文 + 视频路径派生，确保：
/// - 同一视频的分片使用相同密钥（缓存命中）
/// - 不同视频使用不同密钥（隔离性）
/// - 密钥不存储于磁盘（运行时派生）
fn derive_segment_storage_key(file_path: &str) -> [u8; 32] {
    let context = format!("rockzero-segment-at-rest-v1:{}", file_path);
    crate::crypto::blake3_hash_bytes(context.as_bytes())
}

/// 加密所有已生成的 TS 段文件（静态存储加密）
///
/// 在 ffmpeg 完成分片后调用，使用 AES-256-GCM 加密每个 .ts 文件。
/// 加密后的文件使用 .ts.enc 扩展名存储，原始 .ts 文件安全删除。
/// 这确保即使磁盘被物理访问，缓存的视频数据也是加密的。
async fn encrypt_segments_at_rest(
    cache_dir: &std::path::Path,
    storage_key: &[u8; 32],
) -> Result<usize, String> {
    let mut entries = tokio::fs::read_dir(cache_dir)
        .await
        .map_err(|e| format!("Failed to read cache dir: {}", e))?;

    let mut ts_files = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "ts") && !path.with_extension("ts.enc").exists() {
            ts_files.push(path);
        }
    }

    if ts_files.is_empty() {
        return Ok(0);
    }

    // ★ 并行加密：利用多核 CPU 同时加密多个分片，大幅减少加密总耗时
    // AES-256-GCM 加密是 CPU 密集型操作，通过 spawn_blocking 在线程池中并行执行
    let storage_key_owned = *storage_key;
    let mut join_set = tokio::task::JoinSet::new();

    for ts_path in ts_files {
        let key = storage_key_owned;
        join_set.spawn(async move {
            let enc_path = ts_path.with_extension("ts.enc");
            match tokio::fs::read(&ts_path).await {
                Ok(data) => {
                    // 在阻塞线程池中执行 CPU 密集型加密
                    let encrypt_result = tokio::task::spawn_blocking(move || {
                        crate::crypto::aes_encrypt(&key, &data).map_err(|e| format!("{}", e))
                    })
                    .await;

                    match encrypt_result {
                        Ok(Ok(encrypted)) => {
                            if let Err(e) = tokio::fs::write(&enc_path, &encrypted).await {
                                warn!("Failed to write encrypted segment {:?}: {}", enc_path, e);
                                return false;
                            }
                            // 安全删除原始明文段文件
                            let _ = tokio::fs::remove_file(&ts_path).await;
                            true
                        }
                        Ok(Err(e)) => {
                            warn!("Failed to encrypt segment {:?}: {}", ts_path, e);
                            false
                        }
                        Err(e) => {
                            warn!("Encryption task panicked for {:?}: {}", ts_path, e);
                            false
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read segment {:?}: {}", ts_path, e);
                    false
                }
            }
        });
    }

    // 收集所有并行加密结果
    let mut encrypted_count = 0usize;
    while let Some(result) = join_set.join_next().await {
        if let Ok(true) = result {
            encrypted_count += 1;
        }
    }

    if encrypted_count > 0 {
        info!(
            "🔒 Encrypted {} segment files at rest in {:?} (parallel)",
            encrypted_count, cache_dir
        );
    }

    Ok(encrypted_count)
}

async fn read_segment_data(
    segment_path: &std::path::Path,
    storage_key: &[u8; 32],
) -> Result<Vec<u8>, AppError> {
    let enc_path = segment_path.with_extension("ts.enc");

    if enc_path.exists() {
        let encrypted = tokio::fs::read(&enc_path)
            .await
            .map_err(|e| AppError::IoError(format!("Failed to read encrypted segment: {}", e)))?;
        let data = crate::crypto::aes_decrypt(storage_key, &encrypted)?;
        return Ok(data);
    }

    if segment_path.exists() {
        let data = tokio::fs::read(segment_path)
            .await
            .map_err(|e| AppError::IoError(format!("Failed to read segment: {}", e)))?;
        return Ok(data);
    }

    Err(AppError::NotFound(format!(
        "Segment not found: {:?}",
        segment_path
    )))
}

/// 运行 ffmpeg 渐进式分片（在后台 task 中执行）
#[allow(clippy::too_many_arguments)]
async fn run_ffmpeg_progressive(
    ffmpeg_path: &str,
    file_path: &str,
    seg_pattern: &str,
    playlist_path: &str,
    cache_dir: &std::path::Path,
    done_marker: &std::path::Path,
    lock_file: &std::path::Path,
    pre_detected_codec: Option<String>,
) -> Result<(), String> {
    // 使用预检测结果避免重复调用 ffprobe
    let video_codec = if pre_detected_codec.is_some() {
        pre_detected_codec
    } else {
        detect_video_codec(ffmpeg_path, file_path).await
    };
    info!("Detected video codec: {:?}", video_codec);

    // 探测视频开始时间，用于修复 PTS 偏移
    let start_time = detect_video_start_time(ffmpeg_path, file_path).await;
    if start_time > 1.0 {
        info!(
            "Detected video start_time: {:.3}s — will apply -output_ts_offset to normalize timestamps",
            start_time
        );
    }

    let allow_stream_copy = matches!(
        video_codec.as_deref(),
        Some("h264" | "avc" | "avc1" | "hevc" | "h265" | "hev1" | "hvc1")
    );

    // 构建 stream copy 参数
    // 关键修复：对于 mpegts 容器必须添加正确的 bitstream filter
    // 否则 H.264/HEVC 的 NAL 封装格式不正确，导致播放器只有音频没有画面
    let mut copy_args: Vec<String> = vec![
        "-y".into(),
        // ★ 多核并行：使用所有 CPU 核心进行解复用/复用
        "-threads".into(),
        "0".into(),
        // ★ PTS 时间戳修复：重新生成 PTS 并丢弃损坏帧
        // 解决：源文件（如 MKV）内嵌非零 start_time（例如 26:28:10），
        //       stream copy 直接传递导致 HLS 播放器显示错误的时间戳
        "-fflags".into(),
        "+genpts+discardcorrupt".into(),
        "-i".into(),
        file_path.into(),
        "-map".into(),
        "0:v?".into(), // 视频流（如果有）
        "-map".into(),
        "0:a?".into(), // 音频流（如果有）
        "-c".into(),
        "copy".into(),
    ];

    // 根据视频编码添加 bitstream filter — 这是解决黑屏问题的关键
    match video_codec.as_deref() {
        Some("h264" | "avc" | "avc1") => {
            copy_args.extend(["-bsf:v".into(), "h264_mp4toannexb".into()]);
            info!("Applied h264_mp4toannexb bitstream filter for TS muxing");
        }
        Some("hevc" | "h265" | "hev1" | "hvc1") => {
            copy_args.extend(["-bsf:v".into(), "hevc_mp4toannexb".into()]);
            info!("Applied hevc_mp4toannexb bitstream filter for TS muxing");
        }
        _ => {
            // VP9, AV1 等其他编码不需要 bitstream filter
            info!("No bitstream filter needed for codec: {:?}", video_codec);
        }
    }

    // ★ PTS 偏移修复：如果源文件 start_time > 1s（典型的 MKV 内嵌时间戳偏移），
    //   通过 -output_ts_offset 将输出时间戳归零，避免播放器显示错误时间（如 26:28:10）
    if start_time > 1.0 {
        copy_args.extend(["-output_ts_offset".into(), format!("{:.6}", -start_time)]);
    }

    copy_args.extend([
        // ★ 将首个 DTS 重置为 0，消除源文件的 start_time 偏移
        "-avoid_negative_ts".into(),
        "make_zero".into(),
        "-f".into(),
        "hls".into(),
        "-hls_time".into(),
        "2".into(), // 2 秒段提升首帧速度与seek响应
        "-hls_list_size".into(),
        "0".into(),
        "-hls_playlist_type".into(),
        "event".into(), // event 模式 = 渐进式播放列表
        "-hls_flags".into(),
        "append_list+independent_segments".into(),
        "-hls_segment_type".into(),
        "mpegts".into(),
        "-hls_segment_filename".into(),
        seg_pattern.into(),
        playlist_path.into(),
    ]);

    if allow_stream_copy {
        // 先尝试 stream copy + bitstream filter（极快，不需要转码）
        let output = tokio::process::Command::new(ffmpeg_path)
            .args(&copy_args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
            .await
            .map_err(|e| {
                let _ = std::fs::remove_file(lock_file);
                format!("Failed to run ffmpeg: {}", e)
            })?;

        if output.status.success() {
            // stream copy 成功 — 添加 #EXT-X-ENDLIST 标记完成
            if let Ok(mut content) = tokio::fs::read_to_string(playlist_path).await {
                if !content.contains("#EXT-X-ENDLIST") {
                    content.push_str("\n#EXT-X-ENDLIST\n");
                    let _ = tokio::fs::write(playlist_path, &content).await;
                }
            }

            // 使用 SecureFileEncryptor 加密缓存段文件（静态存储保护）
            let storage_key = derive_segment_storage_key(file_path);
            match encrypt_segments_at_rest(cache_dir, &storage_key).await {
                Ok(n) => info!("Stream copy: encrypted {} segments at rest", n),
                Err(e) => warn!("Failed to encrypt segments at rest: {}", e),
            }

            let _ = tokio::fs::write(done_marker, b"").await;
            let _ = tokio::fs::remove_file(lock_file).await;
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(
            "Stream copy failed, trying transcode: {}",
            &stderr[..stderr.len().min(500)]
        );
    } else {
        info!(
            "Skipping stream copy for codec {:?}, using H.264/AAC transcode for compatibility",
            video_codec
        );
    }

    // 清理出错的输出
    for entry in std::fs::read_dir(cache_dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "ts" || e == "m3u8") {
            let _ = std::fs::remove_file(&path);
        }
    }

    // 检测硬件加速
    let hw_accel = detect_hardware_acceleration().await;

    let build_transcode_args = |accel: HardwareAccel| {
        let mut args: Vec<String> = vec![
            "-y".into(),
            // ★ 多核并行：使用所有 CPU 核心进行编解码
            "-threads".into(),
            "0".into(),
            // ★ PTS 时间戳修复（转码路径）
            "-fflags".into(),
            "+genpts+discardcorrupt".into(),
        ];

        // ★ 输入解码选项（必须在 -i 之前）
        // -hwaccel auto：自动选择硬件解码器，支持 AV1/VP9 等非 H.264 源的硬件辅助解码
        // 若硬件不支持（如 ARM 设备不支持 AV1 硬解）则自动回退到 CPU 多线程软解码
        match accel {
            HardwareAccel::Vaapi => {
                // VAAPI 专用解码管线（需指定设备和输出格式）
                args.extend([
                    "-hwaccel".into(),
                    "vaapi".into(),
                    "-hwaccel_device".into(),
                    "/dev/dri/renderD128".into(),
                    "-hwaccel_output_format".into(),
                    "vaapi".into(),
                ]);
            }
            _ => {
                args.extend(["-hwaccel".into(), "auto".into()]);
            }
        }

        args.extend(["-i".into(), file_path.into()]);

        // ★ 输出编码选项
        match accel {
            HardwareAccel::Rkmpp => {
                info!("Using Rockchip MPP hardware encoding for HLS segmentation");
                args.extend([
                    "-c:v".into(),
                    "h264_rkmpp".into(),
                    "-b:v".into(),
                    "3M".into(),
                    "-rc_mode".into(),
                    "VBR".into(),
                ]);
            }
            HardwareAccel::V4l2 => {
                info!("Using V4L2 hardware encoding for HLS segmentation");
                args.extend([
                    "-c:v".into(),
                    "h264_v4l2m2m".into(),
                    "-b:v".into(),
                    "2M".into(),
                ]);
            }
            HardwareAccel::Vaapi => {
                info!("Using VAAPI hardware encoding for HLS segmentation");
                args.extend([
                    "-c:v".into(),
                    "h264_vaapi".into(),
                    "-qp".into(),
                    "23".into(),
                ]);
            }
            HardwareAccel::None => {
                info!("Using software encoding (libx264) for HLS segmentation");
                args.extend([
                    "-c:v".into(),
                    "libx264".into(),
                    "-preset".into(),
                    "ultrafast".into(), // ultrafast 更快输出首个 segment
                    "-crf".into(),
                    "23".into(),
                    "-pix_fmt".into(),
                    "yuv420p".into(),
                ]);
            }
        }

        args.extend([
            "-c:a".into(),
            "aac".into(),
            "-b:a".into(),
            "128k".into(),
            "-ac".into(),
            "2".into(),
            "-f".into(),
            "hls".into(),
            "-hls_time".into(),
            "2".into(),
            "-hls_list_size".into(),
            "0".into(),
            "-hls_playlist_type".into(),
            "event".into(),
            "-hls_flags".into(),
            "append_list+independent_segments".into(),
            "-hls_segment_type".into(),
            "mpegts".into(),
            "-hls_segment_filename".into(),
            seg_pattern.into(),
            playlist_path.into(),
        ]);

        args
    };

    let mut output = tokio::process::Command::new(ffmpeg_path)
        .args(build_transcode_args(hw_accel))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("FFmpeg transcode failed: {}", e))?;

    if !output.status.success() && hw_accel != HardwareAccel::None {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(
            "Hardware transcode failed ({:?}), retrying with software libx264: {}",
            hw_accel,
            &stderr[..stderr.len().min(500)]
        );

        for entry in std::fs::read_dir(cache_dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "ts" || e == "m3u8") {
                let _ = std::fs::remove_file(&path);
            }
        }

        output = tokio::process::Command::new(ffmpeg_path)
            .args(build_transcode_args(HardwareAccel::None))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
            .await
            .map_err(|e| format!("FFmpeg software fallback failed: {}", e))?;
    }

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let _ = tokio::fs::remove_file(lock_file).await;
        return Err(format!(
            "FFmpeg segmentation failed: {}",
            &stderr[..stderr.len().min(500)]
        ));
    }

    // 标记完成
    if let Ok(mut content) = tokio::fs::read_to_string(playlist_path).await {
        if !content.contains("#EXT-X-ENDLIST") {
            content.push_str("\n#EXT-X-ENDLIST\n");
            let _ = tokio::fs::write(playlist_path, &content).await;
        }
    }

    // 使用 SecureFileEncryptor 加密缓存段文件（静态存储保护）
    let storage_key = derive_segment_storage_key(file_path);
    match encrypt_segments_at_rest(cache_dir, &storage_key).await {
        Ok(n) => info!("Transcode: encrypted {} segments at rest", n),
        Err(e) => warn!("Failed to encrypt segments at rest: {}", e),
    }

    let _ = tokio::fs::write(done_marker, b"").await;
    let _ = tokio::fs::remove_file(lock_file).await;

    Ok(())
}

/// 按需生成单个 HLS 分片（用于 seek 场景）
///
/// 当播放器 seek 到视频远处、但 ffmpeg 渐进式转码尚未到达请求的分片时，
/// 使用 `-ss` 直接跳转到目标时间戳，单独生成该分片。
/// 这避免了等待全部前序分片生成完成的漫长延迟，极大改善 seek 体验。
///
/// ★ 关键修复：优先使用 stream copy + bitstream filter（与渐进式分片一致），
///   避免 on-demand 分片使用 transcode 而渐进式分片使用 stream copy 导致
///   编码参数不匹配、播放器 seek 回退时黑屏/卡死。
///
/// 生成的分片会同样进行静态加密（AES-256-GCM）以保持一致的安全策略。
async fn generate_segment_on_demand(
    file_path: &str,
    cache_dir: &std::path::Path,
    segment_index: usize,
    segment_duration: f64,
) -> Result<(), String> {
    let segment_path = cache_dir.join(format!("segment_{}.ts", segment_index));

    // 如果分片已存在（明文或密文），直接返回
    if segment_path.exists() || segment_path.with_extension("ts.enc").exists() {
        return Ok(());
    }

    let ffmpeg_path = std::env::var("FFMPEG_PATH")
        .or_else(|_| rockzero_media::get_global_ffmpeg_path().ok_or(""))
        .unwrap_or_else(|_| "ffmpeg".to_string());

    let start_time = segment_index as f64 * segment_duration;
    let seg_path_str = segment_path.to_string_lossy().to_string();

    info!(
        "🎯 On-demand segment generation: segment_{}.ts (seek to {:.1}s)",
        segment_index, start_time
    );

    // 检测视频编码，决定是否可以 stream copy（与渐进式分片保持一致）
    let video_codec = detect_video_codec(&ffmpeg_path, file_path).await;
    let can_stream_copy = matches!(
        video_codec.as_deref(),
        Some("h264" | "avc" | "avc1" | "hevc" | "h265" | "hev1" | "hvc1")
    );

    // ══════════════════════════════════════════════════════════════
    //  Phase 1: 尝试 stream copy（与渐进式分片编码一致，瞬间完成）
    // ══════════════════════════════════════════════════════════════
    if can_stream_copy {
        let mut copy_args: Vec<String> = vec![
            "-y".into(),
            "-threads".into(),
            "0".into(),
            "-fflags".into(),
            "+genpts+discardcorrupt".into(),
            // -ss 在 -i 前 = input seeking（极快，跳到最近的 keyframe）
            "-ss".into(),
            format!("{:.3}", start_time),
            "-i".into(),
            file_path.into(),
            "-t".into(),
            format!("{:.3}", segment_duration + 0.5), // 多 0.5s 容错
            "-map".into(),
            "0:v?".into(),
            "-map".into(),
            "0:a?".into(),
            "-c".into(),
            "copy".into(),
        ];

        // 关键：添加 bitstream filter，与渐进式分片路径一致
        match video_codec.as_deref() {
            Some("h264" | "avc" | "avc1") => {
                copy_args.extend(["-bsf:v".into(), "h264_mp4toannexb".into()]);
            }
            Some("hevc" | "h265" | "hev1" | "hvc1") => {
                copy_args.extend(["-bsf:v".into(), "hevc_mp4toannexb".into()]);
            }
            _ => {}
        }

        copy_args.extend([
            "-avoid_negative_ts".into(),
            "make_zero".into(),
            "-f".into(),
            "mpegts".into(),
            seg_path_str.clone(),
        ]);

        let output = tokio::process::Command::new(&ffmpeg_path)
            .args(&copy_args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
            .await
            .map_err(|e| format!("On-demand stream copy failed: {}", e))?;

        if output.status.success() {
            // stream copy 成功 — 加密并返回
            encrypt_on_demand_segment(&segment_path, file_path).await;
            info!(
                "✅ On-demand segment_{}.ts generated via stream copy and encrypted",
                segment_index
            );
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(
            "Stream copy failed for on-demand segment_{}, trying transcode: {}",
            segment_index,
            &stderr[..stderr.len().min(300)]
        );
        // 清理失败的输出文件
        let _ = tokio::fs::remove_file(&segment_path).await;
    }

    // ══════════════════════════════════════════════════════════════
    //  Phase 2: 转码（stream copy 不可用或失败时的回退路径）
    // ══════════════════════════════════════════════════════════════
    let hw_accel = detect_hardware_acceleration().await;

    let build_on_demand_transcode_args = |accel: HardwareAccel| -> Vec<String> {
        let mut args: Vec<String> = vec![
            "-y".into(),
            "-threads".into(),
            "0".into(),
            "-fflags".into(),
            "+genpts+discardcorrupt".into(),
            "-ss".into(),
            format!("{:.3}", start_time),
        ];

        // 输入解码加速
        match accel {
            HardwareAccel::Vaapi => {
                args.extend([
                    "-hwaccel".into(),
                    "vaapi".into(),
                    "-hwaccel_device".into(),
                    "/dev/dri/renderD128".into(),
                    "-hwaccel_output_format".into(),
                    "vaapi".into(),
                ]);
            }
            _ => {
                args.extend(["-hwaccel".into(), "auto".into()]);
            }
        }

        args.extend([
            "-i".into(),
            file_path.into(),
            "-t".into(),
            format!("{:.3}", segment_duration + 0.1),
        ]);

        // 输出编码选项
        match accel {
            HardwareAccel::Rkmpp => {
                args.extend([
                    "-c:v".into(),
                    "h264_rkmpp".into(),
                    "-b:v".into(),
                    "3M".into(),
                ]);
            }
            HardwareAccel::V4l2 => {
                args.extend([
                    "-c:v".into(),
                    "h264_v4l2m2m".into(),
                    "-b:v".into(),
                    "2M".into(),
                ]);
            }
            HardwareAccel::Vaapi => {
                args.extend([
                    "-c:v".into(),
                    "h264_vaapi".into(),
                    "-qp".into(),
                    "23".into(),
                ]);
            }
            HardwareAccel::None => {
                args.extend([
                    "-c:v".into(),
                    "libx264".into(),
                    "-preset".into(),
                    "ultrafast".into(),
                    "-crf".into(),
                    "23".into(),
                    "-pix_fmt".into(),
                    "yuv420p".into(),
                ]);
            }
        }

        args.extend([
            "-c:a".into(),
            "aac".into(),
            "-b:a".into(),
            "128k".into(),
            "-ac".into(),
            "2".into(),
            "-f".into(),
            "mpegts".into(),
            seg_path_str.clone(),
        ]);

        args
    };

    let output = tokio::process::Command::new(&ffmpeg_path)
        .args(build_on_demand_transcode_args(hw_accel))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("On-demand segment generation failed: {}", e))?;

    if !output.status.success() {
        // 硬件编码失败时使用软件回退
        if hw_accel != HardwareAccel::None {
            warn!(
                "Hardware on-demand encode failed ({:?}), retrying with software libx264",
                hw_accel
            );
            // 清理失败的输出
            let _ = tokio::fs::remove_file(&segment_path).await;

            let fallback_output = tokio::process::Command::new(&ffmpeg_path)
                .args(build_on_demand_transcode_args(HardwareAccel::None))
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .output()
                .await
                .map_err(|e| format!("On-demand software fallback failed: {}", e))?;

            if !fallback_output.status.success() {
                let stderr = String::from_utf8_lossy(&fallback_output.stderr);
                return Err(format!(
                    "FFmpeg on-demand failed: {}",
                    &stderr[..stderr.len().min(500)]
                ));
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "FFmpeg on-demand failed: {}",
                &stderr[..stderr.len().min(500)]
            ));
        }
    }

    // 对按需生成的分片同样进行静态加密
    encrypt_on_demand_segment(&segment_path, file_path).await;

    info!(
        "✅ On-demand segment_{}.ts generated (transcode) and encrypted",
        segment_index
    );
    Ok(())
}

/// 加密单个按需生成的分片文件
///
/// 和渐进式分片加密使用相同的 `derive_segment_storage_key` 密钥派生，
/// 确保所有分片（无论生成方式）都使用一致的加密策略。
async fn encrypt_on_demand_segment(segment_path: &std::path::Path, file_path: &str) {
    let storage_key = derive_segment_storage_key(file_path);
    if let Ok(data) = tokio::fs::read(segment_path).await {
        if let Ok(encrypted) = crate::crypto::aes_encrypt(&storage_key, &data) {
            let enc_path = segment_path.with_extension("ts.enc");
            if tokio::fs::write(&enc_path, &encrypted).await.is_ok() {
                let _ = tokio::fs::remove_file(segment_path).await;
            }
        }
    }
}

/// 使用 ffprobe 获取视频文件的总时长（秒）
///
/// 用于生成覆盖全时长的虚拟 VOD 播放列表，使播放器可以 seek 到任何位置。
/// 结果缓存到 `.duration` 文件中，避免重复调用 ffprobe。
async fn get_video_duration(ffmpeg_path: &str, file_path: &str) -> Option<f64> {
    let ffprobe_path = get_ffprobe_path(ffmpeg_path).await;

    let output = tokio::process::Command::new(&ffprobe_path)
        .args([
            "-v",
            "quiet",
            "-show_entries",
            "format=duration",
            "-of",
            "csv=p=0",
            file_path,
        ])
        .output()
        .await;

    match output {
        Ok(o) if o.status.success() => {
            let raw = String::from_utf8_lossy(&o.stdout);
            raw.trim().parse::<f64>().ok().filter(|&d| d > 0.0)
        }
        _ => None,
    }
}

/// 生成覆盖完整视频时长的 VOD 播放列表
///
/// 渐进式 HLS 的 ffmpeg playlist 仅列出已生成的分片，导致播放器无法 seek 到
/// 尚未生成的位置。此函数生成一个列出所有分片的完整 VOD playlist，使播放器
/// 可以 seek 到任何位置。当播放器请求尚未生成的分片时，`get_segment_direct`
/// 会调用 `generate_segment_on_demand` 按需生成。
fn generate_complete_vod_playlist(total_duration: f64, segment_duration: f64) -> String {
    let total_segments = (total_duration / segment_duration).ceil() as usize;
    // 实际 target duration 向上取整（HLS 规范要求 TARGETDURATION ≥ 所有 EXTINF）
    let target_duration = segment_duration.ceil() as u64;

    let mut playlist = String::with_capacity(total_segments * 40 + 200);
    playlist.push_str("#EXTM3U\n");
    playlist.push_str("#EXT-X-VERSION:3\n");
    playlist.push_str(&format!("#EXT-X-TARGETDURATION:{}\n", target_duration));
    playlist.push_str("#EXT-X-MEDIA-SEQUENCE:0\n");
    playlist.push_str("#EXT-X-PLAYLIST-TYPE:VOD\n");
    playlist.push_str("#EXT-X-INDEPENDENT-SEGMENTS\n");

    for i in 0..total_segments {
        let dur = if i == total_segments - 1 {
            // 最后一个分片可能短于标准时长
            let remaining = total_duration - (i as f64 * segment_duration);
            if remaining > 0.001 {
                remaining
            } else {
                segment_duration
            }
        } else {
            segment_duration
        };
        playlist.push_str(&format!("#EXTINF:{:.6},\n", dur));
        playlist.push_str(&format!("segment_{}.ts\n", i));
    }

    playlist.push_str("#EXT-X-ENDLIST\n");
    playlist
}

/// 获取 HLS 播放列表（基于 ffmpeg 生成的真实分片）
///
/// 不需要 JWT 认证 — session_id 本身就是鉴权 token（创建时已验证 JWT + SAE）。
/// 首次请求时自动触发 ffmpeg 分片（优先 stream copy）。
///
/// ★ Seek 优化：当视频仍在渐进式分片时，返回覆盖全时长的虚拟 VOD 播放列表，
/// 使播放器可以 seek 到任何位置（尚未生成的分片会被 get_segment_direct 按需生成）。
pub async fn get_secure_playlist(
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    path: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let session_id = path.into_inner();

    info!(
        "📋 Playlist request for session: {} (len={})",
        session_id,
        session_id.len()
    );

    // 验证会话并获取文件路径（然后释放读锁）
    let file_path = {
        let manager = hls_manager.read().await;

        // Debug: list active sessions
        let sessions = manager.sessions.lock().unwrap();
        let active_count = sessions.len();
        let known_ids: Vec<String> = sessions.keys().cloned().collect();
        let found = sessions.contains_key(&session_id);
        drop(sessions);

        info!(
            "📋 Session lookup: requested={}, found={}, active_sessions={}, known_ids={:?}",
            session_id, found, active_count, known_ids
        );

        let session = manager
            .get_session(&session_id)
            .map_err(convert_hls_error)?;
        session.file_path.clone()
    };

    // 确保 HLS 分片存在（首次会触发 ffmpeg 分片）。
    // 若外部缓存不可用，降级为无落盘的虚拟 VOD playlist，避免播放器长时间卡在等待分片。
    let ensured = ensure_hls_segments(&file_path).await;

    let (_cache_dir, playlist_content, no_disk_mode) = match ensured {
        Ok((cache_dir, content)) => (Some(cache_dir), content, false),
        Err(AppError::PreconditionFailed(msg))
            if msg.contains("Refusing to write cache")
                || msg.contains("refusing to create cache")
                || msg.contains("External storage") =>
        {
            warn!(
                "External cache unavailable for session {}, using no-disk virtual playlist: {}",
                session_id, msg
            );
            (None, String::new(), true)
        }
        Err(e) => return Err(e),
    };

    // ★ 关键优化：渐进式 HLS 的 playlist 仅列出已生成的分片，
    //   导致播放器无法 seek 到尚未生成的位置（超出 ffmpeg 当前进度）。
    //   解决方案：当视频仍在分片时，返回覆盖全时长的虚拟 VOD playlist。
    //   播放器因此可以 seek 到任何位置；当它请求尚未生成的分片时，
    //   get_segment_direct 会自动调用 generate_segment_on_demand 按需生成。
    let final_content = if !no_disk_mode && playlist_content.contains("#EXT-X-ENDLIST") {
        // 分片已全部完成 — 使用 ffmpeg 生成的真实 playlist（时长精确）
        playlist_content
    } else {
        // 视频仍在转码中 — 尝试生成覆盖全时长的虚拟 VOD playlist
        let duration_file = _cache_dir.as_ref().map(|d| d.join(".duration"));
        let duration = if duration_file.as_ref().is_some_and(|p| p.exists()) {
            // 优先使用缓存的时长（避免重复调用 ffprobe）
            tokio::fs::read_to_string(duration_file.as_ref().unwrap())
                .await
                .ok()
                .and_then(|s| s.trim().parse::<f64>().ok())
                .filter(|&d| d > 0.0)
        } else {
            // 首次：通过 ffprobe 获取时长并缓存
            let ffmpeg_path = std::env::var("FFMPEG_PATH")
                .or_else(|_| rockzero_media::get_global_ffmpeg_path().ok_or(""))
                .unwrap_or_else(|_| "ffmpeg".to_string());
            let dur = get_video_duration(&ffmpeg_path, &file_path).await;
            if let (Some(d), Some(duration_file)) = (dur, duration_file.as_ref()) {
                let _ = tokio::fs::write(duration_file, format!("{:.6}", d)).await;
            }
            dur
        };

        match duration {
            Some(d) => {
                info!(
                    "📋 Generating complete VOD playlist (duration={:.1}s, segments={}) for full seekability",
                    d,
                    (d / 2.0).ceil() as usize
                );
                generate_complete_vod_playlist(d, 2.0)
            }
            None => {
                // 无法获取时长 — 在 no-disk 模式下回退一个短窗口 playlist，保障尽快起播。
                if no_disk_mode {
                    warn!("📋 Cannot determine duration in no-disk mode, using short fallback playlist");
                    generate_complete_vod_playlist(1800.0, 2.0)
                } else {
                    warn!("📋 Cannot determine video duration, falling back to progressive playlist");
                    playlist_content
                }
            }
        }
    };

    // ★ 更新 .last_access 标记，防止活跃缓存被 LRU 驱逐
    if let Some(cache_dir) = _cache_dir.as_ref() {
        touch_cache_access(cache_dir).await;
    }

    // 记录该会话当前是否处于无落盘模式，供系统状态接口实时查询。
    set_session_no_disk_mode(&session_id, no_disk_mode);

    info!(
        "📋 Serving playlist for session {} ({})",
        session_id, file_path
    );

    Ok(HttpResponse::Ok()
        .content_type("application/vnd.apple.mpegurl")
        .insert_header(("Cache-Control", "no-cache, no-store"))
        .insert_header(("Access-Control-Allow-Origin", "*"))
        .body(final_content))
}

fn parse_segment_index(segment_name: &str) -> Option<usize> {
    if !segment_name.starts_with("segment_") || !segment_name.ends_with(".ts") {
        return None;
    }

    segment_name
        .trim_start_matches("segment_")
        .trim_end_matches(".ts")
        .parse::<usize>()
        .ok()
}

fn get_max_existing_segment_index(cache_dir: &std::path::Path) -> Option<usize> {
    let mut max_idx: Option<usize> = None;

    let entries = match std::fs::read_dir(cache_dir) {
        Ok(entries) => entries,
        Err(_) => return None,
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();

        let idx = if file_name.starts_with("segment_") && file_name.ends_with(".ts") {
            file_name
                .trim_start_matches("segment_")
                .trim_end_matches(".ts")
                .parse::<usize>()
                .ok()
        } else if file_name.starts_with("segment_") && file_name.ends_with(".ts.enc") {
            file_name
                .trim_start_matches("segment_")
                .trim_end_matches(".ts.enc")
                .parse::<usize>()
                .ok()
        } else {
            None
        };

        if let Some(idx) = idx {
            max_idx = Some(max_idx.map_or(idx, |current| current.max(idx)));
        }
    }

    max_idx
}

async fn wait_for_segment_ready(
    cache_dir: &std::path::Path,
    segment_name: &str,
    max_wait_ms: u64,
) -> Result<bool, AppError> {
    let segment_path = cache_dir.join(segment_name);
    let enc_path = segment_path.with_extension("ts.enc");
    let done_marker = cache_dir.join(".done");
    let target_idx = parse_segment_index(segment_name);

    let mut waited_ms = 0u64;
    let poll_interval_ms = 120u64;

    while waited_ms <= max_wait_ms {
        if segment_path.exists() || enc_path.exists() {
            return Ok(true);
        }

        if done_marker.exists() {
            if let Some(target_idx) = target_idx {
                if let Some(max_idx) = get_max_existing_segment_index(cache_dir) {
                    if target_idx > max_idx {
                        return Ok(false);
                    }
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval_ms)).await;
        waited_ms += poll_interval_ms;
    }

    Ok(segment_path.exists() || enc_path.exists())
}

pub async fn get_segment_direct(
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    path: web::Path<(String, String)>,
) -> Result<impl Responder, AppError> {
    let (session_id, segment_name) = path.into_inner();

    // 验证段名称格式
    if !segment_name.ends_with(".ts") {
        return Err(AppError::BadRequest(format!(
            "Invalid segment name: '{}'",
            segment_name
        )));
    }

    // 先读取会话必要数据，避免在 await 期间持有 RwLock 读锁
    let file_path = {
        let manager = hls_manager.read().await;
        let session = manager
            .get_session(&session_id)
            .map_err(convert_hls_error)?;
        session.file_path.clone()
    };

    let video_hash = blake3::hash(file_path.as_bytes());
    let video_id = hex::encode(&video_hash.as_bytes()[..8]);
    let cache_root = ensure_external_hls_cache_root().ok();

    if cache_root.is_none() {
        warn_no_disk_fallback_once(Some(&session_id), &segment_name);
        if let Some(idx) = parse_segment_index_from_name(&segment_name) {
            prewarm_no_disk_segments(file_path.clone(), session_id.clone(), idx);
        }
        let segment_data =
            read_video_segment_from_ffmpeg(&file_path, &segment_name, Some(&session_id)).await?;

        let manager = hls_manager.read().await;
        let session = manager
            .get_session(&session_id)
            .map_err(convert_hls_error)?;
        let encrypted_data = session
            .encrypt_segment(&segment_data)
            .map_err(convert_hls_error)?;

        return Ok(HttpResponse::Ok()
            .content_type("application/octet-stream")
            .insert_header(("X-Encrypted", "true"))
            .insert_header(("X-Encryption-Method", "AES-256-GCM"))
            .insert_header(("X-Key-Exchange", "WPA3-SAE"))
            .insert_header(("X-Integrity", "Blake3"))
            .insert_header(("X-No-Disk-Mode", "true"))
            .insert_header(("Content-Length", encrypted_data.len()))
            .insert_header(("Cache-Control", "no-cache, no-store, must-revalidate"))
            .insert_header(("Access-Control-Allow-Origin", "*"))
            .body(encrypted_data));
    }

    let cache_dir = cache_root.unwrap().join(&video_id);
    let segment_path = cache_dir.join(&segment_name);
    let enc_path = segment_path.with_extension("ts.enc");

    if !segment_path.exists() && !enc_path.exists() {
        ensure_hls_segments(&file_path).await?;

        let done_marker = cache_dir.join(".done");
        let target_idx = parse_segment_index(&segment_name);
        let current_max = get_max_existing_segment_index(&cache_dir);

        let is_far_ahead_seek = !done_marker.exists()
            && target_idx
                .map(|idx| idx > current_max.unwrap_or(0) + 5)
                .unwrap_or(false);

        if is_far_ahead_seek {
            let idx = target_idx.unwrap();
            let max = current_max.unwrap_or(0);
            info!(
                "🎯 Far-ahead seek detected: segment_{} requested (current max={}), generating on-demand immediately",
                idx, max
            );
            match generate_segment_on_demand(&file_path, &cache_dir, idx, 2.0).await {
                Ok(()) => {
                    info!("🎯 On-demand segment_{} ready, serving", idx);
                }
                Err(e) => {
                    warn!("On-demand generation failed for segment_{}: {}", idx, e);
                    let ready = wait_for_segment_ready(&cache_dir, &segment_name, 45_000).await?;
                    if !ready {
                        return Ok(HttpResponse::ServiceUnavailable()
                            .insert_header(("Retry-After", "3"))
                            .insert_header(("Cache-Control", "no-cache, no-store, must-revalidate"))
                            .insert_header(("Access-Control-Allow-Origin", "*"))
                            .body(format!(
                                "Segment '{}' is still being generated, please retry",
                                segment_name
                            )));
                    }
                }
            }
        } else {
            let ready = wait_for_segment_ready(&cache_dir, &segment_name, 15_000).await?;
            if !ready {
                if done_marker.exists() {
                    let max_str = current_max
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    return Err(AppError::NotFound(format!(
                        "Segment '{}' not available (video_id={}, max_generated={})",
                        segment_name, video_id, max_str
                    )));
                }

                if let Some(idx) = target_idx {
                    let max = current_max.unwrap_or(0);
                    if idx > max + 5 {
                        info!(
                            "🎯 Segment_{} still not ready after initial wait (max={}), trying on-demand",
                            idx, max
                        );
                        match generate_segment_on_demand(&file_path, &cache_dir, idx, 2.0).await {
                            Ok(()) => {
                                info!("🎯 On-demand segment_{} ready, serving", idx);
                            }
                            Err(e) => {
                                warn!("On-demand generation failed for segment_{}: {}", idx, e);
                                let ready2 =
                                    wait_for_segment_ready(&cache_dir, &segment_name, 30_000)
                                        .await?;
                                if !ready2 {
                                    return Ok(HttpResponse::ServiceUnavailable()
                                        .insert_header(("Retry-After", "3"))
                                        .insert_header((
                                            "Cache-Control",
                                            "no-cache, no-store, must-revalidate",
                                        ))
                                        .insert_header(("Access-Control-Allow-Origin", "*"))
                                        .body(format!(
                                            "Segment '{}' is still being generated, please retry",
                                            segment_name
                                        )));
                                }
                            }
                        }
                    } else {
                        let ready2 =
                            wait_for_segment_ready(&cache_dir, &segment_name, 30_000).await?;
                        if !ready2 {
                            return Ok(HttpResponse::ServiceUnavailable()
                                .insert_header(("Retry-After", "2"))
                                .insert_header((
                                    "Cache-Control",
                                    "no-cache, no-store, must-revalidate",
                                ))
                                .insert_header(("Access-Control-Allow-Origin", "*"))
                                .body(format!(
                                    "Segment '{}' is still being generated, please retry",
                                    segment_name
                                )));
                        }
                    }
                } else {
                    return Ok(HttpResponse::ServiceUnavailable()
                        .insert_header(("Retry-After", "2"))
                        .insert_header(("Cache-Control", "no-cache, no-store, must-revalidate"))
                        .insert_header(("Access-Control-Allow-Origin", "*"))
                        .body(format!(
                            "Segment '{}' is still being generated, please retry",
                            segment_name
                        )));
                }
            }
        }
    }

    let storage_key = derive_segment_storage_key(&file_path);
    let segment_data = read_segment_data(&segment_path, &storage_key).await?;

    touch_cache_access(&cache_dir).await;

    let manager = hls_manager.read().await;
    let session = manager
        .get_session(&session_id)
        .map_err(convert_hls_error)?;
    let encrypted_data = session
        .encrypt_segment(&segment_data)
        .map_err(convert_hls_error)?;

    info!(
        "🔒 Serving AES-256-GCM encrypted segment {} for session {} (plain: {} bytes, encrypted: {} bytes)",
        segment_name,
        session_id,
        segment_data.len(),
        encrypted_data.len()
    );

    Ok(HttpResponse::Ok()
        .content_type("application/octet-stream")
        .insert_header(("X-Encrypted", "true"))
        .insert_header(("X-Encryption-Method", "AES-256-GCM"))
        .insert_header(("X-Key-Exchange", "WPA3-SAE"))
        .insert_header(("X-Integrity", "Blake3"))
        .insert_header(("X-No-Disk-Mode", "false"))
        .insert_header(("Content-Length", encrypted_data.len()))
        .insert_header(("Cache-Control", "no-cache, no-store, must-revalidate"))
        .insert_header(("Access-Control-Allow-Origin", "*"))
        .body(encrypted_data))
}

pub async fn get_secure_segment(
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    path: web::Path<(String, String)>,
    req: actix_web::HttpRequest,
    body: web::Bytes,
) -> Result<impl Responder, AppError> {
    let (session_id, segment_name) = path.into_inner();

    if req.method() != actix_web::http::Method::POST {
        warn!(
            "Invalid HTTP method for segment request: {} (expected POST)",
            req.method()
        );
        return Err(AppError::BadRequest(
            "Segment requests must use POST method with ZKP proof".to_string(),
        ));
    }

    let segment_request: SecureSegmentRequest = serde_json::from_slice(&body).map_err(|e| {
        warn!("Failed to parse segment request body: {}", e);
        AppError::BadRequest(format!("Invalid JSON body: {}", e))
    })?;

    info!(
        "Secure segment request: session={}, segment={}, zkp_proof_len={}",
        session_id,
        segment_name,
        segment_request.zkp_proof.len()
    );

    let manager = hls_manager.read().await;
    let session = manager
        .get_session(&session_id)
        .map_err(convert_hls_error)?;

    if !verify_zkp_proof(&session, &segment_request.zkp_proof)? {
        warn!(
            "Invalid ZKP proof for session {} segment {}",
            session_id, segment_name
        );
        return Err(AppError::Unauthorized(
            "Invalid ZKP proof - authentication failed".to_string(),
        ));
    }

    info!(
        "✅ ZKP proof verified for session {} segment {}",
        session_id, segment_name
    );

    let mut no_disk_mode = false;

    let segment_data = {
        let video_hash = blake3::hash(session.file_path.as_bytes());
        let video_id = hex::encode(&video_hash.as_bytes()[..8]);
        if let Ok(cache_root) = ensure_external_hls_cache_root() {
            let cache_dir = cache_root.join(&video_id);
            let segment_path = cache_dir.join(&segment_name);

            let storage_key = derive_segment_storage_key(&session.file_path);
            let enc_path = segment_path.with_extension("ts.enc");

            // ★ 更新 .last_access 标记，防止活跃缓存被 LRU 驱逐
            touch_cache_access(&cache_dir).await;

            if enc_path.exists() || segment_path.exists() {
                read_segment_data(&segment_path, &storage_key).await?
            } else {
                read_video_segment_from_ffmpeg(
                    &session.file_path,
                    &segment_name,
                    Some(&session_id),
                )
                .await?
            }
        } else {
            warn_no_disk_fallback_once(Some(&session_id), &segment_name);
            no_disk_mode = true;
            if let Some(idx) = parse_segment_index_from_name(&segment_name) {
                prewarm_no_disk_segments(session.file_path.clone(), session_id.clone(), idx);
            }
            read_video_segment_from_ffmpeg(&session.file_path, &segment_name, Some(&session_id))
                .await?
        }
    };

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
        .insert_header(("X-ZKP-Verified", "true"))
        .insert_header((
            "X-No-Disk-Mode",
            if no_disk_mode { "true" } else { "false" },
        ))
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

    clear_session_no_disk_mode(&session_id);

    info!("Stopping HLS session: {}", session_id);
    let manager = hls_manager.read().await;

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

pub async fn get_transport_stats(
    hybrid_transport: web::Data<Arc<rockzero_media::HybridTransport>>,
) -> Result<impl Responder, AppError> {
    let stats = hybrid_transport.get_stats().await;
    let bandwidth = hybrid_transport.estimate_bandwidth().await;
    let current_ratio = hybrid_transport.current_udp_ratio().await;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "transport": "hybrid",
        "protocol": "UDP+TCP",
        "config": {
            "target_udp_ratio": 0.7,
            "target_tcp_ratio": 0.3,
            "current_udp_ratio": current_ratio,
            "current_tcp_ratio": 1.0 - current_ratio,
            "adaptive": true
        },
        "stats": {
            "udp_chunks_sent": stats.udp_chunks_sent,
            "tcp_chunks_sent": stats.tcp_chunks_sent,
            "udp_bytes_sent": stats.udp_bytes_sent,
            "tcp_bytes_sent": stats.tcp_bytes_sent,
            "udp_packets_lost": stats.udp_packets_lost,
            "total_chunks": stats.total_chunks,
            "effective_udp_ratio": stats.effective_udp_ratio,
            "effective_tcp_ratio": stats.effective_tcp_ratio,
            "bandwidth_bps": bandwidth,
            "bandwidth_mbps": bandwidth as f64 / 1_000_000.0
        },
        "encryption": {
            "method": "AES-256-GCM",
            "key_exchange": "WPA3-SAE",
            "integrity": "Blake3",
            "zkp": "Bulletproofs"
        }
    })))
}

#[allow(dead_code)]
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

/// 验证客户端的 Bulletproofs ZKP 证明
///
/// **生产级安全实现**：使用 Bulletproofs 零知识证明验证
///
/// ## 验证流程
/// 1. 解码 Base64 编码的证明
/// 2. 解析为 EnhancedPasswordProof 结构
/// 3. 验证上下文绑定（必须是 "hls_segment_access"）
/// 4. 验证时间戳（防止延迟重放，5分钟有效期）
/// 5. 使用 ZkpContext 验证 Schnorr 证明和范围证明
///
/// ## 安全特性
/// - Schnorr 证明：验证客户端知道密码，不泄露密码本身
/// - Schnorr 证明：验证密码知识
/// - Bulletproofs 范围证明：密码熵值 >= 28 bits（密码学证明）
/// - 时间戳 + nonce：防止重放攻击
/// - 上下文绑定：防止跨上下文攻击
///
/// ## 证明类型
/// - EnhancedPasswordProof: Schnorr 证明 + Bulletproofs 范围证明（完整版）
///
/// ## 要求
/// - 会话必须包含 PasswordRegistration（用户注册时生成）
/// - 客户端必须使用相同的密码生成证明
///
fn verify_zkp_proof(session: &HlsSession, proof_base64: &str) -> Result<bool, AppError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    // 1. 解码 Base64 编码的证明
    let proof_bytes = BASE64.decode(proof_base64).map_err(|e| {
        AppError::BadRequest(format!("Invalid Base64 encoding in ZKP proof: {}", e))
    })?;

    // 2. 解析为 EnhancedPasswordProof（完整的 Bulletproofs 证明）
    let proof: EnhancedPasswordProof = serde_json::from_slice(&proof_bytes).map_err(|e| {
        AppError::BadRequest(format!(
            "Invalid EnhancedPasswordProof structure: {}. \
             Ensure the client is using the full Bulletproofs implementation.",
            e
        ))
    })?;

    const EXPECTED_CONTEXT: &str = "hls_segment_access";
    const MAX_AGE_SECONDS: i64 = 300; // 5分钟有效期

    // 3. 验证上下文
    if proof.context != EXPECTED_CONTEXT {
        warn!(
            "ZKP proof context mismatch: expected '{}', got '{}'",
            EXPECTED_CONTEXT, proof.context
        );
        return Ok(false);
    }

    // 4. 验证时间戳（防止延迟重放）
    let now = chrono::Utc::now().timestamp();
    if now - proof.timestamp > MAX_AGE_SECONDS {
        warn!(
            "ZKP proof expired: timestamp={}, now={}, age={}s",
            proof.timestamp,
            now,
            now - proof.timestamp
        );
        return Ok(false);
    }

    if proof.timestamp > now + 60 {
        warn!(
            "ZKP proof timestamp in future: timestamp={}, now={}",
            proof.timestamp, now
        );
        return Ok(false);
    }

    // 5. 检查会话是否有 ZKP 注册数据
    let registration = session.get_zkp_registration().ok_or_else(|| {
        AppError::CryptoError(
            "Session does not have ZKP registration data. \
             User must complete registration with ZKP enabled."
                .to_string(),
        )
    })?;

    // 6. 使用 ZkpContext 验证完整的 Bulletproofs 证明
    let zkp_context = ZkpContext::new();

    info!(
        "Verifying EnhancedPasswordProof (Bulletproofs) for session {}",
        session.session_id
    );

    match zkp_context.verify_enhanced_proof(&proof, registration, EXPECTED_CONTEXT, MAX_AGE_SECONDS)
    {
        Ok(valid) => {
            if valid {
                info!(
                    "✅ Bulletproofs ZKP proof verified for session {}",
                    session.session_id
                );
            } else {
                warn!(
                    "❌ Bulletproofs ZKP proof verification failed for session {}",
                    session.session_id
                );
            }
            Ok(valid)
        }
        Err(e) => {
            warn!(
                "Bulletproofs ZKP proof verification error for session {}: {}",
                session.session_id, e
            );
            Ok(false)
        }
    }
}

/// 更新缓存目录的 `.last_access` 时间戳标记
///
/// 每次从缓存目录读取并服务一个 segment 时调用此函数。
/// StorageManager 的 LRU 驱逐和过期清理会检查此标记文件，
/// 避免删除正在被 HLS session 活跃使用的缓存目录。
///
/// 与文件系统 atime 相比，此方法不受 Linux noatime 挂载选项影响。
async fn touch_cache_access(cache_dir: &std::path::Path) {
    let marker = cache_dir.join(".last_access");
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let _ = tokio::fs::write(&marker, ts.to_string().as_bytes()).await;
}

/// 视频段缓存目录配置
///
/// 与 StorageConfig 使用相同的环境变量配置，确保清理任务能正确清理缓存。
///
/// 优先级:
/// 1. `HLS_CACHE_PATH` 环境变量（与 StorageConfig 一致）
/// 2. `ROCKZERO_HLS_CACHE_DIR` 环境变量（兼容旧配置）
/// 3. 默认 `/mnt/external/cache/hls`（与 StorageConfig 默认值一致）
fn get_hls_cache_dir() -> std::path::PathBuf {
    // 优先使用 HLS_CACHE_PATH（与 StorageConfig 一致）
    std::env::var("HLS_CACHE_PATH")
        .or_else(|_| std::env::var("ROCKZERO_HLS_CACHE_DIR"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            // 默认使用 /mnt/external/cache/hls（与 StorageConfig 默认值一致）
            std::path::PathBuf::from("/mnt/external/cache/hls")
        })
}

#[cfg(target_os = "linux")]
fn is_same_filesystem_as_root(path: &std::path::Path) -> bool {
    use std::os::linux::fs::MetadataExt;

    let root_md = match std::fs::metadata("/") {
        Ok(v) => v,
        Err(_) => return false,
    };
    let path_md = match std::fs::metadata(path) {
        Ok(v) => v,
        Err(_) => return false,
    };
    root_md.st_dev() == path_md.st_dev()
}

#[cfg(not(target_os = "linux"))]
fn is_same_filesystem_as_root(_path: &std::path::Path) -> bool {
    false
}

fn ensure_external_hls_cache_root() -> Result<std::path::PathBuf, AppError> {
    let root = get_hls_cache_dir();
    let allow_internal = std::env::var("ROCKZERO_ALLOW_INTERNAL_HLS_CACHE")
        .ok()
        .map(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);

    if allow_internal {
        std::fs::create_dir_all(&root).map_err(|e| {
            AppError::IoError(format!(
                "Failed to create HLS cache directory {:?}: {}",
                root, e
            ))
        })?;
        return Ok(root);
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(stripped) = root.strip_prefix("/") {
            let mut parts = stripped.components();
            if let (Some(first), Some(second)) = (parts.next(), parts.next()) {
                if first.as_os_str() == "mnt" {
                    let anchor = std::path::Path::new("/")
                        .join(first.as_os_str())
                        .join(second.as_os_str());
                    if !anchor.exists() {
                        return Err(AppError::PreconditionFailed(format!(
                            "External storage anchor {:?} is missing; refusing to create cache on internal storage",
                            anchor
                        )));
                    }
                    if is_same_filesystem_as_root(&anchor) {
                        return Err(AppError::PreconditionFailed(format!(
                            "External storage anchor {:?} is on root filesystem; refusing internal cache writes",
                            anchor
                        )));
                    }
                }
            }
        }
    }

    std::fs::create_dir_all(&root).map_err(|e| {
        AppError::IoError(format!(
            "Failed to create external HLS cache directory {:?}: {}",
            root, e
        ))
    })?;

    if is_same_filesystem_as_root(&root) {
        return Err(AppError::PreconditionFailed(format!(
            "External HLS cache path {:?} is on root filesystem. Refusing to write cache to internal storage. Please mount external storage under /mnt and set HLS_CACHE_PATH.",
            root
        )));
    }

    Ok(root)
}

/// 从 FFmpeg 转码输出读取视频段
///
/// 生产级实现流程：
/// 1. 验证段名称格式（防止路径遍历攻击）
/// 2. 计算视频文件的唯一标识符（用于缓存目录）
/// 3. 尝试从 HLS 缓存目录读取预转码的段
/// 4. 如果缓存不存在，触发实时转码（通过 FFmpeg）
/// 5. 支持段索引验证和路径遍历保护
///
/// # 缓存策略
/// - 缓存目录：`/var/cache/rockzero/hls/{video_hash}/`
/// - 段文件命名：`segment_N.ts`
/// - 自动创建缓存目录
/// - 转码失败时返回错误，不阻塞服务
async fn read_video_segment_from_ffmpeg(
    file_path: &str,
    segment_name: &str,
    session_id: Option<&str>,
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
        .map_err(|_| {
            AppError::BadRequest(format!("Invalid segment index in name: '{}'", segment_name))
        })?;

    // 3. 验证段索引范围（防止过大的索引导致问题）
    const MAX_SEGMENT_INDEX: usize = 100_000;
    if segment_index > MAX_SEGMENT_INDEX {
        return Err(AppError::BadRequest(format!(
            "Segment index {} exceeds maximum allowed ({})",
            segment_index, MAX_SEGMENT_INDEX
        )));
    }

    // 4. 计算视频文件的唯一标识符（用于缓存目录）
    let video_hash = blake3::hash(file_path.as_bytes());
    let video_id = hex::encode(&video_hash.as_bytes()[..8]); // 使用前 8 字节作为 ID

    // 5. 构建缓存目录路径（若外部缓存不可用，自动降级到无落盘实时转码）
    let cache_root = ensure_external_hls_cache_root().ok();
    let cache_dir = cache_root.as_ref().map(|root| root.join(&video_id));
    let cached_segment_path = cache_dir.as_ref().map(|dir| dir.join(segment_name));

    if cache_dir.is_none() {
        warn_no_disk_fallback_once(session_id, segment_name);

        let cache_key = format!("{}:{}", video_id, segment_name);
        if let Some(cached) = get_cached_no_disk_segment(&cache_key) {
            return Ok(cached);
        }

        let lock = get_no_disk_segment_lock(&cache_key);
        let _guard = lock.lock().await;

        if let Some(cached) = get_cached_no_disk_segment(&cache_key) {
            return Ok(cached);
        }

        let original_video = PathBuf::from(file_path);
        if !original_video.exists() {
            return Err(AppError::NotFound(format!(
                "Original video file not found: {}",
                file_path
            )));
        }

        let transcode_result = transcode_segment_in_memory(&original_video, segment_index).await;
        if let Ok(ref segment_data) = transcode_result {
            put_cached_no_disk_segment(cache_key.clone(), segment_data.clone());
        }
        drop(_guard);
        release_no_disk_segment_lock(&cache_key);
        return transcode_result;
    }

    let cache_dir = cache_dir.expect("checked above");
    let cached_segment_path = cached_segment_path.expect("checked above");

    // 6. 尝试从缓存读取
    if cached_segment_path.exists() {
        info!(
            "Cache hit for segment {} of video {}",
            segment_name, video_id
        );
        return tokio::fs::read(&cached_segment_path).await.map_err(|e| {
            AppError::IoError(format!(
                "Failed to read cached segment {}: {}",
                segment_name, e
            ))
        });
    }

    // 7. 缓存不存在，检查原始视频文件
    let original_video = PathBuf::from(file_path);
    if !original_video.exists() {
        return Err(AppError::NotFound(format!(
            "Original video file not found: {}",
            file_path
        )));
    }

    // 8. 触发实时转码
    info!(
        "Cache miss for segment {} of video {}, triggering FFmpeg transcode",
        segment_name, video_id
    );

    // 创建缓存目录
    if !cache_dir.exists() {
        tokio::fs::create_dir_all(&cache_dir)
            .await
            .map_err(|e| AppError::IoError(format!("Failed to create cache directory: {}", e)))?;
    }

    // 调用 FFmpeg 进行转码（异步版本）
    let segment_data = transcode_segment_async(&original_video, &cache_dir, segment_index).await?;

    // 将转码结果写入缓存（异步，失败不阻塞）
    let cache_path_clone = cached_segment_path.clone();
    let data_clone = segment_data.clone();
    tokio::spawn(async move {
        if let Err(e) = tokio::fs::write(&cache_path_clone, &data_clone).await {
            warn!("Failed to cache segment: {}", e);
        }
    });

    Ok(segment_data)
}

async fn transcode_segment_in_memory(
    video_path: &std::path::Path,
    segment_index: usize,
) -> Result<Vec<u8>, AppError> {
    use tokio::process::Command;

    const SEGMENT_DURATION: f64 = 2.0;
    let start_time = segment_index as f64 * SEGMENT_DURATION;

    let ffmpeg_path = std::env::var("FFMPEG_PATH")
        .or_else(|_| rockzero_media::get_global_ffmpeg_path().ok_or(""))
        .unwrap_or_else(|_| "ffmpeg".to_string());

    let file_path_str = video_path.to_string_lossy().to_string();
    let codec_key = hex::encode(blake3::hash(file_path_str.as_bytes()).as_bytes());

    let maybe_codec = {
        let cache = video_codec_cache().lock().unwrap_or_else(|e| e.into_inner());
        cache.get(&codec_key).cloned().flatten()
    };

    let video_codec = match maybe_codec {
        Some(codec) => Some(codec),
        None => {
            let detected = detect_video_codec(&ffmpeg_path, &file_path_str).await;
            let mut cache = video_codec_cache().lock().unwrap_or_else(|e| e.into_inner());
            cache.insert(codec_key, detected.clone());
            detected
        }
    };

    let can_try_stream_copy = matches!(video_codec.as_deref(), Some("h264" | "hevc" | "h265"));

    if can_try_stream_copy {
        let bsf = if matches!(video_codec.as_deref(), Some("hevc" | "h265")) {
            "hevc_mp4toannexb"
        } else {
            "h264_mp4toannexb"
        };

        let copy_args = vec![
            "-v".to_string(),
            "warning".to_string(),
            "-ss".to_string(),
            format!("{:.3}", start_time),
            "-i".to_string(),
            file_path_str.clone(),
            "-t".to_string(),
            format!("{:.3}", SEGMENT_DURATION),
            "-map".to_string(),
            "0:v:0".to_string(),
            "-map".to_string(),
            "0:a?".to_string(),
            "-c".to_string(),
            "copy".to_string(),
            "-bsf:v".to_string(),
            bsf.to_string(),
            "-fflags".to_string(),
            "+genpts".to_string(),
            "-avoid_negative_ts".to_string(),
            "make_zero".to_string(),
            "-muxdelay".to_string(),
            "0".to_string(),
            "-muxpreload".to_string(),
            "0".to_string(),
            "-f".to_string(),
            "mpegts".to_string(),
            "pipe:1".to_string(),
        ];

        let copy_out = Command::new(&ffmpeg_path)
            .args(&copy_args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .await
            .map_err(|e| AppError::IoError(format!("Failed to run ffmpeg copy mode: {}", e)))?;

        if copy_out.status.success() && !copy_out.stdout.is_empty() {
            return Ok(copy_out.stdout);
        }
    }

    let hw_accel = detect_hardware_acceleration().await;
    let mut args = vec![
        "-v".to_string(),
        "warning".to_string(),
        "-threads".to_string(),
        "0".to_string(),
        "-ss".to_string(),
        format!("{:.3}", start_time),
    ];

    match hw_accel {
        HardwareAccel::Vaapi => {
            args.extend(vec![
                "-hwaccel".to_string(),
                "vaapi".to_string(),
                "-hwaccel_device".to_string(),
                "/dev/dri/renderD128".to_string(),
                "-hwaccel_output_format".to_string(),
                "vaapi".to_string(),
            ]);
        }
        _ => {
            args.extend(vec!["-hwaccel".to_string(), "auto".to_string()]);
        }
    }

    args.extend(vec![
        "-i".to_string(),
        file_path_str,
        "-t".to_string(),
        format!("{:.3}", SEGMENT_DURATION),
        "-c:v".to_string(),
        "libx264".to_string(),
        "-preset".to_string(),
        "veryfast".to_string(),
        "-c:a".to_string(),
        "aac".to_string(),
        "-f".to_string(),
        "mpegts".to_string(),
        "pipe:1".to_string(),
    ]);

    let out = Command::new(&ffmpeg_path)
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .map_err(|e| AppError::IoError(format!("Failed to run ffmpeg: {}", e)))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(AppError::InternalServerError(format!(
            "ffmpeg in-memory transcode failed for segment {}: {}",
            segment_index, stderr
        )));
    }

    Ok(out.stdout)
}

/// 使用 FFmpeg 异步转码单个视频段
///
/// 这是一个异步实现，用于按需转码。
/// 支持硬件加速和多种编码器选择。
///
/// # FFmpeg 参数说明
/// - `-ss`: 起始时间（基于段索引计算）
/// - `-t`: 段持续时间（默认 10 秒）
/// - `-c:v libx264`: 使用 H.264 编码（软件编码）
/// - `-c:a aac`: 使用 AAC 音频编码
/// - `-f mpegts`: 输出 MPEG-TS 格式
///
/// # 硬件加速支持
/// - 检测 `/dev/dri` 设备（Intel/AMD GPU）
/// - 检测 `/dev/video*` 设备（V4L2 硬件编码器）
/// - ARM 平台优化（A311D 等 SoC）
async fn transcode_segment_async(
    video_path: &std::path::Path,
    output_dir: &std::path::Path,
    segment_index: usize,
) -> Result<Vec<u8>, AppError> {
    use tokio::process::Command;

    const SEGMENT_DURATION: f64 = 2.0; // 与 HLS playlist 保持一致（2 秒分片）
    let start_time = segment_index as f64 * SEGMENT_DURATION;

    let output_path = output_dir.join(format!("segment_{}.ts", segment_index));

    // 检测 FFmpeg 可执行文件路径
    let ffmpeg_path = std::env::var("FFMPEG_PATH")
        .or_else(|_| rockzero_media::get_global_ffmpeg_path().ok_or(""))
        .unwrap_or_else(|_| "ffmpeg".to_string());

    // 检测硬件加速能力
    let hw_accel = detect_hardware_acceleration().await;

    // 构建 FFmpeg 命令参数
    let mut args = vec![
        "-y".to_string(), // 覆盖输出文件
        // ★ 多核并行：使用所有 CPU 核心进行编解码
        "-threads".to_string(),
        "0".to_string(),
        "-ss".to_string(),
        format!("{:.3}", start_time), // 起始时间
    ];

    // ★ 输入解码选项（必须在 -i 之前）
    // -hwaccel auto：自动选择硬件解码器，支持 AV1/VP9 等非 H.264 源的硬件辅助解码
    match hw_accel {
        HardwareAccel::Vaapi => {
            // VAAPI 专用解码管线（需指定设备和输出格式）
            args.extend(vec![
                "-hwaccel".to_string(),
                "vaapi".to_string(),
                "-hwaccel_device".to_string(),
                "/dev/dri/renderD128".to_string(),
                "-hwaccel_output_format".to_string(),
                "vaapi".to_string(),
            ]);
        }
        _ => {
            args.extend(vec!["-hwaccel".to_string(), "auto".to_string()]);
        }
    }

    args.extend(vec![
        "-i".to_string(),
        video_path.to_str().unwrap_or("").to_string(),
        "-t".to_string(),
        format!("{:.3}", SEGMENT_DURATION), // 段持续时间
        "-fflags".to_string(),
        "+genpts".to_string(),
        "-avoid_negative_ts".to_string(),
        "make_zero".to_string(),
    ]);

    // ★ 输出编码选项（根据硬件加速能力选择编码器）
    match hw_accel {
        HardwareAccel::Rkmpp => {
            info!(
                "Using Rockchip MPP hardware acceleration for segment {}",
                segment_index
            );
            args.extend(vec![
                "-c:v".to_string(),
                "h264_rkmpp".to_string(),
                "-b:v".to_string(),
                "3M".to_string(),
                "-rc_mode".to_string(),
                "VBR".to_string(),
            ]);
        }
        HardwareAccel::Vaapi => {
            info!(
                "Using VAAPI hardware acceleration for segment {}",
                segment_index
            );
            args.extend(vec![
                "-c:v".to_string(),
                "h264_vaapi".to_string(),
                "-qp".to_string(),
                "23".to_string(),
            ]);
        }
        HardwareAccel::V4l2 => {
            info!(
                "Using V4L2 hardware acceleration for segment {}",
                segment_index
            );
            args.extend(vec![
                "-c:v".to_string(),
                "h264_v4l2m2m".to_string(),
                "-b:v".to_string(),
                "2M".to_string(),
            ]);
        }
        HardwareAccel::None => {
            info!(
                "Using software encoding (libx264) for segment {}",
                segment_index
            );
            args.extend(vec![
                "-c:v".to_string(),
                "libx264".to_string(),
                "-preset".to_string(),
                "veryfast".to_string(), // 快速编码预设
                "-tune".to_string(),
                "zerolatency".to_string(), // 低延迟调优
                "-profile:v".to_string(),
                "main".to_string(), // Main Profile
                "-level".to_string(),
                "4.0".to_string(), // Level 4.0
                "-crf".to_string(),
                "23".to_string(), // 恒定质量因子
            ]);
        }
    }

    // 音频编码参数（通用）
    args.extend(vec![
        "-c:a".to_string(),
        "aac".to_string(), // AAC 音频编码
        "-b:a".to_string(),
        "128k".to_string(), // 音频码率
        "-ac".to_string(),
        "2".to_string(), // 立体声
        "-ar".to_string(),
        "44100".to_string(), // 采样率
        "-muxdelay".to_string(),
        "0".to_string(),
        "-muxpreload".to_string(),
        "0".to_string(),
        "-f".to_string(),
        "mpegts".to_string(), // MPEG-TS 容器
        output_path.to_str().unwrap_or("").to_string(),
    ]);

    // 执行 FFmpeg 命令
    let output = Command::new(&ffmpeg_path)
        .args(&args)
        .output()
        .await
        .map_err(|e| {
            AppError::IoError(format!(
                "Failed to execute FFmpeg: {}. Ensure FFmpeg is installed and in PATH.",
                e
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::InternalServerError(format!(
            "FFmpeg transcode failed for segment {}: {}",
            segment_index, stderr
        )));
    }

    // 读取生成的段文件
    tokio::fs::read(&output_path)
        .await
        .map_err(|e| AppError::IoError(format!("Failed to read transcoded segment: {}", e)))
}

/// 硬件加速类型
#[derive(Debug, Clone, Copy, PartialEq)]
enum HardwareAccel {
    Rkmpp, // Rockchip MPP (RK3588 等)
    Vaapi, // Intel/AMD GPU (VA-API)
    V4l2,  // V4L2 M2M (ARM SoC)
    None,  // 软件编码
}

/// 检测可用的硬件加速
///
/// 检测顺序（优先ARM场景）：
/// 1. 检查 CPU 架构 — aarch64 优先使用 ARM 编码器
/// 2. Rockchip MPP (`h264_rkmpp`) — RK3588/RK3399 等 SoC
/// 3. V4L2 M2M (`h264_v4l2m2m`) — 通用 ARM 硬件编码
/// 4. VAAPI (`h264_vaapi`) — Intel/AMD GPU（仅 x86_64）
/// 5. 软件编码 (`libx264`) — 最终回退
async fn detect_hardware_acceleration() -> HardwareAccel {
    if let Some(cached) = HW_ACCEL_DETECTION_CACHE.get() {
        return *cached;
    }

    let detected = detect_hardware_acceleration_uncached().await;
    let _ = HW_ACCEL_DETECTION_CACHE.set(detected);
    detected
}

async fn detect_hardware_acceleration_uncached() -> HardwareAccel {
    use tokio::fs;

    let is_arm = cfg!(target_arch = "aarch64") || cfg!(target_arch = "arm") || {
        // 运行时检测（交叉编译场景）
        if let Ok(machine) = tokio::process::Command::new("uname")
            .arg("-m")
            .output()
            .await
        {
            let arch = String::from_utf8_lossy(&machine.stdout)
                .trim()
                .to_lowercase();
            arch.contains("aarch64") || arch.contains("arm")
        } else {
            false
        }
    };

    if is_arm {
        // ARM 平台：优先 Rockchip MPP → V4L2 → 软件编码
        // 不使用 VAAPI（即使 /dev/dri/renderD128 存在也可能是 Mali 显示驱动）

        // Rockchip MPP
        if check_ffmpeg_encoder("h264_rkmpp").await {
            info!("Detected Rockchip MPP hardware encoder on ARM");
            return HardwareAccel::Rkmpp;
        }

        // V4L2 M2M — 检测设备节点和编码器支持
        let has_v4l2_device = fs::metadata("/dev/video10").await.is_ok()
            || fs::metadata("/dev/video11").await.is_ok()
            || fs::metadata("/dev/video0").await.is_ok();

        if has_v4l2_device && check_ffmpeg_encoder("h264_v4l2m2m").await {
            // 验证 V4L2 编码器真正可用（某些设备列出但无法使用）
            if verify_encoder_works("h264_v4l2m2m").await {
                info!("Detected V4L2 M2M hardware encoder on ARM");
                return HardwareAccel::V4l2;
            } else {
                warn!("V4L2 encoder listed but failed test encode, falling back to software");
            }
        }

        info!("No hardware encoder available on ARM, using software encoding");
        return HardwareAccel::None;
    }

    // x86_64 平台：VAAPI → V4L2 → 软件编码
    if fs::metadata("/dev/dri/renderD128").await.is_ok() && check_ffmpeg_encoder("h264_vaapi").await
    {
        // 验证 VAAPI 真正可用
        if verify_vaapi_works().await {
            info!("Detected VAAPI hardware encoder on x86_64");
            return HardwareAccel::Vaapi;
        } else {
            warn!("VAAPI encoder detected but test failed, falling back");
        }
    }

    // V4L2 回退
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

    let output = Command::new(&ffmpeg_path)
        .args(["-encoders"])
        .output()
        .await;

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        return stdout.contains(encoder);
    }

    false
}

/// 验证硬件编码器真正可用（而非仅列出）
///
/// 通过生成一帧测试视频来验证编码器是否真正工作。
/// 某些设备（如 Mali GPU）虽然有 /dev/dri/renderD128 但不支持编码。
async fn verify_encoder_works(encoder: &str) -> bool {
    use tokio::process::Command;

    let ffmpeg_path = std::env::var("FFMPEG_PATH")
        .or_else(|_| rockzero_media::get_global_ffmpeg_path().ok_or(""))
        .unwrap_or_else(|_| "ffmpeg".to_string());

    // 生成 1 帧黑色视频并尝试用指定编码器编码
    let result = Command::new(&ffmpeg_path)
        .args([
            "-f",
            "lavfi",
            "-i",
            "color=black:s=64x64:d=0.04:r=25",
            "-c:v",
            encoder,
            "-frames:v",
            "1",
            "-f",
            "null",
            "-y",
            "/dev/null",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;

    matches!(result, Ok(status) if status.success())
}

/// 验证 VAAPI 编码器真正可用
async fn verify_vaapi_works() -> bool {
    use tokio::process::Command;

    let ffmpeg_path = std::env::var("FFMPEG_PATH")
        .or_else(|_| rockzero_media::get_global_ffmpeg_path().ok_or(""))
        .unwrap_or_else(|_| "ffmpeg".to_string());

    let result = Command::new(&ffmpeg_path)
        .args([
            "-f",
            "lavfi",
            "-i",
            "color=black:s=64x64:d=0.04:r=25",
            "-hwaccel",
            "vaapi",
            "-hwaccel_device",
            "/dev/dri/renderD128",
            "-hwaccel_output_format",
            "vaapi",
            "-c:v",
            "h264_vaapi",
            "-frames:v",
            "1",
            "-f",
            "null",
            "-y",
            "/dev/null",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;

    matches!(result, Ok(status) if status.success())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{
        body::to_bytes,
        http::StatusCode,
        Responder,
    };
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use rockzero_media::HlsSession;
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    fn ensure_test_cache_env() -> std::path::PathBuf {
        static ROOT: OnceLock<std::path::PathBuf> = OnceLock::new();
        ROOT.get_or_init(|| {
            let root = std::env::temp_dir().join("rockzero_hls_cache_tests");
            let _ = std::fs::create_dir_all(&root);
            // CI/tests can run without external mount; enable internal cache only in test scope.
            std::env::set_var("HLS_CACHE_PATH", &root);
            std::env::set_var("ROCKZERO_ALLOW_INTERNAL_HLS_CACHE", "1");
            root
        })
        .clone()
    }

    #[test]
    fn test_secure_playlist_generation() {
        let playlist = generate_secure_m3u8(5, 10.0);

        assert!(playlist.contains("#EXTM3U"));
        assert!(playlist.contains("segment_0.ts"));
        assert!(playlist.contains("segment_4.ts"));
        assert!(!playlist.contains("#EXT-X-KEY"));
        assert!(playlist.contains("AES-256-GCM"));
    }

    #[tokio::test]
    async fn test_segment_name_validation() {
        // 无效的段名称格式（路径遍历攻击）
        let result =
            read_video_segment_from_ffmpeg("/video.mp4", "../../../etc/passwd", None).await;
        assert!(matches!(result, Err(AppError::BadRequest(_))));

        // 无效的段名称格式（负数索引）
        let result = read_video_segment_from_ffmpeg("/video.mp4", "segment_-1.ts", None).await;
        assert!(matches!(result, Err(AppError::BadRequest(_))));

        // 无效的段名称格式（非数字索引）
        let result = read_video_segment_from_ffmpeg("/video.mp4", "segment_abc.ts", None).await;
        assert!(matches!(result, Err(AppError::BadRequest(_))));
    }

    #[tokio::test]
    async fn test_hardware_acceleration_detection() {
        let hw_accel = detect_hardware_acceleration().await;
        assert!(matches!(
            hw_accel,
            HardwareAccel::Vaapi | HardwareAccel::V4l2 | HardwareAccel::None
        ));
    }

    fn test_cache_dir_for_file(file_path: &str) -> std::path::PathBuf {
        let _ = ensure_test_cache_env();
        let video_hash = blake3::hash(file_path.as_bytes());
        let video_id = hex::encode(&video_hash.as_bytes()[..8]);
        get_hls_cache_dir().join(video_id)
    }

    fn cleanup_test_cache(file_path: &str) {
        let cache_dir = test_cache_dir_for_file(file_path);
        let _ = std::fs::remove_dir_all(cache_dir);
    }

    fn insert_test_session(
        manager: &HlsSessionManager,
        file_path: &str,
        zkp_registration: Option<PasswordRegistration>,
    ) -> String {
        let session = HlsSession::new_with_registration(
            "test-user".to_string(),
            file_path.to_string(),
            [7u8; 32],
            1000,
            zkp_registration,
        )
        .unwrap();
        let session_id = session.session_id.clone();
        manager
            .sessions
            .lock()
            .unwrap()
            .insert(session_id.clone(), session);
        session_id
    }

    fn build_zkp_proof_base64(
        password: &str,
        registration: &PasswordRegistration,
        context: &str,
    ) -> String {
        let zkp = ZkpContext::new();
        let proof = zkp
            .generate_enhanced_proof(password, registration, context)
            .unwrap();
        BASE64.encode(serde_json::to_vec(&proof).unwrap())
    }

    #[tokio::test]
    async fn test_e2e_play_then_far_seek_recovers_with_on_demand_segment() {
        let manager = Arc::new(RwLock::new(HlsSessionManager::new()));
        let data = web::Data::new(manager.clone());

        let file_path = format!("e2e_play_seek_{}.mp4", uuid::Uuid::new_v4());
        let session_id = {
            let guard = manager.read().await;
            insert_test_session(&guard, &file_path, None)
        };

        let cache_dir = test_cache_dir_for_file(&file_path);
        std::fs::create_dir_all(&cache_dir).unwrap();
        std::fs::write(
            cache_dir.join("playlist.m3u8"),
            "#EXTM3U\n#EXT-X-VERSION:3\n#EXTINF:2.0,\nsegment_0.ts\n",
        )
        .unwrap();
        std::fs::write(cache_dir.join("segment_0.ts"), b"initial-segment").unwrap();
        std::fs::write(cache_dir.join(".lock"), b"in-progress").unwrap();

        let req = actix_web::test::TestRequest::default().to_http_request();
        let playlist_resp = get_secure_playlist(data.clone(), web::Path::from(session_id.clone()))
            .await
            .unwrap()
            .respond_to(&req);
        assert_eq!(playlist_resp.status(), StatusCode::OK);

        let play_resp = get_segment_direct(
            data.clone(),
            web::Path::from((session_id.clone(), "segment_0.ts".to_string())),
        )
        .await
        .unwrap()
        .respond_to(&req);
        assert_eq!(play_resp.status(), StatusCode::OK);

        let far_segment_name = "segment_80.ts".to_string();
        let far_segment_path = cache_dir.join(&far_segment_name);
        let expected_plain = b"far-ahead-on-demand-segment-data".to_vec();
        let expected_plain_for_writer = expected_plain.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let _ = tokio::fs::write(&far_segment_path, &expected_plain_for_writer).await;
        });

        let started = Instant::now();
        let far_resp = get_segment_direct(
            data.clone(),
            web::Path::from((session_id.clone(), far_segment_name)),
        )
        .await
        .unwrap()
        .respond_to(&req);
        let elapsed = started.elapsed();

        assert_eq!(far_resp.status(), StatusCode::OK);
        assert!(elapsed < Duration::from_secs(8));

        let encrypted_body = to_bytes(far_resp.into_body())
            .await
            .map_err(|_| "failed to read encrypted far-seek body")
            .unwrap();
        let plain = {
            let guard = manager.read().await;
            let session = guard.get_session(&session_id).unwrap();
            session.decrypt_segment(&encrypted_body).unwrap()
        };
        assert_eq!(plain, expected_plain);

        cleanup_test_cache(&file_path);
    }

    #[tokio::test]
    async fn test_e2e_on_demand_segment_returns_within_timeout_window() {
        let manager = Arc::new(RwLock::new(HlsSessionManager::new()));
        let data = web::Data::new(manager.clone());

        let file_path = format!("e2e_timeout_window_{}.mp4", uuid::Uuid::new_v4());
        let session_id = {
            let guard = manager.read().await;
            insert_test_session(&guard, &file_path, None)
        };

        let cache_dir = test_cache_dir_for_file(&file_path);
        std::fs::create_dir_all(&cache_dir).unwrap();
        std::fs::write(
            cache_dir.join("playlist.m3u8"),
            "#EXTM3U\n#EXT-X-VERSION:3\n#EXTINF:2.0,\nsegment_0.ts\n",
        )
        .unwrap();
        std::fs::write(cache_dir.join("segment_0.ts"), b"initial-segment").unwrap();
        std::fs::write(cache_dir.join(".lock"), b"in-progress").unwrap();

        let far_segment_name = "segment_120.ts".to_string();
        let far_segment_path = cache_dir.join(&far_segment_name);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let _ = tokio::fs::write(&far_segment_path, b"timeout-window-segment").await;
        });

        let req = actix_web::test::TestRequest::default().to_http_request();
        let started = Instant::now();
        let resp = get_segment_direct(
            data.clone(),
            web::Path::from((session_id, far_segment_name)),
        )
        .await
        .unwrap()
        .respond_to(&req);
        let elapsed = started.elapsed();

        assert_eq!(resp.status(), StatusCode::OK);
        // far-ahead seek branch has a 45s wait window; this regression should return quickly.
        assert!(elapsed < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn test_e2e_zkp_failure_returns_clear_error_and_recovery_with_new_session() {
        let manager = Arc::new(RwLock::new(HlsSessionManager::new()));
        let data = web::Data::new(manager.clone());

        let file_path = format!("e2e_zkp_recover_{}.mp4", uuid::Uuid::new_v4());
        let password = "RecoverPassword!123".to_string();
        let zkp = ZkpContext::new();
        let registration = zkp.register_password(&password).unwrap();

        let session_id_bad = {
            let guard = manager.read().await;
            insert_test_session(&guard, &file_path, Some(registration.clone()))
        };

        let cache_dir = test_cache_dir_for_file(&file_path);
        std::fs::create_dir_all(&cache_dir).unwrap();
        let segment_plain = b"secure-segment-for-zkp-recovery";
        std::fs::write(cache_dir.join("segment_0.ts"), segment_plain).unwrap();

        let bad_context_proof = build_zkp_proof_base64(&password, &registration, "wrong_context");
        let bad_body = serde_json::json!({ "zkp_proof": bad_context_proof });
        let bad_req = actix_web::test::TestRequest::post().to_http_request();

        let bad_result = get_secure_segment(
            data.clone(),
            web::Path::from((session_id_bad, "segment_0.ts".to_string())),
            bad_req,
            web::Bytes::from(serde_json::to_vec(&bad_body).unwrap()),
        )
        .await;

        assert!(matches!(bad_result, Err(AppError::Unauthorized(msg)) if msg.contains("Invalid ZKP proof")));

        // Rebuild a new playback session and retry with a valid proof.
        let session_id_good = {
            let guard = manager.read().await;
            insert_test_session(&guard, &file_path, Some(registration.clone()))
        };
        let good_proof = build_zkp_proof_base64(&password, &registration, "hls_segment_access");
        let good_body = serde_json::json!({ "zkp_proof": good_proof });
        let good_req = actix_web::test::TestRequest::post().to_http_request();

        let good_resp = get_secure_segment(
            data.clone(),
            web::Path::from((session_id_good.clone(), "segment_0.ts".to_string())),
            good_req,
            web::Bytes::from(serde_json::to_vec(&good_body).unwrap()),
        )
        .await
        .unwrap()
        .respond_to(&actix_web::test::TestRequest::default().to_http_request());

        assert_eq!(good_resp.status(), StatusCode::OK);
        assert_eq!(
            good_resp
                .headers()
                .get("X-ZKP-Verified")
                .and_then(|v| v.to_str().ok()),
            Some("true")
        );

        let encrypted = to_bytes(good_resp.into_body())
            .await
            .map_err(|_| "failed to read encrypted zkp recovery body")
            .unwrap();
        let decrypted = {
            let guard = manager.read().await;
            let session = guard.get_session(&session_id_good).unwrap();
            session.decrypt_segment(&encrypted).unwrap()
        };
        assert_eq!(decrypted, segment_plain);

        cleanup_test_cache(&file_path);
    }
}
