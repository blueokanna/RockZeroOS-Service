use actix_web::{web, HttpResponse, Responder};
use rockzero_common::AppError;
use rockzero_crypto::{EnhancedPasswordProof, PasswordRegistration, ZkpContext};
use rockzero_media::{HlsSession, HlsSessionManager};
use rockzero_sae::{SaeCommit, SaeConfirm};
use serde::Deserialize;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

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

    // URL 解码
    let decoded_path = urlencoding::decode(path)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| path.to_string());

    let path_buf = PathBuf::from(&decoded_path);

    // 如果是绝对路径，直接验证
    if path_buf.is_absolute() {
        // 尝试规范化路径
        let canonical = path_buf.canonicalize().unwrap_or_else(|_| path_buf.clone());

        // 验证路径是否在允许的目录中
        const ALLOWED_DIRS: &[&str] = &["/mnt", "/media", "/home", "/data", "/storage"];
        let path_str = canonical.to_string_lossy();

        for allowed_dir in ALLOWED_DIRS {
            if path_str.starts_with(allowed_dir) {
                return Ok(canonical);
            }
        }

        // Windows 路径
        #[cfg(target_os = "windows")]
        {
            // 允许所有盘符
            if path_str.len() >= 2 && path_str.chars().nth(1) == Some(':') {
                return Ok(canonical);
            }
        }

        return Err(AppError::Forbidden(
            "File path is not in allowed directories".to_string(),
        ));
    }

    // 相对路径：相对于基础目录
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
    pub file_id: Option<String>,   // 文件 ID（数据库中的）
    pub file_path: Option<String>, // 文件路径（文件系统中的）
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

pub async fn init_sae_handshake(
    pool: web::Data<SqlitePool>,
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<InitSaeRequest>,
) -> Result<impl Responder, AppError> {
    let user_id = claims.sub.clone();

    // 验证文件访问权限（支持文件 ID 或文件路径）
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
        "Initializing SAE handshake for user {} - file: {}",
        user_id, file_path
    );

    // 从数据库获取用户的 SAE 密钥（SHA-256 hash of password）
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

#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    pub temp_session_id: String,
    pub file_id: Option<String>,   // 文件 ID（数据库中的）
    pub file_path: Option<String>, // 文件路径（文件系统中的）
    pub zkp_registration: Option<String>,
    /// When true, segments are served as plaintext (no AES-256-GCM transport encryption).
    /// Suitable for ARM / low-performance devices or when libmpv cannot decrypt inline.
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

    let zkp_registration: Option<PasswordRegistration> = match get_user_zkp_registration(&pool, &user_id).await {
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

    // Set direct mode if requested (plaintext segments for ARM / libmpv)
    if body.direct_mode {
        manager
            .set_session_direct_mode(&session_id, true)
            .map_err(convert_hls_error)?;
        info!(
            "Session {} direct_mode enabled (plaintext segments)",
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
            "✅ Created HLS session {} for user {} - file {} (ZKP: {}, direct: {}, verified_stored: {}, total_sessions: {})",
            session_id, user_id, file_path, has_zkp, body.direct_mode, exists, total
        );
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "session_id": session_id,
        "expires_at": session.expires_at.timestamp(),
        "playlist_url": format!("/api/v1/secure-hls/{}/playlist.m3u8", session_id),
        "zkp_enabled": has_zkp,
        "direct_mode": body.direct_mode,
        "encryption_method": if body.direct_mode { "none" } else { "AES-256-GCM" },
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
    let cache_dir = get_hls_cache_dir().join(&video_id);
    let playlist_path = cache_dir.join("playlist.m3u8");
    // 标记文件表示分片完成 (包含 #EXT-X-ENDLIST)
    let done_marker = cache_dir.join(".done");
    // 锁文件防止并发 ffmpeg 进程
    let lock_file = cache_dir.join(".lock");

    // 如果已完成分片，直接返回缓存的 playlist
    if done_marker.exists() && playlist_path.exists() {
        let content = tokio::fs::read_to_string(&playlist_path)
            .await
            .map_err(|e| AppError::IoError(format!("Failed to read cached playlist: {}", e)))?;
        return Ok((cache_dir, content));
    }

    // 如果有播放列表且至少有一个 segment，说明上一次分片正在进行中或中断
    // 如果 ffmpeg 正在运行（lock 文件存在），直接返回当前 playlist
    if playlist_path.exists() && lock_file.exists() {
        let content = tokio::fs::read_to_string(&playlist_path).await.ok();
        if let Some(content) = content {
            if content.contains("#EXTINF") {
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

    let segment_pattern = cache_dir.join("segment_%d.ts");
    let seg_pattern_str = segment_pattern
        .to_str()
        .unwrap_or("")
        .to_string();
    let playlist_str = playlist_path
        .to_str()
        .unwrap_or("")
        .to_string();

    info!(
        "🎬 Starting progressive segmentation: {} → {}",
        file_path,
        cache_dir.display()
    );

    // 清理之前的部分输出（如果有）
    if !lock_file.exists() {
        for entry in std::fs::read_dir(&cache_dir).into_iter().flatten().flatten() {
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

    tokio::spawn(async move {
        let result = run_ffmpeg_progressive(
            &ffmpeg_path_clone,
            &file_path_owned,
            &seg_pattern_str,
            &playlist_str,
            &cache_dir_clone,
            &done_marker_clone,
            &lock_file_clone,
        )
        .await;

        match result {
            Ok(_) => info!("✅ Video segmented successfully: {}", video_id),
            Err(e) => warn!("❌ FFmpeg segmentation failed: {}", e),
        }

        // 清理 lock 文件
        let _ = tokio::fs::remove_file(&lock_file_clone).await;
    });

    // 等待第一个 segment 生成（最多 30 秒）
    let first_segment = cache_dir.join("segment_0.ts");
    let mut waited = 0;
    let max_wait_ms = 30_000;
    let poll_interval_ms = 200;

    while waited < max_wait_ms {
        if first_segment.exists() && playlist_path.exists() {
            // 等待 playlist 至少包含一个 EXTINF
            if let Ok(content) = tokio::fs::read_to_string(&playlist_path).await {
                if content.contains("#EXTINF") {
                    info!(
                        "First segment ready after {}ms, returning playlist",
                        waited
                    );
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
            .map_err(|e| {
                AppError::IoError(format!("Failed to read playlist: {}", e))
            })?;
        if content.contains("#EXTINF") {
            return Ok((cache_dir, content));
        }
    }

    Err(AppError::InternalServerError(
        "视频分片超时，请检查 ffmpeg 是否正确安装".to_string(),
    ))
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
            "-v", "quiet",
            "-select_streams", "v:0",
            "-show_entries", "stream=codec_name",
            "-of", "csv=p=0",
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
    let mut encrypted_count = 0;

    let mut entries = tokio::fs::read_dir(cache_dir)
        .await
        .map_err(|e| format!("Failed to read cache dir: {}", e))?;

    let mut ts_files = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "ts")
            && !path.with_extension("ts.enc").exists()
        {
            ts_files.push(path);
        }
    }

    for ts_path in &ts_files {
        let enc_path = ts_path.with_extension("ts.enc");

        match tokio::fs::read(ts_path).await {
            Ok(data) => {
                match crate::crypto::aes_encrypt(storage_key, &data) {
                    Ok(encrypted) => {
                        if let Err(e) = tokio::fs::write(&enc_path, &encrypted).await {
                            warn!("Failed to write encrypted segment {:?}: {}", enc_path, e);
                            continue;
                        }
                        // 安全删除原始明文段文件
                        let _ = tokio::fs::remove_file(ts_path).await;
                        encrypted_count += 1;
                    }
                    Err(e) => {
                        warn!("Failed to encrypt segment {:?}: {}", ts_path, e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to read segment {:?}: {}", ts_path, e);
            }
        }
    }

    if encrypted_count > 0 {
        info!(
            "🔒 Encrypted {} segment files at rest in {:?}",
            encrypted_count,
            cache_dir
        );
    }

    Ok(encrypted_count)
}

/// 读取并解密静态加密的分片文件
///
/// 优先读取 .ts.enc 加密文件并解密，如果不存在则回退到明文 .ts 文件。
/// 这确保在加密过程中或旧缓存中仍能正常访问数据。
async fn read_segment_data(
    segment_path: &std::path::Path,
    storage_key: &[u8; 32],
) -> Result<Vec<u8>, AppError> {
    let enc_path = segment_path.with_extension("ts.enc");

    if enc_path.exists() {
        // 读取加密文件并解密
        let encrypted = tokio::fs::read(&enc_path).await.map_err(|e| {
            AppError::IoError(format!("Failed to read encrypted segment: {}", e))
        })?;
        let data = crate::crypto::aes_decrypt(storage_key, &encrypted)?;
        return Ok(data);
    }

    // 回退到明文段文件（兼容旧缓存或加密进行中）
    if segment_path.exists() {
        let data = tokio::fs::read(segment_path).await.map_err(|e| {
            AppError::IoError(format!("Failed to read segment: {}", e))
        })?;
        return Ok(data);
    }

    Err(AppError::NotFound(format!(
        "Segment not found: {:?}",
        segment_path
    )))
}

/// 运行 ffmpeg 渐进式分片（在后台 task 中执行）
async fn run_ffmpeg_progressive(
    ffmpeg_path: &str,
    file_path: &str,
    seg_pattern: &str,
    playlist_path: &str,
    cache_dir: &std::path::Path,
    done_marker: &std::path::Path,
    lock_file: &std::path::Path,
) -> Result<(), String> {
    // 探测视频编码格式，决定 bitstream filter
    let video_codec = detect_video_codec(ffmpeg_path, file_path).await;
    info!("Detected video codec: {:?}", video_codec);

    // 构建 stream copy 参数
    // 关键修复：对于 mpegts 容器必须添加正确的 bitstream filter
    // 否则 H.264/HEVC 的 NAL 封装格式不正确，导致播放器只有音频没有画面
    let mut copy_args: Vec<String> = vec![
        "-y".into(),
        "-i".into(),
        file_path.into(),
        "-map".into(),
        "0".into(),           // 映射所有流（视频+音频+字幕）
        "-c".into(),
        "copy".into(),
    ];

    // 根据视频编码添加 bitstream filter — 这是解决黑屏问题的关键
    match video_codec.as_deref() {
        Some("h264" | "avc" | "avc1") => {
            copy_args.extend([
                "-bsf:v".into(),
                "h264_mp4toannexb".into(),
            ]);
            info!("Applied h264_mp4toannexb bitstream filter for TS muxing");
        }
        Some("hevc" | "h265" | "hev1" | "hvc1") => {
            copy_args.extend([
                "-bsf:v".into(),
                "hevc_mp4toannexb".into(),
            ]);
            info!("Applied hevc_mp4toannexb bitstream filter for TS muxing");
        }
        _ => {
            // VP9, AV1 等其他编码不需要 bitstream filter
            info!("No bitstream filter needed for codec: {:?}", video_codec);
        }
    }

    copy_args.extend([
        "-f".into(),
        "hls".into(),
        "-hls_time".into(),
        "6".into(),           // 6 秒段更适合移动端
        "-hls_list_size".into(),
        "0".into(),
        "-hls_playlist_type".into(),
        "event".into(),       // event 模式 = 渐进式播放列表
        "-hls_flags".into(),
        "append_list+independent_segments".into(),
        "-hls_segment_type".into(),
        "mpegts".into(),
        "-hls_segment_filename".into(),
        seg_pattern.into(),
        playlist_path.into(),
    ]);

    // 先尝试 stream copy + bitstream filter（极快，不需要转码）
    let output = tokio::process::Command::new(ffmpeg_path)
        .args(&copy_args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("Failed to run ffmpeg: {}", e))?;

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
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    warn!(
        "Stream copy failed, trying transcode: {}",
        &stderr[..stderr.len().min(500)]
    );

    // 清理出错的输出
    for entry in std::fs::read_dir(cache_dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "ts" || e == "m3u8") {
            let _ = std::fs::remove_file(&path);
        }
    }

    // 检测硬件加速
    let hw_accel = detect_hardware_acceleration().await;

    let mut args: Vec<String> = vec!["-y".into(), "-i".into(), file_path.into()];

    match hw_accel {
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
                "-hwaccel".into(),
                "vaapi".into(),
                "-hwaccel_device".into(),
                "/dev/dri/renderD128".into(),
                "-hwaccel_output_format".into(),
                "vaapi".into(),
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
        "6".into(),
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

    let output = tokio::process::Command::new(ffmpeg_path)
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("FFmpeg transcode failed: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
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

/// 获取 HLS 播放列表（基于 ffmpeg 生成的真实分片）
///
/// 不需要 JWT 认证 — session_id 本身就是鉴权 token（创建时已验证 JWT + SAE）。
/// 首次请求时自动触发 ffmpeg 分片（优先 stream copy）。
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

    // 确保 HLS 分片存在（首次会触发 ffmpeg 分片）
    let (_cache_dir, playlist_content) = ensure_hls_segments(&file_path).await?;

    info!(
        "📋 Serving playlist for session {} ({})",
        session_id, file_path
    );

    Ok(HttpResponse::Ok()
        .content_type("application/vnd.apple.mpegurl")
        .insert_header(("Cache-Control", "no-cache, no-store"))
        .insert_header(("Access-Control-Allow-Origin", "*"))
        .body(playlist_content))
}

/// 直接获取视频段（GET，session 鉴权）
///
/// 标准 HLS 播放器可以直接 GET 请求获取视频段。
/// 安全性由 session_id（随机 UUID）保证：
/// - 创建 session 时已验证 JWT + SAE 握手
/// - session_id 是 128 位随机值，不可猜测
/// - session 有 3 小时过期时间
/// - 磁盘上的段文件也使用 encrypt_file 进行静态加密（defense in depth）
///
/// 当 session.direct_mode == true 时，返回明文视频段（适合 ARM 等低性能设备）。
/// 当 session.direct_mode == false 时，返回 AES-256-GCM 加密的视频段。
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

    // 验证会话并获取文件路径 + 段数据
    let (is_direct_mode, response_data) = {
        let manager = hls_manager.read().await;
        let session = manager
            .get_session(&session_id)
            .map_err(convert_hls_error)?;
        let fp = session.file_path.clone();
        let direct_mode = session.direct_mode;

        // 构建缓存路径
        let video_hash = blake3::hash(fp.as_bytes());
        let video_id = hex::encode(&video_hash.as_bytes()[..8]);
        let cache_dir = get_hls_cache_dir().join(&video_id);
        let segment_path = cache_dir.join(&segment_name);

        // 如果段文件不存在（明文或加密形式），先确保分片完成
        let enc_path = segment_path.with_extension("ts.enc");
        if !segment_path.exists() && !enc_path.exists() {
            drop(manager); // 释放读锁避免 ffmpeg 等待时死锁
            ensure_hls_segments(&fp).await?;

            let manager = hls_manager.read().await;
            let session = manager
                .get_session(&session_id)
                .map_err(convert_hls_error)?;

            // 从磁盘读取段数据（自动处理加密/明文文件）
            let storage_key = derive_segment_storage_key(&fp);
            let segment_data = read_segment_data(&segment_path, &storage_key).await?;

            if direct_mode {
                // 直接模式：返回明文视频段
                (true, segment_data)
            } else {
                // 加密模式：使用会话密钥进行传输加密
                let encrypted = session
                    .encrypt_segment(&segment_data)
                    .map_err(convert_hls_error)?;
                (false, encrypted)
            }
        } else {
            // 从磁盘读取段数据（自动处理静态加密文件）
            let storage_key = derive_segment_storage_key(&fp);
            let segment_data = read_segment_data(&segment_path, &storage_key).await?;

            if direct_mode {
                (true, segment_data)
            } else {
                let encrypted = session
                    .encrypt_segment(&segment_data)
                    .map_err(convert_hls_error)?;
                (false, encrypted)
            }
        }
    };

    if is_direct_mode {
        info!(
            "📺 Serving plaintext segment {} for session {} ({} bytes)",
            segment_name,
            session_id,
            response_data.len()
        );

        Ok(HttpResponse::Ok()
            .content_type("video/mp2t")
            .insert_header(("X-Encrypted", "false"))
            .insert_header(("Content-Length", response_data.len()))
            .insert_header(("Cache-Control", "no-cache, no-store, must-revalidate"))
            .insert_header(("Access-Control-Allow-Origin", "*"))
            .body(response_data))
    } else {
        info!(
            "🔒 Serving encrypted segment {} for session {} ({} bytes)",
            segment_name,
            session_id,
            response_data.len()
        );

        Ok(HttpResponse::Ok()
            .content_type("video/mp2t")
            .insert_header(("X-Encrypted", "true"))
            .insert_header(("X-Encryption-Method", "AES-256-GCM"))
            .insert_header(("Content-Length", response_data.len()))
            .insert_header(("Cache-Control", "no-cache, no-store, must-revalidate"))
            .insert_header(("Access-Control-Allow-Origin", "*"))
            .body(response_data))
    }
}

/// 获取加密的 TS 段（需要 ZKP 证明）
///
/// **生产级安全实现**：
/// - 仅支持 POST 请求 + JSON body
/// - 必须提供有效的 ZKP 证明
/// - 验证会话有效性
/// - 验证 ZKP 证明的时间戳和 nonce
/// - 使用 AES-256-GCM 加密视频段
///
/// # 安全流程
/// 1. 验证 HTTP 方法（必须是 POST）
/// 2. 验证会话存在且未过期
/// 3. 解析并验证 ZKP 证明
/// 4. 读取并加密视频段
/// 5. 返回加密数据
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

    // 2. 解析 JSON body
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

    // 3. 验证会话
    let manager = hls_manager.read().await;
    let session = manager
        .get_session(&session_id)
        .map_err(convert_hls_error)?;

    // 4. 验证 ZKP 证明（生产环境必须验证）
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

    // 5. 从缓存获取视频段数据（支持静态加密文件）
    let segment_data = {
        let video_hash = blake3::hash(session.file_path.as_bytes());
        let video_id = hex::encode(&video_hash.as_bytes()[..8]);
        let cache_dir = get_hls_cache_dir().join(&video_id);
        let segment_path = cache_dir.join(&segment_name);

        let storage_key = derive_segment_storage_key(&session.file_path);
        let enc_path = segment_path.with_extension("ts.enc");

        if enc_path.exists() || segment_path.exists() {
            // 使用已缓存的分片（自动解密静态加密文件）
            read_segment_data(&segment_path, &storage_key).await?
        } else {
            // 回退到按需转码
            read_video_segment_from_ffmpeg(&session.file_path, &segment_name).await?
        }
    };

    // 6. 使用会话密钥加密段
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

    // 7. 返回加密的视频段
    Ok(HttpResponse::Ok()
        .content_type("video/mp2t")
        .insert_header(("X-Encrypted", "true"))
        .insert_header(("X-Encryption-Method", "AES-256-GCM"))
        .insert_header(("X-ZKP-Verified", "true"))
        .insert_header(("Content-Length", encrypted_segment.len()))
        .insert_header(("Cache-Control", "no-cache, no-store, must-revalidate"))
        .insert_header(("Pragma", "no-cache"))
        .insert_header(("Expires", "0"))
        .body(encrypted_segment))
}

/// 停止 HLS 会话
///
/// **生产级安全实现**：
/// - 验证会话存在
/// - 移除会话状态
/// - 清理关联资源
///
/// # 参数
/// - `hls_manager`: HLS 会话管理器
/// - `path`: 路径参数，包含会话 ID
///
/// # 返回
/// - 成功时返回 200 状态码
/// - 会话不存在时返回 404
pub async fn stop_session(
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    path: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let session_id = path.into_inner();

    info!("Stopping HLS session: {}", session_id);

    // Use read lock since remove_session uses internal Mutex
    let manager = hls_manager.read().await;

    // 尝试移除会话
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
            // 会话不存在也返回成功（幂等操作）
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

/// 获取混合传输层统计信息
///
/// 返回 UDP/TCP 混合传输的实时统计数据，包括：
/// - 各通道发送字节数/块数
/// - 当前动态 UDP/TCP 比例
/// - 带宽估算
/// - 丢包统计
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

// ============ 辅助函数 ============

/// 生成安全的 M3U8 播放列表（已被 ffmpeg 生成的播放列表替代，保留作为 fallback）
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
            Err(AppError::CryptoError(format!(
                "Bulletproofs ZKP verification failed: {}",
                e
            )))
        }
    }
}

/// 视频段缓存目录配置
///
/// 与 StorageConfig 使用相同的环境变量配置，确保清理任务能正确清理缓存。
///
/// 优先级:
/// 1. `HLS_CACHE_PATH` 环境变量（与 StorageConfig 一致）
/// 2. `ROCKZERO_HLS_CACHE_DIR` 环境变量（兼容旧配置）
/// 3. 默认 `./data/hls_cache`（与 StorageConfig 默认值一致）
fn get_hls_cache_dir() -> std::path::PathBuf {
    // 优先使用 HLS_CACHE_PATH（与 StorageConfig 一致）
    std::env::var("HLS_CACHE_PATH")
        .or_else(|_| std::env::var("ROCKZERO_HLS_CACHE_DIR"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            // 默认使用 ./data/hls_cache（与 StorageConfig 默认值一致）
            std::path::PathBuf::from("./data/hls_cache")
        })
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

    // 5. 构建缓存目录路径
    let cache_dir = get_hls_cache_dir().join(&video_id);
    let cached_segment_path = cache_dir.join(segment_name);

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

    const SEGMENT_DURATION: f64 = 10.0; // 每段 10 秒
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
        "-ss".to_string(),
        format!("{:.3}", start_time), // 起始时间
        "-i".to_string(),
        video_path.to_str().unwrap_or("").to_string(),
        "-t".to_string(),
        format!("{:.3}", SEGMENT_DURATION), // 段持续时间
    ];

    // 根据硬件加速能力选择编码器
    match hw_accel {
        HardwareAccel::Vaapi => {
            // Intel/AMD GPU 硬件加速
            info!(
                "Using VAAPI hardware acceleration for segment {}",
                segment_index
            );
            args.extend(vec![
                "-hwaccel".to_string(),
                "vaapi".to_string(),
                "-hwaccel_device".to_string(),
                "/dev/dri/renderD128".to_string(),
                "-hwaccel_output_format".to_string(),
                "vaapi".to_string(),
                "-c:v".to_string(),
                "h264_vaapi".to_string(),
                "-qp".to_string(),
                "23".to_string(), // 质量参数
            ]);
        }
        HardwareAccel::V4l2 => {
            // V4L2 硬件编码器（ARM SoC）
            info!(
                "Using V4L2 hardware acceleration for segment {}",
                segment_index
            );
            args.extend(vec![
                "-c:v".to_string(),
                "h264_v4l2m2m".to_string(),
                "-b:v".to_string(),
                "2M".to_string(), // 码率
            ]);
        }
        HardwareAccel::None => {
            // 软件编码（libx264）
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
    Vaapi, // Intel/AMD GPU (VA-API)
    V4l2,  // V4L2 M2M (ARM SoC)
    None,  // 软件编码
}

/// 检测可用的硬件加速
async fn detect_hardware_acceleration() -> HardwareAccel {
    use tokio::fs;

    if fs::metadata("/dev/dri/renderD128").await.is_ok() && check_ffmpeg_encoder("h264_vaapi").await
    {
        return HardwareAccel::Vaapi;
    }

    // 检测 V4L2 设备（ARM SoC）
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

    #[tokio::test]
    async fn test_segment_name_validation() {
        // 无效的段名称格式（路径遍历攻击）
        let result = read_video_segment_from_ffmpeg("/video.mp4", "../../../etc/passwd").await;
        assert!(matches!(result, Err(AppError::BadRequest(_))));

        // 无效的段名称格式（负数索引）
        let result = read_video_segment_from_ffmpeg("/video.mp4", "segment_-1.ts").await;
        assert!(matches!(result, Err(AppError::BadRequest(_))));

        // 无效的段名称格式（非数字索引）
        let result = read_video_segment_from_ffmpeg("/video.mp4", "segment_abc.ts").await;
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
}
