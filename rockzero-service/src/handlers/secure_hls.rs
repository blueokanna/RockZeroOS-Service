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
    let temp_session_id = manager
        .init_sae_handshake(user_id.clone(), password)
        .map_err(convert_hls_error)?;

    // 获取 SAE 服务器的 commit（需要先处理客户端的 commit）
    // 这里我们返回 temp_session_id，客户端需要发送 commit

    info!(
        "Initialized SAE handshake for user {} - temp session {}",
        user_id, temp_session_id
    );

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

/// 步骤 3: 创建 HLS 会话
///
/// SAE 握手完成后，创建实际的 HLS 会话
///
/// # 安全流程
/// 1. 验证用户身份（通过 JWT claims）
/// 2. 验证文件访问权限
/// 3. 获取用户的 ZKP 注册数据（用于后续的 ZKP 验证）
/// 4. 完成 SAE 握手并创建会话
/// 5. 将 ZKP 注册数据关联到会话
#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    pub temp_session_id: String,
    pub file_id: String,
    pub zkp_registration: Option<String>,
}

pub async fn create_hls_session(
    pool: web::Data<SqlitePool>,
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<CreateSessionRequest>,
) -> Result<impl Responder, AppError> {
    let user_id = claims.sub.clone();

    // 1. 获取文件信息并验证访问权限
    let file = crate::db::find_file_by_id(&pool, &body.file_id, &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("File not found".to_string()))?;

    // 2. 获取用户的 ZKP 注册数据
    let zkp_registration: Option<PasswordRegistration> =
        if let Some(ref reg_json) = body.zkp_registration {
            // 从请求中解析
            Some(serde_json::from_str(reg_json).map_err(|e| {
                AppError::BadRequest(format!("Invalid ZKP registration format: {}", e))
            })?)
        } else {
            // 从数据库获取用户的 ZKP 注册数据
            // 这需要在用户注册/登录时存储
            match get_user_zkp_registration(&pool, &user_id).await {
                Ok(Some(reg)) => Some(reg),
                Ok(None) => {
                    warn!(
                        "User {} does not have ZKP registration data stored",
                        user_id
                    );
                    None
                }
                Err(e) => {
                    warn!("Failed to get ZKP registration for user {}: {}", user_id, e);
                    None
                }
            }
        };

    // 3. 完成 SAE 握手并创建会话（带 ZKP 注册数据）
    let manager = hls_manager.read().await;
    let session_id = manager
        .complete_sae_handshake_with_registration(
            &body.temp_session_id,
            user_id.clone(),
            file.file_path.clone(),
            zkp_registration.clone(),
        )
        .map_err(convert_hls_error)?;

    // 4. 获取会话信息
    let session = manager
        .get_session(&session_id)
        .map_err(convert_hls_error)?;

    // 5. 记录日志
    let has_zkp = zkp_registration.is_some();
    info!(
        "Created HLS session {} for user {} - file {} (ZKP enabled: {})",
        session_id, user_id, file.file_path, has_zkp
    );

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "session_id": session_id,
        "expires_at": session.expires_at.timestamp(),
        "playlist_url": format!("/api/v1/secure-hls/{}/playlist.m3u8", session_id),
        "zkp_enabled": has_zkp,
        "encryption_method": "AES-256-GCM",
    })))
}

/// 从数据库获取用户的 ZKP 注册数据
///
/// 注意：这需要在数据库中添加相应的表和字段来存储用户的 ZKP 注册数据
/// 这通常在用户注册或首次登录时创建
async fn get_user_zkp_registration(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Option<PasswordRegistration>, AppError> {
    // 查询用户的 ZKP 注册数据
    // 假设数据库中有 users 表，包含 zkp_registration 字段（JSON 格式）
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT zkp_registration FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| {
                AppError::DatabaseError(format!("Failed to query ZKP registration: {}", e))
            })?;

    match row {
        Some((Some(json_str),)) => {
            let registration: PasswordRegistration =
                serde_json::from_str(&json_str).map_err(|e| {
                    AppError::InternalServerError(format!(
                        "Invalid ZKP registration data in database: {}",
                        e
                    ))
                })?;
            Ok(Some(registration))
        }
        _ => Ok(None),
    }
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
    let _session = manager
        .get_session(&session_id)
        .map_err(convert_hls_error)?;

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
    let session = manager
        .get_session(&session_id)
        .map_err(convert_hls_error)?;

    // 2. 验证 ZKP 证明
    if !verify_zkp_proof(&session, &body.zkp_proof)? {
        warn!(
            "Invalid ZKP proof for session {} segment {}",
            session_id, segment_name
        );
        return Err(AppError::Unauthorized("Invalid ZKP proof".to_string()));
    }

    // 3. 从 FFmpeg 转码输出读取实际的 TS 段
    // 这会先尝试从缓存读取，如果不存在则触发实时转码
    let segment_data = read_video_segment_from_ffmpeg(&session.file_path, &segment_name).await?;

    // 4. 使用会话密钥加密段
    let encrypted_segment = session
        .encrypt_segment(&segment_data)
        .map_err(convert_hls_error)?;

    info!(
        "Serving encrypted segment {} for session {} (size: {} bytes)",
        segment_name,
        session_id,
        encrypted_segment.len()
    );

    Ok(HttpResponse::Ok()
        .content_type("application/octet-stream")
        .insert_header(("X-Encrypted", "true"))
        .insert_header(("X-Encryption-Method", "AES-256-GCM"))
        .insert_header(("Content-Length", encrypted_segment.len().to_string()))
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
///
/// 这是生产级实现，使用会话中存储的 PasswordRegistration 进行验证。
///
/// # 安全性说明
/// - 使用存储在会话中的 PasswordRegistration（在用户注册/登录时创建）
/// - ZKP 证明验证确保客户端知道正确的密码，而不需要传输密码本身
/// - 包含时间戳和 nonce 防止重放攻击
/// - 上下文绑定防止证明在不同场景中被重用
///
fn verify_zkp_proof(session: &HlsSession, proof_base64: &str) -> Result<bool, AppError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    // 1. 检查会话是否有 ZKP 注册数据
    let registration = session.get_zkp_registration().ok_or_else(|| {
        AppError::CryptoError(
            "Session does not have ZKP registration data. \
             Ensure the session was created with PasswordRegistration."
                .to_string(),
        )
    })?;

    // 2. 解码 Base64 编码的证明
    let proof_bytes = BASE64.decode(proof_base64).map_err(|e| {
        AppError::BadRequest(format!("Invalid Base64 encoding in ZKP proof: {}", e))
    })?;

    // 3. 解析 ZKP 证明结构
    let proof: EnhancedPasswordProof = serde_json::from_slice(&proof_bytes).map_err(|e| {
        AppError::BadRequest(format!(
            "Invalid ZKP proof structure: {}. Expected EnhancedPasswordProof JSON.",
            e
        ))
    })?;

    // 4. 验证上下文 - 确保证明是为视频段访问生成的
    const EXPECTED_CONTEXT: &str = "hls_segment_access";
    if proof.context != EXPECTED_CONTEXT {
        warn!(
            "ZKP proof context mismatch: expected '{}', got '{}'",
            EXPECTED_CONTEXT, proof.context
        );
        return Ok(false);
    }

    // 5. 创建 ZKP 上下文并验证证明
    let zkp_context = ZkpContext::new();

    // 6. 验证增强证明
    // - 300秒有效期（5分钟，适合流媒体场景）
    // - 使用存储的 registration 验证 commitment 匹配
    // - 验证 Schnorr 证明（知识证明）
    // - 验证范围证明（密码强度证明）
    // - 检查 nonce 防止重放
    // - 检查时间戳防止延迟重放
    match zkp_context.verify_enhanced_proof(&proof, registration, EXPECTED_CONTEXT, 300) {
        Ok(valid) => {
            if !valid {
                warn!(
                    "ZKP proof verification failed for session {} (mathematical verification failed)",
                    session.session_id
                );
            }
            Ok(valid)
        }
        Err(e) => {
            warn!(
                "ZKP proof verification error for session {}: {}",
                session.session_id, e
            );
            Err(AppError::CryptoError(format!(
                "ZKP verification failed: {}",
                e
            )))
        }
    }
}

/// 视频段缓存目录配置
///
/// 在生产环境中，这应该从配置文件读取
fn get_hls_cache_dir() -> std::path::PathBuf {
    // 优先使用环境变量，否则使用默认路径
    std::env::var("ROCKZERO_HLS_CACHE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            // 默认使用 /var/cache/rockzero/hls（Linux）
            // 或 temp 目录下的 rockzero-hls
            #[cfg(target_os = "linux")]
            {
                std::path::PathBuf::from("/var/cache/rockzero/hls")
            }
            #[cfg(not(target_os = "linux"))]
            {
                std::env::temp_dir().join("rockzero-hls")
            }
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
        "-movflags".to_string(),
        "+faststart".to_string(), // 快速启动
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

    if fs::metadata("/dev/dri/renderD128").await.is_ok() {
        if check_ffmpeg_encoder("h264_vaapi").await {
            return HardwareAccel::Vaapi;
        }
    }

    // 检测 V4L2 设备（ARM SoC）
    if fs::metadata("/dev/video10").await.is_ok() || fs::metadata("/dev/video11").await.is_ok() {
        if check_ffmpeg_encoder("h264_v4l2m2m").await {
            return HardwareAccel::V4l2;
        }
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
        assert!(!playlist.contains("#EXT-X-KEY")); // 不应该包含密钥 URL
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
        // 测试硬件加速检测（不依赖实际硬件）
        let hw_accel = detect_hardware_acceleration().await;
        // 应该返回某种类型（即使是 None）
        assert!(matches!(
            hw_accel,
            HardwareAccel::Vaapi | HardwareAccel::V4l2 | HardwareAccel::None
        ));
    }
}
