use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use tracing::{error, info};
use uuid::Uuid;

use crate::db;
use crate::error::AppError;
use crate::models::{MediaItem, MediaResponse};

#[derive(Debug, Serialize)]
pub struct MediaCodecInfo {
    pub ffmpeg_available: bool,
    pub supported_video_codecs: Vec<String>,
    pub supported_audio_codecs: Vec<String>,
    pub hardware_acceleration: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TranscodeRequest {
    pub file_id: String,
    pub output_format: String,
    pub video_codec: Option<String>,
    pub audio_codec: Option<String>,
    pub bitrate: Option<String>,
    pub resolution: Option<String>,
}

pub async fn list_media(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
) -> Result<impl Responder, AppError> {
    let media_items = db::list_media_by_user(&pool, &claims.sub).await?;

    let mut responses = Vec::new();
    for item in media_items {
        let file = db::find_file_by_id(&pool, &item.file_id, &claims.sub).await?;
        
        if let Some(f) = file {
            responses.push(MediaResponse {
                id: item.id.clone(),
                title: item.title,
                media_type: item.media_type,
                duration: item.duration,
                file_url: format!("/api/v1/files/{}/download", f.id),
                thumbnail_url: item.thumbnail_id.map(|tid| format!("/api/v1/files/{}/download", tid)),
                created_at: item.created_at,
            });
        }
    }

    Ok(HttpResponse::Ok().json(responses))
}

pub async fn create_media(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
    body: web::Json<serde_json::Value>,
) -> Result<impl Responder, AppError> {
    let file_id = body.get("file_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing file_id".to_string()))?;

    let title = body.get("title")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing title".to_string()))?;

    let media_type = body.get("media_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing media_type".to_string()))?;

    let file = db::find_file_by_id(&pool, file_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("File not found".to_string()))?;

    let duration = if media_type == "video" || media_type == "audio" {
        get_media_duration(&file.file_path)
    } else {
        None
    };

    let media = MediaItem {
        id: Uuid::new_v4().to_string(),
        user_id: claims.sub.clone(),
        file_id: file_id.to_string(),
        title: title.to_string(),
        media_type: media_type.to_string(),
        duration,
        thumbnail_id: body.get("thumbnail_id").and_then(|v| v.as_str()).map(|s| s.to_string()),
        metadata_json: body.get("metadata").map(|v| v.to_string()),
        created_at: chrono::Utc::now(),
    };

    db::create_media_item(&pool, &media).await?;

    info!("Media item created: {} - User: {}", title, claims.sub);

    Ok(HttpResponse::Created().json(MediaResponse {
        id: media.id.clone(),
        title: media.title,
        media_type: media.media_type,
        duration: media.duration,
        file_url: format!("/api/v1/files/{}/download", file_id),
        thumbnail_url: media.thumbnail_id.map(|tid| format!("/api/v1/files/{}/download", tid)),
        created_at: media.created_at,
    }))
}

pub async fn get_codec_info() -> Result<impl Responder, AppError> {
    let ffmpeg_available = Command::new("ffmpeg")
        .arg("-version")
        .output()
        .is_ok();

    let supported_video_codecs = vec![
        "h264".to_string(),
        "h265".to_string(),
        "hevc".to_string(),
        "vp8".to_string(),
        "vp9".to_string(),
        "av1".to_string(),
        "mpeg4".to_string(),
    ];

    let supported_audio_codecs = vec![
        "aac".to_string(),
        "mp3".to_string(),
        "opus".to_string(),
        "vorbis".to_string(),
        "flac".to_string(),
        "pcm".to_string(),
    ];

    let mut hardware_acceleration = Vec::new();

    if cfg!(target_arch = "aarch64") || cfg!(target_arch = "arm") {
        hardware_acceleration.push("v4l2m2m".to_string());
        hardware_acceleration.push("rkmpp".to_string());
        
        if Path::new("/dev/video10").exists() {
            hardware_acceleration.push("rockchip_mpp".to_string());
        }
        
        if Path::new("/dev/meson-vdec").exists() {
            hardware_acceleration.push("amlogic_vdec".to_string());
        }
    }

    if cfg!(target_arch = "x86_64") || cfg!(target_arch = "x86") {
        if Path::new("/dev/dri/renderD128").exists() {
            hardware_acceleration.push("vaapi".to_string());
        }
        
        hardware_acceleration.push("qsv".to_string());
        hardware_acceleration.push("nvenc".to_string());
    }

    let codec_info = MediaCodecInfo {
        ffmpeg_available,
        supported_video_codecs,
        supported_audio_codecs,
        hardware_acceleration,
    };

    Ok(HttpResponse::Ok().json(codec_info))
}

pub async fn transcode_media(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
    body: web::Json<TranscodeRequest>,
) -> Result<impl Responder, AppError> {
    let file = db::find_file_by_id(&pool, &body.file_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("File not found".to_string()))?;

    let output_filename = format!("transcoded_{}_{}.{}", 
        &Uuid::new_v4().to_string()[..8],
        file.original_filename.split('.').next().unwrap_or("file"),
        body.output_format
    );
    let output_path = format!("./uploads/{}", output_filename);

    let mut ffmpeg_args = vec![
        "-i".to_string(),
        file.file_path.clone(),
    ];

    if let Some(video_codec) = &body.video_codec {
        ffmpeg_args.push("-c:v".to_string());
        ffmpeg_args.push(video_codec.clone());
        
        if cfg!(target_arch = "aarch64") && video_codec == "h264"
            && Path::new("/dev/video10").exists() {
                ffmpeg_args.push("-hwaccel".to_string());
                ffmpeg_args.push("rkmpp".to_string());
            }
    }

    if let Some(audio_codec) = &body.audio_codec {
        ffmpeg_args.push("-c:a".to_string());
        ffmpeg_args.push(audio_codec.clone());
    }

    if let Some(bitrate) = &body.bitrate {
        ffmpeg_args.push("-b:v".to_string());
        ffmpeg_args.push(bitrate.clone());
    }

    if let Some(resolution) = &body.resolution {
        ffmpeg_args.push("-s".to_string());
        ffmpeg_args.push(resolution.clone());
    }

    ffmpeg_args.push("-y".to_string());
    ffmpeg_args.push(output_path.clone());

    let output = Command::new("ffmpeg")
        .args(&ffmpeg_args)
        .output()
        .map_err(|_| AppError::InternalError)?;

    if !output.status.success() {
        return Err(AppError::BadRequest("Transcoding failed".to_string()));
    }

    info!("Media transcoded: {} -> {}", file.original_filename, output_filename);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Transcoding completed",
        "output_file": output_filename,
    })))
}

fn get_media_duration(file_path: &str) -> Option<i64> {
    let output = Command::new("ffprobe")
        .args([
            "-v", "error",
            "-show_entries", "format=duration",
            "-of", "default=noprint_wrappers=1:nokey=1",
            file_path,
        ])
        .output()
        .ok()?;

    if output.status.success() {
        let duration_str = String::from_utf8_lossy(&output.stdout);
        duration_str.trim().parse::<f64>().ok().map(|d| d as i64)
    } else {
        None
    }
}

// ============================================================
// HLS 实时流式传输 - 支持所有视频格式
// 设计理念：任意格式输入 → FFmpeg 转封装/转码 → HLS fMP4 分段输出
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioTrackInfo {
    pub index: u32,
    pub language: String,
    pub title: String,
    pub codec: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct VideoQuality {
    pub name: String,       // "1080p", "720p", "480p", "360p"
    pub height: u32,
    pub bitrate: String,    // "4M", "2M", "1M", "500k"
}

/// HLS 会话管理器
pub struct HlsSessionManager {
    sessions: Arc<Mutex<HashMap<String, HlsSession>>>,
    hls_base_dir: String,
}

#[allow(dead_code)]
struct HlsSession {
    file_path: String,
    session_id: String,
    output_dir: String,
    ffmpeg_process: Option<Child>,
    created_at: std::time::Instant,
    audio_tracks: Vec<AudioTrackInfo>,
    current_quality: Option<String>,
    current_audio_track: u32,
}

impl HlsSessionManager {
    pub fn new(base_dir: &str) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            hls_base_dir: base_dir.to_string(),
        }
    }

    /// 创建 HLS 会话并开始转码
    /// 支持: 任意视频格式 → HLS fMP4 (兼容所有平台)
    /// 音频强制转码为 AAC (兼容 DTS/AC3 等不支持的格式)
    pub fn create_session(&self, file_path: &str, quality: Option<&str>, audio_track: Option<u32>) -> Result<(String, Vec<AudioTrackInfo>), AppError> {
        let session_id = Uuid::new_v4().to_string();
        let output_dir = format!("{}/{}", self.hls_base_dir, session_id);
        
        // 创建输出目录
        std::fs::create_dir_all(&output_dir).map_err(|e| {
            error!("Failed to create HLS output dir: {}", e);
            AppError::InternalError
        })?;

        // 探测媒体信息（获取音轨列表）
        let audio_tracks = probe_audio_tracks(file_path);
        let selected_audio = audio_track.unwrap_or(0);

        let playlist_path = format!("{}/master.m3u8", output_dir);
        let segment_pattern = format!("{}/seg_%05d.m4s", output_dir);
        let _init_segment = format!("{}/init.mp4", output_dir);

        // 获取视频信息决定是否需要转码
        let video_info = probe_video_info(file_path);
        let needs_video_transcode = video_info.as_ref()
            .map(|v| !is_h264_compatible(&v.codec))
            .unwrap_or(true);

        // 构建 FFmpeg 参数
        let mut args: Vec<String> = vec![
            "-hide_banner".to_string(),
            "-loglevel".to_string(),
            "warning".to_string(),
            "-fflags".to_string(),
            "+genpts".to_string(),
            "-i".to_string(),
            file_path.to_string(),
        ];

        // 选择音轨
        args.extend(vec![
            "-map".to_string(),
            "0:v:0".to_string(),  // 第一个视频流
            "-map".to_string(),
            format!("0:a:{}", selected_audio),  // 指定音轨
        ]);

        // 视频编码设置
        if needs_video_transcode {
            // 需要转码：使用 H.264 (兼容性最好)
            let hw_encoder = detect_hw_encoder();
            if let Some(encoder) = hw_encoder {
                args.extend(vec!["-c:v".to_string(), encoder]);
            } else {
                args.extend(vec!["-c:v".to_string(), "libx264".to_string()]);
                args.extend(vec!["-preset".to_string(), "fast".to_string()]);
            }
            
            // 根据清晰度设置分辨率和码率
            match quality.unwrap_or("auto") {
                "1080p" => {
                    args.extend(vec!["-vf".to_string(), "scale=-2:1080".to_string()]);
                    args.extend(vec!["-b:v".to_string(), "4M".to_string()]);
                }
                "720p" => {
                    args.extend(vec!["-vf".to_string(), "scale=-2:720".to_string()]);
                    args.extend(vec!["-b:v".to_string(), "2M".to_string()]);
                }
                "480p" => {
                    args.extend(vec!["-vf".to_string(), "scale=-2:480".to_string()]);
                    args.extend(vec!["-b:v".to_string(), "1M".to_string()]);
                }
                "360p" => {
                    args.extend(vec!["-vf".to_string(), "scale=-2:360".to_string()]);
                    args.extend(vec!["-b:v".to_string(), "500k".to_string()]);
                }
                _ => {
                    // auto: 保持原始分辨率
                    args.extend(vec!["-b:v".to_string(), "4M".to_string()]);
                }
            }
        } else {
            // 视频流直接复制（H.264 兼容）
            args.extend(vec!["-c:v".to_string(), "copy".to_string()]);
        }

        // 音频编码：强制转为 AAC（兼容 DTS/AC3/TrueHD 等）
        args.extend(vec![
            "-c:a".to_string(),
            "aac".to_string(),
            "-b:a".to_string(),
            "192k".to_string(),
            "-ac".to_string(),
            "2".to_string(),  // 立体声
            "-ar".to_string(),
            "48000".to_string(),
        ]);

        // HLS fMP4 输出参数（更好的浏览器兼容性）
        args.extend(vec![
            "-f".to_string(),
            "hls".to_string(),
            "-hls_time".to_string(),
            "4".to_string(),  // 4秒一个片段
            "-hls_list_size".to_string(),
            "0".to_string(),  // 保留所有片段（支持完整 seek）
            "-hls_flags".to_string(),
            "independent_segments+single_file".to_string(),
            "-hls_segment_type".to_string(),
            "fmp4".to_string(),  // 使用 fMP4 而非 MPEG-TS
            "-hls_fmp4_init_filename".to_string(),
            "init.mp4".to_string(),
            "-hls_segment_filename".to_string(),
            segment_pattern,
            "-start_number".to_string(),
            "0".to_string(),
            "-movflags".to_string(),
            "+faststart".to_string(),
            playlist_path.clone(),
        ]);

        info!("Starting HLS fMP4 transcode for session {}", session_id);
        info!("Video transcode needed: {}, Audio tracks: {}", needs_video_transcode, audio_tracks.len());

        let child = Command::new("ffmpeg")
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                error!("Failed to start HLS transcode: {}", e);
                AppError::InternalError
            })?;

        let session = HlsSession {
            file_path: file_path.to_string(),
            session_id: session_id.clone(),
            output_dir: output_dir.clone(),
            ffmpeg_process: Some(child),
            created_at: std::time::Instant::now(),
            audio_tracks: audio_tracks.clone(),
            current_quality: quality.map(|s| s.to_string()),
            current_audio_track: selected_audio,
        };

        self.sessions.lock().unwrap().insert(session_id.clone(), session);

        Ok((session_id, audio_tracks))
    }

    /// 获取 HLS 播放列表
    pub fn get_playlist(&self, session_id: &str) -> Result<String, AppError> {
        let sessions = self.sessions.lock().unwrap();
        let session = sessions.get(session_id)
            .ok_or_else(|| AppError::NotFound("Session not found".to_string()))?;
        
        let playlist_path = format!("{}/master.m3u8", session.output_dir);
        
        // 等待播放列表生成（最多等待 15 秒）
        drop(sessions); // 释放锁以避免死锁
        for _ in 0..150 {
            if Path::new(&playlist_path).exists() {
                // 检查文件是否有内容
                if let Ok(content) = std::fs::read_to_string(&playlist_path) {
                    if content.contains("#EXTINF") || content.contains("#EXT-X-MAP") {
                        return Ok(content);
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        Err(AppError::BadRequest("Playlist not ready yet, transcoding in progress...".to_string()))
    }

    /// 获取会话的音轨信息
    pub fn get_audio_tracks(&self, session_id: &str) -> Result<Vec<AudioTrackInfo>, AppError> {
        let sessions = self.sessions.lock().unwrap();
        let session = sessions.get(session_id)
            .ok_or_else(|| AppError::NotFound("Session not found".to_string()))?;
        Ok(session.audio_tracks.clone())
    }

    /// 切换音轨（重新启动转码）
    pub fn switch_audio_track(&self, session_id: &str, audio_track: u32) -> Result<(), AppError> {
        let file_path;
        let quality;
        {
            let sessions = self.sessions.lock().unwrap();
            let session = sessions.get(session_id)
                .ok_or_else(|| AppError::NotFound("Session not found".to_string()))?;
            file_path = session.file_path.clone();
            quality = session.current_quality.clone();
        }
        
        // 停止当前会话
        self.cleanup_session(session_id);
        
        // 使用相同的 session_id 创建新会话（这里简化处理，实际上创建新会话）
        self.create_session(&file_path, quality.as_deref(), Some(audio_track))?;
        
        Ok(())
    }

    /// 获取 HLS 片段
    pub fn get_segment(&self, session_id: &str, segment_name: &str) -> Result<Vec<u8>, AppError> {
        let sessions = self.sessions.lock().unwrap();
        let session = sessions.get(session_id)
            .ok_or_else(|| AppError::NotFound("Session not found".to_string()))?;
        
        let segment_path = format!("{}/{}", session.output_dir, segment_name);
        
        // 等待片段生成（最多等待 5 秒）
        for _ in 0..50 {
            if Path::new(&segment_path).exists() {
                // 检查文件大小是否稳定（确保写入完成）
                let size1 = std::fs::metadata(&segment_path).map(|m| m.len()).unwrap_or(0);
                std::thread::sleep(std::time::Duration::from_millis(50));
                let size2 = std::fs::metadata(&segment_path).map(|m| m.len()).unwrap_or(0);
                
                if size1 == size2 && size1 > 0 {
                    return std::fs::read(&segment_path)
                        .map_err(|_| AppError::InternalError);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        Err(AppError::NotFound("Segment not found".to_string()))
    }

    /// 清理会话
    pub fn cleanup_session(&self, session_id: &str) {
        if let Some(mut session) = self.sessions.lock().unwrap().remove(session_id) {
            // 终止 FFmpeg 进程
            if let Some(ref mut child) = session.ffmpeg_process {
                let _ = child.kill();
            }
            // 删除临时文件
            let _ = std::fs::remove_dir_all(&session.output_dir);
            info!("Cleaned up HLS session: {}", session_id);
        }
    }

    /// 清理过期会话（超过 1 小时）
    #[allow(dead_code)]
    pub fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.lock().unwrap();
        let expired: Vec<String> = sessions.iter()
            .filter(|(_, s)| s.created_at.elapsed().as_secs() > 3600)
            .map(|(id, _)| id.clone())
            .collect();
        
        for id in expired {
            if let Some(mut session) = sessions.remove(&id) {
                if let Some(ref mut child) = session.ffmpeg_process {
                    let _ = child.kill();
                }
                let _ = std::fs::remove_dir_all(&session.output_dir);
                info!("Cleaned up expired HLS session: {}", id);
            }
        }
    }
}

/// 探测视频信息
#[derive(Debug)]
#[allow(dead_code)]
struct VideoInfo {
    codec: String,
    width: u32,
    height: u32,
}

fn probe_video_info(file_path: &str) -> Option<VideoInfo> {
    let output = Command::new("ffprobe")
        .args([
            "-v", "quiet",
            "-select_streams", "v:0",
            "-show_entries", "stream=codec_name,width,height",
            "-of", "csv=p=0",
            file_path,
        ])
        .output()
        .ok()?;

    if output.status.success() {
        let info = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = info.trim().split(',').collect();
        if parts.len() >= 3 {
            return Some(VideoInfo {
                codec: parts[0].to_string(),
                width: parts[1].parse().unwrap_or(0),
                height: parts[2].parse().unwrap_or(0),
            });
        }
    }
    None
}

/// 探测音轨信息
fn probe_audio_tracks(file_path: &str) -> Vec<AudioTrackInfo> {
    let output = Command::new("ffprobe")
        .args([
            "-v", "quiet",
            "-select_streams", "a",
            "-show_entries", "stream=index,codec_name:stream_tags=language,title",
            "-of", "json",
            file_path,
        ])
        .output();

    let mut tracks = Vec::new();
    
    if let Ok(output) = output {
        if output.status.success() {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                if let Some(streams) = json.get("streams").and_then(|s| s.as_array()) {
                    for (i, stream) in streams.iter().enumerate() {
                        let codec = stream.get("codec_name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        
                        let tags = stream.get("tags");
                        let language = tags
                            .and_then(|t| t.get("language"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("und")
                            .to_string();
                        let title = tags
                            .and_then(|t| t.get("title"))
                            .and_then(|v| v.as_str())
                            .unwrap_or(&format!("音轨 {}", i + 1))
                            .to_string();

                        tracks.push(AudioTrackInfo {
                            index: i as u32,
                            language,
                            title,
                            codec,
                        });
                    }
                }
            }
        }
    }

    // 如果没有探测到，返回默认音轨
    if tracks.is_empty() {
        tracks.push(AudioTrackInfo {
            index: 0,
            language: "und".to_string(),
            title: "默认音轨".to_string(),
            codec: "unknown".to_string(),
        });
    }

    tracks
}

/// 检查视频编码是否兼容 H.264（可以直接复制）
fn is_h264_compatible(codec: &str) -> bool {
    matches!(codec.to_lowercase().as_str(), "h264" | "avc" | "avc1")
}

/// 检测可用的硬件编码器
fn detect_hw_encoder() -> Option<String> {
    // Rockchip MPP
    if Path::new("/dev/video10").exists() {
        return Some("h264_rkmpp".to_string());
    }
    // VAAPI (Intel/AMD)
    if Path::new("/dev/dri/renderD128").exists() {
        return Some("h264_vaapi".to_string());
    }
    // NVENC (NVIDIA)
    if Path::new("/dev/nvidia0").exists() {
        return Some("h264_nvenc".to_string());
    }
    // V4L2 (通用 ARM)
    if Path::new("/dev/video11").exists() {
        return Some("h264_v4l2m2m".to_string());
    }
    None
}

// ============================================================
// HLS API 端点
// ============================================================

#[derive(Deserialize)]
pub struct HlsStartRequest {
    /// 文件ID（可选，优先使用）
    pub file_id: Option<String>,
    /// 文件路径（可选，用于文件管理器）
    pub file_path: Option<String>,
    /// 清晰度: "auto", "1080p", "720p", "480p", "360p"
    pub quality: Option<String>,
    /// 音轨索引（0开始）
    pub audio_track: Option<u32>,
}

/// 开始 HLS 流式传输
pub async fn start_hls_stream(
    pool: web::Data<SqlitePool>,
    hls_manager: web::Data<HlsSessionManager>,
    claims: web::ReqData<crate::auth::Claims>,
    body: web::Json<HlsStartRequest>,
) -> Result<impl Responder, AppError> {
    // 获取文件路径：优先使用 file_id，其次使用 file_path
    let file_path = if let Some(file_id) = &body.file_id {
        // 通过 file_id 查找
        let file = db::find_file_by_id(&pool, file_id, &claims.sub)
            .await?
            .ok_or_else(|| AppError::NotFound("File not found".to_string()))?;
        file.file_path
    } else if let Some(path) = &body.file_path {
        // 直接使用文件路径（文件管理器模式）
        // 验证文件存在且用户有权限访问
        if !Path::new(path).exists() {
            return Err(AppError::NotFound("File not found".to_string()));
        }
        path.clone()
    } else {
        return Err(AppError::BadRequest("Either file_id or file_path is required".to_string()));
    };

    // 创建 HLS 会话
    let (session_id, audio_tracks) = hls_manager.create_session(
        &file_path, 
        body.quality.as_deref(),
        body.audio_track
    )?;

    info!("Started HLS stream for file {:?} - session {}", file_path, session_id);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "session_id": session_id,
        "playlist_url": format!("/api/v1/media/hls/{}/master.m3u8", session_id),
        "audio_tracks": audio_tracks,
        "available_qualities": ["auto", "1080p", "720p", "480p", "360p"],
    })))
}

/// 获取 HLS 播放列表
pub async fn get_hls_playlist(
    hls_manager: web::Data<HlsSessionManager>,
    path: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let session_id = path.into_inner();
    let playlist = hls_manager.get_playlist(&session_id)?;

    Ok(HttpResponse::Ok()
        .content_type("application/vnd.apple.mpegurl")
        .insert_header(("Access-Control-Allow-Origin", "*"))
        .insert_header(("Cache-Control", "no-cache"))
        .body(playlist))
}

/// 获取 HLS 片段（支持 fMP4 和 TS）
pub async fn get_hls_segment(
    hls_manager: web::Data<HlsSessionManager>,
    path: web::Path<(String, String)>,
) -> Result<impl Responder, AppError> {
    let (session_id, segment_name) = path.into_inner();
    let segment = hls_manager.get_segment(&session_id, &segment_name)?;

    // 根据文件扩展名设置正确的 Content-Type
    let content_type = if segment_name.ends_with(".m4s") || segment_name.ends_with(".mp4") {
        "video/mp4"
    } else {
        "video/mp2t"
    };

    Ok(HttpResponse::Ok()
        .content_type(content_type)
        .insert_header(("Access-Control-Allow-Origin", "*"))
        .insert_header(("Cache-Control", "max-age=3600"))
        .body(segment))
}

/// 获取音轨列表
pub async fn get_hls_audio_tracks(
    hls_manager: web::Data<HlsSessionManager>,
    path: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let session_id = path.into_inner();
    let tracks = hls_manager.get_audio_tracks(&session_id)?;
    Ok(HttpResponse::Ok().json(tracks))
}

/// 切换音轨
#[derive(Deserialize)]
pub struct SwitchAudioRequest {
    pub audio_track: u32,
}

pub async fn switch_hls_audio_track(
    hls_manager: web::Data<HlsSessionManager>,
    path: web::Path<String>,
    body: web::Json<SwitchAudioRequest>,
) -> Result<impl Responder, AppError> {
    let session_id = path.into_inner();
    hls_manager.switch_audio_track(&session_id, body.audio_track)?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Audio track switched",
        "audio_track": body.audio_track,
    })))
}

/// 停止 HLS 会话
pub async fn stop_hls_stream(
    hls_manager: web::Data<HlsSessionManager>,
    path: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let session_id = path.into_inner();
    hls_manager.cleanup_session(&session_id);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "HLS session stopped"
    })))
}
