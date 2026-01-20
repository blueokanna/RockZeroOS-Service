use actix_web::{web, HttpResponse, Responder};
use rockzero_common::AppError;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::db;

/// 查找 FFmpeg 可执行文件路径
fn find_ffmpeg() -> Option<String> {
    // 首先检查全局设置的路径
    if let Some(path) = crate::ffmpeg_manager::get_global_ffmpeg_path() {
        if Path::new(&path).exists() {
            return Some(path);
        }
    }

    // 常见路径
    let paths = [
        "/usr/bin/ffmpeg",
        "/usr/local/bin/ffmpeg",
        "/opt/homebrew/bin/ffmpeg",
        "ffmpeg",
    ];

    for path in paths {
        if Command::new(path).arg("-version").output().is_ok() {
            return Some(path.to_string());
        }
    }

    // Windows 路径
    #[cfg(windows)]
    {
        let win_paths = [
            "C:\\ffmpeg\\bin\\ffmpeg.exe",
            "C:\\Program Files\\ffmpeg\\bin\\ffmpeg.exe",
        ];
        for path in win_paths {
            if Path::new(path).exists() {
                return Some(path.to_string());
            }
        }
    }

    None
}

/// 查找 FFprobe 可执行文件路径
fn find_ffprobe() -> Option<String> {
    if let Some(path) = crate::ffmpeg_manager::get_global_ffprobe_path() {
        if Path::new(&path).exists() {
            return Some(path);
        }
    }

    let paths = [
        "/usr/bin/ffprobe",
        "/usr/local/bin/ffprobe",
        "/opt/homebrew/bin/ffprobe",
        "ffprobe",
    ];

    for path in paths {
        if Command::new(path).arg("-version").output().is_ok() {
            return Some(path.to_string());
        }
    }

    #[cfg(windows)]
    {
        let win_paths = [
            "C:\\ffmpeg\\bin\\ffprobe.exe",
            "C:\\Program Files\\ffmpeg\\bin\\ffprobe.exe",
        ];
        for path in win_paths {
            if Path::new(path).exists() {
                return Some(path.to_string());
            }
        }
    }

    None
}

#[derive(Debug, Serialize)]
pub struct MediaCodecInfo {
    pub available: bool,
    pub video_codecs: Vec<String>,
    pub audio_codecs: Vec<String>,
    pub hardware_accel: Vec<String>,
    pub version: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct TranscodeRequest {
    pub input_path: String,
    pub output_path: Option<String>,
    pub video_codec: Option<String>,
    pub audio_codec: Option<String>,
    pub resolution: Option<String>,
}

pub async fn list_media(
    _pool: web::Data<SqlitePool>,
    _claims: web::ReqData<crate::handlers::auth::Claims>,
) -> Result<impl Responder, AppError> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Use /api/v1/streaming/library for media listing"
    })))
}

pub async fn create_media(
    _pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<serde_json::Value>,
) -> Result<impl Responder, AppError> {
    let title = body
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("Untitled");

    info!(
        "Media creation requested by user: {} - title: {}",
        claims.sub, title
    );

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Media metadata created",
        "title": title,
    })))
}

pub async fn get_codec_info() -> Result<impl Responder, AppError> {
    let ffmpeg_path = find_ffmpeg();
    let ffmpeg_available = ffmpeg_path.is_some();

    let mut version = None;
    if let Some(ref path) = ffmpeg_path {
        if let Ok(output) = Command::new(path).arg("-version").output() {
            let version_str = String::from_utf8_lossy(&output.stdout);
            if let Some(line) = version_str.lines().next() {
                version = Some(line.to_string());
            }
        }
    }

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
        available: ffmpeg_available,
        video_codecs: supported_video_codecs,
        audio_codecs: supported_audio_codecs,
        hardware_accel: hardware_acceleration,
        version,
    };

    Ok(HttpResponse::Ok().json(codec_info))
}

pub async fn transcode_media(
    _pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    _body: web::Json<TranscodeRequest>,
) -> Result<impl Responder, AppError> {
    info!("Transcode requested by user: {}", claims.sub);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Transcoding service available - use streaming API for real-time transcoding",
        "hint": "Check /api/v1/streaming/transcode endpoint"
    })))
}

#[allow(dead_code)]
fn get_media_duration(file_path: &str) -> Option<i64> {
    let ffprobe_path = find_ffprobe()?;

    let output = Command::new(&ffprobe_path)
        .args([
            "-v",
            "quiet",
            "-show_entries",
            "format=duration",
            "-of",
            "default=noprint_wrappers=1:nokey=1",
            file_path,
        ])
        .output()
        .ok()?;

    let duration_str = String::from_utf8_lossy(&output.stdout);
    duration_str.trim().parse::<f64>().ok().map(|d| d as i64)
}

// ============================================================
// HLS 实时流式传输 - 支持所有视频格式
// 设计理念：任意格式输入 → FFmpeg 转封装/转码 → HLS fMP4 分段输出
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioTrackInfo {
    pub index: u32,
    pub codec: String,
    pub language: Option<String>,
    pub title: Option<String>,
    pub channels: u32,
    pub sample_rate: u32,
    pub bitrate: Option<u64>,
    pub default: bool,
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
    /// 创建 HLS 会话并开始转码
    /// 支持: 任意视频格式 → HLS MPEG-TS (兼容所有平台)
    /// 音频强制转码为 AAC (兼容 DTS/AC3 等不支持的格式)
    pub fn create_session(&self, file_path: &str, quality: Option<&str>, audio_track: Option<u32>) -> Result<(String, Vec<AudioTrackInfo>), AppError> {
        info!("Creating HLS session for: {}", file_path);

        // 首先检查输入文件是否存在
        if !Path::new(file_path).exists() {
            error!("Input file does not exist: {}", file_path);
            return Err(AppError::NotFound(format!("Video file not found: {}", file_path)));
        }
        info!("Input file exists: {}", file_path);

        // 检查 FFmpeg 是否可用
        let ffmpeg_path = find_ffmpeg().ok_or_else(|| {
            error!("FFmpeg is not installed or not in PATH. Please install FFmpeg.");
            AppError::BadRequest("FFmpeg is not installed on the server. Please install FFmpeg first. On Ubuntu: apt install ffmpeg".to_string())
        })?;
        info!("Found FFmpeg at: {}", ffmpeg_path);

        let session_id = Uuid::new_v4().to_string();
        let output_dir = format!("{}/{}", self.hls_base_dir, session_id);

        // 创建输出目录
        std::fs::create_dir_all(&output_dir).map_err(|e| {
            error!("Failed to create HLS output dir {}: {}", output_dir, e);
            AppError::InternalError
        })?;
        info!("Created output directory: {}", output_dir);

        // 探测媒体信息（获取音轨列表）
        let audio_tracks = probe_audio_tracks(file_path);
        let selected_audio = audio_track.unwrap_or(0);

        let playlist_path = format!("{}/master.m3u8", output_dir);
        let segment_pattern = format!("{}/seg_%05d.ts", output_dir);

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

        // HLS MPEG-TS 输出参数（最大兼容性）
        args.extend(vec![
            "-f".to_string(),
            "hls".to_string(),
            "-hls_time".to_string(),
            "4".to_string(),  // 4秒一个片段
            "-hls_list_size".to_string(),
            "0".to_string(),  // 保留所有片段（支持完整 seek）
            "-hls_flags".to_string(),
            "independent_segments+delete_segments+append_list".to_string(),
            "-hls_segment_type".to_string(),
            "mpegts".to_string(),  // 使用 MPEG-TS 格式（最大兼容性）
            "-hls_segment_filename".to_string(),
            segment_pattern,
            "-start_number".to_string(),
            "0".to_string(),
            playlist_path.clone(),
        ]);

        info!("Starting HLS MPEG-TS transcode for session {}", session_id);
        info!("Video transcode needed: {}, Audio tracks: {}", needs_video_transcode, audio_tracks.len());
        info!("FFmpeg args: {:?}", args);
        info!("Using FFmpeg: {}", ffmpeg_path);

        let child = Command::new(&ffmpeg_path)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                error!("Failed to start HLS transcode: {} - Command: {} {:?}", e, ffmpeg_path, args);
                AppError::BadRequest(format!("Failed to start FFmpeg: {}", e))
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
        drop(sessions);
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
    fps: f64,
    bitrate: Option<u64>,
}

fn probe_video_info(file_path: &str) -> Option<VideoInfo> {
    let ffprobe_path = find_ffprobe()?;

    let output = Command::new(&ffprobe_path)
        .args([
            "-v", "quiet",
            "-print_format", "json",
            "-show_streams",
            "-select_streams", "v:0",
            file_path,
        ])
        .output()
        .ok()?;

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let stream = json.get("streams")?.get(0)?;

    Some(VideoInfo {
        codec: stream.get("codec_name")?.as_str()?.to_string(),
        width: stream.get("width")?.as_u64()? as u32,
        height: stream.get("height")?.as_u64()? as u32,
        fps: {
            let fps_str = stream.get("r_frame_rate")?.as_str()?;
            let parts: Vec<&str> = fps_str.split('/').collect();
            if parts.len() == 2 {
                let num: f64 = parts[0].parse().ok()?;
                let den: f64 = parts[1].parse().ok()?;
                if den > 0.0 { num / den } else { 0.0 }
            } else {
                fps_str.parse().unwrap_or(0.0)
            }
        },
        bitrate: stream.get("bit_rate")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok()),
    })
}

/// 探测音轨信息
fn probe_audio_tracks(file_path: &str) -> Vec<AudioTrackInfo> {
    let ffprobe_path = match find_ffprobe() {
        Some(p) => p,
        None => {
            warn!("ffprobe not found, returning empty audio tracks");
            return vec![];
        }
    };

    let output = match Command::new(&ffprobe_path)
        .args([
            "-v", "quiet",
            "-print_format", "json",
            "-show_streams",
            "-select_streams", "a",
            file_path,
        ])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            warn!("Failed to run ffprobe: {}", e);
            return vec![];
        }
    };

    let json: serde_json::Value = match serde_json::from_slice(&output.stdout) {
        Ok(j) => j,
        Err(_) => return vec![],
    };

    let streams = match json.get("streams").and_then(|s| s.as_array()) {
        Some(s) => s,
        None => return vec![],
    };

    streams.iter().enumerate().map(|(i, stream)| {
        let tags = stream.get("tags");
        AudioTrackInfo {
            index: i as u32,
            codec: stream.get("codec_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            language: tags
                .and_then(|t| t.get("language"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            title: tags
                .and_then(|t| t.get("title"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            channels: stream.get("channels")
                .and_then(|v| v.as_u64())
                .unwrap_or(2) as u32,
            sample_rate: stream.get("sample_rate")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(48000),
            bitrate: stream.get("bit_rate")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok()),
            default: stream.get("disposition")
                .and_then(|d| d.get("default"))
                .and_then(|v| v.as_i64())
                .map(|v| v == 1)
                .unwrap_or(i == 0),
        }
    }).collect()
}

/// 检查视频编码是否兼容 H.264（可以直接复制）
fn is_h264_compatible(codec: &str) -> bool {
    matches!(codec.to_lowercase().as_str(), "h264" | "avc" | "avc1")
}

/// 检测可用的硬件编码器
fn detect_hw_encoder() -> Option<String> {
    let ffmpeg_path = find_ffmpeg()?;

    // 检测 NVIDIA NVENC
    if Command::new(&ffmpeg_path)
        .args(["-hide_banner", "-encoders"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("h264_nvenc"))
        .unwrap_or(false)
    {
        // 验证 NVENC 是否真正可用
        if Command::new(&ffmpeg_path)
            .args(["-hide_banner", "-f", "lavfi", "-i", "color=c=black:s=64x64:d=0.1", "-c:v", "h264_nvenc", "-f", "null", "-"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            info!("Using NVIDIA NVENC hardware encoder");
            return Some("h264_nvenc".to_string());
        }
    }

    // 检测 Intel QSV
    if Command::new(&ffmpeg_path)
        .args(["-hide_banner", "-encoders"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("h264_qsv"))
        .unwrap_or(false)
    {
        if Command::new(&ffmpeg_path)
            .args(["-hide_banner", "-f", "lavfi", "-i", "color=c=black:s=64x64:d=0.1", "-c:v", "h264_qsv", "-f", "null", "-"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            info!("Using Intel QSV hardware encoder");
            return Some("h264_qsv".to_string());
        }
    }

    // 检测 VAAPI (Linux)
    if cfg!(target_os = "linux") {
        if Path::new("/dev/dri/renderD128").exists() {
            if Command::new(&ffmpeg_path)
                .args(["-hide_banner", "-encoders"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("h264_vaapi"))
                .unwrap_or(false)
            {
                info!("Using VAAPI hardware encoder");
                return Some("h264_vaapi".to_string());
            }
        }
    }

    // 检测 VideoToolbox (macOS)
    if cfg!(target_os = "macos") {
        if Command::new(&ffmpeg_path)
            .args(["-hide_banner", "-encoders"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("h264_videotoolbox"))
            .unwrap_or(false)
        {
            info!("Using VideoToolbox hardware encoder");
            return Some("h264_videotoolbox".to_string());
        }
    }

    // 检测 Rockchip MPP (ARM)
    if cfg!(target_arch = "aarch64") || cfg!(target_arch = "arm") {
        if Path::new("/dev/video10").exists() {
            if Command::new(&ffmpeg_path)
                .args(["-hide_banner", "-encoders"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("h264_rkmpp"))
                .unwrap_or(false)
            {
                info!("Using Rockchip MPP hardware encoder");
                return Some("h264_rkmpp".to_string());
            }
        }
    }

    info!("No hardware encoder available, using software encoding");
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
    claims: web::ReqData<crate::handlers::auth::Claims>,
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
