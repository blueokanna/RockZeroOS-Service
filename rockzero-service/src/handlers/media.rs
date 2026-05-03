use actix_web::{web, HttpResponse, Responder};
use rockzero_common::AppError;
use serde::Serialize;
use sqlx::SqlitePool;
use std::path::Path;
use std::process::Command;
use tracing::info;

fn find_ffmpeg() -> Option<String> {
    if let Some(path) = crate::ffmpeg_manager::get_global_ffmpeg_path() {
        if Path::new(&path).exists() {
            return Some(path);
        }
    }

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

#[derive(Debug, Serialize)]
pub struct MediaCodecInfo {
    pub available: bool,
    pub video_codecs: Vec<String>,
    pub audio_codecs: Vec<String>,
    pub hardware_accel: Vec<String>,
    pub version: Option<String>,
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
        "user_id": claims.sub,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_ffmpeg() {
        let result = find_ffmpeg();

        println!("FFmpeg path: {:?}", result);
    }

    #[test]
    fn test_codec_info_structure() {
        let info = MediaCodecInfo {
            available: true,
            video_codecs: vec!["h264".to_string()],
            audio_codecs: vec!["aac".to_string()],
            hardware_accel: vec!["vaapi".to_string()],
            version: Some("ffmpeg version 4.4.2".to_string()),
        };

        assert!(info.available);
        assert_eq!(info.video_codecs.len(), 1);
        assert_eq!(info.audio_codecs.len(), 1);
    }
}
