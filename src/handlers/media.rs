use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::path::Path;
use std::process::Command;
use tracing::info;
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
