use actix_web::{web, HttpRequest, HttpResponse};
use bytes::Bytes;
use rockzero_common::AppError;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::pin::Pin;
use std::process::Command;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncSeekExt};
use tracing::warn;

use crate::media_processor::needs_audio_transcode;

const MEDIA_BASE: &str = "./media";

/// Chunk sizes for different streaming scenarios
#[allow(dead_code)]
const INITIAL_CHUNK_SIZE: usize = 256 * 1024; // 256KB for initial probe
#[allow(dead_code)]
const STREAMING_CHUNK_SIZE: usize = 2 * 1024 * 1024; // 2MB for sequential streaming
#[allow(dead_code)]
const SEEK_CHUNK_SIZE: usize = 512 * 1024; // 512KB for seek (smaller = faster first-byte)

#[derive(Debug, Serialize)]
pub struct MediaStreamInfo {
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    pub duration: Option<f64>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub video_codec: Option<String>,
    pub audio_codec: Option<String>,
    pub bitrate: Option<u64>,
    pub supports_range: bool,
    pub video_bitrate: Option<u64>,
    pub audio_bitrate: Option<u64>,
    pub frame_rate: Option<f64>,
    pub audio_channels: Option<u32>,
    pub audio_sample_rate: Option<u32>,
    pub audio_tracks: Option<Vec<AudioTrackInfo>>,
    pub has_audio: bool,
    pub needs_audio_transcode: bool,
    pub transcode_url: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct AudioTrackInfo {
    pub index: u32,
    pub codec: String,
    pub channels: Option<u32>,
    pub sample_rate: Option<u32>,
    pub bitrate: Option<u64>,
    pub language: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExtendedMediaInfo {
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    pub duration: Option<f64>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub video_codec: Option<String>,
    pub video_bitrate: Option<u64>,
    pub frame_rate: Option<f64>,
    pub aspect_ratio: Option<String>,
    pub color_space: Option<String>,
    pub audio_codec: Option<String>,
    pub audio_bitrate: Option<u64>,
    pub audio_channels: Option<u32>,
    pub audio_sample_rate: Option<u32>,
    pub audio_tracks: Vec<AudioTrackInfo>,
    pub has_audio: bool,
    pub bitrate: Option<u64>,
    pub container_format: Option<String>,
    pub exif: Option<ExifData>,
}

#[derive(Debug, Serialize, Default)]
pub struct ExifData {
    pub camera_make: Option<String>,
    pub camera_model: Option<String>,
    pub lens_model: Option<String>,
    pub focal_length: Option<String>,
    pub aperture: Option<String>,
    pub shutter_speed: Option<String>,
    pub iso: Option<String>,
    pub date_taken: Option<String>,
    pub gps_latitude: Option<String>,
    pub gps_longitude: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PlaylistEntry {
    pub id: String,
    pub title: String,
    pub path: String,
    pub duration: Option<f64>,
    pub thumbnail: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StreamQuery {
    pub path: Option<String>,
    pub quality: Option<String>,
    #[allow(dead_code)]
    pub seek: Option<f64>,
}

pub async fn get_media_info(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let file_path = get_media_path(&path.into_inner())?;
    if !file_path.exists() {
        return Err(AppError::NotFound("Media file not found".to_string()));
    }

    let metadata = std::fs::metadata(&file_path).map_err(|_| AppError::InternalError)?;
    let content_type = mime_guess::from_path(&file_path)
        .first_or_octet_stream()
        .to_string();

    let media_details = get_detailed_ffprobe_info(&file_path);

    let needs_transcode = media_details
        .audio_codec
        .as_ref()
        .map(|codec| needs_audio_transcode(codec))
        .unwrap_or(false);

    let relative_path = file_path
        .strip_prefix(MEDIA_BASE)
        .unwrap_or(&file_path)
        .to_string_lossy()
        .to_string();

    let transcode_url = if needs_transcode {
        Some(format!("/api/v1/streaming/transcode/{}", relative_path))
    } else {
        None
    };

    let info = MediaStreamInfo {
        filename: file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default(),
        content_type,
        size: metadata.len(),
        duration: media_details.duration,
        width: media_details.width,
        height: media_details.height,
        video_codec: media_details.video_codec,
        audio_codec: media_details.audio_codec.clone(),
        bitrate: media_details.bitrate,
        supports_range: true,
        video_bitrate: media_details.video_bitrate,
        audio_bitrate: media_details.audio_bitrate,
        frame_rate: media_details.frame_rate,
        audio_channels: media_details.audio_channels,
        audio_sample_rate: media_details.audio_sample_rate,
        audio_tracks: if media_details.audio_tracks.is_empty() {
            None
        } else {
            Some(media_details.audio_tracks)
        },
        has_audio: media_details.has_audio,
        needs_audio_transcode: needs_transcode,
        transcode_url,
    };

    Ok(HttpResponse::Ok().json(info))
}

pub async fn get_extended_media_info(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let file_path = get_media_path(&path.into_inner())?;
    if !file_path.exists() {
        return Err(AppError::NotFound("Media file not found".to_string()));
    }

    let metadata = std::fs::metadata(&file_path).map_err(|_| AppError::InternalError)?;
    let content_type = mime_guess::from_path(&file_path)
        .first_or_octet_stream()
        .to_string();

    let exif = if content_type.starts_with("image/") {
        extract_exif_data(&file_path)
    } else {
        None
    };

    let media_details = get_detailed_ffprobe_info(&file_path);

    let info = ExtendedMediaInfo {
        filename: file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default(),
        content_type,
        size: metadata.len(),
        duration: media_details.duration,
        width: media_details.width,
        height: media_details.height,
        video_codec: media_details.video_codec,
        video_bitrate: media_details.video_bitrate,
        frame_rate: media_details.frame_rate,
        aspect_ratio: media_details.aspect_ratio,
        color_space: media_details.color_space,
        audio_codec: media_details.audio_codec,
        audio_bitrate: media_details.audio_bitrate,
        audio_channels: media_details.audio_channels,
        audio_sample_rate: media_details.audio_sample_rate,
        audio_tracks: media_details.audio_tracks,
        has_audio: media_details.has_audio,
        bitrate: media_details.bitrate,
        container_format: media_details.container_format,
        exif,
    };

    Ok(HttpResponse::Ok().json(info))
}

// ============ Async file streaming with proper tokio I/O ============

/// Async file stream that uses tokio::fs for non-blocking I/O.
/// This prevents blocking the async runtime when reading large files,
/// which was the root cause of seek hangs and slow loading for big videos.
#[allow(dead_code)]
struct AsyncFileStream {
    file: tokio::fs::File,
    remaining: u64,
    chunk_size: usize,
    buf: Vec<u8>,
}

impl AsyncFileStream {
    async fn open(
        path: &Path,
        start: u64,
        length: u64,
        is_seek: bool,
    ) -> Result<Self, std::io::Error> {
        let mut file = tokio::fs::File::open(path).await?;
        file.seek(std::io::SeekFrom::Start(start)).await?;

        // Use smaller chunks for seek operations to minimize time-to-first-byte,
        // and larger chunks for sequential streaming for throughput.
        let chunk_size = if is_seek {
            SEEK_CHUNK_SIZE
        } else if length <= INITIAL_CHUNK_SIZE as u64 {
            INITIAL_CHUNK_SIZE
        } else {
            STREAMING_CHUNK_SIZE
        };

        Ok(Self {
            file,
            remaining: length,
            chunk_size,
            buf: vec![0u8; chunk_size],
        })
    }
}

impl futures::Stream for AsyncFileStream {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if this.remaining == 0 {
            return Poll::Ready(None);
        }

        let to_read = std::cmp::min(this.chunk_size as u64, this.remaining) as usize;

        // Use tokio's async read which integrates with the runtime's I/O driver.
        // This does NOT block the runtime thread — it yields Pending until data is ready.
        let mut read_buf = tokio::io::ReadBuf::new(&mut this.buf[..to_read]);
        match Pin::new(&mut this.file).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    Poll::Ready(None)
                } else {
                    let data = Bytes::copy_from_slice(read_buf.filled());
                    this.remaining -= n as u64;
                    Poll::Ready(Some(Ok(data)))
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Generate an ETag from file metadata for caching and conditional requests.
#[allow(dead_code)]
fn generate_etag(metadata: &std::fs::Metadata) -> String {
    let modified = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let size = metadata.len();
    format!("\"{:x}-{:x}\"", modified, size)
}

/// Format a SystemTime as an HTTP date string for Last-Modified header.
#[allow(dead_code)]
fn format_http_date(time: std::time::SystemTime) -> String {
    let duration = time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let dt = chrono::DateTime::from_timestamp(secs as i64, 0).unwrap_or_default();
    dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

#[allow(dead_code)]
pub async fn stream_media(
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let file_path = get_media_path(&path.into_inner())?;

    if !file_path.exists() {
        return Err(AppError::NotFound("Media file not found".to_string()));
    }

    let metadata = std::fs::metadata(&file_path).map_err(|_| AppError::InternalError)?;
    let file_size = metadata.len();

    if file_size == 0 {
        return Err(AppError::BadRequest("Empty file".to_string()));
    }

    let content_type = mime_guess::from_path(&file_path)
        .first_or_octet_stream()
        .to_string();
    let extension = file_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();

    let effective_content_type = match extension.as_str() {
        "mkv" => "video/x-matroska".to_string(),
        "webm" => "video/webm".to_string(),
        "avi" => "video/x-msvideo".to_string(),
        "mov" => "video/quicktime".to_string(),
        "m2ts" | "ts" => "video/mp2t".to_string(),
        "mp4" | "m4v" => "video/mp4".to_string(),
        "flv" => "video/x-flv".to_string(),
        "wmv" => "video/x-ms-wmv".to_string(),
        "mp3" => "audio/mpeg".to_string(),
        "flac" => "audio/flac".to_string(),
        "wav" => "audio/wav".to_string(),
        "aac" => "audio/aac".to_string(),
        "ogg" => "audio/ogg".to_string(),
        "m4a" => "audio/mp4".to_string(),
        "opus" => "audio/opus".to_string(),
        _ => content_type,
    };

    // Generate ETag and Last-Modified for caching / conditional requests
    let etag = generate_etag(&metadata);
    let last_modified = metadata.modified().ok();

    // Handle conditional requests (If-None-Match)
    if let Some(if_none_match) = req.headers().get("If-None-Match").and_then(|v| v.to_str().ok()) {
        if if_none_match.trim() == etag || if_none_match.trim() == "*" {
            return Ok(HttpResponse::NotModified().finish());
        }
    }

    let effective_content_type_clone = effective_content_type.clone();
    let etag_clone = etag.clone();

    // Standard CORS and cache headers applied to all responses
    let apply_common_headers = move |resp: &mut actix_web::HttpResponseBuilder| {
        resp.insert_header(("Content-Type", effective_content_type_clone.as_str()));
        resp.insert_header(("Accept-Ranges", "bytes"));
        resp.insert_header(("ETag", etag_clone.as_str()));
        resp.insert_header(("Cache-Control", "private, max-age=86400, immutable"));
        resp.insert_header(("Access-Control-Allow-Origin", "*"));
        resp.insert_header((
            "Access-Control-Expose-Headers",
            "Content-Range, Accept-Ranges, Content-Length, Content-Duration, \
             X-Content-Duration, X-Audio-Codec, X-Has-Audio, X-Video-Codec, ETag, Last-Modified",
        ));
        if let Some(ref modified) = last_modified {
            resp.insert_header(("Last-Modified", format_http_date(*modified)));
        }
    };

    let range_header = req.headers().get("Range").and_then(|v| v.to_str().ok());

    if let Some(range) = range_header {
        let (start, end) = parse_range(range, file_size)?;

        // Clamp end to file boundary
        let end = std::cmp::min(end, file_size - 1);
        let length = end - start + 1;

        // Do NOT cap the range size. The player knows what it needs; capping causes
        // re-buffering or stalls when seeking. The async streaming delivers data
        // progressively without blocking the runtime.

        let is_seek = start > 0;
        let stream = AsyncFileStream::open(&file_path, start, length, is_seek)
            .await
            .map_err(|e| {
                warn!("Failed to open file for streaming: {}", e);
                AppError::InternalError
            })?;

        let mut response = HttpResponse::PartialContent();
        apply_common_headers(&mut response);
        response.insert_header((
            "Content-Range",
            format!("bytes {}-{}/{}", start, end, file_size),
        ));
        response.insert_header(("Content-Length", length.to_string()));

        Ok(response.streaming(stream))
    } else {
        // Full file request (no Range header)
        let stream = AsyncFileStream::open(&file_path, 0, file_size, false)
            .await
            .map_err(|e| {
                warn!("Failed to open file for streaming: {}", e);
                AppError::InternalError
            })?;

        let media_details = get_detailed_ffprobe_info(&file_path);

        let mut response = HttpResponse::Ok();
        apply_common_headers(&mut response);
        response.insert_header(("Content-Length", file_size.to_string()));

        if let Some(duration) = media_details.duration {
            response.insert_header(("Content-Duration", duration.to_string()));
            response.insert_header(("X-Content-Duration", duration.to_string()));
        }
        if let Some(ref video_codec) = media_details.video_codec {
            response.insert_header(("X-Video-Codec", video_codec.clone()));
        }
        if let Some(ref audio_codec) = media_details.audio_codec {
            response.insert_header(("X-Audio-Codec", audio_codec.clone()));
        }
        response.insert_header(("X-Has-Audio", media_details.has_audio.to_string()));

        Ok(response.streaming(stream))
    }
}

pub async fn list_media_library(query: web::Query<StreamQuery>) -> Result<HttpResponse, AppError> {
    let base_path = if let Some(ref p) = query.path {
        get_media_path(p)?
    } else {
        std::path::PathBuf::from(MEDIA_BASE)
    };

    std::fs::create_dir_all(&base_path).ok();

    let mut entries = Vec::new();

    if let Ok(read_dir) = std::fs::read_dir(&base_path) {
        for entry in read_dir.flatten() {
            let path = entry.path();
            let filename = entry.file_name().to_string_lossy().to_string();

            if is_media_file(&path) {
                let (duration, _, _, _, _, _) = get_ffprobe_info(&path);
                let relative_path = path
                    .strip_prefix(MEDIA_BASE)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();

                entries.push(PlaylistEntry {
                    id: uuid::Uuid::new_v4().to_string(),
                    title: filename,
                    path: relative_path,
                    duration,
                    thumbnail: None,
                });
            }
        }
    }

    Ok(HttpResponse::Ok().json(entries))
}

pub async fn generate_hls_playlist(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let file_path = get_media_path(&path.into_inner())?;

    if !file_path.exists() {
        return Err(AppError::NotFound("Media file not found".to_string()));
    }

    let (duration, _, _, _, _, _) = get_ffprobe_info(&file_path);
    let total_duration = duration.unwrap_or(0.0);
    let segment_duration = 10.0;
    let num_segments = (total_duration / segment_duration).ceil() as u32;
    let mut playlist = String::from("#EXTM3U\n#EXT-X-VERSION:3\n");
    playlist.push_str(&format!(
        "#EXT-X-TARGETDURATION:{}\n",
        segment_duration as u32
    ));
    playlist.push_str("#EXT-X-MEDIA-SEQUENCE:0\n");

    for i in 0..num_segments {
        let seg_duration = if i == num_segments - 1 {
            total_duration - (i as f64 * segment_duration)
        } else {
            segment_duration
        };

        playlist.push_str(&format!("#EXTINF:{:.3},\n", seg_duration));
        playlist.push_str(&format!("segment_{}.ts\n", i));
    }

    playlist.push_str("#EXT-X-ENDLIST\n");

    Ok(HttpResponse::Ok()
        .content_type("application/vnd.apple.mpegurl")
        .body(playlist))
}

pub async fn get_thumbnail(
    path: web::Path<String>,
    query: web::Query<StreamQuery>,
) -> Result<HttpResponse, AppError> {
    let file_path = get_media_path(&path.into_inner())?;

    if !file_path.exists() {
        return Err(AppError::NotFound("Media file not found".to_string()));
    }

    let timestamp = query
        .quality
        .as_ref()
        .and_then(|q| q.parse::<f64>().ok())
        .unwrap_or(1.0);

    let ffmpeg_cmd =
        crate::ffmpeg_manager::get_global_ffmpeg_path().unwrap_or_else(|| "ffmpeg".to_string());

    let output = Command::new(&ffmpeg_cmd)
        .args([
            "-ss",
            &timestamp.to_string(),
            "-i",
            file_path.to_str().unwrap_or(""),
            "-vframes",
            "1",
            "-f",
            "image2pipe",
            "-vcodec",
            "mjpeg",
            "-",
        ])
        .output();

    match output {
        Ok(out) if out.status.success() => Ok(HttpResponse::Ok()
            .content_type("image/jpeg")
            .body(out.stdout)),
        _ => Err(AppError::InternalError),
    }
}

/// Audio transcode endpoint — converts DTS/AC3/TrueHD/EAC3 audio to AAC for browser/mobile playback.
///
/// Uses ffmpeg to transcode audio on-the-fly with fragmented MP4 output (frag_keyframe+empty_moov)
/// for instant streaming start. Video stream is copied without re-encoding.
///
/// The client discovers this URL via the `transcode_url` field in `/streaming/info/{path}`.
pub async fn transcode_audio(
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let file_path = get_media_path(&path.into_inner())?;

    if !file_path.exists() {
        return Err(AppError::NotFound("Media file not found".to_string()));
    }

    let metadata = std::fs::metadata(&file_path).map_err(|_| AppError::InternalError)?;

    if metadata.len() == 0 {
        return Err(AppError::BadRequest("Empty file".to_string()));
    }

    // Verify the file actually needs transcoding
    let media_details = get_detailed_ffprobe_info(&file_path);
    let needs_transcode = media_details
        .audio_codec
        .as_ref()
        .map(|codec| crate::media_processor::needs_audio_transcode(codec))
        .unwrap_or(false);

    if !needs_transcode {
        // No transcoding needed — redirect to direct stream
        let redirect_path = file_path
            .strip_prefix(MEDIA_BASE)
            .unwrap_or(&file_path)
            .to_string_lossy();
        return Ok(HttpResponse::TemporaryRedirect()
            .insert_header(("Location", format!("/api/v1/streaming/play/{}", redirect_path)))
            .finish());
    }

    // Parse seek parameter from query string
    let seek: Option<f64> = req
        .uri()
        .query()
        .and_then(|q| {
            q.split('&')
                .find(|p| p.starts_with("seek="))
                .and_then(|p| p.strip_prefix("seek="))
                .and_then(|v| v.parse().ok())
        });

    // Start ffmpeg transcode process
    let transcoder = crate::media_processor::StreamingTranscoder::new();
    let child = transcoder
        .start_audio_transcode(
            file_path.to_str().unwrap_or(""),
            seek,
            Some("192k"),
            None,
        )
        .map_err(|e| {
            warn!("Failed to start audio transcode: {}", e);
            AppError::InternalError
        })?;

    let stream = crate::media_processor::TranscodeStream::new(child);

    let mut response = HttpResponse::Ok();
    response.insert_header(("Content-Type", "audio/mp4"));
    response.insert_header(("Accept-Ranges", "none"));
    response.insert_header(("Cache-Control", "no-cache, no-store"));
    response.insert_header(("Transfer-Encoding", "chunked"));
    response.insert_header(("Access-Control-Allow-Origin", "*"));
    response.insert_header((
        "Access-Control-Expose-Headers",
        "Content-Duration, X-Content-Duration, X-Audio-Codec, X-Original-Codec",
    ));

    if let Some(duration) = media_details.duration {
        response.insert_header(("Content-Duration", duration.to_string()));
        response.insert_header(("X-Content-Duration", duration.to_string()));
    }
    response.insert_header(("X-Audio-Codec", "aac"));
    if let Some(ref original_codec) = media_details.audio_codec {
        response.insert_header(("X-Original-Codec", original_codec.clone()));
    }

    Ok(response.streaming(stream))
}

pub async fn get_supported_formats() -> Result<HttpResponse, AppError> {
    let formats = serde_json::json!({
        "video": {
            "containers": ["mp4", "mkv", "avi", "mov", "webm", "flv", "wmv", "m4v", "ts", "m2ts"],
            "codecs": ["h264", "h265", "hevc", "vp8", "vp9", "av1", "mpeg4", "mpeg2", "theora"]
        },
        "audio": {
            "containers": ["mp3", "flac", "wav", "aac", "ogg", "m4a", "wma", "opus", "ape", "alac"],
            "codecs": ["mp3", "aac", "flac", "vorbis", "opus", "pcm", "alac", "ac3", "dts"]
        },
        "image": {
            "formats": ["jpg", "jpeg", "png", "gif", "webp", "bmp", "tiff", "svg"]
        }
    });

    Ok(HttpResponse::Ok().json(formats))
}

fn get_media_path(path: &str) -> Result<std::path::PathBuf, AppError> {
    let base = Path::new(MEDIA_BASE);
    std::fs::create_dir_all(base).ok();

    let clean_path = path.trim_start_matches('/');
    let full_path = if clean_path.is_empty() {
        base.to_path_buf()
    } else {
        base.join(clean_path)
    };

    let canonical = full_path
        .canonicalize()
        .unwrap_or_else(|_| full_path.clone());
    let base_canonical = base.canonicalize().unwrap_or_else(|_| base.to_path_buf());

    if !canonical.starts_with(&base_canonical) && canonical != full_path {
        return Err(AppError::Forbidden("Path traversal detected".to_string()));
    }

    Ok(full_path)
}

#[allow(dead_code)]
fn parse_range(range: &str, file_size: u64) -> Result<(u64, u64), AppError> {
    let range = range
        .strip_prefix("bytes=")
        .ok_or_else(|| AppError::BadRequest("Invalid range header".to_string()))?;

    // Handle multiple ranges — only use the first one
    let first_range = range.split(',').next().unwrap_or(range).trim();

    let parts: Vec<&str> = first_range.splitn(2, '-').collect();
    if parts.len() != 2 {
        return Err(AppError::BadRequest("Invalid range format".to_string()));
    }

    let start: u64 = if parts[0].is_empty() {
        // Suffix range: bytes=-500 means last 500 bytes
        if parts[1].is_empty() {
            return Err(AppError::BadRequest("Invalid range".to_string()));
        }
        let suffix_length: u64 = parts[1]
            .parse()
            .map_err(|_| AppError::BadRequest("Invalid range".to_string()))?;
        file_size.saturating_sub(suffix_length)
    } else {
        parts[0]
            .parse()
            .map_err(|_| AppError::BadRequest("Invalid range".to_string()))?
    };

    let end: u64 = if parts[1].is_empty() {
        // Open-ended range: bytes=500- means from 500 to end
        file_size - 1
    } else {
        parts[1]
            .parse()
            .map_err(|_| AppError::BadRequest("Invalid range".to_string()))?
    };

    if start >= file_size {
        return Err(AppError::BadRequest(format!(
            "Range start {} beyond file size {}",
            start, file_size
        )));
    }

    if start > end {
        return Err(AppError::BadRequest(
            "Invalid range: start > end".to_string(),
        ));
    }

    Ok((start, std::cmp::min(end, file_size - 1)))
}

fn is_media_file(path: &Path) -> bool {
    let media_extensions = [
        "mp4", "mkv", "avi", "mov", "webm", "flv", "wmv", "m4v", "ts", "m2ts", "mp3", "flac",
        "wav", "aac", "ogg", "m4a", "wma", "opus", "ape",
    ];

    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| media_extensions.contains(&e.to_lowercase().as_str()))
        .unwrap_or(false)
}

#[derive(Debug, Default)]
struct DetailedMediaInfo {
    duration: Option<f64>,
    width: Option<u32>,
    height: Option<u32>,
    video_codec: Option<String>,
    audio_codec: Option<String>,
    video_bitrate: Option<u64>,
    audio_bitrate: Option<u64>,
    frame_rate: Option<f64>,
    audio_channels: Option<u32>,
    audio_sample_rate: Option<u32>,
    audio_tracks: Vec<AudioTrackInfo>,
    has_audio: bool,
    bitrate: Option<u64>,
    container_format: Option<String>,
    aspect_ratio: Option<String>,
    color_space: Option<String>,
}

fn get_detailed_ffprobe_info(path: &Path) -> DetailedMediaInfo {
    let ffprobe_cmd =
        crate::ffmpeg_manager::get_global_ffprobe_path().unwrap_or_else(|| "ffprobe".to_string());

    let output = Command::new(&ffprobe_cmd)
        .args([
            "-v",
            "quiet",
            "-print_format",
            "json",
            "-show_format",
            "-show_streams",
            path.to_str().unwrap_or(""),
        ])
        .output();

    let mut info = DetailedMediaInfo::default();

    if let Ok(out) = output {
        if out.status.success() {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                if let Some(format) = json.get("format") {
                    info.duration = format
                        .get("duration")
                        .and_then(|d| d.as_str())
                        .and_then(|d| d.parse().ok());
                    info.bitrate = format
                        .get("bit_rate")
                        .and_then(|b| b.as_str())
                        .and_then(|b| b.parse().ok());
                    info.container_format = format
                        .get("format_name")
                        .and_then(|f| f.as_str())
                        .map(String::from);
                }

                if let Some(streams) = json.get("streams").and_then(|s| s.as_array()) {
                    for stream in streams {
                        let codec_type = stream
                            .get("codec_type")
                            .and_then(|ct| ct.as_str())
                            .unwrap_or("");

                        if codec_type == "video" && info.video_codec.is_none() {
                            info.video_codec = stream
                                .get("codec_name")
                                .and_then(|c| c.as_str())
                                .map(String::from);
                            info.width = stream
                                .get("width")
                                .and_then(|w| w.as_u64())
                                .map(|w| w as u32);
                            info.height = stream
                                .get("height")
                                .and_then(|h| h.as_u64())
                                .map(|h| h as u32);
                            info.video_bitrate = stream
                                .get("bit_rate")
                                .and_then(|b| b.as_str())
                                .and_then(|b| b.parse().ok());

                            info.aspect_ratio = stream
                                .get("display_aspect_ratio")
                                .and_then(|a| a.as_str())
                                .map(String::from);
                            info.color_space = stream
                                .get("color_space")
                                .and_then(|c| c.as_str())
                                .map(String::from);

                            if let Some(r_frame_rate) =
                                stream.get("r_frame_rate").and_then(|r| r.as_str())
                            {
                                if let Some((num, den)) = r_frame_rate.split_once('/') {
                                    if let (Ok(n), Ok(d)) =
                                        (num.parse::<f64>(), den.parse::<f64>())
                                    {
                                        if d != 0.0 {
                                            info.frame_rate = Some(n / d);
                                        }
                                    }
                                }
                            }
                        } else if codec_type == "audio" {
                            info.has_audio = true;
                            if info.audio_codec.is_none() {
                                info.audio_codec = stream
                                    .get("codec_name")
                                    .and_then(|c| c.as_str())
                                    .map(String::from);
                                info.audio_channels = stream
                                    .get("channels")
                                    .and_then(|c| c.as_u64())
                                    .map(|c| c as u32);
                                info.audio_sample_rate = stream
                                    .get("sample_rate")
                                    .and_then(|s| s.as_str())
                                    .and_then(|s| s.parse().ok());
                                info.audio_bitrate = stream
                                    .get("bit_rate")
                                    .and_then(|b| b.as_str())
                                    .and_then(|b| b.parse().ok());
                            }

                            let track_index = stream
                                .get("index")
                                .and_then(|i| i.as_u64())
                                .map(|i| i as u32)
                                .unwrap_or(0);

                            info.audio_tracks.push(AudioTrackInfo {
                                index: track_index,
                                codec: stream
                                    .get("codec_name")
                                    .and_then(|c| c.as_str())
                                    .unwrap_or("unknown")
                                    .to_string(),
                                channels: stream
                                    .get("channels")
                                    .and_then(|c| c.as_u64())
                                    .map(|c| c as u32),
                                sample_rate: stream
                                    .get("sample_rate")
                                    .and_then(|s| s.as_str())
                                    .and_then(|s| s.parse().ok()),
                                bitrate: stream
                                    .get("bit_rate")
                                    .and_then(|b| b.as_str())
                                    .and_then(|b| b.parse().ok()),
                                language: stream
                                    .get("tags")
                                    .and_then(|t| t.get("language"))
                                    .and_then(|l| l.as_str())
                                    .map(String::from),
                            });
                        }
                    }
                }
            }
        }
    }

    info
}

fn extract_exif_data(path: &Path) -> Option<ExifData> {
    let output = Command::new("exiftool")
        .args(["-json", path.to_str()?])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let json: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).ok()?;
    let data = json.first()?;

    Some(ExifData {
        camera_make: data.get("Make").and_then(|v| v.as_str()).map(String::from),
        camera_model: data
            .get("Model")
            .and_then(|v| v.as_str())
            .map(String::from),
        lens_model: data
            .get("LensModel")
            .and_then(|v| v.as_str())
            .map(String::from),
        focal_length: data
            .get("FocalLength")
            .and_then(|v| v.as_str())
            .map(String::from),
        aperture: data
            .get("Aperture")
            .and_then(|v| v.as_str())
            .map(String::from),
        shutter_speed: data
            .get("ShutterSpeed")
            .and_then(|v| v.as_str())
            .map(String::from),
        iso: data.get("ISO").and_then(|v| v.as_str()).map(String::from),
        date_taken: data
            .get("DateTimeOriginal")
            .and_then(|v| v.as_str())
            .map(String::from),
        gps_latitude: data
            .get("GPSLatitude")
            .and_then(|v| v.as_str())
            .map(String::from),
        gps_longitude: data
            .get("GPSLongitude")
            .and_then(|v| v.as_str())
            .map(String::from),
    })
}

#[allow(clippy::type_complexity)]
fn get_ffprobe_info(
    path: &Path,
) -> (
    Option<f64>,
    Option<u32>,
    Option<u32>,
    Option<String>,
    Option<String>,
    Option<u64>,
) {
    let info = get_detailed_ffprobe_info(path);
    (
        info.duration,
        info.width,
        info.height,
        info.video_codec,
        info.audio_codec,
        info.bitrate,
    )
}
