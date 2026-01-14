use actix_web::{web, HttpRequest, HttpResponse};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::pin::Pin;
use std::process::Command;
use std::task::{Context, Poll};

use crate::error::AppError;

const MEDIA_BASE: &str = "./media";
const SMALL_CHUNK_SIZE: u64 = 256 * 1024;
const MEDIUM_CHUNK_SIZE: u64 = 1024 * 1024;
const LARGE_CHUNK_SIZE: u64 = 2 * 1024 * 1024;
const HUGE_CHUNK_SIZE: u64 = 4 * 1024 * 1024;

// Dynamic max range based on file size
const DEFAULT_MAX_RANGE_CHUNK: u64 = 8 * 1024 * 1024;
const LARGE_FILE_MAX_RANGE: u64 = 16 * 1024 * 1024;
const HUGE_FILE_MAX_RANGE: u64 = 32 * 1024 * 1024;

// File size thresholds
const LARGE_FILE_THRESHOLD: u64 = 1024 * 1024 * 1024;
const HUGE_FILE_THRESHOLD: u64 = 10 * 1024 * 1024 * 1024;
const MASSIVE_FILE_THRESHOLD: u64 = 20 * 1024 * 1024 * 1024;

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

    let (duration, width, height, video_codec, audio_codec, bitrate) = get_ffprobe_info(&file_path);
    let info = MediaStreamInfo {
        filename: file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default(),
        content_type,
        size: metadata.len(),
        duration,
        width,
        height,
        video_codec,
        audio_codec,
        bitrate,
        supports_range: true,
    };

    Ok(HttpResponse::Ok().json(info))
}

struct ChunkedFileStream {
    reader: BufReader<File>,
    remaining: u64,
    chunk_size: u64,
    buffer: Vec<u8>,
}

impl ChunkedFileStream {
    fn new(file: File, total_size: u64) -> Self {
        let chunk_size = Self::calculate_optimal_chunk_size(total_size);
        let buffer_capacity = chunk_size as usize;

        Self {
            reader: BufReader::with_capacity(buffer_capacity, file),
            remaining: total_size,
            chunk_size,
            buffer: vec![0u8; buffer_capacity],
        }
    }

    fn with_chunk_size(file: File, total_size: u64, chunk_size: u64) -> Self {
        let buffer_capacity = chunk_size as usize;

        Self {
            reader: BufReader::with_capacity(buffer_capacity, file),
            remaining: total_size,
            chunk_size,
            buffer: vec![0u8; buffer_capacity],
        }
    }

    /// Calculate optimal chunk size based on file size for smooth streaming
    fn calculate_optimal_chunk_size(file_size: u64) -> u64 {
        if file_size >= MASSIVE_FILE_THRESHOLD {
            HUGE_CHUNK_SIZE
        } else if file_size >= HUGE_FILE_THRESHOLD {
            LARGE_CHUNK_SIZE
        } else if file_size >= LARGE_FILE_THRESHOLD {
            MEDIUM_CHUNK_SIZE
        } else {
            SMALL_CHUNK_SIZE
        }
    }
}

impl futures::Stream for ChunkedFileStream {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if this.remaining == 0 {
            return Poll::Ready(None);
        }

        let to_read = std::cmp::min(this.remaining, this.chunk_size) as usize;
        if this.buffer.len() < to_read {
            this.buffer.resize(to_read, 0);
        }

        match this.reader.read(&mut this.buffer[..to_read]) {
            Ok(0) => Poll::Ready(None),
            Ok(n) => {
                this.remaining = this.remaining.saturating_sub(n as u64);
                Poll::Ready(Some(Ok(Bytes::copy_from_slice(&this.buffer[..n]))))
            }
            Err(e) => Poll::Ready(Some(Err(e))),
        }
    }
}

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
    let content_type = mime_guess::from_path(&file_path)
        .first_or_octet_stream()
        .to_string();
    let extension = file_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();

    let is_mkv = extension == "mkv";
    let is_container_format = matches!(
        extension.as_str(),
        "mkv" | "avi" | "mov" | "m2ts" | "ts" | "webm"
    );
    let range_header = req.headers().get("Range").and_then(|v| v.to_str().ok());

    let max_range_chunk = if file_size >= MASSIVE_FILE_THRESHOLD {
        HUGE_FILE_MAX_RANGE
    } else if file_size >= HUGE_FILE_THRESHOLD {
        LARGE_FILE_MAX_RANGE
    } else if file_size >= LARGE_FILE_THRESHOLD {
        DEFAULT_MAX_RANGE_CHUNK
    } else {
        DEFAULT_MAX_RANGE_CHUNK / 2
    };

    let stream_chunk_size = ChunkedFileStream::calculate_optimal_chunk_size(file_size);
    if let Some(range) = range_header {
        let (start, mut end) = parse_range(range, file_size)?;
        let effective_max = if start == 0 {
            if file_size >= MASSIVE_FILE_THRESHOLD {
                MEDIUM_CHUNK_SIZE
            } else {
                SMALL_CHUNK_SIZE
            }
        } else {
            max_range_chunk
        };

        if end - start + 1 > effective_max && start != 0 {
            end = start + effective_max - 1;
        }

        if end >= file_size {
            end = file_size - 1;
        }

        let content_length = end - start + 1;

        let mut file = File::open(&file_path).map_err(|_| AppError::InternalError)?;
        file.seek(SeekFrom::Start(start))
            .map_err(|_| AppError::InternalError)?;

        let adaptive_chunk_size = if content_length > LARGE_CHUNK_SIZE {
            stream_chunk_size
        } else {
            std::cmp::min(stream_chunk_size, content_length)
        };

        let stream = ChunkedFileStream::with_chunk_size(file, content_length, adaptive_chunk_size);

        let mut response = HttpResponse::PartialContent();
        response.insert_header(("Content-Type", content_type));
        response.insert_header(("Content-Length", content_length.to_string()));
        response.insert_header((
            "Content-Range",
            format!("bytes {}-{}/{}", start, end, file_size),
        ));
        response.insert_header(("Accept-Ranges", "bytes"));

        // Optimized caching headers for streaming
        response.insert_header(("Cache-Control", "private, max-age=3600"));

        // CORS headers for cross-origin requests
        response.insert_header(("Access-Control-Allow-Origin", "*"));
        response.insert_header(("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS"));
        response.insert_header((
            "Access-Control-Allow-Headers",
            "Range, Accept-Ranges, Content-Range",
        ));
        response.insert_header((
            "Access-Control-Expose-Headers",
            "Content-Range, Accept-Ranges, Content-Length, Content-Duration",
        ));

        // For container formats with complex audio (MKV, AVI, etc.)
        if is_container_format {
            response.insert_header(("X-Content-Type-Options", "nosniff"));
            // Hint for duration if available
            if let Some(duration) = get_media_duration(&file_path) {
                response.insert_header(("Content-Duration", duration.to_string()));
            }
        }

        if is_mkv {
            response.insert_header((
                "X-Audio-Codec",
                get_audio_codec(&file_path).unwrap_or_default(),
            ));
        }

        Ok(response.streaming(stream))
    } else {
        let file = File::open(&file_path).map_err(|_| AppError::InternalError)?;
        let stream = ChunkedFileStream::new(file, file_size);

        let mut response = HttpResponse::Ok();
        response.insert_header(("Content-Type", content_type));
        response.insert_header(("Content-Length", file_size.to_string()));
        response.insert_header(("Accept-Ranges", "bytes"));
        response.insert_header(("Cache-Control", "private, max-age=3600"));
        response.insert_header(("Access-Control-Allow-Origin", "*"));
        response.insert_header((
            "Access-Control-Expose-Headers",
            "Content-Range, Accept-Ranges, Content-Length, Content-Duration",
        ));

        // Add duration hint for full file requests
        if let Some(duration) = get_media_duration(&file_path) {
            response.insert_header(("Content-Duration", duration.to_string()));
        }

        Ok(response.streaming(stream))
    }
}

fn get_media_duration(path: &Path) -> Option<f64> {
    let (duration, _, _, _, _, _) = get_ffprobe_info(path);
    duration
}

fn get_audio_codec(path: &Path) -> Option<String> {
    let (_, _, _, _, audio_codec, _) = get_ffprobe_info(path);
    audio_codec
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

    let output = Command::new("ffmpeg")
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
        },
        "streaming": {
            "protocols": ["http", "https", "hls", "dash"],
            "features": ["range_requests", "adaptive_bitrate", "live_streaming"]
        },
        "hardware_acceleration": get_hw_accel_info()
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

fn parse_range(range: &str, file_size: u64) -> Result<(u64, u64), AppError> {
    let range = range.trim_start_matches("bytes=");
    let parts: Vec<&str> = range.split('-').collect();

    if parts.len() != 2 {
        return Err(AppError::BadRequest("Invalid range format".to_string()));
    }

    let start: u64 = if parts[0].is_empty() {
        0
    } else {
        parts[0]
            .parse()
            .map_err(|_| AppError::BadRequest("Invalid range start".to_string()))?
    };

    let optimal_chunk = ChunkedFileStream::calculate_optimal_chunk_size(file_size);
    let end: u64 = if parts[1].is_empty() {
        std::cmp::min(start + optimal_chunk - 1, file_size - 1)
    } else {
        parts[1]
            .parse()
            .map_err(|_| AppError::BadRequest("Invalid range end".to_string()))?
    };

    if start >= file_size || end >= file_size || start > end {
        return Err(AppError::RangeNotSatisfiable(file_size));
    }

    Ok((start, end))
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
    let output = Command::new("ffprobe")
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

    if let Ok(out) = output {
        if out.status.success() {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                let duration = json
                    .get("format")
                    .and_then(|f| f.get("duration"))
                    .and_then(|d| d.as_str())
                    .and_then(|s| s.parse().ok());

                let bitrate = json
                    .get("format")
                    .and_then(|f| f.get("bit_rate"))
                    .and_then(|b| b.as_str())
                    .and_then(|s| s.parse().ok());

                let streams = json.get("streams").and_then(|s| s.as_array());

                let (mut width, mut height, mut video_codec, mut audio_codec) =
                    (None, None, None, None);

                if let Some(streams) = streams {
                    for stream in streams {
                        let codec_type = stream.get("codec_type").and_then(|t| t.as_str());
                        match codec_type {
                            Some("video") => {
                                width = stream
                                    .get("width")
                                    .and_then(|w| w.as_u64())
                                    .map(|w| w as u32);
                                height = stream
                                    .get("height")
                                    .and_then(|h| h.as_u64())
                                    .map(|h| h as u32);
                                video_codec = stream
                                    .get("codec_name")
                                    .and_then(|c| c.as_str())
                                    .map(|s| s.to_string());
                            }
                            Some("audio") => {
                                audio_codec = stream
                                    .get("codec_name")
                                    .and_then(|c| c.as_str())
                                    .map(|s| s.to_string());
                            }
                            _ => {}
                        }
                    }
                }

                return (duration, width, height, video_codec, audio_codec, bitrate);
            }
        }
    }

    (None, None, None, None, None, None)
}

fn get_hw_accel_info() -> serde_json::Value {
    let mut accel = Vec::new();
    #[cfg(target_arch = "aarch64")]
    {
        accel.push("v4l2m2m");
        if Path::new("/dev/video10").exists() {
            accel.push("rkmpp");
        }
        if Path::new("/dev/meson-vdec").exists() {
            accel.push("amlogic");
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        if Path::new("/dev/dri/renderD128").exists() {
            accel.push("vaapi");
        }
        accel.push("qsv");
        if Path::new("/dev/nvidia0").exists() {
            accel.push("nvenc");
        }
    }

    serde_json::json!(accel)
}
