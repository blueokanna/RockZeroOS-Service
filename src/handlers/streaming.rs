use actix_web::{web, HttpRequest, HttpResponse};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::pin::Pin;
use std::process::Command;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::error::AppError;
use crate::media_processor::{MediaProcessor, needs_audio_transcode, StreamingTranscoder};

const MEDIA_BASE: &str = "./media";

// Optimized chunk sizes for smooth playback
const INITIAL_CHUNK_SIZE: u64 = 512 * 1024;      // 512KB for initial request (fast start)
const STREAMING_CHUNK_SIZE: u64 = 2 * 1024 * 1024; // 2MB for streaming
const SEEK_CHUNK_SIZE: u64 = 4 * 1024 * 1024;    // 4MB for seek operations

// Max range sizes - allow larger ranges for better buffering
const DEFAULT_MAX_RANGE: u64 = 10 * 1024 * 1024;  // 10MB default
const LARGE_FILE_MAX_RANGE: u64 = 20 * 1024 * 1024; // 20MB for large files

// File size thresholds
const HUGE_FILE_THRESHOLD: u64 = 2 * 1024 * 1024 * 1024; // 2GB

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
    // Extended media info
    pub video_bitrate: Option<u64>,
    pub audio_bitrate: Option<u64>,
    pub frame_rate: Option<f64>,
    pub audio_channels: Option<u32>,
    pub audio_sample_rate: Option<u32>,
    pub audio_tracks: Option<Vec<AudioTrackInfo>>,
    pub has_audio: bool,
    // Audio transcoding info
    pub needs_audio_transcode: bool,
    pub transcode_url: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct AudioTrackInfo {
    pub index: u32,
    pub codec: String,
    pub channels: u32,
    pub sample_rate: u32,
    pub bitrate: Option<u64>,
    pub language: Option<String>,
    pub title: Option<String>,
}

/// Extended media info for file details
#[derive(Debug, Serialize)]
pub struct ExtendedMediaInfo {
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    // Video info
    pub duration: Option<f64>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub video_codec: Option<String>,
    pub video_bitrate: Option<u64>,
    pub frame_rate: Option<f64>,
    pub aspect_ratio: Option<String>,
    pub color_space: Option<String>,
    // Audio info
    pub audio_codec: Option<String>,
    pub audio_bitrate: Option<u64>,
    pub audio_channels: Option<u32>,
    pub audio_sample_rate: Option<u32>,
    pub audio_tracks: Vec<AudioTrackInfo>,
    pub has_audio: bool,
    // Overall
    pub bitrate: Option<u64>,
    pub container_format: Option<String>,
    // Image EXIF data
    pub exif: Option<ExifData>,
}

#[derive(Debug, Serialize, Default)]
pub struct ExifData {
    pub camera_make: Option<String>,
    pub camera_model: Option<String>,
    pub date_taken: Option<String>,
    pub exposure_time: Option<String>,
    pub f_number: Option<String>,
    pub iso: Option<u32>,
    pub focal_length: Option<String>,
    pub gps_latitude: Option<f64>,
    pub gps_longitude: Option<f64>,
    pub gps_altitude: Option<f64>,
    pub image_width: Option<u32>,
    pub image_height: Option<u32>,
    pub orientation: Option<u32>,
    pub software: Option<String>,
    pub color_space: Option<String>,
    pub flash: Option<String>,
    pub lens_model: Option<String>,
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

    let media_details = get_detailed_ffprobe_info(&file_path);
    
    // Check if audio needs transcoding (DTS/AC3/TrueHD)
    let needs_transcode = media_details.audio_codec
        .as_ref()
        .map(|codec| needs_audio_transcode(codec))
        .unwrap_or(false);
    
    // Generate transcode URL if needed
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
        supports_range: !needs_transcode, // Transcoded streams don't support range requests well
        video_bitrate: media_details.video_bitrate,
        audio_bitrate: media_details.audio_bitrate,
        frame_rate: media_details.frame_rate,
        audio_channels: media_details.audio_channels,
        audio_sample_rate: media_details.audio_sample_rate,
        audio_tracks: if media_details.audio_tracks.is_empty() { None } else { Some(media_details.audio_tracks) },
        has_audio: media_details.has_audio,
        needs_audio_transcode: needs_transcode,
        transcode_url,
    };

    Ok(HttpResponse::Ok().json(info))
}

/// Get extended media info including EXIF for images
pub async fn get_extended_media_info(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let file_path = get_media_path(&path.into_inner())?;
    if !file_path.exists() {
        return Err(AppError::NotFound("File not found".to_string()));
    }

    let metadata = std::fs::metadata(&file_path).map_err(|_| AppError::InternalError)?;
    let content_type = mime_guess::from_path(&file_path)
        .first_or_octet_stream()
        .to_string();
    
    let extension = file_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();

    // Check if it's an image for EXIF extraction
    let is_image = matches!(extension.as_str(), "jpg" | "jpeg" | "png" | "tiff" | "tif" | "webp" | "heic" | "heif");
    
    let exif = if is_image {
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

struct ChunkedFileStream {
    reader: BufReader<File>,
    remaining: u64,
    chunk_size: u64,
    buffer: Vec<u8>,
}

impl ChunkedFileStream {
    fn new(file: File, total_size: u64) -> Self {
        // Use larger buffer for smoother streaming
        let chunk_size = STREAMING_CHUNK_SIZE;
        let buffer_capacity = chunk_size as usize;

        Self {
            reader: BufReader::with_capacity(buffer_capacity * 2, file), // Double buffer
            remaining: total_size,
            chunk_size,
            buffer: vec![0u8; buffer_capacity],
        }
    }

    fn with_chunk_size(file: File, total_size: u64, chunk_size: u64) -> Self {
        let buffer_capacity = chunk_size as usize;

        Self {
            reader: BufReader::with_capacity(buffer_capacity * 2, file),
            remaining: total_size,
            chunk_size,
            buffer: vec![0u8; buffer_capacity],
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

    // Get detailed media info for proper audio handling
    let media_details = get_detailed_ffprobe_info(&file_path);
    
    // Determine proper content type for container formats
    let effective_content_type = match extension.as_str() {
        "mkv" => "video/x-matroska".to_string(),
        "webm" => "video/webm".to_string(),
        "avi" => "video/x-msvideo".to_string(),
        "mov" => "video/quicktime".to_string(),
        "m2ts" | "ts" => "video/mp2t".to_string(),
        "mp4" | "m4v" => "video/mp4".to_string(),
        _ => content_type.clone(),
    };

    // Determine max range based on file size
    let max_range = if file_size >= HUGE_FILE_THRESHOLD {
        LARGE_FILE_MAX_RANGE
    } else {
        DEFAULT_MAX_RANGE
    };

    if let Some(range) = range_header {
        let (start, requested_end) = parse_range(range, file_size)?;
        
        // Calculate end position - respect client's request but cap at max_range
        let mut end = if requested_end == file_size - 1 {
            // Client requested to end of file, give them a reasonable chunk
            std::cmp::min(start + max_range - 1, file_size - 1)
        } else {
            // Client specified an end, respect it but cap
            std::cmp::min(requested_end, start + max_range - 1)
        };
        
        // Ensure end doesn't exceed file size
        if end >= file_size {
            end = file_size - 1;
        }

        let content_length = end - start + 1;

        let mut file = File::open(&file_path).map_err(|_| AppError::InternalError)?;
        file.seek(SeekFrom::Start(start))
            .map_err(|_| AppError::InternalError)?;

        // Use appropriate chunk size based on request type
        let chunk_size = if start == 0 {
            INITIAL_CHUNK_SIZE // Smaller chunks for initial load (faster start)
        } else {
            SEEK_CHUNK_SIZE // Larger chunks for seek operations
        };

        let stream = ChunkedFileStream::with_chunk_size(file, content_length, chunk_size);

        let mut response = HttpResponse::PartialContent();
        response.insert_header(("Content-Type", effective_content_type.clone()));
        response.insert_header(("Content-Length", content_length.to_string()));
        response.insert_header((
            "Content-Range",
            format!("bytes {}-{}/{}", start, end, file_size),
        ));
        response.insert_header(("Accept-Ranges", "bytes"));

        // Caching headers - allow caching for better performance
        response.insert_header(("Cache-Control", "private, max-age=86400"));

        // CORS headers for cross-origin requests
        response.insert_header(("Access-Control-Allow-Origin", "*"));
        response.insert_header(("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS"));
        response.insert_header((
            "Access-Control-Allow-Headers",
            "Range, Accept-Ranges, Content-Range, Authorization",
        ));
        response.insert_header((
            "Access-Control-Expose-Headers",
            "Content-Range, Accept-Ranges, Content-Length, Content-Duration, X-Audio-Codec, X-Has-Audio, X-Audio-Tracks, X-Video-Codec",
        ));

        // Add media info headers
        if let Some(duration) = media_details.duration {
            response.insert_header(("Content-Duration", duration.to_string()));
        }
        if let Some(ref video_codec) = media_details.video_codec {
            response.insert_header(("X-Video-Codec", video_codec.clone()));
        }
        if let Some(ref audio_codec) = media_details.audio_codec {
            response.insert_header(("X-Audio-Codec", audio_codec.clone()));
        }
        response.insert_header(("X-Has-Audio", media_details.has_audio.to_string()));

        // For container formats with complex audio (MKV, AVI, etc.)
        if is_container_format || is_mkv {
            response.insert_header(("X-Content-Type-Options", "nosniff"));
            response.insert_header(("X-Audio-Tracks", media_details.audio_tracks.len().to_string()));
        }

        Ok(response.streaming(stream))
    } else {
        // No range header - return full file (not recommended for large files)
        let file = File::open(&file_path).map_err(|_| AppError::InternalError)?;
        let stream = ChunkedFileStream::new(file, file_size);

        let mut response = HttpResponse::Ok();
        response.insert_header(("Content-Type", effective_content_type));
        response.insert_header(("Content-Length", file_size.to_string()));
        response.insert_header(("Accept-Ranges", "bytes"));
        response.insert_header(("Cache-Control", "private, max-age=86400"));
        response.insert_header(("Access-Control-Allow-Origin", "*"));
        response.insert_header((
            "Access-Control-Expose-Headers",
            "Content-Range, Accept-Ranges, Content-Length, Content-Duration, X-Audio-Codec, X-Has-Audio, X-Video-Codec",
        ));

        // Add duration hint for full file requests
        if let Some(duration) = media_details.duration {
            response.insert_header(("Content-Duration", duration.to_string()));
        }
        
        // Media info headers
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

#[allow(dead_code)] fn get_media_duration(path: &Path) -> Option<f64> {
    let info = get_detailed_ffprobe_info(path);
    info.duration
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
        // Suffix range like "-500" means last 500 bytes
        let suffix_len: u64 = parts[1]
            .parse()
            .map_err(|_| AppError::BadRequest("Invalid range suffix".to_string()))?;
        file_size.saturating_sub(suffix_len)
    } else {
        parts[0]
            .parse()
            .map_err(|_| AppError::BadRequest("Invalid range start".to_string()))?
    };

    let end: u64 = if parts[1].is_empty() || parts[0].is_empty() {
        // Open-ended range like "500-" means from 500 to end
        file_size - 1
    } else {
        parts[1]
            .parse()
            .map_err(|_| AppError::BadRequest("Invalid range end".to_string()))?
    };

    // Validate range
    if start >= file_size {
        return Err(AppError::RangeNotSatisfiable(file_size));
    }

    // Clamp end to file size
    let end = std::cmp::min(end, file_size - 1);

    if start > end {
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

/// Detailed media info structure for internal use
#[derive(Debug, Default)]
struct DetailedMediaInfo {
    duration: Option<f64>,
    width: Option<u32>,
    height: Option<u32>,
    video_codec: Option<String>,
    video_bitrate: Option<u64>,
    frame_rate: Option<f64>,
    aspect_ratio: Option<String>,
    color_space: Option<String>,
    audio_codec: Option<String>,
    audio_bitrate: Option<u64>,
    audio_channels: Option<u32>,
    audio_sample_rate: Option<u32>,
    audio_tracks: Vec<AudioTrackInfo>,
    has_audio: bool,
    bitrate: Option<u64>,
    container_format: Option<String>,
}

/// Get detailed ffprobe info including all audio tracks
fn get_detailed_ffprobe_info(path: &Path) -> DetailedMediaInfo {
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

    let mut info = DetailedMediaInfo::default();

    if let Ok(out) = output {
        if out.status.success() {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                // Parse format info
                if let Some(format) = json.get("format") {
                    info.duration = format
                        .get("duration")
                        .and_then(|d| d.as_str())
                        .and_then(|s| s.parse().ok());
                    info.bitrate = format
                        .get("bit_rate")
                        .and_then(|b| b.as_str())
                        .and_then(|s| s.parse().ok());
                    info.container_format = format
                        .get("format_name")
                        .and_then(|f| f.as_str())
                        .map(|s| s.to_string());
                }

                // Parse streams
                if let Some(streams) = json.get("streams").and_then(|s| s.as_array()) {
                    let mut audio_track_index = 0u32;
                    
                    for stream in streams {
                        let codec_type = stream.get("codec_type").and_then(|t| t.as_str());
                        
                        match codec_type {
                            Some("video") => {
                                info.width = stream
                                    .get("width")
                                    .and_then(|w| w.as_u64())
                                    .map(|w| w as u32);
                                info.height = stream
                                    .get("height")
                                    .and_then(|h| h.as_u64())
                                    .map(|h| h as u32);
                                info.video_codec = stream
                                    .get("codec_name")
                                    .and_then(|c| c.as_str())
                                    .map(|s| s.to_string());
                                info.video_bitrate = stream
                                    .get("bit_rate")
                                    .and_then(|b| b.as_str())
                                    .and_then(|s| s.parse().ok());
                                
                                // Parse frame rate
                                if let Some(fps_str) = stream.get("r_frame_rate").and_then(|f| f.as_str()) {
                                    if let Some((num, den)) = fps_str.split_once('/') {
                                        if let (Ok(n), Ok(d)) = (num.parse::<f64>(), den.parse::<f64>()) {
                                            if d != 0.0 {
                                                info.frame_rate = Some(n / d);
                                            }
                                        }
                                    }
                                }
                                
                                // Aspect ratio
                                info.aspect_ratio = stream
                                    .get("display_aspect_ratio")
                                    .and_then(|a| a.as_str())
                                    .map(|s| s.to_string());
                                
                                // Color space
                                info.color_space = stream
                                    .get("color_space")
                                    .and_then(|c| c.as_str())
                                    .map(|s| s.to_string());
                            }
                            Some("audio") => {
                                info.has_audio = true;
                                
                                let codec = stream
                                    .get("codec_name")
                                    .and_then(|c| c.as_str())
                                    .unwrap_or("unknown")
                                    .to_string();
                                let channels = stream
                                    .get("channels")
                                    .and_then(|c| c.as_u64())
                                    .unwrap_or(2) as u32;
                                let sample_rate = stream
                                    .get("sample_rate")
                                    .and_then(|s| s.as_str())
                                    .and_then(|s| s.parse::<u32>().ok())
                                    .unwrap_or(44100);
                                let bitrate = stream
                                    .get("bit_rate")
                                    .and_then(|b| b.as_str())
                                    .and_then(|s| s.parse().ok());
                                
                                // Get language from tags
                                let language = stream
                                    .get("tags")
                                    .and_then(|t| t.get("language"))
                                    .and_then(|l| l.as_str())
                                    .map(|s| s.to_string());
                                
                                let title = stream
                                    .get("tags")
                                    .and_then(|t| t.get("title"))
                                    .and_then(|l| l.as_str())
                                    .map(|s| s.to_string());
                                
                                // Set first audio track as default
                                if info.audio_codec.is_none() {
                                    info.audio_codec = Some(codec.clone());
                                    info.audio_channels = Some(channels);
                                    info.audio_sample_rate = Some(sample_rate);
                                    info.audio_bitrate = bitrate;
                                }
                                
                                info.audio_tracks.push(AudioTrackInfo {
                                    index: audio_track_index,
                                    codec,
                                    channels,
                                    sample_rate,
                                    bitrate,
                                    language,
                                    title,
                                });
                                
                                audio_track_index += 1;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    info
}

/// Extract EXIF data from image files using exiftool
fn extract_exif_data(path: &Path) -> Option<ExifData> {
    let output = Command::new("exiftool")
        .args(["-json", "-n", path.to_str().unwrap_or("")])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            if let Ok(json_array) = serde_json::from_slice::<Vec<serde_json::Value>>(&out.stdout) {
                if let Some(json) = json_array.first() {
                    return Some(ExifData {
                        camera_make: json.get("Make").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        camera_model: json.get("Model").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        date_taken: json.get("DateTimeOriginal").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        exposure_time: json.get("ExposureTime").and_then(|v| {
                            if let Some(f) = v.as_f64() {
                                if f < 1.0 {
                                    Some(format!("1/{:.0}", 1.0 / f))
                                } else {
                                    Some(format!("{:.1}s", f))
                                }
                            } else {
                                v.as_str().map(|s| s.to_string())
                            }
                        }),
                        f_number: json.get("FNumber").and_then(|v| v.as_f64()).map(|f| format!("f/{:.1}", f)),
                        iso: json.get("ISO").and_then(|v| v.as_u64()).map(|i| i as u32),
                        focal_length: json.get("FocalLength").and_then(|v| v.as_f64()).map(|f| format!("{:.1}mm", f)),
                        gps_latitude: json.get("GPSLatitude").and_then(|v| v.as_f64()),
                        gps_longitude: json.get("GPSLongitude").and_then(|v| v.as_f64()),
                        gps_altitude: json.get("GPSAltitude").and_then(|v| v.as_f64()),
                        image_width: json.get("ImageWidth").and_then(|v| v.as_u64()).map(|w| w as u32),
                        image_height: json.get("ImageHeight").and_then(|v| v.as_u64()).map(|h| h as u32),
                        orientation: json.get("Orientation").and_then(|v| v.as_u64()).map(|o| o as u32),
                        software: json.get("Software").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        color_space: json.get("ColorSpace").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        flash: json.get("Flash").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        lens_model: json.get("LensModel").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    });
                }
            }
        }
    }
    
    None
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
    (info.duration, info.width, info.height, info.video_codec, info.audio_codec, info.bitrate)
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

// ============================================================================
// Audio Transcoding Stream for DTS/AC3/TrueHD
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct TranscodeQuery {
    /// Seek position in seconds
    pub seek: Option<f64>,
    /// Audio bitrate (e.g., "256k", "320k")
    pub bitrate: Option<String>,
    /// Number of audio channels (default: 2 for stereo)
    pub channels: Option<u32>,
}

/// Stream for reading from ffmpeg transcode process
struct TranscodeStream {
    child: std::process::Child,
    buffer: Vec<u8>,
}

impl TranscodeStream {
    fn new(child: std::process::Child) -> Self {
        Self {
            child,
            buffer: vec![0u8; 64 * 1024], // 64KB buffer
        }
    }
}

impl futures::Stream for TranscodeStream {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        
        if let Some(ref mut stdout) = this.child.stdout {
            match stdout.read(&mut this.buffer) {
                Ok(0) => Poll::Ready(None), // EOF
                Ok(n) => Poll::Ready(Some(Ok(Bytes::copy_from_slice(&this.buffer[..n])))),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Would block, try again later
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Some(Err(e))),
            }
        } else {
            Poll::Ready(None)
        }
    }
}

impl Drop for TranscodeStream {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

/// Transcode media with DTS/AC3/TrueHD audio to AAC for playback
/// This endpoint streams the transcoded video in real-time
pub async fn transcode_stream(
    path: web::Path<String>,
    query: web::Query<TranscodeQuery>,
    _media_processor: web::Data<Arc<MediaProcessor>>,
) -> Result<HttpResponse, AppError> {
    let file_path = get_media_path(&path.into_inner())?;
    
    if !file_path.exists() {
        return Err(AppError::NotFound("Media file not found".to_string()));
    }
    
    // Get media info to verify it needs transcoding
    let media_details = get_detailed_ffprobe_info(&file_path);
    let audio_codec = media_details.audio_codec.as_deref().unwrap_or("");
    
    if !needs_audio_transcode(audio_codec) {
        // If no transcoding needed, redirect to normal stream
        return Err(AppError::BadRequest(
            "This file does not require audio transcoding".to_string()
        ));
    }
    
    // Build ffmpeg command for transcoding
    let transcoder = StreamingTranscoder::new();
    let child = transcoder.start_audio_transcode(
        file_path.to_str().unwrap_or(""),
        query.seek,
        query.bitrate.as_deref(),
        query.channels,
    )?;
    
    let stream = TranscodeStream::new(child);
    
    // Build response with appropriate headers
    let mut response = HttpResponse::Ok();
    response.insert_header(("Content-Type", "video/mp4"));
    response.insert_header(("Transfer-Encoding", "chunked"));
    response.insert_header(("Cache-Control", "no-cache, no-store"));
    response.insert_header(("X-Content-Type-Options", "nosniff"));
    response.insert_header(("X-Transcoded", "true"));
    response.insert_header(("X-Original-Audio-Codec", audio_codec));
    response.insert_header(("X-Transcoded-Audio-Codec", "aac"));
    
    // CORS headers
    response.insert_header(("Access-Control-Allow-Origin", "*"));
    response.insert_header(("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS"));
    response.insert_header((
        "Access-Control-Expose-Headers",
        "X-Transcoded, X-Original-Audio-Codec, X-Transcoded-Audio-Codec",
    ));
    
    // Duration hint if available
    if let Some(duration) = media_details.duration {
        response.insert_header(("Content-Duration", duration.to_string()));
    }
    
    Ok(response.streaming(stream))
}

/// Check if a file needs audio transcoding
pub async fn check_transcode_needed(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let file_path = get_media_path(&path.into_inner())?;
    
    if !file_path.exists() {
        return Err(AppError::NotFound("Media file not found".to_string()));
    }
    
    let media_details = get_detailed_ffprobe_info(&file_path);
    let audio_codec = media_details.audio_codec.as_deref().unwrap_or("");
    let needs_transcode = needs_audio_transcode(audio_codec);
    
    let relative_path = file_path
        .strip_prefix(MEDIA_BASE)
        .unwrap_or(&file_path)
        .to_string_lossy()
        .to_string();
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "needs_transcode": needs_transcode,
        "audio_codec": audio_codec,
        "transcode_url": if needs_transcode {
            Some(format!("/api/v1/streaming/transcode/{}", relative_path))
        } else {
            None
        },
        "supported_codecs": ["aac", "mp3", "opus", "vorbis", "flac"],
        "unsupported_codecs": crate::media_processor::UNSUPPORTED_AUDIO_CODECS,
    })))
}
