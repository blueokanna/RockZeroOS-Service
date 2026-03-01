use actix_web::{web, HttpRequest, HttpResponse};
use bytes::Bytes;
use rockzero_common::AppError;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::pin::Pin;
use std::process::Command;

use std::task::{Context, Poll};

use crate::media_processor::needs_audio_transcode;

const MEDIA_BASE: &str = "./media";

const INITIAL_CHUNK_SIZE: u64 = 512 * 1024;
const STREAMING_CHUNK_SIZE: u64 = 2 * 1024 * 1024;
const SEEK_CHUNK_SIZE: u64 = 4 * 1024 * 1024;

const DEFAULT_MAX_RANGE: u64 = 10 * 1024 * 1024;
const LARGE_FILE_MAX_RANGE: u64 = 20 * 1024 * 1024;

const HUGE_FILE_THRESHOLD: u64 = 2 * 1024 * 1024 * 1024;

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
    
    let needs_transcode = media_details.audio_codec
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
        supports_range: !needs_transcode,
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

struct ChunkedFileStream {
    reader: BufReader<File>,
    remaining: u64,
    chunk_size: u64,
}

impl ChunkedFileStream {
    fn new(mut file: File, start: u64, end: u64, _file_size: u64) -> Result<Self, std::io::Error> {
        file.seek(SeekFrom::Start(start))?;
        let remaining = end - start + 1;
        
        let chunk_size = if start > 0 {
            SEEK_CHUNK_SIZE
        } else if remaining <= INITIAL_CHUNK_SIZE {
            INITIAL_CHUNK_SIZE
        } else {
            STREAMING_CHUNK_SIZE
        };

        Ok(Self {
            reader: BufReader::with_capacity(chunk_size as usize, file),
            remaining,
            chunk_size,
        })
    }
}

impl futures::Stream for ChunkedFileStream {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }

        let to_read = std::cmp::min(self.chunk_size, self.remaining) as usize;
        let mut buffer = vec![0u8; to_read];

        match self.reader.read(&mut buffer) {
            Ok(0) => Poll::Ready(None),
            Ok(n) => {
                buffer.truncate(n);
                self.remaining -= n as u64;
                Poll::Ready(Some(Ok(Bytes::from(buffer))))
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
    
    let range_header = req.headers().get("Range").and_then(|v| v.to_str().ok());

    let media_details = get_detailed_ffprobe_info(&file_path);
    
    let effective_content_type = match extension.as_str() {
        "mkv" => "video/x-matroska".to_string(),
        "webm" => "video/webm".to_string(),
        "avi" => "video/x-msvideo".to_string(),
        "mov" => "video/quicktime".to_string(),
        "m2ts" | "ts" => "video/mp2t".to_string(),
        "mp4" | "m4v" => "video/mp4".to_string(),
        _ => content_type.clone(),
    };

    let max_range = if file_size > HUGE_FILE_THRESHOLD {
        LARGE_FILE_MAX_RANGE
    } else {
        DEFAULT_MAX_RANGE
    };

    if let Some(range) = range_header {
        let (start, mut end) = parse_range(range, file_size)?;
        
        if end >= file_size {
            end = file_size - 1;
        }

        let range_size = end - start + 1;
        if range_size > max_range {
            end = start + max_range - 1;
        }

        let file = File::open(&file_path).map_err(|_| AppError::InternalError)?;
        let stream = ChunkedFileStream::new(file, start, end, file_size)
            .map_err(|_| AppError::InternalError)?;

        let mut response = HttpResponse::PartialContent();
        response.insert_header(("Content-Type", effective_content_type));
        response.insert_header(("Content-Range", format!("bytes {}-{}/{}", start, end, file_size)));
        response.insert_header(("Content-Length", (end - start + 1).to_string()));
        response.insert_header(("Accept-Ranges", "bytes"));
        response.insert_header(("Cache-Control", "private, max-age=86400"));
        response.insert_header(("Access-Control-Allow-Origin", "*"));

        if let Some(duration) = media_details.duration {
            response.insert_header(("X-Content-Duration", duration.to_string()));
        }

        Ok(response.streaming(stream))
    } else {
        let file = File::open(&file_path).map_err(|_| AppError::InternalError)?;
        let stream = ChunkedFileStream::new(file, 0, file_size - 1, file_size)
            .map_err(|_| AppError::InternalError)?;

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

    let ffmpeg_cmd = crate::ffmpeg_manager::get_global_ffmpeg_path()
        .unwrap_or_else(|| "ffmpeg".to_string());

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

fn parse_range(range: &str, file_size: u64) -> Result<(u64, u64), AppError> {
    let range = range.strip_prefix("bytes=")
        .ok_or_else(|| AppError::BadRequest("Invalid range".to_string()))?;

    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return Err(AppError::BadRequest("Invalid range format".to_string()));
    }

    let start: u64 = if parts[0].is_empty() {
        if parts[1].is_empty() {
            return Err(AppError::BadRequest("Invalid range".to_string()));
        }
        let suffix_length: u64 = parts[1].parse()
            .map_err(|_| AppError::BadRequest("Invalid range".to_string()))?;
        file_size.saturating_sub(suffix_length)
    } else {
        parts[0].parse()
            .map_err(|_| AppError::BadRequest("Invalid range".to_string()))?
    };

    let end: u64 = if parts[1].is_empty() {
        file_size - 1
    } else {
        parts[1].parse()
            .map_err(|_| AppError::BadRequest("Invalid range".to_string()))?
    };

    if start > end || start >= file_size {
        return Err(AppError::BadRequest("Invalid range".to_string()));
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
    let ffprobe_cmd = crate::ffmpeg_manager::get_global_ffprobe_path()
        .unwrap_or_else(|| "ffprobe".to_string());

    let output = Command::new(&ffprobe_cmd)
        .args([
            "-v", "quiet",
            "-print_format", "json",
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
                    info.duration = format.get("duration")
                        .and_then(|d| d.as_str())
                        .and_then(|d| d.parse().ok());
                    info.bitrate = format.get("bit_rate")
                        .and_then(|b| b.as_str())
                        .and_then(|b| b.parse().ok());
                    info.container_format = format.get("format_name")
                        .and_then(|f| f.as_str())
                        .map(String::from);
                }

                if let Some(streams) = json.get("streams").and_then(|s| s.as_array()) {
                    for stream in streams {
                        let codec_type = stream.get("codec_type")
                            .and_then(|ct| ct.as_str())
                            .unwrap_or("");

                        if codec_type == "video" && info.video_codec.is_none() {
                            info.video_codec = stream.get("codec_name")
                                .and_then(|c| c.as_str())
                                .map(String::from);
                            info.width = stream.get("width")
                                .and_then(|w| w.as_u64())
                                .map(|w| w as u32);
                            info.height = stream.get("height")
                                .and_then(|h| h.as_u64())
                                .map(|h| h as u32);
                            info.video_bitrate = stream.get("bit_rate")
                                .and_then(|b| b.as_str())
                                .and_then(|b| b.parse().ok());
                            
                            if let Some(r_frame_rate) = stream.get("r_frame_rate")
                                .and_then(|r| r.as_str()) {
                                if let Some((num, den)) = r_frame_rate.split_once('/') {
                                    if let (Ok(n), Ok(d)) = (num.parse::<f64>(), den.parse::<f64>()) {
                                        if d != 0.0 {
                                            info.frame_rate = Some(n / d);
                                        }
                                    }
                                }
                            }
                        } else if codec_type == "audio" {
                            info.has_audio = true;
                            if info.audio_codec.is_none() {
                                info.audio_codec = stream.get("codec_name")
                                    .and_then(|c| c.as_str())
                                    .map(String::from);
                                info.audio_channels = stream.get("channels")
                                    .and_then(|c| c.as_u64())
                                    .map(|c| c as u32);
                                info.audio_sample_rate = stream.get("sample_rate")
                                    .and_then(|s| s.as_str())
                                    .and_then(|s| s.parse().ok());
                                info.audio_bitrate = stream.get("bit_rate")
                                    .and_then(|b| b.as_str())
                                    .and_then(|b| b.parse().ok());
                            }

                            let track_index = stream.get("index")
                                .and_then(|i| i.as_u64())
                                .map(|i| i as u32)
                                .unwrap_or(0);

                            info.audio_tracks.push(AudioTrackInfo {
                                index: track_index,
                                codec: stream.get("codec_name")
                                    .and_then(|c| c.as_str())
                                    .unwrap_or("unknown")
                                    .to_string(),
                                channels: stream.get("channels")
                                    .and_then(|c| c.as_u64())
                                    .map(|c| c as u32),
                                sample_rate: stream.get("sample_rate")
                                    .and_then(|s| s.as_str())
                                    .and_then(|s| s.parse().ok()),
                                bitrate: stream.get("bit_rate")
                                    .and_then(|b| b.as_str())
                                    .and_then(|b| b.parse().ok()),
                                language: stream.get("tags")
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
        camera_model: data.get("Model").and_then(|v| v.as_str()).map(String::from),
        lens_model: data.get("LensModel").and_then(|v| v.as_str()).map(String::from),
        focal_length: data.get("FocalLength").and_then(|v| v.as_str()).map(String::from),
        aperture: data.get("Aperture").and_then(|v| v.as_str()).map(String::from),
        shutter_speed: data.get("ShutterSpeed").and_then(|v| v.as_str()).map(String::from),
        iso: data.get("ISO").and_then(|v| v.as_str()).map(String::from),
        date_taken: data.get("DateTimeOriginal").and_then(|v| v.as_str()).map(String::from),
        gps_latitude: data.get("GPSLatitude").and_then(|v| v.as_str()).map(String::from),
        gps_longitude: data.get("GPSLongitude").and_then(|v| v.as_str()).map(String::from),
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
