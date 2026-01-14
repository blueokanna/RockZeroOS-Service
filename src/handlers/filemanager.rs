use actix_multipart::Multipart;
use actix_web::http::header::{
    ContentDisposition, ContentType, DispositionType, ACCEPT_RANGES,
    CONTENT_RANGE, RANGE,
};
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use tracing::info;
use walkdir::WalkDir;
use bytes::Bytes;

use crate::error::AppError;

// 支持多个基础目录，按优先级尝试
const BASE_DIRS: &[&str] = &["/mnt", "/media", "/home", "/data", "/storage"];
const MAX_FILE_SIZE: usize = 10 * 1024 * 1024 * 1024;
const MAX_TEXT_PREVIEW_SIZE: usize = 1024 * 1024; // 1MB text preview limit
// 流式传输的chunk大小 - 128KB适合低内存设备 (1GB RAM)
const STREAM_CHUNK_SIZE: u64 = 128 * 1024;
// 单次Range请求的最大大小 - 1MB 防止OOM
const MAX_RANGE_SIZE: u64 = 1024 * 1024;
const ALLOWED_TEXT_EXTENSIONS: &[&str] = &[
    "txt",
    "md",
    "json",
    "xml",
    "yaml",
    "yml",
    "toml",
    "ini",
    "cfg",
    "conf",
    "log",
    "csv",
    "html",
    "htm",
    "css",
    "js",
    "ts",
    "jsx",
    "tsx",
    "vue",
    "py",
    "rs",
    "go",
    "java",
    "c",
    "cpp",
    "h",
    "hpp",
    "sh",
    "bash",
    "zsh",
    "sql",
    "dockerfile",
    "makefile",
    "gitignore",
    "env",
    "properties",
];

#[derive(Debug, Serialize)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub is_directory: bool,
    pub size: u64,
    pub modified: i64,
    pub permissions: String,
    pub mime_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DirectoryListing {
    pub current_path: String,
    pub parent_path: Option<String>,
    pub entries: Vec<FileEntry>,
    pub total_size: u64,
    pub total_files: usize,
    pub total_directories: usize,
}

#[derive(Debug, Deserialize)]
pub struct ListDirectoryQuery {
    pub path: Option<String>,
    pub sort_by: Option<String>,
    pub order: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateDirectoryRequest {
    pub path: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct RenameRequest {
    pub old_path: String,
    pub new_name: String,
}

#[derive(Debug, Deserialize)]
pub struct MoveRequest {
    pub source: String,
    pub destination: String,
}

#[derive(Debug, Deserialize)]
pub struct CopyRequest {
    pub source: String,
    pub destination: String,
}

#[derive(Debug, Deserialize)]
pub struct DeleteRequest {
    pub paths: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct StorageInfo {
    pub total_space: u64,
    pub used_space: u64,
    pub available_space: u64,
    pub usage_percentage: f64,
}

#[derive(Debug, Serialize)]
pub struct FilePreview {
    pub content: String,
    pub mime_type: String,
    pub size: u64,
    pub truncated: bool,
    pub encoding: String,
}

#[derive(Debug, Serialize)]
pub struct MediaInfo {
    pub filename: String,
    pub mime_type: String,
    pub size: u64,
    pub duration: Option<f64>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub video_codec: Option<String>,
    pub audio_codec: Option<String>,
    pub bitrate: Option<u64>,
    pub supports_streaming: bool,
}

#[derive(Debug, Deserialize)]
pub struct StreamQuery {
    pub path: Option<String>,
    pub quality: Option<String>,
}

pub async fn list_directory(
    query: web::Query<ListDirectoryQuery>,
) -> Result<impl Responder, AppError> {
    let requested_path = query.path.as_deref().unwrap_or("");
    tracing::info!("Listing directory: {:?}", requested_path);
    
    let full_path = sanitize_path(requested_path)?;
    tracing::info!("Full path: {:?}", full_path);

    if !full_path.exists() {
        tracing::warn!("Directory not found: {:?}", full_path);
        return Err(AppError::NotFound("Directory not found".to_string()));
    }

    if !full_path.is_dir() {
        tracing::warn!("Path is not a directory: {:?}", full_path);
        return Err(AppError::BadRequest("Path is not a directory".to_string()));
    }

    let mut entries = Vec::new();
    let mut total_size = 0u64;
    let mut total_files = 0usize;
    let mut total_directories = 0usize;

    let read_dir = fs::read_dir(&full_path)
        .map_err(|e| {
            tracing::error!("Permission denied reading directory {:?}: {}", full_path, e);
            AppError::Forbidden("Permission denied".to_string())
        })?;

    for entry in read_dir {
        // Skip entries that can't be read
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("Skipping unreadable entry: {}", e);
                continue;
            }
        };
        
        // Skip entries whose metadata can't be read (broken symlinks, permission issues, etc.)
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("Skipping entry with unreadable metadata {:?}: {}", entry.path(), e);
                continue;
            }
        };
        
        let file_name = entry.file_name().to_string_lossy().to_string();

        let relative_path = if requested_path.is_empty() {
            file_name.clone()
        } else {
            format!("{}/{}", requested_path, file_name)
        };

        let is_directory = metadata.is_dir();
        let size = if is_directory { 0 } else { metadata.len() };

        if is_directory {
            total_directories += 1;
        } else {
            total_files += 1;
            total_size += size;
        }

        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let permissions = format_permissions(&metadata);
        let mime_type = if !is_directory {
            Some(
                mime_guess::from_path(&file_name)
                    .first_or_octet_stream()
                    .to_string(),
            )
        } else {
            None
        };

        entries.push(FileEntry {
            name: file_name,
            path: relative_path,
            is_directory,
            size,
            modified,
            permissions,
            mime_type,
        });
    }
    
    tracing::info!("Listed {} files and {} directories", total_files, total_directories);

    let sort_by = query.sort_by.as_deref().unwrap_or("name");
    let order = query.order.as_deref().unwrap_or("asc");

    entries.sort_by(|a, b| {
        let cmp = match sort_by {
            "size" => a.size.cmp(&b.size),
            "modified" => a.modified.cmp(&b.modified),
            "type" => a.is_directory.cmp(&b.is_directory),
            _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        };

        if order == "desc" {
            cmp.reverse()
        } else {
            cmp
        }
    });

    let parent_path = if requested_path.is_empty() {
        None
    } else {
        Path::new(requested_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
    };

    Ok(HttpResponse::Ok().json(DirectoryListing {
        current_path: requested_path.to_string(),
        parent_path,
        entries,
        total_size,
        total_files,
        total_directories,
    }))
}

pub async fn create_directory(
    body: web::Json<CreateDirectoryRequest>,
) -> Result<impl Responder, AppError> {
    let parent_path = sanitize_path(&body.path)?;
    let new_dir_path = parent_path.join(&body.name);

    if new_dir_path.exists() {
        return Err(AppError::Conflict("Directory already exists".to_string()));
    }

    fs::create_dir_all(&new_dir_path).map_err(|_| AppError::InternalError)?;

    info!("Directory created: {:?}", new_dir_path);

    let base = get_base_directory().unwrap_or_else(|_| PathBuf::from("/"));
    Ok(HttpResponse::Created().json(serde_json::json!({
        "message": "Directory created successfully",
        "path": new_dir_path.strip_prefix(&base).unwrap_or(&new_dir_path).to_string_lossy()
    })))
}

pub async fn upload_files(
    query: web::Query<ListDirectoryQuery>,
    mut payload: Multipart,
) -> Result<impl Responder, AppError> {
    let target_path = query.path.as_deref().unwrap_or("");
    let full_path = sanitize_path(target_path)?;

    if !full_path.exists() || !full_path.is_dir() {
        return Err(AppError::BadRequest("Invalid target directory".to_string()));
    }

    let mut uploaded_files = Vec::new();

    while let Some(item) = payload.next().await {
        let mut field = item.map_err(|_| AppError::BadRequest("Invalid file data".to_string()))?;

        let content_disposition = field.content_disposition();
        let filename = content_disposition
            .get_filename()
            .ok_or_else(|| AppError::BadRequest("Missing filename".to_string()))?
            .to_string();

        let file_path = full_path.join(&filename);
        let mut file = fs::File::create(&file_path).map_err(|_| AppError::InternalError)?;

        let mut hasher = Sha256::new();
        let mut file_size = 0usize;

        while let Some(chunk) = field.next().await {
            let data = chunk.map_err(|_| AppError::InternalError)?;
            file_size += data.len();

            if file_size > MAX_FILE_SIZE {
                fs::remove_file(&file_path).ok();
                return Err(AppError::BadRequest("File size exceeds limit".to_string()));
            }

            hasher.update(&data);
            file.write_all(&data).map_err(|_| AppError::InternalError)?;
        }

        let checksum = format!("{:x}", hasher.finalize());

        info!("File uploaded: {} ({} bytes)", filename, file_size);

        uploaded_files.push(serde_json::json!({
            "filename": filename,
            "size": file_size,
            "checksum": checksum,
        }));
    }

    Ok(HttpResponse::Created().json(serde_json::json!({
        "message": "Files uploaded successfully",
        "files": uploaded_files,
    })))
}

pub async fn download_file(
    query: web::Query<ListDirectoryQuery>,
) -> Result<actix_files::NamedFile, AppError> {
    let file_path = query
        .path
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("Missing file path".to_string()))?;

    let full_path = sanitize_path(file_path)?;

    if !full_path.exists() || !full_path.is_file() {
        return Err(AppError::NotFound("File not found".to_string()));
    }

    Ok(actix_files::NamedFile::open(full_path)
        .map_err(|_| AppError::InternalError)?
        .set_content_disposition(actix_web::http::header::ContentDisposition {
            disposition: actix_web::http::header::DispositionType::Attachment,
            parameters: vec![],
        }))
}

pub async fn rename_file(body: web::Json<RenameRequest>) -> Result<impl Responder, AppError> {
    let old_path = sanitize_path(&body.old_path)?;
    let new_path = old_path
        .parent()
        .ok_or_else(|| AppError::BadRequest("Invalid path".to_string()))?
        .join(&body.new_name);

    if new_path.exists() {
        return Err(AppError::Conflict("Target already exists".to_string()));
    }

    fs::rename(&old_path, &new_path).map_err(|_| AppError::InternalError)?;

    info!("Renamed: {:?} -> {:?}", old_path, new_path);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Renamed successfully",
    })))
}

pub async fn move_files(body: web::Json<MoveRequest>) -> Result<impl Responder, AppError> {
    let source_path = sanitize_path(&body.source)?;
    let dest_path = sanitize_path(&body.destination)?;

    if !source_path.exists() {
        return Err(AppError::NotFound("Source not found".to_string()));
    }

    let target_path = if dest_path.is_dir() {
        dest_path.join(source_path.file_name().unwrap())
    } else {
        dest_path
    };

    if target_path.exists() {
        return Err(AppError::Conflict("Target already exists".to_string()));
    }

    fs::rename(&source_path, &target_path).map_err(|_| AppError::InternalError)?;

    info!("Moved: {:?} -> {:?}", source_path, target_path);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Moved successfully",
    })))
}

pub async fn copy_files(body: web::Json<CopyRequest>) -> Result<impl Responder, AppError> {
    let source_path = sanitize_path(&body.source)?;
    let dest_path = sanitize_path(&body.destination)?;

    if !source_path.exists() {
        return Err(AppError::NotFound("Source not found".to_string()));
    }

    let target_path = if dest_path.is_dir() {
        dest_path.join(source_path.file_name().unwrap())
    } else {
        dest_path
    };

    if source_path.is_dir() {
        copy_dir_recursive(&source_path, &target_path)?;
    } else {
        fs::copy(&source_path, &target_path).map_err(|_| AppError::InternalError)?;
    }

    info!("Copied: {:?} -> {:?}", source_path, target_path);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Copied successfully",
    })))
}

pub async fn delete_files(body: web::Json<DeleteRequest>) -> Result<impl Responder, AppError> {
    let mut deleted = Vec::new();

    for path_str in &body.paths {
        let path = sanitize_path(path_str)?;

        if !path.exists() {
            continue;
        }

        if path.is_dir() {
            fs::remove_dir_all(&path).map_err(|_| AppError::InternalError)?;
        } else {
            fs::remove_file(&path).map_err(|_| AppError::InternalError)?;
        }

        deleted.push(path_str.clone());
        info!("Deleted: {:?}", path);
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Deleted successfully",
        "deleted": deleted,
    })))
}

pub async fn get_storage_info() -> Result<impl Responder, AppError> {
    let base_path = get_base_directory()?;

    let mut total_size = 0u64;
    for entry in WalkDir::new(&base_path).max_depth(5).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            if let Ok(metadata) = entry.metadata() {
                total_size += metadata.len();
            }
        }
    }

    // 尝试获取实际的磁盘空间信息
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        if let Ok(output) = Command::new("df")
            .args(&["-B1", base_path.to_str().unwrap_or("/")])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(line) = stdout.lines().nth(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let total_space = parts[1].parse::<u64>().unwrap_or(0);
                        let used_space = parts[2].parse::<u64>().unwrap_or(0);
                        let available_space = parts[3].parse::<u64>().unwrap_or(0);
                        let usage_percentage = if total_space > 0 {
                            (used_space as f64 / total_space as f64) * 100.0
                        } else {
                            0.0
                        };
                        
                        return Ok(HttpResponse::Ok().json(StorageInfo {
                            total_space,
                            used_space,
                            available_space,
                            usage_percentage,
                        }));
                    }
                }
            }
        }
    }

    // 回退到估算值
    let available_space = 100 * 1024 * 1024 * 1024u64;
    let total_space = available_space + total_size;
    let usage_percentage = (total_size as f64 / total_space as f64) * 100.0;

    Ok(HttpResponse::Ok().json(StorageInfo {
        total_space,
        used_space: total_size,
        available_space,
        usage_percentage,
    }))
}

/// 获取有效的基础目录
fn get_base_directory() -> Result<PathBuf, AppError> {
    // Windows 特殊处理
    #[cfg(target_os = "windows")]
    {
        let fallback = Path::new("./storage");
        std::fs::create_dir_all(fallback).ok();
        return Ok(fallback.to_path_buf());
    }

    // Linux/Unix: 按优先级查找可用的基础目录
    #[cfg(not(target_os = "windows"))]
    {
        for base_dir in BASE_DIRS {
            let path = Path::new(base_dir);
            if path.exists() && path.is_dir() {
                // 检查是否有读取权限
                if std::fs::read_dir(path).is_ok() {
                    return Ok(path.to_path_buf());
                }
            }
        }
        
        // 如果都不存在，尝试创建 /data 目录
        let data_dir = Path::new("/data");
        if std::fs::create_dir_all(data_dir).is_ok() {
            return Ok(data_dir.to_path_buf());
        }
        
        // 最后尝试当前目录下的 storage
        let fallback = Path::new("./storage");
        std::fs::create_dir_all(fallback).ok();
        Ok(fallback.to_path_buf())
    }
}

/// 检查路径是否在允许的基础目录内
fn is_path_allowed(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    
    // 允许的基础目录
    for base in BASE_DIRS {
        if path_str.starts_with(base) {
            return true;
        }
    }
    
    // 也允许 ./storage (开发环境)
    if path_str.starts_with("./storage") || path_str.starts_with("storage") {
        return true;
    }
    
    false
}

fn sanitize_path(path: &str) -> Result<PathBuf, AppError> {
    // 如果路径是绝对路径且在允许的目录内，直接使用
    if path.starts_with('/') {
        let abs_path = Path::new(path);
        if is_path_allowed(abs_path) {
            if abs_path.exists() {
                return Ok(abs_path.to_path_buf());
            }
            // 路径不存在但在允许范围内，可能是要创建的新路径
            return Ok(abs_path.to_path_buf());
        }
    }
    
    // 获取基础目录
    let base = get_base_directory()?;

    let full_path = if path.is_empty() {
        base.clone()
    } else {
        // 移除开头的斜杠以避免路径问题
        let clean_path = path.trim_start_matches('/');
        base.join(clean_path)
    };

    // Try to canonicalize, but allow non-existent paths for creation
    let canonical = full_path
        .canonicalize()
        .unwrap_or_else(|_| full_path.clone());

    // Security check: ensure path is within allowed directories
    if !is_path_allowed(&canonical) && !is_path_allowed(&full_path) {
        return Err(AppError::Forbidden("Path traversal detected".to_string()));
    }

    Ok(canonical)
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), AppError> {
    fs::create_dir_all(dst).map_err(|_| AppError::InternalError)?;

    for entry in fs::read_dir(src).map_err(|_| AppError::InternalError)? {
        let entry = entry.map_err(|_| AppError::InternalError)?;
        let file_type = entry.file_type().map_err(|_| AppError::InternalError)?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path).map_err(|_| AppError::InternalError)?;
        }
    }

    Ok(())
}

#[cfg(unix)]
fn format_permissions(metadata: &fs::Metadata) -> String {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode();
    format!("{:o}", mode & 0o777)
}

#[cfg(not(unix))]
fn format_permissions(metadata: &fs::Metadata) -> String {
    if metadata.permissions().readonly() {
        "r--".to_string()
    } else {
        "rw-".to_string()
    }
}

// ============ File Preview API ============

pub async fn preview_text_file(
    query: web::Query<ListDirectoryQuery>,
) -> Result<impl Responder, AppError> {
    let file_path = query
        .path
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("Missing file path".to_string()))?;

    let full_path = sanitize_path(file_path)?;

    if !full_path.exists() || !full_path.is_file() {
        return Err(AppError::NotFound("File not found".to_string()));
    }

    let extension = full_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();

    if !ALLOWED_TEXT_EXTENSIONS.contains(&extension.as_str()) && !extension.is_empty() {
        let mime = mime_guess::from_path(&full_path).first_or_octet_stream();
        if mime.type_() != mime_guess::mime::TEXT {
            return Err(AppError::BadRequest(
                "File type not supported for text preview".to_string(),
            ));
        }
    }

    // Check file size
    let metadata = fs::metadata(&full_path).map_err(|_| AppError::InternalError)?;

    if metadata.len() > MAX_TEXT_PREVIEW_SIZE as u64 {
        // Read only first part
        let mut file = File::open(&full_path).map_err(|_| AppError::InternalError)?;
        let mut buffer = vec![0u8; MAX_TEXT_PREVIEW_SIZE];
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|_| AppError::InternalError)?;
        buffer.truncate(bytes_read);

        let content = String::from_utf8_lossy(&buffer).to_string();

        return Ok(HttpResponse::Ok().json(FilePreview {
            content,
            mime_type: "text/plain".to_string(),
            size: metadata.len(),
            truncated: true,
            encoding: "utf-8".to_string(),
        }));
    }

    // Read entire file
    let content = fs::read_to_string(&full_path)
        .map_err(|_| {
            // Try reading as bytes and convert
            fs::read(&full_path)
                .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
                .map_err(|_| AppError::InternalError)
        })
        .unwrap_or_else(|r| r.unwrap_or_default());

    let mime_type = mime_guess::from_path(&full_path)
        .first_or_octet_stream()
        .to_string();

    Ok(HttpResponse::Ok().json(FilePreview {
        content,
        mime_type,
        size: metadata.len(),
        truncated: false,
        encoding: "utf-8".to_string(),
    }))
}

/// Get media file information
pub async fn get_media_info(
    query: web::Query<ListDirectoryQuery>,
) -> Result<impl Responder, AppError> {
    let file_path = query
        .path
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("Missing file path".to_string()))?;

    let full_path = sanitize_path(file_path)?;

    if !full_path.exists() || !full_path.is_file() {
        return Err(AppError::NotFound("File not found".to_string()));
    }

    let metadata = fs::metadata(&full_path).map_err(|_| AppError::InternalError)?;

    let mime_type = mime_guess::from_path(&full_path)
        .first_or_octet_stream()
        .to_string();

    let filename = full_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Check if it's a media file
    let is_video = mime_type.starts_with("video/");
    let is_audio = mime_type.starts_with("audio/");

    if !is_video && !is_audio {
        return Err(AppError::BadRequest("Not a media file".to_string()));
    }

    // Try to get media info using ffprobe
    let (duration, width, height, video_codec, audio_codec, bitrate) = get_ffprobe_info(&full_path);

    Ok(HttpResponse::Ok().json(MediaInfo {
        filename,
        mime_type,
        size: metadata.len(),
        duration,
        width,
        height,
        video_codec,
        audio_codec,
        bitrate,
        supports_streaming: true,
    }))
}

/// 流式文件读取器 - 用于低内存设备的视频流传输
struct StreamingFileReader {
    file: File,
    remaining: u64,
    chunk_size: u64,
}

impl StreamingFileReader {
    fn new(file: File, total_size: u64) -> Self {
        Self {
            file,
            remaining: total_size,
            chunk_size: STREAM_CHUNK_SIZE,
        }
    }
}

impl futures::Stream for StreamingFileReader {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }

        let to_read = std::cmp::min(self.remaining, self.chunk_size) as usize;
        let mut buffer = vec![0u8; to_read];
        
        match self.file.read(&mut buffer) {
            Ok(0) => Poll::Ready(None),
            Ok(n) => {
                buffer.truncate(n);
                self.remaining = self.remaining.saturating_sub(n as u64);
                Poll::Ready(Some(Ok(Bytes::from(buffer))))
            }
            Err(e) => Poll::Ready(Some(Err(e))),
        }
    }
}

/// Stream media file with range support - 优化版本，使用流式传输
/// 避免一次性加载整个文件到内存，防止OOM
pub async fn stream_media(
    req: HttpRequest,
    query: web::Query<StreamQuery>,
) -> Result<HttpResponse, AppError> {
    let file_path = query
        .path
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("Missing file path".to_string()))?;

    let full_path = sanitize_path(file_path)?;

    if !full_path.exists() || !full_path.is_file() {
        return Err(AppError::NotFound("File not found".to_string()));
    }

    let mime_type = mime_guess::from_path(&full_path)
        .first_or_octet_stream()
        .to_string();

    // Verify it's a media file
    if !mime_type.starts_with("video/")
        && !mime_type.starts_with("audio/")
        && !mime_type.starts_with("image/")
    {
        return Err(AppError::BadRequest("Not a media file".to_string()));
    }

    let metadata = fs::metadata(&full_path).map_err(|_| AppError::InternalError)?;
    let file_size = metadata.len();

    // Parse Range header
    let range_header = req.headers().get(RANGE);

    if let Some(range_value) = range_header {
        let range_str = range_value.to_str().unwrap_or("");
        if let Some((start, mut end)) = parse_range_header(range_str, file_size) {
            // 限制单次请求的最大范围，防止内存溢出
            if end - start + 1 > MAX_RANGE_SIZE {
                end = start + MAX_RANGE_SIZE - 1;
            }
            
            let length = end - start + 1;

            let mut file = File::open(&full_path).map_err(|_| AppError::InternalError)?;
            file.seek(SeekFrom::Start(start))
                .map_err(|_| AppError::InternalError)?;

            // 使用流式传输
            let stream = StreamingFileReader::new(file, length);

            return Ok(HttpResponse::PartialContent()
                .insert_header((
                    CONTENT_RANGE,
                    format!("bytes {}-{}/{}", start, end, file_size),
                ))
                .insert_header((ACCEPT_RANGES, "bytes"))
                .insert_header(("Cache-Control", "no-cache"))
                .insert_header(ContentType(
                    mime_type
                        .parse()
                        .unwrap_or(mime_guess::mime::APPLICATION_OCTET_STREAM),
                ))
                .streaming(stream));
        }
    }

    // No range requested - 也使用流式传输
    let file = File::open(&full_path).map_err(|_| AppError::InternalError)?;
    let stream = StreamingFileReader::new(file, file_size);

    Ok(HttpResponse::Ok()
        .insert_header((ACCEPT_RANGES, "bytes"))
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("Content-Length", file_size.to_string()))
        .insert_header(ContentType(
            mime_type
                .parse()
                .unwrap_or(mime_guess::mime::APPLICATION_OCTET_STREAM),
        ))
        .streaming(stream))
}

/// Serve image file with optional resize
pub async fn serve_image(query: web::Query<ListDirectoryQuery>) -> Result<HttpResponse, AppError> {
    let file_path = query
        .path
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("Missing file path".to_string()))?;

    let full_path = sanitize_path(file_path)?;

    if !full_path.exists() || !full_path.is_file() {
        return Err(AppError::NotFound("File not found".to_string()));
    }

    let mime_type = mime_guess::from_path(&full_path)
        .first_or_octet_stream()
        .to_string();

    // Verify it's an image
    if !mime_type.starts_with("image/") {
        return Err(AppError::BadRequest("Not an image file".to_string()));
    }

    let file_content = fs::read(&full_path).map_err(|_| AppError::InternalError)?;

    Ok(HttpResponse::Ok()
        .insert_header(ContentType(mime_type.parse().unwrap_or(mime_guess::mime::IMAGE_PNG)))
        .insert_header(ContentDisposition {
            disposition: DispositionType::Inline,
            parameters: vec![],
        })
        .body(file_content))
}

/// Generate thumbnail for media file
pub async fn get_thumbnail(query: web::Query<StreamQuery>) -> Result<HttpResponse, AppError> {
    let file_path = query
        .path
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("Missing file path".to_string()))?;

    let full_path = sanitize_path(file_path)?;

    if !full_path.exists() || !full_path.is_file() {
        return Err(AppError::NotFound("File not found".to_string()));
    }

    let mime_type = mime_guess::from_path(&full_path)
        .first_or_octet_stream()
        .to_string();

    // For images, return the image itself (could add resize later)
    if mime_type.starts_with("image/") {
        let file_content = fs::read(&full_path).map_err(|_| AppError::InternalError)?;

        return Ok(HttpResponse::Ok()
            .insert_header(ContentType(mime_type.parse().unwrap_or(mime_guess::mime::IMAGE_PNG)))
            .body(file_content));
    }

    // For videos, try to generate thumbnail using ffmpeg
    if mime_type.starts_with("video/") {
        let timestamp = query.quality.as_deref().unwrap_or("00:00:01");

        if let Some(thumbnail_data) = generate_video_thumbnail(&full_path, timestamp) {
            return Ok(HttpResponse::Ok()
                .insert_header(ContentType(mime_guess::mime::IMAGE_JPEG))
                .body(thumbnail_data));
        }
    }

    // Return placeholder or error
    Err(AppError::BadRequest(
        "Cannot generate thumbnail for this file type".to_string(),
    ))
}

// ============ Helper Functions ============

fn parse_range_header(range: &str, file_size: u64) -> Option<(u64, u64)> {
    if !range.starts_with("bytes=") {
        return None;
    }

    let range = &range[6..];
    let parts: Vec<&str> = range.split('-').collect();

    if parts.len() != 2 {
        return None;
    }

    let start: u64 = parts[0].parse().ok()?;
    let end: u64 = if parts[1].is_empty() {
        file_size - 1
    } else {
        parts[1].parse().ok()?
    };

    if start > end || end >= file_size {
        return None;
    }

    Some((start, end))
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
    use std::process::Command;

    let output = Command::new("ffprobe")
        .args(&[
            "-v",
            "quiet",
            "-print_format",
            "json",
            "-show_format",
            "-show_streams",
            path.to_str().unwrap_or(""),
        ])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            if let Ok(json_str) = String::from_utf8(output.stdout) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_str) {
                    let duration = json["format"]["duration"]
                        .as_str()
                        .and_then(|s| s.parse::<f64>().ok());

                    let bitrate = json["format"]["bit_rate"]
                        .as_str()
                        .and_then(|s| s.parse::<u64>().ok());

                    let mut width = None;
                    let mut height = None;
                    let mut video_codec = None;
                    let mut audio_codec = None;

                    if let Some(streams) = json["streams"].as_array() {
                        for stream in streams {
                            let codec_type = stream["codec_type"].as_str().unwrap_or("");
                            if codec_type == "video" && width.is_none() {
                                width = stream["width"].as_u64().map(|w| w as u32);
                                height = stream["height"].as_u64().map(|h| h as u32);
                                video_codec = stream["codec_name"].as_str().map(|s| s.to_string());
                            } else if codec_type == "audio" && audio_codec.is_none() {
                                audio_codec = stream["codec_name"].as_str().map(|s| s.to_string());
                            }
                        }
                    }

                    return (duration, width, height, video_codec, audio_codec, bitrate);
                }
            }
        }
    }

    (None, None, None, None, None, None)
}

fn generate_video_thumbnail(path: &Path, timestamp: &str) -> Option<Vec<u8>> {
    use std::process::Command;

    // Create temp file for thumbnail
    let temp_path = std::env::temp_dir().join(format!("thumb_{}.jpg", uuid::Uuid::new_v4()));

    let output = Command::new("ffmpeg")
        .args(&[
            "-ss",
            timestamp,
            "-i",
            path.to_str()?,
            "-vframes",
            "1",
            "-vf",
            "scale=320:-1",
            "-y",
            temp_path.to_str()?,
        ])
        .output()
        .ok()?;

    if output.status.success() {
        let data = fs::read(&temp_path).ok();
        fs::remove_file(&temp_path).ok();
        return data;
    }

    None
}
