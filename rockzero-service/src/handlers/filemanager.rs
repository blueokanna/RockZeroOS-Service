use actix_multipart::Multipart;
use actix_web::http::header::{
    ContentDisposition, ContentType, DispositionType, CONTENT_RANGE, RANGE,
};
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use bytes::Bytes;
use futures::StreamExt;
use rockzero_common::AppError;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncSeekExt};
use tracing::{info, warn};

const BASE_DIRS: &[&str] = &["/mnt", "/media", "/home", "/data", "/storage"];
const MAX_FILE_SIZE: usize = 1000 * 1024 * 1024 * 1024;
const MAX_TEXT_PREVIEW_SIZE: usize = 1024 * 1024;

/// Chunk sizes for different streaming scenarios
const INITIAL_CHUNK_SIZE: usize = 256 * 1024; // 256KB for initial probe
const STREAMING_CHUNK_SIZE: usize = 2 * 1024 * 1024; // 2MB for sequential streaming
const SEEK_CHUNK_SIZE: usize = 512 * 1024; // 512KB for seek (faster time-to-first-byte)
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
    "ino",
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
    let decoded_path = urlencoding::decode(requested_path)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| requested_path.to_string());

    tracing::info!(
        "Listing directory: {:?} (decoded: {:?})",
        requested_path,
        decoded_path
    );

    let full_path = sanitize_path(&decoded_path)?;
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

    let read_dir = fs::read_dir(&full_path).map_err(|e| {
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

        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(
                    "Skipping entry with unreadable metadata {:?}: {}",
                    entry.path(),
                    e
                );
                continue;
            }
        };

        let file_name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(os_str) => os_str.to_string_lossy().to_string(),
        };

        let relative_path = if decoded_path.is_empty() {
            file_name.clone()
        } else {
            format!("{}/{}", decoded_path, file_name)
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

    tracing::info!(
        "Listed {} files and {} directories",
        total_files,
        total_directories
    );

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
    let decoded_path = urlencoding::decode(&body.path)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| body.path.clone());
    let decoded_name = urlencoding::decode(&body.name)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| body.name.clone());

    let parent_path = sanitize_path(&decoded_path)?;
    let new_dir_path = parent_path.join(&decoded_name);

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

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct UploadProgress {
    pub filename: String,
    pub total_bytes: usize,
    pub uploaded_bytes: usize,
    pub speed_mbps: f64,
    pub percentage: f64,
    #[serde(skip)]
    pub started_at: std::time::Instant,
}

pub async fn upload_files(
    query: web::Query<ListDirectoryQuery>,
    mut payload: Multipart,
    req: actix_web::HttpRequest,
) -> Result<impl Responder, AppError> {
    tracing::info!("📤 Upload request received");
    tracing::info!(
        "  - Authorization header: {:?}",
        req.headers().get("authorization")
    );
    tracing::info!("  - Content-Type: {:?}", req.headers().get("content-type"));

    if let Err(e) = crate::middleware::verify_fido2_or_passkey(&req).await {
        tracing::error!("❌ Authentication failed: {:?}", e);
        return Err(e);
    }

    tracing::info!("✅ Authentication successful");

    let target_path = query.path.as_deref().unwrap_or("");
    tracing::info!("  - Target path: {:?}", target_path);

    let decoded_target_path = if target_path.is_empty() {
        tracing::info!("  - Using base directory (empty path)");
        String::new()
    } else {
        urlencoding::decode(target_path)
            .map(|s| s.into_owned())
            .unwrap_or_else(|_| target_path.to_string())
    };

    let full_path = match sanitize_path(&decoded_target_path) {
        Ok(path) => path,
        Err(e) => {
            tracing::error!("❌ Path sanitization failed: {:?}", e);
            return Err(e);
        }
    };

    tracing::info!("📂 Resolved upload path: {:?}", full_path);

    // 🔒 验证目标路径是否在外部存储上（非eMMC）
    #[cfg(target_os = "linux")]
    {
        let path_str = full_path.to_string_lossy();
        if let Err(e) = crate::handlers::storage::validate_external_storage_path(&path_str) {
            tracing::error!("❌ External storage validation failed: {:?}", e);
            return Err(e);
        }
        tracing::info!("✅ External storage validation passed");
    }

    if !full_path.exists() {
        tracing::info!("📁 Creating upload directory: {:?}", full_path);
        std::fs::create_dir_all(&full_path).map_err(|e| {
            tracing::error!("❌ Failed to create directory: {}", e);
            AppError::InternalError
        })?;
    }

    if !full_path.is_dir() {
        tracing::error!("❌ Target path is not a directory: {:?}", full_path);
        return Err(AppError::BadRequest(format!(
            "Target path is not a directory: {}",
            full_path.display()
        )));
    }

    let canonical_path = full_path
        .canonicalize()
        .unwrap_or_else(|_| full_path.clone());

    tracing::info!("✅ Upload target validated: {:?}", canonical_path);

    let mut uploaded_files = Vec::new();
    let start_time = std::time::Instant::now();
    let mut file_count = 0;

    while let Some(item) = payload.next().await {
        let mut field = item.map_err(|e| {
            tracing::error!("Failed to read multipart field: {}", e);
            AppError::BadRequest(format!("Invalid file data: {}", e))
        })?;

        let content_disposition = field.content_disposition();
        let filename = content_disposition
            .get_filename()
            .ok_or_else(|| {
                tracing::error!("Missing filename in multipart field");
                AppError::BadRequest("Missing filename in upload".to_string())
            })?
            .to_string();

        file_count += 1;
        tracing::info!("Processing file {}: {}", file_count, filename);

        let decoded_filename = urlencoding::decode(&filename)
            .map(|s| s.into_owned())
            .unwrap_or_else(|_| filename.clone());

        let file_path = full_path.join(&decoded_filename);

        #[cfg(target_os = "linux")]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .custom_flags(libc::O_SYNC)
                .open(&file_path)
                .map_err(|_| AppError::InternalError)?
        };

        #[cfg(not(target_os = "linux"))]
        let mut file = fs::File::create(&file_path).map_err(|_| AppError::InternalError)?;

        let mut hasher = blake3::Hasher::new();
        let mut file_size = 0usize;
        let file_start_time = std::time::Instant::now();

        while let Some(chunk) = field.next().await {
            let data = chunk.map_err(|e| {
                tracing::error!("Failed to read chunk for {}: {}", decoded_filename, e);
                fs::remove_file(&file_path).ok();
                AppError::BadRequest(format!("Failed to read file data: {}", e))
            })?;

            file_size += data.len();

            if file_size > MAX_FILE_SIZE {
                tracing::error!("File {} exceeds size limit", decoded_filename);
                fs::remove_file(&file_path).ok();
                return Err(AppError::BadRequest(format!(
                    "File {} exceeds maximum size limit of {} GB",
                    decoded_filename,
                    MAX_FILE_SIZE / (1024 * 1024 * 1024)
                )));
            }

            hasher.update(&data);
            file.write_all(&data).map_err(|e| {
                tracing::error!("Failed to write file {}: {}", decoded_filename, e);
                fs::remove_file(&file_path).ok();
                AppError::InternalError
            })?;

            if file_size.is_multiple_of(1024 * 1024) {
                let elapsed = file_start_time.elapsed().as_secs_f64();
                if elapsed > 0.0 {
                    let speed_mbps = (file_size as f64 * 8.0) / (elapsed * 1_000_000.0);
                    info!(
                        "Upload progress: {} - {:.2} MB - {:.2} Mbps",
                        decoded_filename,
                        file_size as f64 / (1024.0 * 1024.0),
                        speed_mbps
                    );
                }
            }
        }

        file.sync_all().map_err(|e| {
            tracing::error!("Failed to sync file {}: {}", decoded_filename, e);
            fs::remove_file(&file_path).ok();
            AppError::InternalError
        })?;

        drop(file);

        let checksum = hasher.finalize().to_hex().to_string();

        // 计算最终速度
        let elapsed = file_start_time.elapsed().as_secs_f64();
        let speed_mbps = if elapsed > 0.0 {
            (file_size as f64 * 8.0) / (elapsed * 1_000_000.0)
        } else {
            0.0
        };

        tracing::info!(
            "✅ File uploaded successfully: {} ({} bytes, {:.2} Mbps) to {}",
            decoded_filename,
            file_size,
            speed_mbps,
            canonical_path.display()
        );

        uploaded_files.push(serde_json::json!({
            "filename": decoded_filename,
            "size": file_size,
            "checksum": checksum,
            "path": file_path.to_string_lossy(),
            "speed_mbps": format!("{:.2}", speed_mbps),
            "duration_seconds": format!("{:.2}", elapsed),
        }));
    }

    if uploaded_files.is_empty() {
        tracing::warn!("No files were uploaded");
        return Err(AppError::BadRequest(
            "No files were uploaded. Please select files to upload.".to_string(),
        ));
    }

    let total_elapsed = start_time.elapsed().as_secs_f64();
    let total_size: usize = uploaded_files
        .iter()
        .filter_map(|f| f.get("size").and_then(|s| s.as_u64()))
        .map(|s| s as usize)
        .sum();
    let avg_speed_mbps = if total_elapsed > 0.0 {
        (total_size as f64 * 8.0) / (total_elapsed * 1_000_000.0)
    } else {
        0.0
    };

    tracing::info!(
        "✅ Upload complete: {} files, {} bytes total, {:.2} Mbps average",
        uploaded_files.len(),
        total_size,
        avg_speed_mbps
    );

    Ok(HttpResponse::Created().json(serde_json::json!({
        "message": "Files uploaded successfully",
        "files": uploaded_files,
        "total_size": total_size,
        "total_duration_seconds": format!("{:.2}", total_elapsed),
        "average_speed_mbps": format!("{:.2}", avg_speed_mbps),
    })))
}

pub async fn download_file(
    query: web::Query<ListDirectoryQuery>,
) -> Result<actix_files::NamedFile, AppError> {
    let file_path = query
        .path
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("Missing file path".to_string()))?;

    // URL-decode the path to handle UTF-8 characters
    let decoded_file_path = urlencoding::decode(file_path)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| file_path.to_string());

    let full_path = sanitize_path(&decoded_file_path)?;

    if !full_path.exists() || !full_path.is_file() {
        return Err(AppError::NotFound("File not found".to_string()));
    }

    // Get the file name and properly encode it for Content-Disposition header
    // Clone the file name before opening the file to avoid borrow issues
    let file_name = full_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("download")
        .to_string();

    Ok(actix_files::NamedFile::open(full_path)
        .map_err(|_| AppError::InternalError)?
        .set_content_disposition(actix_web::http::header::ContentDisposition {
            disposition: actix_web::http::header::DispositionType::Attachment,
            parameters: vec![actix_web::http::header::DispositionParam::FilenameExt(
                actix_web::http::header::ExtendedValue {
                    charset: actix_web::http::header::Charset::Ext("UTF-8".to_string()),
                    language_tag: None,
                    value: file_name.as_bytes().to_vec(),
                },
            )],
        }))
}

pub async fn rename_file(body: web::Json<RenameRequest>) -> Result<impl Responder, AppError> {
    // URL-decode paths to handle UTF-8 characters
    let decoded_old_path = urlencoding::decode(&body.old_path)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| body.old_path.clone());
    let decoded_new_name = urlencoding::decode(&body.new_name)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| body.new_name.clone());

    let old_path = sanitize_path(&decoded_old_path)?;
    let new_path = old_path
        .parent()
        .ok_or_else(|| AppError::BadRequest("Invalid path".to_string()))?
        .join(&decoded_new_name);

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
    // URL-decode paths to handle UTF-8 characters
    let decoded_source = urlencoding::decode(&body.source)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| body.source.clone());
    let decoded_dest = urlencoding::decode(&body.destination)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| body.destination.clone());

    let source_path = sanitize_path(&decoded_source)?;
    let dest_path = sanitize_path(&decoded_dest)?;

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
    // URL-decode paths to handle UTF-8 characters
    let decoded_source = urlencoding::decode(&body.source)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| body.source.clone());
    let decoded_dest = urlencoding::decode(&body.destination)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| body.destination.clone());

    let source_path = sanitize_path(&decoded_source)?;
    let dest_path = sanitize_path(&decoded_dest)?;

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
        // URL-decode path to handle UTF-8 characters
        let decoded_path = urlencoding::decode(path_str)
            .map(|s| s.into_owned())
            .unwrap_or_else(|_| path_str.clone());

        let path = sanitize_path(&decoded_path)?;

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

    tracing::info!("📊 Getting storage info for: {:?}", base_path);

    #[cfg(target_os = "linux")]
    {
        use std::mem::MaybeUninit;

        let path_cstr = match std::ffi::CString::new(base_path.to_string_lossy().as_bytes()) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Failed to create CString: {}", e);
                return Err(AppError::InternalError);
            }
        };

        let mut stat: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();

        unsafe {
            if libc::statvfs(path_cstr.as_ptr(), stat.as_mut_ptr()) == 0 {
                let stat = stat.assume_init();

                let block_size = stat.f_frsize as u64;
                let total_blocks = stat.f_blocks as u64;
                let free_blocks = stat.f_bfree as u64;
                let available_blocks = stat.f_bavail as u64;

                let raw_total_space = total_blocks * block_size;
                let free_space = free_blocks * block_size;
                let available_space = available_blocks * block_size;
                let used_space = raw_total_space.saturating_sub(free_space);
                let reserved_space = free_space.saturating_sub(available_space);
                let total_space = raw_total_space.saturating_sub(reserved_space);
                let usage_percentage = if total_space > 0 {
                    (used_space as f64 / total_space as f64) * 100.0
                } else {
                    0.0
                };

                tracing::info!(
                    "✅ Storage info (statvfs):\n\
                     - Path: {:?}\n\
                     - Block size: {} bytes\n\
                     - Raw total: {:.2} GB\n\
                     - Reserved (root): {:.2} GB\n\
                     - User total: {:.2} GB\n\
                     - Used space: {:.2} GB\n\
                     - Available space: {:.2} GB\n\
                     - Usage: {:.2}%",
                    base_path,
                    block_size,
                    raw_total_space as f64 / (1024.0 * 1024.0 * 1024.0),
                    reserved_space as f64 / (1024.0 * 1024.0 * 1024.0),
                    total_space as f64 / (1024.0 * 1024.0 * 1024.0),
                    used_space as f64 / (1024.0 * 1024.0 * 1024.0),
                    available_space as f64 / (1024.0 * 1024.0 * 1024.0),
                    usage_percentage
                );

                return Ok(HttpResponse::Ok().json(StorageInfo {
                    total_space,
                    used_space,
                    available_space,
                    usage_percentage,
                }));
            } else {
                let err = std::io::Error::last_os_error();
                tracing::error!("statvfs failed for {:?}: {}", base_path, err);
                return Err(AppError::InternalServerError(format!(
                    "Failed to get storage info: {}",
                    err
                )));
            }
        }
    }

    // Windows 和其他平台使用 sysinfo
    #[cfg(not(target_os = "linux"))]
    {
        use sysinfo::Disks;
        let disks = Disks::new_with_refreshed_list();

        // 查找包含 base_path 的磁盘
        for disk in disks.list() {
            let mount_point = disk.mount_point();
            if base_path.starts_with(mount_point) {
                let total_space = disk.total_space();
                let available_space = disk.available_space();
                let used_space = total_space.saturating_sub(available_space);
                let usage_percentage = if total_space > 0 {
                    (used_space as f64 / total_space as f64) * 100.0
                } else {
                    0.0
                };

                tracing::info!(
                    "✅ Storage info (sysinfo):\n\
                     - Path: {:?}\n\
                     - Mount point: {:?}\n\
                     - Total space: {} bytes ({:.2} GB)\n\
                     - Used space: {} bytes ({:.2} GB)\n\
                     - Available space: {} bytes ({:.2} GB)\n\
                     - Usage: {:.2}%",
                    base_path,
                    mount_point,
                    total_space,
                    total_space as f64 / (1024.0 * 1024.0 * 1024.0),
                    used_space,
                    used_space as f64 / (1024.0 * 1024.0 * 1024.0),
                    available_space,
                    available_space as f64 / (1024.0 * 1024.0 * 1024.0),
                    usage_percentage
                );

                return Ok(HttpResponse::Ok().json(StorageInfo {
                    total_space,
                    used_space,
                    available_space,
                    usage_percentage,
                }));
            }
        }

        tracing::error!("⚠️ Could not find disk for path: {:?}", base_path);
        Err(AppError::InternalServerError(
            "Could not find disk for path".to_string(),
        ))
    }
}

/// 获取有效的基础目录
fn get_base_directory() -> Result<PathBuf, AppError> {
    #[cfg(target_os = "windows")]
    {
        let fallback = Path::new("./storage");
        std::fs::create_dir_all(fallback).ok();
        Ok(fallback.to_path_buf())
    }

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
    // URL-decode the path first to handle UTF-8 encoded characters
    let decoded_path = urlencoding::decode(path)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| path.to_string());

    // If path is absolute and in allowed directories, use it directly
    if decoded_path.starts_with('/') {
        let abs_path = Path::new(&decoded_path);
        if is_path_allowed(abs_path) {
            if abs_path.exists() {
                return Ok(abs_path.to_path_buf());
            }
            // Path doesn't exist but is in allowed range, may be for creating new paths
            return Ok(abs_path.to_path_buf());
        }
    }

    // Get base directory
    let base = get_base_directory()?;

    let full_path = if decoded_path.is_empty() {
        base.clone()
    } else {
        // Remove leading slashes to avoid path issues
        let clean_path = decoded_path.trim_start_matches('/');
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

/// 异步流式文件读取器 - 使用 tokio 异步文件 I/O，不阻塞运行时
///
/// 相比旧版同步 StreamingFileReader 的优势：
/// - 使用 tokio::fs::File 进行真正的异步 I/O，不阻塞 worker 线程
/// - 根据 seek/sequential 场景自动选择最优 chunk 大小
/// - 支持任意大文件的流式传输，内存占用恒定
struct AsyncStreamingReader {
    file: tokio::fs::File,
    remaining: u64,
    chunk_size: usize,
    buf: Vec<u8>,
}

impl AsyncStreamingReader {
    async fn open(
        path: &Path,
        start: u64,
        length: u64,
        is_seek: bool,
    ) -> Result<Self, std::io::Error> {
        let mut file = tokio::fs::File::open(path).await?;
        file.seek(std::io::SeekFrom::Start(start)).await?;

        // 根据场景选择最优 chunk 大小：
        // - seek 操作：小 chunk = 更快的首字节时间
        // - 顺序读取：大 chunk = 更高吞吐量
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

impl futures::Stream for AsyncStreamingReader {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if this.remaining == 0 {
            return Poll::Ready(None);
        }

        let to_read = std::cmp::min(this.chunk_size as u64, this.remaining) as usize;

        // 使用 tokio 的异步读取 — 不会阻塞 runtime 线程
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

/// 生成 ETag 用于缓存和条件请求
fn generate_media_etag(metadata: &std::fs::Metadata) -> String {
    let modified = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let size = metadata.len();
    format!("\"{:x}-{:x}\"", modified, size)
}

/// 流式媒体文件传输 - 完整的 HTTP Range 支持 + 异步 I/O
///
/// 优化要点：
/// - 使用 tokio 异步文件 I/O，不阻塞 runtime
/// - 不限制 Range 大小（由播放器决定需要多少数据）
/// - 支持 ETag/条件请求减少重复传输
/// - 自适应 chunk 大小（seek vs 顺序读取）
/// - 支持 CORS 头，允许跨域播放
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

    if file_size == 0 {
        return Err(AppError::BadRequest("Empty file".to_string()));
    }

    // 优化 Content-Type 映射
    let extension = full_path
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
        "wma" => "audio/x-ms-wma".to_string(),
        "ape" => "audio/x-ape".to_string(),
        _ => mime_type,
    };

    // ETag 和条件请求支持
    let etag = generate_media_etag(&metadata);
    if let Some(if_none_match) = req
        .headers()
        .get("If-None-Match")
        .and_then(|v| v.to_str().ok())
    {
        if if_none_match.trim() == etag || if_none_match.trim() == "*" {
            return Ok(HttpResponse::NotModified().finish());
        }
    }

    let ct = effective_content_type.clone();
    let etag_clone = etag.clone();

    // Probe media info for duration and codec headers (non-blocking spawn)
    // This lets clients display duration and codec info without a separate /streaming/info call
    let probe_info = {
        let path = full_path.clone();
        tokio::task::spawn_blocking(move || get_ffprobe_info(&path))
            .await
            .unwrap_or((None, None, None, None, None, None))
    };
    let (media_duration, _, _, video_codec, audio_codec, _) = probe_info;

    // 通用头部 — 包含 duration 和 codec 信息供客户端即时使用
    let apply_headers = move |resp: &mut actix_web::HttpResponseBuilder| {
        resp.insert_header(("Content-Type", ct.as_str()));
        resp.insert_header(("Accept-Ranges", "bytes"));
        resp.insert_header(("ETag", etag_clone.as_str()));
        resp.insert_header(("Cache-Control", "private, max-age=86400, immutable"));
        resp.insert_header(("Access-Control-Allow-Origin", "*"));
        resp.insert_header((
            "Access-Control-Expose-Headers",
            "Content-Range, Accept-Ranges, Content-Length, Content-Duration, \
             X-Content-Duration, X-Video-Codec, X-Audio-Codec, X-Has-Audio, ETag",
        ));
        if let Some(dur) = media_duration {
            resp.insert_header(("Content-Duration", dur.to_string()));
            resp.insert_header(("X-Content-Duration", dur.to_string()));
        }
        if let Some(ref vc) = video_codec {
            resp.insert_header(("X-Video-Codec", vc.clone()));
        }
        if let Some(ref ac) = audio_codec {
            resp.insert_header(("X-Audio-Codec", ac.clone()));
            resp.insert_header(("X-Has-Audio", "true"));
        }
    };

    // Handle HEAD requests — return headers only, no body (for preflight checks)
    if req.method() == actix_web::http::Method::HEAD {
        let mut response = HttpResponse::Ok();
        apply_headers(&mut response);
        response.insert_header(("Content-Length", file_size.to_string()));
        return Ok(response.finish());
    }

    // Parse Range header
    let range_header = req.headers().get(RANGE).and_then(|v| v.to_str().ok());

    if let Some(range_str) = range_header {
        if let Some((start, end)) = parse_range_header(range_str, file_size) {
            // 不限制 Range 大小 — 播放器知道它需要多少数据
            // 限制 Range 会导致播放器反复重新缓冲和 seek 卡顿
            let end = std::cmp::min(end, file_size - 1);
            let length = end - start + 1;
            let is_seek = start > 0;

            let stream = AsyncStreamingReader::open(&full_path, start, length, is_seek)
                .await
                .map_err(|e| {
                    warn!("Failed to open file for streaming: {}", e);
                    AppError::InternalError
                })?;

            let mut response = HttpResponse::PartialContent();
            apply_headers(&mut response);
            response.insert_header((
                CONTENT_RANGE,
                format!("bytes {}-{}/{}", start, end, file_size),
            ));
            response.insert_header(("Content-Length", length.to_string()));

            return Ok(response.streaming(stream));
        }
    }

    // No Range — 完整文件流式传输
    let stream = AsyncStreamingReader::open(&full_path, 0, file_size, false)
        .await
        .map_err(|e| {
            warn!("Failed to open file for streaming: {}", e);
            AppError::InternalError
        })?;

    let mut response = HttpResponse::Ok();
    apply_headers(&mut response);
    response.insert_header(("Content-Length", file_size.to_string()));

    Ok(response.streaming(stream))
}

/// 图片文件服务 - 支持缓存、条件请求和流式传输大图
///
/// 对于小图片（<10MB）直接返回 body，对于大图使用流式传输。
/// 支持 ETag 和 If-None-Match 条件请求，避免重复传输。
pub async fn serve_image(
    req: HttpRequest,
    query: web::Query<ListDirectoryQuery>,
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

    // Verify it's an image
    if !mime_type.starts_with("image/") {
        return Err(AppError::BadRequest("Not an image file".to_string()));
    }

    let metadata = fs::metadata(&full_path).map_err(|_| AppError::InternalError)?;
    let file_size = metadata.len();

    // ETag 和条件请求 — 图片未变化时返回 304
    let etag = generate_media_etag(&metadata);
    if let Some(if_none_match) = req
        .headers()
        .get("If-None-Match")
        .and_then(|v| v.to_str().ok())
    {
        if if_none_match.trim() == etag || if_none_match.trim() == "*" {
            return Ok(HttpResponse::NotModified().finish());
        }
    }

    let content_type_parsed = mime_type
        .parse()
        .unwrap_or(mime_guess::mime::IMAGE_PNG);

    // 10MB 以下直接 body 返回（更高效），以上用流式
    if file_size <= 10 * 1024 * 1024 {
        let file_content = tokio::fs::read(&full_path)
            .await
            .map_err(|_| AppError::InternalError)?;

        Ok(HttpResponse::Ok()
            .insert_header(ContentType(content_type_parsed))
            .insert_header(("Content-Length", file_size.to_string()))
            .insert_header(("ETag", etag.as_str()))
            .insert_header(("Cache-Control", "public, max-age=86400, immutable"))
            .insert_header(("Access-Control-Allow-Origin", "*"))
            .insert_header(ContentDisposition {
                disposition: DispositionType::Inline,
                parameters: vec![],
            })
            .body(file_content))
    } else {
        // 大图片使用流式传输
        let stream = AsyncStreamingReader::open(&full_path, 0, file_size, false)
            .await
            .map_err(|e| {
                warn!("Failed to open image for streaming: {}", e);
                AppError::InternalError
            })?;

        Ok(HttpResponse::Ok()
            .insert_header(ContentType(content_type_parsed))
            .insert_header(("Content-Length", file_size.to_string()))
            .insert_header(("ETag", etag.as_str()))
            .insert_header(("Cache-Control", "public, max-age=86400, immutable"))
            .insert_header(("Access-Control-Allow-Origin", "*"))
            .insert_header(ContentDisposition {
                disposition: DispositionType::Inline,
                parameters: vec![],
            })
            .streaming(stream))
    }
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
            .insert_header(ContentType(
                mime_type.parse().unwrap_or(mime_guess::mime::IMAGE_PNG),
            ))
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
    use std::process::Command;

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
        .args([
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
