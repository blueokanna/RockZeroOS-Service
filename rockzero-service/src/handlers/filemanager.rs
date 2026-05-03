use crate::storage_manager::{
    is_windows_drive_root, load_windows_storage_binding, persist_windows_storage_binding,
    windows_storage_binding_path, StorageConfig,
};
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
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncSeekExt};
use tracing::{info, warn};

#[cfg(not(target_os = "windows"))]
const BASE_DIRS: &[&str] = &["/mnt", "/media", "/home", "/data", "/storage"];
const MAX_FILE_SIZE: usize = 1000 * 1024 * 1024 * 1024;
const MAX_TEXT_PREVIEW_SIZE: usize = 1024 * 1024;

const INITIAL_CHUNK_SIZE: usize = 256 * 1024;
const STREAMING_CHUNK_SIZE: usize = 2 * 1024 * 1024;
const SEEK_CHUNK_SIZE: usize = 512 * 1024;
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
const MAX_TEXT_SAVE_SIZE: usize = 4 * 1024 * 1024;

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

#[derive(Debug, Serialize)]
pub struct StorageRootBindingStatus {
    pub platform: String,
    pub scoped_mode: bool,
    pub configured: bool,
    pub requires_selection: bool,
    pub selected_root: Option<String>,
    pub config_path: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StorageRootBrowseEntry {
    pub name: String,
    pub path: String,
    pub is_directory: bool,
    pub total_space: Option<u64>,
    pub available_space: Option<u64>,
    pub file_system: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StorageRootBrowseResponse {
    pub current_path: String,
    pub parent_path: Option<String>,
    pub entries: Vec<StorageRootBrowseEntry>,
}

#[derive(Debug, Deserialize)]
pub struct StorageRootBrowseQuery {
    pub path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigureStorageRootRequest {
    pub path: String,
    pub create_if_missing: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct SaveTextFileRequest {
    pub path: String,
    pub content: String,
}

pub async fn get_storage_scope_status(req: HttpRequest) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let binding = load_windows_storage_binding().map_err(|e| {
        AppError::InternalServerError(format!("Failed to read Windows storage binding: {e}"))
    })?;

    Ok(HttpResponse::Ok().json(StorageRootBindingStatus {
        platform: std::env::consts::OS.to_string(),
        scoped_mode: cfg!(target_os = "windows"),
        configured: !cfg!(target_os = "windows") || binding.is_some(),
        requires_selection: cfg!(target_os = "windows") && binding.is_none(),
        selected_root: binding
            .as_ref()
            .map(|entry| entry.selected_root.to_string_lossy().to_string()),
        config_path: if cfg!(target_os = "windows") {
            Some(windows_storage_binding_path().to_string_lossy().to_string())
        } else {
            None
        },
    }))
}

pub async fn browse_storage_scope(
    query: web::Query<StorageRootBrowseQuery>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    #[cfg(not(target_os = "windows"))]
    {
        let _ = req;
        let _ = query;
        return Err(AppError::BadRequest(
            "Storage root browsing is only required on Windows".to_string(),
        ));
    }

    #[cfg(target_os = "windows")]
    {
        let requested_path = query.path.as_deref().unwrap_or("");
        let decoded_path = decode_path_value(requested_path);

        if decoded_path.is_empty() {
            let mut entries = Vec::new();
            let disks = sysinfo::Disks::new_with_refreshed_list();

            for disk in disks.list() {
                let mount_point = disk.mount_point().to_path_buf();
                if !has_windows_drive_prefix(&mount_point) {
                    continue;
                }

                let path = mount_point.to_string_lossy().to_string();
                let disk_name = disk.name().to_string_lossy().trim().to_string();
                let display_name = if disk_name.is_empty() {
                    path.clone()
                } else {
                    format!("{} ({})", path, disk_name)
                };

                entries.push(StorageRootBrowseEntry {
                    name: display_name,
                    path,
                    is_directory: true,
                    total_space: Some(disk.total_space()),
                    available_space: Some(disk.available_space()),
                    file_system: Some(disk.file_system().to_string_lossy().to_string()),
                });
            }

            entries.sort_by_key(|entry| entry.path.clone());

            return Ok(HttpResponse::Ok().json(StorageRootBrowseResponse {
                current_path: String::new(),
                parent_path: None,
                entries,
            }));
        }

        let target_path = sanitize_windows_storage_selection_path(&decoded_path, false, true)?;
        if !target_path.exists() {
            return Err(AppError::NotFound("Directory not found".to_string()));
        }

        if !target_path.is_dir() {
            return Err(AppError::BadRequest(
                "Selected path is not a directory".to_string(),
            ));
        }

        let mut entries = Vec::new();
        for entry in fs::read_dir(&target_path).map_err(|_| AppError::InternalError)? {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    warn!(
                        "Skipping unreadable Windows storage browse entry under {}: {}",
                        target_path.display(),
                        error
                    );
                    continue;
                }
            };

            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) => {
                    warn!(
                        "Skipping Windows storage browse entry with unreadable metadata {}: {}",
                        entry.path().display(),
                        error
                    );
                    continue;
                }
            };

            if !metadata.is_dir() {
                continue;
            }

            let name = entry.file_name().to_string_lossy().to_string();
            let path = entry.path().to_string_lossy().to_string();
            entries.push(StorageRootBrowseEntry {
                name,
                path,
                is_directory: true,
                total_space: None,
                available_space: None,
                file_system: None,
            });
        }

        entries.sort_by_key(|entry| entry.name.to_lowercase());

        let parent_path = if is_windows_drive_root(&target_path) {
            Some(String::new())
        } else {
            target_path.parent().and_then(|parent| {
                let value = parent.to_string_lossy().to_string();
                if value == target_path.to_string_lossy() {
                    None
                } else {
                    Some(value)
                }
            })
        };

        Ok(HttpResponse::Ok().json(StorageRootBrowseResponse {
            current_path: target_path.to_string_lossy().to_string(),
            parent_path,
            entries,
        }))
    }
}

pub async fn configure_storage_scope(
    body: web::Json<ConfigureStorageRootRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    #[cfg(not(target_os = "windows"))]
    {
        let _ = req;
        let _ = body;
        return Err(AppError::BadRequest(
            "Storage root configuration is only required on Windows".to_string(),
        ));
    }

    #[cfg(target_os = "windows")]
    {
        let requested_path = decode_path_value(&body.path);
        let allow_missing = body.create_if_missing.unwrap_or(false);
        let target_path =
            sanitize_windows_storage_selection_path(&requested_path, allow_missing, false)?;

        if !target_path.exists() {
            fs::create_dir_all(&target_path).map_err(|e| {
                AppError::InternalServerError(format!(
                    "Failed to create Windows storage root {}: {e}",
                    target_path.display()
                ))
            })?;
        }

        if !target_path.is_dir() {
            return Err(AppError::BadRequest(
                "Selected Windows storage root must be a directory".to_string(),
            ));
        }

        let binding = persist_windows_storage_binding(&target_path).map_err(|e| {
            AppError::InternalServerError(format!("Failed to persist Windows storage root: {e}"))
        })?;

        let storage_config = StorageConfig::from_env();
        storage_config.init_directories().await.map_err(|e| {
            AppError::InternalServerError(format!(
                "Failed to initialize scoped storage directories: {e}"
            ))
        })?;

        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Windows storage root configured successfully",
            "selected_root": binding.selected_root.to_string_lossy(),
            "managed_directories": {
                "videos": storage_config.video_storage_path.to_string_lossy(),
                "temp": storage_config.temp_storage_path.to_string_lossy(),
                "cache": storage_config.hls_cache_path.to_string_lossy(),
                "logs": storage_config.log_path.to_string_lossy(),
            }
        })))
    }
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
    tracing::info!("馃摛 Upload request received");
    tracing::info!(
        "  - Authorization header present: {}",
        req.headers().contains_key("authorization")
    );
    tracing::info!("  - Content-Type: {:?}", req.headers().get("content-type"));

    if let Err(e) = crate::middleware::verify_fido2_or_passkey(&req).await {
        tracing::error!("鉂?Authentication failed: {:?}", e);
        return Err(e);
    }

    tracing::info!("鉁?Authentication successful");

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
            tracing::error!("鉂?Path sanitization failed: {:?}", e);
            return Err(e);
        }
    };

    tracing::info!("馃搨 Resolved upload path: {:?}", full_path);

    #[cfg(target_os = "linux")]
    {
        let path_str = full_path.to_string_lossy();
        if let Err(e) = crate::handlers::storage::validate_external_storage_path(&path_str) {
            tracing::error!("鉂?External storage validation failed: {:?}", e);
            return Err(e);
        }
        tracing::info!("鉁?External storage validation passed");
    }

    if !full_path.exists() {
        tracing::info!("馃搧 Creating upload directory: {:?}", full_path);
        std::fs::create_dir_all(&full_path).map_err(|e| {
            tracing::error!("鉂?Failed to create directory: {}", e);
            AppError::InternalError
        })?;
    }

    if !full_path.is_dir() {
        tracing::error!("鉂?Target path is not a directory: {:?}", full_path);
        return Err(AppError::BadRequest(format!(
            "Target path is not a directory: {}",
            full_path.display()
        )));
    }

    let canonical_path = full_path
        .canonicalize()
        .unwrap_or_else(|_| full_path.clone());

    tracing::info!("鉁?Upload target validated: {:?}", canonical_path);

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

        let elapsed = file_start_time.elapsed().as_secs_f64();
        let speed_mbps = if elapsed > 0.0 {
            (file_size as f64 * 8.0) / (elapsed * 1_000_000.0)
        } else {
            0.0
        };

        tracing::info!(
            "鉁?File uploaded successfully: {} ({} bytes, {:.2} Mbps) to {}",
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
        "鉁?Upload complete: {} files, {} bytes total, {:.2} Mbps average",
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

    let decoded_file_path = urlencoding::decode(file_path)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| file_path.to_string());

    let full_path = sanitize_path(&decoded_file_path)?;

    if !full_path.exists() || !full_path.is_file() {
        return Err(AppError::NotFound("File not found".to_string()));
    }

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

    tracing::info!("馃搳 Getting storage info for: {:?}", base_path);

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
                    "鉁?Storage info (statvfs):\n\
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

    #[cfg(not(target_os = "linux"))]
    {
        use sysinfo::Disks;
        let disks = Disks::new_with_refreshed_list();

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
                    "鉁?Storage info (sysinfo):\n\
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

        tracing::error!("鈿狅笍 Could not find disk for path: {:?}", base_path);
        Err(AppError::InternalServerError(
            "Could not find disk for path".to_string(),
        ))
    }
}

pub async fn write_text_file(
    body: web::Json<SaveTextFileRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let decoded_path = decode_path_value(&body.path);
    let full_path = sanitize_path(&decoded_path)?;

    if body.content.len() > MAX_TEXT_SAVE_SIZE {
        return Err(AppError::BadRequest(format!(
            "Text file content exceeds the {} MB editor limit",
            MAX_TEXT_SAVE_SIZE / (1024 * 1024)
        )));
    }

    if full_path.exists() && full_path.is_dir() {
        return Err(AppError::BadRequest(
            "Cannot write text content into a directory".to_string(),
        ));
    }

    if !is_text_file_supported(&full_path) {
        return Err(AppError::BadRequest(
            "Only supported text file types can be edited inline".to_string(),
        ));
    }

    let parent = full_path.parent().ok_or_else(|| {
        AppError::BadRequest("Target file must have a valid parent directory".to_string())
    })?;

    if !parent.exists() || !parent.is_dir() {
        return Err(AppError::NotFound(
            "Parent directory does not exist".to_string(),
        ));
    }

    fs::write(&full_path, body.content.as_bytes()).map_err(|e| {
        AppError::InternalServerError(format!(
            "Failed to write text file {}: {e}",
            full_path.display()
        ))
    })?;

    let base = get_base_directory()?;
    let relative_path = full_path
        .strip_prefix(&base)
        .unwrap_or(&full_path)
        .to_string_lossy()
        .trim_start_matches(['/', '\\'])
        .replace('\\', "/")
        .to_string();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Text file saved successfully",
        "path": relative_path,
        "size": body.content.len(),
    })))
}

fn get_base_directory() -> Result<PathBuf, AppError> {
    #[cfg(target_os = "windows")]
    {
        let binding = load_windows_storage_binding().map_err(|e| {
            AppError::InternalServerError(format!(
                "Failed to read Windows storage root configuration: {e}"
            ))
        })?;

        let selected_root = binding.ok_or_else(|| {
            AppError::PreconditionFailed(
                "Windows storage root is not configured. Select one disk folder before browsing files."
                    .to_string(),
            )
        })?;

        if !selected_root.selected_root.exists() || !selected_root.selected_root.is_dir() {
            return Err(AppError::PreconditionFailed(format!(
                "Configured Windows storage root is unavailable: {}",
                selected_root.selected_root.display()
            )));
        }

        Ok(selected_root.selected_root)
    }

    #[cfg(not(target_os = "windows"))]
    {
        for base_dir in BASE_DIRS {
            let path = Path::new(base_dir);
            if path.exists() && path.is_dir() {
                if std::fs::read_dir(path).is_ok() {
                    return Ok(path.to_path_buf());
                }
            }
        }

        let data_dir = Path::new("/data");
        if std::fs::create_dir_all(data_dir).is_ok() {
            return Ok(data_dir.to_path_buf());
        }

        let fallback = Path::new("./storage");
        std::fs::create_dir_all(fallback).ok();
        Ok(fallback.to_path_buf())
    }
}

fn is_path_allowed(path: &Path, base: &Path) -> bool {
    let Ok(base_canonical) = base.canonicalize() else {
        return false;
    };
    path.starts_with(&base_canonical)
}

fn sanitize_path(path: &str) -> Result<PathBuf, AppError> {
    let decoded_path = decode_path_value(path);
    let base = get_base_directory()?;
    let input_path = Path::new(&decoded_path);

    if path_contains_parent_dir(input_path) {
        return Err(AppError::Forbidden("Path traversal detected".to_string()));
    }

    let full_path = if decoded_path.is_empty() {
        base.clone()
    } else if input_path.is_absolute() {
        input_path.to_path_buf()
    } else {
        let clean_path = decoded_path.trim_start_matches(['/', '\\']);
        base.join(clean_path)
    };

    let canonical = if full_path.exists() {
        full_path
            .canonicalize()
            .map_err(|e| AppError::Forbidden(format!("Failed to resolve path: {e}")))?
    } else {
        resolve_path_from_existing_parent(&full_path, &base)?
    };

    if !is_path_allowed(&canonical, &base) {
        return Err(AppError::Forbidden("Path traversal detected".to_string()));
    }

    Ok(canonical)
}

fn resolve_path_from_existing_parent(full_path: &Path, base: &Path) -> Result<PathBuf, AppError> {
    let mut existing_parent = full_path;
    let mut suffix = Vec::new();

    while !existing_parent.exists() {
        let file_name = existing_parent
            .file_name()
            .ok_or_else(|| AppError::Forbidden("Path traversal detected".to_string()))?;
        suffix.push(file_name.to_os_string());
        existing_parent = existing_parent
            .parent()
            .ok_or_else(|| AppError::Forbidden("Path traversal detected".to_string()))?;
    }

    let resolved_parent = existing_parent
        .canonicalize()
        .map_err(|e| AppError::Forbidden(format!("Failed to resolve parent path: {e}")))?;
    let base_canonical = base
        .canonicalize()
        .map_err(|e| AppError::Forbidden(format!("Failed to resolve base path: {e}")))?;

    if !resolved_parent.starts_with(&base_canonical) {
        return Err(AppError::Forbidden("Path traversal detected".to_string()));
    }

    let mut resolved = resolved_parent;
    for component in suffix.iter().rev() {
        resolved.push(component);
    }

    Ok(resolved)
}

fn decode_path_value(path: &str) -> String {
    urlencoding::decode(path)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| path.to_string())
}

fn path_contains_parent_dir(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

fn is_text_file_supported(path: &Path) -> bool {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_lowercase())
        .unwrap_or_default();

    extension.is_empty() || ALLOWED_TEXT_EXTENSIONS.contains(&extension.as_str())
}

#[cfg(target_os = "windows")]
fn has_windows_drive_prefix(path: &Path) -> bool {
    use std::path::Prefix;

    matches!(path.components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
}

#[cfg(target_os = "windows")]
fn sanitize_windows_storage_selection_path(
    path: &str,
    allow_missing: bool,
    allow_drive_root: bool,
) -> Result<PathBuf, AppError> {
    let candidate = PathBuf::from(path);

    if !candidate.is_absolute() || !has_windows_drive_prefix(&candidate) {
        return Err(AppError::BadRequest(
            "Windows storage root must be an absolute local drive path, for example D:\\Media"
                .to_string(),
        ));
    }

    if !allow_drive_root && is_windows_drive_root(&candidate) {
        return Err(AppError::BadRequest(
            "Windows storage root must be a folder inside a drive, not the drive root".to_string(),
        ));
    }

    if path_contains_parent_dir(&candidate) {
        return Err(AppError::Forbidden("Path traversal detected".to_string()));
    }

    if candidate.exists() {
        if !candidate.is_dir() {
            return Err(AppError::BadRequest(
                "Selected Windows storage root must be a directory".to_string(),
            ));
        }

        return Ok(candidate.canonicalize().unwrap_or(candidate));
    }

    if !allow_missing {
        return Err(AppError::NotFound(
            "Selected Windows storage root does not exist".to_string(),
        ));
    }

    if let Some(parent) = candidate.parent() {
        if !parent.exists() || !parent.is_dir() {
            return Err(AppError::NotFound(
                "Parent directory for the Windows storage root does not exist".to_string(),
            ));
        }
    }

    Ok(candidate)
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

    if !is_text_file_supported(&full_path) {
        let mime = mime_guess::from_path(&full_path).first_or_octet_stream();
        if mime.type_() != mime_guess::mime::TEXT {
            return Err(AppError::BadRequest(
                "File type not supported for text preview".to_string(),
            ));
        }
    }

    let metadata = fs::metadata(&full_path).map_err(|_| AppError::InternalError)?;

    if metadata.len() > MAX_TEXT_PREVIEW_SIZE as u64 {
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

    let content = fs::read_to_string(&full_path)
        .map_err(|_| {
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

    let is_video = mime_type.starts_with("video/");
    let is_audio = mime_type.starts_with("audio/");

    if !is_video && !is_audio {
        return Err(AppError::BadRequest("Not a media file".to_string()));
    }

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

#[allow(dead_code)]
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

    let probe_info = {
        let path = full_path.clone();
        tokio::task::spawn_blocking(move || get_ffprobe_info(&path))
            .await
            .unwrap_or((None, None, None, None, None, None))
    };
    let (media_duration, _, _, video_codec, audio_codec, _) = probe_info;

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

    if req.method() == actix_web::http::Method::HEAD {
        let mut response = HttpResponse::Ok();
        apply_headers(&mut response);
        response.insert_header(("Content-Length", file_size.to_string()));
        return Ok(response.finish());
    }

    let range_header = req.headers().get(RANGE).and_then(|v| v.to_str().ok());

    if let Some(range_str) = range_header {
        if let Some((start, end)) = parse_range_header(range_str, file_size) {
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

    if !mime_type.starts_with("image/") {
        return Err(AppError::BadRequest("Not an image file".to_string()));
    }

    let metadata = fs::metadata(&full_path).map_err(|_| AppError::InternalError)?;
    let file_size = metadata.len();

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

    let content_type_parsed = mime_type.parse().unwrap_or(mime_guess::mime::IMAGE_PNG);

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

    if mime_type.starts_with("image/") {
        let file_content = fs::read(&full_path).map_err(|_| AppError::InternalError)?;

        return Ok(HttpResponse::Ok()
            .insert_header(ContentType(
                mime_type.parse().unwrap_or(mime_guess::mime::IMAGE_PNG),
            ))
            .body(file_content));
    }

    if mime_type.starts_with("video/") {
        let timestamp = query.quality.as_deref().unwrap_or("00:00:01");

        if let Some(thumbnail_data) = generate_video_thumbnail(&full_path, timestamp) {
            return Ok(HttpResponse::Ok()
                .insert_header(ContentType(mime_guess::mime::IMAGE_JPEG))
                .body(thumbnail_data));
        }
    }

    Err(AppError::BadRequest(
        "Cannot generate thumbnail for this file type".to_string(),
    ))
}

#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::auth::JwtHandler;
    use actix_web::{http::StatusCode, test, web, App};
    use rockzero_common::AppConfig;
    use serde_json::{json, Value};
    use tokio::sync::Mutex;
    use uuid::Uuid;

    static ENV_LOCK: Mutex<()> = Mutex::const_new(());
    const SCOPED_ENV_KEYS: &[&str] = &[
        "DATA_DIR",
        "EXTERNAL_STORAGE_PATH",
        "VIDEO_STORAGE_PATH",
        "TEMP_STORAGE_PATH",
        "HLS_CACHE_PATH",
        "LOG_PATH",
    ];

    fn test_app_config() -> AppConfig {
        AppConfig {
            jwt_secret: "filemanager-test-secret".to_string(),
            jwt_expiration_hours: 24,
            refresh_token_expiration_days: 7,
            ..Default::default()
        }
    }

    fn test_auth_header() -> (&'static str, String) {
        let config = test_app_config();
        let handler = JwtHandler::new(&config);
        let tokens = handler
            .generate_tokens("admin-test", "admin@example.com", "admin")
            .unwrap();
        ("Authorization", format!("Bearer {}", tokens.access_token))
    }

    struct FileManagerTestEnv {
        base_dir: PathBuf,
        data_dir: PathBuf,
        scope_root: PathBuf,
        previous_env: Vec<(String, Option<String>)>,
    }

    impl FileManagerTestEnv {
        fn new(name: &str) -> Self {
            let base_dir = std::env::temp_dir()
                .join(format!("rockzero-filemanager-{name}-{}", Uuid::new_v4()));
            let data_dir = base_dir.join("data");
            let scope_root = base_dir.join("scope-root");

            fs::create_dir_all(&data_dir).unwrap();
            fs::create_dir_all(&scope_root).unwrap();

            let previous_env = SCOPED_ENV_KEYS
                .iter()
                .map(|key| ((*key).to_string(), std::env::var(key).ok()))
                .collect::<Vec<_>>();

            std::env::set_var("DATA_DIR", &data_dir);
            for key in &SCOPED_ENV_KEYS[1..] {
                std::env::remove_var(key);
            }

            Self {
                base_dir,
                data_dir,
                scope_root,
                previous_env,
            }
        }

        fn create_dir(&self, relative: &str) -> PathBuf {
            let path = self.scope_root.join(relative);
            fs::create_dir_all(&path).unwrap();
            path
        }

        fn read_binding_root(&self) -> String {
            let raw = fs::read_to_string(
                self.data_dir
                    .join("storage")
                    .join("windows-storage-root.json"),
            )
            .unwrap();
            serde_json::from_str::<Value>(&raw).unwrap()["selected_root"]
                .as_str()
                .unwrap()
                .to_string()
        }

        #[cfg(target_os = "windows")]
        fn drive_root(&self) -> PathBuf {
            use std::path::Prefix;

            match self.scope_root.components().next() {
                Some(Component::Prefix(prefix)) => match prefix.kind() {
                    Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                        PathBuf::from(format!("{}:\\", (letter as char).to_ascii_uppercase()))
                    }
                    _ => panic!("test path is not on a local Windows drive"),
                },
                _ => panic!("test path is not on a Windows drive"),
            }
        }
    }

    impl Drop for FileManagerTestEnv {
        fn drop(&mut self) {
            for (key, value) in self.previous_env.drain(..) {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }

            let _ = fs::remove_dir_all(&self.base_dir);
        }
    }

    #[cfg(target_os = "windows")]
    #[actix_web::test]
    async fn storage_scope_status_requires_binding_before_windows_file_access() {
        let _env_lock = ENV_LOCK.lock().await;
        let _env = FileManagerTestEnv::new("status");

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(test_app_config()))
                .route("/scope/status", web::get().to(get_storage_scope_status)),
        )
        .await;

        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/scope/status")
                .insert_header(test_auth_header())
                .to_request(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);

        let payload: Value = test::read_body_json(response).await;
        assert_eq!(payload["platform"], "windows");
        assert_eq!(payload["scoped_mode"], true);
        assert_eq!(payload["configured"], false);
        assert_eq!(payload["requires_selection"], true);
        assert!(payload["selected_root"].is_null());
        assert!(payload["config_path"]
            .as_str()
            .unwrap_or_default()
            .ends_with("windows-storage-root.json"));
    }

    #[cfg(target_os = "windows")]
    #[actix_web::test]
    async fn storage_scope_configure_persists_binding_and_browse_lists_directories() {
        let _env_lock = ENV_LOCK.lock().await;
        let env = FileManagerTestEnv::new("configure-browse");
        env.create_dir("Documents");
        env.create_dir("Media");
        fs::write(env.scope_root.join("ignore.txt"), b"ignore").unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(test_app_config()))
                .route("/scope/status", web::get().to(get_storage_scope_status))
                .route("/scope/browse", web::get().to(browse_storage_scope))
                .route("/scope/configure", web::post().to(configure_storage_scope)),
        )
        .await;

        let configure_request = test::TestRequest::post()
            .uri("/scope/configure")
            .insert_header(test_auth_header())
            .set_json(json!({
                "path": env.scope_root.to_string_lossy(),
                "create_if_missing": false,
            }))
            .to_request();
        let configure_response = test::call_service(&app, configure_request).await;

        assert_eq!(configure_response.status(), StatusCode::OK);

        let configure_payload: Value = test::read_body_json(configure_response).await;
        let expected_root = env.scope_root.canonicalize().unwrap();
        assert_eq!(
            configure_payload["selected_root"],
            Value::String(expected_root.to_string_lossy().to_string())
        );
        assert_eq!(
            env.read_binding_root(),
            expected_root.to_string_lossy().to_string()
        );

        let status_response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/scope/status")
                .insert_header(test_auth_header())
                .to_request(),
        )
        .await;
        assert_eq!(status_response.status(), StatusCode::OK);

        let status_payload: Value = test::read_body_json(status_response).await;
        assert_eq!(status_payload["configured"], true);
        assert_eq!(status_payload["requires_selection"], false);
        assert_eq!(
            status_payload["selected_root"],
            Value::String(expected_root.to_string_lossy().to_string())
        );

        let browse_uri = format!(
            "/scope/browse?path={}",
            urlencoding::encode(expected_root.to_string_lossy().as_ref())
        );
        let browse_response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&browse_uri)
                .insert_header(test_auth_header())
                .to_request(),
        )
        .await;
        assert_eq!(browse_response.status(), StatusCode::OK);

        let browse_payload: Value = test::read_body_json(browse_response).await;
        let entry_names = browse_payload["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|entry| entry["name"].as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            browse_payload["current_path"],
            expected_root.to_string_lossy().to_string()
        );
        assert!(entry_names.contains(&"Documents"));
        assert!(entry_names.contains(&"Media"));
    }

    #[cfg(target_os = "windows")]
    #[actix_web::test]
    async fn storage_scope_browse_allows_drive_root_navigation() {
        let _env_lock = ENV_LOCK.lock().await;
        let env = FileManagerTestEnv::new("browse-drive-root");

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(test_app_config()))
                .route("/scope/browse", web::get().to(browse_storage_scope)),
        )
        .await;

        let drive_root = env.drive_root();
        let browse_uri = format!(
            "/scope/browse?path={}",
            urlencoding::encode(drive_root.to_string_lossy().as_ref())
        );
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&browse_uri)
                .insert_header(test_auth_header())
                .to_request(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);

        let payload: Value = test::read_body_json(response).await;
        let expected_drive_root = drive_root.canonicalize().unwrap_or(drive_root);
        assert_eq!(
            payload["current_path"],
            Value::String(expected_drive_root.to_string_lossy().to_string())
        );
        assert!(payload["entries"].is_array());
    }

    #[cfg(target_os = "windows")]
    #[actix_web::test]
    async fn storage_scope_configure_rejects_drive_root_binding() {
        let _env_lock = ENV_LOCK.lock().await;
        let env = FileManagerTestEnv::new("reject-drive-root");

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(test_app_config()))
                .route("/scope/configure", web::post().to(configure_storage_scope)),
        )
        .await;

        let drive_root = env.drive_root();
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/scope/configure")
                .insert_header(test_auth_header())
                .set_json(json!({
                    "path": drive_root.to_string_lossy(),
                    "create_if_missing": false,
                }))
                .to_request(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let payload: Value = test::read_body_json(response).await;
        assert!(payload["message"]
            .as_str()
            .unwrap_or_default()
            .contains("folder inside a drive"));
    }

    #[cfg(target_os = "windows")]
    #[actix_web::test]
    async fn text_save_writes_inside_configured_windows_scope() {
        let _env_lock = ENV_LOCK.lock().await;
        let env = FileManagerTestEnv::new("text-save");
        env.create_dir("notes");
        persist_windows_storage_binding(&env.scope_root).unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(test_app_config()))
                .route("/text/save", web::post().to(write_text_file)),
        )
        .await;

        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/text/save")
                .insert_header(test_auth_header())
                .set_json(json!({
                    "path": "notes/readme.md",
                    "content": "hello from scoped storage",
                }))
                .to_request(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);

        let payload: Value = test::read_body_json(response).await;
        let saved_path = env.scope_root.join("notes").join("readme.md");
        assert_eq!(payload["path"], "notes/readme.md");
        assert_eq!(payload["size"], 25);
        assert_eq!(
            fs::read_to_string(saved_path).unwrap(),
            "hello from scoped storage"
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[actix_web::test]
    async fn non_windows_scope_endpoints_report_not_required() {
        let app = test::init_service(
            App::new()
                .route("/scope/status", web::get().to(get_storage_scope_status))
                .route("/scope/browse", web::get().to(browse_storage_scope))
                .route("/scope/configure", web::post().to(configure_storage_scope)),
        )
        .await;

        let status_response = test::call_service(
            &app,
            test::TestRequest::get().uri("/scope/status").to_request(),
        )
        .await;
        assert_eq!(status_response.status(), StatusCode::OK);

        let status_payload: Value = test::read_body_json(status_response).await;
        assert_eq!(status_payload["scoped_mode"], false);
        assert_eq!(status_payload["configured"], true);
        assert_eq!(status_payload["requires_selection"], false);

        let browse_response = test::call_service(
            &app,
            test::TestRequest::get().uri("/scope/browse").to_request(),
        )
        .await;
        assert_eq!(browse_response.status(), StatusCode::BAD_REQUEST);
    }
}
