use actix_multipart::Multipart;
use actix_web::{web, HttpResponse, Responder};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::info;
use walkdir::WalkDir;

use crate::error::AppError;

const BASE_DIR: &str = "/home";
const MAX_FILE_SIZE: usize = 10 * 1024 * 1024 * 1024;

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

pub async fn list_directory(
    query: web::Query<ListDirectoryQuery>,
) -> Result<impl Responder, AppError> {
    let requested_path = query.path.as_deref().unwrap_or("");
    let full_path = sanitize_path(requested_path)?;

    if !full_path.exists() {
        return Err(AppError::NotFound("Directory not found".to_string()));
    }

    if !full_path.is_dir() {
        return Err(AppError::BadRequest("Path is not a directory".to_string()));
    }

    let mut entries = Vec::new();
    let mut total_size = 0u64;
    let mut total_files = 0usize;
    let mut total_directories = 0usize;

    let read_dir = fs::read_dir(&full_path)
        .map_err(|_| AppError::Forbidden("Permission denied".to_string()))?;

    for entry in read_dir {
        let entry = entry.map_err(|_| AppError::InternalError)?;
        let metadata = entry.metadata().map_err(|_| AppError::InternalError)?;
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

        let modified = metadata.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let permissions = format_permissions(&metadata);
        let mime_type = if !is_directory {
            Some(mime_guess::from_path(&file_name).first_or_octet_stream().to_string())
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

    fs::create_dir_all(&new_dir_path)
        .map_err(|_| AppError::InternalError)?;

    info!("Directory created: {:?}", new_dir_path);

    Ok(HttpResponse::Created().json(serde_json::json!({
        "message": "Directory created successfully",
        "path": new_dir_path.strip_prefix(BASE_DIR).unwrap_or(&new_dir_path).to_string_lossy()
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
        let mut file = fs::File::create(&file_path)
            .map_err(|_| AppError::InternalError)?;

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
    let file_path = query.path.as_deref()
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

pub async fn rename_file(
    body: web::Json<RenameRequest>,
) -> Result<impl Responder, AppError> {
    let old_path = sanitize_path(&body.old_path)?;
    let new_path = old_path.parent()
        .ok_or_else(|| AppError::BadRequest("Invalid path".to_string()))?
        .join(&body.new_name);

    if new_path.exists() {
        return Err(AppError::Conflict("Target already exists".to_string()));
    }

    fs::rename(&old_path, &new_path)
        .map_err(|_| AppError::InternalError)?;

    info!("Renamed: {:?} -> {:?}", old_path, new_path);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Renamed successfully",
    })))
}

pub async fn move_files(
    body: web::Json<MoveRequest>,
) -> Result<impl Responder, AppError> {
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

    fs::rename(&source_path, &target_path)
        .map_err(|_| AppError::InternalError)?;

    info!("Moved: {:?} -> {:?}", source_path, target_path);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Moved successfully",
    })))
}

pub async fn copy_files(
    body: web::Json<CopyRequest>,
) -> Result<impl Responder, AppError> {
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
        fs::copy(&source_path, &target_path)
            .map_err(|_| AppError::InternalError)?;
    }

    info!("Copied: {:?} -> {:?}", source_path, target_path);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Copied successfully",
    })))
}

pub async fn delete_files(
    body: web::Json<DeleteRequest>,
) -> Result<impl Responder, AppError> {
    let mut deleted = Vec::new();

    for path_str in &body.paths {
        let path = sanitize_path(path_str)?;

        if !path.exists() {
            continue;
        }

        if path.is_dir() {
            fs::remove_dir_all(&path)
                .map_err(|_| AppError::InternalError)?;
        } else {
            fs::remove_file(&path)
                .map_err(|_| AppError::InternalError)?;
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
    let base_path = Path::new(BASE_DIR);
    
    let mut total_size = 0u64;
    for entry in WalkDir::new(base_path).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            if let Ok(metadata) = entry.metadata() {
                total_size += metadata.len();
            }
        }
    }

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

fn sanitize_path(path: &str) -> Result<PathBuf, AppError> {
    let base = Path::new(BASE_DIR);
    
    // Ensure base directory exists
    if !base.exists() {
        // Fallback to current directory if /home doesn't exist (Windows)
        #[cfg(target_os = "windows")]
        {
            let fallback = Path::new("./storage");
            std::fs::create_dir_all(fallback).ok();
            let full_path = if path.is_empty() {
                fallback.to_path_buf()
            } else {
                fallback.join(path)
            };
            return Ok(full_path);
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            return Err(AppError::NotFound("Base directory not found".to_string()));
        }
    }

    let full_path = if path.is_empty() {
        base.to_path_buf()
    } else {
        base.join(path)
    };

    // Try to canonicalize, but allow non-existent paths for creation
    let canonical = full_path.canonicalize()
        .or_else(|_| Ok::<_, AppError>(full_path.clone()))?;

    // Security check: ensure path is within base directory
    let base_canonical = base.canonicalize().unwrap_or_else(|_| base.to_path_buf());
    if !canonical.starts_with(&base_canonical) && !full_path.starts_with(base) {
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
