use actix_multipart::Multipart;
use actix_web::{web, HttpResponse, Responder};
use futures::StreamExt;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::io::Write;
use std::path::PathBuf;
use tracing::{error, info};
use uuid::Uuid;

use crate::db;
use crate::error::AppError;
use crate::models::{FileListResponse, FileMetadata, FileResponse};

const MAX_FILE_SIZE: usize = 500 * 1024 * 1024;
const UPLOAD_DIR: &str = "./uploads";

pub async fn upload_file(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
    mut payload: Multipart,
) -> Result<impl Responder, AppError> {
    std::fs::create_dir_all(UPLOAD_DIR).map_err(|_| AppError::InternalError)?;

    let mut file_metadata_list = Vec::new();

    while let Some(item) = payload.next().await {
        let mut field = item.map_err(|_| AppError::BadRequest("Invalid file data".to_string()))?;

        let content_disposition = field.content_disposition();
        let original_filename = content_disposition
            .get_filename()
            .ok_or_else(|| AppError::BadRequest("Missing filename".to_string()))?
            .to_string();

        let file_id = Uuid::new_v4().to_string();
        let path_buf = PathBuf::from(&original_filename);
        let file_ext = path_buf
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("bin");
        let filename = format!("{}_{}.{}", claims.sub, file_id, file_ext);
        let file_path = format!("{}/{}", UPLOAD_DIR, filename);

        let mut file = std::fs::File::create(&file_path)
            .map_err(|_| AppError::InternalError)?;

        let mut hasher = Sha256::new();
        let mut file_size = 0usize;

        while let Some(chunk) = field.next().await {
            let data = chunk.map_err(|_| AppError::InternalError)?;
            file_size += data.len();

            if file_size > MAX_FILE_SIZE {
                std::fs::remove_file(&file_path).ok();
                return Err(AppError::BadRequest("File size exceeds limit".to_string()));
            }

            hasher.update(&data);
            file.write_all(&data).map_err(|_| AppError::InternalError)?;
        }

        let checksum = format!("{:x}", hasher.finalize());
        let mime_type = mime_guess::from_path(&original_filename)
            .first_or_octet_stream()
            .to_string();

        let metadata = FileMetadata {
            id: file_id.clone(),
            user_id: claims.sub.clone(),
            filename: filename.clone(),
            original_filename: original_filename.clone(),
            file_path: file_path.clone(),
            mime_type: mime_type.clone(),
            file_size: file_size as i64,
            checksum: checksum.clone(),
            is_public: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        db::create_file_metadata(&pool, &metadata).await?;
        file_metadata_list.push(metadata);

        info!(
            "File uploaded: {} ({} bytes) - User: {}",
            original_filename, file_size, claims.sub
        );
    }

    let responses: Vec<FileResponse> = file_metadata_list
        .into_iter()
        .map(|f| FileResponse {
            id: f.id.clone(),
            filename: f.original_filename,
            mime_type: f.mime_type,
            file_size: f.file_size,
            is_public: f.is_public,
            created_at: f.created_at,
            download_url: format!("/api/v1/files/{}/download", f.id),
        })
        .collect();

    Ok(HttpResponse::Created().json(responses))
}

pub async fn list_files(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
) -> Result<impl Responder, AppError> {
    let files = db::list_files_by_user(&pool, &claims.sub).await?;
    let total = files.len() as i64;

    let responses: Vec<FileResponse> = files
        .into_iter()
        .map(|f| FileResponse {
            id: f.id.clone(),
            filename: f.original_filename,
            mime_type: f.mime_type,
            file_size: f.file_size,
            is_public: f.is_public,
            created_at: f.created_at,
            download_url: format!("/api/v1/files/{}/download", f.id),
        })
        .collect();

    Ok(HttpResponse::Ok().json(FileListResponse {
        files: responses,
        total,
    }))
}

pub async fn download_file(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
    file_id: web::Path<String>,
) -> Result<actix_files::NamedFile, AppError> {
    let file = db::find_file_by_id(&pool, &file_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("File not found".to_string()))?;

    let path = PathBuf::from(&file.file_path);
    if !path.exists() {
        error!("File path does not exist: {}", file.file_path);
        return Err(AppError::NotFound("File not found".to_string()));
    }

    Ok(actix_files::NamedFile::open(path)
        .map_err(|_| AppError::InternalError)?
        .set_content_disposition(actix_web::http::header::ContentDisposition {
            disposition: actix_web::http::header::DispositionType::Attachment,
            parameters: vec![actix_web::http::header::DispositionParam::Filename(
                file.original_filename,
            )],
        }))
}

pub async fn delete_file(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
    file_id: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let file = db::find_file_by_id(&pool, &file_id, &claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("File not found".to_string()))?;

    std::fs::remove_file(&file.file_path).ok();

    db::delete_file_metadata(&pool, &file_id, &claims.sub).await?;

    info!("File deleted: {} - User: {}", file.original_filename, claims.sub);

    Ok(HttpResponse::NoContent().finish())
}
