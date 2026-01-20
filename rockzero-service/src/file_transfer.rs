#![allow(dead_code)]

use actix_multipart::Multipart;
use actix_web::{web, HttpRequest, HttpResponse};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use rockzero_common::AppError;

#[derive(Debug, Deserialize)]
pub struct UploadRequest {
    pub path: String,
    pub filename: String,
    pub total_size: u64,
    pub chunk_size: usize,
}

#[derive(Debug, Deserialize)]
pub struct DownloadRequest {
    pub path: String,
    pub range: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TransferStatus {
    pub filename: String,
    pub total_size: u64,
    pub transferred: u64,
    pub percentage: f32,
    pub speed_mbps: f32,
    pub eta_seconds: u64,
    pub checksum: Option<String>,
}

pub async fn upload_file(
    mut payload: Multipart,
    query: web::Query<UploadRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_auth(&req).await?;

    let upload_path = PathBuf::from(&query.path);
    let file_path = upload_path.join(&query.filename);

    if let Some(parent) = file_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&file_path)
        .await?;

    let mut total_written = 0u64;
    let mut hasher = blake3::Hasher::new();
    let start_time = std::time::Instant::now();

    while let Some(item) = payload.next().await {
        let mut field = item?;
        while let Some(chunk) = field.next().await {
            let data = chunk?;
            file.write_all(&data).await?;
            hasher.update(&data);

            total_written += data.len() as u64;
        }
    }

    file.flush().await?;

    let checksum = hasher.finalize().to_hex().to_string();
    let elapsed = start_time.elapsed().as_secs_f32();
    let speed_mbps = (total_written as f32 / 1024.0 / 1024.0) / elapsed;

    Ok(HttpResponse::Ok().json(TransferStatus {
        filename: query.filename.clone(),
        total_size: query.total_size,
        transferred: total_written,
        percentage: (total_written as f32 / query.total_size as f32) * 100.0,
        speed_mbps,
        eta_seconds: 0,
        checksum: Some(checksum),
    }))
}

pub async fn download_file(
    query: web::Query<DownloadRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_auth(&req).await?;

    let file_path = PathBuf::from(&query.path);
    if !file_path.exists() {
        return Err(AppError::NotFound("File not found".to_string()));
    }

    let metadata = tokio::fs::metadata(&file_path).await?;
    let file_size = metadata.len();
    let (start, end) = if let Some(range) = &query.range {
        parse_range(range, file_size)?
    } else if let Some(range_header) = req.headers().get("Range") {
        let range_str = range_header.to_str().unwrap_or("");
        parse_range(range_str, file_size)?
    } else {
        (0, file_size - 1)
    };

    let content_length = end - start + 1;
    let mut file = File::open(&file_path).await?;
    if start > 0 {
        use tokio::io::AsyncSeekExt;
        file.seek(std::io::SeekFrom::Start(start)).await?;
    }

    let mut buffer = vec![0u8; content_length as usize];
    file.read_exact(&mut buffer).await?;

    let mut response = if start > 0 || end < file_size - 1 {
        HttpResponse::PartialContent()
    } else {
        HttpResponse::Ok()
    };

    response
        .insert_header(("Content-Length", content_length.to_string()))
        .insert_header((
            "Content-Range",
            format!("bytes {}-{}/{}", start, end, file_size),
        ))
        .insert_header(("Accept-Ranges", "bytes"))
        .insert_header(("Content-Type", "application/octet-stream"))
        .body(buffer);

    Ok(response.finish())
}

pub async fn chunked_upload(
    payload: web::Bytes,
    query: web::Query<ChunkedUploadRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_auth(&req).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "sequence": query.sequence,
        "size": payload.len(),
        "is_keyframe": query.is_keyframe,
    })))
}

pub async fn chunked_download(
    query: web::Query<ChunkedDownloadRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_auth(&req).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "seek_to": query.seek_to,
        "timeout_ms": query.timeout_ms,
    })))
}

/// 分块上传请求
#[derive(Debug, Deserialize)]
pub struct ChunkedUploadRequest {
    pub sequence: u64,
    pub is_keyframe: bool,
}

/// 分块下载请求
#[derive(Debug, Deserialize)]
pub struct ChunkedDownloadRequest {
    pub seek_to: Option<u64>,
    pub timeout_ms: Option<u64>,
}

/// 解析Range头
fn parse_range(range: &str, file_size: u64) -> Result<(u64, u64), AppError> {
    // 格式: "bytes=start-end" 或 "bytes=start-"
    let range = range.trim_start_matches("bytes=");
    let parts: Vec<&str> = range.split('-').collect();

    if parts.len() != 2 {
        return Err(AppError::BadRequest("Invalid range format".to_string()));
    }

    let start = if parts[0].is_empty() {
        0
    } else {
        parts[0]
            .parse::<u64>()
            .map_err(|_| AppError::BadRequest("Invalid start position".to_string()))?
    };

    let end = if parts[1].is_empty() {
        file_size - 1
    } else {
        parts[1]
            .parse::<u64>()
            .map_err(|_| AppError::BadRequest("Invalid end position".to_string()))?
    };

    if start > end || end >= file_size {
        return Err(AppError::BadRequest("Invalid range".to_string()));
    }

    Ok((start, end))
}

/// 获取文件校验和
pub async fn get_file_checksum(
    query: web::Query<DownloadRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    // 验证认证
    crate::middleware::verify_auth(&req).await?;

    let file_path = PathBuf::from(&query.path);

    if !file_path.exists() {
        return Err(AppError::NotFound("File not found".to_string()));
    }

    // 计算 Blake3 校验和
    let mut file = File::open(&file_path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; 8192];

    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    let checksum = hasher.finalize().to_hex().to_string();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "path": query.path,
        "checksum": checksum,
        "algorithm": "Blake3",
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_range() {
        assert_eq!(parse_range("bytes=0-999", 1000).unwrap(), (0, 999));
        assert_eq!(parse_range("bytes=500-", 1000).unwrap(), (500, 999));
        assert_eq!(parse_range("bytes=0-499", 1000).unwrap(), (0, 499));
    }
}
