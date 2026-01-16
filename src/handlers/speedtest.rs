use actix_web::{web, HttpRequest, HttpResponse, Responder};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::time::Instant;

use crate::error::AppError;

/// 测速结果
#[derive(Debug, Serialize)]
pub struct SpeedTestResult {
    pub download_speed_mbps: f64,
    pub upload_speed_mbps: f64,
    pub ping_ms: u64,
    pub jitter_ms: f64,
}

/// Ping 测试响应
#[derive(Debug, Serialize)]
pub struct PingResponse {
    pub timestamp: u64,
    pub server_time: u64,
}

#[derive(Debug, Deserialize)]
pub struct DownloadQuery {
    pub size: Option<u32>,
}

/// 下载测试 - 生成随机数据流
/// 参考 OpenSpeedTest 的实现，使用流式传输大量随机数据
pub async fn download_test(req: HttpRequest) -> Result<impl Responder, AppError> {
    // 从查询参数获取请求的数据大小，默认 100MB
    let query = web::Query::<DownloadQuery>::from_query(req.query_string())
        .unwrap_or(web::Query(DownloadQuery { size: None }));
    
    // 限制最大 500MB，防止滥用
    let size_mb = query.size.unwrap_or(100).min(500);
    let total_bytes = size_mb as usize * 1024 * 1024;
    
    // 使用流式响应，每次发送 64KB 的随机数据
    let chunk_size = 64 * 1024; // 64KB chunks
    
    // 创建一个简单的流，使用 futures::stream::unfold
    let stream = futures::stream::unfold(
        (total_bytes, chunk_size),
        |(remaining, chunk_size)| async move {
            if remaining == 0 {
                return None;
            }
            
            let current_chunk = remaining.min(chunk_size);
            let mut buffer = vec![0u8; current_chunk];
            
            // 使用简单的伪随机填充
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            
            for (i, byte) in buffer.iter_mut().enumerate() {
                *byte = ((seed.wrapping_add(i as u64)).wrapping_mul(1103515245).wrapping_add(12345) >> 16) as u8;
            }
            
            let new_remaining = remaining - current_chunk;
            Some((Ok::<_, actix_web::error::Error>(web::Bytes::from(buffer)), (new_remaining, chunk_size)))
        },
    );
    
    Ok(HttpResponse::Ok()
        .content_type("application/octet-stream")
        .insert_header(("Content-Length", total_bytes.to_string()))
        .insert_header(("Cache-Control", "no-cache, no-store, must-revalidate"))
        .insert_header(("Pragma", "no-cache"))
        .insert_header(("Expires", "0"))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .streaming(stream))
}

/// 上传测试 - 接收并丢弃上传的数据，返回速度统计
pub async fn upload_test(mut payload: web::Payload) -> Result<impl Responder, AppError> {
    let start = Instant::now();
    let mut total_bytes: usize = 0;
    
    // 读取并丢弃所有上传的数据
    while let Some(chunk) = payload.next().await {
        match chunk {
            Ok(data) => {
                total_bytes += data.len();
            }
            Err(e) => {
                return Err(AppError::BadRequest(format!("Upload error: {}", e)));
            }
        }
    }
    
    let elapsed = start.elapsed();
    let elapsed_secs = elapsed.as_secs_f64();
    
    // 计算上传速度 (Mbps)
    let speed_mbps = if elapsed_secs > 0.0 {
        (total_bytes as f64 * 8.0) / (elapsed_secs * 1_000_000.0)
    } else {
        0.0
    };
    
    Ok(HttpResponse::Ok().json(UploadResult {
        bytes_received: total_bytes,
        elapsed_ms: elapsed.as_millis() as u64,
        speed_mbps,
    }))
}

#[derive(Debug, Serialize)]
pub struct UploadResult {
    pub bytes_received: usize,
    pub elapsed_ms: u64,
    pub speed_mbps: f64,
}

/// Ping 测试 - 返回服务器时间戳用于计算延迟
pub async fn ping_test() -> Result<impl Responder, AppError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    
    Ok(HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-cache, no-store, must-revalidate"))
        .insert_header(("Pragma", "no-cache"))
        .json(PingResponse {
            timestamp: now.as_millis() as u64,
            server_time: now.as_nanos() as u64,
        }))
}

/// 获取测速服务器信息
pub async fn server_info() -> Result<impl Responder, AppError> {
    let hostname = sysinfo::System::host_name().unwrap_or_else(|| "NAS".to_string());
    
    Ok(HttpResponse::Ok().json(ServerInfo {
        name: hostname,
        version: env!("CARGO_PKG_VERSION").to_string(),
        max_download_size_mb: 500,
        max_upload_size_mb: 100,
        supported_tests: vec![
            "ping".to_string(),
            "download".to_string(),
            "upload".to_string(),
        ],
    }))
}

#[derive(Debug, Serialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    pub max_download_size_mb: u32,
    pub max_upload_size_mb: u32,
    pub supported_tests: Vec<String>,
}

/// 空响应 - 用于最小延迟测试
pub async fn empty_response() -> Result<impl Responder, AppError> {
    Ok(HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("Content-Length", "0"))
        .finish())
}
