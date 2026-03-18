use actix_web::{web, HttpRequest, HttpResponse, Responder};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::Instant;

use rockzero_common::AppError;

/// 测速结果
#[derive(Debug, Serialize)]
#[allow(dead_code)]
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
    pub monotonic_ns: u128,
    pub processing_ns: u128,
}

#[derive(Debug, Deserialize)]
pub struct DownloadQuery {
    pub size: Option<u32>,
    pub chunk_kb: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct PingQuery {
    pub count: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct PingStatsResponse {
    pub sent: u32,
    pub results: Vec<PingResponse>,
    pub min_ms: f64,
    pub max_ms: f64,
    pub avg_ms: f64,
    pub jitter_ms: f64,
}

static DOWNLOAD_BLOCK: OnceLock<Vec<u8>> = OnceLock::new();
static START_INSTANT: OnceLock<Instant> = OnceLock::new();

fn get_download_block() -> &'static [u8] {
    DOWNLOAD_BLOCK
        .get_or_init(|| {
            // Build once and reuse. Avoid per-request random generation CPU overhead.
            // 1 MiB repeated pattern is enough to saturate network throughput tests.
            let mut block = vec![0u8; 1024 * 1024];
            let mut x: u64 = 0x9E3779B97F4A7C15;
            for byte in &mut block {
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                *byte = (x.wrapping_mul(0x2545F4914F6CDD1D) & 0xFF) as u8;
            }
            block
        })
        .as_slice()
}

fn monotonic_now_ns() -> u128 {
    START_INSTANT
        .get_or_init(Instant::now)
        .elapsed()
        .as_nanos()
}

/// 下载测试 - 生成随机数据流
/// 参考 OpenSpeedTest 的实现，使用流式传输大量随机数据
pub async fn download_test(req: HttpRequest) -> Result<impl Responder, AppError> {
    // 从查询参数获取请求的数据大小，默认 100MB
    let query = web::Query::<DownloadQuery>::from_query(req.query_string()).unwrap_or(web::Query(
        DownloadQuery {
            size: None,
            chunk_kb: None,
        },
    ));
    
    // 限制最大 500MB，防止滥用
    let size_mb = query.size.unwrap_or(100).min(500);
    let total_bytes = size_mb as usize * 1024 * 1024;
    
    // Tune chunk size for fewer syscalls and better throughput.
    let chunk_size = query
        .chunk_kb
        .map(|v| v.clamp(64, 2048) as usize * 1024)
        .unwrap_or(512 * 1024); // default 512KB
    let source = get_download_block().to_vec();
    let source_len = source.len();
    
    // 创建一个简单的流，使用 futures::stream::unfold
    let stream = futures::stream::unfold(
        (total_bytes, chunk_size, source, source_len),
        |(remaining, chunk_size, source, source_len)| async move {
            if remaining == 0 {
                return None;
            }
            
            let current_chunk = remaining.min(chunk_size);
            let mut buffer = Vec::with_capacity(current_chunk);
            let mut copied = 0;
            while copied < current_chunk {
                let take = (current_chunk - copied).min(source_len);
                buffer.extend_from_slice(&source[..take]);
                copied += take;
            }
            
            let new_remaining = remaining - current_chunk;
            Some((
                Ok::<_, actix_web::error::Error>(web::Bytes::from(buffer)),
                (new_remaining, chunk_size, source, source_len),
            ))
        },
    );
    
    Ok(HttpResponse::Ok()
        .content_type("application/octet-stream")
        .insert_header(("Content-Length", total_bytes.to_string()))
        .insert_header(("Cache-Control", "no-cache, no-store, must-revalidate, private"))
        .insert_header(("Pragma", "no-cache"))
        .insert_header(("Expires", "0"))
        .insert_header(("Content-Encoding", "identity"))
        .insert_header(("X-Accel-Buffering", "no"))
        .insert_header(("Connection", "keep-alive"))
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
pub async fn ping_test(req: HttpRequest) -> Result<impl Responder, AppError> {
    let q = web::Query::<PingQuery>::from_query(req.query_string())
        .unwrap_or(web::Query(PingQuery { count: None }));
    let count = q.count.unwrap_or(1).clamp(1, 16);

    let mut samples = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let processing_start = Instant::now();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();

        samples.push(PingResponse {
            timestamp: now.as_millis() as u64,
            server_time: now.as_nanos() as u64,
            monotonic_ns: monotonic_now_ns(),
            processing_ns: processing_start.elapsed().as_nanos(),
        });
    }

    if count == 1 {
        return Ok(HttpResponse::Ok()
            .insert_header(("Cache-Control", "no-cache, no-store, must-revalidate"))
            .insert_header(("Pragma", "no-cache"))
            .insert_header(("Content-Encoding", "identity"))
            .json(samples.remove(0)));
    }

    let mut prev: Option<f64> = None;
    let mut min_ms: f64 = f64::MAX;
    let mut max_ms: f64 = 0.0;
    let mut sum_ms: f64 = 0.0;
    let mut jitter_acc: f64 = 0.0;

    for sample in &samples {
        let ms = sample.processing_ns as f64 / 1_000_000.0;
        min_ms = min_ms.min(ms);
        max_ms = max_ms.max(ms);
        sum_ms += ms;
        if let Some(p) = prev {
            jitter_acc += (ms - p).abs();
        }
        prev = Some(ms);
    }

    let avg_ms = sum_ms / samples.len() as f64;
    let jitter_ms = if samples.len() > 1 {
        jitter_acc / (samples.len() as f64 - 1.0)
    } else {
        0.0
    };

    Ok(HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-cache, no-store, must-revalidate"))
        .insert_header(("Pragma", "no-cache"))
        .insert_header(("Content-Encoding", "identity"))
        .json(PingStatsResponse {
            sent: count,
            results: samples,
            min_ms,
            max_ms,
            avg_ms,
            jitter_ms,
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
            "empty".to_string(),
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
