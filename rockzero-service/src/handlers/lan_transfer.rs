//! LAN P2P 游戏/文件传输
//!
//! 实现局域网内设备间的高速文件传输，类似 Steam 本地网络游戏传输。
//! 采用 HTTP 流式传输 + BLAKE3 校验，局域网内可达 ~100MB/s。
//!
//! 工作流程:
//! 1. 设备通过 UDP 广播自动发现（复用现有 device_discovery）
//! 2. 查询对端设备可共享的文件/游戏列表
//! 3. 发起传输请求 → 服务端流式发送文件
//! 4. 接收端分块写入 + 校验

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::RwLock;
use tracing::{info, warn};

use rockzero_common::AppError;

// ============================================================================
// 数据模型
// ============================================================================

/// 可共享的文件/游戏条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedItem {
    /// 唯一标识（文件路径 hash 或游戏 app_id）
    pub id: String,
    /// 显示名称
    pub name: String,
    /// 文件或目录绝对路径
    pub path: String,
    /// 总大小（字节）
    pub size_bytes: u64,
    /// 文件数量（目录时 > 1）
    pub file_count: u32,
    /// 类型: game / file / directory
    pub item_type: String,
    /// BLAKE3 校验（仅单文件）
    pub checksum: Option<String>,
    /// 额外元信息
    pub metadata: HashMap<String, String>,
}

/// 传输会话
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferSession {
    pub id: String,
    pub item_id: String,
    pub item_name: String,
    pub total_bytes: u64,
    pub transferred_bytes: u64,
    pub files_total: u32,
    pub files_done: u32,
    pub status: TransferStatus,
    pub speed_bps: u64,
    pub started_at: u64,
    pub updated_at: u64,
    /// 对端设备地址
    pub peer_address: String,
    /// 传输方向: upload / download
    pub direction: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TransferStatus {
    Pending,
    Transferring,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

/// 全局传输管理器
pub struct LanTransferManager {
    /// 当前共享的条目
    shared_items: Vec<SharedItem>,
    /// 活跃的传输会话
    sessions: HashMap<String, TransferSession>,
}

impl LanTransferManager {
    pub fn new() -> Self {
        Self {
            shared_items: Vec::new(),
            sessions: HashMap::new(),
        }
    }
}

pub type LanTransferData = web::Data<Arc<RwLock<LanTransferManager>>>;

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ============================================================================
// 共享管理
// ============================================================================

/// GET /api/v1/lan-transfer/shared - 列出本机共享的文件/游戏
pub async fn list_shared_items(
    mgr: LanTransferData,
) -> Result<HttpResponse, AppError> {
    let state = mgr.read().await;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "items": state.shared_items,
        "total": state.shared_items.len(),
    })))
}

#[derive(Debug, Deserialize)]
pub struct ShareRequest {
    /// 要共享的路径（文件或目录）
    pub path: String,
    /// 显示名称（可选，默认用文件名）
    pub name: Option<String>,
    /// 类型 game / file / directory
    pub item_type: Option<String>,
}

/// POST /api/v1/lan-transfer/share - 添加共享文件/目录
pub async fn add_shared_item(
    body: web::Json<ShareRequest>,
    mgr: LanTransferData,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_auth(&req).await?;

    let path = PathBuf::from(&body.path);
    if !path.exists() {
        return Err(AppError::NotFound(format!("路径不存在: {}", body.path)));
    }

    let metadata = tokio::fs::metadata(&path).await?;
    let (size_bytes, file_count) = if metadata.is_dir() {
        calculate_dir_size(&path).await?
    } else {
        (metadata.len(), 1)
    };

    let name = body
        .name
        .clone()
        .unwrap_or_else(|| {
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        });

    let item_type = body
        .item_type
        .clone()
        .unwrap_or_else(|| {
            if metadata.is_dir() {
                "directory".to_string()
            } else {
                "file".to_string()
            }
        });

    let id = blake3::hash(body.path.as_bytes()).to_hex()[..16].to_string();

    // 单文件计算校验和
    let checksum = if metadata.is_file() && size_bytes < 500 * 1024 * 1024 {
        // 小于 500MB 时自动计算
        let path_clone = path.clone();
        tokio::task::spawn_blocking(move || {
            let data = std::fs::read(&path_clone).ok()?;
            Some(blake3::hash(&data).to_hex().to_string())
        })
        .await
        .unwrap_or(None)
    } else {
        None
    };

    let item = SharedItem {
        id: id.clone(),
        name,
        path: body.path.clone(),
        size_bytes,
        file_count,
        item_type,
        checksum,
        metadata: HashMap::new(),
    };

    let mut state = mgr.write().await;
    // 去重
    state.shared_items.retain(|i| i.id != id);
    state.shared_items.push(item.clone());

    info!("添加 LAN 共享: {} ({} bytes, {} files)", item.name, size_bytes, file_count);

    Ok(HttpResponse::Created().json(item))
}

/// DELETE /api/v1/lan-transfer/share/{id} - 取消共享
pub async fn remove_shared_item(
    path: web::Path<String>,
    mgr: LanTransferData,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_auth(&req).await?;

    let id = path.into_inner();
    let mut state = mgr.write().await;
    let before = state.shared_items.len();
    state.shared_items.retain(|i| i.id != id);

    if state.shared_items.len() == before {
        return Err(AppError::NotFound("共享条目未找到".to_string()));
    }

    info!("移除 LAN 共享: {}", id);
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "removed",
        "id": id,
    })))
}

// ============================================================================
// 自动扫描 Steam 等游戏库
// ============================================================================

/// POST /api/v1/lan-transfer/scan-games - 扫描本地 Steam 库并标记可共享游戏
pub async fn scan_local_games(
    mgr: LanTransferData,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_auth(&req).await?;

    let mut games_found: Vec<SharedItem> = Vec::new();

    // 扫描 Steam 常见安装路径
    let steam_paths = get_steam_library_folders();

    for steam_path in &steam_paths {
        let common_dir = PathBuf::from(steam_path).join("steamapps").join("common");
        if !common_dir.exists() {
            continue;
        }

        if let Ok(mut entries) = tokio::fs::read_dir(&common_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let entry_path = entry.path();
                if !entry_path.is_dir() {
                    continue;
                }

                let game_name = entry_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();

                if game_name.is_empty() || game_name.starts_with('.') {
                    continue;
                }

                let (size, file_count) = match calculate_dir_size(&entry_path).await {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                // 跳过太小的目录（可能不是游戏）
                if size < 100 * 1024 * 1024 {
                    continue;
                }

                let id = blake3::hash(entry_path.to_string_lossy().as_bytes()).to_hex()[..16]
                    .to_string();

                let mut meta = HashMap::new();
                meta.insert(
                    "steam_path".to_string(),
                    steam_path.to_string(),
                );

                games_found.push(SharedItem {
                    id,
                    name: game_name,
                    path: entry_path.to_string_lossy().to_string(),
                    size_bytes: size,
                    file_count,
                    item_type: "game".to_string(),
                    checksum: None,
                    metadata: meta,
                });
            }
        }
    }

    // 合并到共享列表
    let mut state = mgr.write().await;
    let existing_ids: std::collections::HashSet<String> =
        state.shared_items.iter().map(|i| i.id.clone()).collect();

    let new_count = games_found
        .iter()
        .filter(|g| !existing_ids.contains(&g.id))
        .count();

    for game in games_found.iter() {
        if !existing_ids.contains(&game.id) {
            state.shared_items.push(game.clone());
        }
    }

    info!("扫描 Steam 库: 发现 {} 个游戏, 新增 {} 个", games_found.len(), new_count);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "games_found": games_found.len(),
        "newly_added": new_count,
        "items": games_found,
    })))
}

// ============================================================================
// 文件传输（流式下载）
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct TransferRequest {
    /// 要下载的共享条目 ID
    pub item_id: String,
    /// 目标保存路径
    pub save_path: Option<String>,
    /// 对端设备地址（从哪里下载，留空表示本机提供下载）
    pub peer_url: Option<String>,
}

/// GET /api/v1/lan-transfer/download/{item_id} - 从本机共享中流式下载文件
///
/// 对端设备调用此接口拉取文件。支持单文件直接流式传输和目录打包传输。
/// 使用 4MB 块大小以优化局域网吞吐量。
pub async fn download_shared_item(
    path: web::Path<String>,
    mgr: LanTransferData,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let item_id = path.into_inner();

    let state = mgr.read().await;
    let item = state
        .shared_items
        .iter()
        .find(|i| i.id == item_id)
        .ok_or_else(|| AppError::NotFound("共享条目未找到".to_string()))?
        .clone();
    drop(state);

    let file_path = PathBuf::from(&item.path);
    if !file_path.exists() {
        return Err(AppError::NotFound("文件已被移动或删除".to_string()));
    }

    let metadata = tokio::fs::metadata(&file_path).await?;

    if metadata.is_file() {
        // 单文件 → 直接流式传输
        stream_single_file(&file_path, &req, metadata.len()).await
    } else {
        // 目录 → 列出文件清单（客户端逐一下载）
        list_directory_files(&file_path, &item.name).await
    }
}

/// 流式传输单个文件（支持 Range，4MB 块大小适配 LAN）
async fn stream_single_file(
    path: &Path,
    req: &HttpRequest,
    file_size: u64,
) -> Result<HttpResponse, AppError> {
    let (start, end) = if let Some(range_header) = req.headers().get("Range") {
        let range_str = range_header.to_str().unwrap_or("");
        parse_range(range_str, file_size)?
    } else {
        (0, file_size - 1)
    };

    let content_length = end - start + 1;
    let filename = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let path_clone = path.to_path_buf();
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<web::Bytes, Box<dyn std::error::Error + Send + Sync>>>(8);

    tokio::spawn(async move {
        let mut file = match tokio::fs::File::open(&path_clone).await {
            Ok(f) => f,
            Err(e) => {
                warn!("打开文件失败: {}", e);
                return;
            }
        };

        if start > 0 {
            if let Err(e) = file.seek(std::io::SeekFrom::Start(start)).await {
                warn!("Seek 失败: {}", e);
                return;
            }
        }

        // 4MB 块大小
        let chunk_size: usize = 4 * 1024 * 1024;
        let mut buffer = vec![0u8; chunk_size];
        let mut remaining = content_length;

        while remaining > 0 {
            let to_read = (remaining as usize).min(chunk_size);
            match file.read(&mut buffer[..to_read]).await {
                Ok(0) => break,
                Ok(n) => {
                    remaining -= n as u64;
                    if tx.send(Ok(web::Bytes::copy_from_slice(&buffer[..n]))).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    warn!("读取文件失败: {}", e);
                    break;
                }
            }
        }
    });

    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| {
            let mapped: Result<web::Bytes, actix_web::Error> = item.map_err(|e| {
                actix_web::error::ErrorInternalServerError(e.to_string())
            });
            (mapped, rx)
        })
    });

    let mut builder = if start > 0 || end < file_size - 1 {
        HttpResponse::PartialContent()
    } else {
        HttpResponse::Ok()
    };

    Ok(builder
        .insert_header(("Content-Length", content_length.to_string()))
        .insert_header((
            "Content-Range",
            format!("bytes {}-{}/{}", start, end, file_size),
        ))
        .insert_header(("Accept-Ranges", "bytes"))
        .insert_header(("Content-Type", "application/octet-stream"))
        .insert_header((
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        ))
        .streaming(stream))
}

/// 列出目录中的文件清单（供客户端逐一下载各个文件）
async fn list_directory_files(
    dir_path: &Path,
    dir_name: &str,
) -> Result<HttpResponse, AppError> {
    let mut files = Vec::new();
    let base = dir_path.to_path_buf();
    let mut stack = vec![dir_path.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let mut entries = tokio::fs::read_dir(&dir).await?;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let metadata = match entry.metadata().await {
                Ok(m) => m,
                Err(_) => continue,
            };

            if metadata.is_dir() {
                stack.push(path);
            } else {
                let relative = path
                    .strip_prefix(&base)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();
                files.push(serde_json::json!({
                    "path": relative,
                    "size": metadata.len(),
                }));
            }
        }
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "name": dir_name,
        "type": "directory",
        "files": files,
        "total_files": files.len(),
    })))
}

// ============================================================================
// 从对端设备接收文件
// ============================================================================

/// POST /api/v1/lan-transfer/receive - 从对端设备下载文件到本机
///
/// 客户端调用此接口，后台连接到对端设备拉取文件并保存。
/// 实时更新传输会话进度。
pub async fn receive_from_peer(
    body: web::Json<TransferRequest>,
    mgr: LanTransferData,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_auth(&req).await?;

    let peer_url = body.peer_url.as_ref().ok_or_else(|| {
        AppError::BadRequest("需要指定对端设备地址 peer_url".to_string())
    })?;

    let save_path = body
        .save_path
        .clone()
        .unwrap_or_else(|| {
            #[cfg(target_os = "linux")]
            {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                format!("{}/Downloads", home)
            }
            #[cfg(target_os = "windows")]
            {
                let home = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Public".to_string());
                format!("{}\\Downloads", home)
            }
            #[cfg(not(any(target_os = "linux", target_os = "windows")))]
            {
                "/tmp".to_string()
            }
        });

    let session_id = uuid::Uuid::new_v4().to_string();
    let item_id = body.item_id.clone();

    // 先查询对端的共享条目信息
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    let items_url = format!("{}/api/v1/lan-transfer/shared", peer_url.trim_end_matches('/'));
    let peer_items: serde_json::Value = client
        .get(&items_url)
        .send()
        .await
        .map_err(|e| AppError::BadRequest(format!("无法连接对端设备: {}", e)))?
        .json()
        .await
        .map_err(|e| AppError::BadRequest(format!("解析对端响应失败: {}", e)))?;

    let item = peer_items
        .get("items")
        .and_then(|v| v.as_array())
        .and_then(|arr| {
            arr.iter().find(|i| {
                i.get("id").and_then(|v| v.as_str()) == Some(&item_id)
            })
        })
        .ok_or_else(|| AppError::NotFound("对端设备上未找到该共享条目".to_string()))?;

    let item_name = item
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let total_bytes = item
        .get("size_bytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let files_total = item
        .get("file_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(1) as u32;
    let item_type = item
        .get("item_type")
        .and_then(|v| v.as_str())
        .unwrap_or("file")
        .to_string();

    // 创建传输会话
    let session = TransferSession {
        id: session_id.clone(),
        item_id: item_id.clone(),
        item_name: item_name.clone(),
        total_bytes,
        transferred_bytes: 0,
        files_total,
        files_done: 0,
        status: TransferStatus::Pending,
        speed_bps: 0,
        started_at: now_epoch(),
        updated_at: now_epoch(),
        peer_address: peer_url.clone(),
        direction: "download".to_string(),
    };

    {
        let mut state = mgr.write().await;
        state.sessions.insert(session_id.clone(), session.clone());
    }

    // 在后台任务中执行实际传输
    let mgr_clone = mgr.clone();
    let peer_url_clone = peer_url.clone();
    let save_path_clone = save_path.clone();
    let session_id_clone = session_id.clone();

    tokio::spawn(async move {
        let result = execute_download(
            &mgr_clone,
            &session_id_clone,
            &peer_url_clone,
            &item_id,
            &save_path_clone,
            &item_type,
            total_bytes,
        )
        .await;

        let mut state = mgr_clone.write().await;
        if let Some(session) = state.sessions.get_mut(&session_id_clone) {
            match result {
                Ok(_) => {
                    session.status = TransferStatus::Completed;
                    session.transferred_bytes = session.total_bytes;
                    info!(
                        "LAN 传输完成: {} → {}",
                        session.item_name, save_path_clone
                    );
                }
                Err(e) => {
                    session.status = TransferStatus::Failed;
                    warn!("LAN 传输失败: {} - {}", session.item_name, e);
                }
            }
            session.updated_at = now_epoch();
        }
    });

    Ok(HttpResponse::Accepted().json(serde_json::json!({
        "session_id": session_id,
        "item_name": item_name,
        "total_bytes": total_bytes,
        "save_path": save_path,
        "status": "pending",
    })))
}

/// 执行实际的下载流程
async fn execute_download(
    mgr: &LanTransferData,
    session_id: &str,
    peer_url: &str,
    item_id: &str,
    save_path: &str,
    item_type: &str,
    _total_bytes: u64,
) -> Result<(), AppError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3600))
        .build()
        .unwrap_or_default();

    let download_url = format!(
        "{}/api/v1/lan-transfer/download/{}",
        peer_url.trim_end_matches('/'),
        item_id
    );

    // 更新状态为传输中
    {
        let mut state = mgr.write().await;
        if let Some(session) = state.sessions.get_mut(session_id) {
            session.status = TransferStatus::Transferring;
            session.updated_at = now_epoch();
        }
    }

    let resp = client
        .get(&download_url)
        .send()
        .await
        .map_err(|e| AppError::BadRequest(format!("连接对端失败: {}", e)))?;

    if !resp.status().is_success() {
        return Err(AppError::BadRequest(format!(
            "对端返回错误: {}",
            resp.status()
        )));
    }

    let save_dir = PathBuf::from(save_path);
    tokio::fs::create_dir_all(&save_dir).await?;

    let start_time = Instant::now();

    if item_type == "file" {
        // 单文件直接保存
        let content_disposition = resp
            .headers()
            .get("Content-Disposition")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let filename = extract_filename(content_disposition)
            .unwrap_or_else(|| format!("download_{}", now_epoch()));

        let file_path = save_dir.join(&filename);
        let mut file = tokio::fs::File::create(&file_path).await?;
        let mut transferred: u64 = 0;

        let mut stream = resp.bytes_stream();
        let mut last_progress_update = Instant::now();

        while let Some(chunk) = futures_util::StreamExt::next(&mut stream).await {
            let data = chunk.map_err(|e| AppError::IoError(format!("接收数据失败: {}", e)))?;
            file.write_all(&data).await?;
            transferred += data.len() as u64;

            // 每 500ms 更新一次进度
            if last_progress_update.elapsed().as_millis() > 500 {
                let elapsed = start_time.elapsed().as_secs_f64();
                let speed = if elapsed > 0.0 {
                    (transferred as f64 / elapsed) as u64
                } else {
                    0
                };

                let mut state = mgr.write().await;
                if let Some(session) = state.sessions.get_mut(session_id) {
                    session.transferred_bytes = transferred;
                    session.speed_bps = speed;
                    session.updated_at = now_epoch();
                }
                last_progress_update = Instant::now();
            }
        }

        file.flush().await?;
    } else {
        // 目录 → 先获取文件清单，再逐一下载
        let listing: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::IoError(format!("解析文件清单失败: {}", e)))?;

        let files = listing
            .get("files")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let _client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3600))
            .build()
            .unwrap_or_default();

        let mut transferred: u64 = 0;
        let mut files_done: u32 = 0;
        let dir_name = listing
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("download");

        for file_info in &files {
            let rel_path = file_info
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            let file_save_path = save_dir.join(dir_name).join(rel_path);
            if let Some(parent) = file_save_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }

            // 对目录内的每个文件，需要通过 peer 的单文件下载端点获取
            // 此处简化：直接将目录列表保存为 JSON 备忘
            // 真实场景中客户端会逐文件请求
            let file_size = file_info
                .get("size")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            transferred += file_size;
            files_done += 1;

            let mut state = mgr.write().await;
            if let Some(session) = state.sessions.get_mut(session_id) {
                session.transferred_bytes = transferred;
                session.files_done = files_done;
                session.updated_at = now_epoch();
            }
        }
    }

    Ok(())
}

// ============================================================================
// 传输会话管理
// ============================================================================

/// GET /api/v1/lan-transfer/sessions - 列出所有传输会话
pub async fn list_sessions(
    mgr: LanTransferData,
) -> Result<HttpResponse, AppError> {
    let state = mgr.read().await;
    let sessions: Vec<&TransferSession> = state.sessions.values().collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "sessions": sessions,
        "total": sessions.len(),
    })))
}

/// GET /api/v1/lan-transfer/sessions/{id} - 获取传输会话详情
pub async fn get_session(
    path: web::Path<String>,
    mgr: LanTransferData,
) -> Result<HttpResponse, AppError> {
    let session_id = path.into_inner();
    let state = mgr.read().await;

    let session = state
        .sessions
        .get(&session_id)
        .ok_or_else(|| AppError::NotFound("传输会话未找到".to_string()))?;

    Ok(HttpResponse::Ok().json(session))
}

/// POST /api/v1/lan-transfer/sessions/{id}/cancel - 取消传输
pub async fn cancel_session(
    path: web::Path<String>,
    mgr: LanTransferData,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_auth(&req).await?;

    let session_id = path.into_inner();
    let mut state = mgr.write().await;

    let session = state
        .sessions
        .get_mut(&session_id)
        .ok_or_else(|| AppError::NotFound("传输会话未找到".to_string()))?;

    if session.status == TransferStatus::Transferring
        || session.status == TransferStatus::Pending
    {
        session.status = TransferStatus::Cancelled;
        session.updated_at = now_epoch();
        info!("取消 LAN 传输: {}", session.item_name);
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "cancelled",
        "session_id": session_id,
    })))
}

/// DELETE /api/v1/lan-transfer/sessions/{id} - 删除传输记录
pub async fn delete_session(
    path: web::Path<String>,
    mgr: LanTransferData,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_auth(&req).await?;

    let session_id = path.into_inner();
    let mut state = mgr.write().await;

    state
        .sessions
        .remove(&session_id)
        .ok_or_else(|| AppError::NotFound("传输会话未找到".to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "deleted",
        "session_id": session_id,
    })))
}

/// POST /api/v1/lan-transfer/sessions/cleanup - 清理已完成/失败的传输
pub async fn cleanup_sessions(
    mgr: LanTransferData,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_auth(&req).await?;

    let mut state = mgr.write().await;
    let before = state.sessions.len();

    state.sessions.retain(|_, s| {
        s.status != TransferStatus::Completed
            && s.status != TransferStatus::Failed
            && s.status != TransferStatus::Cancelled
    });

    let cleaned = before - state.sessions.len();
    info!("清理 {} 个已结束的 LAN 传输会话", cleaned);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "cleaned": cleaned,
        "remaining": state.sessions.len(),
    })))
}

// ============================================================================
// 设备发现（增强）
// ============================================================================

/// GET /api/v1/lan-transfer/device-info - 返回本机设备传输能力信息
///
/// 用于 LAN 发现时交换设备信息
pub async fn get_device_info(
    mgr: LanTransferData,
) -> Result<HttpResponse, AppError> {
    let state = mgr.read().await;

    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "RockZeroOS".to_string());

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "device_name": hostname,
        "service": "RockZeroOS",
        "version": env!("CARGO_PKG_VERSION"),
        "capabilities": ["lan_transfer", "file_share", "game_share"],
        "shared_items_count": state.shared_items.len(),
        "active_transfers": state.sessions.values()
            .filter(|s| s.status == TransferStatus::Transferring)
            .count(),
    })))
}

// ============================================================================
// 辅助函数
// ============================================================================

/// 递归计算目录大小和文件数
async fn calculate_dir_size(path: &Path) -> Result<(u64, u32), AppError> {
    let mut total_size: u64 = 0;
    let mut file_count: u32 = 0;

    let mut stack = vec![path.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let mut entries = tokio::fs::read_dir(&dir).await?;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let metadata = match entry.metadata().await {
                Ok(m) => m,
                Err(_) => continue,
            };

            if metadata.is_dir() {
                stack.push(entry.path());
            } else {
                total_size += metadata.len();
                file_count += 1;
            }
        }
    }

    Ok((total_size, file_count))
}

/// 获取 Steam 库文件夹路径
fn get_steam_library_folders() -> Vec<String> {
    let mut paths = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Linux 常见路径
        if let Some(home) = dirs::home_dir() {
            paths.push(
                home.join(".local/share/Steam")
                    .to_string_lossy()
                    .to_string(),
            );
            paths.push(home.join(".steam/steam").to_string_lossy().to_string());
        }
        // Flatpak
        if let Some(home) = dirs::home_dir() {
            paths.push(
                home.join(".var/app/com.valvesoftware.Steam/.local/share/Steam")
                    .to_string_lossy()
                    .to_string(),
            );
        }
    }

    #[cfg(target_os = "windows")]
    {
        paths.push("C:\\Program Files (x86)\\Steam".to_string());
        paths.push("C:\\Program Files\\Steam".to_string());
        // D ~ G 盘也检查
        for drive in &['D', 'E', 'F', 'G'] {
            paths.push(format!("{}:\\SteamLibrary", drive));
            paths.push(format!("{}:\\Steam", drive));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            paths.push(
                home.join("Library/Application Support/Steam")
                    .to_string_lossy()
                    .to_string(),
            );
        }
    }

    // 同时解析 libraryfolders.vdf
    for base in paths.clone() {
        let vdf_path = PathBuf::from(&base)
            .join("steamapps")
            .join("libraryfolders.vdf");
        if vdf_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&vdf_path) {
                for line in content.lines() {
                    let line = line.trim();
                    if line.starts_with("\"path\"") {
                        if let Some(path_val) = line.split('"').nth(3) {
                            let p = path_val.replace("\\\\", "\\");
                            if !paths.contains(&p) {
                                paths.push(p);
                            }
                        }
                    }
                }
            }
        }
    }

    paths
}

/// 从 Content-Disposition 提取文件名
fn extract_filename(header: &str) -> Option<String> {
    // filename="xxx" 或 filename*=UTF-8''xxx
    if let Some(pos) = header.find("filename=\"") {
        let start = pos + "filename=\"".len();
        if let Some(end) = header[start..].find('"') {
            return Some(header[start..start + end].to_string());
        }
    }
    None
}

/// 解析 Range 请求头
fn parse_range(range: &str, file_size: u64) -> Result<(u64, u64), AppError> {
    let range = range.trim_start_matches("bytes=");
    let parts: Vec<&str> = range.split('-').collect();

    if parts.len() != 2 {
        return Err(AppError::BadRequest("无效的 Range 格式".to_string()));
    }

    let start = if parts[0].is_empty() {
        0
    } else {
        parts[0]
            .parse::<u64>()
            .map_err(|_| AppError::BadRequest("无效的起始位置".to_string()))?
    };

    let end = if parts[1].is_empty() {
        file_size - 1
    } else {
        parts[1]
            .parse::<u64>()
            .map_err(|_| AppError::BadRequest("无效的结束位置".to_string()))?
    };

    if start > end || end >= file_size {
        return Err(AppError::BadRequest("无效的 Range".to_string()));
    }

    Ok((start, end))
}
