use actix_web::{web, HttpRequest, HttpResponse};
use reqwest::Client;
use rockzero_common::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::info;

// ============================================================================
// 数据模型
// ============================================================================

/// WASM 应用信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmApp {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub author: String,
    pub icon_url: String,
    pub wasm_url: String,
    pub category: WasmAppCategory,
    pub size_bytes: u64,
    pub installed: bool,
    pub installed_path: Option<String>,
    pub permissions: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// WASM 应用分类
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum WasmAppCategory {
    Game,
    Tool,
    Media,
    Web3,
    Social,
    Productivity,
    Other,
}

/// 插件接口定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub api_version: String,
    pub description: String,
    pub author: String,
    pub entry_point: String,
    pub capabilities: Vec<String>,
    pub config_schema: Option<Value>,
}

/// 商店分类
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreCategory {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub count: i64,
}

// ============================================================================
// 请求/响应模型
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: Option<String>,
    pub category: Option<String>,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub sort: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StoreOverview {
    pub categories: Vec<StoreCategory>,
    pub wasm_apps: Vec<WasmApp>,
    pub total_wasm_apps: i64,
    pub available_plugins: Vec<PluginManifest>,
}

#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T: Serialize> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: u32,
    pub page_size: u32,
    pub total_pages: u32,
}

#[derive(Debug, Deserialize)]
pub struct InstallWasmAppRequest {
    pub app_id: String,
    pub wasm_url: String,
    pub name: String,
    pub expected_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RunWasmAppRequest {
    pub function: Option<String>,
    pub args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterPluginRequest {
    pub manifest: PluginManifest,
    pub wasm_url: String,
}

// ============================================================================
// WASM 应用存储管理
// ============================================================================

fn wasm_store_root() -> PathBuf {
    if let Ok(path) = std::env::var("WASM_STORE_ROOT") {
        return PathBuf::from(path);
    }
    if let Ok(ext) = std::env::var("EXTERNAL_STORAGE_PATH") {
        return PathBuf::from(ext).join("wasm_store");
    }
    PathBuf::from("/mnt/external/wasm_store")
}

fn wasm_registry_path() -> PathBuf {
    wasm_store_root().join("registry.json")
}

fn plugin_registry_path() -> PathBuf {
    wasm_store_root().join("plugins.json")
}

fn load_wasm_registry() -> Result<Vec<WasmApp>, AppError> {
    let path = wasm_registry_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = std::fs::read_to_string(&path).map_err(|e| AppError::IoError(e.to_string()))?;
    serde_json::from_str(&data).map_err(|e| AppError::BadRequest(e.to_string()))
}

fn save_wasm_registry(apps: &[WasmApp]) -> Result<(), AppError> {
    let root = wasm_store_root();
    std::fs::create_dir_all(&root).map_err(|e| AppError::IoError(e.to_string()))?;
    let path = wasm_registry_path();
    let data = serde_json::to_string_pretty(apps)
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;
    std::fs::write(path, data).map_err(|e| AppError::IoError(e.to_string()))
}

fn load_plugin_registry() -> Result<Vec<PluginManifest>, AppError> {
    let path = plugin_registry_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = std::fs::read_to_string(&path).map_err(|e| AppError::IoError(e.to_string()))?;
    serde_json::from_str(&data).map_err(|e| AppError::BadRequest(e.to_string()))
}

fn save_plugin_registry(plugins: &[PluginManifest]) -> Result<(), AppError> {
    let root = wasm_store_root();
    std::fs::create_dir_all(&root).map_err(|e| AppError::IoError(e.to_string()))?;
    let path = plugin_registry_path();
    let data = serde_json::to_string_pretty(plugins)
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;
    std::fs::write(path, data).map_err(|e| AppError::IoError(e.to_string()))
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ============================================================================
// HTTP 处理函数
// ============================================================================

/// GET /api/v1/wasm-store/overview - 商店首页概览
pub async fn get_store_overview() -> Result<HttpResponse, AppError> {
    info!("🏪 获取 WASM 商店概览");

    let wasm_apps = load_wasm_registry().unwrap_or_default();
    let plugins = load_plugin_registry().unwrap_or_default();

    let categories = vec![
        StoreCategory {
            id: "wasm_apps".to_string(),
            name: "WASM 应用".to_string(),
            icon: "📦".to_string(),
            count: wasm_apps.len() as i64,
        },
        StoreCategory {
            id: "games".to_string(),
            name: "WASM 游戏".to_string(),
            icon: "🎮".to_string(),
            count: wasm_apps
                .iter()
                .filter(|a| a.category == WasmAppCategory::Game)
                .count() as i64,
        },
        StoreCategory {
            id: "tools".to_string(),
            name: "工具".to_string(),
            icon: "🔧".to_string(),
            count: wasm_apps
                .iter()
                .filter(|a| a.category == WasmAppCategory::Tool)
                .count() as i64,
        },
        StoreCategory {
            id: "media".to_string(),
            name: "媒体".to_string(),
            icon: "🎬".to_string(),
            count: wasm_apps
                .iter()
                .filter(|a| a.category == WasmAppCategory::Media)
                .count() as i64,
        },
        StoreCategory {
            id: "web3".to_string(),
            name: "Web3 服务".to_string(),
            icon: "🔗".to_string(),
            count: wasm_apps
                .iter()
                .filter(|a| a.category == WasmAppCategory::Web3)
                .count() as i64,
        },
        StoreCategory {
            id: "productivity".to_string(),
            name: "生产力".to_string(),
            icon: "📊".to_string(),
            count: wasm_apps
                .iter()
                .filter(|a| a.category == WasmAppCategory::Productivity)
                .count() as i64,
        },
        StoreCategory {
            id: "plugins".to_string(),
            name: "扩展插件".to_string(),
            icon: "🔌".to_string(),
            count: plugins.len() as i64,
        },
    ];

    let overview = StoreOverview {
        total_wasm_apps: wasm_apps.len() as i64,
        categories,
        wasm_apps,
        available_plugins: plugins,
    };

    Ok(HttpResponse::Ok().json(overview))
}

/// GET /api/v1/wasm-store/search - 搜索 WASM 应用
pub async fn search_wasm_apps(query: web::Query<SearchQuery>) -> Result<HttpResponse, AppError> {
    let search_term = query.q.clone().unwrap_or_default().to_lowercase();
    let category_filter = query.category.clone();
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).min(100);

    info!(
        "🔍 搜索 WASM 应用: q={}, category={:?}",
        search_term, category_filter
    );

    let mut apps = load_wasm_registry().unwrap_or_default();

    // 按分类过滤
    if let Some(cat) = &category_filter {
        let cat_lower = cat.to_lowercase();
        apps.retain(|a| {
            let app_cat = serde_json::to_string(&a.category)
                .unwrap_or_default()
                .trim_matches('"')
                .to_lowercase();
            app_cat == cat_lower
        });
    }

    // 按搜索词过滤
    if !search_term.is_empty() {
        apps.retain(|a| {
            a.name.to_lowercase().contains(&search_term)
                || a.description.to_lowercase().contains(&search_term)
                || a.author.to_lowercase().contains(&search_term)
        });
    }

    // 排序
    if let Some(sort) = &query.sort {
        match sort.as_str() {
            "name" => apps.sort_by(|a, b| a.name.cmp(&b.name)),
            "newest" => apps.sort_by(|a, b| b.created_at.cmp(&a.created_at)),
            "updated" => apps.sort_by(|a, b| b.updated_at.cmp(&a.updated_at)),
            "size" => apps.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes)),
            _ => {}
        }
    }

    let total = apps.len() as i64;
    let start = ((page - 1) * page_size) as usize;
    let items: Vec<WasmApp> = apps
        .into_iter()
        .skip(start)
        .take(page_size as usize)
        .collect();

    Ok(HttpResponse::Ok().json(PaginatedResponse {
        items,
        total,
        page,
        page_size,
        total_pages: ((total as f64) / (page_size as f64)).ceil() as u32,
    }))
}

/// GET /api/v1/wasm-store/wasm/apps - WASM 应用列表
pub async fn list_wasm_apps() -> Result<HttpResponse, AppError> {
    info!("📦 获取 WASM 应用列表");
    let apps = load_wasm_registry()?;
    Ok(HttpResponse::Ok().json(apps))
}

/// GET /api/v1/wasm-store/wasm/apps/{app_id} - 获取单个 WASM 应用详情
pub async fn get_wasm_app_details(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let app_id = path.into_inner();
    info!("📦 获取 WASM 应用详情: {}", app_id);

    let apps = load_wasm_registry()?;
    let app = apps
        .iter()
        .find(|a| a.id == app_id)
        .ok_or_else(|| AppError::NotFound(format!("WASM 应用 {} 未找到", app_id)))?;

    Ok(HttpResponse::Ok().json(app))
}

/// POST /api/v1/wasm-store/wasm/install - 安装 WASM 应用
pub async fn install_wasm_app(
    body: web::Json<InstallWasmAppRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    info!("📦 安装 WASM 应用: {}", body.name);

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    let response = client
        .get(&body.wasm_url)
        .send()
        .await
        .map_err(|e| AppError::BadRequest(format!("下载 WASM 模块失败: {}", e)))?;

    if !response.status().is_success() {
        return Err(AppError::BadRequest("下载 WASM 模块失败".to_string()));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| AppError::BadRequest(format!("读取 WASM 数据失败: {}", e)))?;

    // 验证 BLAKE3 哈希
    let hash = blake3::hash(&bytes);
    let hash_hex = hash.to_hex().to_string();

    if let Some(expected) = &body.expected_hash {
        if expected != &hash_hex {
            return Err(AppError::PreconditionFailed(format!(
                "BLAKE3 哈希不匹配: 期望 {}, 实际 {}",
                expected, hash_hex
            )));
        }
    }

    // 验证是有效的 WASM 模块
    let engine = wasmtime::Engine::default();
    wasmtime::Module::new(&engine, &bytes)
        .map_err(|e| AppError::BadRequest(format!("无效的 WASM 模块: {}", e)))?;

    // 保存到磁盘
    let store_dir = wasm_store_root().join("modules");
    std::fs::create_dir_all(&store_dir).map_err(|e| AppError::IoError(e.to_string()))?;

    let filename = format!("{}_{}.wasm", body.app_id, &hash_hex[..8]);
    let file_path = store_dir.join(&filename);
    std::fs::write(&file_path, &bytes).map_err(|e| AppError::IoError(e.to_string()))?;

    // 更新注册表
    let mut apps = load_wasm_registry()?;

    if let Some(existing) = apps.iter_mut().find(|a| a.id == body.app_id) {
        existing.installed = true;
        existing.installed_path = Some(file_path.to_string_lossy().to_string());
        existing.updated_at = now_epoch();
    } else {
        apps.push(WasmApp {
            id: body.app_id.clone(),
            name: body.name.clone(),
            description: String::new(),
            version: "1.0.0".to_string(),
            author: String::new(),
            icon_url: String::new(),
            wasm_url: body.wasm_url.clone(),
            category: WasmAppCategory::Other,
            size_bytes: bytes.len() as u64,
            installed: true,
            installed_path: Some(file_path.to_string_lossy().to_string()),
            permissions: Vec::new(),
            created_at: now_epoch(),
            updated_at: now_epoch(),
        });
    }

    save_wasm_registry(&apps)?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "status": "installed",
        "app_id": body.app_id,
        "hash": hash_hex,
        "size": bytes.len(),
    })))
}

/// POST /api/v1/wasm-store/wasm/{app_id}/run - 运行 WASM 应用
pub async fn run_wasm_app(
    path: web::Path<String>,
    body: web::Json<RunWasmAppRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let app_id = path.into_inner();
    info!("▶️ 运行 WASM 应用: {}", app_id);

    let apps = load_wasm_registry()?;
    let app = apps
        .iter()
        .find(|a| a.id == app_id && a.installed)
        .ok_or_else(|| AppError::NotFound(format!("WASM 应用 {} 未安装", app_id)))?;

    let wasm_path = app
        .installed_path
        .as_ref()
        .ok_or_else(|| AppError::NotFound("WASM 模块路径未找到".to_string()))?;

    if !Path::new(wasm_path).exists() {
        return Err(AppError::NotFound("WASM 模块文件不存在".to_string()));
    }

    let engine = wasmtime::Engine::default();
    let module = wasmtime::Module::from_file(&engine, wasm_path)
        .map_err(|e| AppError::BadRequest(format!("加载 WASM 模块失败: {}", e)))?;

    let mut linker = wasmtime::Linker::new(&engine);
    wasmtime_wasi::add_to_linker(&mut linker, |cx| cx)
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    let mut builder = wasmtime_wasi::sync::WasiCtxBuilder::new();
    builder.inherit_stdio();

    if let Some(args) = &body.args {
        for arg in args {
            builder
                .arg(arg)
                .map_err(|e| AppError::ValidationError(format!("无效参数: {}", e)))?;
        }
    }

    if let Some(env) = &body.env {
        for (key, value) in env {
            builder
                .env(key, value)
                .map_err(|e| AppError::ValidationError(format!("无效环境变量: {}", e)))?;
        }
    }

    let mut store = wasmtime::Store::new(&engine, builder.build());
    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| AppError::BadRequest(format!("实例化 WASM 失败: {}", e)))?;

    let func_name = body
        .function
        .clone()
        .unwrap_or_else(|| "_start".to_string());

    if let Ok(entry) = instance.get_typed_func::<(), ()>(&mut store, &func_name) {
        entry
            .call(&mut store, ())
            .map_err(|e| AppError::BadRequest(format!("WASM 执行失败: {}", e)))?;
    } else if let Some(func) = instance.get_func(&mut store, &func_name) {
        func.call(&mut store, &[], &mut [])
            .map_err(|e| AppError::BadRequest(format!("WASM 执行失败: {}", e)))?;
    } else {
        return Err(AppError::NotFound(format!(
            "函数 '{}' 在 WASM 模块中未找到",
            func_name
        )));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "completed",
        "app_id": app_id,
        "function": func_name,
    })))
}

/// DELETE /api/v1/wasm-store/wasm/{app_id} - 卸载 WASM 应用
pub async fn uninstall_wasm_app(
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let app_id = path.into_inner();
    info!("🗑️ 卸载 WASM 应用: {}", app_id);

    let mut apps = load_wasm_registry()?;

    if let Some(app) = apps.iter_mut().find(|a| a.id == app_id) {
        if let Some(path) = &app.installed_path {
            let _ = std::fs::remove_file(path);
        }
        app.installed = false;
        app.installed_path = None;
        save_wasm_registry(&apps)?;

        Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "uninstalled",
            "app_id": app_id,
        })))
    } else {
        Err(AppError::NotFound(format!("WASM 应用 {} 未找到", app_id)))
    }
}

// ============================================================================
// 插件系统
// ============================================================================

/// GET /api/v1/wasm-store/plugins - 获取已注册插件列表
pub async fn list_plugins() -> Result<HttpResponse, AppError> {
    info!("🔌 获取插件列表");
    let plugins = load_plugin_registry()?;
    Ok(HttpResponse::Ok().json(plugins))
}

/// POST /api/v1/wasm-store/plugins/register - 注册新插件
pub async fn register_plugin(
    body: web::Json<RegisterPluginRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    info!("🔌 注册插件: {}", body.manifest.name);

    let mut plugins = load_plugin_registry()?;

    if plugins.iter().any(|p| p.id == body.manifest.id) {
        if let Some(existing) = plugins.iter_mut().find(|p| p.id == body.manifest.id) {
            *existing = body.manifest.clone();
        }
    } else {
        plugins.push(body.manifest.clone());
    }

    save_plugin_registry(&plugins)?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "status": "registered",
        "plugin_id": body.manifest.id,
    })))
}

/// DELETE /api/v1/wasm-store/plugins/{plugin_id} - 注销插件
pub async fn unregister_plugin(
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let plugin_id = path.into_inner();
    info!("🔌 注销插件: {}", plugin_id);

    let mut plugins = load_plugin_registry()?;
    let original_len = plugins.len();
    plugins.retain(|p| p.id != plugin_id);

    if plugins.len() == original_len {
        return Err(AppError::NotFound(format!("插件 {} 未找到", plugin_id)));
    }

    save_plugin_registry(&plugins)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "unregistered",
        "plugin_id": plugin_id,
    })))
}
