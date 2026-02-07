#![allow(dead_code)]
#![allow(unused_variables)]

use actix_web::{web, HttpRequest, HttpResponse};
use blake3::Hasher;
use reqwest::Client;
use rockzero_common::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::{fs, time::SystemTime};
use tracing::{error, info, warn};
use uuid::Uuid;

const DEFAULT_APPSTORE_ROOT: &str = "./data/appstore";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WasmAppPackage {
    pub id: String,
    pub name: String,
    pub source_url: String,
    pub installed_path: String,
    pub blake3: String,
    pub size_bytes: u64,
    pub created_at: i64,
    pub manifest: Option<Value>,
    pub status: WasmAppStatus,
    pub version: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub icon_url: Option<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum WasmAppStatus {
    Installed,
    Running,
    Stopped,
    Error,
}

#[derive(Debug, Deserialize)]
pub struct WasmInstallRequest {
    pub name: Option<String>,
    pub url: String,
    pub expected_blake3: Option<String>,
    pub manifest_url: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub icon_url: Option<String>,
    pub permissions: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct WasmAppList {
    pub apps: Vec<WasmAppPackage>,
    pub total: usize,
}

#[derive(Debug, Deserialize)]
pub struct UpdateStatusRequest {
    pub status: WasmAppStatus,
}

fn appstore_root() -> PathBuf {
    std::env::var("APPSTORE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_APPSTORE_ROOT))
}

fn index_path(root: &Path) -> PathBuf {
    root.join("wasm_enhanced_index.json")
}

fn ensure_wasm_storage() -> Result<PathBuf, AppError> {
    let root = appstore_root();
    fs::create_dir_all(&root).map_err(|e| AppError::IoError(e.to_string()))?;

    let dir = root.join("wasm");
    fs::create_dir_all(&dir).map_err(|e| AppError::IoError(e.to_string()))?;
    Ok(dir)
}

fn load_packages() -> Result<Vec<WasmAppPackage>, AppError> {
    let root = appstore_root();
    fs::create_dir_all(&root).map_err(|e| AppError::IoError(e.to_string()))?;
    let path = index_path(&root);

    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read_to_string(&path).map_err(|e| AppError::IoError(e.to_string()))?;
    serde_json::from_str(&data).map_err(|e| AppError::BadRequest(e.to_string()))
}

fn save_packages(entries: &[WasmAppPackage]) -> Result<(), AppError> {
    let root = appstore_root();
    fs::create_dir_all(&root).map_err(|e| AppError::IoError(e.to_string()))?;
    let path = index_path(&root);
    let serialized = serde_json::to_string_pretty(entries)
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;
    fs::write(path, serialized).map_err(|e| AppError::IoError(e.to_string()))
}

fn sanitize_filename(name: &str) -> String {
    name.replace(['/', '\\'], "_").replace("..", "_")
}

fn blake3_hex(bytes: &[u8]) -> String {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

fn now_epoch_seconds() -> i64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// GET /api/v1/appstore-enhanced/wasm/apps - 列出所有已安装的 WASM 应用
pub async fn list_wasm_apps() -> Result<HttpResponse, AppError> {
    info!("📦 Listing enhanced WASM apps");

    let packages = match load_packages() {
        Ok(pkgs) => {
            info!("✅ Found {} WASM apps", pkgs.len());
            pkgs
        }
        Err(e) => {
            warn!("⚠️ Failed to load WASM apps: {:?}, returning empty list", e);
            Vec::new()
        }
    };

    let total = packages.len();
    Ok(HttpResponse::Ok().json(WasmAppList {
        apps: packages,
        total,
    }))
}

/// GET /api/v1/appstore-enhanced/wasm/apps/{id} - 获取单个 WASM 应用详情
pub async fn get_wasm_app(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let app_id = path.into_inner();
    info!("📦 Getting WASM app details: {}", app_id);

    let packages = load_packages()?;
    let package = packages
        .iter()
        .find(|p| p.id == app_id)
        .ok_or_else(|| AppError::NotFound(format!("WASM app {} not found", app_id)))?;

    Ok(HttpResponse::Ok().json(package))
}

/// POST /api/v1/appstore-enhanced/wasm/install - 安装 WASM 应用（增强版，带验证和元数据）
pub async fn install_wasm_app(
    body: web::Json<WasmInstallRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    info!("📦 Installing WASM app from {}", body.url);

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    let response = client
        .get(&body.url)
        .send()
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to download WASM package: {}", e)))?;

    if !response.status().is_success() {
        return Err(AppError::BadRequest(
            "Failed to download WASM package".to_string(),
        ));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to read response: {}", e)))?;

    let digest = blake3_hex(&bytes);
    if let Some(expected) = &body.expected_blake3 {
        if expected != &digest {
            return Err(AppError::PreconditionFailed(format!(
                "BLAKE3 mismatch: expected {}, got {}",
                expected, digest
            )));
        }
    }

    // Validate that the downloaded bytes are a valid WASM module
    let engine = wasmtime::Engine::default();
    wasmtime::Module::new(&engine, &bytes)
        .map_err(|e| AppError::BadRequest(format!("Invalid WASM module: {}", e)))?;

    let dir = ensure_wasm_storage()?;
    let filename = body.name.clone().unwrap_or_else(|| {
        body.url
            .rsplit('/')
            .next()
            .unwrap_or("module.wasm")
            .to_string()
    });
    let safe_filename = sanitize_filename(&filename);
    let target = dir.join(&safe_filename);

    if target.exists() {
        return Err(AppError::Conflict(
            "WASM package already exists".to_string(),
        ));
    }

    fs::write(&target, &bytes).map_err(|e| AppError::IoError(e.to_string()))?;

    // Fetch optional manifest
    let manifest = if let Some(manifest_url) = &body.manifest_url {
        if !manifest_url.is_empty() {
            match client.get(manifest_url).send().await {
                Ok(resp) if resp.status().is_success() => match resp.text().await {
                    Ok(text) => serde_json::from_str::<Value>(&text).ok(),
                    Err(e) => {
                        warn!("Failed to read manifest response: {}", e);
                        None
                    }
                },
                Ok(resp) => {
                    warn!("Manifest download returned status: {}", resp.status());
                    None
                }
                Err(e) => {
                    warn!("Failed to download manifest: {}", e);
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    let mut packages = load_packages()?;
    let record = WasmAppPackage {
        id: Uuid::new_v4().to_string(),
        name: safe_filename,
        source_url: body.url.clone(),
        installed_path: target.to_str().unwrap_or(DEFAULT_APPSTORE_ROOT).to_string(),
        blake3: digest.clone(),
        size_bytes: bytes.len() as u64,
        created_at: now_epoch_seconds(),
        manifest,
        status: WasmAppStatus::Installed,
        version: body.version.clone(),
        description: body.description.clone(),
        author: body.author.clone(),
        icon_url: body.icon_url.clone(),
        permissions: body.permissions.clone().unwrap_or_default(),
    };

    packages.push(record.clone());
    save_packages(&packages)?;

    info!(
        "✅ WASM app installed: {} (blake3: {})",
        record.name, digest
    );
    Ok(HttpResponse::Created().json(record))
}

/// DELETE /api/v1/appstore-enhanced/wasm/apps/{id} - 卸载 WASM 应用
pub async fn uninstall_wasm_app(
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let app_id = path.into_inner();
    info!("🗑️ Uninstalling WASM app: {}", app_id);

    let mut packages = load_packages()?;

    if let Some(index) = packages.iter().position(|p| p.id == app_id) {
        let entry = packages.remove(index);
        if !entry.installed_path.is_empty() {
            let file_path = Path::new(&entry.installed_path);
            if file_path.exists() {
                if let Err(e) = fs::remove_file(file_path) {
                    warn!("Failed to remove WASM file {}: {}", entry.installed_path, e);
                }
            }
        }
        save_packages(&packages)?;

        info!("✅ WASM app uninstalled: {}", entry.name);
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "removed",
            "id": app_id,
            "name": entry.name,
        })));
    }

    Err(AppError::NotFound(format!("WASM app {} not found", app_id)))
}

/// PUT /api/v1/appstore-enhanced/wasm/apps/{id}/status - 更新 WASM 应用状态
pub async fn update_wasm_app_status(
    path: web::Path<String>,
    body: web::Json<UpdateStatusRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let app_id = path.into_inner();
    info!(
        "📦 Updating WASM app status: {} -> {:?}",
        app_id, body.status
    );

    let mut packages = load_packages()?;

    if let Some(app) = packages.iter_mut().find(|p| p.id == app_id) {
        app.status = body.status.clone();
        save_packages(&packages)?;

        info!(
            "✅ WASM app status updated: {} -> {:?}",
            app_id, body.status
        );
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "updated",
            "id": app_id,
            "new_status": body.status,
        })));
    }

    Err(AppError::NotFound(format!("WASM app {} not found", app_id)))
}

/// POST /api/v1/appstore-enhanced/wasm/apps/{id}/run - 运行 WASM 应用
pub async fn run_wasm_app(
    path: web::Path<String>,
    body: web::Json<RunWasmAppRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let app_id = path.into_inner();
    info!("▶️ Running WASM app: {}", app_id);

    let mut packages = load_packages()?;
    let app = packages
        .iter()
        .find(|p| p.id == app_id)
        .ok_or_else(|| AppError::NotFound(format!("WASM app {} not found", app_id)))?;

    let wasm_path = &app.installed_path;
    if !Path::new(wasm_path).exists() {
        return Err(AppError::NotFound(
            "WASM module file not found on disk".to_string(),
        ));
    }

    let engine = wasmtime::Engine::default();
    let module = wasmtime::Module::from_file(&engine, wasm_path)
        .map_err(|e| AppError::BadRequest(format!("Failed to load WASM module: {}", e)))?;

    let mut linker = wasmtime::Linker::new(&engine);
    wasmtime_wasi::add_to_linker(&mut linker, |cx| cx)
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    let mut builder = wasmtime_wasi::sync::WasiCtxBuilder::new();
    builder.inherit_stdio();

    if let Some(args) = &body.args {
        for arg in args {
            builder
                .arg(arg)
                .map_err(|e| AppError::ValidationError(format!("Invalid WASM arg: {}", e)))?;
        }
    }

    if let Some(env) = &body.env {
        for (key, value) in env {
            builder
                .env(key, value)
                .map_err(|e| AppError::ValidationError(format!("Invalid env var: {}", e)))?;
        }
    }

    let mut store = wasmtime::Store::new(&engine, builder.build());
    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| AppError::BadRequest(format!("Failed to instantiate WASM: {}", e)))?;

    let func_name = body
        .function
        .clone()
        .unwrap_or_else(|| "_start".to_string());

    // Update status to Running
    if let Some(app_mut) = packages.iter_mut().find(|p| p.id == app_id) {
        app_mut.status = WasmAppStatus::Running;
        let _ = save_packages(&packages);
    }

    let exec_result = if let Ok(entry) = instance.get_typed_func::<(), ()>(&mut store, &func_name) {
        entry.call(&mut store, ()).map_err(|e| e.to_string())
    } else if let Some(func) = instance.get_func(&mut store, &func_name) {
        func.call(&mut store, &[], &mut [])
            .map_err(|e| e.to_string())
    } else {
        Err(format!("Function '{}' not found in WASM module", func_name))
    };

    // Update status based on result
    let mut packages = load_packages().unwrap_or_default();
    match &exec_result {
        Ok(()) => {
            if let Some(app_mut) = packages.iter_mut().find(|p| p.id == app_id) {
                app_mut.status = WasmAppStatus::Stopped;
                let _ = save_packages(&packages);
            }
            info!("✅ WASM app executed successfully: {}", app_id);
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "status": "completed",
                "id": app_id,
                "function": func_name,
            })))
        }
        Err(err_msg) => {
            if let Some(app_mut) = packages.iter_mut().find(|p| p.id == app_id) {
                app_mut.status = WasmAppStatus::Error;
                let _ = save_packages(&packages);
            }
            error!("❌ WASM app execution failed: {}: {}", app_id, err_msg);
            Err(AppError::BadRequest(format!(
                "WASM execution failed: {}",
                err_msg
            )))
        }
    }
}

/// 运行 WASM 应用请求
#[derive(Debug, Deserialize)]
pub struct RunWasmAppRequest {
    pub function: Option<String>,
    pub args: Option<Vec<String>>,
    pub env: Option<std::collections::HashMap<String, String>>,
}

/// POST /api/v1/appstore-enhanced/wasm/validate - 验证 WASM 模块（不安装）
pub async fn validate_wasm_module(
    body: web::Bytes,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    info!("🔍 Validating WASM module ({} bytes)", body.len());

    if body.is_empty() {
        return Err(AppError::BadRequest(
            "Empty WASM module provided".to_string(),
        ));
    }

    let engine = wasmtime::Engine::default();
    match wasmtime::Module::new(&engine, &body) {
        Ok(module) => {
            let exports: Vec<String> = module
                .exports()
                .map(|e| format!("{}:{:?}", e.name(), e.ty()))
                .collect();
            let imports: Vec<String> = module
                .imports()
                .map(|i| format!("{}::{}", i.module(), i.name()))
                .collect();

            let hash = blake3_hex(&body);

            info!(
                "✅ WASM module is valid ({} exports, {} imports)",
                exports.len(),
                imports.len()
            );
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "valid": true,
                "size_bytes": body.len(),
                "blake3": hash,
                "exports_count": exports.len(),
                "imports_count": imports.len(),
                "exports": exports,
                "imports": imports,
            })))
        }
        Err(e) => {
            warn!("❌ Invalid WASM module: {}", e);
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "valid": false,
                "error": e.to_string(),
                "size_bytes": body.len(),
            })))
        }
    }
}
