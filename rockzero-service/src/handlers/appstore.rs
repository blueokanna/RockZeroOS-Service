#![allow(dead_code)]
#![allow(unused_variables)]

use actix_web::{web, HttpRequest, HttpResponse};
use blake3::Hasher;
use reqwest::Client;
use rockzero_common::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use wasmtime::{Engine, Linker, Module, Store};
use wasmtime_wasi::add_to_linker;
use wasmtime_wasi::sync::WasiCtxBuilder;

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const DEFAULT_APPSTORE_ROOT: &str = "./data/appstore";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WasmPackage {
    pub id: String,
    pub name: String,
    pub source_url: String,
    pub installed_path: String,
    pub blake3: String,
    pub size_bytes: u64,
    pub created_at: i64,
    pub manifest: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct WasmInstallRequest {
    pub name: Option<String>,
    pub url: String,
    pub expected_blake3: Option<String>,
    pub manifest_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RunWasmRequest {
    pub function: Option<String>,
    pub args: Option<Vec<String>>,
}

fn appstore_root() -> PathBuf {
    std::env::var("APPSTORE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_APPSTORE_ROOT))
}

fn index_path(root: &Path) -> PathBuf {
    root.join("wasm_index.json")
}

fn ensure_wasm_storage() -> Result<PathBuf, AppError> {
    let root = appstore_root();
    fs::create_dir_all(&root).map_err(|e| AppError::IoError(e.to_string()))?;

    let dir = root.join("wasm");
    fs::create_dir_all(&dir).map_err(|e| AppError::IoError(e.to_string()))?;
    Ok(dir)
}

fn load_packages() -> Result<Vec<WasmPackage>, AppError> {
    let root = appstore_root();
    fs::create_dir_all(&root).map_err(|e| AppError::IoError(e.to_string()))?;
    let path = index_path(&root);

    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read_to_string(&path).map_err(|e| AppError::IoError(e.to_string()))?;
    serde_json::from_str(&data).map_err(|e| AppError::BadRequest(e.to_string()))
}

fn save_packages(entries: &[WasmPackage]) -> Result<(), AppError> {
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
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

async fn fetch_manifest(client: &Client, url: &str) -> Result<Option<Value>, AppError> {
    if url.is_empty() {
        return Ok(None);
    }

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    if !response.status().is_success() {
        return Err(AppError::BadRequest(
            "Failed to download manifest".to_string(),
        ));
    }

    let text = response
        .text()
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let manifest: Value =
        serde_json::from_str(&text).map_err(|e| AppError::BadRequest(e.to_string()))?;

    Ok(Some(manifest))
}

/// Execute a WASM module in a blocking thread with a 30-second timeout.
/// This prevents WASM execution from blocking the tokio async runtime.
async fn execute_wasm_module(
    wasm_path: &str,
    function: Option<String>,
    args: &[String],
) -> Result<(), AppError> {
    let wasm_path = wasm_path.to_string();
    let args = args.to_vec();

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::task::spawn_blocking(move || -> Result<(), AppError> {
            let engine = Engine::default();
            let module = Module::from_file(&engine, &wasm_path).map_err(|e| {
                AppError::BadRequest(format!("Failed to load WASM module '{}': {}", wasm_path, e))
            })?;

            let mut linker = Linker::new(&engine);
            #[allow(deprecated)]
            add_to_linker(&mut linker, |cx| cx)
                .map_err(|e| AppError::InternalServerError(e.to_string()))?;

            #[allow(deprecated)]
            let mut builder = WasiCtxBuilder::new();
            builder.inherit_stdio();
            let _ = builder.inherit_env();
            for arg in &args {
                builder
                    .arg(arg)
                    .map_err(|e| AppError::ValidationError(format!("Invalid WASM arg '{}': {}", arg, e)))?;
            }

            let mut store = Store::new(&engine, builder.build());
            let instance = linker
                .instantiate(&mut store, &module)
                .map_err(|e| AppError::BadRequest(format!("Failed to instantiate WASM: {}", e)))?;

            let func_name = function.unwrap_or_else(|| "_start".to_string());

            if let Ok(entry) = instance.get_typed_func::<(), ()>(&mut store, &func_name) {
                entry
                    .call(&mut store, ())
                    .map_err(|e| AppError::BadRequest(format!("WASM call failed: {}", e)))?;
                return Ok(());
            }

            if let Some(func) = instance.get_func(&mut store, &func_name) {
                func.call(&mut store, &[], &mut [])
                    .map_err(|e| AppError::BadRequest(format!("WASM call failed: {}", e)))?;
                return Ok(());
            }

            Err(AppError::NotFound(format!(
                "Function '{}' not found in WASM module",
                func_name
            )))
        }),
    )
    .await;

    match result {
        Ok(Ok(inner)) => inner,
        Ok(Err(join_err)) => Err(AppError::InternalServerError(format!(
            "WASM execution task panicked: {}",
            join_err
        ))),
        Err(_timeout) => Err(AppError::InternalServerError(
            "WASM execution timed out (30s)".to_string(),
        )),
    }
}

pub async fn list_packages(_req: HttpRequest) -> Result<HttpResponse, AppError> {
    tracing::info!("📦 Listing WASM packages");

    let packages = match load_packages() {
        Ok(pkgs) => {
            tracing::info!("✅ Found {} WASM packages", pkgs.len());
            pkgs
        }
        Err(e) => {
            tracing::warn!(
                "⚠️ Failed to load WASM packages: {:?}, returning empty list",
                e
            );
            Vec::new()
        }
    };

    Ok(HttpResponse::Ok().json(packages))
}

pub async fn install_package(
    body: web::Json<WasmInstallRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let client = Client::builder()
        .build()
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    let response = client
        .get(&body.url)
        .send()
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    if !response.status().is_success() {
        return Err(AppError::BadRequest(
            "Failed to download WASM package".to_string(),
        ));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let digest = blake3_hex(&bytes);
    if let Some(expected) = &body.expected_blake3 {
        if expected != &digest {
            return Err(AppError::PreconditionFailed("BLAKE3 mismatch".to_string()));
        }
    }

    // Validate that the downloaded bytes are a valid WASM module
    let engine = Engine::default();
    Module::new(&engine, &bytes)
        .map_err(|e| AppError::BadRequest(format!("Invalid WASM module: {}", e)))?;

    let dir = ensure_wasm_storage()?;
    let filename = body
        .name
        .clone()
        .unwrap_or_else(|| body.url.rsplit('/').next().unwrap_or("module.wasm").to_string());
    let safe_filename = sanitize_filename(&filename);
    let target = dir.join(&safe_filename);

    if target.exists() {
        return Err(AppError::Conflict(
            "WASM package already exists".to_string(),
        ));
    }

    fs::write(&target, &bytes).map_err(|e| AppError::IoError(e.to_string()))?;

    let manifest = if let Some(manifest_url) = &body.manifest_url {
        fetch_manifest(&client, manifest_url).await?
    } else {
        None
    };

    let mut packages = load_packages()?;
    let record = WasmPackage {
        id: Uuid::new_v4().to_string(),
        name: safe_filename,
        source_url: body.url.clone(),
        installed_path: target
            .to_str()
            .unwrap_or(DEFAULT_APPSTORE_ROOT)
            .to_string(),
        blake3: digest,
        size_bytes: bytes.len() as u64,
        created_at: now_epoch_seconds(),
        manifest,
    };

    packages.push(record.clone());
    save_packages(&packages)?;

    Ok(HttpResponse::Created().json(record))
}

pub async fn remove_package(
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let package_id = path.into_inner();
    let mut packages = load_packages()?;

    if let Some(index) = packages.iter().position(|p| p.id == package_id) {
        let entry = packages.remove(index);
        if !entry.installed_path.is_empty() {
            let _ = fs::remove_file(Path::new(&entry.installed_path));
        }
        save_packages(&packages)?;

        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "removed",
            "id": package_id,
        })));
    }

    Err(AppError::NotFound("WASM package not found".to_string()))
}

pub async fn run_wasm_package(
    path: web::Path<String>,
    body: web::Json<RunWasmRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let package_id = path.into_inner();
    let packages = load_packages()?;
    let package = packages
        .iter()
        .find(|p| p.id == package_id)
        .ok_or_else(|| AppError::NotFound("WASM package not found".to_string()))?;

    let args = body.args.clone().unwrap_or_default();
    execute_wasm_module(&package.installed_path, body.function.clone(), &args).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "executed",
        "id": package_id,
        "function": body.function.clone().unwrap_or_else(|| "_start".to_string()),
        "args": args,
    })))
}
