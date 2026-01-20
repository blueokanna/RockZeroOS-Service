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

#[cfg(target_os = "linux")]
use std::process::Command;

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
const DEFAULT_APPSTORE_ROOT: &str = "./data/appstore";

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum AppPackageKind {
    Wasm,
    Casaos,
    Istoreos,
    Docker,
}

impl AppPackageKind {
    fn dir_name(&self) -> &'static str {
        match self {
            AppPackageKind::Wasm => "wasm",
            AppPackageKind::Casaos => "casaos",
            AppPackageKind::Istoreos => "istoreos",
            AppPackageKind::Docker => "docker",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppPackage {
    pub id: String,
    pub name: String,
    pub kind: AppPackageKind,
    pub source_url: String,
    pub installed_path: String,
    pub blake3: String,
    pub size_bytes: u64,
    pub created_at: i64,
    pub manifest: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct PackageInstallRequest {
    pub name: Option<String>,
    pub url: String,
    pub kind: AppPackageKind,
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
    root.join("index.json")
}

fn ensure_storage(kind: &AppPackageKind) -> Result<PathBuf, AppError> {
    let root = appstore_root();
    fs::create_dir_all(&root).map_err(|e| AppError::IoError(e.to_string()))?;

    let dir = root.join(kind.dir_name());
    fs::create_dir_all(&dir).map_err(|e| AppError::IoError(e.to_string()))?;
    Ok(dir)
}

fn load_packages() -> Result<Vec<AppPackage>, AppError> {
    let root = appstore_root();
    fs::create_dir_all(&root).map_err(|e| AppError::IoError(e.to_string()))?;
    let path = index_path(&root);

    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read_to_string(&path).map_err(|e| AppError::IoError(e.to_string()))?;
    serde_json::from_str(&data).map_err(|e| AppError::BadRequest(e.to_string()))
}

fn save_packages(entries: &[AppPackage]) -> Result<(), AppError> {
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
        return Err(AppError::BadRequest("Failed to download manifest".to_string()));
    }

    let text = response
        .text()
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let manifest: Value = serde_json::from_str(&text)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    Ok(Some(manifest))
}

fn require_string(manifest: &Value, key: &str, context: &str) -> Result<(), AppError> {
    if !manifest
        .get(key)
        .map(|v| v.is_string())
        .unwrap_or(false)
    {
        return Err(AppError::ValidationError(format!(
            "{} manifest missing required string field '{}'",
            context, key
        )));
    }
    Ok(())
}

fn require_string_array(manifest: &Value, key: &str, context: &str) -> Result<(), AppError> {
    if !manifest
        .get(key)
        .map(|v| v.as_array().map(|arr| arr.iter().all(|i| i.is_string())).unwrap_or(false))
        .unwrap_or(false)
    {
        return Err(AppError::ValidationError(format!(
            "{} manifest '{}' must be an array of strings",
            context, key
        )));
    }
    Ok(())
}

fn validate_casaos_manifest(manifest: &Value) -> Result<(), AppError> {
    require_string(manifest, "id", "CasaOS")?;
    require_string(manifest, "title", "CasaOS")?;
    require_string(manifest, "version", "CasaOS")?;
    require_string(manifest, "description", "CasaOS")?;
    require_string_array(manifest, "arch", "CasaOS")?;
    Ok(())
}

fn validate_istoreos_manifest(manifest: &Value) -> Result<(), AppError> {
    require_string(manifest, "name", "IStoreOS")?;
    require_string(manifest, "version", "IStoreOS")?;
    require_string(manifest, "summary", "IStoreOS")?;
    require_string_array(manifest, "platforms", "IStoreOS")?;
    Ok(())
}

fn validate_manifest(kind: &AppPackageKind, manifest: &Option<Value>) -> Result<(), AppError> {
    match kind {
        AppPackageKind::Casaos => {
            let doc = manifest
                .as_ref()
                .ok_or_else(|| AppError::ValidationError("CasaOS manifest is required".to_string()))?;
            validate_casaos_manifest(doc)
        }
        AppPackageKind::Istoreos => {
            let doc = manifest
                .as_ref()
                .ok_or_else(|| AppError::ValidationError("IStoreOS manifest is required".to_string()))?;
            validate_istoreos_manifest(doc)
        }
        _ => Ok(()),
    }
}

async fn execute_wasm_module(
    wasm_path: &str,
    function: Option<String>,
    args: &[String],
) -> Result<(), AppError> {
    let engine = Engine::default();
    let module = Module::from_file(&engine, wasm_path).map_err(|e| {
        AppError::BadRequest(format!("Failed to load WASM module '{}': {}", wasm_path, e))
    })?;

    let mut linker = Linker::new(&engine);
    add_to_linker(&mut linker, |cx| cx).map_err(|e| AppError::InternalServerError(e.to_string()))?;

    let mut builder = WasiCtxBuilder::new();
    builder.inherit_stdio();
    let _ = builder.inherit_env();
    for arg in args {
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
}

pub async fn list_packages(_req: HttpRequest) -> Result<HttpResponse, AppError> {
    // Allow listing packages without FIDO2 - read-only operation
    // JWT authentication is handled by middleware if configured
    let packages = load_packages()?;
    Ok(HttpResponse::Ok().json(packages))
}

pub async fn install_package(
    body: web::Json<PackageInstallRequest>,
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
        return Err(AppError::BadRequest("Failed to download package".to_string()));
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

    let dir = ensure_storage(&body.kind)?;
    let filename = body
        .name
        .clone()
        .unwrap_or_else(|| body.url.rsplit('/').next().unwrap_or("package.bin").to_string());
    let safe_filename = sanitize_filename(&filename);
    let target = dir.join(&safe_filename);

    if target.exists() {
        return Err(AppError::Conflict("Package already exists".to_string()));
    }

    fs::write(&target, &bytes).map_err(|e| AppError::IoError(e.to_string()))?;

    let manifest = if let Some(manifest_url) = &body.manifest_url {
        fetch_manifest(&client, manifest_url).await?
    } else {
        None
    };

    validate_manifest(&body.kind, &manifest)?;

    let mut packages = load_packages()?;
    let record = AppPackage {
        id: Uuid::new_v4().to_string(),
        name: safe_filename,
        kind: body.kind.clone(),
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

    Err(AppError::NotFound("Package not found".to_string()))
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
        .ok_or_else(|| AppError::NotFound("Package not found".to_string()))?;

    if !matches!(package.kind, AppPackageKind::Wasm) {
        return Err(AppError::BadRequest("Package is not a WASM bundle".to_string()));
    }

    let args = body.args.clone().unwrap_or_default();
    execute_wasm_module(&package.installed_path, body.function.clone(), &args).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "executed",
        "id": package_id,
        "function": body.function.clone().unwrap_or_else(|| "_start".to_string()),
        "args": args,
    })))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DockerContainer {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub ports: Vec<String>,
    pub created: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DockerImage {
    pub id: String,
    pub repository: String,
    pub tag: String,
    pub size: u64,
    pub created: i64,
}

#[derive(Debug, Deserialize)]
pub struct CreateContainerRequest {
    pub name: String,
    pub image: String,
    pub ports: Vec<String>,
    pub volumes: Vec<String>,
    pub env: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct PullImageRequest {
    pub image: String,
    pub tag: Option<String>,
}

pub async fn list_containers(_req: HttpRequest) -> Result<HttpResponse, AppError> {
    // Allow listing containers without FIDO2 - read-only operation
    // JWT authentication is handled by middleware if configured

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("docker")
            .args(&["ps", "-a", "--format", "{{json .}}"])
            .output()
            .map_err(|_| AppError::InternalError)?;

        if !output.status.success() {
            return Err(AppError::InternalError);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let containers: Vec<DockerContainer> = stdout
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();

        Ok(HttpResponse::Ok().json(containers))
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(HttpResponse::Ok().json(Vec::<DockerContainer>::new()))
    }
}

pub async fn list_images(_req: HttpRequest) -> Result<HttpResponse, AppError> {
    // Allow listing images without FIDO2 - read-only operation
    // JWT authentication is handled by middleware if configured

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("docker")
            .args(&["images", "--format", "{{json .}}"])
            .output()
            .map_err(|_| AppError::InternalError)?;

        if !output.status.success() {
            return Err(AppError::InternalError);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let images: Vec<DockerImage> = stdout
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();

        Ok(HttpResponse::Ok().json(images))
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(HttpResponse::Ok().json(Vec::<DockerImage>::new()))
    }
}

pub async fn create_container(
    body: web::Json<CreateContainerRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    #[cfg(target_os = "linux")]
    {
        let mut args = vec!["run", "-d", "--name", &body.name];

        for port in &body.ports {
            args.push("-p");
            args.push(port);
        }

        for volume in &body.volumes {
            args.push("-v");
            args.push(volume);
        }

        for env in &body.env {
            args.push("-e");
            args.push(env);
        }

        args.push(&body.image);

        let output = Command::new("docker")
            .args(&args)
            .output()
            .map_err(|_| AppError::InternalError)?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(AppError::BadRequest(error.to_string()));
        }

        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

        Ok(HttpResponse::Created().json(serde_json::json!({
            "container_id": container_id,
            "name": body.name,
        })))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = body;
        Ok(HttpResponse::NotImplemented().json(serde_json::json!({
            "error": "Docker not supported on this platform"
        })))
    }
}

pub async fn start_container(
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let container_id = path.into_inner();

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("docker")
            .args(&["start", &container_id])
            .output()
            .map_err(|_| AppError::InternalError)?;

        if !output.status.success() {
            return Err(AppError::BadRequest("Failed to start container".to_string()));
        }

        Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "started",
            "container_id": container_id,
        })))
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(HttpResponse::NotImplemented().finish())
    }
}

pub async fn stop_container(
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let container_id = path.into_inner();

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("docker")
            .args(&["stop", &container_id])
            .output()
            .map_err(|_| AppError::InternalError)?;

        if !output.status.success() {
            return Err(AppError::BadRequest("Failed to stop container".to_string()));
        }

        Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "stopped",
            "container_id": container_id,
        })))
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(HttpResponse::NotImplemented().finish())
    }
}

pub async fn remove_container(
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let container_id = path.into_inner();

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("docker")
            .args(&["rm", "-f", &container_id])
            .output()
            .map_err(|_| AppError::InternalError)?;

        if !output.status.success() {
            return Err(AppError::BadRequest("Failed to remove container".to_string()));
        }

        Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "removed",
            "container_id": container_id,
        })))
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(HttpResponse::NotImplemented().finish())
    }
}

pub async fn pull_image(
    body: web::Json<PullImageRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    #[cfg(target_os = "linux")]
    {
        let image_name = if let Some(tag) = &body.tag {
            format!("{}:{}", body.image, tag)
        } else {
            body.image.clone()
        };

        let output = Command::new("docker")
            .args(&["pull", &image_name])
            .output()
            .map_err(|_| AppError::InternalError)?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(AppError::BadRequest(error.to_string()));
        }

        Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "pulled",
            "image": image_name,
        })))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = body;
        Ok(HttpResponse::NotImplemented().finish())
    }
}

pub async fn remove_image(
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let image_id = path.into_inner();

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("docker")
            .args(&["rmi", "-f", &image_id])
            .output()
            .map_err(|_| AppError::InternalError)?;

        if !output.status.success() {
            return Err(AppError::BadRequest("Failed to remove image".to_string()));
        }

        Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "removed",
            "image_id": image_id,
        })))
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(HttpResponse::NotImplemented().finish())
    }
}

pub async fn get_container_logs(
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let container_id = path.into_inner();

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("docker")
            .args(&["logs", "--tail", "100", &container_id])
            .output()
            .map_err(|_| AppError::InternalError)?;

        let logs = String::from_utf8_lossy(&output.stdout).to_string();

        Ok(HttpResponse::Ok().json(serde_json::json!({
            "container_id": container_id,
            "logs": logs,
        })))
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(HttpResponse::NotImplemented().finish())
    }
}

pub async fn get_container_stats(
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let container_id = path.into_inner();

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("docker")
            .args(&["stats", "--no-stream", "--format", "{{json .}}", &container_id])
            .output()
            .map_err(|_| AppError::InternalError)?;

        if !output.status.success() {
            return Err(AppError::BadRequest("Failed to get stats".to_string()));
        }

        let stats = String::from_utf8_lossy(&output.stdout);
        let stats_json: serde_json::Value = serde_json::from_str(&stats)
            .unwrap_or_else(|_| serde_json::json!({}));

        Ok(HttpResponse::Ok().json(stats_json))
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(HttpResponse::NotImplemented().finish())
    }
}
