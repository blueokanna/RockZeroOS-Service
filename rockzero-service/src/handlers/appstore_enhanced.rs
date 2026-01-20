#![allow(dead_code)]
#![allow(unused_variables)]

use actix_web::{web, HttpRequest, HttpResponse};
use blake3::Hasher;
use reqwest::Client;
use rockzero_common::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::{fs, time::SystemTime};

#[cfg(target_os = "linux")]
use std::process::Command;
use tracing::{error, info, warn};
use uuid::Uuid;

const DEFAULT_APPSTORE_ROOT: &str = "./data/appstore";
const CASAOS_STORE_URL: &str = "https://casaos.icewhale.org/store/apps";
const ISTOREOS_STORE_URL: &str = "https://fw.koolcenter.com/iStoreOS/apps";

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum AppPackageKind {
    Wasm,
    Casaos,
    Istoreos,
    Docker,
    Ipk,
}

impl AppPackageKind {
    fn dir_name(&self) -> &'static str {
        match self {
            AppPackageKind::Wasm => "wasm",
            AppPackageKind::Casaos => "casaos",
            AppPackageKind::Istoreos => "istoreos",
            AppPackageKind::Docker => "docker",
            AppPackageKind::Ipk => "ipk",
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
    pub status: AppStatus,
    pub container_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AppStatus {
    Installed,
    Running,
    Stopped,
    Error,
}

#[derive(Debug, Deserialize)]
pub struct PackageInstallRequest {
    pub name: Option<String>,
    pub url: String,
    pub kind: AppPackageKind,
    pub expected_blake3: Option<String>,
    pub manifest_url: Option<String>,
    pub auto_start: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct AppStoreList {
    pub apps: Vec<AppStoreItem>,
    pub total: usize,
    pub source: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppStoreItem {
    pub id: String,
    pub name: String,
    pub title: String,
    pub description: String,
    pub version: String,
    pub icon: Option<String>,
    pub category: String,
    pub author: Option<String>,
    pub source: String, // "casaos", "istoreos", "docker"
    pub install_url: String,
    pub manifest_url: Option<String>,
    pub architectures: Vec<String>,
    pub installed: bool,
}

/// 获取 CasaOS 应用商店列表（无需认证）
pub async fn list_casaos_apps() -> Result<HttpResponse, AppError> {
    info!("🔍 Fetching CasaOS app store...");
    
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| {
            error!("❌ Failed to create HTTP client: {}", e);
            AppError::InternalServerError(e.to_string())
        })?;

    let response = client
        .get(CASAOS_STORE_URL)
        .send()
        .await
        .map_err(|e| {
            error!("❌ Failed to fetch CasaOS store: {}", e);
            AppError::BadRequest(format!("Failed to fetch CasaOS store: {}", e))
        })?;

    if !response.status().is_success() {
        error!("❌ CasaOS store returned error: {}", response.status());
        return Err(AppError::BadRequest("CasaOS store unavailable".to_string()));
    }

    let apps_json: Value = response.json().await.map_err(|e| {
        error!("❌ Failed to parse CasaOS response: {}", e);
        AppError::BadRequest(format!("Invalid response from CasaOS store: {}", e))
    })?;

    let installed_packages = load_packages()?;
    let installed_ids: HashMap<String, bool> = installed_packages
        .iter()
        .map(|p| (p.id.clone(), true))
        .collect();

    let mut apps = Vec::new();
    if let Some(app_list) = apps_json.as_array() {
        for app in app_list {
            if let Some(item) = parse_casaos_app(app, &installed_ids) {
                apps.push(item);
            }
        }
    }

    let total = apps.len();
    info!("✅ Found {} CasaOS apps", total);

    Ok(HttpResponse::Ok().json(AppStoreList {
        apps,
        total,
        source: "casaos".to_string(),
    }))
}

fn parse_casaos_app(app: &Value, installed: &HashMap<String, bool>) -> Option<AppStoreItem> {
    let id = app.get("id")?.as_str()?.to_string();
    let name = app.get("name")?.as_str()?.to_string();
    let title = app.get("title")?.as_str()?.to_string();
    let description = app.get("description")?.as_str().unwrap_or("").to_string();
    let version = app.get("version")?.as_str()?.to_string();
    let icon = app.get("icon").and_then(|v| v.as_str()).map(|s| s.to_string());
    let category = app.get("category").and_then(|v| v.as_str()).unwrap_or("Other").to_string();
    let author = app.get("author").and_then(|v| v.as_str()).map(|s| s.to_string());
    let install_url = app.get("compose_url")?.as_str()?.to_string();
    
    let architectures = app
        .get("arch")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_else(|| vec!["amd64".to_string(), "arm64".to_string()]);

    Some(AppStoreItem {
        id: id.clone(),
        name,
        title,
        description,
        version,
        icon,
        category,
        author,
        source: "casaos".to_string(),
        install_url,
        manifest_url: None,
        architectures,
        installed: installed.contains_key(&id),
    })
}

/// 获取 iStoreOS 应用商店列表（无需认证）
pub async fn list_istoreos_apps() -> Result<HttpResponse, AppError> {
    info!("🔍 Fetching iStoreOS app store...");
    
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    let response = client
        .get(ISTOREOS_STORE_URL)
        .send()
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to fetch iStoreOS store: {}", e)))?;

    if !response.status().is_success() {
        return Err(AppError::BadRequest("iStoreOS store unavailable".to_string()));
    }

    let apps_json: Value = response.json().await.map_err(|e| {
        AppError::BadRequest(format!("Invalid response from iStoreOS store: {}", e))
    })?;

    let installed_packages = load_packages()?;
    let installed_ids: HashMap<String, bool> = installed_packages
        .iter()
        .map(|p| (p.id.clone(), true))
        .collect();

    let mut apps = Vec::new();
    if let Some(app_list) = apps_json.as_array() {
        for app in app_list {
            if let Some(item) = parse_istoreos_app(app, &installed_ids) {
                apps.push(item);
            }
        }
    }

    let total = apps.len();
    info!("✅ Found {} iStoreOS apps", total);

    Ok(HttpResponse::Ok().json(AppStoreList {
        apps,
        total,
        source: "istoreos".to_string(),
    }))
}

fn parse_istoreos_app(app: &Value, installed: &HashMap<String, bool>) -> Option<AppStoreItem> {
    let name = app.get("name")?.as_str()?.to_string();
    let id = format!("istoreos_{}", name);
    let title = app.get("title").and_then(|v| v.as_str()).unwrap_or(&name).to_string();
    let description = app.get("summary")?.as_str()?.to_string();
    let version = app.get("version")?.as_str()?.to_string();
    let icon = app.get("icon").and_then(|v| v.as_str()).map(|s| s.to_string());
    let category = app.get("category").and_then(|v| v.as_str()).unwrap_or("Other").to_string();
    let author = app.get("maintainer").and_then(|v| v.as_str()).map(|s| s.to_string());
    let install_url = app.get("download_url")?.as_str()?.to_string();
    
    let architectures = app
        .get("platforms")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_else(|| vec!["all".to_string()]);

    Some(AppStoreItem {
        id: id.clone(),
        name,
        title,
        description,
        version,
        icon,
        category,
        author,
        source: "istoreos".to_string(),
        install_url,
        manifest_url: None,
        architectures,
        installed: installed.contains_key(&id),
    })
}

/// 安装 IPK 包
pub async fn install_ipk_package(
    body: web::Json<PackageInstallRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    info!("📦 Installing IPK package from {}", body.url);

    let client = Client::builder()
        .build()
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    let response = client
        .get(&body.url)
        .send()
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    if !response.status().is_success() {
        return Err(AppError::BadRequest("Failed to download IPK package".to_string()));
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

    let dir = ensure_storage(&AppPackageKind::Ipk)?;
    let filename = body
        .name
        .clone()
        .unwrap_or_else(|| body.url.rsplit('/').next().unwrap_or("package.ipk").to_string());
    let safe_filename = sanitize_filename(&filename);
    let target = dir.join(&safe_filename);

    fs::write(&target, &bytes).map_err(|e| AppError::IoError(e.to_string()))?;

    #[cfg(target_os = "linux")]
    {
        // 使用 opkg 安装
        info!("🔧 Installing IPK with opkg...");
        let output = Command::new("opkg")
            .args(["install", target.to_str().unwrap()])
            .output()
            .map_err(|e| AppError::BadRequest(format!("Failed to run opkg: {}", e)))?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            error!("❌ IPK installation failed: {}", err);
            return Err(AppError::BadRequest(format!("IPK installation failed: {}", err)));
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        warn!("⚠️ IPK installation is only supported on Linux");
    }

    let mut packages = load_packages()?;
    let record = AppPackage {
        id: Uuid::new_v4().to_string(),
        name: safe_filename,
        kind: AppPackageKind::Ipk,
        source_url: body.url.clone(),
        installed_path: target.to_str().unwrap().to_string(),
        blake3: digest,
        size_bytes: bytes.len() as u64,
        created_at: now_epoch_seconds(),
        manifest: None,
        status: AppStatus::Installed,
        container_id: None,
    };

    packages.push(record.clone());
    save_packages(&packages)?;

    info!("✅ IPK package installed successfully");
    Ok(HttpResponse::Created().json(record))
}

// Helper functions
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
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
