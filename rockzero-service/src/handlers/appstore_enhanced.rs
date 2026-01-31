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
use tracing::warn;

#[cfg(target_os = "linux")]
use std::process::Command;
use tracing::{error, info};
use uuid::Uuid;

const DEFAULT_APPSTORE_ROOT: &str = "./data/appstore";
const ISTOREOS_STORE_URL: &str = "https://fw.koolcenter.com/iStoreOS/apps";

// CasaOS App Store URLs - 使用多个镜像源
const CASAOS_STORE_URLS: &[&str] = &[
    // 优先使用 Cp0204 的 AppStore-Play 镜像
    "https://play.cuse.eu.org/Cp0204-AppStore-Play/apps.json",
    "https://cdn.jsdelivr.net/gh/Cp0204/CasaOS-AppStore-Play@main/Apps/apps.json",
    // 备用源
    "https://raw.githubusercontent.com/Cp0204/CasaOS-AppStore-Play/main/Apps/apps.json",
    "https://raw.githubusercontent.com/bigbeartechworld/big-bear-casaos/master/Apps/big-bear-casaos-apps.json",
    "https://raw.githubusercontent.com/WisdomSky/CasaOS-Coolstore/main/apps.json",
];

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum AppPackageKind {
    Wasm,
    Docker,
    Ipk,
}

impl AppPackageKind {
    fn dir_name(&self) -> &'static str {
        match self {
            AppPackageKind::Wasm => "wasm",
            AppPackageKind::Docker => "docker",
            AppPackageKind::Ipk => "ipk",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            AppPackageKind::Wasm => "WASM Application",
            AppPackageKind::Docker => "Docker Container (CasaOS)",
            AppPackageKind::Ipk => "IPK Package (iStoreOS/OpenWRT)",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            AppPackageKind::Wasm => "Custom WASM-based online application with flexible rules",
            AppPackageKind::Docker => "Docker-based application from CasaOS App Store",
            AppPackageKind::Ipk => "OpenWRT IPK package from iStoreOS",
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

pub async fn list_casaos_apps() -> Result<HttpResponse, AppError> {
    info!("Fetching CasaOS app store...");

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(10))
        .pool_idle_timeout(std::time::Duration::from_secs(90))
        .pool_max_idle_per_host(10)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        .gzip(true)
        .brotli(true)
        .deflate(true)
        .use_rustls_tls()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| {
            error!("Failed to create HTTP client: {}", e);
            AppError::InternalServerError(e.to_string())
        })?;

    let mut last_error = String::new();
    
    for store_url in CASAOS_STORE_URLS {
        for attempt in 1..=2 {
            info!("Attempt {} to fetch CasaOS store from {}", attempt, store_url);

            match client
                .get(*store_url)
                .header("Accept", "application/json, text/plain, */*")
                .header("Accept-Language", "en-US,en;q=0.9")
                .header("Cache-Control", "no-cache")
                .header("Connection", "keep-alive")
                .send()
                .await
            {
                Ok(response) => {
                    let status = response.status();
                    info!("Response status: {}", status);

                    if !status.is_success() {
                        error!("CasaOS store returned error: {}", status);
                        last_error = format!("CasaOS store returned status: {}", status);
                        if attempt < 2 {
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            continue;
                        }
                    } else {
                        match response.text().await {
                            Ok(text) => {
                                info!("Received {} bytes of data", text.len());

                                match serde_json::from_str::<Value>(&text) {
                                    Ok(apps_json) => {
                                        let installed_packages = load_packages()?;
                                        let installed_ids: HashMap<String, bool> = installed_packages
                                            .iter()
                                            .map(|p| (p.id.clone(), true))
                                            .collect();

                                        let mut apps = Vec::new();
                                        
                                        if let Some(app_list) = apps_json.as_array() {
                                            info!("Processing {} apps from CasaOS store", app_list.len());
                                            for app in app_list {
                                                if let Some(item) = parse_casaos_app(app, &installed_ids) {
                                                    apps.push(item);
                                                }
                                            }
                                        } else if let Some(data) = apps_json.get("data").and_then(|d| d.as_array()) {
                                            info!("Processing {} apps from CasaOS store (nested data)", data.len());
                                            for app in data {
                                                if let Some(item) = parse_casaos_app(app, &installed_ids) {
                                                    apps.push(item);
                                                }
                                            }
                                        } else if let Some(data) = apps_json.get("apps").and_then(|d| d.as_array()) {
                                            info!("Processing {} apps from CasaOS store (apps field)", data.len());
                                            for app in data {
                                                if let Some(item) = parse_casaos_app(app, &installed_ids) {
                                                    apps.push(item);
                                                }
                                            }
                                        } else if apps_json.is_object() {
                                            info!("Processing apps from CasaOS store (object format)");
                                            for (key, app) in apps_json.as_object().unwrap() {
                                                if app.is_object() {
                                                    let mut app_with_id = app.clone();
                                                    if app_with_id.get("id").is_none() {
                                                        if let Some(obj) = app_with_id.as_object_mut() {
                                                            obj.insert("id".to_string(), Value::String(key.clone()));
                                                        }
                                                    }
                                                    if let Some(item) = parse_casaos_app(&app_with_id, &installed_ids) {
                                                        apps.push(item);
                                                    }
                                                }
                                            }
                                        } else {
                                            warn!("Unexpected JSON structure from CasaOS store");
                                        }

                                        let total = apps.len();
                                        info!("Successfully parsed {} CasaOS apps", total);

                                        return Ok(HttpResponse::Ok().json(AppStoreList {
                                            apps,
                                            total,
                                            source: "casaos".to_string(),
                                        }));
                                    }
                                    Err(e) => {
                                        error!("Failed to parse JSON: {}", e);
                                        last_error = format!("Invalid JSON from CasaOS store: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to read response text: {}", e);
                                last_error = format!("Failed to read response: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Network error (attempt {}): {}", attempt, e);
                    last_error = format!("Network error: {}", e);
                    if attempt < 2 {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        continue;
                    }
                }
            }
        }
    }

    warn!("CasaOS store unavailable, returning empty list. Last error: {}", last_error);
    Ok(HttpResponse::Ok().json(AppStoreList {
        apps: Vec::new(),
        total: 0,
        source: "casaos".to_string(),
    }))
}

fn parse_casaos_app(app: &Value, installed: &HashMap<String, bool>) -> Option<AppStoreItem> {
    let id = app.get("id")
        .or_else(|| app.get("name"))
        .or_else(|| app.get("title"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())?;
    
    let name = app.get("name")
        .or_else(|| app.get("title"))
        .or_else(|| app.get("id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())?;
    
    let title = app.get("title")
        .or_else(|| app.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or(&name)
        .to_string();
    
    let description = app.get("description")
        .or_else(|| app.get("tagline"))
        .or_else(|| app.get("short_description"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    
    let version = app.get("version")
        .or_else(|| app.get("main").and_then(|m| m.get("version")))
        .and_then(|v| v.as_str())
        .or_else(|| {
            app.get("image")
                .and_then(|i| i.as_str())
                .and_then(|s| s.split(':').last())
        })
        .unwrap_or("latest")
        .to_string();
    
    let icon = app.get("icon")
        .or_else(|| app.get("image"))
        .or_else(|| app.get("thumbnail"))
        .or_else(|| app.get("logo"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    
    let category = app.get("category")
        .or_else(|| app.get("categories").and_then(|c| c.as_array()).and_then(|arr| arr.first()))
        .and_then(|v| v.as_str())
        .unwrap_or("Other")
        .to_string();
    
    let author = app.get("author")
        .or_else(|| app.get("developer"))
        .or_else(|| app.get("maintainer"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    
    let install_url = app.get("compose_url")
        .or_else(|| app.get("url"))
        .or_else(|| app.get("source"))
        .or_else(|| app.get("docker_image"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("docker://{}", id));

    let architectures = app
        .get("arch")
        .or_else(|| app.get("architectures"))
        .or_else(|| app.get("supported_architectures"))
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

pub async fn list_istoreos_apps() -> Result<HttpResponse, AppError> {
    info!("Fetching iStoreOS app store...");

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    match client.get(ISTOREOS_STORE_URL).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                warn!("iStoreOS store returned error: {}", response.status());
                return Ok(HttpResponse::Ok().json(AppStoreList {
                    apps: Vec::new(),
                    total: 0,
                    source: "istoreos".to_string(),
                }));
            }

            match response.json::<Value>().await {
                Ok(apps_json) => {
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
                    info!("Found {} iStoreOS apps", total);

                    Ok(HttpResponse::Ok().json(AppStoreList {
                        apps,
                        total,
                        source: "istoreos".to_string(),
                    }))
                }
                Err(e) => {
                    warn!("Failed to parse iStoreOS response: {}", e);
                    Ok(HttpResponse::Ok().json(AppStoreList {
                        apps: Vec::new(),
                        total: 0,
                        source: "istoreos".to_string(),
                    }))
                }
            }
        }
        Err(e) => {
            warn!("Failed to fetch iStoreOS store: {}", e);
            Ok(HttpResponse::Ok().json(AppStoreList {
                apps: Vec::new(),
                total: 0,
                source: "istoreos".to_string(),
            }))
        }
    }
}

fn parse_istoreos_app(app: &Value, installed: &HashMap<String, bool>) -> Option<AppStoreItem> {
    let name = app.get("name").and_then(|v| v.as_str())?.to_string();
    let id = format!("istoreos_{}", name);
    let title = app
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or(&name)
        .to_string();
    let description = app.get("summary")
        .or_else(|| app.get("description"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let version = app.get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("latest")
        .to_string();
    let icon = app
        .get("icon")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let category = app
        .get("category")
        .and_then(|v| v.as_str())
        .unwrap_or("Other")
        .to_string();
    let author = app
        .get("maintainer")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let install_url = app.get("download_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

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

pub async fn install_ipk_package(
    body: web::Json<PackageInstallRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    info!("Installing IPK package from {}", body.url);

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
            "Failed to download IPK package".to_string(),
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

    let dir = ensure_storage(&AppPackageKind::Ipk)?;
    let filename = body.name.clone().unwrap_or_else(|| {
        body.url
            .rsplit('/')
            .next()
            .unwrap_or("package.ipk")
            .to_string()
    });
    let safe_filename = sanitize_filename(&filename);
    let target = dir.join(&safe_filename);

    fs::write(&target, &bytes).map_err(|e| AppError::IoError(e.to_string()))?;

    #[cfg(target_os = "linux")]
    {
        info!("Installing IPK with opkg...");
        let output = Command::new("opkg")
            .args(["install", target.to_str().unwrap()])
            .output()
            .map_err(|e| AppError::BadRequest(format!("Failed to run opkg: {}", e)))?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            error!("IPK installation failed: {}", err);
            return Err(AppError::BadRequest(format!(
                "IPK installation failed: {}",
                err
            )));
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        warn!("IPK installation is only supported on Linux");
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

    info!("IPK package installed successfully");
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
