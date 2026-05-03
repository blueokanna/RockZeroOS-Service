use actix_web::{web, HttpRequest, HttpResponse};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng as AeadOsRng},
    AeadCore, ChaCha20Poly1305, Key, Nonce,
};
use futures_util::StreamExt;
use reqwest::Client;
use rockzero_common::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, Notify, RwLock};
use tracing::{info, warn};
use uuid::Uuid;

const EDGE_ROOT_DEFAULT: &str = "./data/edge";
const NODES_FILE: &str = "nodes.json";
const JOBS_FILE: &str = "jobs.json";
const WXY_AUTH_FILE: &str = "wxy_auth.bin";
const WXY_AUTH_LEGACY_FILE: &str = "wxy_auth.json";
const WXY_AUTH_KEY_DOMAIN: &str = "rockzero.edge.wxy_auth.v1";
const WXY_QR_FILE: &str = "wxy_qr_sessions.json";
const DEFAULT_MAX_PENDING_JOBS: usize = 256;
const DEFAULT_MAX_TOTAL_JOBS: usize = 5000;
const DEFAULT_MAX_WASM_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_STDIO_BYTES: usize = 1024 * 1024;

fn edge_secret_master() -> Result<Vec<u8>, AppError> {
    if let Ok(value) = std::env::var("ROCKZERO_EDGE_SECRET") {
        if value.len() >= 32 {
            return Ok(value.into_bytes());
        }
        return Err(AppError::InternalServerError(
            "ROCKZERO_EDGE_SECRET must be at least 32 characters".to_string(),
        ));
    }
    if let Ok(value) = std::env::var("ROCKZERO_MASTER_KEY") {
        if value.len() >= 32 {
            return Ok(value.into_bytes());
        }
    }
    Err(AppError::InternalServerError(
        "ROCKZERO_EDGE_SECRET is required to persist edge credentials".to_string(),
    ))
}

fn edge_envelope_cipher() -> Result<ChaCha20Poly1305, AppError> {
    let master = edge_secret_master()?;
    let derived = blake3::derive_key(WXY_AUTH_KEY_DOMAIN, &master);
    let key = Key::from_slice(&derived);
    Ok(ChaCha20Poly1305::new(key))
}

fn encrypt_edge_envelope(plaintext: &[u8]) -> Result<Vec<u8>, AppError> {
    let cipher = edge_envelope_cipher()?;
    let nonce = ChaCha20Poly1305::generate_nonce(&mut AeadOsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| AppError::CryptoError(format!("edge envelope encrypt failed: {}", e)))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_edge_envelope(blob: &[u8]) -> Result<Vec<u8>, AppError> {
    if blob.len() < 13 {
        return Err(AppError::BadRequest(
            "Edge credential envelope too short".to_string(),
        ));
    }
    let cipher = edge_envelope_cipher()?;
    let nonce = Nonce::from_slice(&blob[..12]);
    cipher
        .decrypt(nonce, &blob[12..])
        .map_err(|e| AppError::CryptoError(format!("edge envelope decrypt failed: {}", e)))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WxyQrStatus {
    Pending,
    Scanned,
    Confirmed,
    Expired,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WxyQrSession {
    pub session_id: String,
    pub qr_url: String,
    pub device_code: Option<String>,
    pub status: WxyQrStatus,
    pub created_at: i64,
    pub updated_at: i64,
    pub raw: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WxyAuthToken {
    pub provider: String,
    pub account_id: Option<String>,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<i64>,
    pub login_at: i64,
    pub extra: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct StartWxyQrLoginRequest {
    pub scope: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BindWxyTokenRequest {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub account_id: Option<String>,
    pub expires_at: Option<i64>,
    pub extra: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct AdapterInspectRequest {
    pub mode: String,
    pub raw: Value,
}

#[derive(Debug, Deserialize)]
pub struct RefreshWxyTokenRequest {
    pub force: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WxyRefreshReport {
    pub checked_at: i64,
    pub attempted: bool,
    pub success: bool,
    pub used_fallback: bool,
    pub reason: String,
    pub expires_at: Option<i64>,
    pub seconds_left: Option<i64>,
    pub refresh_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeStartupSelfCheckReport {
    pub checked_at: i64,
    pub trigger: String,
    pub overall_status: String,
    pub gateway: Value,
    pub field_mapping: Value,
    pub auth: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Online,
    Degraded,
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeNode {
    pub node_id: String,
    pub name: String,
    pub endpoint: Option<String>,
    pub tags: Vec<String>,
    pub max_concurrency: u32,
    pub capabilities: Vec<String>,
    pub registered_at: i64,
    pub last_heartbeat: i64,
    pub status: NodeStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeJob {
    pub job_id: String,
    #[serde(default)]
    pub owner_user_id: Option<String>,
    pub priority: i32,
    pub wasm_url: Option<String>,
    pub wasm_path: Option<String>,
    pub app_id: Option<String>,
    pub function: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub timeout_ms: u64,
    pub max_retries: u32,
    pub retry_count: u32,
    pub status: JobStatus,
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub assigned_node: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub error: Option<String>,
    #[serde(default)]
    pub requires_wxy_auth: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeStats {
    pub nodes_online: usize,
    pub nodes_total: usize,
    pub jobs_pending: usize,
    pub jobs_running: usize,
    pub jobs_completed: usize,
    pub jobs_failed: usize,
    pub jobs_cancelled: usize,
}

#[derive(Debug, Deserialize)]
pub struct RegisterNodeRequest {
    pub name: Option<String>,
    pub endpoint: Option<String>,
    pub tags: Option<Vec<String>>,
    pub max_concurrency: Option<u32>,
    pub capabilities: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct HeartbeatRequest {
    pub status: Option<NodeStatus>,
}

#[derive(Debug, Deserialize)]
pub struct SubmitJobRequest {
    pub wasm_url: Option<String>,
    pub wasm_path: Option<String>,
    pub app_id: Option<String>,
    pub function: Option<String>,
    pub args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
    pub priority: Option<i32>,
    pub timeout_ms: Option<u64>,
    pub max_retries: Option<u32>,
    pub requires_wxy_auth: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct JobsQuery {
    pub status: Option<JobStatus>,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct RegisterNodeResponse {
    pub node_id: String,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct SubmitJobResponse {
    pub job_id: String,
    pub status: String,
}

#[derive(Clone)]
struct RunningJobControl {
    engine: wasmtime::Engine,
    cancel_requested: Arc<AtomicBool>,
}

struct EdgeManager {
    root: PathBuf,
    local_node_id: String,
    nodes: RwLock<HashMap<String, EdgeNode>>,
    jobs: RwLock<HashMap<String, EdgeJob>>,
    running_jobs: RwLock<HashMap<String, RunningJobControl>>,
    wxy_auth: RwLock<Option<WxyAuthToken>>,
    wxy_qr_sessions: RwLock<HashMap<String, WxyQrSession>>,
    last_wxy_refresh: RwLock<Option<WxyRefreshReport>>,
    startup_self_check: RwLock<Option<EdgeStartupSelfCheckReport>>,
    wakeup: Notify,
}

static EDGE_MANAGER: OnceLock<Arc<EdgeManager>> = OnceLock::new();
static EDGE_MANAGER_INIT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn edge_root() -> PathBuf {
    std::env::var("EDGE_COMPUTE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(EDGE_ROOT_DEFAULT))
}

fn is_admin_claims(claims: &crate::handlers::auth::Claims) -> bool {
    claims.role.eq_ignore_ascii_case("admin")
}

fn can_access_job(job: &EdgeJob, claims: &crate::handlers::auth::Claims) -> bool {
    is_admin_claims(claims) || job.owner_user_id.as_deref() == Some(claims.sub.as_str())
}

fn ensure_admin(claims: &crate::handlers::auth::Claims) -> Result<(), AppError> {
    if is_admin_claims(claims) {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "Administrator access is required for this operation".to_string(),
        ))
    }
}

fn node_is_online(node: &EdgeNode) -> bool {
    let now = now_epoch();
    let ttl = std::env::var("EDGE_NODE_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(90);
    node.status != NodeStatus::Offline && now - node.last_heartbeat <= ttl
}

fn env_bool(name: &str, default_value: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            let s = v.to_ascii_lowercase();
            s == "1" || s == "true" || s == "yes" || s == "on"
        })
        .unwrap_or(default_value)
}

fn env_i64(name: &str, default_value: i64) -> i64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(default_value)
}

fn env_u64(name: &str, default_value: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default_value)
}

fn env_usize(name: &str, default_value: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default_value)
}

fn truncate_utf8(mut bytes: Vec<u8>, max_bytes: usize) -> String {
    if bytes.len() <= max_bytes {
        return String::from_utf8_lossy(&bytes).to_string();
    }

    bytes.truncate(max_bytes);
    while std::str::from_utf8(&bytes).is_err() {
        if bytes.is_empty() {
            break;
        }
        let _ = bytes.pop();
    }

    let mut s = String::from_utf8_lossy(&bytes).to_string();
    s.push_str("\n...[truncated]");
    s
}

impl EdgeManager {
    async fn new() -> Result<Arc<Self>, AppError> {
        let root = edge_root();
        tokio::fs::create_dir_all(&root)
            .await
            .map_err(|e| AppError::IoError(e.to_string()))?;

        let local_node_id = format!(
            "local-{}",
            std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("COMPUTERNAME"))
                .unwrap_or_else(|_| "rockzero".to_string())
        );

        let manager = Arc::new(Self {
            root,
            local_node_id,
            nodes: RwLock::new(HashMap::new()),
            jobs: RwLock::new(HashMap::new()),
            running_jobs: RwLock::new(HashMap::new()),
            wxy_auth: RwLock::new(None),
            wxy_qr_sessions: RwLock::new(HashMap::new()),
            last_wxy_refresh: RwLock::new(None),
            startup_self_check: RwLock::new(None),
            wakeup: Notify::new(),
        });

        manager.load_state().await?;
        manager.ensure_local_node().await?;
        manager.start_workers();
        manager.start_background_tasks();
        let report = manager.run_startup_self_check("startup").await;
        *manager.startup_self_check.write().await = Some(report);
        Ok(manager)
    }

    fn start_workers(self: &Arc<Self>) {
        let workers = std::env::var("EDGE_LOCAL_WORKERS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|v| v.get().max(2))
                    .unwrap_or(2)
            })
            .clamp(1, 16);

        for i in 0..workers {
            let mgr = Arc::clone(self);
            tokio::spawn(async move {
                loop {
                    let run_mgr = Arc::clone(&mgr);
                    let handle = tokio::spawn(async move {
                        loop {
                            let notified = run_mgr.wakeup.notified();
                            if let Some(job) = run_mgr.take_next_job().await {
                                let _ = run_mgr.execute_job(job.job_id.clone()).await;
                                continue;
                            }
                            if i == 0 {
                                let _ = run_mgr.mark_stale_nodes().await;
                            }
                            notified.await;
                        }
                    });

                    match handle.await {
                        Ok(_) => {
                            warn!("edge worker {} exited unexpectedly, restarting", i);
                        }
                        Err(e) => {
                            warn!("edge worker {} crashed: {}, restarting", i, e);
                        }
                    }

                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            });
        }

        info!("Edge compute workers started: {}", workers);
    }

    fn start_background_tasks(self: &Arc<Self>) {
        if env_bool("WXY_AUTO_REFRESH_ENABLED", true) {
            let mgr = Arc::clone(self);
            let interval_secs = env_u64("WXY_AUTO_REFRESH_INTERVAL_SECS", 60).max(10);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(interval_secs)).await;
                    let report = mgr.ensure_wxy_auth_valid(false).await;
                    if report.attempted {
                        info!(
                            "WXY auto refresh attempted, success={}, fallback={}, reason={}",
                            report.success, report.used_fallback, report.reason
                        );
                    }
                }
            });
        }

        let self_check_interval = env_u64("EDGE_SELF_CHECK_INTERVAL_SECS", 0);
        if self_check_interval > 0 {
            let mgr = Arc::clone(self);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(self_check_interval.max(30))).await;
                    let report = mgr.run_startup_self_check("periodic").await;
                    *mgr.startup_self_check.write().await = Some(report);
                }
            });
        }
    }

    async fn ensure_wxy_auth_valid(&self, force_refresh: bool) -> WxyRefreshReport {
        let now = now_epoch();
        let current = self.wxy_auth.read().await.clone();

        let Some(token) = current else {
            let report = WxyRefreshReport {
                checked_at: now,
                attempted: false,
                success: false,
                used_fallback: false,
                reason: "not_logged_in".to_string(),
                expires_at: None,
                seconds_left: None,
                refresh_error: None,
            };
            *self.last_wxy_refresh.write().await = Some(report.clone());
            return report;
        };

        let expires_at = token.expires_at;
        let seconds_left = expires_at.map(|exp| exp - now);
        let refresh_ahead_secs = env_i64("WXY_REFRESH_AHEAD_SECS", 300).max(0);

        let should_refresh = if force_refresh {
            true
        } else {
            match seconds_left {
                Some(v) => v <= refresh_ahead_secs,
                None => false,
            }
        };

        if !should_refresh {
            let report = WxyRefreshReport {
                checked_at: now,
                attempted: false,
                success: true,
                used_fallback: false,
                reason: "token_still_valid".to_string(),
                expires_at,
                seconds_left,
                refresh_error: None,
            };
            *self.last_wxy_refresh.write().await = Some(report.clone());
            return report;
        }

        if token.refresh_token.as_ref().is_none_or(|s| s.is_empty()) {
            let still_usable = seconds_left.unwrap_or(1) > 0;
            let report = WxyRefreshReport {
                checked_at: now,
                attempted: false,
                success: still_usable,
                used_fallback: still_usable,
                reason: if still_usable {
                    "refresh_token_missing_keep_current".to_string()
                } else {
                    "refresh_token_missing_and_expired".to_string()
                },
                expires_at,
                seconds_left,
                refresh_error: None,
            };
            *self.last_wxy_refresh.write().await = Some(report.clone());
            return report;
        }

        match call_wxy_refresh_token(&token).await {
            Ok(new_token) => {
                let new_expires_at = new_token.expires_at;
                let new_seconds_left = new_expires_at.map(|exp| exp - now_epoch());
                *self.wxy_auth.write().await = Some(new_token);
                let persist_result = self.persist_wxy_auth().await;
                let report = WxyRefreshReport {
                    checked_at: now,
                    attempted: true,
                    success: persist_result.is_ok(),
                    used_fallback: false,
                    reason: if persist_result.is_ok() {
                        "refresh_success".to_string()
                    } else {
                        "refresh_success_but_persist_failed".to_string()
                    },
                    expires_at: new_expires_at,
                    seconds_left: new_seconds_left,
                    refresh_error: persist_result.err().map(|e| e.to_string()),
                };
                *self.last_wxy_refresh.write().await = Some(report.clone());
                report
            }
            Err(err) => {
                let grace_secs = env_i64("WXY_REFRESH_FAIL_GRACE_SECS", 300).max(0);
                let within_grace = seconds_left.map(|v| v > -grace_secs).unwrap_or(false);
                let report = WxyRefreshReport {
                    checked_at: now,
                    attempted: true,
                    success: within_grace,
                    used_fallback: within_grace,
                    reason: if within_grace {
                        "refresh_failed_fallback_to_cached_token".to_string()
                    } else {
                        "refresh_failed_and_token_expired".to_string()
                    },
                    expires_at,
                    seconds_left,
                    refresh_error: Some(err.to_string()),
                };
                *self.last_wxy_refresh.write().await = Some(report.clone());
                report
            }
        }
    }

    async fn check_wxy_gateway_connectivity(&self) -> Value {
        let api_base = std::env::var("WXY_API_BASE").unwrap_or_default();
        if api_base.trim().is_empty() {
            return serde_json::json!({
                "configured": false,
                "reachable": false,
                "error": "missing WXY_API_BASE"
            });
        }

        let path = env_or("WXY_GATEWAY_HEALTH_PATH", "/");
        let method = env_or("WXY_GATEWAY_HEALTH_METHOD", "GET").to_uppercase();
        let timeout_secs = env_u64("WXY_GATEWAY_HEALTH_TIMEOUT_SECS", 8).max(1);

        let endpoint = format!("{}{}", api_base.trim_end_matches('/'), path);
        let client = match Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                return serde_json::json!({
                    "configured": true,
                    "reachable": false,
                    "endpoint": endpoint,
                    "error": format!("build_client_failed: {}", e),
                });
            }
        };

        let started = Instant::now();
        let send_res = if method == "HEAD" {
            client.head(&endpoint).send().await
        } else {
            client.get(&endpoint).send().await
        };
        let latency_ms = started.elapsed().as_millis() as u64;

        match send_res {
            Ok(resp) => {
                let status = resp.status().as_u16();
                serde_json::json!({
                    "configured": true,
                    "reachable": resp.status().is_success(),
                    "endpoint": endpoint,
                    "method": method,
                    "status_code": status,
                    "latency_ms": latency_ms,
                })
            }
            Err(e) => serde_json::json!({
                "configured": true,
                "reachable": false,
                "endpoint": endpoint,
                "method": method,
                "latency_ms": latency_ms,
                "error": e.to_string(),
            }),
        }
    }

    fn validate_field_mapping(&self) -> Value {
        let required_vars = [
            "WXY_ADAPTER_QR_URL_PATHS",
            "WXY_ADAPTER_STATUS_PATHS",
            "WXY_ADAPTER_ACCESS_TOKEN_PATHS",
        ];

        let mut missing: Vec<String> = Vec::new();
        for key in required_vars {
            if std::env::var(key).unwrap_or_default().trim().is_empty() {
                missing.push(key.to_string());
            }
        }

        let start_sample = std::env::var("WXY_SELF_CHECK_START_SAMPLE_JSON")
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok());
        let poll_sample = std::env::var("WXY_SELF_CHECK_POLL_SAMPLE_JSON")
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok());

        let start_preview = start_sample.as_ref().map(|json| {
            serde_json::json!({
                "qr_url": get_first_string(
                    json,
                    "WXY_ADAPTER_QR_URL_PATHS",
                    &["qr_url", "data.qr_url", "result.qr_url"],
                ),
                "session_id": get_first_string(
                    json,
                    "WXY_ADAPTER_SESSION_ID_PATHS",
                    &["session_id", "sid", "data.session_id"],
                ),
            })
        });

        let poll_preview = poll_sample.as_ref().map(|json| {
            let raw_status = get_first_string(
                json,
                "WXY_ADAPTER_STATUS_PATHS",
                &["status", "data.status", "result.status"],
            )
            .unwrap_or_else(|| "pending".to_string());
            let token = extract_auth_from_poll_json(json);
            serde_json::json!({
                "raw_status": raw_status,
                "mapped_status": status_from_text(
                    &get_first_string(
                        json,
                        "WXY_ADAPTER_STATUS_PATHS",
                        &["status", "data.status", "result.status"],
                    )
                    .unwrap_or_else(|| "pending".to_string())
                ),
                "has_token": token.is_some(),
            })
        });

        serde_json::json!({
            "ok": missing.is_empty(),
            "missing_required": missing,
            "sample_check": {
                "start": start_preview,
                "poll": poll_preview,
            }
        })
    }

    async fn run_startup_self_check(&self, trigger: &str) -> EdgeStartupSelfCheckReport {
        let checked_at = now_epoch();
        let gateway = self.check_wxy_gateway_connectivity().await;
        let field_mapping = self.validate_field_mapping();

        let refresh_report = self.ensure_wxy_auth_valid(false).await;
        let auth = self.wxy_auth.read().await.clone();
        let logged_in = auth.is_some();
        let expires_at = auth.as_ref().and_then(|a| a.expires_at);
        let seconds_left = expires_at.map(|exp| exp - checked_at);

        let gateway_ok = gateway
            .get("reachable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let mapping_ok = field_mapping
            .get("ok")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let overall_status =
            if !gateway_ok || !mapping_ok || (logged_in && !refresh_report.success) {
                "degraded"
            } else {
                "ok"
            }
            .to_string();

        EdgeStartupSelfCheckReport {
            checked_at,
            trigger: trigger.to_string(),
            overall_status,
            gateway,
            field_mapping,
            auth: serde_json::json!({
                "logged_in": logged_in,
                "account_id": auth.as_ref().and_then(|a| a.account_id.clone()),
                "expires_at": expires_at,
                "seconds_left": seconds_left,
                "refresh": refresh_report,
            }),
        }
    }

    async fn ensure_local_node(&self) -> Result<(), AppError> {
        let mut nodes = self.nodes.write().await;
        let now = now_epoch();
        nodes
            .entry(self.local_node_id.clone())
            .and_modify(|n| {
                n.last_heartbeat = now;
                n.status = NodeStatus::Online;
            })
            .or_insert_with(|| EdgeNode {
                node_id: self.local_node_id.clone(),
                name: "RockZero Local Edge Node".to_string(),
                endpoint: None,
                tags: vec!["local".to_string(), "native".to_string()],
                max_concurrency: std::thread::available_parallelism()
                    .map(|v| v.get() as u32)
                    .unwrap_or(2)
                    .max(2),
                capabilities: vec![
                    "wasm32-wasi".to_string(),
                    "native-execution".to_string(),
                    "sandbox".to_string(),
                ],
                registered_at: now,
                last_heartbeat: now,
                status: NodeStatus::Online,
            });
        drop(nodes);
        self.persist_nodes().await
    }

    async fn mark_stale_nodes(&self) -> Result<(), AppError> {
        let mut changed = false;
        let mut nodes = self.nodes.write().await;
        for node in nodes.values_mut() {
            if !node_is_online(node) && node.status != NodeStatus::Offline {
                node.status = NodeStatus::Offline;
                changed = true;
            }
        }
        drop(nodes);
        if changed {
            self.persist_nodes().await?;
        }
        Ok(())
    }

    async fn load_state(&self) -> Result<(), AppError> {
        let nodes_path = self.root.join(NODES_FILE);
        if nodes_path.exists() {
            let data = tokio::fs::read_to_string(&nodes_path)
                .await
                .map_err(|e| AppError::IoError(e.to_string()))?;
            let parsed: Vec<EdgeNode> = serde_json::from_str(&data)
                .map_err(|e| AppError::BadRequest(format!("Invalid nodes file: {}", e)))?;
            let mut nodes = self.nodes.write().await;
            for node in parsed {
                nodes.insert(node.node_id.clone(), node);
            }
        }

        let jobs_path = self.root.join(JOBS_FILE);
        if jobs_path.exists() {
            let data = tokio::fs::read_to_string(&jobs_path)
                .await
                .map_err(|e| AppError::IoError(e.to_string()))?;
            let parsed: Vec<EdgeJob> = serde_json::from_str(&data)
                .map_err(|e| AppError::BadRequest(format!("Invalid jobs file: {}", e)))?;
            let mut jobs = self.jobs.write().await;
            for mut job in parsed {
                if job.status == JobStatus::Running {
                    job.status = JobStatus::Pending;
                    job.assigned_node = None;
                    job.started_at = None;
                }
                jobs.insert(job.job_id.clone(), job);
            }
        }

        let wxy_auth_path = self.root.join(WXY_AUTH_FILE);
        if wxy_auth_path.exists() {
            let blob = tokio::fs::read(&wxy_auth_path)
                .await
                .map_err(|e| AppError::IoError(e.to_string()))?;
            let plaintext = decrypt_edge_envelope(&blob)?;
            let token: WxyAuthToken = serde_json::from_slice(&plaintext)
                .map_err(|e| AppError::BadRequest(format!("Invalid wxy auth file: {}", e)))?;
            *self.wxy_auth.write().await = Some(token);
        } else {
            let legacy_path = self.root.join(WXY_AUTH_LEGACY_FILE);
            if legacy_path.exists() {
                let data = tokio::fs::read_to_string(&legacy_path)
                    .await
                    .map_err(|e| AppError::IoError(e.to_string()))?;
                let token: WxyAuthToken = serde_json::from_str(&data)
                    .map_err(|e| AppError::BadRequest(format!("Invalid wxy auth file: {}", e)))?;
                *self.wxy_auth.write().await = Some(token);
                let plaintext = data.into_bytes();
                if let Ok(blob) = encrypt_edge_envelope(&plaintext) {
                    if tokio::fs::write(&wxy_auth_path, blob).await.is_ok() {
                        let _ = tokio::fs::remove_file(&legacy_path).await;
                    }
                }
            }
        }

        let wxy_qr_path = self.root.join(WXY_QR_FILE);
        if wxy_qr_path.exists() {
            let data = tokio::fs::read_to_string(&wxy_qr_path)
                .await
                .map_err(|e| AppError::IoError(e.to_string()))?;
            let parsed: Vec<WxyQrSession> = serde_json::from_str(&data)
                .map_err(|e| AppError::BadRequest(format!("Invalid wxy qr file: {}", e)))?;
            let mut sessions = self.wxy_qr_sessions.write().await;
            for s in parsed {
                sessions.insert(s.session_id.clone(), s);
            }
        }

        Ok(())
    }

    async fn persist_nodes(&self) -> Result<(), AppError> {
        let nodes = self.nodes.read().await;
        let all: Vec<EdgeNode> = nodes.values().cloned().collect();
        let text = serde_json::to_string_pretty(&all)
            .map_err(|e| AppError::InternalServerError(e.to_string()))?;
        tokio::fs::write(self.root.join(NODES_FILE), text)
            .await
            .map_err(|e| AppError::IoError(e.to_string()))
    }

    async fn persist_jobs(&self) -> Result<(), AppError> {
        let jobs = self.jobs.read().await;
        let mut all: Vec<EdgeJob> = jobs.values().cloned().collect();
        all.sort_by_key(|job| std::cmp::Reverse(job.created_at));

        let max_total = env_usize("EDGE_MAX_TOTAL_JOBS", DEFAULT_MAX_TOTAL_JOBS).max(100);
        if all.len() > max_total {
            all.truncate(max_total);
        }

        let text = serde_json::to_string_pretty(&all)
            .map_err(|e| AppError::InternalServerError(e.to_string()))?;
        tokio::fs::write(self.root.join(JOBS_FILE), text)
            .await
            .map_err(|e| AppError::IoError(e.to_string()))
    }

    async fn persist_wxy_auth(&self) -> Result<(), AppError> {
        let auth = self.wxy_auth.read().await;
        let target = self.root.join(WXY_AUTH_FILE);
        let legacy = self.root.join(WXY_AUTH_LEGACY_FILE);
        match auth.as_ref() {
            Some(token) => {
                let plaintext = serde_json::to_vec(token)
                    .map_err(|e| AppError::InternalServerError(e.to_string()))?;
                let blob = encrypt_edge_envelope(&plaintext)?;
                tokio::fs::write(&target, blob)
                    .await
                    .map_err(|e| AppError::IoError(e.to_string()))?;
                if legacy.exists() {
                    let _ = tokio::fs::remove_file(&legacy).await;
                }
                Ok(())
            }
            None => {
                if target.exists() {
                    let _ = tokio::fs::remove_file(&target).await;
                }
                if legacy.exists() {
                    let _ = tokio::fs::remove_file(&legacy).await;
                }
                Ok(())
            }
        }
    }

    async fn persist_wxy_qr_sessions(&self) -> Result<(), AppError> {
        let sessions = self.wxy_qr_sessions.read().await;
        let mut all: Vec<WxyQrSession> = sessions.values().cloned().collect();
        all.sort_by_key(|session| std::cmp::Reverse(session.created_at));
        if all.len() > 500 {
            all.truncate(500);
        }
        let text = serde_json::to_string_pretty(&all)
            .map_err(|e| AppError::InternalServerError(e.to_string()))?;
        tokio::fs::write(self.root.join(WXY_QR_FILE), text)
            .await
            .map_err(|e| AppError::IoError(e.to_string()))
    }

    async fn register_node(&self, body: RegisterNodeRequest) -> Result<String, AppError> {
        let node_id = format!("edge-{}", Uuid::new_v4());
        let now = now_epoch();
        let node = EdgeNode {
            node_id: node_id.clone(),
            name: body
                .name
                .unwrap_or_else(|| "RockZero Edge Node".to_string()),
            endpoint: body.endpoint,
            tags: body.tags.unwrap_or_default(),
            max_concurrency: body.max_concurrency.unwrap_or(2).clamp(1, 128),
            capabilities: body
                .capabilities
                .unwrap_or_else(|| vec!["wasm32-wasi".to_string()]),
            registered_at: now,
            last_heartbeat: now,
            status: NodeStatus::Online,
        };

        self.nodes.write().await.insert(node_id.clone(), node);
        self.persist_nodes().await?;
        Ok(node_id)
    }

    async fn heartbeat(&self, node_id: &str, status: Option<NodeStatus>) -> Result<(), AppError> {
        let mut nodes = self.nodes.write().await;
        let node = nodes
            .get_mut(node_id)
            .ok_or_else(|| AppError::NotFound(format!("Node {} not found", node_id)))?;
        node.last_heartbeat = now_epoch();
        node.status = status.unwrap_or(NodeStatus::Online);
        drop(nodes);
        self.persist_nodes().await
    }

    async fn submit_job(
        &self,
        owner_user_id: String,
        body: SubmitJobRequest,
    ) -> Result<String, AppError> {
        if body.wasm_url.is_none() && body.wasm_path.is_none() && body.app_id.is_none() {
            return Err(AppError::BadRequest(
                "One of wasm_url / wasm_path / app_id is required".to_string(),
            ));
        }

        let timeout_ms = body.timeout_ms.unwrap_or(30_000).clamp(1_000, 300_000);
        let max_retries = body.max_retries.unwrap_or(1).min(10);
        let priority = body.priority.unwrap_or(0).clamp(-100, 100);

        let max_pending = env_usize("EDGE_MAX_PENDING_JOBS", DEFAULT_MAX_PENDING_JOBS).max(1);
        {
            let jobs = self.jobs.read().await;
            let pending = jobs
                .values()
                .filter(|j| j.status == JobStatus::Pending)
                .count();
            if pending >= max_pending {
                return Err(AppError::PreconditionFailed(format!(
                    "Edge queue is full: pending={} max_pending={}",
                    pending, max_pending
                )));
            }
        }

        let require_auth = body.requires_wxy_auth.unwrap_or(false)
            || std::env::var("EDGE_REQUIRE_WXY_AUTH")
                .ok()
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);

        let refresh_report = if require_auth {
            self.ensure_wxy_auth_valid(false).await
        } else {
            WxyRefreshReport {
                checked_at: now_epoch(),
                attempted: false,
                success: false,
                used_fallback: false,
                reason: "wxy_auth_not_required".to_string(),
                expires_at: None,
                seconds_left: None,
                refresh_error: None,
            }
        };
        let auth = self.wxy_auth.read().await.clone();
        if require_auth && auth.is_none() {
            return Err(AppError::PreconditionFailed(
                "WXY auth required. Please complete WXY QR login first".to_string(),
            ));
        }
        if require_auth && !refresh_report.success {
            return Err(AppError::PreconditionFailed(format!(
                "WXY auth is not usable: {}",
                refresh_report.reason
            )));
        }

        let env = body.env.unwrap_or_default();

        let job_id = Uuid::new_v4().to_string();
        let job = EdgeJob {
            job_id: job_id.clone(),
            owner_user_id: Some(owner_user_id),
            priority,
            wasm_url: body.wasm_url,
            wasm_path: body.wasm_path,
            app_id: body.app_id,
            function: body.function.unwrap_or_else(|| "_start".to_string()),
            args: body.args.unwrap_or_default(),
            env,
            timeout_ms,
            max_retries,
            retry_count: 0,
            status: JobStatus::Pending,
            created_at: now_epoch(),
            started_at: None,
            finished_at: None,
            assigned_node: None,
            stdout: None,
            stderr: None,
            error: None,
            requires_wxy_auth: require_auth,
        };

        self.jobs.write().await.insert(job_id.clone(), job);
        self.prune_jobs_in_memory().await;
        self.persist_jobs().await?;
        self.wakeup.notify_waiters();
        Ok(job_id)
    }

    async fn prune_jobs_in_memory(&self) {
        let max_total = env_usize("EDGE_MAX_TOTAL_JOBS", DEFAULT_MAX_TOTAL_JOBS).max(100);
        let mut jobs = self.jobs.write().await;
        if jobs.len() <= max_total {
            return;
        }

        let mut finished: Vec<(String, i64)> = jobs
            .iter()
            .filter(|(_, j)| {
                j.status == JobStatus::Completed
                    || j.status == JobStatus::Failed
                    || j.status == JobStatus::Cancelled
            })
            .map(|(id, j)| (id.clone(), j.finished_at.unwrap_or(j.created_at)))
            .collect();
        finished.sort_by_key(|item| item.1);

        let mut to_remove = jobs.len().saturating_sub(max_total);
        for (id, _) in finished {
            if to_remove == 0 {
                break;
            }
            jobs.remove(&id);
            to_remove -= 1;
        }
    }

    async fn take_next_job(&self) -> Option<EdgeJob> {
        let mut jobs = self.jobs.write().await;
        let next_job_id = jobs
            .values()
            .filter(|j| j.status == JobStatus::Pending)
            .max_by(|a, b| {
                a.priority
                    .cmp(&b.priority)
                    .then_with(|| b.created_at.cmp(&a.created_at))
            })
            .map(|j| j.job_id.clone())?;

        let j = jobs.get_mut(&next_job_id)?;
        j.status = JobStatus::Running;
        j.started_at = Some(now_epoch());
        j.assigned_node = Some(self.local_node_id.clone());
        j.error = None;
        let copy = j.clone();
        drop(jobs);
        let _ = self.persist_jobs().await;
        Some(copy)
    }

    async fn execute_job(&self, job_id: String) -> Result<(), AppError> {
        let snapshot = {
            let jobs = self.jobs.read().await;
            jobs.get(&job_id)
                .cloned()
                .ok_or_else(|| AppError::NotFound(format!("Job {} not found", job_id)))?
        };

        let wasm_bytes = self.resolve_wasm_bytes(&snapshot).await?;

        let mut config = wasmtime::Config::new();
        config.epoch_interruption(true);
        let engine = wasmtime::Engine::new(&config).map_err(|e| {
            AppError::InternalServerError(format!("Failed to initialize WASM engine: {}", e))
        })?;
        let cancel_requested = Arc::new(AtomicBool::new(false));

        self.running_jobs.write().await.insert(
            job_id.clone(),
            RunningJobControl {
                engine: engine.clone(),
                cancel_requested: Arc::clone(&cancel_requested),
            },
        );

        let function = snapshot.function.clone();
        let args = snapshot.args.clone();
        let mut env = snapshot.env.clone();
        if snapshot.requires_wxy_auth {
            if let Some(token) = self.wxy_auth.read().await.clone() {
                env.insert("WXY_ACCESS_TOKEN".to_string(), token.access_token);
                if let Some(refresh) = token.refresh_token {
                    env.insert("WXY_REFRESH_TOKEN".to_string(), refresh);
                }
                if let Some(account_id) = token.account_id {
                    env.insert("WXY_ACCOUNT_ID".to_string(), account_id);
                }
                if let Some(expires_at) = token.expires_at {
                    env.insert("WXY_EXPIRES_AT".to_string(), expires_at.to_string());
                }
            }
        }
        let stdio_max = env_usize("EDGE_JOB_STDIO_MAX_BYTES", DEFAULT_MAX_STDIO_BYTES).max(4096);

        let run = tokio::time::timeout(
            Duration::from_millis(snapshot.timeout_ms),
            tokio::task::spawn_blocking(move || -> Result<(String, String), AppError> {
                if cancel_requested.load(Ordering::SeqCst) {
                    return Err(AppError::Conflict("Job cancelled".to_string()));
                }

                let module = wasmtime::Module::new(&engine, &wasm_bytes)
                    .map_err(|e| AppError::BadRequest(format!("Invalid WASM module: {}", e)))?;

                let mut linker = wasmtime::Linker::new(&engine);
                #[allow(deprecated)]
                wasmtime_wasi::add_to_linker(&mut linker, |cx| cx)
                    .map_err(|e| AppError::InternalServerError(e.to_string()))?;

                #[allow(deprecated)]
                let mut builder = wasmtime_wasi::sync::WasiCtxBuilder::new();
                let stdout_pipe = wasi_common::pipe::WritePipe::new_in_memory();
                let stderr_pipe = wasi_common::pipe::WritePipe::new_in_memory();

                builder.stdout(Box::new(stdout_pipe.clone()));
                builder.stderr(Box::new(stderr_pipe.clone()));

                for arg in &args {
                    builder
                        .arg(arg)
                        .map_err(|e| AppError::ValidationError(format!("Invalid arg: {}", e)))?;
                }
                for (k, v) in &env {
                    builder
                        .env(k, v)
                        .map_err(|e| AppError::ValidationError(format!("Invalid env: {}", e)))?;
                }

                let mut store = wasmtime::Store::new(&engine, builder.build());
                store.set_epoch_deadline(1);

                if cancel_requested.load(Ordering::SeqCst) {
                    return Err(AppError::Conflict("Job cancelled".to_string()));
                }

                let instance = linker
                    .instantiate(&mut store, &module)
                    .map_err(|e| AppError::BadRequest(format!("WASM instantiate failed: {}", e)))?;

                if let Ok(entry) = instance.get_typed_func::<(), ()>(&mut store, &function) {
                    entry
                        .call(&mut store, ())
                        .map_err(|e| AppError::BadRequest(format!("WASM call failed: {}", e)))?;
                } else if let Some(func) = instance.get_func(&mut store, &function) {
                    func.call(&mut store, &[], &mut [])
                        .map_err(|e| AppError::BadRequest(format!("WASM call failed: {}", e)))?;
                } else {
                    return Err(AppError::NotFound(format!(
                        "Function '{}' not found",
                        function
                    )));
                }

                drop(store);

                let stdout = stdout_pipe
                    .try_into_inner()
                    .map(|c| truncate_utf8(c.into_inner(), stdio_max))
                    .unwrap_or_default();
                let stderr = stderr_pipe
                    .try_into_inner()
                    .map(|c| truncate_utf8(c.into_inner(), stdio_max))
                    .unwrap_or_default();

                Ok((stdout, stderr))
            }),
        )
        .await;

        let control = self.running_jobs.write().await.remove(&job_id);

        let mut jobs = self.jobs.write().await;
        let j = match jobs.get_mut(&job_id) {
            Some(v) => v,
            None => return Ok(()),
        };

        let cancelled = control
            .as_ref()
            .map(|c| c.cancel_requested.load(Ordering::SeqCst))
            .unwrap_or(false)
            || j.status == JobStatus::Cancelled;

        if cancelled {
            j.status = JobStatus::Cancelled;
            j.assigned_node = None;
            j.finished_at = Some(now_epoch());
            j.error = Some("Cancelled by user".to_string());
            drop(jobs);
            return self.persist_jobs().await;
        }

        match run {
            Ok(Ok(Ok((stdout, stderr)))) => {
                j.status = JobStatus::Completed;
                j.stdout = Some(stdout);
                j.stderr = Some(stderr);
                j.error = None;
                j.finished_at = Some(now_epoch());
                j.assigned_node = None;
            }
            Ok(Ok(Err(e))) => {
                let should_retry = j.retry_count < j.max_retries;
                if should_retry {
                    j.retry_count += 1;
                    j.status = JobStatus::Pending;
                    j.started_at = None;
                    j.assigned_node = None;
                    j.error = Some(e.to_string());
                    self.wakeup.notify_waiters();
                } else {
                    j.status = JobStatus::Failed;
                    j.assigned_node = None;
                    j.error = Some(e.to_string());
                    j.finished_at = Some(now_epoch());
                }
            }
            Ok(Err(join_err)) => {
                j.status = JobStatus::Failed;
                j.assigned_node = None;
                j.error = Some(format!("Worker panic: {}", join_err));
                j.finished_at = Some(now_epoch());
            }
            Err(_) => {
                let should_retry = j.retry_count < j.max_retries;
                if should_retry {
                    j.retry_count += 1;
                    j.status = JobStatus::Pending;
                    j.started_at = None;
                    j.assigned_node = None;
                    j.error = Some("Job timeout".to_string());
                    self.wakeup.notify_waiters();
                } else {
                    j.status = JobStatus::Failed;
                    j.assigned_node = None;
                    j.error = Some("Job timeout".to_string());
                    j.finished_at = Some(now_epoch());
                }
            }
        }

        drop(jobs);
        self.persist_jobs().await
    }

    async fn resolve_wasm_bytes(&self, job: &EdgeJob) -> Result<Vec<u8>, AppError> {
        let max_wasm_bytes =
            env_usize("EDGE_WASM_MAX_BYTES", DEFAULT_MAX_WASM_BYTES).max(64 * 1024);

        if let Some(path) = &job.wasm_path {
            let p = Path::new(path);
            if !p.exists() {
                return Err(AppError::NotFound(format!("WASM path not found: {}", path)));
            }
            let meta = tokio::fs::metadata(p)
                .await
                .map_err(|e| AppError::IoError(format!("Read wasm_path metadata failed: {}", e)))?;
            let size = meta.len() as usize;
            if size > max_wasm_bytes {
                return Err(AppError::BadRequest(format!(
                    "WASM file too large: {} bytes > limit {}",
                    size, max_wasm_bytes
                )));
            }
            return tokio::fs::read(p)
                .await
                .map_err(|e| AppError::IoError(format!("Read wasm_path failed: {}", e)));
        }

        if let Some(app_id) = &job.app_id {
            if let Some(path) = resolve_app_path(app_id).await? {
                let meta = tokio::fs::metadata(&path).await.map_err(|e| {
                    AppError::IoError(format!("Read app wasm metadata failed: {}", e))
                })?;
                let size = meta.len() as usize;
                if size > max_wasm_bytes {
                    return Err(AppError::BadRequest(format!(
                        "App WASM too large: {} bytes > limit {}",
                        size, max_wasm_bytes
                    )));
                }
                return tokio::fs::read(path)
                    .await
                    .map_err(|e| AppError::IoError(format!("Read app wasm failed: {}", e)));
            }
            return Err(AppError::NotFound(format!(
                "Installed app '{}' not found",
                app_id
            )));
        }

        if let Some(url) = &job.wasm_url {
            validate_wasm_url(url).await?;
            let client = Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .map_err(|e| AppError::InternalServerError(e.to_string()))?;
            let resp =
                client.get(url).send().await.map_err(|e| {
                    AppError::BadRequest(format!("Download wasm_url failed: {}", e))
                })?;
            if !resp.status().is_success() {
                return Err(AppError::BadRequest(format!(
                    "wasm_url returned status {}",
                    resp.status()
                )));
            }

            if let Some(content_len) = resp.content_length() {
                if content_len as usize > max_wasm_bytes {
                    return Err(AppError::BadRequest(format!(
                        "wasm_url content too large: {} bytes > limit {}",
                        content_len, max_wasm_bytes
                    )));
                }
            }

            let mut bytes: Vec<u8> = Vec::new();
            let mut stream = resp.bytes_stream();
            while let Some(chunk_res) = stream.next().await {
                let chunk = chunk_res.map_err(|e| {
                    AppError::BadRequest(format!("Read wasm_url stream failed: {}", e))
                })?;
                if bytes.len() + chunk.len() > max_wasm_bytes {
                    return Err(AppError::BadRequest(format!(
                        "wasm_url stream exceeds limit {} bytes",
                        max_wasm_bytes
                    )));
                }
                bytes.extend_from_slice(&chunk);
            }
            return Ok(bytes);
        }

        Err(AppError::BadRequest("No wasm source provided".to_string()))
    }

    async fn cancel_job(
        &self,
        job_id: &str,
        claims: &crate::handlers::auth::Claims,
    ) -> Result<(), AppError> {
        let mut jobs = self.jobs.write().await;
        let j = jobs
            .get_mut(job_id)
            .ok_or_else(|| AppError::NotFound(format!("Job {} not found", job_id)))?;
        if !can_access_job(j, claims) {
            return Err(AppError::Forbidden("Job access denied".to_string()));
        }
        if j.status == JobStatus::Completed || j.status == JobStatus::Failed {
            return Err(AppError::Conflict(
                "Finished job cannot be cancelled".to_string(),
            ));
        }
        j.status = JobStatus::Cancelled;
        j.assigned_node = None;
        j.finished_at = Some(now_epoch());
        j.error = Some("Cancelled by user".to_string());
        drop(jobs);

        if let Some(control) = self.running_jobs.read().await.get(job_id).cloned() {
            control.cancel_requested.store(true, Ordering::SeqCst);
            control.engine.increment_epoch();
        }

        self.persist_jobs().await
    }

    async fn stats(&self) -> EdgeStats {
        let nodes = self.nodes.read().await;
        let jobs = self.jobs.read().await;

        let nodes_online = nodes.values().filter(|n| node_is_online(n)).count();
        let nodes_total = nodes.len();
        let jobs_pending = jobs
            .values()
            .filter(|j| j.status == JobStatus::Pending)
            .count();
        let jobs_running = jobs
            .values()
            .filter(|j| j.status == JobStatus::Running)
            .count();
        let jobs_completed = jobs
            .values()
            .filter(|j| j.status == JobStatus::Completed)
            .count();
        let jobs_failed = jobs
            .values()
            .filter(|j| j.status == JobStatus::Failed)
            .count();
        let jobs_cancelled = jobs
            .values()
            .filter(|j| j.status == JobStatus::Cancelled)
            .count();

        EdgeStats {
            nodes_online,
            nodes_total,
            jobs_pending,
            jobs_running,
            jobs_completed,
            jobs_failed,
            jobs_cancelled,
        }
    }
}

async fn validate_wasm_url(url: &str) -> Result<(), AppError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| AppError::BadRequest(format!("Invalid wasm_url: {}", e)))?;

    if parsed.scheme() != "https" {
        return Err(AppError::BadRequest("wasm_url must use https".to_string()));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| AppError::BadRequest("wasm_url must include a host".to_string()))?;
    let port = parsed.port_or_known_default().unwrap_or(443);

    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_internal_address(ip) {
            return Err(AppError::BadRequest(format!(
                "wasm_url host {} resolves to a blocked address",
                host
            )));
        }
        return Ok(());
    }

    let resolved = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to resolve wasm_url host: {}", e)))?;

    for socket in resolved {
        if is_internal_address(socket.ip()) {
            return Err(AppError::BadRequest(format!(
                "wasm_url host {} resolves to a blocked address",
                host
            )));
        }
    }

    Ok(())
}

fn is_internal_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.octets()[0] == 0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

async fn resolve_app_path(app_id: &str) -> Result<Option<String>, AppError> {
    let root = std::env::var("WASM_STORE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/mnt/external/wasm_store"));
    let registry = root.join("registry.json");

    if !registry.exists() {
        return Ok(None);
    }

    let text = tokio::fs::read_to_string(registry)
        .await
        .map_err(|e| AppError::IoError(e.to_string()))?;
    let json: Value = serde_json::from_str(&text)
        .map_err(|e| AppError::BadRequest(format!("Invalid wasm registry: {}", e)))?;

    let arr = json.as_array().cloned().unwrap_or_default();
    for item in &arr {
        let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let installed = item
            .get("installed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if id == app_id && installed {
            let p = item
                .get("installed_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !p.is_empty() {
                return Ok(Some(p.to_string()));
            }
        }
    }
    Ok(None)
}

async fn manager() -> Result<Arc<EdgeManager>, AppError> {
    if let Some(m) = EDGE_MANAGER.get() {
        return Ok(Arc::clone(m));
    }

    let lock = EDGE_MANAGER_INIT_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().await;
    if let Some(m) = EDGE_MANAGER.get() {
        return Ok(Arc::clone(m));
    }

    let created = EdgeManager::new().await?;
    let _ = EDGE_MANAGER.set(Arc::clone(&created));
    Ok(created)
}

pub async fn inspect_wxy_adapter(
    req: HttpRequest,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<AdapterInspectRequest>,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    ensure_admin(&claims)?;
    let payload = body.into_inner();
    let mode = payload.mode.to_lowercase();
    let json = payload.raw;

    if mode == "start" {
        let qr_url = get_first_string(
            &json,
            "WXY_ADAPTER_QR_URL_PATHS",
            &[
                "qr_url",
                "qrcode_url",
                "data.qr_url",
                "data.qrcode_url",
                "data.url",
                "result.qr_url",
            ],
        );
        let session_id = get_first_string(
            &json,
            "WXY_ADAPTER_SESSION_ID_PATHS",
            &["session_id", "sid", "data.session_id", "result.session_id"],
        );
        let device_code = get_first_string(
            &json,
            "WXY_ADAPTER_DEVICE_CODE_PATHS",
            &["device_code", "data.device_code", "result.device_code"],
        );

        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "mode": "start",
            "mapped": {
                "qr_url": qr_url,
                "session_id": session_id,
                "device_code": device_code,
            }
        })));
    }

    if mode == "poll" {
        let raw_status = get_first_string(
            &json,
            "WXY_ADAPTER_STATUS_PATHS",
            &[
                "status",
                "data.status",
                "result.status",
                "code",
                "data.code",
            ],
        )
        .unwrap_or_else(|| "pending".to_string());
        let status = status_from_text(&raw_status);
        let token = extract_auth_from_poll_json(&json);

        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "mode": "poll",
            "mapped": {
                "raw_status": raw_status,
                "status": status,
                "has_token": token.is_some(),
                "account_id": token.as_ref().and_then(|t| t.account_id.clone()),
                "expires_at": token.as_ref().and_then(|t| t.expires_at),
            }
        })));
    }

    Err(AppError::BadRequest(
        "mode must be one of: start, poll".to_string(),
    ))
}

fn env_required(name: &str) -> Result<String, AppError> {
    std::env::var(name).map_err(|_| {
        AppError::PreconditionFailed(format!("Missing environment variable: {}", name))
    })
}

fn env_or(name: &str, default_value: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default_value.to_string())
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn to_pointer(path: &str) -> String {
    if path.starts_with('/') {
        return path.to_string();
    }
    let normalized = path.trim().replace('.', "/");
    format!("/{}", normalized)
}

fn get_value_by_path<'a>(json: &'a Value, path: &str) -> Option<&'a Value> {
    json.pointer(&to_pointer(path))
}

fn get_first_string(json: &Value, env_name: &str, defaults: &[&str]) -> Option<String> {
    let configured = env_or(env_name, &defaults.join(","));
    for path in split_csv(&configured) {
        if let Some(v) = get_value_by_path(json, &path) {
            if let Some(s) = v.as_str() {
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            } else if let Some(n) = v.as_i64() {
                return Some(n.to_string());
            }
        }
    }
    None
}

fn get_first_i64(json: &Value, env_name: &str, defaults: &[&str]) -> Option<i64> {
    let configured = env_or(env_name, &defaults.join(","));
    for path in split_csv(&configured) {
        if let Some(v) = get_value_by_path(json, &path) {
            if let Some(n) = v.as_i64() {
                return Some(n);
            }
            if let Some(s) = v.as_str() {
                if let Ok(parsed) = s.parse::<i64>() {
                    return Some(parsed);
                }
            }
        }
    }
    None
}

fn merge_json(base: &mut serde_json::Map<String, Value>, extra: Value) {
    if let Some(obj) = extra.as_object() {
        for (k, v) in obj {
            base.insert(k.clone(), v.clone());
        }
    }
}

fn status_from_text(v: &str) -> WxyQrStatus {
    let s = v.to_lowercase();
    let confirmed_keys = split_csv(&env_or(
        "WXY_ADAPTER_STATUS_CONFIRMED",
        "confirm,success,authorized,ok,done",
    ));
    let scanned_keys = split_csv(&env_or("WXY_ADAPTER_STATUS_SCANNED", "scan,scanned"));
    let expired_keys = split_csv(&env_or(
        "WXY_ADAPTER_STATUS_EXPIRED",
        "expire,expired,timeout,timed_out",
    ));
    let failed_keys = split_csv(&env_or(
        "WXY_ADAPTER_STATUS_FAILED",
        "fail,failed,deny,reject,cancel,cancelled,error",
    ));

    if confirmed_keys.iter().any(|k| s.contains(k)) {
        return WxyQrStatus::Confirmed;
    }
    if scanned_keys.iter().any(|k| s.contains(k)) {
        return WxyQrStatus::Scanned;
    }
    if expired_keys.iter().any(|k| s.contains(k)) {
        return WxyQrStatus::Expired;
    }
    if failed_keys.iter().any(|k| s.contains(k)) {
        return WxyQrStatus::Failed;
    }
    WxyQrStatus::Pending
}

async fn call_wxy_start_qr(body: &StartWxyQrLoginRequest) -> Result<WxyQrSession, AppError> {
    let api_base = env_required("WXY_API_BASE")?;
    let path = std::env::var("WXY_QR_START_PATH").unwrap_or_else(|_| "/auth/qr/start".to_string());
    let url = format!("{}{}", api_base.trim_end_matches('/'), path);

    let client_id = std::env::var("WXY_CLIENT_ID").unwrap_or_default();
    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    let method = env_or("WXY_QR_START_METHOD", "POST").to_uppercase();
    let mut req_map = serde_json::Map::new();
    req_map.insert("client_id".to_string(), Value::String(client_id));
    req_map.insert(
        "scope".to_string(),
        Value::String(
            body.scope
                .clone()
                .unwrap_or_else(|| "edge.compute".to_string()),
        ),
    );
    if let Some(redirect) = &body.redirect_uri {
        req_map.insert("redirect_uri".to_string(), Value::String(redirect.clone()));
    }
    if let Some(state) = &body.state {
        req_map.insert("state".to_string(), Value::String(state.clone()));
    }

    if let Ok(extra_json) = std::env::var("WXY_QR_START_EXTRA_JSON") {
        if let Ok(extra) = serde_json::from_str::<Value>(&extra_json) {
            merge_json(&mut req_map, extra);
        }
    }

    let req_body = Value::Object(req_map);

    let mut req_builder = if method == "GET" {
        client.get(&url)
    } else {
        client.post(&url)
    };
    req_builder = req_builder.header("Accept", "application/json");
    if method != "GET" {
        req_builder = req_builder.json(&req_body);
    }

    let resp = req_builder
        .send()
        .await
        .map_err(|e| AppError::BadRequest(format!("WXY start QR request failed: {}", e)))?;

    if !resp.status().is_success() {
        return Err(AppError::BadRequest(format!(
            "WXY start QR returned status {}",
            resp.status()
        )));
    }

    let json: Value = resp
        .json()
        .await
        .map_err(|e| AppError::BadRequest(format!("WXY start QR parse failed: {}", e)))?;

    let qr_url = get_first_string(
        &json,
        "WXY_ADAPTER_QR_URL_PATHS",
        &[
            "qr_url",
            "qrcode_url",
            "data.qr_url",
            "data.qrcode_url",
            "data.url",
            "result.qr_url",
        ],
    )
    .ok_or_else(|| AppError::BadRequest("WXY response missing qr_url".to_string()))?;

    let session_id = get_first_string(
        &json,
        "WXY_ADAPTER_SESSION_ID_PATHS",
        &["session_id", "sid", "data.session_id", "result.session_id"],
    )
    .unwrap_or_else(|| Uuid::new_v4().to_string());

    let device_code = get_first_string(
        &json,
        "WXY_ADAPTER_DEVICE_CODE_PATHS",
        &["device_code", "data.device_code", "result.device_code"],
    );

    let now = now_epoch();
    Ok(WxyQrSession {
        session_id,
        qr_url,
        device_code,
        status: WxyQrStatus::Pending,
        created_at: now,
        updated_at: now,
        raw: Some(json),
    })
}

async fn call_wxy_poll_qr(session: &WxyQrSession) -> Result<(WxyQrStatus, Value), AppError> {
    let api_base = env_required("WXY_API_BASE")?;
    let mut path = std::env::var("WXY_QR_POLL_PATH")
        .unwrap_or_else(|_| "/auth/qr/poll/{session_id}".to_string());
    path = path.replace("{session_id}", &session.session_id);
    if let Some(code) = &session.device_code {
        path = path.replace("{device_code}", code);
    }

    let url = format!("{}{}", api_base.trim_end_matches('/'), path);
    let method = env_or("WXY_QR_POLL_METHOD", "GET").to_uppercase();

    let client_id = std::env::var("WXY_CLIENT_ID").unwrap_or_default();
    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    let mut req_map = serde_json::Map::new();
    req_map.insert("client_id".to_string(), Value::String(client_id));
    req_map.insert(
        "session_id".to_string(),
        Value::String(session.session_id.clone()),
    );
    if let Some(code) = &session.device_code {
        req_map.insert("device_code".to_string(), Value::String(code.clone()));
    }
    if let Ok(extra_json) = std::env::var("WXY_QR_POLL_EXTRA_JSON") {
        if let Ok(extra) = serde_json::from_str::<Value>(&extra_json) {
            merge_json(&mut req_map, extra);
        }
    }
    let req_body = Value::Object(req_map);

    let mut req_builder = if method == "POST" {
        client.post(&url)
    } else {
        client.get(&url)
    };
    req_builder = req_builder.header("Accept", "application/json");
    if method == "POST" {
        req_builder = req_builder.json(&req_body);
    }

    let resp = req_builder
        .send()
        .await
        .map_err(|e| AppError::BadRequest(format!("WXY poll failed: {}", e)))?;

    if !resp.status().is_success() {
        return Err(AppError::BadRequest(format!(
            "WXY poll returned status {}",
            resp.status()
        )));
    }

    let json: Value = resp
        .json()
        .await
        .map_err(|e| AppError::BadRequest(format!("WXY poll parse failed: {}", e)))?;

    let raw_status = get_first_string(
        &json,
        "WXY_ADAPTER_STATUS_PATHS",
        &[
            "status",
            "data.status",
            "result.status",
            "code",
            "data.code",
        ],
    )
    .unwrap_or_else(|| "pending".to_string());

    Ok((status_from_text(&raw_status), json))
}

async fn call_wxy_refresh_token(current: &WxyAuthToken) -> Result<WxyAuthToken, AppError> {
    let refresh_token = current
        .refresh_token
        .as_ref()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::PreconditionFailed("Missing refresh token".to_string()))?;

    let api_base = env_required("WXY_API_BASE")?;
    let path = env_or("WXY_TOKEN_REFRESH_PATH", "/auth/token/refresh");
    let method = env_or("WXY_TOKEN_REFRESH_METHOD", "POST").to_uppercase();
    let url = format!("{}{}", api_base.trim_end_matches('/'), path);
    let timeout_secs = env_u64("WXY_TOKEN_REFRESH_TIMEOUT_SECS", 20).max(1);

    let client = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    let mut req_map = serde_json::Map::new();
    req_map.insert(
        "client_id".to_string(),
        Value::String(std::env::var("WXY_CLIENT_ID").unwrap_or_default()),
    );
    req_map.insert(
        "refresh_token".to_string(),
        Value::String(refresh_token.to_string()),
    );
    req_map.insert(
        "access_token".to_string(),
        Value::String(current.access_token.clone()),
    );

    if let Ok(extra_json) = std::env::var("WXY_TOKEN_REFRESH_EXTRA_JSON") {
        if let Ok(extra) = serde_json::from_str::<Value>(&extra_json) {
            merge_json(&mut req_map, extra);
        }
    }

    let req_body = Value::Object(req_map);
    let mut req_builder = if method == "GET" {
        client.get(&url)
    } else {
        client.post(&url)
    };
    req_builder = req_builder.header("Accept", "application/json");
    if method != "GET" {
        req_builder = req_builder.json(&req_body);
    }

    let resp = req_builder
        .send()
        .await
        .map_err(|e| AppError::BadRequest(format!("WXY refresh request failed: {}", e)))?;
    if !resp.status().is_success() {
        return Err(AppError::BadRequest(format!(
            "WXY refresh returned status {}",
            resp.status()
        )));
    }

    let json: Value = resp
        .json()
        .await
        .map_err(|e| AppError::BadRequest(format!("WXY refresh parse failed: {}", e)))?;

    let mut next = extract_auth_from_poll_json(&json).ok_or_else(|| {
        AppError::BadRequest("WXY refresh response missing access token".to_string())
    })?;
    next.provider = "wangxinyun".to_string();
    if next.refresh_token.as_ref().is_none_or(|v| v.is_empty()) {
        next.refresh_token = current.refresh_token.clone();
    }
    if next.account_id.is_none() {
        next.account_id = current.account_id.clone();
    }
    next.login_at = current.login_at;

    Ok(next)
}

fn extract_auth_from_poll_json(json: &Value) -> Option<WxyAuthToken> {
    let access_token = get_first_string(
        json,
        "WXY_ADAPTER_ACCESS_TOKEN_PATHS",
        &[
            "access_token",
            "data.access_token",
            "result.access_token",
            "data.token",
            "result.token",
        ],
    )?;

    let refresh_token = get_first_string(
        json,
        "WXY_ADAPTER_REFRESH_TOKEN_PATHS",
        &[
            "refresh_token",
            "data.refresh_token",
            "result.refresh_token",
        ],
    );

    let account_id = get_first_string(
        json,
        "WXY_ADAPTER_ACCOUNT_ID_PATHS",
        &[
            "account_id",
            "data.account_id",
            "result.account_id",
            "data.user_id",
            "result.user_id",
            "data.uid",
        ],
    );

    let expires_at = get_first_i64(
        json,
        "WXY_ADAPTER_EXPIRES_AT_PATHS",
        &["expires_at", "data.expires_at", "result.expires_at"],
    )
    .or_else(|| {
        get_first_i64(
            json,
            "WXY_ADAPTER_EXPIRES_IN_PATHS",
            &["expires_in", "data.expires_in", "result.expires_in"],
        )
        .map(|sec| now_epoch() + sec)
    });

    Some(WxyAuthToken {
        provider: "wangxinyun".to_string(),
        account_id,
        access_token,
        refresh_token,
        expires_at,
        login_at: now_epoch(),
        extra: Some(json.clone()),
    })
}

pub async fn register_node(
    req: HttpRequest,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<RegisterNodeRequest>,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    ensure_admin(&claims)?;
    let mgr = manager().await?;
    let node_id = mgr.register_node(body.into_inner()).await?;
    Ok(HttpResponse::Created().json(RegisterNodeResponse {
        node_id,
        status: "registered".to_string(),
    }))
}

pub async fn start_wxy_qr_login(
    req: HttpRequest,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<StartWxyQrLoginRequest>,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    ensure_admin(&claims)?;
    let mgr = manager().await?;

    let session = call_wxy_start_qr(&body.into_inner()).await?;
    let sid = session.session_id.clone();

    mgr.wxy_qr_sessions
        .write()
        .await
        .insert(sid.clone(), session.clone());
    mgr.persist_wxy_qr_sessions().await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "session_id": sid,
        "qr_url": session.qr_url,
        "status": session.status,
        "created_at": session.created_at,
    })))
}

pub async fn poll_wxy_qr_login(
    req: HttpRequest,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    ensure_admin(&claims)?;
    let mgr = manager().await?;
    let session_id = path.into_inner();

    let existing = {
        let sessions = mgr.wxy_qr_sessions.read().await;
        sessions
            .get(&session_id)
            .cloned()
            .ok_or_else(|| AppError::NotFound("QR session not found".to_string()))?
    };

    let (status, raw) = call_wxy_poll_qr(&existing).await?;
    let mut updated = existing.clone();
    updated.status = status.clone();
    updated.updated_at = now_epoch();
    updated.raw = Some(raw.clone());

    if status == WxyQrStatus::Confirmed {
        if let Some(token) = extract_auth_from_poll_json(&raw) {
            *mgr.wxy_auth.write().await = Some(token);
            mgr.persist_wxy_auth().await?;
        }
    }

    mgr.wxy_qr_sessions
        .write()
        .await
        .insert(session_id.clone(), updated.clone());
    mgr.persist_wxy_qr_sessions().await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "session_id": session_id,
        "status": updated.status,
        "updated_at": updated.updated_at,
        "logged_in": mgr.wxy_auth.read().await.is_some(),
        "raw": updated.raw,
    })))
}

pub async fn bind_wxy_token(
    req: HttpRequest,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<BindWxyTokenRequest>,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    ensure_admin(&claims)?;
    let mgr = manager().await?;
    let b = body.into_inner();

    let token = WxyAuthToken {
        provider: "wangxinyun".to_string(),
        account_id: b.account_id,
        access_token: b.access_token,
        refresh_token: b.refresh_token,
        expires_at: b.expires_at,
        login_at: now_epoch(),
        extra: b.extra,
    };

    *mgr.wxy_auth.write().await = Some(token);
    mgr.persist_wxy_auth().await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "bound",
        "provider": "wangxinyun",
    })))
}

pub async fn wxy_auth_status(
    req: HttpRequest,
    claims: web::ReqData<crate::handlers::auth::Claims>,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    ensure_admin(&claims)?;
    let mgr = manager().await?;
    let refresh_report = mgr.ensure_wxy_auth_valid(false).await;
    let auth = mgr.wxy_auth.read().await.clone();
    let logged_in = auth.is_some();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "provider": "wangxinyun",
        "logged_in": logged_in,
        "account_id": auth.as_ref().and_then(|a| a.account_id.clone()),
        "expires_at": auth.as_ref().and_then(|a| a.expires_at),
        "login_at": auth.as_ref().map(|a| a.login_at),
        "refresh": refresh_report,
        "last_refresh": mgr.last_wxy_refresh.read().await.clone(),
    })))
}

pub async fn refresh_wxy_auth_token(
    req: HttpRequest,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: Option<web::Json<RefreshWxyTokenRequest>>,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    ensure_admin(&claims)?;
    let mgr = manager().await?;
    let force = body.as_ref().and_then(|b| b.force).unwrap_or(true);
    let report = mgr.ensure_wxy_auth_valid(force).await;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "provider": "wangxinyun",
        "refresh": report,
        "logged_in": mgr.wxy_auth.read().await.is_some(),
    })))
}

pub async fn wxy_logout(
    req: HttpRequest,
    claims: web::ReqData<crate::handlers::auth::Claims>,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    ensure_admin(&claims)?;
    let mgr = manager().await?;
    *mgr.wxy_auth.write().await = None;
    *mgr.last_wxy_refresh.write().await = None;
    mgr.persist_wxy_auth().await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "provider": "wangxinyun",
        "status": "logged_out",
    })))
}

pub async fn node_heartbeat(
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<HeartbeatRequest>,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    let mgr = manager().await?;
    mgr.heartbeat(&path.into_inner(), body.status.clone())
        .await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
    })))
}

pub async fn list_nodes(
    req: HttpRequest,
    claims: web::ReqData<crate::handlers::auth::Claims>,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    ensure_admin(&claims)?;
    let mgr = manager().await?;
    let nodes = mgr.nodes.read().await;
    let mut result: Vec<EdgeNode> = nodes.values().cloned().collect();
    for node in &mut result {
        if !node_is_online(node) {
            node.status = NodeStatus::Offline;
        }
    }
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "items": result,
        "total": result.len(),
    })))
}

pub async fn submit_job(
    req: HttpRequest,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<SubmitJobRequest>,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    let mgr = manager().await?;
    let job_id = mgr
        .submit_job(claims.sub.clone(), body.into_inner())
        .await?;
    Ok(HttpResponse::Accepted().json(SubmitJobResponse {
        job_id,
        status: "queued".to_string(),
    }))
}

pub async fn get_job(
    req: HttpRequest,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    let mgr = manager().await?;
    let jobs = mgr.jobs.read().await;
    let job = jobs
        .get(&path.into_inner())
        .ok_or_else(|| AppError::NotFound("Job not found".to_string()))?;
    if !can_access_job(job, &claims) {
        return Err(AppError::Forbidden("Job access denied".to_string()));
    }
    Ok(HttpResponse::Ok().json(job))
}

pub async fn list_jobs(
    req: HttpRequest,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    query: web::Query<JobsQuery>,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    let mgr = manager().await?;
    let limit = query.limit.unwrap_or(100).min(1000) as usize;

    let mut jobs: Vec<EdgeJob> = mgr
        .jobs
        .read()
        .await
        .values()
        .filter(|j| can_access_job(j, &claims))
        .filter(|j| query.status.as_ref().is_none_or(|s| j.status == *s))
        .cloned()
        .collect();

    jobs.sort_by_key(|job| std::cmp::Reverse(job.created_at));
    if jobs.len() > limit {
        jobs.truncate(limit);
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "items": jobs,
        "total": jobs.len(),
    })))
}

pub async fn cancel_job(
    req: HttpRequest,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    let mgr = manager().await?;
    mgr.cancel_job(&path.into_inner(), &claims).await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "cancelled",
    })))
}

pub async fn retry_job(
    req: HttpRequest,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    let mgr = manager().await?;

    let mut jobs = mgr.jobs.write().await;
    let job = jobs
        .get_mut(&path.into_inner())
        .ok_or_else(|| AppError::NotFound("Job not found".to_string()))?;
    if !can_access_job(job, &claims) {
        return Err(AppError::Forbidden("Job access denied".to_string()));
    }

    if job.status != JobStatus::Failed && job.status != JobStatus::Cancelled {
        return Err(AppError::Conflict(
            "Only failed/cancelled jobs can be retried".to_string(),
        ));
    }

    job.status = JobStatus::Pending;
    job.started_at = None;
    job.finished_at = None;
    job.assigned_node = None;
    job.error = None;
    job.retry_count = 0;
    drop(jobs);

    mgr.persist_jobs().await?;
    mgr.wakeup.notify_waiters();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "requeued",
    })))
}

pub async fn edge_stats(
    req: HttpRequest,
    claims: web::ReqData<crate::handlers::auth::Claims>,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    ensure_admin(&claims)?;
    let mgr = manager().await?;
    let stats = mgr.stats().await;
    Ok(HttpResponse::Ok().json(stats))
}

pub async fn get_startup_self_check(
    req: HttpRequest,
    claims: web::ReqData<crate::handlers::auth::Claims>,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    ensure_admin(&claims)?;
    let mgr = manager().await?;
    let existing = mgr.startup_self_check.read().await.clone();

    if let Some(report) = existing {
        return Ok(HttpResponse::Ok().json(report));
    }

    let report = mgr.run_startup_self_check("on_demand_initial").await;
    *mgr.startup_self_check.write().await = Some(report.clone());
    Ok(HttpResponse::Ok().json(report))
}

pub async fn run_startup_self_check_now(
    req: HttpRequest,
    claims: web::ReqData<crate::handlers::auth::Claims>,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    ensure_admin(&claims)?;
    let mgr = manager().await?;
    let report = mgr.run_startup_self_check("manual").await;
    *mgr.startup_self_check.write().await = Some(report.clone());
    Ok(HttpResponse::Ok().json(report))
}

pub async fn health() -> Result<HttpResponse, AppError> {
    let mgr = manager().await?;
    let stats = mgr.stats().await;
    let logged_in = mgr.wxy_auth.read().await.is_some();
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "service": "edge-compute",
        "status": "ok",
        "stats": stats,
        "wxy_logged_in": logged_in,
        "now": now_epoch(),
    })))
}

pub async fn admin_health(
    req: HttpRequest,
    claims: web::ReqData<crate::handlers::auth::Claims>,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    ensure_admin(&claims)?;
    let mgr = manager().await?;
    let stats = mgr.stats().await;
    let logged_in = mgr.wxy_auth.read().await.is_some();
    let startup_report = mgr.startup_self_check.read().await.clone();
    let last_refresh = mgr.last_wxy_refresh.read().await.clone();
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "service": "edge-compute",
        "status": "ok",
        "stats": stats,
        "wxy_logged_in": logged_in,
        "wxy_last_refresh": last_refresh,
        "startup_self_check": startup_report,
        "now": now_epoch(),
    })))
}

pub async fn builtin_wxy_edge_node_status() -> Result<Value, AppError> {
    let mgr = manager().await?;
    let stats = mgr.stats().await;
    let logged_in = mgr.wxy_auth.read().await.is_some();

    Ok(serde_json::json!({
        "service": "edge-compute",
        "status": "ok",
        "stats": stats,
        "wxy_logged_in": logged_in,
        "now": now_epoch(),
    }))
}
