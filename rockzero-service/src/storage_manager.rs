use serde::{Deserialize, Serialize};
use std::collections::BinaryHeap;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use sysinfo::System;
use tokio::fs;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CachePressureLevel {
    Normal,
    Warning,
    Critical,
    Emergency,
}

impl std::fmt::Display for CachePressureLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Normal => write!(f, "Normal"),
            Self::Warning => write!(f, "Warning"),
            Self::Critical => write!(f, "Critical"),
            Self::Emergency => write!(f, "Emergency"),
        }
    }
}

const WINDOWS_UNCONFIGURED_STORAGE_ROOT: &str = "./storage/unconfigured";
const WINDOWS_PORTABLE_STORAGE_ROOT: &str = "./storage";
const WINDOWS_STORAGE_BINDING_FILE: &str = "windows-storage-root.json";
const HLS_CACHE_PROTECTION_SECS: u64 = 600;
const WINDOWS_STORAGE_ROOT_ENV_KEYS: &[&str] =
    &["ROCKZERO_WINDOWS_STORAGE_ROOT", "EXTERNAL_STORAGE_PATH"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsStorageBinding {
    pub selected_root: PathBuf,
    pub configured_at_unix: u64,
}

#[cfg(target_os = "windows")]
fn has_windows_drive_prefix(path: &Path) -> bool {
    use std::path::{Component, Prefix};

    matches!(
        path.components().next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    )
}

#[cfg(target_os = "windows")]
pub fn is_windows_drive_root(path: &Path) -> bool {
    use std::path::{Component, Prefix};

    let mut components = path.components();
    matches!(
        components.next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    ) && matches!(components.next(), Some(Component::RootDir))
        && components.next().is_none()
}

#[cfg(not(target_os = "windows"))]
pub fn is_windows_drive_root(_path: &Path) -> bool {
    false
}

#[cfg(target_os = "windows")]
fn prepare_windows_storage_root_candidate(
    root: PathBuf,
    allow_create: bool,
    source: &str,
) -> std::io::Result<Option<PathBuf>> {
    if allow_create && !root.exists() {
        std::fs::create_dir_all(&root)?;
    }

    if !root.exists() || !root.is_dir() {
        return Ok(None);
    }

    let canonical = root.canonicalize().unwrap_or(root);
    if !canonical.is_absolute() || !has_windows_drive_prefix(&canonical) {
        warn!(
            "Ignoring Windows storage root candidate from {} because it is not an absolute local drive path: {}",
            source,
            canonical.display()
        );
        return Ok(None);
    }

    if is_windows_drive_root(&canonical) {
        warn!(
            "Ignoring Windows storage root candidate from {} because drive roots are not allowed: {}",
            source,
            canonical.display()
        );
        return Ok(None);
    }

    Ok(Some(canonical))
}

#[cfg(target_os = "windows")]
fn try_initialize_windows_storage_binding() -> std::io::Result<Option<WindowsStorageBinding>> {
    for key in WINDOWS_STORAGE_ROOT_ENV_KEYS {
        let Some(raw) = env::var(key).ok().filter(|value| !value.trim().is_empty()) else {
            continue;
        };

        if let Some(candidate) =
            prepare_windows_storage_root_candidate(PathBuf::from(raw), false, key)?
        {
            let binding = persist_windows_storage_binding(&candidate)?;
            info!(
                "Auto-configured Windows storage root from {}: {}",
                key,
                binding.selected_root.display()
            );
            return Ok(Some(binding));
        }
    }

    let portable_root = PathBuf::from(WINDOWS_PORTABLE_STORAGE_ROOT);
    if let Some(candidate) =
        prepare_windows_storage_root_candidate(portable_root, true, "portable storage root")?
    {
        info!(
            "Detected portable Windows storage root candidate but leaving selection explicit: {}",
            candidate.display()
        );
        return Ok(None);
    }

    Ok(None)
}

fn storage_data_dir() -> PathBuf {
    env::var("DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./data"))
}

pub fn windows_storage_binding_path() -> PathBuf {
    storage_data_dir()
        .join("storage")
        .join(WINDOWS_STORAGE_BINDING_FILE)
}

pub fn load_windows_storage_binding() -> std::io::Result<Option<WindowsStorageBinding>> {
    if !cfg!(target_os = "windows") {
        return Ok(None);
    }

    let binding_path = windows_storage_binding_path();
    if !binding_path.exists() {
        #[cfg(target_os = "windows")]
        {
            return try_initialize_windows_storage_binding();
        }

        #[allow(unreachable_code)]
        return Ok(None);
    }

    let raw = std::fs::read_to_string(&binding_path)?;
    let mut binding: WindowsStorageBinding = serde_json::from_str(&raw)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    match prepare_windows_storage_root_candidate(
        binding.selected_root.clone(),
        false,
        "persisted binding",
    )? {
        Some(validated_root) => {
            binding.selected_root = validated_root;
            Ok(Some(binding))
        }
        None => try_initialize_windows_storage_binding(),
    }
}

pub fn apply_storage_root_environment(root: &Path) {
    let external = root.to_path_buf();
    env::set_var("EXTERNAL_STORAGE_PATH", &external);
    env::set_var("VIDEO_STORAGE_PATH", external.join("videos"));
    env::set_var("TEMP_STORAGE_PATH", external.join("temp"));
    env::set_var("HLS_CACHE_PATH", external.join("cache").join("hls"));
    env::set_var("LOG_PATH", external.join("logs"));
}

pub fn persist_windows_storage_binding(root: &Path) -> std::io::Result<WindowsStorageBinding> {
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let binding = WindowsStorageBinding {
        selected_root: canonical_root.clone(),
        configured_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let binding_path = windows_storage_binding_path();
    if let Some(parent) = binding_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&binding_path, serde_json::to_vec_pretty(&binding)?)?;
    apply_storage_root_environment(&canonical_root);

    Ok(binding)
}

fn default_external_storage_root() -> PathBuf {
    if cfg!(target_os = "windows") {
        if let Ok(Some(binding)) = load_windows_storage_binding() {
            apply_storage_root_environment(&binding.selected_root);
            return binding.selected_root;
        }

        return PathBuf::from(WINDOWS_UNCONFIGURED_STORAGE_ROOT);
    }

    PathBuf::from("/mnt/external")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub external_storage_path: PathBuf,
    pub video_storage_path: PathBuf,
    pub temp_storage_path: PathBuf,
    pub hls_cache_path: PathBuf,
    pub log_path: PathBuf,
    pub min_free_space: u64,
    pub min_free_memory: u64,
    pub warning_free_memory: u64,
    pub warning_free_space: u64,
    pub critical_free_space: u64,
    pub max_hls_cache_size: u64,
    pub max_temp_size: u64,
    pub max_log_size: u64,
    pub hls_cache_retention_days: u64,
    pub temp_file_retention_days: u64,
    pub log_retention_days: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        let external = default_external_storage_root();
        Self {
            external_storage_path: external.clone(),
            video_storage_path: external.join("videos"),
            temp_storage_path: external.join("temp"),
            hls_cache_path: external.join("cache/hls"),
            log_path: external.join("logs"),
            min_free_space: 512 * 1024 * 1024,
            min_free_memory: 512 * 1024 * 1024,
            warning_free_memory: 768 * 1024 * 1024,
            warning_free_space: 2 * 1024 * 1024 * 1024,
            critical_free_space: 1024 * 1024 * 1024,
            max_hls_cache_size: 1024 * 1024 * 1024,
            max_temp_size: 1024 * 1024 * 1024,
            max_log_size: 512 * 1024 * 1024,
            hls_cache_retention_days: 1,
            temp_file_retention_days: 1,
            log_retention_days: 30,
        }
    }
}

impl StorageConfig {
    pub fn from_env() -> Self {
        let defaults = Self::default();
        let env_u64 = |var: &str, default: u64| -> u64 {
            env::var(var)
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default)
        };

        let external_storage_path = env::var("EXTERNAL_STORAGE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| defaults.external_storage_path.clone());

        Self {
            external_storage_path: external_storage_path.clone(),
            video_storage_path: env::var("VIDEO_STORAGE_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| external_storage_path.join("videos")),
            temp_storage_path: env::var("TEMP_STORAGE_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| external_storage_path.join("temp")),
            hls_cache_path: env::var("HLS_CACHE_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| external_storage_path.join("cache").join("hls")),
            log_path: env::var("LOG_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| external_storage_path.join("logs")),
            min_free_space: env_u64("MIN_FREE_SPACE", defaults.min_free_space),
            min_free_memory: env_u64("MIN_FREE_MEMORY", defaults.min_free_memory),
            warning_free_memory: env_u64("WARNING_FREE_MEMORY", defaults.warning_free_memory),
            warning_free_space: env_u64("WARNING_FREE_SPACE", defaults.warning_free_space),
            critical_free_space: env_u64("CRITICAL_FREE_SPACE", defaults.critical_free_space),
            max_hls_cache_size: env_u64("MAX_HLS_CACHE_SIZE", defaults.max_hls_cache_size),
            max_temp_size: env_u64("MAX_TEMP_SIZE", defaults.max_temp_size),
            max_log_size: env_u64("MAX_LOG_SIZE", defaults.max_log_size),
            hls_cache_retention_days: env_u64(
                "HLS_CACHE_RETENTION_DAYS",
                defaults.hls_cache_retention_days,
            ),
            temp_file_retention_days: env_u64(
                "TEMP_FILE_RETENTION_DAYS",
                defaults.temp_file_retention_days,
            ),
            log_retention_days: env_u64("LOG_RETENTION_DAYS", defaults.log_retention_days),
        }
        .normalize_external_paths()
    }

    fn normalize_external_paths(mut self) -> Self {
        self.video_storage_path = coerce_external_path(
            &self.video_storage_path,
            &self.external_storage_path,
            "videos",
        );
        self.temp_storage_path =
            coerce_external_path(&self.temp_storage_path, &self.external_storage_path, "temp");
        self.hls_cache_path = coerce_external_path(
            &self.hls_cache_path,
            &self.external_storage_path,
            "cache/hls",
        );
        self.log_path = coerce_external_path(&self.log_path, &self.external_storage_path, "logs");
        self
    }

    pub async fn init_directories(&self) -> std::io::Result<()> {
        for dir in [
            &self.external_storage_path,
            &self.video_storage_path,
            &self.temp_storage_path,
            &self.hls_cache_path,
            &self.log_path,
        ] {
            match fs::create_dir_all(dir).await {
                Ok(_) => info!("Initialized storage directory: {:?}", dir),
                Err(e) => warn!("Failed to create directory {:?}: {}", dir, e),
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CleanupReport {
    pub hls_bytes_freed: u64,
    pub temp_bytes_freed: u64,
    pub log_bytes_freed: u64,
    pub total_bytes_freed: u64,
}

#[derive(Debug, Eq, PartialEq)]
struct CacheEntry {
    path: PathBuf,
    size: u64,
    last_access: u64,
    is_dir: bool,
}

impl Ord for CacheEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.last_access.cmp(&self.last_access)
    }
}

impl PartialOrd for CacheEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub struct StorageManager {
    config: StorageConfig,
    cleanup_lock: Mutex<()>,
    hls_cache_bytes: AtomicU64,
    temp_bytes: AtomicU64,
    log_bytes: AtomicU64,
}

impl StorageManager {
    pub fn new(config: StorageConfig) -> Self {
        Self {
            config,
            cleanup_lock: Mutex::new(()),
            hls_cache_bytes: AtomicU64::new(0),
            temp_bytes: AtomicU64::new(0),
            log_bytes: AtomicU64::new(0),
        }
    }

    async fn refresh_cache_sizes(&self) {
        if let Ok(s) = get_directory_size(&self.config.hls_cache_path).await {
            self.hls_cache_bytes.store(s, Ordering::Relaxed);
        }
        if let Ok(s) = get_directory_size(&self.config.temp_storage_path).await {
            self.temp_bytes.store(s, Ordering::Relaxed);
        }
        if let Ok(s) = get_directory_size(&self.config.log_path).await {
            self.log_bytes.store(s, Ordering::Relaxed);
        }
    }

    pub async fn get_pressure_level(&self) -> CachePressureLevel {
        let available = match get_available_space(&self.config.external_storage_path).await {
            Ok(a) => a,
            Err(_) => return CachePressureLevel::Normal,
        };

        if available < self.config.min_free_space {
            CachePressureLevel::Emergency
        } else if available < self.config.critical_free_space {
            CachePressureLevel::Critical
        } else if available < self.config.warning_free_space {
            CachePressureLevel::Warning
        } else {
            CachePressureLevel::Normal
        }
    }

    pub fn get_memory_pressure_level(&self) -> CachePressureLevel {
        let available = get_available_memory_bytes();
        if available < self.config.min_free_memory {
            CachePressureLevel::Emergency
        } else if available < self.config.warning_free_memory {
            CachePressureLevel::Warning
        } else {
            CachePressureLevel::Normal
        }
    }

    pub async fn get_accurate_disk_usage(
        &self,
        mount_point: &Path,
    ) -> std::io::Result<AccurateDiskUsage> {
        let (total, available, used) = get_filesystem_stats(mount_point).await?;
        let cache_size = self.hls_cache_bytes.load(Ordering::Relaxed)
            + self.temp_bytes.load(Ordering::Relaxed)
            + self.log_bytes.load(Ordering::Relaxed);
        let actual_user_data = used.saturating_sub(cache_size);

        Ok(AccurateDiskUsage {
            total_space: total,
            available_space: available,
            used_space: used,
            cache_size,
            actual_user_data,
            usage_percentage: if total > 0 {
                (used as f64 / total as f64) * 100.0
            } else {
                0.0
            },
        })
    }

    #[allow(dead_code)]
    async fn get_total_cache_size(&self) -> u64 {
        self.hls_cache_bytes.load(Ordering::Relaxed)
            + self.temp_bytes.load(Ordering::Relaxed)
            + self.log_bytes.load(Ordering::Relaxed)
    }

    pub async fn get_storage_stats(&self) -> StorageStats {
        self.refresh_cache_sizes().await;

        let hls = self.hls_cache_bytes.load(Ordering::Relaxed);
        let temp = self.temp_bytes.load(Ordering::Relaxed);
        let logs = self.log_bytes.load(Ordering::Relaxed);

        let video_size = get_directory_size(&self.config.video_storage_path)
            .await
            .unwrap_or(0);

        let db_size = get_db_files_size(&PathBuf::from("./data"))
            .await
            .unwrap_or(0);

        let total_app_usage = hls + temp + logs + video_size + db_size;

        let available = get_available_space(&self.config.external_storage_path)
            .await
            .unwrap_or(0);

        StorageStats {
            hls_cache_size: hls,
            temp_storage_size: temp,
            log_size: logs,
            video_storage_size: video_size,
            database_size: db_size,
            total_app_usage,
            available_space: available,
        }
    }

    #[allow(dead_code)]
    pub fn get_hls_cache_path(&self) -> &Path {
        &self.config.hls_cache_path
    }

    pub async fn get_auto_cleanup_status(&self) -> AutoCleanupStatus {
        self.refresh_cache_sizes().await;

        let hls = self.hls_cache_bytes.load(Ordering::Relaxed);
        let temp = self.temp_bytes.load(Ordering::Relaxed);
        let logs = self.log_bytes.load(Ordering::Relaxed);
        let total_cache = hls + temp;
        let threshold: u64 = 1024 * 1024 * 1024;

        let usage_percent = if threshold > 0 {
            (total_cache as f64 / threshold as f64 * 100.0).min(100.0)
        } else {
            0.0
        };

        let memory_pressure = self.get_memory_pressure_level();
        let status = if total_cache > threshold || memory_pressure == CachePressureLevel::Emergency
        {
            "cleaning".to_string()
        } else if total_cache as f64 > threshold as f64 * 0.8
            || memory_pressure == CachePressureLevel::Warning
        {
            "warning".to_string()
        } else {
            "healthy".to_string()
        };

        let pressure = self.get_pressure_level().await;
        let available_memory = get_available_memory_bytes();

        AutoCleanupStatus {
            enabled: true,
            status,
            threshold_bytes: threshold,
            threshold_display: "1 GB".to_string(),
            hls_cache_bytes: hls,
            temp_bytes: temp,
            log_bytes: logs,
            total_cache_bytes: total_cache,
            usage_percent,
            pressure_level: format!("{}", pressure),
            available_memory_bytes: available_memory,
            min_reserved_memory_bytes: self.config.min_free_memory,
            memory_pressure_level: format!("{}", memory_pressure),
            check_interval_secs: 30,
        }
    }

    pub async fn force_cleanup_all_cache(&self) -> std::io::Result<CleanupReport> {
        let _guard = self.cleanup_lock.lock().await;
        let mut report = CleanupReport::default();

        if dir_exists(&self.config.hls_cache_path).await {
            report.hls_bytes_freed = get_directory_size(&self.config.hls_cache_path)
                .await
                .unwrap_or(0);
            fs::remove_dir_all(&self.config.hls_cache_path).await.ok();
            fs::create_dir_all(&self.config.hls_cache_path).await.ok();
            self.hls_cache_bytes.store(0, Ordering::Relaxed);
        }

        if dir_exists(&self.config.temp_storage_path).await {
            report.temp_bytes_freed = get_directory_size(&self.config.temp_storage_path)
                .await
                .unwrap_or(0);
            fs::remove_dir_all(&self.config.temp_storage_path)
                .await
                .ok();
            fs::create_dir_all(&self.config.temp_storage_path)
                .await
                .ok();
            self.temp_bytes.store(0, Ordering::Relaxed);
        }

        report.total_bytes_freed = report.hls_bytes_freed + report.temp_bytes_freed;

        info!(
            "Force cleanup completed: {} freed ({} HLS, {} temp)",
            format_bytes(report.total_bytes_freed),
            format_bytes(report.hls_bytes_freed),
            format_bytes(report.temp_bytes_freed),
        );

        Ok(report)
    }

    pub fn start_cleanup_tasks(self: Arc<Self>) {
        let m = self.clone();
        tokio::spawn(async move {
            m.refresh_cache_sizes().await;
            info!(
                "Initial cache sizes 鈥?HLS: {}, Temp: {}, Log: {}",
                format_bytes(m.hls_cache_bytes.load(Ordering::Relaxed)),
                format_bytes(m.temp_bytes.load(Ordering::Relaxed)),
                format_bytes(m.log_bytes.load(Ordering::Relaxed)),
            );
        });

        let m = self.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(3600));
            loop {
                tick.tick().await;
                info!("Starting scheduled cleanup...");
                m.refresh_cache_sizes().await;
                if let Err(e) = m.run_cleanup().await {
                    error!("Scheduled cleanup failed: {}", e);
                }
            }
        });

        let m = self.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                if let Err(e) = m.cleanup_stale_hls_cache(5 * 60).await {
                    warn!("Stale HLS cache cleanup failed: {}", e);
                }
            }
        });

        let m = self.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                match m.get_memory_pressure_level() {
                    CachePressureLevel::Emergency => {
                        warn!(
                            "EMERGENCY memory pressure 鈥?available {} below minimum {}",
                            format_bytes(get_available_memory_bytes()),
                            format_bytes(m.config.min_free_memory),
                        );
                        if let Err(e) = m.emergency_eviction().await {
                            error!("Emergency memory eviction failed: {}", e);
                        }
                        continue;
                    }
                    CachePressureLevel::Warning => {
                        warn!(
                            "Memory pressure warning 鈥?available {} below warning {}",
                            format_bytes(get_available_memory_bytes()),
                            format_bytes(m.config.warning_free_memory),
                        );
                        if let Err(e) = m.aggressive_cleanup().await {
                            error!("Aggressive cleanup (memory pressure) failed: {}", e);
                        }
                    }
                    _ => {}
                }

                match m.get_pressure_level().await {
                    CachePressureLevel::Emergency => {
                        warn!("EMERGENCY disk pressure 鈥?evicting all caches");
                        if let Err(e) = m.emergency_eviction().await {
                            error!("Emergency eviction failed: {}", e);
                        }
                    }
                    CachePressureLevel::Critical => {
                        warn!("Critical disk pressure 鈥?aggressive cleanup");
                        if let Err(e) = m.aggressive_cleanup().await {
                            error!("Aggressive cleanup failed: {}", e);
                        }
                    }
                    CachePressureLevel::Warning => {
                        info!("Disk pressure warning 鈥?running cleanup");
                        if let Err(e) = m.run_cleanup().await {
                            error!("Warning cleanup failed: {}", e);
                        }
                    }
                    CachePressureLevel::Normal => {}
                }
            }
        });

        let m = self.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(600));
            loop {
                tick.tick().await;
                if let Err(e) = m.enforce_cache_limits().await {
                    warn!("Cache limit enforcement failed: {}", e);
                }
            }
        });

        let m = self.clone();
        tokio::spawn(async move {
            let threshold: u64 = 1024 * 1024 * 1024;
            let mut tick = interval(Duration::from_secs(30));
            loop {
                tick.tick().await;

                let hls_size = get_directory_size(&m.config.hls_cache_path)
                    .await
                    .unwrap_or(0);
                let temp_size = get_directory_size(&m.config.temp_storage_path)
                    .await
                    .unwrap_or(0);
                let total = hls_size + temp_size;

                m.hls_cache_bytes.store(hls_size, Ordering::Relaxed);
                m.temp_bytes.store(temp_size, Ordering::Relaxed);

                if total > threshold {
                    let excess = total - threshold;
                    info!(
                        "鈿狅笍 Cache+Temp ({}) exceeds 1GB threshold, auto-cleaning {} ...",
                        format_bytes(total),
                        format_bytes(excess),
                    );

                    let hls_excess = hls_size.saturating_sub(threshold / 2);
                    if hls_excess > 0 {
                        match lru_evict_from_directory(&m.config.hls_cache_path, hls_excess).await {
                            Ok(freed) => {
                                m.hls_cache_bytes
                                    .store(hls_size.saturating_sub(freed), Ordering::Relaxed);
                                info!("馃棏锔?Auto-cleaned HLS cache: {}", format_bytes(freed));
                            }
                            Err(e) => warn!("HLS auto-cleanup failed: {}", e),
                        }
                    }

                    let temp_excess = temp_size.saturating_sub(threshold / 2);
                    if temp_excess > 0 {
                        match lru_evict_from_directory(&m.config.temp_storage_path, temp_excess)
                            .await
                        {
                            Ok(freed) => {
                                m.temp_bytes
                                    .store(temp_size.saturating_sub(freed), Ordering::Relaxed);
                                info!("馃棏锔?Auto-cleaned temp storage: {}", format_bytes(freed));
                            }
                            Err(e) => warn!("Temp auto-cleanup failed: {}", e),
                        }
                    }

                    let new_hls = get_directory_size(&m.config.hls_cache_path)
                        .await
                        .unwrap_or(0);
                    let new_temp = get_directory_size(&m.config.temp_storage_path)
                        .await
                        .unwrap_or(0);
                    m.hls_cache_bytes.store(new_hls, Ordering::Relaxed);
                    m.temp_bytes.store(new_temp, Ordering::Relaxed);

                    info!(
                        "鉁?Auto-cleanup complete 鈥?HLS: {}, Temp: {}, Total: {}",
                        format_bytes(new_hls),
                        format_bytes(new_temp),
                        format_bytes(new_hls + new_temp),
                    );
                }
            }
        });
    }

    async fn enforce_cache_limits(&self) -> std::io::Result<()> {
        let _guard = self.cleanup_lock.lock().await;

        if self.config.max_hls_cache_size > 0 {
            let cur = get_directory_size(&self.config.hls_cache_path)
                .await
                .unwrap_or(0);
            self.hls_cache_bytes.store(cur, Ordering::Relaxed);
            if cur > self.config.max_hls_cache_size {
                let excess = cur - self.config.max_hls_cache_size;
                let freed = lru_evict_from_directory(&self.config.hls_cache_path, excess).await?;
                self.hls_cache_bytes
                    .store(cur.saturating_sub(freed), Ordering::Relaxed);
                info!(
                    "HLS LRU eviction: freed {} (was {}, limit {})",
                    format_bytes(freed),
                    format_bytes(cur),
                    format_bytes(self.config.max_hls_cache_size),
                );
            }
        }

        if self.config.max_temp_size > 0 {
            let cur = get_directory_size(&self.config.temp_storage_path)
                .await
                .unwrap_or(0);
            self.temp_bytes.store(cur, Ordering::Relaxed);
            if cur > self.config.max_temp_size {
                let excess = cur - self.config.max_temp_size;
                let freed =
                    lru_evict_from_directory(&self.config.temp_storage_path, excess).await?;
                self.temp_bytes
                    .store(cur.saturating_sub(freed), Ordering::Relaxed);
                info!(
                    "Temp LRU eviction: freed {} (was {}, limit {})",
                    format_bytes(freed),
                    format_bytes(cur),
                    format_bytes(self.config.max_temp_size),
                );
            }
        }

        if self.config.max_log_size > 0 {
            let cur = get_directory_size(&self.config.log_path).await.unwrap_or(0);
            self.log_bytes.store(cur, Ordering::Relaxed);
            if cur > self.config.max_log_size {
                let excess = cur - self.config.max_log_size;
                let freed = lru_evict_from_directory(&self.config.log_path, excess).await?;
                self.log_bytes
                    .store(cur.saturating_sub(freed), Ordering::Relaxed);
                info!(
                    "Log LRU eviction: freed {} (was {}, limit {})",
                    format_bytes(freed),
                    format_bytes(cur),
                    format_bytes(self.config.max_log_size),
                );
            }
        }

        Ok(())
    }

    async fn emergency_eviction(&self) -> std::io::Result<()> {
        let _guard = self.cleanup_lock.lock().await;
        let mut total_freed = 0u64;

        if dir_exists(&self.config.hls_cache_path).await {
            let sz = get_directory_size(&self.config.hls_cache_path)
                .await
                .unwrap_or(0);
            if fs::remove_dir_all(&self.config.hls_cache_path)
                .await
                .is_ok()
            {
                total_freed += sz;
                fs::create_dir_all(&self.config.hls_cache_path).await.ok();
            }
            self.hls_cache_bytes.store(0, Ordering::Relaxed);
        }

        if dir_exists(&self.config.temp_storage_path).await {
            let sz = get_directory_size(&self.config.temp_storage_path)
                .await
                .unwrap_or(0);
            if fs::remove_dir_all(&self.config.temp_storage_path)
                .await
                .is_ok()
            {
                total_freed += sz;
                fs::create_dir_all(&self.config.temp_storage_path)
                    .await
                    .ok();
            }
            self.temp_bytes.store(0, Ordering::Relaxed);
        }

        if dir_exists(&self.config.log_path).await {
            let freed = cleanup_old_files_bytes(&self.config.log_path, 24 * 3600).await?;
            total_freed += freed;
            let rem = get_directory_size(&self.config.log_path).await.unwrap_or(0);
            self.log_bytes.store(rem, Ordering::Relaxed);
        }

        warn!("Emergency eviction freed {}", format_bytes(total_freed));
        Ok(())
    }

    async fn aggressive_cleanup(&self) -> std::io::Result<()> {
        let _guard = self.cleanup_lock.lock().await;

        if dir_exists(&self.config.hls_cache_path).await {
            let _ = cleanup_old_entries_bytes(
                &self.config.hls_cache_path,
                3600,
                HLS_CACHE_PROTECTION_SECS,
            )
            .await;
        }

        if dir_exists(&self.config.temp_storage_path).await {
            let _ = cleanup_old_files_bytes(&self.config.temp_storage_path, 2 * 3600).await;
        }

        if dir_exists(&self.config.log_path).await {
            let _ = cleanup_old_files_bytes(&self.config.log_path, 3 * 24 * 3600).await;
        }

        self.refresh_cache_sizes().await;
        Ok(())
    }

    pub async fn run_cleanup(&self) -> std::io::Result<()> {
        let _guard = self.cleanup_lock.lock().await;

        if dir_exists(&self.config.hls_cache_path).await {
            let retention = self.config.hls_cache_retention_days * 24 * 3600;
            let freed = cleanup_old_entries_bytes(
                &self.config.hls_cache_path,
                retention,
                HLS_CACHE_PROTECTION_SECS,
            )
            .await?;
            if freed > 0 {
                info!(
                    "Cleaned {} from HLS cache (retention: {}d)",
                    format_bytes(freed),
                    self.config.hls_cache_retention_days,
                );
            }
        }

        if dir_exists(&self.config.temp_storage_path).await {
            let retention = self.config.temp_file_retention_days * 24 * 3600;
            let freed = cleanup_old_files_bytes(&self.config.temp_storage_path, retention).await?;
            if freed > 0 {
                info!(
                    "Cleaned {} from temp (retention: {}d)",
                    format_bytes(freed),
                    self.config.temp_file_retention_days,
                );
            }
        }

        if dir_exists(&self.config.log_path).await {
            let retention = self.config.log_retention_days * 24 * 3600;
            let freed = cleanup_old_files_bytes(&self.config.log_path, retention).await?;
            if freed > 0 {
                info!(
                    "Cleaned {} from logs (retention: {}d)",
                    format_bytes(freed),
                    self.config.log_retention_days,
                );
            }
        }

        self.refresh_cache_sizes().await;
        let mut pressure = self.get_pressure_level().await;

        if pressure >= CachePressureLevel::Warning {
            info!(
                "Disk pressure at {} after standard cleanup 鈥?escalating with shorter retention",
                pressure
            );

            let hls_short = (self.config.hls_cache_retention_days * 24 * 3600) / 4;
            let temp_short = (self.config.temp_file_retention_days * 24 * 3600) / 4;
            let log_short = (self.config.log_retention_days * 24 * 3600) / 4;

            if dir_exists(&self.config.hls_cache_path).await {
                let freed = cleanup_old_entries_bytes(
                    &self.config.hls_cache_path,
                    hls_short,
                    HLS_CACHE_PROTECTION_SECS,
                )
                .await
                .unwrap_or(0);
                if freed > 0 {
                    info!("Escalated HLS cleanup freed {}", format_bytes(freed));
                }
            }
            if dir_exists(&self.config.temp_storage_path).await {
                let freed = cleanup_old_files_bytes(&self.config.temp_storage_path, temp_short)
                    .await
                    .unwrap_or(0);
                if freed > 0 {
                    info!("Escalated temp cleanup freed {}", format_bytes(freed));
                }
            }
            if dir_exists(&self.config.log_path).await {
                let freed = cleanup_old_files_bytes(&self.config.log_path, log_short)
                    .await
                    .unwrap_or(0);
                if freed > 0 {
                    info!("Escalated log cleanup freed {}", format_bytes(freed));
                }
            }

            self.refresh_cache_sizes().await;
            pressure = self.get_pressure_level().await;
        }

        if pressure >= CachePressureLevel::Warning {
            info!(
                "Disk pressure still at {} 鈥?enforcing strict cache limits",
                pressure
            );

            let hls_cur = get_directory_size(&self.config.hls_cache_path)
                .await
                .unwrap_or(0);
            let half_limit = self.config.max_hls_cache_size / 2;
            if hls_cur > half_limit && half_limit > 0 {
                let excess = hls_cur - half_limit;
                let freed = lru_evict_from_directory(&self.config.hls_cache_path, excess)
                    .await
                    .unwrap_or(0);
                if freed > 0 {
                    info!(
                        "Strict HLS LRU eviction freed {} (target: {})",
                        format_bytes(freed),
                        format_bytes(excess)
                    );
                }
            }

            let temp_cur = get_directory_size(&self.config.temp_storage_path)
                .await
                .unwrap_or(0);
            let half_temp = self.config.max_temp_size / 2;
            if temp_cur > half_temp && half_temp > 0 {
                let excess = temp_cur - half_temp;
                let freed = lru_evict_from_directory(&self.config.temp_storage_path, excess)
                    .await
                    .unwrap_or(0);
                if freed > 0 {
                    info!(
                        "Strict temp LRU eviction freed {} (target: {})",
                        format_bytes(freed),
                        format_bytes(excess),
                    );
                }
            }

            self.refresh_cache_sizes().await;
            pressure = self.get_pressure_level().await;
        }

        if pressure >= CachePressureLevel::Warning {
            warn!(
                "Disk pressure remains at {} after all cleanup phases. \
                 Consider increasing storage or reducing WARNING_FREE_SPACE threshold (current: {}).",
                pressure,
                format_bytes(self.config.warning_free_space),
            );
        } else {
            info!("Disk pressure resolved to {} after cleanup", pressure);
        }

        info!("Cleanup completed");
        Ok(())
    }

    pub async fn check_storage_space(&self) -> std::io::Result<()> {
        let checks = [
            ("External Storage", &self.config.external_storage_path),
            ("Video Storage", &self.config.video_storage_path),
            ("HLS Cache", &self.config.hls_cache_path),
        ];

        for (name, path) in checks {
            if !dir_exists(path).await {
                continue;
            }
            match get_available_space(path).await {
                Ok(avail) => {
                    if avail < self.config.min_free_space {
                        warn!(
                            "LOW SPACE on {}: {} available (min: {})",
                            name,
                            format_bytes(avail),
                            format_bytes(self.config.min_free_space),
                        );
                    } else {
                        info!("{}: {} available", name, format_bytes(avail));
                    }
                }
                Err(e) => warn!("Failed to check space for {}: {}", name, e),
            }
        }

        Ok(())
    }

    pub async fn cleanup_hls_cache(&self) -> std::io::Result<()> {
        if !dir_exists(&self.config.hls_cache_path).await {
            return Ok(());
        }
        let retention = self.config.hls_cache_retention_days * 24 * 3600;
        let freed = cleanup_old_entries_bytes(
            &self.config.hls_cache_path,
            retention,
            HLS_CACHE_PROTECTION_SECS,
        )
        .await?;
        if freed > 0 {
            info!("Cleaned {} from old HLS cache", format_bytes(freed));
        }
        Ok(())
    }

    pub async fn cleanup_stale_hls_cache(&self, max_idle_secs: u64) -> std::io::Result<()> {
        if !dir_exists(&self.config.hls_cache_path).await {
            return Ok(());
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut deleted = 0u64;
        let mut freed = 0u64;
        let mut entries = fs::read_dir(&self.config.hls_cache_path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let md = match entry.metadata().await {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !md.is_dir() {
                continue;
            }

            let entry_path = entry.path();

            if fs::metadata(entry_path.join(".lock")).await.is_ok() {
                continue;
            }

            let last_activity = {
                let access_file = entry_path.join(".last_access");
                if let Ok(amd) = fs::metadata(&access_file).await {
                    let modified = amd
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0);

                    if now.saturating_sub(modified) <= max_idle_secs {
                        continue;
                    }

                    modified
                } else {
                    most_recent_access_in_dir(&entry_path).await
                }
            };

            if now.saturating_sub(last_activity) > max_idle_secs {
                let sz = get_directory_size(&entry_path).await.unwrap_or(0);
                if fs::remove_dir_all(entry_path).await.is_ok() {
                    freed += sz;
                    deleted += 1;
                }
            }
        }

        if deleted > 0 {
            info!(
                "Removed {} stale HLS dirs (idle > {}min), freed {}",
                deleted,
                max_idle_secs / 60,
                format_bytes(freed),
            );
            let new = get_directory_size(&self.config.hls_cache_path)
                .await
                .unwrap_or(0);
            self.hls_cache_bytes.store(new, Ordering::Relaxed);
        }

        Ok(())
    }

    pub async fn cleanup_temp_files(&self) -> std::io::Result<()> {
        if !dir_exists(&self.config.temp_storage_path).await {
            return Ok(());
        }
        let retention = self.config.temp_file_retention_days * 24 * 3600;
        let freed = cleanup_old_files_bytes(&self.config.temp_storage_path, retention).await?;
        if freed > 0 {
            info!("Cleaned {} from temporary files", format_bytes(freed));
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn cleanup_old_logs(&self) -> std::io::Result<()> {
        if !dir_exists(&self.config.log_path).await {
            return Ok(());
        }
        let retention = self.config.log_retention_days * 24 * 3600;
        let freed = cleanup_old_files_bytes(&self.config.log_path, retention).await?;
        if freed > 0 {
            info!("Cleaned {} from old log files", format_bytes(freed));
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn cleanup_session_cache(&self, video_hash: &str) -> std::io::Result<u64> {
        let dir = self.config.hls_cache_path.join(video_hash);
        if !dir_exists(&dir).await {
            return Ok(0);
        }
        let sz = get_directory_size(&dir).await.unwrap_or(0);
        fs::remove_dir_all(&dir).await?;
        self.hls_cache_bytes.fetch_sub(
            std::cmp::min(sz, self.hls_cache_bytes.load(Ordering::Relaxed)),
            Ordering::Relaxed,
        );
        info!(
            "Cleaned session cache: {} ({})",
            video_hash,
            format_bytes(sz)
        );
        Ok(sz)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct StorageStats {
    pub hls_cache_size: u64,
    pub temp_storage_size: u64,
    pub log_size: u64,
    pub video_storage_size: u64,
    pub database_size: u64,
    pub total_app_usage: u64,
    pub available_space: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AccurateDiskUsage {
    pub total_space: u64,
    pub available_space: u64,
    pub used_space: u64,
    pub cache_size: u64,
    pub actual_user_data: u64,
    pub usage_percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoCleanupStatus {
    pub enabled: bool,
    pub status: String,
    pub threshold_bytes: u64,
    pub threshold_display: String,
    pub hls_cache_bytes: u64,
    pub temp_bytes: u64,
    pub log_bytes: u64,
    pub total_cache_bytes: u64,
    pub usage_percent: f64,
    pub pressure_level: String,
    pub available_memory_bytes: u64,
    pub min_reserved_memory_bytes: u64,
    pub memory_pressure_level: String,
    pub check_interval_secs: u32,
}

async fn dir_exists(path: &Path) -> bool {
    fs::metadata(path).await.is_ok()
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;
    const TB: u64 = 1024 * 1024 * 1024 * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn path_is_external_like(path: &Path) -> bool {
    let s = path.to_string_lossy();
    if cfg!(target_os = "windows") {
        return true;
    }
    s.starts_with("/mnt") || s.starts_with("/media") || s.starts_with("/storage")
}

fn coerce_external_path(path: &Path, external_root: &Path, fallback_suffix: &str) -> PathBuf {
    if path_is_external_like(path) {
        return path.to_path_buf();
    }
    let fallback = external_root.join(fallback_suffix);
    warn!(
        "Storage path {:?} is not external; redirecting to {:?}",
        path, fallback
    );
    fallback
}

fn get_available_memory_bytes() -> u64 {
    let mut sys = System::new();
    sys.refresh_memory();
    sys.available_memory()
}

async fn get_filesystem_stats(path: &Path) -> std::io::Result<(u64, u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        use std::mem::MaybeUninit;
        let path_cstr = std::ffi::CString::new(path.to_string_lossy().as_bytes())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        let mut stat: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();

        unsafe {
            if libc::statvfs(path_cstr.as_ptr(), stat.as_mut_ptr()) == 0 {
                let stat = stat.assume_init();
                let block_size = stat.f_frsize as u64;
                let total = stat.f_blocks as u64 * block_size;
                let available = stat.f_bavail as u64 * block_size;
                let free = stat.f_bfree as u64 * block_size;
                let used = total - free;
                return Ok((total, available, used));
            }
        }

        Err(std::io::Error::last_os_error())
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;
        use winapi::um::fileapi::GetDiskFreeSpaceExW;

        let wide_path: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut free_bytes: u64 = 0;
        let mut total_bytes: u64 = 0;
        let mut total_free_bytes: u64 = 0;

        unsafe {
            if GetDiskFreeSpaceExW(
                wide_path.as_ptr(),
                &mut free_bytes as *mut u64 as *mut _,
                &mut total_bytes as *mut u64 as *mut _,
                &mut total_free_bytes as *mut u64 as *mut _,
            ) != 0
            {
                let used = total_bytes - total_free_bytes;
                return Ok((total_bytes, free_bytes, used));
            }
        }

        Err(std::io::Error::last_os_error())
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok((0, 0, 0))
    }
}

async fn get_available_space(path: &Path) -> std::io::Result<u64> {
    #[cfg(target_os = "linux")]
    {
        use std::mem::MaybeUninit;
        let path_cstr = std::ffi::CString::new(path.to_string_lossy().as_bytes())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        let mut stat: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();

        unsafe {
            if libc::statvfs(path_cstr.as_ptr(), stat.as_mut_ptr()) == 0 {
                let stat = stat.assume_init();
                let available = stat.f_bavail as u64 * stat.f_frsize as u64;
                return Ok(available);
            }
        }

        Err(std::io::Error::last_os_error())
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;
        use winapi::um::fileapi::GetDiskFreeSpaceExW;

        let wide_path: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut free_bytes: u64 = 0;

        unsafe {
            if GetDiskFreeSpaceExW(
                wide_path.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut free_bytes as *mut u64 as *mut _,
            ) != 0
            {
                return Ok(free_bytes);
            }
        }

        Err(std::io::Error::last_os_error())
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(0)
    }
}

async fn get_db_files_size(path: &Path) -> std::io::Result<u64> {
    if !dir_exists(path).await {
        return Ok(0);
    }
    let mut total = 0u64;
    let mut entries = fs::read_dir(path).await?;
    while let Some(entry) = entries.next_entry().await? {
        let md = entry.metadata().await?;
        if md.is_file() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.ends_with(".db")
                || name_str.ends_with(".db-shm")
                || name_str.ends_with(".db-wal")
            {
                total += md.len();
            }
        }
    }
    Ok(total)
}

fn get_directory_size(
    path: &Path,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<u64>> + Send + '_>> {
    Box::pin(async move {
        if !dir_exists(path).await {
            return Ok(0);
        }
        let mut total = 0u64;
        let mut entries = fs::read_dir(path).await?;
        while let Some(entry) = entries.next_entry().await? {
            let md = entry.metadata().await?;
            if md.is_file() {
                total += md.len();
            } else if md.is_dir() {
                total += get_directory_size(&entry.path()).await?;
            }
        }
        Ok(total)
    })
}

async fn most_recent_access_in_dir(path: &Path) -> u64 {
    let mut best = 0u64;
    if let Ok(mut entries) = fs::read_dir(path).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Ok(md) = entry.metadata().await {
                let ts = md
                    .accessed()
                    .or_else(|_| md.modified())
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if ts > best {
                    best = ts;
                }
            }
        }
    }
    best
}

async fn cleanup_old_files_bytes(path: &Path, retention_secs: u64) -> std::io::Result<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut freed = 0u64;
    let mut entries = fs::read_dir(path).await?;

    while let Some(entry) = entries.next_entry().await? {
        let md = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        let modified = match md.modified() {
            Ok(t) => match t.duration_since(UNIX_EPOCH) {
                Ok(d) => d.as_secs(),
                Err(_) => continue,
            },
            Err(_) => continue,
        };
        if now.saturating_sub(modified) <= retention_secs {
            continue;
        }
        if md.is_file() {
            let sz = md.len();
            if fs::remove_file(entry.path()).await.is_ok() {
                freed += sz;
            }
        } else if md.is_dir() {
            let sz = get_directory_size(&entry.path()).await.unwrap_or(0);
            if fs::remove_dir_all(entry.path()).await.is_ok() {
                freed += sz;
            }
        }
    }

    Ok(freed)
}

async fn cleanup_old_entries_bytes(
    path: &Path,
    retention_secs: u64,
    protection_secs: u64,
) -> std::io::Result<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut freed = 0u64;
    let mut entries = fs::read_dir(path).await?;

    while let Some(entry) = entries.next_entry().await? {
        let md = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        if md.is_dir() {
            if is_cache_entry_protected(&entry.path(), protection_secs).await {
                continue;
            }
            let recent = most_recent_access_in_dir(&entry.path()).await;
            if now.saturating_sub(recent) > retention_secs {
                let sz = get_directory_size(&entry.path()).await.unwrap_or(0);
                if fs::remove_dir_all(entry.path()).await.is_ok() {
                    freed += sz;
                }
            }
        } else if md.is_file() {
            if is_cache_entry_protected(&entry.path(), protection_secs).await {
                continue;
            }
            let modified = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if now.saturating_sub(modified) > retention_secs {
                let sz = md.len();
                if fs::remove_file(entry.path()).await.is_ok() {
                    freed += sz;
                }
            }
        }
    }

    Ok(freed)
}

async fn is_cache_entry_protected(path: &Path, protection_secs: u64) -> bool {
    let lock_file = path.join(".lock");
    if fs::metadata(&lock_file).await.is_ok() {
        return true;
    }

    let access_file = path.join(".last_access");
    if let Ok(md) = fs::metadata(&access_file).await {
        if let Ok(modified) = md.modified() {
            if let Ok(elapsed) = modified.elapsed() {
                return elapsed.as_secs() < protection_secs;
            }
        }
    }

    false
}

async fn lru_evict_from_directory(path: &Path, target_bytes: u64) -> std::io::Result<u64> {
    let mut heap: BinaryHeap<CacheEntry> = BinaryHeap::new();
    let mut entries = fs::read_dir(path).await?;

    while let Some(entry) = entries.next_entry().await? {
        let md = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };

        if md.is_dir() && is_cache_entry_protected(&entry.path(), HLS_CACHE_PROTECTION_SECS).await {
            continue;
        }

        let last_access = md
            .accessed()
            .or_else(|_| md.modified())
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let is_dir = md.is_dir();
        let size = if is_dir {
            get_directory_size(&entry.path()).await.unwrap_or(0)
        } else {
            md.len()
        };
        heap.push(CacheEntry {
            path: entry.path(),
            size,
            last_access,
            is_dir,
        });
    }

    let mut freed = 0u64;
    while let Some(ce) = heap.pop() {
        if freed >= target_bytes {
            break;
        }
        let ok = if ce.is_dir {
            fs::remove_dir_all(&ce.path).await.is_ok()
        } else {
            fs::remove_file(&ce.path).await.is_ok()
        };
        if ok {
            freed += ce.size;
            info!(
                "LRU eviction: removed {:?} ({} freed)",
                ce.path,
                format_bytes(ce.size)
            );
        } else {
            warn!(
                "LRU eviction: failed to remove {:?} (may be in use)",
                ce.path
            );
        }
    }

    Ok(freed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_storage_config_defaults() {
        let config = StorageConfig::default();
        assert_eq!(config.hls_cache_retention_days, 1);
        assert_eq!(config.temp_file_retention_days, 1);
        assert_eq!(config.max_hls_cache_size, 1024 * 1024 * 1024);
        assert_eq!(config.max_temp_size, 1024 * 1024 * 1024);
        assert_eq!(config.max_log_size, 512 * 1024 * 1024);
    }

    #[tokio::test]
    async fn test_directory_size() {
        let temp_dir = std::env::temp_dir().join(format!(
            "rockzero_test_dir_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        fs::create_dir_all(&temp_dir).await.unwrap();
        fs::write(temp_dir.join("test.txt"), "Hello, World!")
            .await
            .unwrap();
        let size = get_directory_size(&temp_dir).await.unwrap();
        assert!(size >= 13);
        fs::remove_dir_all(&temp_dir).await.ok();
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
    }

    #[test]
    fn test_pressure_ordering() {
        assert!(CachePressureLevel::Emergency > CachePressureLevel::Critical);
        assert!(CachePressureLevel::Critical > CachePressureLevel::Warning);
        assert!(CachePressureLevel::Warning > CachePressureLevel::Normal);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_drive_root_rejected() {
        let root = PathBuf::from(r"D:\");
        assert!(is_windows_drive_root(&root));
    }
}
