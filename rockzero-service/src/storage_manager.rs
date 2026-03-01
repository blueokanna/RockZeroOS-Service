use serde::{Deserialize, Serialize};
use std::collections::BinaryHeap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

// ════════════════════════════════════════════════════════════════
//  Pressure level
// ════════════════════════════════════════════════════════════════

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

// ════════════════════════════════════════════════════════════════
//  Configuration
// ════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub external_storage_path: PathBuf,
    pub video_storage_path: PathBuf,
    pub temp_storage_path: PathBuf,
    pub hls_cache_path: PathBuf,
    pub log_path: PathBuf,
    /// Emergency threshold (bytes) — all caches wiped when free space drops below
    pub min_free_space: u64,
    /// Warning threshold (bytes) — standard cleanup triggered
    pub warning_free_space: u64,
    /// Critical threshold (bytes) — aggressive cleanup triggered
    pub critical_free_space: u64,
    /// Maximum HLS cache size in bytes (0 = unlimited)
    pub max_hls_cache_size: u64,
    /// Maximum temp storage size in bytes (0 = unlimited)
    pub max_temp_size: u64,
    /// Maximum log storage size in bytes (0 = unlimited)
    pub max_log_size: u64,
    pub hls_cache_retention_days: u64,
    pub temp_file_retention_days: u64,
    pub log_retention_days: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            external_storage_path: PathBuf::from("/mnt/external"),
            video_storage_path: PathBuf::from("/mnt/external/videos"),
            temp_storage_path: PathBuf::from("/mnt/external/temp"),
            hls_cache_path: PathBuf::from("./data/hls_cache"),
            log_path: PathBuf::from("./data/logs"),
            min_free_space: 512 * 1024 * 1024,             // 512 MB
            warning_free_space: 2 * 1024 * 1024 * 1024,    // 2 GB
            critical_free_space: 1024 * 1024 * 1024,        // 1 GB
            max_hls_cache_size: 10 * 1024 * 1024 * 1024,   // 10 GB
            max_temp_size: 5 * 1024 * 1024 * 1024,          // 5 GB
            max_log_size: 1024 * 1024 * 1024,                // 1 GB
            hls_cache_retention_days: 7,
            temp_file_retention_days: 1,
            log_retention_days: 30,
        }
    }
}

impl StorageConfig {
    pub fn from_env() -> Self {
        let defaults = Self::default();
        let env_u64 = |var: &str, default: u64| -> u64 {
            std::env::var(var)
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default)
        };

        Self {
            external_storage_path: std::env::var("EXTERNAL_STORAGE_PATH")
                .unwrap_or_else(|_| "/mnt/external".to_string())
                .into(),
            video_storage_path: std::env::var("VIDEO_STORAGE_PATH")
                .unwrap_or_else(|_| "/mnt/external/videos".to_string())
                .into(),
            temp_storage_path: std::env::var("TEMP_STORAGE_PATH")
                .unwrap_or_else(|_| "/mnt/external/temp".to_string())
                .into(),
            hls_cache_path: std::env::var("HLS_CACHE_PATH")
                .unwrap_or_else(|_| "./data/hls_cache".to_string())
                .into(),
            log_path: std::env::var("LOG_PATH")
                .unwrap_or_else(|_| "./data/logs".to_string())
                .into(),
            min_free_space: env_u64("MIN_FREE_SPACE", defaults.min_free_space),
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

// ════════════════════════════════════════════════════════════════
//  Cleanup report
// ════════════════════════════════════════════════════════════════

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CleanupReport {
    pub hls_bytes_freed: u64,
    pub temp_bytes_freed: u64,
    pub log_bytes_freed: u64,
    pub total_bytes_freed: u64,
}

// ════════════════════════════════════════════════════════════════
//  LRU cache entry (private)
// ════════════════════════════════════════════════════════════════

#[derive(Debug, Eq, PartialEq)]
struct CacheEntry {
    path: PathBuf,
    size: u64,
    last_access: u64,
    is_dir: bool,
}

// BinaryHeap is a max-heap; reversing the comparison makes pop() yield
// the entry with the *smallest* last_access (oldest), i.e. LRU ordering.
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

// ════════════════════════════════════════════════════════════════
//  Storage Manager
// ════════════════════════════════════════════════════════════════

pub struct StorageManager {
    config: StorageConfig,
    /// Serialises concurrent cleanup / eviction operations
    cleanup_lock: Mutex<()>,
    /// Tracked HLS cache size (updated after operations and periodically)
    hls_cache_bytes: AtomicU64,
    /// Tracked temp storage size
    temp_bytes: AtomicU64,
    /// Tracked log size
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

    // ─── cache size tracking ───────────────────────────────────

    /// Re-scan disk to update tracked cache sizes
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

    /// Determine current cache pressure level based on available space
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

    // ─── queries ───────────────────────────────────────────────

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

    /// Get total size of all caches (uses tracked values)
    #[allow(dead_code)]
    async fn get_total_cache_size(&self) -> u64 {
        self.hls_cache_bytes.load(Ordering::Relaxed)
            + self.temp_bytes.load(Ordering::Relaxed)
            + self.log_bytes.load(Ordering::Relaxed)
    }

    /// Get storage statistics
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

    /// Get HLS cache path (for external use)
    #[allow(dead_code)]
    pub fn get_hls_cache_path(&self) -> &Path {
        &self.config.hls_cache_path
    }

    // ─── cleanup operations ────────────────────────────────────

    /// Force cleanup all caches (for use after formatting or manual trigger)
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
            fs::remove_dir_all(&self.config.temp_storage_path).await.ok();
            fs::create_dir_all(&self.config.temp_storage_path).await.ok();
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

    /// Start all background cleanup tasks:
    ///  - Initial cache size scan
    ///  - Hourly full cleanup + refresh
    ///  - Stale HLS cache check every 5 minutes
    ///  - Disk pressure monitor every 60 seconds
    ///  - LRU cache limit enforcement every 10 minutes
    pub fn start_cleanup_tasks(self: Arc<Self>) {
        // Initial scan
        let m = self.clone();
        tokio::spawn(async move {
            m.refresh_cache_sizes().await;
            info!(
                "Initial cache sizes — HLS: {}, Temp: {}, Log: {}",
                format_bytes(m.hls_cache_bytes.load(Ordering::Relaxed)),
                format_bytes(m.temp_bytes.load(Ordering::Relaxed)),
                format_bytes(m.log_bytes.load(Ordering::Relaxed)),
            );
        });

        // Hourly full cleanup
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

        // Stale HLS cache: delete segments not accessed in 30 min (check every 5 min)
        let m = self.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(300));
            loop {
                tick.tick().await;
                if let Err(e) = m.cleanup_stale_hls_cache(30 * 60).await {
                    warn!("Stale HLS cache cleanup failed: {}", e);
                }
            }
        });

        // Pressure monitor every 60s
        let m = self.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                match m.get_pressure_level().await {
                    CachePressureLevel::Emergency => {
                        warn!("EMERGENCY disk pressure — evicting all caches");
                        if let Err(e) = m.emergency_eviction().await {
                            error!("Emergency eviction failed: {}", e);
                        }
                    }
                    CachePressureLevel::Critical => {
                        warn!("Critical disk pressure — aggressive cleanup");
                        if let Err(e) = m.aggressive_cleanup().await {
                            error!("Aggressive cleanup failed: {}", e);
                        }
                    }
                    CachePressureLevel::Warning => {
                        info!("Disk pressure warning — running cleanup");
                        if let Err(e) = m.run_cleanup().await {
                            error!("Warning cleanup failed: {}", e);
                        }
                    }
                    CachePressureLevel::Normal => {}
                }
            }
        });

        // LRU cache limit enforcement every 10 min
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
    }

    /// Enforce maximum cache sizes via LRU eviction
    async fn enforce_cache_limits(&self) -> std::io::Result<()> {
        let _guard = self.cleanup_lock.lock().await;

        // HLS cache
        if self.config.max_hls_cache_size > 0 {
            let cur = get_directory_size(&self.config.hls_cache_path)
                .await
                .unwrap_or(0);
            self.hls_cache_bytes.store(cur, Ordering::Relaxed);
            if cur > self.config.max_hls_cache_size {
                let excess = cur - self.config.max_hls_cache_size;
                let freed =
                    lru_evict_from_directory(&self.config.hls_cache_path, excess).await?;
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

        // Temp storage
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

        // Logs
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

    /// Emergency eviction — wipe ALL caches, keep only 24 h of logs
    async fn emergency_eviction(&self) -> std::io::Result<()> {
        let _guard = self.cleanup_lock.lock().await;
        let mut total_freed = 0u64;

        if dir_exists(&self.config.hls_cache_path).await {
            let sz = get_directory_size(&self.config.hls_cache_path)
                .await
                .unwrap_or(0);
            if fs::remove_dir_all(&self.config.hls_cache_path).await.is_ok() {
                total_freed += sz;
                fs::create_dir_all(&self.config.hls_cache_path).await.ok();
            }
            self.hls_cache_bytes.store(0, Ordering::Relaxed);
        }

        if dir_exists(&self.config.temp_storage_path).await {
            let sz = get_directory_size(&self.config.temp_storage_path)
                .await
                .unwrap_or(0);
            if fs::remove_dir_all(&self.config.temp_storage_path).await.is_ok() {
                total_freed += sz;
                fs::create_dir_all(&self.config.temp_storage_path).await.ok();
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

    /// Aggressive cleanup with shortened retention periods
    async fn aggressive_cleanup(&self) -> std::io::Result<()> {
        let _guard = self.cleanup_lock.lock().await;

        // HLS cache: delete entries older than 1 hour
        if dir_exists(&self.config.hls_cache_path).await {
            let _ = cleanup_old_entries_bytes(&self.config.hls_cache_path, 3600).await;
        }

        // Temp: delete entries older than 2 hours
        if dir_exists(&self.config.temp_storage_path).await {
            let _ = cleanup_old_files_bytes(&self.config.temp_storage_path, 2 * 3600).await;
        }

        // Logs: keep only last 3 days
        if dir_exists(&self.config.log_path).await {
            let _ = cleanup_old_files_bytes(&self.config.log_path, 3 * 24 * 3600).await;
        }

        self.refresh_cache_sizes().await;
        Ok(())
    }

    /// Run all standard cleanup tasks
    pub async fn run_cleanup(&self) -> std::io::Result<()> {
        let _guard = self.cleanup_lock.lock().await;

        // 1. Clean HLS cache by retention
        if dir_exists(&self.config.hls_cache_path).await {
            let retention = self.config.hls_cache_retention_days * 24 * 3600;
            let freed =
                cleanup_old_entries_bytes(&self.config.hls_cache_path, retention).await?;
            if freed > 0 {
                info!(
                    "Cleaned {} from HLS cache (retention: {}d)",
                    format_bytes(freed),
                    self.config.hls_cache_retention_days,
                );
            }
        }

        // 2. Clean temp files
        if dir_exists(&self.config.temp_storage_path).await {
            let retention = self.config.temp_file_retention_days * 24 * 3600;
            let freed =
                cleanup_old_files_bytes(&self.config.temp_storage_path, retention).await?;
            if freed > 0 {
                info!(
                    "Cleaned {} from temp (retention: {}d)",
                    format_bytes(freed),
                    self.config.temp_file_retention_days,
                );
            }
        }

        // 3. Clean old logs
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

        // 4. Refresh tracked sizes
        self.refresh_cache_sizes().await;

        // 5. Check pressure after cleanup
        let pressure = self.get_pressure_level().await;
        if pressure >= CachePressureLevel::Warning {
            warn!("Disk pressure still at {} after cleanup", pressure);
        }

        info!("Cleanup completed");
        Ok(())
    }

    /// Check storage space and log warnings
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

    /// Clean HLS cache by configured retention
    pub async fn cleanup_hls_cache(&self) -> std::io::Result<()> {
        if !dir_exists(&self.config.hls_cache_path).await {
            return Ok(());
        }
        let retention = self.config.hls_cache_retention_days * 24 * 3600;
        let freed = cleanup_old_entries_bytes(&self.config.hls_cache_path, retention).await?;
        if freed > 0 {
            info!("Cleaned {} from old HLS cache", format_bytes(freed));
        }
        Ok(())
    }

    /// Clean HLS cache entries not accessed within `max_idle_secs`
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
            let most_recent = most_recent_access_in_dir(&entry.path()).await;
            if now.saturating_sub(most_recent) > max_idle_secs {
                let sz = get_directory_size(&entry.path()).await.unwrap_or(0);
                if fs::remove_dir_all(entry.path()).await.is_ok() {
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

    /// Clean temporary files by configured retention
    pub async fn cleanup_temp_files(&self) -> std::io::Result<()> {
        if !dir_exists(&self.config.temp_storage_path).await {
            return Ok(());
        }
        let retention = self.config.temp_file_retention_days * 24 * 3600;
        let freed =
            cleanup_old_files_bytes(&self.config.temp_storage_path, retention).await?;
        if freed > 0 {
            info!("Cleaned {} from temporary files", format_bytes(freed));
        }
        Ok(())
    }

    /// Clean old logs by configured retention
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

    /// Immediately clean up the HLS session cache for a specific video
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
        info!("Cleaned session cache: {} ({})", video_hash, format_bytes(sz));
        Ok(sz)
    }
}

// ════════════════════════════════════════════════════════════════
//  Stats types
// ════════════════════════════════════════════════════════════════

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

/// Accurate disk usage statistics
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AccurateDiskUsage {
    /// Total space
    pub total_space: u64,
    /// Available space
    pub available_space: u64,
    /// Used space (filesystem level)
    pub used_space: u64,
    /// Cache occupied space
    pub cache_size: u64,
    /// Actual user data (excluding cache)
    pub actual_user_data: u64,
    /// Usage percentage (based on actual used space)
    pub usage_percentage: f64,
}

// ════════════════════════════════════════════════════════════════
//  Helper functions
// ════════════════════════════════════════════════════════════════

/// Async-safe path existence check (avoids blocking `.exists()`)
async fn dir_exists(path: &Path) -> bool {
    fs::metadata(path).await.is_ok()
}

/// Human-readable byte formatting
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

/// Get filesystem-level statistics via platform syscalls
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

/// Get available space on the filesystem containing `path`
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

/// Get database files size (.db, .db-shm, .db-wal)
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

/// Recursively compute directory size
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

/// Most recent access/modification timestamp among files in a directory
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

/// Delete files/directories older than `retention_secs`. Returns bytes freed.
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

/// Delete directory entries whose *content* hasn't been accessed within `retention_secs`.
/// For subdirectories, checks `most_recent_access_in_dir`; for flat files, checks mtime.
/// Returns bytes freed.
async fn cleanup_old_entries_bytes(path: &Path, retention_secs: u64) -> std::io::Result<u64> {
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
            let recent = most_recent_access_in_dir(&entry.path()).await;
            if now.saturating_sub(recent) > retention_secs {
                let sz = get_directory_size(&entry.path()).await.unwrap_or(0);
                if fs::remove_dir_all(entry.path()).await.is_ok() {
                    freed += sz;
                }
            }
        } else if md.is_file() {
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

/// LRU eviction: remove the oldest entries from a directory until at least
/// `target_bytes` have been freed. Returns actual bytes freed.
async fn lru_evict_from_directory(path: &Path, target_bytes: u64) -> std::io::Result<u64> {
    let mut heap: BinaryHeap<CacheEntry> = BinaryHeap::new();
    let mut entries = fs::read_dir(path).await?;

    while let Some(entry) = entries.next_entry().await? {
        let md = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
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
        } else {
            warn!("LRU eviction: failed to remove {:?}", ce.path);
        }
    }

    Ok(freed)
}

// ════════════════════════════════════════════════════════════════
//  Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_storage_config_defaults() {
        let config = StorageConfig::default();
        assert_eq!(config.hls_cache_retention_days, 7);
        assert_eq!(config.temp_file_retention_days, 1);
        assert_eq!(config.max_hls_cache_size, 10 * 1024 * 1024 * 1024);
        assert_eq!(config.max_log_size, 1024 * 1024 * 1024);
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
}
