use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub external_storage_path: PathBuf,
    pub video_storage_path: PathBuf,
    pub temp_storage_path: PathBuf,
    pub hls_cache_path: PathBuf,
    pub log_path: PathBuf,
    pub min_free_space: u64,
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
            min_free_space: 1024 * 1024 * 1024, // 1GB
            hls_cache_retention_days: 7,
            temp_file_retention_days: 1,
            log_retention_days: 30,
        }
    }
}

impl StorageConfig {
    pub fn from_env() -> Self {
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
            min_free_space: std::env::var("MIN_FREE_SPACE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1024 * 1024 * 1024),
            hls_cache_retention_days: std::env::var("HLS_CACHE_RETENTION_DAYS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(7),
            temp_file_retention_days: std::env::var("TEMP_FILE_RETENTION_DAYS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1),
            log_retention_days: std::env::var("LOG_RETENTION_DAYS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
        }
    }

    pub async fn init_directories(&self) -> std::io::Result<()> {
        let dirs = [
            &self.external_storage_path,
            &self.video_storage_path,
            &self.temp_storage_path,
            &self.hls_cache_path,
            &self.log_path,
        ];

        for dir in dirs {
            if let Err(e) = fs::create_dir_all(dir).await {
                warn!("Failed to create directory {:?}: {}", dir, e);
            } else {
                info!("Initialized storage directory: {:?}", dir);
            }
        }

        Ok(())
    }
}

pub struct StorageManager {
    config: StorageConfig,
}

impl StorageManager {
    pub fn new(config: StorageConfig) -> Self {
        Self { config }
    }

    pub async fn get_accurate_disk_usage(
        &self,
        mount_point: &std::path::Path,
    ) -> std::io::Result<AccurateDiskUsage> {
        let (total, available, used) = get_filesystem_stats(mount_point).await?;
        let cache_size = self.get_total_cache_size().await;
        let actual_user_data = used.saturating_sub(cache_size);

        Ok(AccurateDiskUsage {
            total_space: total,
            available_space: available,
            used_space: used,
            cache_size,
            actual_user_data,
            usage_percentage: if total > 0 {
                (actual_user_data as f64 / total as f64) * 100.0
            } else {
                0.0
            },
        })
    }

    /// Get total size of all caches
    async fn get_total_cache_size(&self) -> u64 {
        let mut total = 0u64;

        // HLS cache
        if let Ok(size) = get_directory_size(&self.config.hls_cache_path).await {
            total += size;
        }

        // Temporary files
        if let Ok(size) = get_directory_size(&self.config.temp_storage_path).await {
            total += size;
        }

        // Log files
        if let Ok(size) = get_directory_size(&self.config.log_path).await {
            total += size;
        }

        total
    }

    /// Force cleanup all caches (for use after formatting)
    pub async fn force_cleanup_all_cache(&self) -> std::io::Result<u64> {
        let mut total_cleaned = 0u64;

        // Clean HLS cache
        if self.config.hls_cache_path.exists() {
            if let Ok(size) = get_directory_size(&self.config.hls_cache_path).await {
                total_cleaned += size;
            }
            fs::remove_dir_all(&self.config.hls_cache_path).await.ok();
            fs::create_dir_all(&self.config.hls_cache_path).await.ok();
            info!("🗑️ Cleaned HLS cache directory");
        }

        // Clean temporary files
        if self.config.temp_storage_path.exists() {
            if let Ok(size) = get_directory_size(&self.config.temp_storage_path).await {
                total_cleaned += size;
            }
            fs::remove_dir_all(&self.config.temp_storage_path)
                .await
                .ok();
            fs::create_dir_all(&self.config.temp_storage_path)
                .await
                .ok();
            info!("🗑️ Cleaned temp storage directory");
        }

        info!("✅ Force cleanup completed: {} bytes freed", total_cleaned);
        Ok(total_cleaned)
    }

    /// Start background cleanup tasks
    pub fn start_cleanup_tasks(self: std::sync::Arc<Self>) {
        let manager = self.clone();
        // Hourly full cleanup
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(3600));
            loop {
                interval.tick().await;
                info!("🧹 Starting scheduled cleanup tasks...");
                if let Err(e) = manager.run_cleanup().await {
                    error!("Cleanup task failed: {}", e);
                }
            }
        });

        // HLS cache: delete segments not accessed in 30 minutes (check every 5 min)
        let manager2 = self.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                if let Err(e) = manager2.cleanup_stale_hls_cache(30 * 60).await {
                    warn!("Stale HLS cache cleanup failed: {}", e);
                }
            }
        });
    }

    /// Run all cleanup tasks
    pub async fn run_cleanup(&self) -> std::io::Result<()> {
        // 1. Check storage space
        self.check_storage_space().await?;

        // 2. Clean HLS cache
        self.cleanup_hls_cache().await?;

        // 3. Clean temporary files
        self.cleanup_temp_files().await?;

        // 4. Clean old logs
        self.cleanup_old_logs().await?;

        info!("✅ Cleanup tasks completed");
        Ok(())
    }

    /// Check storage space
    pub async fn check_storage_space(&self) -> std::io::Result<()> {
        let paths = [
            ("External Storage", &self.config.external_storage_path),
            ("Video Storage", &self.config.video_storage_path),
            ("Temp Storage", &self.config.temp_storage_path),
            ("HLS Cache", &self.config.hls_cache_path),
        ];

        for (name, path) in paths {
            if !path.exists() {
                continue;
            }

            match get_available_space(path).await {
                Ok(available) => {
                    let available_gb = available as f64 / 1024.0 / 1024.0 / 1024.0;

                    if available < self.config.min_free_space {
                        warn!(
                            "⚠️ Low disk space on {}: {:.2} GB available (minimum: {:.2} GB)",
                            name,
                            available_gb,
                            self.config.min_free_space as f64 / 1024.0 / 1024.0 / 1024.0
                        );
                    } else {
                        info!("💾 {}: {:.2} GB available", name, available_gb);
                    }
                }
                Err(e) => {
                    warn!("Failed to check space for {}: {}", name, e);
                }
            }
        }

        Ok(())
    }

    /// Clean HLS cache
    pub async fn cleanup_hls_cache(&self) -> std::io::Result<()> {
        let path = &self.config.hls_cache_path;
        if !path.exists() {
            return Ok(());
        }

        let retention_secs = self.config.hls_cache_retention_days * 24 * 3600;
        let deleted = cleanup_old_files(path, retention_secs).await?;

        if deleted > 0 {
            info!("🗑️ Cleaned up {} old HLS cache files", deleted);
        }

        Ok(())
    }

    /// Clean HLS cache entries not accessed within `max_idle_secs` seconds
    pub async fn cleanup_stale_hls_cache(&self, max_idle_secs: u64) -> std::io::Result<()> {
        let path = &self.config.hls_cache_path;
        if !path.exists() {
            return Ok(());
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut deleted_dirs = 0u64;
        let mut freed_bytes = 0u64;
        let mut entries = fs::read_dir(path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let metadata = entry.metadata().await?;
            if !metadata.is_dir() {
                continue;
            }

            // Check the most recent access/modification time of any file in this dir
            let most_recent = most_recent_access_in_dir(&entry.path()).await;
            let age = now.saturating_sub(most_recent);

            if age > max_idle_secs {
                if let Ok(size) = get_directory_size(&entry.path()).await {
                    freed_bytes += size;
                }
                if let Err(e) = fs::remove_dir_all(entry.path()).await {
                    warn!("Failed to remove stale HLS cache dir {:?}: {}", entry.path(), e);
                } else {
                    deleted_dirs += 1;
                }
            }
        }

        if deleted_dirs > 0 {
            info!(
                "🗑️ Removed {} stale HLS cache dirs (idle > {}min), freed {:.2} MB",
                deleted_dirs,
                max_idle_secs / 60,
                freed_bytes as f64 / 1024.0 / 1024.0
            );
        }

        Ok(())
    }

    /// Clean temporary files
    pub async fn cleanup_temp_files(&self) -> std::io::Result<()> {
        let path = &self.config.temp_storage_path;
        if !path.exists() {
            return Ok(());
        }

        let retention_secs = self.config.temp_file_retention_days * 24 * 3600;
        let deleted = cleanup_old_files(path, retention_secs).await?;

        if deleted > 0 {
            info!("🗑️ Cleaned up {} temporary files", deleted);
        }

        Ok(())
    }

    /// Clean old logs
    pub async fn cleanup_old_logs(&self) -> std::io::Result<()> {
        let path = &self.config.log_path;
        if !path.exists() {
            return Ok(());
        }

        let retention_secs = self.config.log_retention_days * 24 * 3600;
        let deleted = cleanup_old_files(path, retention_secs).await?;

        if deleted > 0 {
            info!("🗑️ Cleaned up {} old log files", deleted);
        }

        Ok(())
    }

    /// Get storage statistics
    pub async fn get_storage_stats(&self) -> StorageStats {
        let mut stats = StorageStats::default();

        // Calculate usage for each directory
        if let Ok(size) = get_directory_size(&self.config.hls_cache_path).await {
            stats.hls_cache_size = size;
        }

        if let Ok(size) = get_directory_size(&self.config.temp_storage_path).await {
            stats.temp_storage_size = size;
        }

        if let Ok(size) = get_directory_size(&self.config.log_path).await {
            stats.log_size = size;
        }

        // Calculate video storage directory
        if let Ok(size) = get_directory_size(&self.config.video_storage_path).await {
            stats.video_storage_size = size;
        }

        // Calculate database size (find .db files in data directory)
        let data_dir = std::path::PathBuf::from("./data");
        if let Ok(size) = get_db_files_size(&data_dir).await {
            stats.database_size = size;
        }

        // Calculate total RockZeroOS usage
        stats.total_app_usage = stats.hls_cache_size
            + stats.temp_storage_size
            + stats.log_size
            + stats.video_storage_size
            + stats.database_size;

        if let Ok(available) = get_available_space(&self.config.external_storage_path).await {
            stats.available_space = available;
        }

        stats
    }

    /// Get HLS cache path (for external use)
    pub fn get_hls_cache_path(&self) -> &std::path::Path {
        &self.config.hls_cache_path
    }

    /// Immediately clean up specified HLS session cache
    pub async fn cleanup_session_cache(&self, video_hash: &str) -> std::io::Result<u64> {
        let cache_dir = self.config.hls_cache_path.join(video_hash);
        if !cache_dir.exists() {
            return Ok(0);
        }

        let size_before = get_directory_size(&cache_dir).await.unwrap_or(0);
        fs::remove_dir_all(&cache_dir).await?;

        info!(
            "🗑️ Cleaned up session cache: {} ({} bytes)",
            video_hash, size_before
        );
        Ok(size_before)
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

/// Accurate disk usage
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
    /// Usage percentage (based on actual user data)
    pub usage_percentage: f64,
}

/// Get filesystem level statistics
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

/// Get database files size
async fn get_db_files_size(path: &std::path::Path) -> std::io::Result<u64> {
    if !path.exists() {
        return Ok(0);
    }

    let mut total_size = 0u64;
    let mut entries = fs::read_dir(path).await?;

    while let Some(entry) = entries.next_entry().await? {
        let metadata = entry.metadata().await?;
        let file_name = entry.file_name();
        let file_name_str = file_name.to_string_lossy();

        if metadata.is_file() {
            // Count all database related files
            if file_name_str.ends_with(".db")
                || file_name_str.ends_with(".db-shm")
                || file_name_str.ends_with(".db-wal")
            {
                total_size += metadata.len();
            }
        }
    }

    Ok(total_size)
}

/// Get available space
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

/// Get directory size
fn get_directory_size(
    path: &Path,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<u64>> + Send + '_>> {
    Box::pin(async move {
        if !path.exists() {
            return Ok(0);
        }

        let mut total_size = 0u64;
        let mut entries = fs::read_dir(path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let metadata = entry.metadata().await?;

            if metadata.is_file() {
                total_size += metadata.len();
            } else if metadata.is_dir() {
                total_size += get_directory_size(&entry.path()).await?;
            }
        }

        Ok(total_size)
    })
}

/// Get the most recent access/modification timestamp of any file in a directory
async fn most_recent_access_in_dir(path: &Path) -> u64 {
    let mut most_recent = 0u64;

    if let Ok(mut entries) = fs::read_dir(path).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Ok(metadata) = entry.metadata().await {
                // Use the later of accessed and modified time
                let ts = metadata
                    .accessed()
                    .or_else(|_| metadata.modified())
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if ts > most_recent {
                    most_recent = ts;
                }
            }
        }
    }

    most_recent
}

/// Clean up old files
async fn cleanup_old_files(path: &Path, retention_secs: u64) -> std::io::Result<usize> {
    if !path.exists() {
        return Ok(0);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut deleted_count = 0;
    let mut entries = fs::read_dir(path).await?;

    while let Some(entry) = entries.next_entry().await? {
        let metadata = entry.metadata().await?;

        if let Ok(modified) = metadata.modified() {
            if let Ok(duration) = modified.duration_since(UNIX_EPOCH) {
                let file_age = now.saturating_sub(duration.as_secs());

                if file_age > retention_secs {
                    if metadata.is_file() {
                        if let Err(e) = fs::remove_file(entry.path()).await {
                            warn!("Failed to delete file {:?}: {}", entry.path(), e);
                        } else {
                            deleted_count += 1;
                        }
                    } else if metadata.is_dir() {
                        if let Err(e) = fs::remove_dir_all(entry.path()).await {
                            warn!("Failed to delete directory {:?}: {}", entry.path(), e);
                        } else {
                            deleted_count += 1;
                        }
                    }
                }
            }
        }
    }

    Ok(deleted_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_storage_config() {
        let config = StorageConfig::default();
        assert_eq!(config.hls_cache_retention_days, 7);
        assert_eq!(config.temp_file_retention_days, 1);
    }

    #[tokio::test]
    async fn test_directory_size() {
        // Create a controlled temp directory for testing
        let temp_dir = std::env::temp_dir().join(format!(
            "rockzero_test_dir_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir)
            .await
            .expect("Failed to create test directory");

        // Create some test files
        let test_file = temp_dir.join("test_file.txt");
        fs::write(&test_file, "Hello, World!")
            .await
            .expect("Failed to write test file");

        let size = get_directory_size(&temp_dir).await;
        assert!(size.is_ok());
        assert!(size.unwrap() >= 13); // "Hello, World!" is 13 bytes

        // Cleanup
        fs::remove_dir_all(&temp_dir).await.ok();
    }
}
