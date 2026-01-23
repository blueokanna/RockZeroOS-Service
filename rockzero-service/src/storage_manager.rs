use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::time::{interval, Duration};
use tracing::{info, warn, error};
use serde::{Deserialize, Serialize};

/// 存储空间配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// 外部存储路径
    pub external_storage_path: PathBuf,
    /// 视频存储路径
    pub video_storage_path: PathBuf,
    /// 临时文件路径
    pub temp_storage_path: PathBuf,
    /// HLS 缓存路径
    pub hls_cache_path: PathBuf,
    /// 日志路径
    pub log_path: PathBuf,
    /// 最小可用空间（字节）
    pub min_free_space: u64,
    /// HLS 缓存保留天数
    pub hls_cache_retention_days: u64,
    /// 临时文件保留天数
    pub temp_file_retention_days: u64,
    /// 日志文件保留天数
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
    /// 从环境变量加载配置
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

    /// 初始化所有存储目录
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

/// 存储空间管理器
pub struct StorageManager {
    config: StorageConfig,
}

impl StorageManager {
    pub fn new(config: StorageConfig) -> Self {
        Self { config }
    }

    /// 启动后台清理任务
    pub fn start_cleanup_tasks(self: std::sync::Arc<Self>) {
        let manager = self.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(3600)); // 每小时运行一次
            loop {
                interval.tick().await;
                info!("🧹 Starting scheduled cleanup tasks...");
                
                if let Err(e) = manager.run_cleanup().await {
                    error!("Cleanup task failed: {}", e);
                }
            }
        });
    }

    /// 运行所有清理任务
    pub async fn run_cleanup(&self) -> std::io::Result<()> {
        // 1. 检查存储空间
        self.check_storage_space().await?;

        // 2. 清理 HLS 缓存
        self.cleanup_hls_cache().await?;

        // 3. 清理临时文件
        self.cleanup_temp_files().await?;

        // 4. 清理旧日志
        self.cleanup_old_logs().await?;

        info!("✅ Cleanup tasks completed");
        Ok(())
    }

    /// 检查存储空间
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

    /// 清理 HLS 缓存
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

    /// 清理临时文件
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

    /// 清理旧日志
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

    /// 获取存储统计信息
    pub async fn get_storage_stats(&self) -> StorageStats {
        let mut stats = StorageStats::default();

        // 统计各个目录的使用情况
        if let Ok(size) = get_directory_size(&self.config.hls_cache_path).await {
            stats.hls_cache_size = size;
        }

        if let Ok(size) = get_directory_size(&self.config.temp_storage_path).await {
            stats.temp_storage_size = size;
        }

        if let Ok(size) = get_directory_size(&self.config.log_path).await {
            stats.log_size = size;
        }

        // 统计视频存储目录
        if let Ok(size) = get_directory_size(&self.config.video_storage_path).await {
            stats.video_storage_size = size;
        }

        // 统计数据库大小（查找 data 目录下的 .db 文件）
        let data_dir = std::path::PathBuf::from("./data");
        if let Ok(size) = get_db_files_size(&data_dir).await {
            stats.database_size = size;
        }

        // 计算 RockZeroOS 总占用
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

    /// 获取 HLS 缓存路径（供外部使用）
    pub fn get_hls_cache_path(&self) -> &std::path::Path {
        &self.config.hls_cache_path
    }

    /// 立即清理指定的 HLS 会话缓存
    pub async fn cleanup_session_cache(&self, video_hash: &str) -> std::io::Result<u64> {
        let cache_dir = self.config.hls_cache_path.join(video_hash);
        if !cache_dir.exists() {
            return Ok(0);
        }

        let size_before = get_directory_size(&cache_dir).await.unwrap_or(0);
        fs::remove_dir_all(&cache_dir).await?;
        
        info!("🗑️ Cleaned up session cache: {} ({} bytes)", video_hash, size_before);
        Ok(size_before)
    }
}

/// 存储统计信息
/// 
/// 提供 RockZeroOS 应用专用的存储使用详情
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct StorageStats {
    /// HLS 转码缓存大小
    pub hls_cache_size: u64,
    /// 临时文件大小
    pub temp_storage_size: u64,
    /// 日志文件大小
    pub log_size: u64,
    /// 视频存储大小
    pub video_storage_size: u64,
    /// 数据库文件大小
    pub database_size: u64,
    /// RockZeroOS 应用总占用
    pub total_app_usage: u64,
    /// 外部存储可用空间
    pub available_space: u64,
}

/// 获取数据库文件大小
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
            // 统计所有数据库相关文件
            if file_name_str.ends_with(".db") 
                || file_name_str.ends_with(".db-shm")
                || file_name_str.ends_with(".db-wal") {
                total_size += metadata.len();
            }
        }
    }

    Ok(total_size)
}

/// 获取可用空间
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
        
        let wide_path: Vec<u16> = path.as_os_str()
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
            ) != 0 {
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

/// 获取目录大小
fn get_directory_size(path: &Path) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<u64>> + Send + '_>> {
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

/// 清理旧文件
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
        // 创建一个受控的临时目录用于测试
        let temp_dir = std::env::temp_dir().join(format!(
            "rockzero_test_dir_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).await.expect("Failed to create test directory");
        
        // 创建一些测试文件
        let test_file = temp_dir.join("test_file.txt");
        fs::write(&test_file, "Hello, World!").await.expect("Failed to write test file");
        
        let size = get_directory_size(&temp_dir).await;
        assert!(size.is_ok());
        assert!(size.unwrap() >= 13); // "Hello, World!" 有 13 字节
        
        // 清理
        fs::remove_dir_all(&temp_dir).await.ok();
    }
}
