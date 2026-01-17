//! FFmpeg 自动下载和管理模块
//! 
//! 自动检测系统架构并下载对应的 FFmpeg 静态二进制文件

use std::path::{Path, PathBuf};
use std::process::Command;
use std::io;
use std::fs;
use tracing::{info, warn};

/// FFmpeg 下载源配置
const FFMPEG_STATIC_BASE_URL: &str = "https://johnvansickle.com/ffmpeg/releases";
#[allow(dead_code)]
const FFMPEG_GITHUB_RELEASES: &str = "https://github.com/BtbN/FFmpeg-Builds/releases/download/latest";

/// 系统架构类型
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum Architecture {
    X86_64,
    Aarch64,  // ARM64
    Armhf,    // ARM 32-bit
    Unknown,
}

#[allow(dead_code)]
impl Architecture {
    /// 检测当前系统架构
    pub fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        return Architecture::X86_64;
        
        #[cfg(target_arch = "aarch64")]
        return Architecture::Aarch64;
        
        #[cfg(target_arch = "arm")]
        return Architecture::Armhf;
        
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
        {
            // 尝试通过 uname 命令检测
            if let Ok(output) = Command::new("uname").arg("-m").output() {
                let arch = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
                match arch.as_str() {
                    "x86_64" | "amd64" => return Architecture::X86_64,
                    "aarch64" | "arm64" => return Architecture::Aarch64,
                    "armv7l" | "armhf" | "arm" => return Architecture::Armhf,
                    _ => {}
                }
            }
            Architecture::Unknown
        }
    }
    
    /// 获取架构名称字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            Architecture::X86_64 => "x86_64",
            Architecture::Aarch64 => "aarch64",
            Architecture::Armhf => "armhf",
            Architecture::Unknown => "unknown",
        }
    }
}

/// FFmpeg 管理器
pub struct FfmpegManager {
    /// FFmpeg 安装目录
    install_dir: PathBuf,
    /// FFmpeg 可执行文件路径
    ffmpeg_path: Option<PathBuf>,
    /// FFprobe 可执行文件路径
    ffprobe_path: Option<PathBuf>,
}

#[allow(dead_code)]
impl FfmpegManager {
    /// 创建新的 FFmpeg 管理器
    pub fn new(data_dir: &str) -> Self {
        let install_dir = PathBuf::from(data_dir).join("ffmpeg");
        Self {
            install_dir,
            ffmpeg_path: None,
            ffprobe_path: None,
        }
    }
    
    /// 初始化 FFmpeg（检查系统安装或自动下载）
    pub async fn ensure_available(&mut self) -> io::Result<()> {
        info!("Checking FFmpeg availability...");
        
        // 1. 首先检查系统是否已安装 FFmpeg
        if let Some(path) = find_system_ffmpeg() {
            info!("Found system FFmpeg: {}", path);
            self.ffmpeg_path = Some(PathBuf::from(&path));
            self.ffprobe_path = find_system_ffprobe().map(PathBuf::from);
            return Ok(());
        }
        
        // 2. 检查我们的安装目录是否有 FFmpeg
        #[cfg(not(target_os = "windows"))]
        let local_ffmpeg = self.install_dir.join("ffmpeg");
        #[cfg(not(target_os = "windows"))]
        let local_ffprobe = self.install_dir.join("ffprobe");
        
        #[cfg(target_os = "windows")]
        let local_ffmpeg = self.install_dir.join("ffmpeg.exe");
        #[cfg(target_os = "windows")]
        let local_ffprobe = self.install_dir.join("ffprobe.exe");
        
        if local_ffmpeg.exists() && is_executable(&local_ffmpeg) {
            info!("Found local FFmpeg: {}", local_ffmpeg.display());
            self.ffmpeg_path = Some(local_ffmpeg);
            if local_ffprobe.exists() {
                self.ffprobe_path = Some(local_ffprobe);
            }
            return Ok(());
        }
        
        // 3. 需要下载 FFmpeg
        info!("FFmpeg not found, attempting to download...");
        self.download_ffmpeg().await
    }
    
    /// 下载 FFmpeg
    async fn download_ffmpeg(&mut self) -> io::Result<()> {
        let arch = Architecture::detect();
        info!("Detected architecture: {:?}", arch);
        
        if arch == Architecture::Unknown {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Unknown architecture, cannot download FFmpeg automatically"
            ));
        }
        
        // 创建安装目录
        fs::create_dir_all(&self.install_dir)?;
        
        // 根据架构选择下载源
        let download_result = match arch {
            Architecture::Aarch64 => self.download_from_johnvansickle("arm64").await,
            Architecture::Armhf => self.download_from_johnvansickle("armhf").await,
            Architecture::X86_64 => self.download_from_johnvansickle("amd64").await,
            Architecture::Unknown => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Unknown architecture"
            )),
        };
        
        // 如果第一个源失败，尝试使用包管理器
        if download_result.is_err() {
            warn!("Static download failed, trying package manager...");
            return self.install_via_package_manager().await;
        }
        
        download_result
    }
    
    /// 从 John Van Sickle 网站下载静态编译的 FFmpeg
    async fn download_from_johnvansickle(&mut self, arch: &str) -> io::Result<()> {
        let filename = format!("ffmpeg-release-{}-static.tar.xz", arch);
        let url = format!("{}/{}", FFMPEG_STATIC_BASE_URL, filename);
        
        info!("Downloading FFmpeg from: {}", url);
        
        let temp_dir = self.install_dir.join("temp");
        fs::create_dir_all(&temp_dir)?;
        
        let archive_path = temp_dir.join(&filename);
        
        // 使用 curl 或 wget 下载
        let download_success = self.download_file(&url, &archive_path).await?;
        
        if !download_success {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to download FFmpeg"
            ));
        }
        
        // 解压文件
        info!("Extracting FFmpeg...");
        self.extract_tar_xz(&archive_path, &temp_dir)?;
        
        // 查找解压后的 ffmpeg 二进制文件
        let extracted_dir = self.find_extracted_ffmpeg_dir(&temp_dir)?;
        
        // 移动二进制文件到安装目录
        let ffmpeg_src = extracted_dir.join("ffmpeg");
        let ffprobe_src = extracted_dir.join("ffprobe");
        let ffmpeg_dst = self.install_dir.join("ffmpeg");
        let ffprobe_dst = self.install_dir.join("ffprobe");
        
        if ffmpeg_src.exists() {
            fs::copy(&ffmpeg_src, &ffmpeg_dst)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&ffmpeg_dst, fs::Permissions::from_mode(0o755))?;
            }
            self.ffmpeg_path = Some(ffmpeg_dst);
            info!("FFmpeg installed successfully");
        }
        
        if ffprobe_src.exists() {
            fs::copy(&ffprobe_src, &ffprobe_dst)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&ffprobe_dst, fs::Permissions::from_mode(0o755))?;
            }
            self.ffprobe_path = Some(ffprobe_dst);
            info!("FFprobe installed successfully");
        }
        
        // 清理临时文件
        let _ = fs::remove_dir_all(&temp_dir);
        
        Ok(())
    }
    
    /// 使用系统下载工具下载文件
    async fn download_file(&self, url: &str, dest: &Path) -> io::Result<bool> {
        // 尝试使用 curl
        let curl_result = Command::new("curl")
            .args(["-fSL", "-o", dest.to_str().unwrap(), "--progress-bar", url])
            .status();
        
        if let Ok(status) = curl_result {
            if status.success() {
                return Ok(true);
            }
        }
        
        // 尝试使用 wget
        let wget_result = Command::new("wget")
            .args(["-q", "--show-progress", "-O", dest.to_str().unwrap(), url])
            .status();
        
        if let Ok(status) = wget_result {
            if status.success() {
                return Ok(true);
            }
        }
        
        // 使用 Rust 内置的 HTTP 客户端
        self.download_with_reqwest(url, dest).await
    }
    
    /// 使用 reqwest 下载（备用方案）
    async fn download_with_reqwest(&self, url: &str, dest: &Path) -> io::Result<bool> {
        // 使用简单的 HTTP 请求
        // 注意：这需要 reqwest 依赖，如果没有就跳过
        
        // 尝试使用系统的 curl 命令（不带进度条）
        let result = Command::new("curl")
            .args(["-fsSL", "-o", dest.to_str().unwrap(), url])
            .status();
        
        if let Ok(status) = result {
            return Ok(status.success());
        }
        
        // 尝试使用 busybox wget
        let result = Command::new("busybox")
            .args(["wget", "-O", dest.to_str().unwrap(), url])
            .status();
        
        if let Ok(status) = result {
            return Ok(status.success());
        }
        
        Err(io::Error::new(
            io::ErrorKind::Other,
            "No download tool available (curl, wget, or busybox)"
        ))
    }
    
    /// 解压 tar.xz 文件
    fn extract_tar_xz(&self, archive: &Path, dest: &Path) -> io::Result<()> {
        // 尝试使用 tar 命令
        let status = Command::new("tar")
            .args(["-xJf", archive.to_str().unwrap(), "-C", dest.to_str().unwrap()])
            .status()?;
        
        if !status.success() {
            // 尝试使用 xz + tar 分步解压
            let xz_output = archive.with_extension("");
            
            let xz_status = Command::new("xz")
                .args(["-dk", archive.to_str().unwrap()])
                .status();
            
            if let Ok(s) = xz_status {
                if s.success() {
                    let tar_status = Command::new("tar")
                        .args(["-xf", xz_output.to_str().unwrap(), "-C", dest.to_str().unwrap()])
                        .status()?;
                    
                    let _ = fs::remove_file(&xz_output);
                    
                    if !tar_status.success() {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "Failed to extract tar archive"
                        ));
                    }
                    return Ok(());
                }
            }
            
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to extract tar.xz archive"
            ));
        }
        
        Ok(())
    }
    
    /// 查找解压后的 FFmpeg 目录
    fn find_extracted_ffmpeg_dir(&self, temp_dir: &Path) -> io::Result<PathBuf> {
        for entry in fs::read_dir(temp_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && path.file_name()
                .map(|n| n.to_string_lossy().contains("ffmpeg"))
                .unwrap_or(false) 
            {
                return Ok(path);
            }
        }
        
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Could not find extracted FFmpeg directory"
        ))
    }
    
    /// 通过包管理器安装 FFmpeg
    async fn install_via_package_manager(&mut self) -> io::Result<()> {
        info!("Attempting to install FFmpeg via package manager...");
        
        // 检测包管理器并安装
        let install_result = if Path::new("/usr/bin/apt-get").exists() {
            // Debian/Ubuntu/Armbian
            info!("Using apt-get to install FFmpeg...");
            Command::new("sudo")
                .args(["apt-get", "update", "-qq"])
                .status()
                .ok();
            Command::new("sudo")
                .args(["apt-get", "install", "-y", "ffmpeg"])
                .status()
        } else if Path::new("/usr/bin/apt").exists() {
            // 较新的 Debian/Ubuntu
            info!("Using apt to install FFmpeg...");
            Command::new("sudo")
                .args(["apt", "update", "-qq"])
                .status()
                .ok();
            Command::new("sudo")
                .args(["apt", "install", "-y", "ffmpeg"])
                .status()
        } else if Path::new("/usr/bin/dnf").exists() {
            // Fedora/RHEL
            info!("Using dnf to install FFmpeg...");
            Command::new("sudo")
                .args(["dnf", "install", "-y", "ffmpeg"])
                .status()
        } else if Path::new("/usr/bin/yum").exists() {
            // CentOS/RHEL (older)
            info!("Using yum to install FFmpeg...");
            Command::new("sudo")
                .args(["yum", "install", "-y", "ffmpeg"])
                .status()
        } else if Path::new("/usr/bin/pacman").exists() {
            // Arch Linux
            info!("Using pacman to install FFmpeg...");
            Command::new("sudo")
                .args(["pacman", "-S", "--noconfirm", "ffmpeg"])
                .status()
        } else if Path::new("/sbin/apk").exists() {
            // Alpine Linux
            info!("Using apk to install FFmpeg...");
            Command::new("sudo")
                .args(["apk", "add", "ffmpeg"])
                .status()
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No supported package manager found"
            ));
        };
        
        match install_result {
            Ok(status) if status.success() => {
                info!("FFmpeg installed successfully via package manager");
                // 重新查找系统 FFmpeg
                if let Some(path) = find_system_ffmpeg() {
                    self.ffmpeg_path = Some(PathBuf::from(&path));
                    self.ffprobe_path = find_system_ffprobe().map(PathBuf::from);
                    return Ok(());
                }
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "FFmpeg installed but not found in PATH"
                ))
            }
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "Package manager failed to install FFmpeg"
            )),
            Err(e) => Err(e),
        }
    }
    
    /// 获取 FFmpeg 路径
    pub fn ffmpeg_path(&self) -> Option<&Path> {
        self.ffmpeg_path.as_deref()
    }
    
    /// 获取 FFprobe 路径
    pub fn ffprobe_path(&self) -> Option<&Path> {
        self.ffprobe_path.as_deref()
    }
    
    /// 检查 FFmpeg 是否可用
    pub fn is_available(&self) -> bool {
        self.ffmpeg_path.is_some()
    }
    
    /// 获取 FFmpeg 版本信息
    pub fn get_version(&self) -> Option<String> {
        let ffmpeg_path = self.ffmpeg_path.as_ref()?;
        
        let output = Command::new(ffmpeg_path)
            .arg("-version")
            .output()
            .ok()?;
        
        let version_str = String::from_utf8_lossy(&output.stdout);
        version_str.lines().next().map(|s| s.to_string())
    }
}

/// 查找系统安装的 FFmpeg
fn find_system_ffmpeg() -> Option<String> {
    let paths = [
        "ffmpeg",
        "/usr/bin/ffmpeg",
        "/usr/local/bin/ffmpeg",
        "/opt/ffmpeg/bin/ffmpeg",
        "/snap/bin/ffmpeg",
        #[cfg(target_os = "windows")]
        "C:\\ffmpeg\\bin\\ffmpeg.exe",
        #[cfg(target_os = "windows")]
        "C:\\Program Files\\ffmpeg\\bin\\ffmpeg.exe",
    ];
    
    for path in paths {
        let result = Command::new(path)
            .arg("-version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        
        if let Ok(status) = result {
            if status.success() {
                return Some(path.to_string());
            }
        }
    }
    
    None
}

/// 查找系统安装的 FFprobe
fn find_system_ffprobe() -> Option<String> {
    let paths = [
        "ffprobe",
        "/usr/bin/ffprobe",
        "/usr/local/bin/ffprobe",
        "/opt/ffmpeg/bin/ffprobe",
        "/snap/bin/ffprobe",
        #[cfg(target_os = "windows")]
        "C:\\ffmpeg\\bin\\ffprobe.exe",
        #[cfg(target_os = "windows")]
        "C:\\Program Files\\ffmpeg\\bin\\ffprobe.exe",
    ];
    
    for path in paths {
        let result = Command::new(path)
            .arg("-version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        
        if let Ok(status) = result {
            if status.success() {
                return Some(path.to_string());
            }
        }
    }
    
    None
}

/// 检查文件是否可执行
#[allow(unreachable_code)]
fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(path) {
            return metadata.permissions().mode() & 0o111 != 0;
        }
        return false;
    }
    #[cfg(not(unix))]
    {
        return path.exists();
    }
}

/// 全局 FFmpeg 路径缓存
static FFMPEG_PATH: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
static FFPROBE_PATH: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

/// 设置全局 FFmpeg 路径
pub fn set_global_ffmpeg_path(path: Option<String>) {
    let _ = FFMPEG_PATH.set(path);
}

/// 设置全局 FFprobe 路径
pub fn set_global_ffprobe_path(path: Option<String>) {
    let _ = FFPROBE_PATH.set(path);
}

/// 获取全局 FFmpeg 路径
pub fn get_global_ffmpeg_path() -> Option<String> {
    FFMPEG_PATH.get().and_then(|p| p.clone())
}

/// 获取全局 FFprobe 路径
pub fn get_global_ffprobe_path() -> Option<String> {
    FFPROBE_PATH.get().and_then(|p| p.clone())
}
