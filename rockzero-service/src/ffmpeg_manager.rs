use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use tracing::{error, info, warn};

static GLOBAL_FFMPEG_PATH: Mutex<Option<String>> = Mutex::new(None);
static GLOBAL_FFPROBE_PATH: Mutex<Option<String>> = Mutex::new(None);

#[cfg(target_os = "windows")]
const LOCAL_ASSETS_PATH: &str = r".\assets";

#[cfg(not(target_os = "windows"))]
const LOCAL_ASSETS_PATH: &str = "./assets";

pub fn set_global_ffmpeg_path(path: Option<String>) {
    let mut global = GLOBAL_FFMPEG_PATH.lock().unwrap();
    *global = path;
}

pub fn set_global_ffprobe_path(path: Option<String>) {
    let mut global = GLOBAL_FFPROBE_PATH.lock().unwrap();
    *global = path;
}

pub fn get_global_ffmpeg_path() -> Option<String> {
    GLOBAL_FFMPEG_PATH.lock().unwrap().clone()
}

pub fn get_global_ffprobe_path() -> Option<String> {
    GLOBAL_FFPROBE_PATH.lock().unwrap().clone()
}

pub struct FfmpegManager {
    base_dir: PathBuf,
    ffmpeg_path: Option<PathBuf>,
    ffprobe_path: Option<PathBuf>,
    version: Option<String>,
    local_assets_dir: PathBuf,
}

impl FfmpegManager {
    pub fn new(base_dir: &str) -> Self {
        let base = PathBuf::from(base_dir).join("ffmpeg");
        std::fs::create_dir_all(&base).ok();

        let local_assets_dir = if let Ok(path) = env::var("FFMPEG_ASSETS_PATH") {
            PathBuf::from(path)
        } else {
            PathBuf::from(LOCAL_ASSETS_PATH)
        };

        info!("FfmpegManager initialized");
        info!("  Base directory: {}", base.display());
        info!("  Local assets directory: {}", local_assets_dir.display());

        Self {
            base_dir: base,
            ffmpeg_path: None,
            ffprobe_path: None,
            version: None,
            local_assets_dir,
        }
    }

    pub fn with_assets_path(base_dir: &str, assets_path: &str) -> Self {
        let base = PathBuf::from(base_dir).join("ffmpeg");
        std::fs::create_dir_all(&base).ok();
        let local_assets_dir = PathBuf::from(assets_path);

        info!("FfmpegManager initialized with custom assets path");
        info!("  Base directory: {}", base.display());
        info!("  Local assets directory: {}", local_assets_dir.display());

        Self {
            base_dir: base,
            ffmpeg_path: None,
            ffprobe_path: None,
            version: None,
            local_assets_dir,
        }
    }

    pub async fn ensure_available(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let local_ffmpeg = self.base_dir.join("ffmpeg");
        if local_ffmpeg.exists() {
            info!("Found installed FFmpeg: {}", local_ffmpeg.display());
            self.ffmpeg_path = Some(local_ffmpeg.clone());

            let local_ffprobe = self.base_dir.join("ffprobe");
            if local_ffprobe.exists() {
                self.ffprobe_path = Some(local_ffprobe);
            }

            if let Some(version) = self.get_ffmpeg_version(&local_ffmpeg) {
                self.version = Some(version);
            }
            return Ok(());
        }

        if let Some(path) = self.find_system_ffmpeg() {
            info!("Using system FFmpeg: {}", path.display());
            self.ffmpeg_path = Some(path.clone());
            if let Some(version) = self.get_ffmpeg_version(&path) {
                self.version = Some(version);
            }
            if let Some(probe_path) = self.find_system_ffprobe() {
                self.ffprobe_path = Some(probe_path);
            }
            return Ok(());
        }

        let archive_candidates = self.get_archive_candidates();
        let mut found_archive: Option<PathBuf> = None;

        info!("Searching for FFmpeg archive in:");
        for candidate in &archive_candidates {
            info!("  - {}", candidate.display());
            if candidate.exists() {
                info!("Found local FFmpeg archive: {}", candidate.display());
                found_archive = Some(candidate.clone());
                break;
            }
        }

        if let Some(archive_path) = found_archive {
            match self.extract_ffmpeg_archive(&archive_path).await {
                Ok(_) => {
                    info!(
                        "FFmpeg extracted successfully from {}",
                        archive_path.display()
                    );
                    // 设置路径
                    let ffmpeg_bin = self.base_dir.join("ffmpeg");
                    if ffmpeg_bin.exists() {
                        self.ffmpeg_path = Some(ffmpeg_bin.clone());
                        if let Some(version) = self.get_ffmpeg_version(&ffmpeg_bin) {
                            self.version = Some(version);
                        }
                    }
                    let ffprobe_bin = self.base_dir.join("ffprobe");
                    if ffprobe_bin.exists() {
                        self.ffprobe_path = Some(ffprobe_bin);
                    }
                    return Ok(());
                }
                Err(e) => {
                    error!("Failed to extract FFmpeg archive: {}", e);
                    warn!("Attempting to download FFmpeg...");
                }
            }
        } else {
            warn!("FFmpeg archive not found in any of the searched locations");
        }

        let downloaded = self.download_ffmpeg().await?;
        if downloaded {
            info!("FFmpeg downloaded successfully");
        }

        if let Some(path) = self.find_system_ffmpeg() {
            self.ffmpeg_path = Some(path.clone());
            if let Some(version) = self.get_ffmpeg_version(&path) {
                self.version = Some(version);
            }
        }

        if let Some(path) = self.find_system_ffprobe() {
            self.ffprobe_path = Some(path);
        }

        if self.ffmpeg_path.is_none() {
            return Err("FFmpeg not available after all attempts".into());
        }

        Ok(())
    }

    fn get_archive_candidates(&self) -> Vec<PathBuf> {
        let arch_slug = Self::detect_arch_slug();
        let archive_name = format!("ffmpeg-release-{}-static.tar.xz", arch_slug);
        let mut candidates = Vec::new();

        if let Ok(path) = env::var("FFMPEG_ARCHIVE_PATH") {
            candidates.push(PathBuf::from(path));
        }

        candidates.push(self.local_assets_dir.join(&archive_name));
        candidates.push(
            self.local_assets_dir
                .join("ffmpeg-release-arm64-static.tar.xz"),
        );
        candidates.push(
            self.local_assets_dir
                .join("ffmpeg-release-amd64-static.tar.xz"),
        );
        candidates.push(self.base_dir.join(&archive_name));

        // 父目录
        if let Some(parent) = self.base_dir.parent() {
            candidates.push(parent.join(&archive_name));
            candidates.push(parent.join("assets").join(&archive_name));
        }

        // 当前目录
        candidates.push(PathBuf::from(&archive_name));
        candidates.push(PathBuf::from("assets").join(&archive_name));

        // 绝对路径尝试
        candidates.push(PathBuf::from("/app/assets").join(&archive_name));
        candidates.push(PathBuf::from("/opt/rockzero/assets").join(&archive_name));

        candidates
    }

    fn detect_arch_slug() -> &'static str {
        #[cfg(target_arch = "x86_64")]
        return "amd64";

        #[cfg(target_arch = "aarch64")]
        return "arm64";

        #[cfg(target_arch = "arm")]
        return "armhf";

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
        return "amd64";
    }

    fn find_system_ffmpeg(&self) -> Option<PathBuf> {
        // 检查 base_dir 中的 ffmpeg
        let local_path = self.base_dir.join(if cfg!(target_os = "windows") {
            "ffmpeg.exe"
        } else {
            "ffmpeg"
        });
        if local_path.exists() {
            return Some(local_path);
        }

        #[cfg(target_os = "windows")]
        {
            let local_path = self.local_assets_dir.join("ffmpeg.exe");
            if local_path.exists() {
                return Some(local_path);
            }
        }

        // 检查系统 PATH
        if cfg!(target_os = "windows") {
            if let Ok(output) = Command::new("where").arg("ffmpeg").output() {
                if output.status.success() {
                    let path = String::from_utf8_lossy(&output.stdout);
                    return Some(PathBuf::from(path.trim().split('\n').next()?));
                }
            }
        } else if let Ok(output) = Command::new("which").arg("ffmpeg").output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout);
                return Some(PathBuf::from(path.trim()));
            }
        }

        // 检查常见路径
        let common_paths = [
            "/usr/bin/ffmpeg",
            "/usr/local/bin/ffmpeg",
            "/opt/ffmpeg/bin/ffmpeg",
            "/snap/bin/ffmpeg",
        ];

        for path in &common_paths {
            let p = PathBuf::from(path);
            if p.exists() {
                return Some(p);
            }
        }

        None
    }

    fn find_system_ffprobe(&self) -> Option<PathBuf> {
        // 检查 base_dir 中的 ffprobe
        let local_path = self.base_dir.join(if cfg!(target_os = "windows") {
            "ffprobe.exe"
        } else {
            "ffprobe"
        });
        if local_path.exists() {
            return Some(local_path);
        }

        #[cfg(target_os = "windows")]
        {
            let local_path = self.local_assets_dir.join("ffprobe.exe");
            if local_path.exists() {
                return Some(local_path);
            }
        }

        if cfg!(target_os = "windows") {
            if let Ok(output) = Command::new("where").arg("ffprobe").output() {
                if output.status.success() {
                    let path = String::from_utf8_lossy(&output.stdout);
                    return Some(PathBuf::from(path.trim().split('\n').next()?));
                }
            }
        } else if let Ok(output) = Command::new("which").arg("ffprobe").output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout);
                return Some(PathBuf::from(path.trim()));
            }
        }

        let common_paths = [
            "/usr/bin/ffprobe",
            "/usr/local/bin/ffprobe",
            "/opt/ffmpeg/bin/ffprobe",
            "/snap/bin/ffprobe",
        ];

        for path in &common_paths {
            let p = PathBuf::from(path);
            if p.exists() {
                return Some(p);
            }
        }

        None
    }

    fn get_ffmpeg_version(&self, path: &Path) -> Option<String> {
        if let Ok(output) = Command::new(path).arg("-version").output() {
            if output.status.success() {
                let version_str = String::from_utf8_lossy(&output.stdout);
                if let Some(line) = version_str.lines().next() {
                    return Some(line.to_string());
                }
            }
        }
        None
    }

    async fn download_ffmpeg(&mut self) -> Result<bool, Box<dyn std::error::Error>> {
        info!("Attempting to download FFmpeg...");

        let download_url = if cfg!(target_os = "windows") {
            "https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-essentials.zip"
        } else if cfg!(target_os = "linux") {
            if cfg!(target_arch = "x86_64") {
                "https://johnvansickle.com/ffmpeg/releases/ffmpeg-release-amd64-static.tar.xz"
            } else if cfg!(target_arch = "aarch64") {
                "https://johnvansickle.com/ffmpeg/releases/ffmpeg-release-arm64-static.tar.xz"
            } else {
                return Err("Unsupported architecture for FFmpeg download".into());
            }
        } else if cfg!(target_os = "macos") {
            warn!("FFmpeg auto-download not supported on macOS. Please install via Homebrew: brew install ffmpeg");
            return Ok(false);
        } else {
            return Err("Unsupported OS for FFmpeg download".into());
        };

        info!("Downloading from: {}", download_url);

        let client = reqwest::Client::new();
        let response = client.get(download_url).send().await?;

        if !response.status().is_success() {
            error!("Failed to download FFmpeg: HTTP {}", response.status());
            return Ok(false);
        }

        let bytes = response.bytes().await?;
        let archive_path = self.base_dir.join("ffmpeg_download.tmp");
        std::fs::write(&archive_path, &bytes)?;

        info!("Download complete, extracting...");

        self.extract_ffmpeg_archive(&archive_path).await?;

        Ok(true)
    }

    async fn extract_ffmpeg_archive(
        &mut self,
        archive_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("Extracting FFmpeg from: {}", archive_path.display());

        #[cfg(target_family = "unix")]
        {
            // 创建临时解压目录
            let temp_dir = self.base_dir.join("temp_extract");
            if temp_dir.exists() {
                std::fs::remove_dir_all(&temp_dir)?;
            }
            std::fs::create_dir_all(&temp_dir)?;

            let output = Command::new("tar")
                .arg("-xJf")
                .arg(archive_path)
                .arg("-C")
                .arg(&temp_dir)
                .output()?;

            if !output.status.success() {
                let error_msg = String::from_utf8_lossy(&output.stderr);
                return Err(format!("Failed to extract archive: {}", error_msg).into());
            }

            // 查找解压后的 ffmpeg 二进制文件
            self.find_and_setup_extracted_binaries(&temp_dir)?;

            // 清理临时目录
            let _ = std::fs::remove_dir_all(&temp_dir);

            return Ok(());
        }

        #[cfg(not(target_family = "unix"))]
        {
            let _ = archive_path;
            Err("Archive extraction on this platform requires manual extraction".into())
        }
    }

    #[cfg(target_family = "unix")]
    fn find_and_setup_extracted_binaries(
        &mut self,
        temp_dir: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;
        use walkdir::WalkDir;

        let mut found_ffmpeg = false;
        let mut found_ffprobe = false;

        for entry in WalkDir::new(temp_dir).follow_links(false).max_depth(5) {
            if let Ok(entry) = entry {
                let file_name = entry.file_name().to_string_lossy();

                if file_name == "ffmpeg" && entry.path().is_file() {
                    info!("Found ffmpeg at: {}", entry.path().display());

                    let dest_path = self.base_dir.join("ffmpeg");
                    std::fs::copy(entry.path(), &dest_path)?;

                    // Set executable permissions
                    let metadata = std::fs::metadata(&dest_path)?;
                    let mut permissions = metadata.permissions();
                    permissions.set_mode(0o755);
                    std::fs::set_permissions(&dest_path, permissions)?;

                    self.ffmpeg_path = Some(dest_path);
                    found_ffmpeg = true;
                } else if file_name == "ffprobe" && entry.path().is_file() {
                    info!("Found ffprobe at: {}", entry.path().display());

                    let dest_path = self.base_dir.join("ffprobe");
                    std::fs::copy(entry.path(), &dest_path)?;

                    // Set executable permissions
                    let metadata = std::fs::metadata(&dest_path)?;
                    let mut permissions = metadata.permissions();
                    permissions.set_mode(0o755);
                    std::fs::set_permissions(&dest_path, permissions)?;

                    self.ffprobe_path = Some(dest_path);
                    found_ffprobe = true;
                }

                if found_ffmpeg && found_ffprobe {
                    break;
                }
            }
        }

        if found_ffmpeg {
            info!("FFmpeg binaries configured successfully");
            Ok(())
        } else {
            Err("Could not find ffmpeg binary in extracted archive".into())
        }
    }

    pub fn ffmpeg_path(&self) -> Option<&Path> {
        self.ffmpeg_path.as_deref()
    }

    pub fn ffprobe_path(&self) -> Option<&Path> {
        self.ffprobe_path.as_deref()
    }

    pub fn get_version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    pub fn local_assets_dir(&self) -> &Path {
        &self.local_assets_dir
    }
}
