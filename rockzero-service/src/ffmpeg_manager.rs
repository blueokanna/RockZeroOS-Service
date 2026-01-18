use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use tracing::{info, warn, error};

static GLOBAL_FFMPEG_PATH: Mutex<Option<String>> = Mutex::new(None);
static GLOBAL_FFPROBE_PATH: Mutex<Option<String>> = Mutex::new(None);

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
}

impl FfmpegManager {
    pub fn new(base_dir: &str) -> Self {
        let base = PathBuf::from(base_dir).join("ffmpeg");
        std::fs::create_dir_all(&base).ok();
        
        Self {
            base_dir: base,
            ffmpeg_path: None,
            ffprobe_path: None,
            version: None,
        }
    }

    pub async fn ensure_available(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(path) = self.find_system_ffmpeg() {
            info!("Using system FFmpeg: {}", path.display());
            self.ffmpeg_path = Some(path.clone());
            if let Some(version) = self.get_ffmpeg_version(&path) {
                self.version = Some(version);
            }
        } else {
            warn!("FFmpeg not found in system PATH");
            let downloaded = self.download_ffmpeg().await?;
            if downloaded {
                info!("FFmpeg downloaded successfully");
            }
        }

        if let Some(path) = self.find_system_ffprobe() {
            self.ffprobe_path = Some(path);
        }

        Ok(())
    }

    fn find_system_ffmpeg(&self) -> Option<PathBuf> {
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

        let local_path = self.base_dir.join(if cfg!(target_os = "windows") {
            "ffmpeg.exe"
        } else {
            "ffmpeg"
        });
        
        if local_path.exists() {
            return Some(local_path);
        }

        None
    }

    fn find_system_ffprobe(&self) -> Option<PathBuf> {
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

        let local_path = self.base_dir.join(if cfg!(target_os = "windows") {
            "ffprobe.exe"
        } else {
            "ffprobe"
        });
        
        if local_path.exists() {
            return Some(local_path);
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
        
        Ok(true)
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
}
