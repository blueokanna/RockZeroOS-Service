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
        // First, try to find FFmpeg in system PATH
        if let Some(path) = self.find_system_ffmpeg() {
            info!("Using system FFmpeg: {}", path.display());
            self.ffmpeg_path = Some(path.clone());
            if let Some(version) = self.get_ffmpeg_version(&path) {
                self.version = Some(version);
            }
        } else {
            // Check if we have a local archive to extract
            let archive_path = PathBuf::from("ffmpeg-release-arm64-static.tar.xz");
            if archive_path.exists() {
                info!("Found local FFmpeg archive: {}", archive_path.display());
                if let Err(e) = self.extract_ffmpeg_archive(&archive_path).await {
                    error!("Failed to extract FFmpeg archive: {}", e);
                    warn!("Attempting to download FFmpeg...");
                    let downloaded = self.download_ffmpeg().await?;
                    if downloaded {
                        info!("FFmpeg downloaded successfully");
                    }
                } else {
                    info!("FFmpeg extracted successfully");
                }
            } else {
                warn!("FFmpeg not found in system PATH or local directory");
                let downloaded = self.download_ffmpeg().await?;
                if downloaded {
                    info!("FFmpeg downloaded successfully");
                }
            }
            
            // After extraction/download, try to find it again
            if let Some(path) = self.find_system_ffmpeg() {
                self.ffmpeg_path = Some(path.clone());
                if let Some(version) = self.get_ffmpeg_version(&path) {
                    self.version = Some(version);
                }
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

    async fn extract_ffmpeg_archive(&mut self, archive_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        info!("Extracting FFmpeg from: {}", archive_path.display());

        // For tar.xz files, we need to use tar command on Unix systems
        #[cfg(target_family = "unix")]
        {
            let output = Command::new("tar")
                .arg("-xJf")
                .arg(archive_path)
                .arg("-C")
                .arg(&self.base_dir)
                .output()?;

            if !output.status.success() {
                let error_msg = String::from_utf8_lossy(&output.stderr);
                return Err(format!("Failed to extract archive: {}", error_msg).into());
            }

            // Find the extracted ffmpeg and ffprobe binaries
            self.find_and_setup_extracted_binaries()?;
            return Ok(());
        }

        #[cfg(not(target_family = "unix"))]
        {
            let _ = archive_path; // Suppress unused variable warning
            Err("Archive extraction on this platform requires manual extraction".into())
        }
    }

    #[cfg(target_family = "unix")]
    fn find_and_setup_extracted_binaries(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        use walkdir::WalkDir;
        use std::os::unix::fs::PermissionsExt;

        // Walk through the base_dir to find ffmpeg and ffprobe
        for entry in WalkDir::new(&self.base_dir)
            .follow_links(false)
            .max_depth(5)
        {
            if let Ok(entry) = entry {
                let file_name = entry.file_name().to_string_lossy();
                
                if file_name == "ffmpeg" && entry.path().is_file() {
                    info!("Found ffmpeg at: {}", entry.path().display());
                    
                    // Set executable permissions
                    let metadata = std::fs::metadata(entry.path())?;
                    let mut permissions = metadata.permissions();
                    permissions.set_mode(0o755);
                    std::fs::set_permissions(entry.path(), permissions)?;
                    
                    self.ffmpeg_path = Some(entry.path().to_path_buf());
                } else if file_name == "ffprobe" && entry.path().is_file() {
                    info!("Found ffprobe at: {}", entry.path().display());
                    
                    // Set executable permissions
                    let metadata = std::fs::metadata(entry.path())?;
                    let mut permissions = metadata.permissions();
                    permissions.set_mode(0o755);
                    std::fs::set_permissions(entry.path(), permissions)?;
                    
                    self.ffprobe_path = Some(entry.path().to_path_buf());
                }
            }
        }

        if self.ffmpeg_path.is_some() {
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
}
