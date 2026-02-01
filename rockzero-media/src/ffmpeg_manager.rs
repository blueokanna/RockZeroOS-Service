use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use tracing::{info, warn};

static GLOBAL_FFMPEG_PATH: OnceLock<Option<String>> = OnceLock::new();
static GLOBAL_FFPROBE_PATH: OnceLock<Option<String>> = OnceLock::new();

const FFMPEG_STATIC_BASE_URL: &str = "https://johnvansickle.com/ffmpeg/releases";

#[allow(dead_code)]
const FFMPEG_GITHUB_RELEASES: &str =
    "https://github.com/BtbN/FFmpeg-Builds/releases/download/latest";

#[cfg(target_os = "windows")]
const LOCAL_ASSETS_PATH: &str = r".\assets";

#[cfg(not(target_os = "windows"))]
const LOCAL_ASSETS_PATH: &str = "./assets";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86_64,
    Aarch64,
    Armhf,
    Unknown,
}

impl Architecture {
    pub fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            return Architecture::X86_64;
        }

        #[cfg(target_arch = "aarch64")]
        {
            return Architecture::Aarch64;
        }

        #[cfg(target_arch = "arm")]
        {
            return Architecture::Armhf;
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
        {
            if let Ok(output) = Command::new("uname").arg("-m").output() {
                let arch = String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .to_lowercase();
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

    pub fn as_str(&self) -> &'static str {
        match self {
            Architecture::X86_64 => "x86_64",
            Architecture::Aarch64 => "aarch64",
            Architecture::Armhf => "armhf",
            Architecture::Unknown => "unknown",
        }
    }

    pub fn download_slug(&self) -> &'static str {
        match self {
            Architecture::Aarch64 => "arm64",
            Architecture::Armhf => "armhf",
            Architecture::X86_64 => "amd64",
            Architecture::Unknown => "unknown",
        }
    }
}

pub struct FfmpegManager {
    install_dir: PathBuf,
    ffmpeg_path: Option<PathBuf>,
    ffprobe_path: Option<PathBuf>,
    local_assets_dir: PathBuf,
}

impl FfmpegManager {
    pub fn new(data_dir: &str) -> Self {
        let install_dir = PathBuf::from(data_dir).join("ffmpeg");
        let local_assets_dir = if let Ok(path) = env::var("FFMPEG_ASSETS_PATH") {
            PathBuf::from(path)
        } else {
            PathBuf::from(LOCAL_ASSETS_PATH)
        };

        info!("FFmpeg manager initialized");
        info!("  Install directory: {}", install_dir.display());
        info!("  Local assets directory: {}", local_assets_dir.display());

        Self {
            install_dir,
            ffmpeg_path: None,
            ffprobe_path: None,
            local_assets_dir,
        }
    }

    pub fn with_assets_path(data_dir: &str, assets_path: &str) -> Self {
        let install_dir = PathBuf::from(data_dir).join("ffmpeg");
        let local_assets_dir = PathBuf::from(assets_path);

        info!("FFmpeg manager initialized with custom assets path");
        info!("  Install directory: {}", install_dir.display());
        info!("  Local assets directory: {}", local_assets_dir.display());

        Self {
            install_dir,
            ffmpeg_path: None,
            ffprobe_path: None,
            local_assets_dir,
        }
    }

    pub async fn ensure_available(&mut self) -> io::Result<()> {
        info!("Checking FFmpeg availability...");

        // 1. 首先检查系统是否已安装 FFmpeg
        if let Some(path) = find_system_ffmpeg() {
            info!("Found system FFmpeg: {}", path);
            self.ffmpeg_path = Some(PathBuf::from(&path));
            self.ffprobe_path = find_system_ffprobe().map(PathBuf::from);
            return Ok(());
        }

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

        info!("FFmpeg not found, attempting to install from local assets or download...");
        self.install_ffmpeg().await
    }

    async fn install_ffmpeg(&mut self) -> io::Result<()> {
        let arch = Architecture::detect();
        info!("Detected architecture: {:?}", arch);

        if arch == Architecture::Unknown {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Unknown architecture, cannot install FFmpeg automatically",
            ));
        }

        let arch_slug = arch.download_slug();

        fs::create_dir_all(&self.install_dir)?;

        let archive_name = format!("ffmpeg-release-{}-static.tar.xz", arch_slug);
        let local_archive = self.locate_local_archive(&archive_name);

        if let Some(archive_path) = local_archive {
            info!("Found local FFmpeg archive: {}", archive_path.display());
            match self.install_from_archive(&archive_path) {
                Ok(_) => {
                    info!("FFmpeg installed successfully from local archive");
                    return Ok(());
                }
                Err(err) => {
                    warn!(
                        "Failed to install FFmpeg from local archive: {}. Will try online download...",
                        err
                    );
                }
            }
        } else {
            info!("No local FFmpeg archive found, will try online download");
            info!("  Searched for: {}", archive_name);
            info!("  In directories:");
            info!("    - {}", self.local_assets_dir.display());
            info!("    - {}", self.install_dir.display());
            if let Some(parent) = self.install_dir.parent() {
                info!("    - {}", parent.display());
            }
            info!("    - ./");
        }

        let download_result = self.download_from_johnvansickle(arch_slug).await;
        if download_result.is_err() {
            warn!("Static download failed, trying package manager...");
            return self.install_via_package_manager().await;
        }

        download_result
    }

    async fn download_from_johnvansickle(&mut self, arch: &str) -> io::Result<()> {
        let filename = format!("ffmpeg-release-{}-static.tar.xz", arch);
        let url = format!("{}/{}", FFMPEG_STATIC_BASE_URL, filename);

        info!("Downloading FFmpeg from: {}", url);

        let temp_dir = self.install_dir.join("temp");
        fs::create_dir_all(&temp_dir)?;

        let archive_path = temp_dir.join(&filename);
        let download_success = self.download_file(&url, &archive_path).await?;

        if !download_success {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to download FFmpeg",
            ));
        }

        self.install_from_archive(&archive_path)
    }

    async fn download_file(&self, url: &str, dest: &Path) -> io::Result<bool> {
        if let Ok(status) = Command::new("curl")
            .args(["-fSL", "-o", dest.to_str().unwrap(), "--progress-bar", url])
            .status()
        {
            if status.success() {
                return Ok(true);
            }
        }

        if let Ok(status) = Command::new("wget")
            .args(["-q", "--show-progress", "-O", dest.to_str().unwrap(), url])
            .status()
        {
            if status.success() {
                return Ok(true);
            }
        }

        if let Ok(status) = Command::new("curl")
            .args(["-fsSL", "-o", dest.to_str().unwrap(), url])
            .status()
        {
            if status.success() {
                return Ok(true);
            }
        }

        if let Ok(status) = Command::new("busybox")
            .args(["wget", "-O", dest.to_str().unwrap(), url])
            .status()
        {
            if status.success() {
                return Ok(true);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            "No download tool available (curl, wget, or busybox)",
        ))
    }

    fn extract_tar_xz(&self, archive: &Path, dest: &Path) -> io::Result<()> {
        if let Ok(status) = Command::new("tar")
            .args([
                "-xJf",
                archive.to_str().unwrap(),
                "-C",
                dest.to_str().unwrap(),
            ])
            .status()
        {
            if status.success() {
                return Ok(());
            }
        }

        let xz_output = archive.with_extension("");

        if let Ok(xz_status) = Command::new("xz")
            .args(["-dk", archive.to_str().unwrap()])
            .status()
        {
            if xz_status.success() {
                let tar_result = Command::new("tar")
                    .args([
                        "-xf",
                        xz_output.to_str().unwrap(),
                        "-C",
                        dest.to_str().unwrap(),
                    ])
                    .status();

                let _ = fs::remove_file(&xz_output);

                if let Ok(tar_status) = tar_result {
                    if tar_status.success() {
                        return Ok(());
                    }
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to extract tar.xz archive",
        ))
    }

    fn find_extracted_ffmpeg_dir(&self, temp_dir: &Path) -> io::Result<PathBuf> {
        for entry in fs::read_dir(temp_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir()
                && path
                    .file_name()
                    .map(|n| n.to_string_lossy().contains("ffmpeg"))
                    .unwrap_or(false)
            {
                return Ok(path);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Could not find extracted FFmpeg directory",
        ))
    }

    async fn install_via_package_manager(&mut self) -> io::Result<()> {
        info!("Attempting to install FFmpeg via package manager...");

        let install_result = if Path::new("/usr/bin/apt-get").exists() {
            info!("Using apt-get to install FFmpeg...");
            let _ = Command::new("sudo")
                .args(["apt-get", "update", "-qq"])
                .status();
            Command::new("sudo")
                .args(["apt-get", "install", "-y", "ffmpeg"])
                .status()
        } else if Path::new("/usr/bin/apt").exists() {
            info!("Using apt to install FFmpeg...");
            let _ = Command::new("sudo").args(["apt", "update", "-qq"]).status();
            Command::new("sudo")
                .args(["apt", "install", "-y", "ffmpeg"])
                .status()
        } else if Path::new("/usr/bin/dnf").exists() {
            info!("Using dnf to install FFmpeg...");
            Command::new("sudo")
                .args(["dnf", "install", "-y", "ffmpeg"])
                .status()
        } else if Path::new("/usr/bin/yum").exists() {
            info!("Using yum to install FFmpeg...");
            Command::new("sudo")
                .args(["yum", "install", "-y", "ffmpeg"])
                .status()
        } else if Path::new("/usr/bin/pacman").exists() {
            info!("Using pacman to install FFmpeg...");
            Command::new("sudo")
                .args(["pacman", "-S", "--noconfirm", "ffmpeg"])
                .status()
        } else if Path::new("/sbin/apk").exists() {
            info!("Using apk to install FFmpeg...");
            Command::new("sudo").args(["apk", "add", "ffmpeg"]).status()
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No supported package manager found",
            ));
        };

        match install_result {
            Ok(status) if status.success() => {
                info!("FFmpeg installed successfully via package manager");
                if let Some(path) = find_system_ffmpeg() {
                    self.ffmpeg_path = Some(PathBuf::from(&path));
                    self.ffprobe_path = find_system_ffprobe().map(PathBuf::from);
                    return Ok(());
                }
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "FFmpeg installed but not found in PATH",
                ))
            }
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "Package manager failed to install FFmpeg",
            )),
            Err(e) => Err(e),
        }
    }

    fn install_from_archive(&mut self, archive_path: &Path) -> io::Result<()> {
        let temp_dir = self.install_dir.join("temp");

        if temp_dir.exists() {
            let _ = fs::remove_dir_all(&temp_dir);
        }
        fs::create_dir_all(&temp_dir)?;

        let archive_in_temp = temp_dir.join(archive_path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Archive file name missing")
        })?);

        if archive_path != archive_in_temp {
            info!("Copying archive to temp directory...");
            fs::copy(archive_path, &archive_in_temp)?;
        }

        info!(
            "Extracting FFmpeg from archive: {}",
            archive_in_temp.display()
        );
        self.extract_tar_xz(&archive_in_temp, &temp_dir)?;

        let extracted_dir = self.find_extracted_ffmpeg_dir(&temp_dir)?;
        info!("Found extracted directory: {}", extracted_dir.display());

        #[cfg(not(target_os = "windows"))]
        let (ffmpeg_src, ffprobe_src) =
            (extracted_dir.join("ffmpeg"), extracted_dir.join("ffprobe"));
        #[cfg(not(target_os = "windows"))]
        let (ffmpeg_dst, ffprobe_dst) = (
            self.install_dir.join("ffmpeg"),
            self.install_dir.join("ffprobe"),
        );

        #[cfg(target_os = "windows")]
        let (ffmpeg_src, ffprobe_src) = (
            extracted_dir.join("ffmpeg.exe"),
            extracted_dir.join("ffprobe.exe"),
        );
        #[cfg(target_os = "windows")]
        let (ffmpeg_dst, ffprobe_dst) = (
            self.install_dir.join("ffmpeg.exe"),
            self.install_dir.join("ffprobe.exe"),
        );

        if ffmpeg_src.exists() {
            info!("Installing ffmpeg binary...");
            fs::copy(&ffmpeg_src, &ffmpeg_dst)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&ffmpeg_dst, fs::Permissions::from_mode(0o755))?;
            }
            self.ffmpeg_path = Some(ffmpeg_dst.clone());
            info!("FFmpeg installed: {}", ffmpeg_dst.display());
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "ffmpeg binary missing in archive",
            ));
        }

        if ffprobe_src.exists() {
            info!("Installing ffprobe binary...");
            fs::copy(&ffprobe_src, &ffprobe_dst)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&ffprobe_dst, fs::Permissions::from_mode(0o755))?;
            }
            self.ffprobe_path = Some(ffprobe_dst.clone());
            info!("FFprobe installed: {}", ffprobe_dst.display());
        }

        info!("Cleaning up temp directory...");
        let _ = fs::remove_dir_all(&temp_dir);

        Ok(())
    }

    fn locate_local_archive(&self, filename: &str) -> Option<PathBuf> {
        if let Ok(path) = env::var("FFMPEG_ARCHIVE_PATH") {
            let candidate = PathBuf::from(&path);
            if candidate.is_file() {
                info!(
                    "Found FFmpeg archive via FFMPEG_ARCHIVE_PATH: {}",
                    candidate.display()
                );
                return Some(candidate);
            }
        }

        let candidate = self.local_assets_dir.join(filename);
        if candidate.is_file() {
            info!(
                "Found FFmpeg archive in local assets: {}",
                candidate.display()
            );
            return Some(candidate);
        }

        let candidate = self.install_dir.join(filename);
        if candidate.is_file() {
            info!(
                "Found FFmpeg archive in install dir: {}",
                candidate.display()
            );
            return Some(candidate);
        }

        if let Some(parent) = self.install_dir.parent() {
            let candidate = parent.join(filename);
            if candidate.is_file() {
                info!(
                    "Found FFmpeg archive in parent dir: {}",
                    candidate.display()
                );
                return Some(candidate);
            }
        }

        let candidate = PathBuf::from(filename);
        if candidate.is_file() {
            info!(
                "Found FFmpeg archive in current dir: {}",
                candidate.display()
            );
            return Some(candidate);
        }

        None
    }

    pub fn ffmpeg_path(&self) -> Option<&Path> {
        self.ffmpeg_path.as_deref()
    }

    pub fn ffprobe_path(&self) -> Option<&Path> {
        self.ffprobe_path.as_deref()
    }

    pub fn is_available(&self) -> bool {
        self.ffmpeg_path.is_some()
    }

    pub fn get_version(&self) -> Option<String> {
        let ffmpeg_path = self.ffmpeg_path.as_ref()?;
        let output = Command::new(ffmpeg_path).arg("-version").output().ok()?;
        let version_str = String::from_utf8_lossy(&output.stdout);
        version_str.lines().next().map(|s| s.to_string())
    }

    pub fn local_assets_dir(&self) -> &Path {
        &self.local_assets_dir
    }

    pub fn install_dir(&self) -> &Path {
        &self.install_dir
    }
}

fn find_system_ffmpeg() -> Option<String> {
    #[cfg(target_os = "windows")]
    let paths = [
        "ffmpeg",
        "ffmpeg.exe",
        r".\assets\ffmpeg.exe",
        r"C:\ffmpeg\bin\ffmpeg.exe",
        r"C:\Program Files\ffmpeg\bin\ffmpeg.exe",
    ];

    #[cfg(not(target_os = "windows"))]
    let paths = [
        "ffmpeg",
        "./assets/ffmpeg",
        "/usr/bin/ffmpeg",
        "/usr/local/bin/ffmpeg",
        "/opt/ffmpeg/bin/ffmpeg",
        "/snap/bin/ffmpeg",
    ];

    for path in paths {
        if let Ok(status) = Command::new(path)
            .arg("-version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
        {
            if status.success() {
                return Some(path.to_string());
            }
        }
    }

    None
}

fn find_system_ffprobe() -> Option<String> {
    #[cfg(target_os = "windows")]
    let paths = [
        "ffprobe",
        "ffprobe.exe",
        r".\assets\ffprobe.exe",
        r"C:\ffmpeg\bin\ffprobe.exe",
        r"C:\Program Files\ffmpeg\bin\ffprobe.exe",
    ];

    #[cfg(not(target_os = "windows"))]
    let paths = [
        "ffprobe",
        "./assets/ffprobe",
        "/usr/bin/ffprobe",
        "/usr/local/bin/ffprobe",
        "/opt/ffmpeg/bin/ffprobe",
        "/snap/bin/ffprobe",
    ];

    for path in paths {
        if let Ok(status) = Command::new(path)
            .arg("-version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
        {
            if status.success() {
                return Some(path.to_string());
            }
        }
    }

    None
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(path) {
            return metadata.permissions().mode() & 0o111 != 0;
        }
        false
    }

    #[cfg(not(unix))]
    {
        path.exists()
    }
}

pub fn set_global_ffmpeg_path(path: Option<String>) {
    let _ = GLOBAL_FFMPEG_PATH.set(path);
}

pub fn set_global_ffprobe_path(path: Option<String>) {
    let _ = GLOBAL_FFPROBE_PATH.set(path);
}

pub fn get_global_ffmpeg_path() -> Option<String> {
    GLOBAL_FFMPEG_PATH.get().and_then(|p| p.clone())
}

pub fn get_global_ffprobe_path() -> Option<String> {
    GLOBAL_FFPROBE_PATH.get().and_then(|p| p.clone())
}

// ============================================================================
// 测试模块
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_architecture_detect() {
        let arch = Architecture::detect();
        assert_ne!(arch, Architecture::Unknown);
    }

    #[test]
    fn test_architecture_as_str() {
        assert_eq!(Architecture::X86_64.as_str(), "x86_64");
        assert_eq!(Architecture::Aarch64.as_str(), "aarch64");
        assert_eq!(Architecture::Armhf.as_str(), "armhf");
        assert_eq!(Architecture::Unknown.as_str(), "unknown");
    }

    #[test]
    fn test_architecture_download_slug() {
        assert_eq!(Architecture::X86_64.download_slug(), "amd64");
        assert_eq!(Architecture::Aarch64.download_slug(), "arm64");
        assert_eq!(Architecture::Armhf.download_slug(), "armhf");
        assert_eq!(Architecture::Unknown.download_slug(), "unknown");
    }

    #[test]
    fn test_ffmpeg_manager_new() {
        let manager = FfmpegManager::new("/tmp/test");
        assert!(!manager.is_available());
        assert!(manager.ffmpeg_path().is_none());
        assert!(manager.ffprobe_path().is_none());
    }

    #[test]
    fn test_ffmpeg_manager_with_assets_path() {
        let manager = FfmpegManager::with_assets_path("/tmp/test", "/custom/assets");
        assert_eq!(manager.local_assets_dir(), Path::new("/custom/assets"));
    }
}
