#![allow(dead_code)]

use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::env;
use sysinfo::Disks;

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::Command;

use rockzero_common::AppError;

use crate::storage_manager::{load_windows_storage_binding, windows_storage_binding_path};

#[derive(Debug, Serialize)]
pub struct DiskPlatformCapabilities {
    pub platform: String,
    pub architecture: String,
    pub environment_profile: String,
    pub environment_label: String,
    pub device_model: Option<String>,
    pub supports_disk_listing: bool,
    pub supports_disk_details: bool,
    pub supports_disk_scan: bool,
    pub supports_mount: bool,
    pub supports_unmount: bool,
    pub supports_format: bool,
    pub supports_initialize: bool,
    pub supports_rename: bool,
    pub supports_health: bool,
    pub supports_eject: bool,
    pub supports_file_operations: bool,
    pub read_write_only_mode: bool,
    pub scoped_storage_required: bool,
    pub scoped_storage_configured: bool,
    pub selected_root: Option<String>,
    pub config_path: Option<String>,
    pub restriction_message: Option<String>,
}

#[derive(Debug)]
struct EnvironmentDescriptor {
    profile: String,
    label: String,
    device_model: Option<String>,
}

fn current_platform_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        std::env::consts::OS
    }
}

fn current_architecture_name() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "x86" | "i686" | "i586" => "x86",
        "aarch64" => "arm64",
        "arm" | "armv7" => "arm",
        other => other,
    }
}

fn detect_environment_descriptor() -> EnvironmentDescriptor {
    let platform = current_platform_name();
    let arch = current_architecture_name();

    if let Ok(override_profile) = env::var("ROCKZERO_PLATFORM_PROFILE") {
        let override_profile = override_profile.trim();
        if !override_profile.is_empty() {
            return EnvironmentDescriptor {
                profile: override_profile.to_string(),
                label: format!("{} {} backend", platform.to_uppercase(), arch.to_uppercase()),
                device_model: detect_device_model(),
            };
        }
    }

    let device_model = detect_device_model();
    let profile = match (platform, arch) {
        ("windows", "arm64") => "windows-arm64",
        ("windows", "x86") | ("windows", "x86_64") => "windows-x86",
        ("linux", "arm") | ("linux", "arm64") if is_oes_device(device_model.as_deref()) => {
            "linux-arm-oes"
        }
        ("linux", "arm") | ("linux", "arm64") => "linux-arm",
        ("linux", "x86") | ("linux", "x86_64") => "linux-x86",
        ("macos", "arm64") => "macos-arm64",
        ("macos", _) => "macos-x86",
        _ => "generic",
    }
    .to_string();

    let label = match profile.as_str() {
        "linux-arm-oes" => format!(
            "OES Linux ARM backend{}",
            device_model
                .as_deref()
                .map(|model| format!(" ({model})"))
                .unwrap_or_default()
        ),
        "linux-arm" => format!(
            "Linux ARM backend{}",
            device_model
                .as_deref()
                .map(|model| format!(" ({model})"))
                .unwrap_or_default()
        ),
        "linux-x86" => format!("Linux {} backend", arch.to_uppercase()),
        "windows-arm64" => "Windows ARM64 backend".to_string(),
        "windows-x86" => format!("Windows {} backend", arch.to_uppercase()),
        "macos-arm64" => "macOS ARM64 backend".to_string(),
        "macos-x86" => "macOS x86 backend".to_string(),
        _ => format!("{} {} backend", platform.to_uppercase(), arch.to_uppercase()),
    };

    EnvironmentDescriptor {
        profile,
        label,
        device_model,
    }
}

fn is_oes_device(device_model: Option<&str>) -> bool {
    let Some(device_model) = device_model else {
        return false;
    };

    let normalized = device_model.to_ascii_lowercase();
    normalized.contains("oes")
        || normalized.contains("a311d")
        || normalized.contains("amlogic")
        || normalized.contains("meson-g12b")
}

#[cfg(target_os = "linux")]
fn detect_device_model() -> Option<String> {
    let candidates = [
        "/proc/device-tree/model",
        "/sys/firmware/devicetree/base/model",
        "/sys/devices/virtual/dmi/id/product_name",
    ];

    for candidate in candidates {
        let path = Path::new(candidate);
        if !path.exists() {
            continue;
        }

        if let Ok(raw) = fs::read(path) {
            let value = String::from_utf8_lossy(&raw)
                .replace('\0', "")
                .trim()
                .to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }

    if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
        for key in ["Model", "Hardware", "Processor"] {
            if let Some(value) = cpuinfo.lines().find_map(|line| {
                let (left, right) = line.split_once(':')?;
                if left.trim().eq_ignore_ascii_case(key) {
                    Some(right.trim().to_string())
                } else {
                    None
                }
            }) {
                if !value.is_empty() {
                    return Some(value);
                }
            }
        }
    }

    None
}

#[cfg(not(target_os = "linux"))]
fn detect_device_model() -> Option<String> {
    None
}

pub async fn get_disk_capabilities() -> Result<HttpResponse, AppError> {
    let is_linux = cfg!(target_os = "linux");
    let read_write_only_mode = !is_linux;
    let environment = detect_environment_descriptor();
    let windows_binding = if cfg!(target_os = "windows") {
        Some(load_windows_storage_binding().map_err(|e| {
            AppError::InternalServerError(format!(
                "Failed to read Windows storage root configuration: {e}"
            ))
        })?)
    } else {
        None
    };
    let selected_root = windows_binding
        .as_ref()
        .and_then(|binding| binding.as_ref())
        .map(|binding| binding.selected_root.to_string_lossy().to_string());
    let scoped_storage_required = cfg!(target_os = "windows");
    let scoped_storage_configured = !scoped_storage_required || selected_root.is_some();

    Ok(HttpResponse::Ok().json(DiskPlatformCapabilities {
        platform: current_platform_name().to_string(),
        architecture: current_architecture_name().to_string(),
        environment_profile: environment.profile,
        environment_label: environment.label,
        device_model: environment.device_model,
        supports_disk_listing: true,
        supports_disk_details: true,
        supports_disk_scan: is_linux,
        supports_mount: is_linux,
        supports_unmount: is_linux,
        supports_format: is_linux,
        supports_initialize: is_linux,
        supports_rename: is_linux,
        supports_health: is_linux,
        supports_eject: is_linux,
        supports_file_operations: true,
        read_write_only_mode,
        scoped_storage_required,
        scoped_storage_configured,
        selected_root: selected_root.clone(),
        config_path: scoped_storage_required
            .then(|| windows_storage_binding_path().to_string_lossy().to_string()),
        restriction_message: read_write_only_mode.then(|| {
            if scoped_storage_required {
                match selected_root {
                    Some(root) => format!(
                        "This Windows backend runs in scoped read/write mode. Disk status is available, but initialize, format, mount, unmount, rename, SMART, and eject operations are disabled. File access is constrained to the bound root: {root}."
                    ),
                    None => "This Windows backend runs in scoped read/write mode. Disk status is available, but initialize, format, mount, unmount, rename, SMART, and eject operations are disabled. Select one Windows storage root before file browsing is enabled.".to_string(),
                }
            } else {
                "This backend is running in read/write-only storage mode. Disk status is available, but initialize, format, mount, unmount, rename, SMART, and eject operations are disabled on this platform.".to_string()
            }
        }),
    }))
}

#[cfg(target_os = "linux")]
pub fn auto_mount_all_disks() {
    log::info!("Starting auto-mount for all disks...");

    let output = Command::new("lsblk")
        .args(["-J", "-o", "NAME,TYPE,MOUNTPOINT,FSTYPE,SIZE,UUID"])
        .output();

    let Ok(output) = output else {
        log::warn!("Failed to run lsblk for auto-mount");
        return;
    };
    
    if !output.status.success() {
        log::warn!("lsblk failed: {}", String::from_utf8_lossy(&output.stderr));
        return;
    }
    
    let lsblk_json = String::from_utf8_lossy(&output.stdout);
    let lsblk: serde_json::Value = match serde_json::from_str(&lsblk_json) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("Failed to parse lsblk output: {}", e);
            return;
        }
    };
    
    let Some(blockdevices) = lsblk.get("blockdevices").and_then(|v| v.as_array()) else {
        log::warn!("No block devices found");
        return;
    };

    let mount_base = std::env::var("MOUNT_BASE").unwrap_or_else(|_| "/mnt".to_string());
    let mut mounted_count = 0;

    for device in blockdevices {
        let children = device.get("children").and_then(|c| c.as_array());

        let devices_to_check: Vec<&serde_json::Value> = if let Some(children) = children {
            children.iter().collect()
        } else {
            vec![device]
        };

        for dev in devices_to_check {
            let name = dev.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let dev_type = dev.get("type").and_then(|t| t.as_str()).unwrap_or("");
            let mountpoint = dev.get("mountpoint").and_then(|m| m.as_str());
            let fstype = dev.get("fstype").and_then(|f| f.as_str());

            if dev_type != "part" && dev_type != "disk" {
                continue;
            }

            if mountpoint.is_some() && !mountpoint.unwrap().is_empty() {
                continue;
            }

            let Some(fstype) = fstype else {
                continue;
            };
            if fstype.is_empty() {
                continue;
            }

            if fstype == "swap" || fstype == "vfat" && name.contains("boot") {
                continue;
            }

            let device_path = format!("/dev/{}", name);
            let mount_point = format!("{}/{}", mount_base, name);

            if let Err(e) = std::fs::create_dir_all(&mount_point) {
                log::warn!("Failed to create mount point {}: {}", mount_point, e);
                continue;
            }

            let mount_result = Command::new("mount")
                .arg(&device_path)
                .arg(&mount_point)
                .output();

            match mount_result {
                Ok(output) => {
                    if output.status.success() {
                        log::info!("Auto-mounted {} to {}", device_path, mount_point);
                        mounted_count += 1;

                        let _ = Command::new("chmod")
                            .args(["755", &mount_point])
                            .output();
                    } else {
                        let error = String::from_utf8_lossy(&output.stderr);
                        log::debug!("Failed to mount {}: {}", device_path, error.trim());
                    }
                }
                Err(e) => {
                    log::warn!("Failed to execute mount for {}: {}", device_path, e);
                }
            }
        }
    }
    
    log::info!("Auto-mount completed: {} disks mounted", mounted_count);
}

#[cfg(not(target_os = "linux"))]
pub fn auto_mount_all_disks() {
    log::info!("Auto-mount not supported on this platform");
}

#[cfg(target_os = "linux")]
fn auto_mount_after_format(partition_device: &str, mount_point: &str) -> Result<(), String> {
    std::fs::create_dir_all(mount_point)
        .map_err(|e| format!("Failed to create mount point {}: {}", mount_point, e))?;

    let output = Command::new("mount")
        .arg(partition_device)
        .arg(mount_point)
        .output()
        .map_err(|e| format!("Failed to execute mount: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Mount failed: {}", stderr.trim()));
    }

    let _ = Command::new("chmod").args(["755", mount_point]).output();

    if let Ok(fstab) = std::fs::read_to_string("/etc/fstab") {
        if !fstab.contains(partition_device) {
            let uuid = Command::new("blkid")
                .args(["-s", "UUID", "-o", "value", partition_device])
                .output()
                .ok()
                .and_then(|o| {
                    if o.status.success() {
                        Some(
                            String::from_utf8_lossy(&o.stdout)
                                .trim()
                                .to_string(),
                        )
                    } else {
                        None
                    }
                });

            let fstype = Command::new("blkid")
                .args(["-s", "TYPE", "-o", "value", partition_device])
                .output()
                .ok()
                .and_then(|o| {
                    if o.status.success() {
                        Some(
                            String::from_utf8_lossy(&o.stdout)
                                .trim()
                                .to_string(),
                        )
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| "auto".to_string());

            if let Some(uuid) = uuid {
                let fstab_entry = format!(
                    "\n# Auto-added by RockZeroOS after disk initialization\nUUID={}  {}  {}  defaults,nofail  0  2\n",
                    uuid, mount_point, fstype
                );
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .append(true)
                    .open("/etc/fstab")
                {
                    use std::io::Write;
                    let _ = file.write_all(fstab_entry.as_bytes());
                    log::info!(
                        "Added fstab entry: UUID={} -> {}",
                        uuid,
                        mount_point
                    );
                }
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn auto_format_and_mount_uninitialized_disks() {
    log::info!("Scanning for uninitialized disks...");

    let output = Command::new("lsblk")
        .args(["-J", "-d", "-o", "NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,TRAN,RO"])
        .output();

    let Ok(output) = output else {
        log::warn!("Failed to run lsblk for uninitialized disk scan");
        return;
    };

    if !output.status.success() {
        return;
    }

    let lsblk: serde_json::Value = match serde_json::from_str(
        &String::from_utf8_lossy(&output.stdout),
    ) {
        Ok(v) => v,
        Err(_) => return,
    };

    let Some(devices) = lsblk.get("blockdevices").and_then(|v| v.as_array()) else {
        return;
    };

    let mount_base = std::env::var("MOUNT_BASE").unwrap_or_else(|_| "/mnt".to_string());
    let mut formatted_count = 0;

    for device in devices {
        let name = device.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let dev_type = device.get("type").and_then(|t| t.as_str()).unwrap_or("");
        let fstype = device.get("fstype").and_then(|f| f.as_str());
        let mountpoint = device.get("mountpoint").and_then(|m| m.as_str());
        let ro = device
            .get("ro")
            .and_then(|r| r.as_bool())
            .unwrap_or(false);
        let size_str = device.get("size").and_then(|s| s.as_str()).unwrap_or("0");

        if dev_type != "disk" {
            continue;
        }

        if ro {
            continue;
        }

        if name.starts_with("mmcblk0") || name.starts_with("mmcblk1") {
            continue;
        }

        if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("zram") {
            continue;
        }

        if fstype.is_some_and(|f| !f.is_empty()) {
            continue;
        }
        if mountpoint.is_some_and(|m| !m.is_empty()) {
            continue;
        }

        let size_bytes = parse_size_string(size_str);
        if size_bytes < 1024 * 1024 * 1024 {
            log::debug!("Skipping small disk {} ({})", name, size_str);
            continue;
        }

        let part_check = Command::new("lsblk")
            .args(["-n", "-o", "TYPE", &format!("/dev/{}", name)])
            .output();

        if let Ok(output) = part_check {
            let types = String::from_utf8_lossy(&output.stdout);
            let has_partitions = types.lines().any(|l| l.trim() == "part");
            if has_partitions {
                continue;
            }
        }

        let device_path = format!("/dev/{}", name);
        let mount_point = format!("{}/{}", mount_base, name);

        log::info!(
            "Found uninitialized disk: {} ({}), auto-formatting with GPT + ext4...",
            device_path,
            size_str
        );

        let parted_result = Command::new("parted")
            .args(["-s", "-a", "optimal", &device_path, "mklabel", "gpt"])
            .output();

        if !parted_result.as_ref().map_or(false, |o| o.status.success()) {
            log::warn!("Failed to create GPT partition table on {}", device_path);
            continue;
        }

        let mkpart_result = Command::new("parted")
            .args([
                "-s",
                "-a",
                "optimal",
                &device_path,
                "mkpart",
                "primary",
                "1MiB",
                "100%",
            ])
            .output();

        if !mkpart_result.as_ref().map_or(false, |o| o.status.success()) {
            log::warn!("Failed to create partition on {}", device_path);
            continue;
        }

        let _ = Command::new("partprobe").arg(&device_path).output();
        std::thread::sleep(std::time::Duration::from_secs(2));

        let partition_device = if device_path.contains("nvme") || device_path.contains("mmcblk") {
            format!("{}p1", device_path)
        } else {
            format!("{}1", device_path)
        };

        let mut found = false;
        for _ in 0..10 {
            if std::path::Path::new(&partition_device).exists() {
                found = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        if !found {
            log::warn!("Partition {} did not appear", partition_device);
            continue;
        }

        let label = format!("rz-{}", name);
        let mkfs_result = Command::new("mkfs.ext4")
            .args(["-F", "-m", "1", "-L", &label, &partition_device])
            .output();

        if !mkfs_result.as_ref().map_or(false, |o| o.status.success()) {
            log::warn!("Failed to format {} as ext4", partition_device);
            continue;
        }

        match auto_mount_after_format(&partition_device, &mount_point) {
            Ok(()) => {
                log::info!(
                    "Auto-formatted and mounted {} -> {} (ext4, label: {})",
                    partition_device,
                    mount_point,
                    label
                );
                formatted_count += 1;
            }
            Err(e) => {
                log::warn!("Auto-mount failed for {}: {}", partition_device, e);
            }
        }
    }

    if formatted_count > 0 {
        log::info!(
            "Auto-format completed: {} disks formatted and mounted",
            formatted_count
        );
    } else {
        log::info!("No uninitialized disks found");
    }
}

#[cfg(target_os = "linux")]
fn parse_size_string(size: &str) -> u64 {
    let s = size.trim().to_uppercase();
    let (num_str, multiplier) = if s.ends_with('T') {
        (&s[..s.len() - 1], 1024u64 * 1024 * 1024 * 1024)
    } else if s.ends_with('G') {
        (&s[..s.len() - 1], 1024u64 * 1024 * 1024)
    } else if s.ends_with('M') {
        (&s[..s.len() - 1], 1024u64 * 1024)
    } else if s.ends_with('K') {
        (&s[..s.len() - 1], 1024u64)
    } else {
        (s.as_str(), 1u64)
    };

    num_str
        .parse::<f64>()
        .map(|n| (n * multiplier as f64) as u64)
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
pub fn auto_format_and_mount_uninitialized_disks() {
    log::info!("Auto-format not supported on this platform");
}

#[allow(dead_code)]
pub const SUPPORTED_FILESYSTEMS: &[&str] = &[
    "ext4", "ext3", "ext2", "xfs", "btrfs", "f2fs", "fat32", "exfat", "ntfs",
];

#[derive(Debug, Serialize)]
pub struct DiskDetail {
    pub name: String,
    pub device_path: String,
    pub mount_point: String,
    pub file_system: String,
    pub total_space: u64,
    pub available_space: u64,
    pub used_space: u64,
    pub usage_percentage: f64,
    pub is_removable: bool,
    pub disk_type: String,
    pub is_mounted: bool,
    pub read_only: bool,
    pub label: Option<String>,
    pub uuid: Option<String>,
    pub serial: Option<String>,
    pub model: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PartitionInfo {
    pub device: String,
    pub size: u64,
    pub partition_type: String,
    pub file_system: Option<String>,
    pub mount_point: Option<String>,
    pub label: Option<String>,
    pub uuid: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DiskHealthInfo {
    pub device: String,
    pub healthy: bool,
    pub temperature: Option<f64>,
    pub power_on_hours: Option<u64>,
    pub reallocated_sectors: Option<u64>,
    pub pending_sectors: Option<u64>,
    pub details: String,
    pub smart_status: String,
}

#[derive(Debug, Serialize)]
pub struct DiskIOStats {
    pub device: String,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_ops: u64,
    pub write_ops: u64,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct MountRequest {
    pub device: String,
    pub mount_point: String,
    pub file_system: Option<String>,
    pub options: Option<Vec<String>>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct UnmountRequest {
    pub device: String,
    pub force: Option<bool>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct FormatRequest {
    pub device: String,
    pub file_system: String,
    pub label: Option<String>,
    #[allow(dead_code)]
    pub quick: Option<bool>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct InitializeDiskRequest {
    pub device: String,
    pub file_system: String,
    pub label: Option<String>,
    pub partition_table: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct RenameDiskRequest {
    pub device: String,
    pub new_label: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct ResizePartitionRequest {
    pub device: String,
    pub new_size: String,
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct DiskOperationResult {
    pub success: bool,
    pub message: String,
    pub device: String,
    pub operation: String,
}

pub async fn list_disks() -> Result<HttpResponse, AppError> {
    let disks = tokio::task::spawn_blocking(move || -> Vec<DiskDetail> {
    let disks_info = Disks::new_with_refreshed_list();
    let mut disks = Vec::new();

    for disk in disks_info.list() {
        let device_path = disk.name().to_string_lossy().to_string();
        let mount_point = disk.mount_point().to_string_lossy().to_string();
        
        if device_path.contains("zram") || 
           device_path.contains("log2ram") ||
           mount_point.contains("log2ram") ||
           device_path.contains("loop") ||
           (device_path.contains("ram") && !device_path.contains("nvram")) {
            continue;
        }
        
        #[cfg(target_os = "linux")]
        let (total_space, available_space, used_space, usage_percentage) = {
            use std::mem::MaybeUninit;
            let mut stat_result: Option<(u64, u64, u64, f64)> = None;
            
            if !mount_point.is_empty() {
                if let Ok(path_cstr) = std::ffi::CString::new(mount_point.as_bytes()) {
                    let mut stat: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();
                    unsafe {
                        if libc::statvfs(path_cstr.as_ptr(), stat.as_mut_ptr()) == 0 {
                            let stat = stat.assume_init();
                            let block_size = stat.f_frsize as u64;
                            let total_blocks = stat.f_blocks as u64;
                            let free_blocks = stat.f_bfree as u64;
                            let avail_blocks = stat.f_bavail as u64;
                            
                            let raw_total = total_blocks * block_size;
                            let free = free_blocks * block_size;
                            let avail = avail_blocks * block_size;
                            
                            let used = raw_total.saturating_sub(free);
                            let reserved = free.saturating_sub(avail);
                            let user_total = raw_total.saturating_sub(reserved);
                            
                            let pct = if user_total > 0 {
                                (used as f64 / user_total as f64) * 100.0
                            } else {
                                0.0
                            };
                            
                            stat_result = Some((user_total, avail, used, pct));
                        }
                    }
                }
            }
            
            if let Some(result) = stat_result {
                result
            } else {
                let total = disk.total_space();
                let avail = disk.available_space();
                let used = total.saturating_sub(avail);
                let pct = if total > 0 { (used as f64 / total as f64) * 100.0 } else { 0.0 };
                (total, avail, used, pct)
            }
        };
        
        #[cfg(not(target_os = "linux"))]
        let (total_space, available_space, used_space, usage_percentage) = {
            let total = disk.total_space();
            let avail = disk.available_space();
            let used = total.saturating_sub(avail);
            let pct = if total > 0 { (used as f64 / total as f64) * 100.0 } else { 0.0 };
            (total, avail, used, pct)
        };
        
        let is_removable = disk.is_removable();
        let disk_type = format!("{:?}", disk.kind());
        
        let file_system = disk.file_system().to_string_lossy().to_string();
        
        #[cfg(target_os = "linux")]
        let file_system = {
            if let Ok(output) = Command::new("blkid")
                .args(["-s", "TYPE", "-o", "value", &device_path])
                .output()
            {
                if output.status.success() {
                    let fs_from_blkid = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !fs_from_blkid.is_empty() {
                        fs_from_blkid
                    } else {
                        file_system
                    }
                } else {
                    file_system
                }
            } else {
                file_system
            }
        };

        let (label, uuid, serial, model) = get_disk_metadata(&device_path);

        disks.push(DiskDetail {
            name: device_path.clone(),
            device_path,
            mount_point,
            file_system,
            total_space,
            available_space,
            used_space,
            usage_percentage,
            is_removable,
            disk_type,
            is_mounted: true,
            read_only: false,
            label,
            uuid,
            serial,
            model,
        });
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(unmounted) = get_unmounted_disks() {
            for disk in unmounted {
                if disk.device_path.contains("zram") || 
                   disk.device_path.contains("log2ram") ||
                   disk.mount_point.contains("log2ram") ||
                   disk.device_path.contains("loop") ||
                   (disk.device_path.contains("ram") && !disk.device_path.contains("nvram")) {
                    continue;
                }
                if !disks.iter().any(|d| d.device_path == disk.device_path) {
                    disks.push(disk);
                }
            }
        }
    }

    disks
    }).await.map_err(|_| AppError::InternalError)?;

    Ok(HttpResponse::Ok().json(disks))
}

#[cfg(target_os = "linux")]
fn get_unmounted_disks() -> Result<Vec<DiskDetail>, std::io::Error> {
    let output = Command::new("lsblk")
        .args([
            "-J",
            "-o",
            "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,LABEL,UUID,MODEL,SERIAL,RM,RO",
        ])
        .output()?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let json_str = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap_or_default();

    let mut disks = Vec::new();

    if let Some(blockdevices) = parsed.get("blockdevices").and_then(|v| v.as_array()) {
        for device in blockdevices {
            let device_type = device.get("type").and_then(|v| v.as_str()).unwrap_or("");

            if device_type != "disk" {
                continue;
            }

            let device_name = device.get("name").and_then(|v| v.as_str()).unwrap_or("");

            if device_name.starts_with("mmcblk") || device_name.starts_with("loop") {
                continue;
            }

            let disk_type = detect_disk_type(device_name);

            let has_children = device
                .get("children")
                .and_then(|v| v.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false);
            let fs_type = device
                .get("fstype")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let mount_point = device
                .get("mountpoint")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if !has_children && fs_type.is_empty() && mount_point.is_empty() {
                let name = device_name.to_string();
                let device_path = format!("/dev/{}", name);
                let label = device
                    .get("label")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let uuid = device
                    .get("uuid")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let model = device
                    .get("model")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let serial = device
                    .get("serial")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let is_removable = device
                    .get("rm")
                    .and_then(|v| v.as_bool())
                    .or_else(|| {
                        device
                            .get("rm")
                            .and_then(|v| v.as_str())
                            .map(|s| s == "1" || s == "true")
                    })
                    .unwrap_or(false);
                let read_only = device
                    .get("ro")
                    .and_then(|v| v.as_bool())
                    .or_else(|| {
                        device
                            .get("ro")
                            .and_then(|v| v.as_str())
                            .map(|s| s == "1" || s == "true")
                    })
                    .unwrap_or(false);

                let size_str = device.get("size").and_then(|v| v.as_str()).unwrap_or("0");
                let total_space = parse_size_string(size_str);

                disks.push(DiskDetail {
                    name: name.clone(),
                    device_path,
                    mount_point: String::new(),
                    file_system: String::new(),
                    total_space,
                    available_space: total_space,
                    used_space: 0,
                    usage_percentage: 0.0,
                    is_removable,
                    disk_type: disk_type.clone(),
                    is_mounted: false,
                    read_only,
                    label,
                    uuid,
                    serial,
                    model,
                });
            }

            if let Some(children) = device.get("children").and_then(|v| v.as_array()) {
                for child in children {
                    let child_mount = child
                        .get("mountpoint")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    if child_mount.is_empty() {
                        let name = child
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let device_path = format!("/dev/{}", name);
                        
                        let mut fs_type = child
                            .get("fstype")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        
                        if fs_type.is_empty() {
                            if let Ok(output) = Command::new("blkid")
                                .args(["-s", "TYPE", "-o", "value", &device_path])
                                .output()
                            {
                                if output.status.success() {
                                    let fs_from_blkid = String::from_utf8_lossy(&output.stdout).trim().to_string();
                                    if !fs_from_blkid.is_empty() {
                                        fs_type = fs_from_blkid;
                                    }
                                }
                            }
                        }
                        
                        let label = child
                            .get("label")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let uuid = child
                            .get("uuid")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let model = child
                            .get("model")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let serial = child
                            .get("serial")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let is_removable = child
                            .get("rm")
                            .and_then(|v| v.as_bool())
                            .or_else(|| {
                                child
                                    .get("rm")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s == "1" || s == "true")
                            })
                            .unwrap_or(false);
                        let read_only = child
                            .get("ro")
                            .and_then(|v| v.as_bool())
                            .or_else(|| {
                                child
                                    .get("ro")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s == "1" || s == "true")
                            })
                            .unwrap_or(false);

                        let size_str = child.get("size").and_then(|v| v.as_str()).unwrap_or("0");
                        let total_space = parse_size_string(size_str);

                        let partition_disk_type = format!("{} 鍒嗗尯", disk_type);

                        disks.push(DiskDetail {
                            name: name.clone(),
                            device_path,
                            mount_point: String::new(),
                            file_system: fs_type,
                            total_space,
                            available_space: total_space,
                            used_space: 0,
                            usage_percentage: 0.0,
                            is_removable,
                            disk_type: partition_disk_type,
                            is_mounted: false,
                            read_only,
                            label,
                            uuid,
                            serial,
                            model,
                        });
                    }
                }
            }
        }
    }

    Ok(disks)
}

#[allow(unused_variables)]
fn get_disk_metadata(
    device_path: &str,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    #[cfg(target_os = "linux")]
    {
        let label = Command::new("blkid")
            .args(["-s", "LABEL", "-o", "value", device_path])
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                } else {
                    None
                }
            })
            .filter(|s| !s.is_empty());

        let uuid = Command::new("blkid")
            .args(["-s", "UUID", "-o", "value", device_path])
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                } else {
                    None
                }
            })
            .filter(|s| !s.is_empty());

        return (label, uuid, None, None);
    }

    #[cfg(not(target_os = "linux"))]
    {
        (None, None, None, None)
    }
}

pub async fn list_partitions() -> Result<impl Responder, AppError> {
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("lsblk")
            .args(["-J", "-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,LABEL,UUID"])
            .output()
            .map_err(|_| AppError::InternalError)?;

        if output.status.success() {
            let json_str = String::from_utf8_lossy(&output.stdout);
            return Ok(HttpResponse::Ok().body(json_str.to_string()));
        }
    }

    Ok(HttpResponse::Ok().json(Vec::<PartitionInfo>::new()))
}

pub async fn get_disk_io_stats() -> Result<impl Responder, AppError> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = tokio::fs::read_to_string("/proc/diskstats").await {
            let mut stats = Vec::new();
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 14 {
                    let device = parts[2].to_string();
                    if device.starts_with("sd")
                        || device.starts_with("nvme")
                        || device.starts_with("vd")
                    {
                        stats.push(DiskIOStats {
                            device,
                            read_ops: parts[3].parse().unwrap_or(0),
                            read_bytes: parts[5].parse::<u64>().unwrap_or(0) * 512,
                            write_ops: parts[7].parse().unwrap_or(0),
                            write_bytes: parts[9].parse::<u64>().unwrap_or(0) * 512,
                        });
                    }
                }
            }
            return Ok(HttpResponse::Ok().json(stats));
        }
    }

    Ok(HttpResponse::Ok().json(Vec::<DiskIOStats>::new()))
}

pub async fn mount_disk(body: web::Json<MountRequest>) -> Result<HttpResponse, AppError> {
    #[cfg(target_os = "linux")]
    {
        let device = &body.device;

        if !std::path::Path::new(device).exists() {
            return Err(AppError::BadRequest(format!(
                "Device {} does not exist",
                device
            )));
        }

        let mount_check = Command::new("findmnt")
            .args(["-n", "-o", "TARGET", device])
            .output();
        
        if let Ok(output) = mount_check {
            if output.status.success() {
                let mount_point = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !mount_point.is_empty() {
                    return Ok(HttpResponse::Ok().json(serde_json::json!({
                        "success": true,
                        "message": "Disk is already mounted",
                        "device": device,
                        "mount_point": mount_point,
                        "already_mounted": true,
                    })));
                }
            }
        }

        let device_name = device.split('/').last().unwrap_or("");
        let is_whole_disk = is_whole_disk_device(device_name);

        let actual_device = if is_whole_disk {
            let partition1 = if device.contains("nvme") || device.contains("mmcblk") {
                format!("{}p1", device)
            } else {
                format!("{}1", device)
            };

            if std::path::Path::new(&partition1).exists() {
                partition1
            } else {
                let blkid_output = Command::new("blkid")
                    .args(["-s", "TYPE", "-o", "value", device])
                    .output();

                if let Ok(output) = blkid_output {
                    if output.status.success() {
                        let fs_type = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        if !fs_type.is_empty() {
                            device.clone()
                        } else {
                            return Err(AppError::BadRequest(format!(
                                "Device {} has no partitions and no filesystem. Please initialize the disk first.",
                                device
                            )));
                        }
                    } else {
                        return Err(AppError::BadRequest(format!(
                            "Device {} has no partitions and no filesystem. Please initialize the disk first.",
                            device
                        )));
                    }
                } else {
                    return Err(AppError::BadRequest(format!(
                        "Cannot detect filesystem on {}. Please initialize the disk first.",
                        device
                    )));
                }
            }
        } else {
            let blkid_output = Command::new("blkid")
                .args(["-s", "TYPE", "-o", "value", device])
                .output();

            if let Ok(output) = blkid_output {
                if output.status.success() {
                    let fs_type = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if fs_type.is_empty() {
                        return Err(AppError::BadRequest(format!(
                            "Device {} has no filesystem. Please format the partition first.",
                            device
                        )));
                    }
                } else {
                    return Err(AppError::BadRequest(format!(
                        "Cannot detect filesystem on {}. Please format the partition first.",
                        device
                    )));
                }
            }
            device.clone()
        };

        tokio::fs::create_dir_all(&body.mount_point).await
            .map_err(|e| AppError::BadRequest(format!("Failed to create mount point: {}", e)))?;

        let mut cmd = Command::new("mount");

        if let Some(fs) = &body.file_system {
            if fs != "auto" && !fs.is_empty() {
                cmd.arg("-t").arg(fs);
            }
        }

        if let Some(options) = &body.options {
            if !options.is_empty() {
                cmd.arg("-o").arg(options.join(","));
            }
        }

        cmd.arg(&actual_device).arg(&body.mount_point);

        let output = cmd
            .output()
            .map_err(|e| AppError::BadRequest(format!("Failed to execute mount: {}", e)))?;

        if output.status.success() {
            let _ = Command::new("chmod")
                .args(["755", &body.mount_point])
                .output();
            
            let _ = Command::new("chown")
                .args(["-R", "1000:1000", &body.mount_point])
                .output();

            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Disk mounted successfully",
                "device": actual_device,
                "mount_point": body.mount_point,
            })));
        } else {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(AppError::BadRequest(format!("Mount failed: {}", error)));
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = &body;
        Err(AppError::BadRequest(
            "Mount operation not supported on this platform".to_string(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn is_whole_disk_device(device_name: &str) -> bool {
    if device_name.starts_with("sd") && device_name.len() == 3 {
        return device_name
            .chars()
            .nth(2)
            .map(|c| c.is_alphabetic())
            .unwrap_or(false);
    }
    if device_name.starts_with("vd") && device_name.len() == 3 {
        return device_name
            .chars()
            .nth(2)
            .map(|c| c.is_alphabetic())
            .unwrap_or(false);
    }
    if device_name.starts_with("hd") && device_name.len() == 3 {
        return device_name
            .chars()
            .nth(2)
            .map(|c| c.is_alphabetic())
            .unwrap_or(false);
    }
    if device_name.starts_with("nvme") {
        return !device_name.contains('p')
            || device_name.ends_with("n1")
            || device_name.ends_with("n2");
    }
    if device_name.starts_with("mmcblk") {
        return !device_name.contains('p');
    }
    false
}

#[cfg(target_os = "linux")]
fn detect_disk_type(device_name: &str) -> String {
    if device_name.starts_with("nvme") {
        return "NVMe SSD".to_string();
    }

    let base_device = if device_name
        .chars()
        .last()
        .map(|c| c.is_numeric())
        .unwrap_or(false)
    {
        device_name.trim_end_matches(|c: char| c.is_numeric())
    } else {
        device_name
    };

    let rotational_path = format!("/sys/block/{}/queue/rotational", base_device);
    if let Ok(content) = std::fs::read_to_string(&rotational_path) {
        let rotational = content.trim();
        if rotational == "0" {
            return "SSD".to_string();
        } else if rotational == "1" {
            return "HDD".to_string();
        }
    }

    "HDD".to_string()
}

pub async fn unmount_disk(
    body: web::Json<UnmountRequest>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    #[cfg(target_os = "linux")]
    {
        let mut cmd = Command::new("umount");

        if body.force.unwrap_or(false) {
            cmd.arg("-f");
        }

        cmd.arg(&body.device);

        let output = cmd.output().map_err(|_| AppError::InternalError)?;

        if output.status.success() {
            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Disk unmounted successfully",
                "device": body.device,
            })));
        } else {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(AppError::BadRequest(format!("Unmount failed: {}", error)));
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = &body;
        Err(AppError::BadRequest(
            "Unmount operation not supported on this platform".to_string(),
        ))
    }
}

pub async fn format_disk(
    body: web::Json<FormatRequest>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    #[cfg(target_os = "linux")]
    {
        let device = &body.device;
        
        if !std::path::Path::new(device).exists() {
            return Err(AppError::BadRequest(format!(
                "Device {} does not exist",
                device
            )));
        }

        let mut original_mount_point: Option<String> = None;
        let mount_check = Command::new("findmnt")
            .args(["-n", "-o", "TARGET", device])
            .output();
        
        if let Ok(output) = mount_check {
            if output.status.success() {
                let mount_point = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !mount_point.is_empty() {
                    log::info!("Device {} is mounted at '{}', auto-unmounting...", device, mount_point);
                    original_mount_point = Some(mount_point.clone());
                    
                    let _ = Command::new("fuser")
                        .args(["-km", &mount_point])
                        .output();
                    
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    
                    let unmount_output = Command::new("umount")
                        .arg("-f")
                        .arg(&mount_point)
                        .output();
                    
                    if let Err(e) = unmount_output {
                        return Err(AppError::BadRequest(format!(
                            "Failed to unmount device {} from '{}': {}",
                            device, mount_point, e
                        )));
                    }
                    
                    let unmount_result = unmount_output.unwrap();
                    if !unmount_result.status.success() {
                        let lazy_unmount = Command::new("umount")
                            .arg("-l")
                            .arg(&mount_point)
                            .output();
                        
                        if let Ok(lazy_result) = lazy_unmount {
                            if !lazy_result.status.success() {
                                let error = String::from_utf8_lossy(&lazy_result.stderr);
                                return Err(AppError::BadRequest(format!(
                                    "Failed to unmount device {} from '{}'. Please close all programs using the disk and try again. Error: {}",
                                    device, mount_point, error
                                )));
                            }
                        }
                    }
                    
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    log::info!("Successfully unmounted {} from '{}'", device, mount_point);
                }
            }
        }

        let cmd_name = match body.file_system.to_lowercase().as_str() {
            "ext4" => "mkfs.ext4",
            "ext3" => "mkfs.ext3",
            "ext2" => "mkfs.ext2",
            "fat32" | "vfat" => "mkfs.vfat",
            "ntfs" => "mkfs.ntfs",
            "exfat" => "mkfs.exfat",
            "xfs" => "mkfs.xfs",
            "btrfs" => "mkfs.btrfs",
            "f2fs" => "mkfs.f2fs",
            _ => {
                return Err(AppError::BadRequest(format!(
                    "Unsupported file system: {}",
                    body.file_system
                )))
            }
        };

        let which_check = Command::new("which").arg(cmd_name).output();
        if let Ok(output) = which_check {
            if !output.status.success() {
                return Err(AppError::BadRequest(format!(
                    "Command '{}' not found. Please install the required package (e.g., xfsprogs for XFS)",
                    cmd_name
                )));
            }
        }

        let mut cmd = Command::new(cmd_name);

        if let Some(label) = &body.label {
            if !label.is_empty() {
                match body.file_system.to_lowercase().as_str() {
                    "ext4" | "ext3" | "ext2" => {
                        cmd.arg("-L").arg(label);
                    }
                    "xfs" => {
                        cmd.arg("-L").arg(label);
                    }
                    "btrfs" => {
                        cmd.arg("-L").arg(label);
                    }
                    "ntfs" => {
                        cmd.arg("-L").arg(label);
                    }
                    "vfat" | "fat32" => {
                        cmd.arg("-n").arg(label);
                    }
                    "exfat" => {
                        cmd.arg("-n").arg(label);
                    }
                    "f2fs" => {
                        cmd.arg("-l").arg(label);
                    }
                    _ => {}
                }
            }
        }

        match body.file_system.to_lowercase().as_str() {
            "ext4" | "ext3" | "ext2" => {
                cmd.arg("-F");
            }
            "xfs" => {
                cmd.arg("-f");
            }
            "btrfs" => {
                cmd.arg("-f");
            }
            "ntfs" => {
                cmd.arg("-Q");
                cmd.arg("-F");
            }
            "fat32" | "vfat" => {
                cmd.arg("-F").arg("32");
            }
            "f2fs" => {
                cmd.arg("-f");
            }
            _ => {}
        }

        cmd.arg(device);

        let output = cmd.output().map_err(|e| {
            AppError::BadRequest(format!("Failed to run mkfs command '{}': {}. Make sure the package is installed.", cmd_name, e))
        })?;

        if output.status.success() {
            let _ = Command::new("udevadm")
                .args(["trigger", "--subsystem-match=block"])
                .output();
            
            let _ = Command::new("udevadm")
                .args(["settle", "--timeout=5"])
                .output();
            
            let _ = Command::new("partprobe").arg(device).output();
            
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

            let mut remounted = false;
            if let Some(mount_point) = &original_mount_point {
                log::info!("Re-mounting {} to '{}'...", device, mount_point);
                
                let _ = tokio::fs::create_dir_all(mount_point).await;
                
                let remount_output = Command::new("mount")
                    .arg(device)
                    .arg(mount_point)
                    .output();
                
                if let Ok(result) = remount_output {
                    if result.status.success() {
                        remounted = true;
                        log::info!("Successfully re-mounted {} to '{}'", device, mount_point);
                    } else {
                        let error = String::from_utf8_lossy(&result.stderr);
                        log::warn!("Failed to re-mount {} to '{}': {}", device, mount_point, error);
                    }
                }
            }

            let message = if remounted {
                format!("Disk formatted successfully with {} filesystem and re-mounted", body.file_system)
            } else {
                format!("Disk formatted successfully with {} filesystem", body.file_system)
            };

            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": message,
                "device": device,
                "file_system": body.file_system,
                "remounted": remounted,
                "mount_point": original_mount_point,
            })));
        } else {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(AppError::BadRequest(format!("Format failed: {}", error)));
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = &body;
        Err(AppError::BadRequest(
            "Format operation not supported on this platform".to_string(),
        ))
    }
}

pub async fn check_disk_health(device: web::Path<String>) -> Result<HttpResponse, AppError> {
    let device_path = if device.starts_with("/dev/") {
        device.to_string()
    } else {
        format!("/dev/{}", device.as_str())
    };

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("smartctl")
            .args(["-H", "-A", "-i", &device_path])
            .output();

        if let Ok(output) = output {
            if output.status.success() || output.status.code() == Some(4) {
                let result = String::from_utf8_lossy(&output.stdout);
                let is_healthy = result.contains("PASSED") || !result.contains("FAILED");

                let temperature = parse_smart_attribute(&result, "Temperature");
                let power_on_hours =
                    parse_smart_attribute(&result, "Power_On_Hours").map(|v| v as u64);
                let reallocated_sectors =
                    parse_smart_attribute(&result, "Reallocated_Sector").map(|v| v as u64);
                let pending_sectors =
                    parse_smart_attribute(&result, "Current_Pending_Sector").map(|v| v as u64);

                let smart_status = if is_healthy { "PASSED" } else { "FAILED" };

                return Ok(HttpResponse::Ok().json(DiskHealthInfo {
                    device: device_path,
                    healthy: is_healthy,
                    temperature,
                    power_on_hours,
                    reallocated_sectors,
                    pending_sectors,
                    details: result.to_string(),
                    smart_status: smart_status.to_string(),
                }));
            }
        }

        return Ok(HttpResponse::Ok().json(DiskHealthInfo {
            device: device_path,
            healthy: true,
            temperature: None,
            power_on_hours: None,
            reallocated_sectors: None,
            pending_sectors: None,
            details: "SMART data not available. Install smartmontools for detailed health info."
                .to_string(),
            smart_status: "UNKNOWN".to_string(),
        }));
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(HttpResponse::Ok().json(DiskHealthInfo {
            device: device_path,
            healthy: true,
            temperature: None,
            power_on_hours: None,
            reallocated_sectors: None,
            pending_sectors: None,
            details: "Health check not available on this platform".to_string(),
            smart_status: "UNKNOWN".to_string(),
        }))
    }
}

#[cfg(target_os = "linux")]
fn parse_smart_attribute(output: &str, attr_name: &str) -> Option<f64> {
    for line in output.lines() {
        if line.contains(attr_name) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 10 {
                return parts[9].parse().ok();
            }
        }
    }
    None
}

pub async fn eject_disk(
    device: web::Path<String>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    #[cfg(target_os = "linux")]
    {
        let device_path = if device.starts_with("/dev/") {
            device.to_string()
        } else {
            format!("/dev/{}", device.as_str())
        };

        let _ = Command::new("umount").arg(&device_path).output();

        let output = Command::new("eject")
            .arg(&device_path)
            .output()
            .map_err(|_| AppError::InternalError)?;

        if output.status.success() {
            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Disk ejected successfully",
                "device": device_path,
            })));
        } else {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(AppError::BadRequest(format!("Eject failed: {}", error)));
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = &device;
        Err(AppError::BadRequest(
            "Eject operation not supported on this platform".to_string(),
        ))
    }
}

pub async fn get_supported_filesystems() -> Result<impl Responder, AppError> {
    let filesystems = vec![
        serde_json::json!({
            "name": "ext4",
            "description": "Fourth Extended Filesystem - Default Linux filesystem",
            "supports_label": true,
            "max_file_size": "16 TB",
            "max_volume_size": "1 EB",
            "platforms": ["linux"]
        }),
        serde_json::json!({
            "name": "xfs",
            "description": "XFS - High-performance filesystem",
            "supports_label": true,
            "max_file_size": "8 EB",
            "max_volume_size": "8 EB",
            "platforms": ["linux"]
        }),
        serde_json::json!({
            "name": "btrfs",
            "description": "B-tree Filesystem - Modern copy-on-write filesystem",
            "supports_label": true,
            "max_file_size": "16 EB",
            "max_volume_size": "16 EB",
            "platforms": ["linux"]
        }),
        serde_json::json!({
            "name": "fat32",
            "description": "FAT32 - Universal compatibility",
            "supports_label": true,
            "max_file_size": "4 GB",
            "max_volume_size": "2 TB",
            "platforms": ["linux", "windows", "macos"]
        }),
        serde_json::json!({
            "name": "exfat",
            "description": "exFAT - Extended FAT for large files",
            "supports_label": true,
            "max_file_size": "16 EB",
            "max_volume_size": "128 PB",
            "platforms": ["linux", "windows", "macos"]
        }),
        serde_json::json!({
            "name": "ntfs",
            "description": "NTFS - Windows native filesystem",
            "supports_label": true,
            "max_file_size": "16 EB",
            "max_volume_size": "256 TB",
            "platforms": ["linux", "windows"]
        }),
    ];

    Ok(HttpResponse::Ok().json(filesystems))
}

pub async fn initialize_disk(
    body: web::Json<InitializeDiskRequest>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    #[cfg(target_os = "linux")]
    {
        let device = &body.device;
        let partition_table = body.partition_table.as_deref().unwrap_or("gpt");

        if !device.starts_with("/dev/") {
            return Err(AppError::BadRequest("Invalid device path".to_string()));
        }

        if device.contains("mmcblk0") || device.contains("mmcblk1") {
            return Err(AppError::BadRequest(
                "Cannot initialize system disk".to_string(),
            ));
        }

        if !std::path::Path::new(device).exists() {
            return Err(AppError::BadRequest(format!(
                "Device {} does not exist",
                device
            )));
        }

        let fs_lower = body.file_system.to_lowercase();
        if !SUPPORTED_FILESYSTEMS.contains(&fs_lower.as_str()) {
            return Err(AppError::BadRequest(format!(
                "Unsupported file system: {}. Supported: {:?}",
                body.file_system, SUPPORTED_FILESYSTEMS
            )));
        }

        let lsblk_output = Command::new("lsblk")
            .args(["-n", "-o", "MOUNTPOINT", device])
            .output();

        if let Ok(output) = lsblk_output {
            let mount_points = String::from_utf8_lossy(&output.stdout);
            for line in mount_points.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    return Err(AppError::BadRequest(format!(
                        "Device {} or its partitions are currently mounted at '{}'. Please unmount first before initializing.",
                        device, trimmed
                    )));
                }
            }
        }

        let wipefs_output = Command::new("wipefs")
            .args(["--all", "--force", device])
            .output();

        if let Ok(output) = &wipefs_output {
            if !output.status.success() {
                let _ = Command::new("dd")
                    .args([
                        "if=/dev/zero",
                        &format!("of={}", device),
                        "bs=1M",
                        "count=10",
                        "conv=notrunc",
                    ])
                    .output();
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let parted_label = Command::new("parted")
            .args(["-s", "-a", "optimal", device, "mklabel", partition_table])
            .output()
            .map_err(|e| AppError::BadRequest(format!("Failed to run parted: {}", e)))?;

        if !parted_label.status.success() {
            let error = String::from_utf8_lossy(&parted_label.stderr);
            return Err(AppError::BadRequest(format!(
                "Failed to create partition table: {}",
                error
            )));
        }

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let parted_mkpart = Command::new("parted")
            .args([
                "-s", "-a", "optimal", device, "mkpart", "primary", "1MiB", "100%",
            ])
            .output()
            .map_err(|e| AppError::BadRequest(format!("Failed to create partition: {}", e)))?;

        if !parted_mkpart.status.success() {
            let error = String::from_utf8_lossy(&parted_mkpart.stderr);
            return Err(AppError::BadRequest(format!(
                "Failed to create partition: {}",
                error
            )));
        }

        let _ = Command::new("partprobe").arg(device).output();
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        
        let _ = Command::new("udevadm")
            .args(["settle", "--timeout=10"])
            .output();

        let _ = Command::new("blockdev")
            .args(["--rereadpt", device])
            .output();

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let partition_device = if device.contains("nvme") || device.contains("mmcblk") {
            format!("{}p1", device)
        } else {
            format!("{}1", device)
        };

        let mut partition_exists = false;
        for _ in 0..10 {
            if std::path::Path::new(&partition_device).exists() {
                partition_exists = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let _ = Command::new("partprobe").arg(device).output();
        }

        if !partition_exists {
            return Err(AppError::BadRequest(format!(
                "Partition {} was not created. Please try again.",
                partition_device
            )));
        }

        let mkfs_cmd = match fs_lower.as_str() {
            "ext4" => "mkfs.ext4",
            "ext3" => "mkfs.ext3",
            "ext2" => "mkfs.ext2",
            "xfs" => "mkfs.xfs",
            "btrfs" => "mkfs.btrfs",
            "f2fs" => "mkfs.f2fs",
            "fat32" | "vfat" => "mkfs.vfat",
            "exfat" => "mkfs.exfat",
            "ntfs" => "mkfs.ntfs",
            _ => {
                return Err(AppError::BadRequest(format!(
                    "Unsupported file system: {}",
                    body.file_system
                )))
            }
        };

        let mut format_cmd = Command::new(mkfs_cmd);
        
        if let Some(label) = &body.label {
            if !label.is_empty() {
                match fs_lower.as_str() {
                    "ext4" | "ext3" | "ext2" => {
                        format_cmd.arg("-L").arg(label);
                    }
                    "xfs" | "btrfs" | "ntfs" => {
                        format_cmd.arg("-L").arg(label);
                    }
                    "fat32" | "vfat" | "exfat" => {
                        format_cmd.arg("-n").arg(label);
                    }
                    "f2fs" => {
                        format_cmd.arg("-l").arg(label);
                    }
                    _ => {}
                }
            }
        }

        match fs_lower.as_str() {
            "ext4" => {
                format_cmd.arg("-F");
                format_cmd.arg("-m").arg("1");
                format_cmd.arg("-O").arg("^has_journal");
            }
            "ext3" | "ext2" => {
                format_cmd.arg("-F");
            }
            "xfs" => {
                format_cmd.arg("-f");
                format_cmd.arg("-K");
            }
            "btrfs" => {
                format_cmd.arg("-f");
            }
            "f2fs" => {
                format_cmd.arg("-f");
            }
            "ntfs" => {
                format_cmd.arg("-Q");
                format_cmd.arg("-F");
            }
            "fat32" | "vfat" => {
                format_cmd.arg("-F").arg("32");
                format_cmd.arg("-I");
            }
            "exfat" => {
            }
            _ => {}
        }

        format_cmd.arg(&partition_device);

        let format_output = format_cmd
            .output()
            .map_err(|e| AppError::BadRequest(format!("Failed to run mkfs: {}", e)))?;

        if !format_output.status.success() {
            let error = String::from_utf8_lossy(&format_output.stderr);
            return Err(AppError::BadRequest(format!("Format failed: {}", error)));
        }

        let _ = Command::new("udevadm")
            .args(["trigger", "--subsystem-match=block"])
            .output();
        
        let _ = Command::new("udevadm")
            .args(["settle", "--timeout=10"])
            .output();
        
        let _ = Command::new("partprobe").arg(device).output();
        
        let _ = Command::new("blkid")
            .args(["-p", &partition_device])
            .output();
        
        tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
        
        let verify_output = Command::new("blkid")
            .args(["-s", "TYPE", "-o", "value", &partition_device])
            .output();
        
        let actual_fs = if let Ok(output) = verify_output {
            if output.status.success() {
                String::from_utf8_lossy(&output.stdout).trim().to_string()
            } else {
                "unknown".to_string()
            }
        } else {
            "unknown".to_string()
        };

        let mount_base = std::env::var("MOUNT_BASE").unwrap_or_else(|_| "/mnt".to_string());
        let default_mount_label = partition_device.replace("/dev/", "").replace("/", "_");
        let mount_label = body
            .label
            .clone()
            .unwrap_or(default_mount_label);
        let auto_mount_point = format!("{}/{}", mount_base, mount_label);

        let auto_mount_msg = match auto_mount_after_format(&partition_device, &auto_mount_point) {
            Ok(()) => {
                log::info!(
                    "Auto-mounted {} -> {} after initialization",
                    partition_device,
                    auto_mount_point
                );
                format!(" Mounted at {}", auto_mount_point)
            }
            Err(e) => {
                log::warn!(
                    "Auto-mount failed for {} -> {}: {}",
                    partition_device,
                    auto_mount_point,
                    e
                );
                format!(" (auto-mount failed: {})", e)
            }
        };

        return Ok(HttpResponse::Ok().json(DiskOperationResult {
            success: true,
            message: format!(
                "Disk initialized successfully with {} filesystem on {} (verified: {}).{}",
                body.file_system, partition_device, actual_fs, auto_mount_msg
            ),
            device: partition_device,
            operation: "initialize".to_string(),
        }));
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = &body;
        let _ = &req;
        Err(AppError::BadRequest(
            "Initialize disk operation not supported on this platform".to_string(),
        ))
    }
}

pub async fn rename_disk(
    body: web::Json<RenameDiskRequest>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    #[cfg(target_os = "linux")]
    {
        let device = &body.device;
        let new_label = &body.new_label;

        let blkid_output = Command::new("blkid")
            .args(["-s", "TYPE", "-o", "value", device])
            .output()
            .map_err(|_| AppError::InternalError)?;

        if !blkid_output.status.success() {
            return Err(AppError::BadRequest(
                "Failed to detect filesystem type".to_string(),
            ));
        }

        let fs_type = String::from_utf8_lossy(&blkid_output.stdout)
            .trim()
            .to_lowercase();

        let result = match fs_type.as_str() {
            "ext4" | "ext3" | "ext2" => Command::new("e2label").args([device, new_label]).output(),
            "xfs" => Command::new("xfs_admin")
                .args(["-L", new_label, device])
                .output(),
            "btrfs" => Command::new("btrfs")
                .args(["filesystem", "label", device, new_label])
                .output(),
            "vfat" | "fat32" | "fat16" => {
                Command::new("fatlabel").args([device, new_label]).output()
            }
            "exfat" => Command::new("exfatlabel")
                .args([device, new_label])
                .output(),
            "ntfs" => Command::new("ntfslabel").args([device, new_label]).output(),
            "f2fs" => {
                return Err(AppError::BadRequest(
                    "F2FS label change not supported".to_string(),
                ));
            }
            _ => {
                return Err(AppError::BadRequest(format!(
                    "Unsupported filesystem for label change: {}",
                    fs_type
                )));
            }
        };

        match result {
            Ok(output) if output.status.success() => {
                Ok(HttpResponse::Ok().json(DiskOperationResult {
                    success: true,
                    message: format!("Disk label changed to '{}'", new_label),
                    device: device.clone(),
                    operation: "rename".to_string(),
                }))
            }
            Ok(output) => {
                let error = String::from_utf8_lossy(&output.stderr);
                Err(AppError::BadRequest(format!(
                    "Failed to change label: {}",
                    error
                )))
            }
            Err(e) => Err(AppError::BadRequest(format!(
                "Failed to run label command: {}",
                e
            ))),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = &body;
        Err(AppError::BadRequest(
            "Rename disk operation not supported on this platform".to_string(),
        ))
    }
}

pub async fn get_disk_details(device: web::Path<String>) -> Result<HttpResponse, AppError> {
    let device_path = if device.starts_with("/dev/") {
        device.to_string()
    } else {
        format!("/dev/{}", device.as_str())
    };

    #[cfg(target_os = "linux")]
    {
        let lsblk_output = Command::new("lsblk")
            .args([
                "-J",
                "-o",
                "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,LABEL,UUID,MODEL,SERIAL,RM,RO,TRAN",
                &device_path,
            ])
            .output();

        let mut details = serde_json::json!({
            "device": device_path,
        });

        if let Ok(output) = lsblk_output {
            if output.status.success() {
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                    details["lsblk"] = json;
                }
            }
        }

        let smart_output = Command::new("smartctl")
            .args(["-i", "-H", &device_path])
            .output();

        if let Ok(output) = smart_output {
            if output.status.success() || output.status.code() == Some(4) {
                let smart_text = String::from_utf8_lossy(&output.stdout);
                details["smart_info"] = serde_json::json!({
                    "available": true,
                    "raw_output": smart_text.to_string(),
                });
            } else {
                details["smart_info"] = serde_json::json!({
                    "available": false,
                    "reason": "SMART not supported or smartctl not installed",
                });
            }
        }

        let df_output = Command::new("df").args(["-B1", &device_path]).output();

        if let Ok(output) = df_output {
            if output.status.success() {
                let df_text = String::from_utf8_lossy(&output.stdout);
                let lines: Vec<&str> = df_text.lines().collect();
                if lines.len() >= 2 {
                    let parts: Vec<&str> = lines[1].split_whitespace().collect();
                    if parts.len() >= 6 {
                        details["usage"] = serde_json::json!({
                            "total": parts[1].parse::<u64>().unwrap_or(0),
                            "used": parts[2].parse::<u64>().unwrap_or(0),
                            "available": parts[3].parse::<u64>().unwrap_or(0),
                            "use_percent": parts[4].trim_end_matches('%'),
                            "mount_point": parts[5],
                        });
                    }
                }
            }
        }

        return Ok(HttpResponse::Ok().json(details));
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "device": device_path,
            "error": "Detailed disk info not available on this platform",
        })))
    }
}

pub async fn scan_disks() -> Result<HttpResponse, AppError> {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("partprobe").output();

        let _ = Command::new("udevadm")
            .args(["trigger", "--subsystem-match=block"])
            .output();

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        return list_disks().await;
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(AppError::BadRequest(
            "Disk scan not supported on this platform".to_string(),
        ))
    }
}

pub async fn get_zfs_status() -> Result<HttpResponse, AppError> {
    #[cfg(target_os = "linux")]
    {
        let zfs_check = Command::new("which").arg("zpool").output();

        let zfs_available = zfs_check.map(|o| o.status.success()).unwrap_or(false);

        if !zfs_available {
            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "available": false,
                "message": "ZFS is not installed. Install zfsutils-linux to use ZFS.",
                "pools": [],
            })));
        }

        let zpool_output = Command::new("zpool")
            .args(["list", "-H", "-o", "name,size,alloc,free,health"])
            .output();

        let mut pools = Vec::new();

        if let Ok(output) = zpool_output {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    let parts: Vec<&str> = line.split('\t').collect();
                    if parts.len() >= 5 {
                        pools.push(serde_json::json!({
                            "name": parts[0],
                            "size": parts[1],
                            "allocated": parts[2],
                            "free": parts[3],
                            "health": parts[4],
                        }));
                    }
                }
            }
        }

        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "available": true,
            "pools": pools,
        })));
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "available": false,
            "message": "ZFS is not supported on this platform",
            "pools": [],
        })))
    }
}


#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct ZfsPoolConfig {
    pub name: String,
    pub vdev_type: String,
    pub devices: Vec<String>,
    pub ashift: Option<u8>,
    pub compression: Option<String>,
    pub dedup: Option<bool>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct SmartTestRequest {
    pub test_type: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct WipeDiskRequest {
    pub method: String,
}

#[allow(dead_code)]
pub async fn create_zfs_pool(
    body: web::Json<ZfsPoolConfig>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    #[cfg(target_os = "linux")]
    {
        let zfs_check = Command::new("which").arg("zpool").output();
        if zfs_check.is_err() || !zfs_check.unwrap().status.success() {
            return Err(AppError::BadRequest(
                "ZFS is not installed. Please install zfsutils-linux".to_string()
            ));
        }

        let mut cmd = Command::new("zpool");
        cmd.arg("create");
        
        if let Some(ashift) = body.ashift {
            cmd.arg("-o").arg(format!("ashift={}", ashift));
        }
        
        cmd.arg(&body.name);
        
        match body.vdev_type.as_str() {
            "mirror" => { cmd.arg("mirror"); }
            "raidz1" => { cmd.arg("raidz1"); }
            "raidz2" => { cmd.arg("raidz2"); }
            "raidz3" => { cmd.arg("raidz3"); }
            _ => {}
        }
        
        for device in &body.devices {
            cmd.arg(device);
        }
        
        let output = cmd.output()
            .map_err(|e| AppError::BadRequest(format!("Failed to create ZFS pool: {}", e)))?;
        
        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(AppError::BadRequest(format!("ZFS pool creation failed: {}", error)));
        }
        
        if let Some(compression) = &body.compression {
            let _ = Command::new("zfs")
                .args(["set", &format!("compression={}", compression), &body.name])
                .output();
        }
        
        if let Some(true) = body.dedup {
            let _ = Command::new("zfs")
                .args(["set", "dedup=on", &body.name])
                .output();
        }
        
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": format!("ZFS pool '{}' created successfully", body.name),
            "pool": body.name,
        })))
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        let _ = &body;
        Err(AppError::BadRequest("ZFS is only supported on Linux".to_string()))
    }
}

#[allow(dead_code)]
pub async fn get_zfs_pool_status(
    pool_name: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("zpool")
            .args(["status", "-v", &pool_name])
            .output()
            .map_err(|_| AppError::InternalError)?;
        
        if !output.status.success() {
            return Err(AppError::NotFound(format!("Pool '{}' not found", pool_name)));
        }
        
        let status = String::from_utf8_lossy(&output.stdout).to_string();
        
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "pool": pool_name.as_str(),
            "status": status,
        })))
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        let _ = &pool_name;
        Err(AppError::BadRequest("ZFS is only supported on Linux".to_string()))
    }
}

#[allow(dead_code)]
pub async fn run_smart_test(
    device: web::Path<String>,
    body: web::Json<SmartTestRequest>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    
    #[cfg(target_os = "linux")]
    {
        let test_arg = match body.test_type.as_str() {
            "short" => "short",
            "long" => "long",
            "conveyance" => "conveyance",
            _ => return Err(AppError::BadRequest("Invalid test type".to_string())),
        };
        
        let device_path = if device.starts_with("/dev/") {
            device.to_string()
        } else {
            format!("/dev/{}", device.as_str())
        };
        
        let output = Command::new("smartctl")
            .args(["-t", test_arg, &device_path])
            .output()
            .map_err(|_| AppError::BadRequest("smartctl not found. Please install smartmontools".to_string()))?;
        
        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(AppError::BadRequest(format!("SMART test failed: {}", error)));
        }
        
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": format!("{} SMART test started on {}", test_arg, device),
            "device": device.as_str(),
        })))
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (&device, &body);
        Err(AppError::BadRequest("SMART tests are only supported on Linux".to_string()))
    }
}

#[allow(dead_code)]
pub async fn wipe_disk(
    device: web::Path<String>,
    body: web::Json<WipeDiskRequest>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    
    #[cfg(target_os = "linux")]
    {
        let device_path = format!("/dev/{}", device.as_str());
        
        let mount_check = Command::new("findmnt")
            .args(["-n", "-o", "TARGET", &device_path])
            .output();
        
        if let Ok(output) = mount_check {
            if output.status.success() {
                let mount_point = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !mount_point.is_empty() {
                    return Err(AppError::BadRequest(format!(
                        "Device {} is mounted at '{}'. Please unmount first.",
                        device, mount_point
                    )));
                }
            }
        }
        
        match body.method.as_str() {
            "quick" => {
                let _ = Command::new("dd")
                    .args([
                        "if=/dev/zero",
                        &format!("of={}", device_path),
                        "bs=1M",
                        "count=1",
                        "conv=notrunc",
                    ])
                    .output();
            }
            "full" => {
                let _ = Command::new("dd")
                    .args([
                        "if=/dev/zero",
                        &format!("of={}", device_path),
                        "bs=1M",
                    ])
                    .output();
            }
            "secure" => {
                let output = Command::new("shred")
                    .args([
                        "-v",
                        "-n", "3",
                        "-z",
                        &device_path,
                    ])
                    .output()
                    .map_err(|_| AppError::BadRequest("shred command not found".to_string()))?;
                
                if !output.status.success() {
                    let error = String::from_utf8_lossy(&output.stderr);
                    return Err(AppError::BadRequest(format!("Secure wipe failed: {}", error)));
                }
            }
            _ => return Err(AppError::BadRequest("Invalid wipe method".to_string())),
        }
        
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": format!("Disk {} wiped successfully", device),
            "device": device.as_str(),
        })))
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (&device, &body);
        Err(AppError::BadRequest("Disk wipe is only supported on Linux".to_string()))
    }
}

#[allow(dead_code)]
pub async fn get_disk_temperature(
    device: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    #[cfg(target_os = "linux")]
    {
        let device_path = if device.starts_with("/dev/") {
            device.to_string()
        } else {
            format!("/dev/{}", device.as_str())
        };
        
        let output = Command::new("smartctl")
            .args(["-A", &device_path])
            .output()
            .map_err(|_| AppError::InternalError)?;
        
        if !output.status.success() {
            return Err(AppError::BadRequest("Failed to read SMART data".to_string()));
        }
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut temperature: Option<i32> = None;
        
        for line in output_str.lines() {
            if line.contains("Temperature") || line.contains("Airflow_Temperature") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 10 {
                    if let Ok(temp) = parts[9].parse::<i32>() {
                        temperature = Some(temp);
                        break;
                    }
                }
            }
        }
        
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "device": device.as_str(),
            "temperature_celsius": temperature,
        })))
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        let _ = &device;
        Err(AppError::BadRequest("Temperature reading is only supported on Linux".to_string()))
    }
}
