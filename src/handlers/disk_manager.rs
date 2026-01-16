use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use sysinfo::Disks;

#[cfg(target_os = "linux")]
use std::process::Command;

use crate::error::AppError;

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

/// Request to initialize a new disk (create partition table and format)
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct InitializeDiskRequest {
    pub device: String,
    pub file_system: String,
    pub label: Option<String>,
    /// Partition table type: "gpt" or "msdos" (default: gpt)
    pub partition_table: Option<String>,
}

/// Request to rename a disk label
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct RenameDiskRequest {
    pub device: String,
    pub new_label: String,
}

/// Request to resize a partition
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct ResizePartitionRequest {
    pub device: String,
    /// New size in bytes, or "max" to use all available space
    pub new_size: String,
}

/// Disk operation result
#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct DiskOperationResult {
    pub success: bool,
    pub message: String,
    pub device: String,
    pub operation: String,
}

pub async fn list_disks() -> Result<HttpResponse, AppError> {
    let disks_info = Disks::new_with_refreshed_list();
    let mut disks = Vec::new();

    for disk in disks_info.list() {
        let total_space = disk.total_space();
        let available_space = disk.available_space();
        let used_space = total_space.saturating_sub(available_space);
        let usage_percentage = if total_space > 0 {
            (used_space as f64 / total_space as f64) * 100.0
        } else {
            0.0
        };

        let device_path = disk.name().to_string_lossy().to_string();
        let mount_point = disk.mount_point().to_string_lossy().to_string();
        let is_removable = disk.is_removable();
        let disk_type = format!("{:?}", disk.kind());

        let (label, uuid, serial, model) = get_disk_metadata(&device_path);

        disks.push(DiskDetail {
            name: device_path.clone(),
            device_path,
            mount_point,
            file_system: disk.file_system().to_string_lossy().to_string(),
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
                if !disks.iter().any(|d| d.device_path == disk.device_path) {
                    disks.push(disk);
                }
            }
        }
    }

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

            // Skip non-disk devices (like loop, rom, etc.)
            if device_type != "disk" {
                continue;
            }

            let device_name = device.get("name").and_then(|v| v.as_str()).unwrap_or("");

            // Skip system disks (mmcblk0, mmcblk1 are typically eMMC/SD boot devices)
            if device_name.starts_with("mmcblk") || device_name.starts_with("loop") {
                continue;
            }

            // Detect disk type (SSD/HDD/NVMe)
            let disk_type = detect_disk_type(device_name);

            // Check if this is a raw disk without partitions
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

            // If disk has no partitions and no filesystem, it's a raw unpartitioned disk
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
                    file_system: String::new(), // Empty means unpartitioned/unformatted
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

            // Also check partitions (children) that are unmounted
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
                        let fs_type = child
                            .get("fstype")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
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

                        // 使用父设备的类型
                        let partition_disk_type = format!("{} 分区", disk_type);

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

#[cfg(target_os = "linux")]
fn parse_size_string(size_str: &str) -> u64 {
    let size_str = size_str.trim();
    let (num_str, unit) = if size_str.ends_with('G') {
        (&size_str[..size_str.len() - 1], 1024u64 * 1024 * 1024)
    } else if size_str.ends_with('M') {
        (&size_str[..size_str.len() - 1], 1024u64 * 1024)
    } else if size_str.ends_with('K') {
        (&size_str[..size_str.len() - 1], 1024u64)
    } else if size_str.ends_with('T') {
        (
            &size_str[..size_str.len() - 1],
            1024u64 * 1024 * 1024 * 1024,
        )
    } else {
        (size_str, 1u64)
    };
    num_str.parse::<f64>().unwrap_or(0.0) as u64 * unit
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
        if let Ok(content) = std::fs::read_to_string("/proc/diskstats") {
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

        // 检查设备是否存在
        if !std::path::Path::new(device).exists() {
            return Err(AppError::BadRequest(format!(
                "Device {} does not exist",
                device
            )));
        }

        // 检查设备是否已经挂载
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

        // 检查是否是整盘设备（没有分区号）
        let device_name = device.split('/').last().unwrap_or("");
        let is_whole_disk = is_whole_disk_device(device_name);

        // 如果是整盘设备，尝试找到第一个分区
        let actual_device = if is_whole_disk {
            // 检查是否有分区
            let partition1 = if device.contains("nvme") || device.contains("mmcblk") {
                format!("{}p1", device)
            } else {
                format!("{}1", device)
            };

            if std::path::Path::new(&partition1).exists() {
                partition1
            } else {
                // 没有分区，检查整盘是否有文件系统
                let blkid_output = Command::new("blkid")
                    .args(["-s", "TYPE", "-o", "value", device])
                    .output();

                if let Ok(output) = blkid_output {
                    if output.status.success() {
                        let fs_type = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        if !fs_type.is_empty() {
                            // 整盘有文件系统，可以直接挂载
                            device.clone()
                        } else {
                            return Err(AppError::BadRequest(format!(
                                "Device {} has no partitions and no filesystem. Please initialize the disk first.",
                                device
                            )));
                        }
                    } else {
                        return Err(AppError::BadRequest(format!(
                            "Device {} has no partitions. Please initialize the disk first.",
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
            device.clone()
        };

        // 创建挂载点目录
        std::fs::create_dir_all(&body.mount_point)
            .map_err(|e| AppError::BadRequest(format!("Failed to create mount point: {}", e)))?;

        let mut cmd = Command::new("mount");

        // 如果指定了文件系统类型且不是 "auto"
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

/// 检查是否是整盘设备（而不是分区）
#[cfg(target_os = "linux")]
fn is_whole_disk_device(device_name: &str) -> bool {
    // sd[a-z] 是整盘，sd[a-z][0-9]+ 是分区
    if device_name.starts_with("sd") && device_name.len() == 3 {
        return device_name
            .chars()
            .nth(2)
            .map(|c| c.is_alphabetic())
            .unwrap_or(false);
    }
    // vd[a-z] 是整盘
    if device_name.starts_with("vd") && device_name.len() == 3 {
        return device_name
            .chars()
            .nth(2)
            .map(|c| c.is_alphabetic())
            .unwrap_or(false);
    }
    // hd[a-z] 是整盘
    if device_name.starts_with("hd") && device_name.len() == 3 {
        return device_name
            .chars()
            .nth(2)
            .map(|c| c.is_alphabetic())
            .unwrap_or(false);
    }
    // nvme0n1 是整盘，nvme0n1p1 是分区
    if device_name.starts_with("nvme") {
        return !device_name.contains('p')
            || device_name.ends_with("n1")
            || device_name.ends_with("n2");
    }
    // mmcblk0 是整盘，mmcblk0p1 是分区
    if device_name.starts_with("mmcblk") {
        return !device_name.contains('p');
    }
    false
}

/// 检测磁盘类型 (SSD/HDD/NVMe)
#[cfg(target_os = "linux")]
fn detect_disk_type(device_name: &str) -> String {
    // NVMe 设备
    if device_name.starts_with("nvme") {
        return "NVMe SSD".to_string();
    }

    // 尝试读取 rotational 属性来判断是 SSD 还是 HDD
    // 0 = SSD, 1 = HDD
    let base_device = if device_name
        .chars()
        .last()
        .map(|c| c.is_numeric())
        .unwrap_or(false)
    {
        // 这是分区，获取基础设备名
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

    // 默认返回 HDD
    "HDD".to_string()
}

pub async fn unmount_disk(
    body: web::Json<UnmountRequest>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, AppError> {
    // 验证FIDO2认证
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
    // 验证FIDO2认证 - 格式化是危险操作
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    #[cfg(target_os = "linux")]
    {
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

        let mut cmd = Command::new(cmd_name);

        if let Some(label) = &body.label {
            match body.file_system.to_lowercase().as_str() {
                "ext4" | "ext3" | "ext2" | "ntfs" | "xfs" | "btrfs" => {
                    cmd.arg("-L").arg(label);
                }
                "vfat" | "fat32" | "exfat" => {
                    cmd.arg("-n").arg(label);
                }
                _ => {}
            }
        }

        match body.file_system.to_lowercase().as_str() {
            "ext4" | "ext3" | "ext2" => {
                cmd.arg("-F");
            }
            "xfs" | "btrfs" => {
                cmd.arg("-f");
            }
            _ => {}
        }

        cmd.arg(&body.device);

        let output = cmd.output().map_err(|_| AppError::InternalError)?;

        if output.status.success() {
            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Disk formatted successfully",
                "device": body.device,
                "file_system": body.file_system,
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
    // 验证FIDO2认证
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

        // Validate device path
        if !device.starts_with("/dev/") {
            return Err(AppError::BadRequest("Invalid device path".to_string()));
        }

        // Safety check: don't allow initializing system disks
        if device.contains("mmcblk0") || device.contains("mmcblk1") {
            return Err(AppError::BadRequest(
                "Cannot initialize system disk".to_string(),
            ));
        }

        // Check if device exists
        if !std::path::Path::new(device).exists() {
            return Err(AppError::BadRequest(format!(
                "Device {} does not exist",
                device
            )));
        }

        // Validate file system
        let fs_lower = body.file_system.to_lowercase();
        if !SUPPORTED_FILESYSTEMS.contains(&fs_lower.as_str()) {
            return Err(AppError::BadRequest(format!(
                "Unsupported file system: {}. Supported: {:?}",
                body.file_system, SUPPORTED_FILESYSTEMS
            )));
        }

        // Check if disk or any of its partitions are mounted - refuse if so
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

        // Step 1: Wipe existing partition table signatures
        let wipefs_output = Command::new("wipefs")
            .args(["--all", "--force", device])
            .output();

        if let Ok(output) = &wipefs_output {
            if !output.status.success() {
                // Try alternative: dd to zero out first sectors
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

        std::thread::sleep(std::time::Duration::from_millis(500));

        // Step 2: Create partition table using parted with optimal alignment (4096 sector)
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

        std::thread::sleep(std::time::Duration::from_millis(300));

        // Step 3: Create a single partition using all space with 4096 alignment
        // Start at 1MiB (2048 sectors for 512-byte sectors, aligned to 4096)
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

        // Step 4: Notify kernel about partition table changes
        let _ = Command::new("partprobe").arg(device).output();
        std::thread::sleep(std::time::Duration::from_millis(1000));
        
        let _ = Command::new("udevadm")
            .args(["settle", "--timeout=10"])
            .output();

        // Force kernel to re-read partition table
        let _ = Command::new("blockdev")
            .args(["--rereadpt", device])
            .output();

        std::thread::sleep(std::time::Duration::from_millis(500));

        // Determine partition device name
        let partition_device = if device.contains("nvme") || device.contains("mmcblk") {
            format!("{}p1", device)
        } else {
            format!("{}1", device)
        };

        // Verify partition exists with retries
        let mut partition_exists = false;
        for _ in 0..10 {
            if std::path::Path::new(&partition_device).exists() {
                partition_exists = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
            let _ = Command::new("partprobe").arg(device).output();
        }

        if !partition_exists {
            return Err(AppError::BadRequest(format!(
                "Partition {} was not created. Please try again.",
                partition_device
            )));
        }

        // Step 5: Format the partition
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
        
        // Add label if provided
        if let Some(label) = &body.label {
            if !label.is_empty() {
                match fs_lower.as_str() {
                    "ext4" | "ext3" | "ext2" | "xfs" | "btrfs" | "ntfs" => {
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

        // Add force flag for certain filesystems
        match fs_lower.as_str() {
            "ext4" => {
                format_cmd.arg("-F");
                format_cmd.arg("-m").arg("1"); // Reserve 1% for root
            }
            "ext3" | "ext2" => {
                format_cmd.arg("-F");
            }
            "xfs" | "btrfs" | "f2fs" => {
                format_cmd.arg("-f");
            }
            "ntfs" => {
                format_cmd.arg("-Q"); // Quick format
                format_cmd.arg("-F");
            }
            "fat32" | "vfat" => {
                format_cmd.arg("-F").arg("32");
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

        // Trigger udev to update device info
        let _ = Command::new("udevadm")
            .args(["trigger", "--subsystem-match=block"])
            .output();

        return Ok(HttpResponse::Ok().json(DiskOperationResult {
            success: true,
            message: format!(
                "Disk initialized successfully with {} filesystem on {}",
                body.file_system, partition_device
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

/// Get detailed disk information including SMART data
pub async fn get_disk_details(device: web::Path<String>) -> Result<HttpResponse, AppError> {
    let device_path = if device.starts_with("/dev/") {
        device.to_string()
    } else {
        format!("/dev/{}", device.as_str())
    };

    #[cfg(target_os = "linux")]
    {
        // Get basic info from lsblk
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

        // Get SMART info
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

        // Get filesystem usage if mounted
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

/// Scan for new disks (useful after hot-plugging)
pub async fn scan_disks() -> Result<HttpResponse, AppError> {
    #[cfg(target_os = "linux")]
    {
        // Trigger kernel to rescan for new devices
        let _ = Command::new("partprobe").output();

        // Also try udevadm trigger
        let _ = Command::new("udevadm")
            .args(["trigger", "--subsystem-match=block"])
            .output();

        // Wait a moment for devices to be recognized
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Return updated disk list
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
