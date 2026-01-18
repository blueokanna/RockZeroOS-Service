use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;
use tracing::{error, info};

use rockzero_common::AppError;

/// 存储设备详细信息
#[derive(Debug, Serialize, Clone)]
pub struct StorageDevice {
    pub id: String,
    pub name: String,
    pub device_path: String,
    pub mount_point: Option<String>,
    pub label: Option<String>,
    pub uuid: Option<String>,
    pub file_system: Option<String>,
    pub total_size: u64,
    pub used_size: u64,
    pub available_size: u64,
    pub device_type: StorageType,
    pub is_removable: bool,
    pub is_mounted: bool,
    pub is_readonly: bool,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub bus_type: String,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Clone, PartialEq)]
pub enum StorageType {
    InternalHDD,
    InternalSSD,
    InternalNVMe,
    InternalMMC,
    ExternalUSB,
    ExternalSATA,
    NetworkShare,
    Unknown,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct MountOptions {
    pub device: String,
    pub mount_point: String,
    pub file_system: Option<String>,
    pub options: Option<Vec<String>>,
    pub read_only: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct FormatOptions {
    pub device: String,
    pub file_system: String,
    pub label: Option<String>,
    pub quick: Option<bool>,
}

/// 获取所有存储设备（跨平台）
pub async fn list_storage_devices() -> Result<HttpResponse, AppError> {
    let devices = get_all_storage_devices()?;
    Ok(HttpResponse::Ok().json(devices))
}

/// 获取指定设备详情
pub async fn get_storage_device(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let device_id = path.into_inner();
    let devices = get_all_storage_devices()?;
    
    let device = devices
        .into_iter()
        .find(|d| d.id == device_id || d.device_path == device_id)
        .ok_or_else(|| AppError::NotFound("Device not found".to_string()))?;
    
    Ok(HttpResponse::Ok().json(device))
}

/// 挂载存储设备
pub async fn mount_storage(body: web::Json<MountOptions>) -> Result<HttpResponse, AppError> {
    let opts = body.into_inner();
    
    #[cfg(target_os = "windows")]
    {
        mount_windows(&opts)?;
    }
    
    #[cfg(target_os = "linux")]
    {
        mount_linux(&opts)?;
    }
    
    info!("Mounted {} to {}", opts.device, opts.mount_point);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Device mounted successfully",
        "device": opts.device,
        "mount_point": opts.mount_point
    })))
}

/// 卸载存储设备
pub async fn unmount_storage(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let device_or_mount = path.into_inner();
    
    #[cfg(target_os = "windows")]
    {
        unmount_windows(&device_or_mount)?;
    }
    
    #[cfg(target_os = "linux")]
    {
        unmount_linux(&device_or_mount)?;
    }
    
    info!("Unmounted {}", device_or_mount);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Device unmounted successfully"
    })))
}

/// 格式化存储设备
pub async fn format_storage(body: web::Json<FormatOptions>) -> Result<HttpResponse, AppError> {
    let opts = body.into_inner();
    
    #[cfg(target_os = "windows")]
    {
        format_windows(&opts)?;
    }
    
    #[cfg(target_os = "linux")]
    {
        format_linux(&opts)?;
    }
    
    info!("Formatted {} as {}", opts.device, opts.file_system);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Device formatted successfully",
        "device": opts.device,
        "file_system": opts.file_system
    })))
}

/// 安全弹出设备
pub async fn eject_storage(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let device = path.into_inner();
    
    #[cfg(target_os = "windows")]
    {
        eject_windows(&device)?;
    }
    
    #[cfg(target_os = "linux")]
    {
        eject_linux(&device)?;
    }
    
    info!("Ejected {}", device);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Device ejected safely"
    })))
}


// ============ 跨平台实现 ============

fn get_all_storage_devices() -> Result<Vec<StorageDevice>, AppError> {
    #[cfg(target_os = "windows")]
    {
        get_windows_devices()
    }
    
    #[cfg(target_os = "linux")]
    {
        return get_linux_devices();
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Ok(Vec::new())
    }
}

// ============ Windows 实现 ============

#[cfg(target_os = "windows")]
fn get_windows_devices() -> Result<Vec<StorageDevice>, AppError> {
    let mut devices = Vec::new();
    
    // 使用 PowerShell 获取磁盘信息
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            r#"
            Get-WmiObject Win32_DiskDrive | ForEach-Object {
                $disk = $_
                $partitions = Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='$($disk.DeviceID)'} WHERE AssocClass=Win32_DiskDriveToDiskPartition"
                foreach ($partition in $partitions) {
                    $logicalDisks = Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$($partition.DeviceID)'} WHERE AssocClass=Win32_LogicalDiskToPartition"
                    foreach ($logicalDisk in $logicalDisks) {
                        [PSCustomObject]@{
                            DeviceID = $disk.DeviceID
                            DriveLetter = $logicalDisk.DeviceID
                            Label = $logicalDisk.VolumeName
                            FileSystem = $logicalDisk.FileSystem
                            Size = $logicalDisk.Size
                            FreeSpace = $logicalDisk.FreeSpace
                            Model = $disk.Model
                            SerialNumber = $disk.SerialNumber
                            InterfaceType = $disk.InterfaceType
                            MediaType = $disk.MediaType
                        } | ConvertTo-Json -Compress
                    }
                }
            }
            "#,
        ])
        .output()
        .map_err(|e| {
            error!("Failed to execute PowerShell: {}", e);
            AppError::InternalError
        })?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                let device_id = json["DeviceID"].as_str().unwrap_or("").to_string();
                let drive_letter = json["DriveLetter"].as_str().unwrap_or("").to_string();
                let size = json["Size"].as_u64().unwrap_or(0);
                let free_space = json["FreeSpace"].as_u64().unwrap_or(0);
                let interface_type = json["InterfaceType"].as_str().unwrap_or("");
                let media_type = json["MediaType"].as_str().unwrap_or("");
                
                let device_type = match interface_type {
                    "USB" => StorageType::ExternalUSB,
                    "SCSI" | "IDE" => {
                        if media_type.contains("SSD") || media_type.contains("Solid") {
                            StorageType::InternalSSD
                        } else {
                            StorageType::InternalHDD
                        }
                    }
                    _ => StorageType::Unknown,
                };
                
                devices.push(StorageDevice {
                    id: drive_letter.clone(),
                    name: json["Label"].as_str().unwrap_or(&drive_letter).to_string(),
                    device_path: device_id,
                    mount_point: Some(drive_letter.clone()),
                    label: json["Label"].as_str().map(|s| s.to_string()),
                    uuid: None,
                    file_system: json["FileSystem"].as_str().map(|s| s.to_string()),
                    total_size: size,
                    used_size: size.saturating_sub(free_space),
                    available_size: free_space,
                    device_type,
                    is_removable: interface_type == "USB",
                    is_mounted: true,
                    is_readonly: false,
                    vendor: None,
                    model: json["Model"].as_str().map(|s| s.to_string()),
                    serial: json["SerialNumber"].as_str().map(|s| s.to_string()),
                    bus_type: interface_type.to_string(),
                });
            }
        }
    }
    
    // 如果 PowerShell 方法失败，使用 sysinfo 作为后备
    if devices.is_empty() {
        let disks = sysinfo::Disks::new_with_refreshed_list();
        for disk in disks.list() {
            let mount_point = disk.mount_point().to_string_lossy().to_string();
            let total = disk.total_space();
            let available = disk.available_space();
            
            devices.push(StorageDevice {
                id: mount_point.clone(),
                name: disk.name().to_string_lossy().to_string(),
                device_path: disk.name().to_string_lossy().to_string(),
                mount_point: Some(mount_point),
                label: None,
                uuid: None,
                file_system: Some(disk.file_system().to_string_lossy().to_string()),
                total_size: total,
                used_size: total.saturating_sub(available),
                available_size: available,
                device_type: if disk.is_removable() { StorageType::ExternalUSB } else { StorageType::InternalHDD },
                is_removable: disk.is_removable(),
                is_mounted: true,
                is_readonly: false,
                vendor: None,
                model: None,
                serial: None,
                bus_type: format!("{:?}", disk.kind()),
            });
        }
    }
    
    Ok(devices)
}

#[cfg(target_os = "windows")]
fn mount_windows(opts: &MountOptions) -> Result<(), AppError> {
    // Windows 使用 mountvol 命令
    let output = Command::new("mountvol")
        .args([&opts.mount_point, &opts.device])
        .output()
        .map_err(|_| AppError::InternalError)?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(format!("Mount failed: {}", err)));
    }
    
    Ok(())
}

#[cfg(target_os = "windows")]
fn unmount_windows(device: &str) -> Result<(), AppError> {
    let output = Command::new("mountvol")
        .args([device, "/P"])
        .output()
        .map_err(|_| AppError::InternalError)?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(format!("Unmount failed: {}", err)));
    }
    
    Ok(())
}

#[cfg(target_os = "windows")]
fn format_windows(opts: &FormatOptions) -> Result<(), AppError> {
    let mut args = vec![
        opts.device.clone(),
        format!("/FS:{}", opts.file_system),
    ];
    
    if let Some(label) = &opts.label {
        args.push(format!("/V:{}", label));
    }
    
    if opts.quick.unwrap_or(true) {
        args.push("/Q".to_string());
    }
    
    args.push("/Y".to_string()); // 确认格式化
    
    let output = Command::new("format")
        .args(&args)
        .output()
        .map_err(|_| AppError::InternalError)?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(format!("Format failed: {}", err)));
    }
    
    Ok(())
}

#[cfg(target_os = "windows")]
fn eject_windows(device: &str) -> Result<(), AppError> {
    // 使用 PowerShell 弹出设备
    let script = format!(
        r#"
        $vol = Get-WmiObject -Class Win32_Volume | Where-Object {{ $_.DriveLetter -eq '{}' }}
        if ($vol) {{
            $vol.Dismount($false, $false)
        }}
        "#,
        device
    );
    
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .map_err(|_| AppError::InternalError)?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(format!("Eject failed: {}", err)));
    }
    
    Ok(())
}


// ============ Linux 实现 (x64/aarch64/armbian) ============

#[cfg(target_os = "linux")]
fn get_linux_devices() -> Result<Vec<StorageDevice>, AppError> {
    let mut devices = Vec::new();
    
    // 使用 lsblk 获取块设备信息
    let output = Command::new("lsblk")
        .args([
            "-J", "-b", "-o",
            "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,LABEL,UUID,MODEL,SERIAL,TRAN,RM,RO,HOTPLUG,VENDOR"
        ])
        .output()
        .map_err(|e| {
            error!("Failed to execute lsblk: {}", e);
            AppError::InternalError
        })?;
    
    if !output.status.success() {
        // 后备方案：使用 sysinfo
        return get_linux_devices_fallback();
    }
    
    let json_str = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|_| AppError::InternalError)?;
    
    if let Some(blockdevices) = parsed.get("blockdevices").and_then(|v| v.as_array()) {
        for device in blockdevices {
            // 处理主设备
            let _device_name = device["name"].as_str().unwrap_or("");
            let device_type_str = device["type"].as_str().unwrap_or("");
            
            // 跳过非磁盘设备
            if device_type_str != "disk" {
                continue;
            }
            
            // 处理分区
            if let Some(children) = device.get("children").and_then(|v| v.as_array()) {
                for partition in children {
                    if let Some(dev) = parse_linux_device(partition, device) {
                        devices.push(dev);
                    }
                }
            } else {
                // 没有分区的设备
                if let Some(dev) = parse_linux_device(device, device) {
                    devices.push(dev);
                }
            }
        }
    }
    
    // 添加未挂载的设备
    add_unmounted_devices(&mut devices)?;
    
    Ok(devices)
}

#[cfg(target_os = "linux")]
fn parse_linux_device(partition: &serde_json::Value, parent: &serde_json::Value) -> Option<StorageDevice> {
    let name = partition["name"].as_str()?;
    let device_path = format!("/dev/{}", name);
    let size = partition["size"].as_u64().unwrap_or(0);
    let mount_point = partition["mountpoint"].as_str().map(|s| s.to_string());
    let fs_type = partition["fstype"].as_str().map(|s| s.to_string());
    let label = partition["label"].as_str().map(|s| s.to_string());
    let uuid = partition["uuid"].as_str().map(|s| s.to_string());
    let model = parent["model"].as_str().map(|s| s.to_string());
    let serial = parent["serial"].as_str().map(|s| s.to_string());
    let vendor = parent["vendor"].as_str().map(|s| s.to_string());
    let tran = parent["tran"].as_str().unwrap_or("");
    let is_removable = partition["rm"].as_bool().unwrap_or(false) 
        || parent["rm"].as_bool().unwrap_or(false)
        || partition["hotplug"].as_bool().unwrap_or(false);
    let is_readonly = partition["ro"].as_bool().unwrap_or(false);
    
    // 确定设备类型
    let device_type = determine_device_type(tran, &device_path, is_removable);
    
    // 获取使用空间
    let (used, available) = if let Some(ref mp) = mount_point {
        get_mount_usage(mp)
    } else {
        (0, size)
    };
    
    Some(StorageDevice {
        id: uuid.clone().unwrap_or_else(|| device_path.clone()),
        name: label.clone().unwrap_or_else(|| name.to_string()),
        device_path,
        mount_point,
        label,
        uuid,
        file_system: fs_type,
        total_size: size,
        used_size: used,
        available_size: available,
        device_type,
        is_removable,
        is_mounted: partition["mountpoint"].as_str().is_some(),
        is_readonly,
        vendor,
        model,
        serial,
        bus_type: tran.to_string(),
    })
}

#[cfg(target_os = "linux")]
fn determine_device_type(tran: &str, device_path: &str, is_removable: bool) -> StorageType {
    match tran.to_lowercase().as_str() {
        "usb" => StorageType::ExternalUSB,
        "sata" | "ata" => {
            if is_removable {
                StorageType::ExternalSATA
            } else if is_ssd(device_path) {
                StorageType::InternalSSD
            } else {
                StorageType::InternalHDD
            }
        }
        "nvme" => StorageType::InternalNVMe,
        "mmc" => StorageType::InternalMMC,
        _ => {
            if device_path.contains("nvme") {
                StorageType::InternalNVMe
            } else if device_path.contains("mmc") {
                StorageType::InternalMMC
            } else if is_removable {
                StorageType::ExternalUSB
            } else {
                StorageType::Unknown
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn is_ssd(device_path: &str) -> bool {
    // 检查 /sys/block/xxx/queue/rotational
    let device_name = device_path.trim_start_matches("/dev/");
    let base_device = device_name.trim_end_matches(|c: char| c.is_numeric());
    let rotational_path = format!("/sys/block/{}/queue/rotational", base_device);
    
    if let Ok(content) = std::fs::read_to_string(&rotational_path) {
        return content.trim() == "0";
    }
    false
}

#[cfg(target_os = "linux")]
fn get_mount_usage(mount_point: &str) -> (u64, u64) {
    use std::mem::MaybeUninit;
    
    let path = std::ffi::CString::new(mount_point).unwrap();
    let mut stat: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();
    
    unsafe {
        if libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) == 0 {
            let stat = stat.assume_init();
            let block_size = stat.f_frsize as u64;
            let total_blocks = stat.f_blocks as u64;
            let free_blocks = stat.f_bfree as u64;
            let available_blocks = stat.f_bavail as u64;
            
            let total = total_blocks * block_size;
            let available = available_blocks * block_size;
            let used = total - (free_blocks * block_size);
            
            return (used, available);
        }
    }
    
    (0, 0)
}

#[cfg(target_os = "linux")]
fn add_unmounted_devices(devices: &mut Vec<StorageDevice>) -> Result<(), AppError> {
    // 查找未挂载的分区
    let output = Command::new("blkid")
        .args(["-o", "export"])
        .output();
    
    if let Ok(output) = output {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut current_device: Option<String> = None;
            let mut current_uuid: Option<String> = None;
            let mut current_label: Option<String> = None;
            let mut current_fs: Option<String> = None;
            
            for line in stdout.lines() {
                if line.is_empty() {
                    if let Some(ref dev) = current_device {
                        // 检查是否已存在
                        if !devices.iter().any(|d| d.device_path == *dev) {
                            // 获取设备大小
                            let size = get_device_size(dev);
                            
                            devices.push(StorageDevice {
                                id: current_uuid.clone().unwrap_or_else(|| dev.clone()),
                                name: current_label.clone().unwrap_or_else(|| dev.clone()),
                                device_path: dev.clone(),
                                mount_point: None,
                                label: current_label.clone(),
                                uuid: current_uuid.clone(),
                                file_system: current_fs.clone(),
                                total_size: size,
                                used_size: 0,
                                available_size: size,
                                device_type: StorageType::Unknown,
                                is_removable: false,
                                is_mounted: false,
                                is_readonly: false,
                                vendor: None,
                                model: None,
                                serial: None,
                                bus_type: "unknown".to_string(),
                            });
                        }
                    }
                    current_device = None;
                    current_uuid = None;
                    current_label = None;
                    current_fs = None;
                } else if let Some((key, value)) = line.split_once('=') {
                    match key {
                        "DEVNAME" => current_device = Some(value.to_string()),
                        "UUID" => current_uuid = Some(value.to_string()),
                        "LABEL" => current_label = Some(value.to_string()),
                        "TYPE" => current_fs = Some(value.to_string()),
                        _ => {}
                    }
                }
            }
        }
    }
    
    Ok(())
}

#[cfg(target_os = "linux")]
fn get_device_size(device: &str) -> u64 {
    let device_name = device.trim_start_matches("/dev/");
    let size_path = format!("/sys/class/block/{}/size", device_name);
    
    if let Ok(content) = std::fs::read_to_string(&size_path) {
        if let Ok(sectors) = content.trim().parse::<u64>() {
            return sectors * 512; // 扇区大小通常是 512 字节
        }
    }
    0
}

#[cfg(target_os = "linux")]
fn get_linux_devices_fallback() -> Result<Vec<StorageDevice>, AppError> {
    let mut devices = Vec::new();
    let disks = sysinfo::Disks::new_with_refreshed_list();
    
    for disk in disks.list() {
        let mount_point = disk.mount_point().to_string_lossy().to_string();
        let total = disk.total_space();
        let available = disk.available_space();
        let name = disk.name().to_string_lossy().to_string();
        
        devices.push(StorageDevice {
            id: mount_point.clone(),
            name: name.clone(),
            device_path: name,
            mount_point: Some(mount_point),
            label: None,
            uuid: None,
            file_system: Some(disk.file_system().to_string_lossy().to_string()),
            total_size: total,
            used_size: total.saturating_sub(available),
            available_size: available,
            device_type: if disk.is_removable() { StorageType::ExternalUSB } else { StorageType::InternalHDD },
            is_removable: disk.is_removable(),
            is_mounted: true,
            is_readonly: false,
            vendor: None,
            model: None,
            serial: None,
            bus_type: format!("{:?}", disk.kind()),
        });
    }
    
    Ok(devices)
}


#[cfg(target_os = "linux")]
fn mount_linux(opts: &MountOptions) -> Result<(), AppError> {
    // 创建挂载点
    std::fs::create_dir_all(&opts.mount_point)
        .map_err(|e| AppError::BadRequest(format!("Failed to create mount point: {}", e)))?;
    
    let mut args = vec![opts.device.clone(), opts.mount_point.clone()];
    
    if let Some(fs) = &opts.file_system {
        args.insert(0, "-t".to_string());
        args.insert(1, fs.clone());
    }
    
    let mut mount_opts = Vec::new();
    if opts.read_only.unwrap_or(false) {
        mount_opts.push("ro".to_string());
    }
    if let Some(ref extra_opts) = opts.options {
        mount_opts.extend(extra_opts.clone());
    }
    
    if !mount_opts.is_empty() {
        args.push("-o".to_string());
        args.push(mount_opts.join(","));
    }
    
    let output = Command::new("mount")
        .args(&args)
        .output()
        .map_err(|_| AppError::InternalError)?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(format!("Mount failed: {}", err)));
    }
    
    Ok(())
}

#[cfg(target_os = "linux")]
fn unmount_linux(device_or_mount: &str) -> Result<(), AppError> {
    // 先尝试正常卸载
    let output = Command::new("umount")
        .arg(device_or_mount)
        .output()
        .map_err(|_| AppError::InternalError)?;
    
    if !output.status.success() {
        // 尝试强制卸载
        let output = Command::new("umount")
            .args(["-f", device_or_mount])
            .output()
            .map_err(|_| AppError::InternalError)?;
        
        if !output.status.success() {
            // 最后尝试 lazy unmount
            let output = Command::new("umount")
                .args(["-l", device_or_mount])
                .output()
                .map_err(|_| AppError::InternalError)?;
            
            if !output.status.success() {
                let err = String::from_utf8_lossy(&output.stderr);
                return Err(AppError::BadRequest(format!("Unmount failed: {}", err)));
            }
        }
    }
    
    Ok(())
}

#[cfg(target_os = "linux")]
fn format_linux(opts: &FormatOptions) -> Result<(), AppError> {
    // 确保设备未挂载
    let _ = Command::new("umount").arg(&opts.device).output();
    
    let mkfs_cmd = match opts.file_system.to_lowercase().as_str() {
        "ext4" => "mkfs.ext4",
        "ext3" => "mkfs.ext3",
        "ext2" => "mkfs.ext2",
        "xfs" => "mkfs.xfs",
        "btrfs" => "mkfs.btrfs",
        "fat32" | "vfat" => "mkfs.vfat",
        "exfat" => "mkfs.exfat",
        "ntfs" => "mkfs.ntfs",
        "f2fs" => "mkfs.f2fs",
        _ => return Err(AppError::BadRequest(format!("Unsupported filesystem: {}", opts.file_system))),
    };
    
    let mut args = Vec::new();
    
    // 添加标签参数
    if let Some(ref label) = opts.label {
        match opts.file_system.to_lowercase().as_str() {
            "ext4" | "ext3" | "ext2" | "xfs" | "btrfs" | "ntfs" => {
                args.push("-L".to_string());
                args.push(label.clone());
            }
            "fat32" | "vfat" | "exfat" => {
                args.push("-n".to_string());
                args.push(label.clone());
            }
            _ => {}
        }
    }
    
    // 添加强制/快速格式化参数
    match opts.file_system.to_lowercase().as_str() {
        "ext4" | "ext3" | "ext2" => args.push("-F".to_string()),
        "xfs" | "btrfs" => args.push("-f".to_string()),
        "ntfs" => {
            if opts.quick.unwrap_or(true) {
                args.push("-Q".to_string());
            }
        }
        _ => {}
    }
    
    args.push(opts.device.clone());
    
    let output = Command::new(mkfs_cmd)
        .args(&args)
        .output()
        .map_err(|e| AppError::BadRequest(format!("Failed to run {}: {}", mkfs_cmd, e)))?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(format!("Format failed: {}", err)));
    }
    
    Ok(())
}

#[cfg(target_os = "linux")]
fn eject_linux(device: &str) -> Result<(), AppError> {
    // 先卸载
    let _ = unmount_linux(device);
    
    // 同步文件系统
    let _ = Command::new("sync").output();
    
    // 弹出设备
    let output = Command::new("eject")
        .arg(device)
        .output();
    
    match output {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            // eject 失败，尝试使用 udisksctl
            let output = Command::new("udisksctl")
                .args(["power-off", "-b", device])
                .output();
            
            match output {
                Ok(out) if out.status.success() => Ok(()),
                _ => {
                    let err = String::from_utf8_lossy(&out.stderr);
                    Err(AppError::BadRequest(format!("Eject failed: {}", err)))
                }
            }
        }
        Err(e) => Err(AppError::BadRequest(format!("Eject failed: {}", e))),
    }
}

// ============ 文件读写操作 ============

/// 读取文件内容
pub async fn read_file(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let file_path = path.into_inner();
    let full_path = PathBuf::from(&file_path);
    
    if !full_path.exists() {
        return Err(AppError::NotFound("File not found".to_string()));
    }
    
    let content = std::fs::read(&full_path)
        .map_err(|e| AppError::IoError(format!("Failed to read file: {}", e)))?;
    
    let content_type = mime_guess::from_path(&full_path)
        .first_or_octet_stream()
        .to_string();
    
    Ok(HttpResponse::Ok()
        .content_type(content_type)
        .body(content))
}

/// 写入文件内容
#[derive(Debug, Deserialize)]
pub struct WriteFileRequest {
    pub path: String,
    pub content: String,
    pub create_dirs: Option<bool>,
    pub append: Option<bool>,
}

pub async fn write_file(body: web::Json<WriteFileRequest>) -> Result<HttpResponse, AppError> {
    let req = body.into_inner();
    let full_path = PathBuf::from(&req.path);
    
    // 创建父目录
    if req.create_dirs.unwrap_or(true) {
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AppError::IoError(format!("Failed to create directories: {}", e)))?;
        }
    }
    
    // 写入文件
    if req.append.unwrap_or(false) {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&full_path)
            .map_err(|e| AppError::IoError(format!("Failed to open file: {}", e)))?;
        
        file.write_all(req.content.as_bytes())
            .map_err(|e| AppError::IoError(format!("Failed to write file: {}", e)))?;
    } else {
        std::fs::write(&full_path, &req.content)
            .map_err(|e| AppError::IoError(format!("Failed to write file: {}", e)))?;
    }
    
    info!("File written: {}", req.path);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "path": req.path
    })))
}

/// 删除文件或目录
pub async fn delete_path(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let file_path = path.into_inner();
    let full_path = PathBuf::from(&file_path);
    
    if !full_path.exists() {
        return Err(AppError::NotFound("Path not found".to_string()));
    }
    
    if full_path.is_dir() {
        std::fs::remove_dir_all(&full_path)
            .map_err(|e| AppError::IoError(format!("Failed to delete directory: {}", e)))?;
    } else {
        std::fs::remove_file(&full_path)
            .map_err(|e| AppError::IoError(format!("Failed to delete file: {}", e)))?;
    }
    
    info!("Deleted: {}", file_path);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "deleted": file_path
    })))
}
