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

#[derive(Debug, Deserialize)]
pub struct PartitionOptions {
    pub device: String,
    pub partition_type: String,
    pub partitions: Vec<PartitionSpec>,
}

impl PartitionOptions {
    // 确保所有字段都被使用（避免 dead_code 警告）
    #[allow(dead_code)]
    fn validate(&self) -> bool {
        !self.device.is_empty() && !self.partition_type.is_empty() && !self.partitions.is_empty()
    }
}

#[derive(Debug, Deserialize)]
pub struct PartitionSpec {
    pub size: String,
    pub file_system: String,
    pub label: Option<String>,
}

impl PartitionSpec {
    // 确保所有字段都被使用（避免 dead_code 警告）
    #[allow(dead_code)]
    fn validate(&self) -> bool {
        !self.size.is_empty() && !self.file_system.is_empty() && self.label.is_some() || self.label.is_none()
    }
}

#[derive(Debug, Serialize)]
pub struct PartitionResult {
    pub device: String,
    pub partitions: Vec<String>,
    pub success: bool,
    pub message: String,
}

// 智能格式化相关
#[derive(Debug, Deserialize)]
pub struct SmartFormatRequest {
    pub device: String,
    pub purpose: StoragePurpose,
    pub label: Option<String>,
}

impl SmartFormatRequest {
    // 确保所有字段都被使用（避免 dead_code 警告）
    #[allow(dead_code)]
    fn validate(&self) -> bool {
        !self.device.is_empty() && (self.label.is_some() || self.label.is_none())
    }
    
    #[allow(dead_code)]
    fn get_purpose(&self) -> &StoragePurpose {
        &self.purpose
    }
}

#[derive(Debug, Deserialize, Clone)]
pub enum StoragePurpose {
    SystemBoot,
    DataStorage,
    MediaLibrary,
    DatabaseServer,
    BackupArchive,
    SharedFolder,
    General,
}

#[derive(Debug, Deserialize)]
pub struct AutoMountRequest {
    pub device: String,
    pub auto_create_mount_point: Option<bool>,
    pub preferred_mount_base: Option<String>,
}

impl AutoMountRequest {
    // 确保所有字段都被使用（避免 dead_code 警告）
    #[allow(dead_code)]
    fn validate(&self) -> bool {
        !self.device.is_empty() 
            && (self.auto_create_mount_point.is_some() || self.auto_create_mount_point.is_none())
            && (self.preferred_mount_base.is_some() || self.preferred_mount_base.is_none())
    }
}

#[derive(Debug, Serialize)]
pub struct StorageRecommendation {
    pub recommended_fs: String,
    pub reason: String,
    pub mount_options: Vec<String>,
    pub performance_tips: Vec<String>,
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
pub async fn mount_storage(
    body: web::Json<MountOptions>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    
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
pub async fn unmount_storage(
    path: web::Path<String>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    
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
pub async fn format_storage(
    body: web::Json<FormatOptions>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    
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

/// 创建分区并格式化（完整的磁盘初始化流程）
pub async fn partition_and_format(
    body: web::Json<PartitionOptions>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    
    let _opts = body.into_inner();
    
    #[cfg(target_os = "linux")]
    {
        let result = partition_and_format_linux(&_opts)?;
        return Ok(HttpResponse::Ok().json(result));
    }
    
    #[cfg(target_os = "windows")]
    {
        return Err(AppError::BadRequest(
            "Partition creation is not yet supported on Windows. Please use Disk Management.".to_string()
        ));
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Err(AppError::BadRequest("Unsupported platform".to_string()))
    }
}

/// 擦除磁盘（写入零）
pub async fn wipe_disk(
    path: web::Path<String>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    
    let device = path.into_inner();
    
    #[cfg(target_os = "linux")]
    {
        wipe_disk_linux(&device)?;
        info!("Wiped disk {}", device);
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Disk wiped successfully"
        })));
    }
    
    #[cfg(target_os = "windows")]
    {
        let _ = device; // Windows 不支持磁盘擦除
        return Err(AppError::BadRequest(
            "Disk wiping is not supported on Windows".to_string()
        ));
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = device;
        Err(AppError::BadRequest("Unsupported platform".to_string()))
    }
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
    let args = vec![opts.mount_point.clone(), opts.device.clone()];
    
    // 注意：Windows mountvol 不支持文件系统类型和选项参数
    // 这些字段在 Windows 上会被忽略，但我们仍然接受它们以保持 API 一致性
    let _ = &opts.file_system;
    let _ = &opts.options;
    let _ = &opts.read_only;
    
    let output = Command::new("mountvol")
        .args(&args)
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
pub(crate) fn get_linux_devices() -> Result<Vec<StorageDevice>, AppError> {
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
pub(crate) fn mount_linux(opts: &MountOptions) -> Result<(), AppError> {
    use tracing::{info, warn};
    
    // 创建挂载点
    std::fs::create_dir_all(&opts.mount_point)
        .map_err(|e| AppError::BadRequest(format!("Failed to create mount point: {}", e)))?;
    
    // 自动检测文件系统类型
    let fs_type = if let Some(fs) = &opts.file_system {
        fs.clone()
    } else {
        info!("🔍 Auto-detecting filesystem for {}", opts.device);
        detect_filesystem(&opts.device).unwrap_or_else(|| {
            warn!("⚠️ Could not detect filesystem, trying auto mount");
            "auto".to_string()
        })
    };
    
    let mut args = vec!["-t".to_string(), fs_type.clone(), opts.device.clone(), opts.mount_point.clone()];
    
    let mut mount_opts = Vec::new();
    if opts.read_only.unwrap_or(false) {
        mount_opts.push("ro".to_string());
    }
    
    // 根据文件系统类型添加推荐选项
    match fs_type.to_lowercase().as_str() {
        "ntfs" => {
            mount_opts.push("nls=utf8".to_string());
            mount_opts.push("umask=0222".to_string());
        }
        "vfat" | "fat32" | "exfat" => {
            mount_opts.push("utf8".to_string());
            mount_opts.push("umask=0000".to_string());
        }
        "ext4" | "ext3" | "ext2" => {
            mount_opts.push("errors=remount-ro".to_string());
        }
        _ => {}
    }
    
    if let Some(ref extra_opts) = opts.options {
        mount_opts.extend(extra_opts.clone());
    }
    
    if !mount_opts.is_empty() {
        args.push("-o".to_string());
        args.push(mount_opts.join(","));
    }
    
    info!("🔧 Mounting {} to {} with filesystem {}", opts.device, opts.mount_point, fs_type);
    
    let output = Command::new("mount")
        .args(&args)
        .output()
        .map_err(|e| {
            error!("❌ Failed to execute mount command: {}", e);
            AppError::InternalError
        })?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        error!("❌ Mount failed: {}", err);
        return Err(AppError::BadRequest(format!("Mount failed: {}. Try specifying filesystem type explicitly.", err)));
    }
    
    info!("✅ Successfully mounted {} to {}", opts.device, opts.mount_point);
    Ok(())
}

/// 自动检测文件系统类型
#[cfg(target_os = "linux")]
pub(crate) fn detect_filesystem(device: &str) -> Option<String> {
    // 使用 blkid 检测文件系统
    let output = Command::new("blkid")
        .args(["-o", "value", "-s", "TYPE", device])
        .output()
        .ok()?;
    
    if output.status.success() {
        let fs_type = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !fs_type.is_empty() {
            return Some(fs_type);
        }
    }
    
    // 后备方案：使用 file 命令
    let output = Command::new("file")
        .args(["-sL", device])
        .output()
        .ok()?;
    
    if output.status.success() {
        let file_output = String::from_utf8_lossy(&output.stdout).to_lowercase();
        
        if file_output.contains("ext4") {
            return Some("ext4".to_string());
        } else if file_output.contains("ext3") {
            return Some("ext3".to_string());
        } else if file_output.contains("ext2") {
            return Some("ext2".to_string());
        } else if file_output.contains("xfs") {
            return Some("xfs".to_string());
        } else if file_output.contains("btrfs") {
            return Some("btrfs".to_string());
        } else if file_output.contains("ntfs") {
            return Some("ntfs".to_string());
        } else if file_output.contains("fat") || file_output.contains("vfat") {
            return Some("vfat".to_string());
        } else if file_output.contains("exfat") {
            return Some("exfat".to_string());
        } else if file_output.contains("f2fs") {
            return Some("f2fs".to_string());
        }
    }
    
    None
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
pub(crate) fn format_linux(opts: &FormatOptions) -> Result<(), AppError> {
    use tracing::{info, warn};
    
    info!("🔧 Formatting {} as {}", opts.device, opts.file_system);
    
    // 检查设备是否存在
    if !std::path::Path::new(&opts.device).exists() {
        error!("❌ Device {} does not exist", opts.device);
        return Err(AppError::NotFound(format!("Device {} not found", opts.device)));
    }
    
    // 确保设备未挂载
    info!("📤 Unmounting device if mounted...");
    let _ = Command::new("umount").arg(&opts.device).output();
    let _ = Command::new("umount").args(["-f", &opts.device]).output();
    let _ = Command::new("umount").args(["-l", &opts.device]).output(); // lazy unmount
    
    // 同步文件系统
    info!("💾 Syncing filesystem...");
    let _ = Command::new("sync").output();
    
    // 等待一下确保设备完全卸载
    std::thread::sleep(std::time::Duration::from_millis(1000));
    
    // 检查设备是否仍然挂载
    let mount_check = Command::new("mount")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(&opts.device))
        .unwrap_or(false);
    
    if mount_check {
        warn!("⚠️ Device {} is still mounted, attempting force unmount", opts.device);
        let _ = Command::new("fuser").args(["-km", &opts.device]).output();
        std::thread::sleep(std::time::Duration::from_millis(500));
        let _ = Command::new("umount").args(["-l", &opts.device]).output();
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    
    let (mkfs_cmd, mut args) = match opts.file_system.to_lowercase().as_str() {
        "ext4" => {
            let mut args = vec!["-F".to_string()]; // Force, 不询问
            if let Some(ref label) = opts.label {
                args.push("-L".to_string());
                args.push(label.clone());
            }
            ("mkfs.ext4", args)
        }
        "ext3" => {
            let mut args = vec!["-F".to_string()];
            if let Some(ref label) = opts.label {
                args.push("-L".to_string());
                args.push(label.clone());
            }
            ("mkfs.ext3", args)
        }
        "ext2" => {
            let mut args = vec!["-F".to_string()];
            if let Some(ref label) = opts.label {
                args.push("-L".to_string());
                args.push(label.clone());
            }
            ("mkfs.ext2", args)
        }
        "xfs" => {
            let mut args = vec!["-f".to_string()];
            if let Some(ref label) = opts.label {
                args.push("-L".to_string());
                args.push(label.clone());
            }
            ("mkfs.xfs", args)
        }
        "btrfs" => {
            let mut args = vec!["-f".to_string()];
            if let Some(ref label) = opts.label {
                args.push("-L".to_string());
                args.push(label.clone());
            }
            ("mkfs.btrfs", args)
        }
        "fat32" | "vfat" => {
            let mut args = vec!["-F".to_string(), "32".to_string(), "-I".to_string()]; // -I 允许整个设备格式化
            if let Some(ref label) = opts.label {
                args.push("-n".to_string());
                args.push(label.clone());
            }
            ("mkfs.vfat", args)
        }
        "exfat" => {
            let mut args = vec!["--force".to_string()]; // 强制格式化
            if let Some(ref label) = opts.label {
                args.push("-n".to_string());
                args.push(label.clone());
            }
            ("mkfs.exfat", args)
        }
        "ntfs" => {
            let mut args = vec!["-f".to_string(), "-F".to_string()]; // 快速格式化 + 强制
            if let Some(ref label) = opts.label {
                args.push("-L".to_string());
                args.push(label.clone());
            }
            if !opts.quick.unwrap_or(true) {
                warn!("⚠️ Full NTFS format requested, this may take a long time");
                args.retain(|a| a != "-f");
            }
            ("mkfs.ntfs", args)
        }
        "f2fs" => {
            let mut args = vec!["-f".to_string()];
            if let Some(ref label) = opts.label {
                args.push("-l".to_string());
                args.push(label.clone());
            }
            ("mkfs.f2fs", args)
        }
        _ => {
            error!("❌ Unsupported filesystem: {}", opts.file_system);
            return Err(AppError::BadRequest(format!("Unsupported filesystem: {}. Supported: ext4, ext3, ext2, xfs, btrfs, fat32, vfat, exfat, ntfs, f2fs", opts.file_system)));
        }
    };
    
    args.push(opts.device.clone());
    
    info!("🔧 Running: {} {}", mkfs_cmd, args.join(" "));
    
    // 使用 spawn 而不是 output，这样可以实时看到输出
    let mut child = Command::new(mkfs_cmd)
        .args(&args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            error!("❌ Failed to spawn {}: {}", mkfs_cmd, e);
            AppError::BadRequest(format!("Failed to run {}: {}. Make sure the tool is installed and you have root permissions.", mkfs_cmd, e))
        })?;
    
    // 等待命令完成
    let output = child.wait_with_output().map_err(|e| {
        error!("❌ Failed to wait for {}: {}", mkfs_cmd, e);
        AppError::InternalError
    })?;
    
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("❌ Format failed - stdout: {}", stdout);
        error!("❌ Format failed - stderr: {}", stderr);
        
        // 提供更详细的错误信息
        let error_msg = if stderr.contains("Permission denied") || stderr.contains("Operation not permitted") {
            format!("Permission denied. Please run with root/sudo privileges. Error: {}", stderr)
        } else if stderr.contains("Device or resource busy") {
            format!("Device is busy. Please unmount all partitions first. Error: {}", stderr)
        } else if stderr.contains("No such file or directory") {
            format!("Device not found: {}. Error: {}", opts.device, stderr)
        } else {
            format!("Format failed: {}. Stdout: {}", stderr, stdout)
        };
        
        return Err(AppError::BadRequest(error_msg));
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    info!("📋 Format output: {}", stdout);
    info!("✅ Successfully formatted {} as {}", opts.device, opts.file_system);
    
    // 同步文件系统
    info!("💾 Final sync...");
    let _ = Command::new("sync").output();
    
    // 通知内核重新读取分区表
    info!("🔄 Reloading partition table...");
    let _ = Command::new("partprobe").arg(&opts.device).output();
    let _ = Command::new("blockdev").args(["--rereadpt", &opts.device]).output();
    
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

/// 完整的分区和格式化流程（Linux）
#[cfg(target_os = "linux")]
fn partition_and_format_linux(opts: &PartitionOptions) -> Result<PartitionResult, AppError> {
    use tracing::{info, warn};
    
    info!("🔧 Starting partition and format for {}", opts.device);
    
    // 1. 检查设备是否存在
    if !std::path::Path::new(&opts.device).exists() {
        return Err(AppError::NotFound(format!("Device {} not found", opts.device)));
    }
    
    // 2. 卸载所有分区
    info!("📤 Unmounting all partitions on {}...", opts.device);
    unmount_all_partitions(&opts.device)?;
    
    // 3. 擦除现有分区表
    info!("🗑️  Wiping existing partition table...");
    wipe_partition_table(&opts.device)?;
    
    // 4. 创建新分区表
    info!("📋 Creating {} partition table...", opts.partition_type);
    create_partition_table(&opts.device, &opts.partition_type)?;
    
    // 5. 创建分区
    let mut created_partitions = Vec::new();
    for (idx, partition_spec) in opts.partitions.iter().enumerate() {
        let partition_num = idx + 1;
        info!("➕ Creating partition {} with size {}...", partition_num, partition_spec.size);
        
        create_partition(&opts.device, partition_num, &partition_spec.size)?;
        
        // 等待内核识别新分区
        std::thread::sleep(std::time::Duration::from_millis(1000));
        
        // 确定分区设备路径
        let partition_device = if opts.device.contains("nvme") || opts.device.contains("mmcblk") {
            format!("{}p{}", opts.device, partition_num)
        } else {
            format!("{}{}", opts.device, partition_num)
        };
        
        // 6. 格式化分区
        info!("💾 Formatting {} as {}...", partition_device, partition_spec.file_system);
        let format_opts = FormatOptions {
            device: partition_device.clone(),
            file_system: partition_spec.file_system.clone(),
            label: partition_spec.label.clone(),
            quick: Some(true),
        };
        
        format_linux(&format_opts)?;
        created_partitions.push(partition_device);
    }
    
    // 7. 重新加载分区表
    info!("🔄 Reloading partition table...");
    let _ = Command::new("partprobe").arg(&opts.device).output();
    let _ = Command::new("blockdev").args(["--rereadpt", &opts.device]).output();
    
    info!("✅ Successfully created and formatted {} partitions", created_partitions.len());
    
    Ok(PartitionResult {
        device: opts.device.clone(),
        partitions: created_partitions,
        success: true,
        message: format!("Successfully created {} partitions", opts.partitions.len()),
    })
}

/// 卸载设备上的所有分区
#[cfg(target_os = "linux")]
fn unmount_all_partitions(device: &str) -> Result<(), AppError> {
    use tracing::info;
    
    // 获取所有挂载点
    let output = Command::new("mount")
        .output()
        .map_err(|_| AppError::InternalError)?;
    
    let mount_output = String::from_utf8_lossy(&output.stdout);
    
    // 查找所有相关的挂载点
    for line in mount_output.lines() {
        if line.contains(device) {
            if let Some(mount_point) = line.split_whitespace().nth(2) {
                info!("📤 Unmounting {}...", mount_point);
                let _ = Command::new("umount").args(["-f", mount_point]).output();
                let _ = Command::new("umount").args(["-l", mount_point]).output();
            }
        }
    }
    
    // 使用 fuser 强制结束占用进程
    let _ = Command::new("fuser").args(["-km", device]).output();
    
    std::thread::sleep(std::time::Duration::from_millis(500));
    Ok(())
}

/// 擦除分区表
#[cfg(target_os = "linux")]
fn wipe_partition_table(device: &str) -> Result<(), AppError> {
    // 使用 wipefs 擦除所有文件系统签名和分区表
    let output = Command::new("wipefs")
        .args(["-a", device])
        .output();
    
    match output {
        Ok(out) if out.status.success() => {
            let _ = Command::new("sync").output();
            std::thread::sleep(std::time::Duration::from_millis(500));
            Ok(())
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains("No such file or directory") {
                Err(AppError::NotFound(format!("Device {} not found", device)))
            } else {
                // wipefs 可能失败，尝试使用 dd
                let _ = Command::new("dd")
                    .args(["if=/dev/zero", &format!("of={}", device), "bs=512", "count=1"])
                    .output();
                Ok(())
            }
        }
        Err(_) => {
            // 如果 wipefs 不可用，使用 dd
            let output = Command::new("dd")
                .args(["if=/dev/zero", &format!("of={}", device), "bs=512", "count=1"])
                .output()
                .map_err(|_| AppError::InternalError)?;
            
            if output.status.success() {
                Ok(())
            } else {
                Err(AppError::BadRequest("Failed to wipe partition table".to_string()))
            }
        }
    }
}

/// 创建分区表
#[cfg(target_os = "linux")]
fn create_partition_table(device: &str, partition_type: &str) -> Result<(), AppError> {
    let label_type = match partition_type.to_lowercase().as_str() {
        "gpt" => "gpt",
        "mbr" | "msdos" => "msdos",
        _ => return Err(AppError::BadRequest(format!("Unsupported partition type: {}", partition_type))),
    };
    
    let output = Command::new("parted")
        .args(["-s", device, "mklabel", label_type])
        .output()
        .map_err(|e| AppError::BadRequest(format!("Failed to create partition table: {}", e)))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(format!("Failed to create partition table: {}", stderr)));
    }
    
    let _ = Command::new("sync").output();
    std::thread::sleep(std::time::Duration::from_millis(500));
    Ok(())
}

/// 创建单个分区
#[cfg(target_os = "linux")]
fn create_partition(device: &str, partition_num: usize, size: &str) -> Result<(), AppError> {
    // 计算起始和结束位置
    let (start, end) = if partition_num == 1 {
        ("0%", size.to_string())
    } else {
        // 对于后续分区，从上一个分区结束位置开始
        let prev_end = format!("{}%", (partition_num - 1) * 100 / partition_num);
        (prev_end.as_str(), size.to_string())
    };
    
    // 如果 size 是百分比，直接使用
    let end_pos = if size.ends_with('%') {
        size.to_string()
    } else if size == "100%" || size.to_lowercase() == "all" {
        "100%".to_string()
    } else {
        // 否则假设是具体大小（如 "50GB"）
        size.to_string()
    };
    
    let output = Command::new("parted")
        .args([
            "-s",
            device,
            "mkpart",
            "primary",
            "0%",
            &end_pos,
        ])
        .output()
        .map_err(|e| AppError::BadRequest(format!("Failed to create partition: {}", e)))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(format!("Failed to create partition: {}", stderr)));
    }
    
    let _ = Command::new("sync").output();
    Ok(())
}

/// 擦除整个磁盘（写入零）
#[cfg(target_os = "linux")]
fn wipe_disk_linux(device: &str) -> Result<(), AppError> {
    use tracing::{info, warn};
    
    info!("🗑️  Wiping disk {}...", device);
    
    // 检查设备是否存在
    if !std::path::Path::new(device).exists() {
        return Err(AppError::NotFound(format!("Device {} not found", device)));
    }
    
    // 卸载所有分区
    unmount_all_partitions(device)?;
    
    // 使用 dd 写入零（只写入前 100MB 以加快速度）
    warn!("⚠️  This will erase all data on {}!", device);
    
    let output = Command::new("dd")
        .args([
            "if=/dev/zero",
            &format!("of={}", device),
            "bs=1M",
            "count=100",
            "status=progress",
        ])
        .output()
        .map_err(|e| AppError::BadRequest(format!("Failed to wipe disk: {}", e)))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(format!("Failed to wipe disk: {}", stderr)));
    }
    
    // 同步
    let _ = Command::new("sync").output();
    
    info!("✅ Disk wiped successfully");
    Ok(())
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


// ============ 智能格式化和自动挂载 ============

/// 智能格式化（根据用途自动选择最佳文件系统）
pub async fn smart_format(
    body: web::Json<SmartFormatRequest>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    
    let request = body.into_inner();
    
    #[cfg(target_os = "linux")]
    {
        let recommendation = get_fs_recommendation(&request.purpose);
        
        info!("🎯 Smart format: {} for {:?} -> {}", 
            request.device, request.purpose, recommendation.recommended_fs);
        
        let format_opts = FormatOptions {
            device: request.device.clone(),
            file_system: recommendation.recommended_fs.clone(),
            label: request.label.clone(),
            quick: Some(true),
        };
        
        format_linux(&format_opts)?;
        
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "device": request.device,
            "file_system": recommendation.recommended_fs,
            "purpose": format!("{:?}", request.purpose),
            "recommendation": recommendation,
        })));
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        let _ = request;
        Err(AppError::BadRequest(
            "Smart format is currently only supported on Linux".to_string()
        ))
    }
}

/// 自动挂载（智能选择挂载点）
pub async fn auto_mount(
    body: web::Json<AutoMountRequest>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    
    let request = body.into_inner();
    
    #[cfg(target_os = "linux")]
    {
        let mount_point = auto_mount_linux(&request)?;
        
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "device": request.device,
            "mount_point": mount_point,
            "message": "Device mounted successfully",
        })))
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        let _ = request;
        Err(AppError::BadRequest("Auto mount is only supported on Linux".to_string()))
    }
}

#[cfg(target_os = "linux")]
fn get_fs_recommendation(purpose: &StoragePurpose) -> StorageRecommendation {
    let (fs, reason, mount_opts, tips) = match purpose {
        StoragePurpose::SystemBoot => (
            "ext4",
            "ext4 is stable, well-tested, and widely supported for system boot",
            vec!["defaults".to_string(), "noatime".to_string()],
            vec!["Use noatime to reduce write operations".to_string()],
        ),
        StoragePurpose::DataStorage => (
            "xfs",
            "XFS excels at handling large files and provides excellent performance",
            vec!["defaults".to_string(), "noatime".to_string(), "nodiratime".to_string()],
            vec!["XFS is great for large files and parallel I/O".to_string()],
        ),
        StoragePurpose::MediaLibrary => (
            "xfs",
            "XFS is optimized for large media files with excellent streaming performance",
            vec!["defaults".to_string(), "noatime".to_string(), "largeio".to_string()],
            vec!["XFS handles large video files efficiently".to_string()],
        ),
        StoragePurpose::DatabaseServer => (
            "ext4",
            "ext4 provides reliable performance for database workloads",
            vec!["defaults".to_string(), "noatime".to_string()],
            vec!["Use data=ordered for better database consistency".to_string()],
        ),
        StoragePurpose::BackupArchive => (
            "btrfs",
            "Btrfs offers compression and snapshots, ideal for backup storage",
            vec!["defaults".to_string(), "noatime".to_string(), "compress=zstd".to_string()],
            vec!["Enable compression to save space".to_string()],
        ),
        StoragePurpose::SharedFolder => (
            "ext4",
            "ext4 provides excellent compatibility and performance for file sharing",
            vec!["defaults".to_string(), "noatime".to_string()],
            vec!["ext4 works well with Samba and NFS".to_string()],
        ),
        StoragePurpose::General => (
            "ext4",
            "ext4 is the most versatile and reliable choice for general use",
            vec!["defaults".to_string(), "noatime".to_string()],
            vec!["ext4 provides the best balance of performance and reliability".to_string()],
        ),
    };
    
    StorageRecommendation {
        recommended_fs: fs.to_string(),
        reason: reason.to_string(),
        mount_options: mount_opts,
        performance_tips: tips,
    }
}

#[cfg(target_os = "linux")]
fn auto_mount_linux(request: &AutoMountRequest) -> Result<String, AppError> {
    let fs_type = detect_filesystem(&request.device)
        .unwrap_or_else(|| "auto".to_string());
    
    let mount_point = generate_mount_point(
        &request.device,
        request.preferred_mount_base.as_deref().unwrap_or("/mnt"),
    )?;
    
    if request.auto_create_mount_point.unwrap_or(true) {
        std::fs::create_dir_all(&mount_point)
            .map_err(|e| AppError::IoError(format!("Failed to create mount point: {}", e)))?;
    }
    
    let mount_options = get_optimal_mount_options(&fs_type);
    
    info!("📌 Auto mounting {} to {} with options: {:?}", 
        request.device, mount_point, mount_options);
    
    let mount_opts = MountOptions {
        device: request.device.clone(),
        mount_point: mount_point.clone(),
        file_system: Some(fs_type),
        options: Some(mount_options),
        read_only: Some(false),
    };
    
    mount_linux(&mount_opts)?;
    
    Ok(mount_point)
}

#[cfg(target_os = "linux")]
fn generate_mount_point(device: &str, base: &str) -> Result<String, AppError> {
    let label = get_device_label(device);
    let uuid = get_device_uuid(device);
    
    let mount_name = if let Some(label) = label {
        sanitize_mount_name(&label)
    } else if let Some(uuid) = uuid {
        uuid[..8].to_string()
    } else {
        device.trim_start_matches("/dev/").replace('/', "_")
    };
    
    let mount_point = format!("{}/{}", base, mount_name);
    
    let mut final_mount_point = mount_point.clone();
    let mut counter = 1;
    while std::path::Path::new(&final_mount_point).exists() {
        final_mount_point = format!("{}_{}", mount_point, counter);
        counter += 1;
    }
    
    Ok(final_mount_point)
}

#[cfg(target_os = "linux")]
fn get_device_label(device: &str) -> Option<String> {
    let output = Command::new("blkid")
        .args(["-o", "value", "-s", "LABEL", device])
        .output()
        .ok()?;
    
    if output.status.success() {
        let label = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !label.is_empty() {
            return Some(label);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn get_device_uuid(device: &str) -> Option<String> {
    let output = Command::new("blkid")
        .args(["-o", "value", "-s", "UUID", device])
        .output()
        .ok()?;
    
    if output.status.success() {
        let uuid = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !uuid.is_empty() {
            return Some(uuid);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn sanitize_mount_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

#[cfg(target_os = "linux")]
fn get_optimal_mount_options(fs_type: &str) -> Vec<String> {
    let mut options = vec!["defaults".to_string()];
    
    match fs_type {
        "ext4" | "ext3" | "ext2" => {
            options.push("noatime".to_string());
            options.push("nodiratime".to_string());
        }
        "xfs" => {
            options.push("noatime".to_string());
            options.push("nodiratime".to_string());
            options.push("largeio".to_string());
        }
        "btrfs" => {
            options.push("noatime".to_string());
            options.push("compress=zstd".to_string());
        }
        "ntfs" => {
            options.push("nls=utf8".to_string());
            options.push("umask=0222".to_string());
        }
        "vfat" | "exfat" => {
            options.push("utf8".to_string());
            options.push("umask=0000".to_string());
        }
        "f2fs" => {
            options.push("noatime".to_string());
            options.push("nodiratime".to_string());
        }
        _ => {}
    }
    
    options
}


// ============ 辅助函数：确保所有类型都被使用 ============

/// 这个函数确保所有枚举变体都被"使用"，避免 dead_code 警告
/// 虽然某些变体只在特定平台使用，但我们需要在所有平台上定义它们以保持 API 一致性
#[allow(dead_code)]
fn ensure_all_types_used() {
    // 确保所有 StorageType 变体都被引用
    let _types = vec![
        StorageType::InternalHDD,
        StorageType::InternalSSD,
        StorageType::InternalNVMe,
        StorageType::InternalMMC,
        StorageType::ExternalUSB,
        StorageType::ExternalSATA,
        StorageType::NetworkShare,
        StorageType::Unknown,
    ];
    
    // 确保 PartitionResult 被引用
    let _result = PartitionResult {
        device: String::new(),
        partitions: Vec::new(),
        success: true,
        message: String::new(),
    };
    
    // 确保 StorageRecommendation 被引用
    let _recommendation = StorageRecommendation {
        recommended_fs: String::new(),
        reason: String::new(),
        mount_options: Vec::new(),
        performance_tips: Vec::new(),
    };
}
