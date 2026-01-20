use actix_web::{HttpResponse, Responder};
use serde::Serialize;
use sysinfo::{Disks, Networks, System};

#[cfg(target_os = "linux")]
use std::fs;

use rockzero_common::AppError;
use crate::hardware;

#[derive(Debug, Serialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub architecture: String,
    pub uptime: u64,
}

/// CPU 核心使用率信息
#[derive(Debug, Serialize)]
pub struct CpuCoreUsage {
    pub core_id: usize,
    pub usage: f32,
    pub frequency: u64,
}

/// CPU 核心架构信息 (用于 ARM big.LITTLE 等异构架构)
#[derive(Debug, Serialize)]
pub struct CpuCoreArchInfo {
    /// 核心架构名称 (如 Cortex-A55, Cortex-A76)
    pub core_name: String,
    /// CPU Part ID
    pub part_id: String,
    /// 该类型核心的数量
    pub count: usize,
    /// CPU 实现者 (如 ARM, Qualcomm)
    pub implementer: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CpuInfo {
    pub name: String,
    pub vendor: String,
    pub brand: String,
    pub frequency: u64,
    pub cores: usize,
    pub usage: f32,
    pub temperature: Option<f32>,
    pub per_core_usage: Vec<CpuCoreUsage>,
    /// CPU 核心架构信息 (ARM 异构架构)
    pub core_types: Vec<CpuCoreArchInfo>,
}

#[derive(Debug, Serialize)]
pub struct MemoryInfo {
    pub total: u64,
    pub used: u64,
    pub available: u64,
    pub usage_percentage: f64,
    pub swap_total: u64,
    pub swap_used: u64,
}

#[derive(Debug, Serialize)]
pub struct DiskInfo {
    pub name: String,
    pub mount_point: String,
    pub file_system: String,
    pub total_space: u64,
    pub available_space: u64,
    pub used_space: u64,
    pub usage_percentage: f64,
    pub is_removable: bool,
    pub disk_type: String,
}

#[derive(Debug, Serialize)]
pub struct UsbDevice {
    pub name: String,
    pub vendor_id: String,
    pub product_id: String,
    pub manufacturer: Option<String>,
    pub device_class: String,
    pub mount_point: Option<String>,
    pub size: Option<u64>,
    pub serial: Option<String>,
    pub speed: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct NetworkInterfaceInfo {
    pub name: String,
    pub mac_address: String,
    pub ip_addresses: Vec<String>,
    pub is_up: bool,
    pub speed_mbps: Option<u64>,
    pub interface_type: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct HardwareInfo {
    pub system: SystemInfo,
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub disks: Vec<DiskInfo>,
    pub usb_devices: Vec<UsbDevice>,
    pub network_interfaces: Vec<NetworkInterfaceInfo>,
}

pub async fn get_system_info() -> Result<impl Responder, AppError> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());
    let os_name = System::name().unwrap_or_else(|| "unknown".to_string());
    let os_version = System::os_version().unwrap_or_else(|| "unknown".to_string());
    let kernel_version = System::kernel_version().unwrap_or_else(|| "unknown".to_string());
    let architecture = std::env::consts::ARCH.to_string();
    let uptime = System::uptime();

    let system_info = SystemInfo {
        hostname,
        os_name,
        os_version,
        kernel_version,
        architecture,
        uptime,
    };

    Ok(HttpResponse::Ok().json(system_info))
}

pub async fn get_cpu_info() -> Result<impl Responder, AppError> {
    let mut sys = System::new_all();
    sys.refresh_cpu();

    std::thread::sleep(std::time::Duration::from_millis(200));
    sys.refresh_cpu();

    let cpus = sys.cpus();
    let cpu = cpus.first().ok_or(AppError::InternalError)?;

    let total_usage: f32 = cpus.iter().map(|c| c.cpu_usage()).sum::<f32>() / cpus.len() as f32;

    // 获取每个核心的使用率
    let per_core_usage: Vec<CpuCoreUsage> = cpus
        .iter()
        .enumerate()
        .map(|(idx, c)| CpuCoreUsage {
            core_id: idx,
            usage: c.cpu_usage(),
            frequency: c.frequency(),
        })
        .collect();

    // 获取 CPU 核心架构信息 (ARM big.LITTLE 等)
    let hw_caps = hardware::detect_hardware();
    let core_types: Vec<CpuCoreArchInfo> = hw_caps.cpu_core_types
        .into_iter()
        .map(|ct| CpuCoreArchInfo {
            core_name: ct.core_name,
            part_id: ct.part_id,
            count: ct.count,
            implementer: ct.implementer,
        })
        .collect();

    let cpu_info = CpuInfo {
        name: cpu.name().to_string(),
        vendor: cpu.vendor_id().to_string(),
        brand: cpu.brand().to_string(),
        frequency: cpu.frequency(),
        cores: cpus.len(),
        usage: total_usage,
        temperature: get_cpu_temperature(),
        per_core_usage,
        core_types,
    };

    Ok(HttpResponse::Ok().json(cpu_info))
}

pub async fn get_memory_info() -> Result<impl Responder, AppError> {
    let mut sys = System::new_all();
    sys.refresh_memory();

    let total = sys.total_memory();
    let used = sys.used_memory();
    let available = sys.available_memory();
    let usage_percentage = (used as f64 / total as f64) * 100.0;

    let memory_info = MemoryInfo {
        total,
        used,
        available,
        usage_percentage,
        swap_total: sys.total_swap(),
        swap_used: sys.used_swap(),
    };

    Ok(HttpResponse::Ok().json(memory_info))
}

pub async fn get_disk_info() -> Result<impl Responder, AppError> {
    // 获取所有块设备信息（包括未挂载的）
    let block_devices = hardware::get_all_block_devices();
    let mut disks = Vec::new();
    let mut seen_devices: std::collections::HashSet<String> = std::collections::HashSet::new();

    // 首先添加所有块设备
    for block_dev in block_devices {
        // 跳过虚拟设备
        if block_dev.name.starts_with("loop") 
            || block_dev.name.starts_with("ram") 
            || block_dev.name.starts_with("zram")
            || block_dev.name.starts_with("dm-") {
            continue;
        }

        // 跳过 eMMC boot 分区 (mmcblk*boot0, mmcblk*boot1)
        if block_dev.name.contains("boot0") 
            || block_dev.name.contains("boot1")
            || block_dev.name.contains("rpmb") {
            continue;
        }

        // 如果设备有分区，添加分区信息
        if !block_dev.partitions.is_empty() {
            for partition in &block_dev.partitions {
                let device_key = partition.device_path.clone();
                if seen_devices.contains(&device_key) {
                    continue;
                }
                seen_devices.insert(device_key.clone());

                let mount_point = partition.mount_point.clone().unwrap_or_else(|| "Not mounted".to_string());
                let file_system = partition.file_system.clone().unwrap_or_else(|| "Unknown".to_string());
                
                // 跳过 VFAT/FAT 格式的磁盘（通常是 /boot 分区）
                let fs_upper = file_system.to_uppercase();
                if fs_upper == "VFAT" || fs_upper == "FAT32" || fs_upper == "FAT16" || fs_upper == "FAT" {
                    continue;
                }
                
                // 跳过 /boot 分区
                if mount_point == "/boot" || mount_point.starts_with("/boot/") {
                    continue;
                }
                
                // 跳过系统虚拟文件系统
                if mount_point.starts_with("/sys")
                    || mount_point.starts_with("/proc")
                    || mount_point.starts_with("/dev") && !mount_point.starts_with("/dev/shm")
                    || mount_point.starts_with("/run")
                    || mount_point.contains("/snap/")
                    || file_system == "squashfs"
                    || file_system == "tmpfs"
                    || file_system == "devtmpfs"
                    || file_system == "overlay" {
                    continue;
                }

                // 跳过 eMMC boot 分区
                if partition.name.contains("boot0") 
                    || partition.name.contains("boot1")
                    || partition.name.contains("rpmb") {
                    continue;
                }

                let used_space = if partition.mount_point.is_some() {
                    partition.size - get_available_space(&partition.device_path).unwrap_or(partition.size)
                } else {
                    0
                };
                
                let usage_percentage = if partition.size > 0 {
                    (used_space as f64 / partition.size as f64) * 100.0
                } else {
                    0.0
                };

                disks.push(DiskInfo {
                    name: partition.name.clone(),
                    mount_point,
                    file_system,
                    total_space: partition.size,
                    available_space: partition.size - used_space,
                    used_space,
                    usage_percentage,
                    is_removable: block_dev.is_removable,
                    disk_type: block_dev.device_type.clone(),
                });
            }
        } else {
            // 没有分区的设备，显示整个设备
            let device_key = block_dev.device_path.clone();
            if seen_devices.contains(&device_key) {
                continue;
            }
            seen_devices.insert(device_key);

            disks.push(DiskInfo {
                name: block_dev.name.clone(),
                mount_point: "Not mounted".to_string(),
                file_system: "Unknown".to_string(),
                total_space: block_dev.size,
                available_space: block_dev.size,
                used_space: 0,
                usage_percentage: 0.0,
                is_removable: block_dev.is_removable,
                disk_type: block_dev.device_type,
            });
        }
    }

    // 按挂载点排序
    disks.sort_by(|a, b| {
        if a.mount_point == "/" {
            return std::cmp::Ordering::Less;
        }
        if b.mount_point == "/" {
            return std::cmp::Ordering::Greater;
        }
        if a.mount_point == "Not mounted" && b.mount_point != "Not mounted" {
            return std::cmp::Ordering::Greater;
        }
        if b.mount_point == "Not mounted" && a.mount_point != "Not mounted" {
            return std::cmp::Ordering::Less;
        }
        a.mount_point.cmp(&b.mount_point)
    });

    Ok(HttpResponse::Ok().json(disks))
}

#[cfg(target_os = "linux")]
fn get_available_space(device_path: &str) -> Option<u64> {
    use std::fs;
    
    // 从 /proc/mounts 查找挂载点
    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[0] == device_path {
                let mount_point = parts[1];
                // 使用 statvfs 获取可用空间
                let disks_info = Disks::new_with_refreshed_list();
                for disk in disks_info.list() {
                    if disk.mount_point().to_string_lossy() == mount_point {
                        return Some(disk.available_space());
                    }
                }
            }
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn get_available_space(_device_path: &str) -> Option<u64> {
    None
}

pub async fn get_usb_devices() -> Result<impl Responder, AppError> {
    let usb_devices = detect_usb_devices();
    Ok(HttpResponse::Ok().json(usb_devices))
}

pub async fn get_network_interfaces() -> Result<impl Responder, AppError> {
    let interfaces = detect_network_interfaces();
    Ok(HttpResponse::Ok().json(interfaces))
}

pub async fn get_block_devices() -> Result<impl Responder, AppError> {
    let devices = hardware::get_all_block_devices();
    Ok(HttpResponse::Ok().json(devices))
}

pub async fn get_hardware_info() -> Result<impl Responder, AppError> {
    use tracing::{info, error};
    
    info!("🔍 Starting hardware info collection...");
    
    let mut sys = System::new_all();
    sys.refresh_all();

    std::thread::sleep(std::time::Duration::from_millis(200));
    sys.refresh_cpu();

    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());
    let os_name = System::name().unwrap_or_else(|| "unknown".to_string());
    let os_version = System::os_version().unwrap_or_else(|| "unknown".to_string());
    let kernel_version = System::kernel_version().unwrap_or_else(|| "unknown".to_string());
    let architecture = std::env::consts::ARCH.to_string();
    let uptime = System::uptime();

    let system_info = SystemInfo {
        hostname,
        os_name,
        os_version,
        kernel_version,
        architecture,
        uptime,
    };
    info!("✅ System info collected");

    let cpus = sys.cpus();
    if cpus.is_empty() {
        error!("❌ No CPU information available");
        return Err(AppError::InternalError);
    }
    
    let cpu = cpus.first().unwrap();
    let total_usage: f32 = cpus.iter().map(|c| c.cpu_usage()).sum::<f32>() / cpus.len() as f32;

    // 获取每个核心的使用率
    let per_core_usage: Vec<CpuCoreUsage> = cpus
        .iter()
        .enumerate()
        .map(|(idx, c)| CpuCoreUsage {
            core_id: idx,
            usage: c.cpu_usage(),
            frequency: c.frequency(),
        })
        .collect();

    // 获取 CPU 核心架构信息 (ARM big.LITTLE 等)
    let hw_caps = hardware::detect_hardware();
    let core_types: Vec<CpuCoreArchInfo> = hw_caps.cpu_core_types
        .into_iter()
        .map(|ct| CpuCoreArchInfo {
            core_name: ct.core_name,
            part_id: ct.part_id,
            count: ct.count,
            implementer: ct.implementer,
        })
        .collect();

    let cpu_info = CpuInfo {
        name: cpu.name().to_string(),
        vendor: cpu.vendor_id().to_string(),
        brand: cpu.brand().to_string(),
        frequency: cpu.frequency(),
        cores: cpus.len(),
        usage: total_usage,
        temperature: get_cpu_temperature(),
        per_core_usage,
        core_types,
    };
    info!("✅ CPU info collected: {} cores, {:.1}% usage", cpus.len(), total_usage);

    let total_mem = sys.total_memory();
    let used_mem = sys.used_memory();
    let available_mem = sys.available_memory();
    let usage_percentage = if total_mem > 0 {
        (used_mem as f64 / total_mem as f64) * 100.0
    } else {
        0.0
    };

    let memory_info = MemoryInfo {
        total: total_mem,
        used: used_mem,
        available: available_mem,
        usage_percentage,
        swap_total: sys.total_swap(),
        swap_used: sys.used_swap(),
    };
    info!("✅ Memory info collected: {:.1}% used", usage_percentage);

    let disks_info = Disks::new_with_refreshed_list();
    let mut disks = Vec::new();
    for disk in disks_info.list() {
        let total_space = disk.total_space();
        let available_space = disk.available_space();
        let used_space = total_space.saturating_sub(available_space);
        let disk_usage_percentage = if total_space > 0 {
            (used_space as f64 / total_space as f64) * 100.0
        } else {
            0.0
        };

        disks.push(DiskInfo {
            name: disk.name().to_string_lossy().to_string(),
            mount_point: disk.mount_point().to_string_lossy().to_string(),
            file_system: disk.file_system().to_string_lossy().to_string(),
            total_space,
            available_space,
            used_space,
            usage_percentage: disk_usage_percentage,
            is_removable: disk.is_removable(),
            disk_type: format!("{:?}", disk.kind()),
        });
    }
    info!("✅ Disk info collected: {} disks", disks.len());

    let usb_devices = detect_usb_devices();
    info!("✅ USB devices collected: {} devices", usb_devices.len());
    
    let network_interfaces = detect_network_interfaces();
    info!("✅ Network interfaces collected: {} interfaces", network_interfaces.len());

    let hardware_info = HardwareInfo {
        system: system_info,
        cpu: cpu_info,
        memory: memory_info,
        disks,
        usb_devices,
        network_interfaces,
    };

    info!("✅ Hardware info collection complete");
    Ok(HttpResponse::Ok().json(hardware_info))
}

#[cfg(target_os = "linux")]
fn get_cpu_temperature() -> Option<f32> {
    let thermal_zones = [
        "/sys/class/thermal/thermal_zone0/temp",
        "/sys/class/thermal/thermal_zone1/temp",
        "/sys/devices/virtual/thermal/thermal_zone0/temp",
    ];

    for zone in &thermal_zones {
        if let Ok(temp_str) = fs::read_to_string(zone) {
            if let Ok(temp) = temp_str.trim().parse::<f32>() {
                return Some(temp / 1000.0);
            }
        }
    }

    None
}

#[cfg(not(target_os = "linux"))]
fn get_cpu_temperature() -> Option<f32> {
    None
}

#[cfg(target_os = "linux")]
fn detect_usb_devices() -> Vec<UsbDevice> {
    let detailed = hardware::detect_usb_devices_detailed();
    let disks_info = Disks::new_with_refreshed_list();
    let mut used_mount_points: std::collections::HashSet<String> = std::collections::HashSet::new();

    let mut available_usb_mounts: Vec<(String, u64)> = Vec::new();
    for disk in disks_info.list() {
        let mount_point = disk.mount_point().to_string_lossy().to_string();
        if disk.is_removable()
            && (mount_point.starts_with("/mnt/") || mount_point.starts_with("/media/"))
        {
            available_usb_mounts.push((mount_point, disk.total_space()));
        }
    }

    detailed
        .into_iter()
        .filter_map(|d| {
            if d.device_class != "Mass Storage" && !d.device_class.contains("Storage") {
                return Some(UsbDevice {
                    name: d.name,
                    vendor_id: d.vendor_id,
                    product_id: d.product_id,
                    manufacturer: Some(d.manufacturer),
                    device_class: d.device_class,
                    mount_point: None,
                    size: None,
                    serial: d.serial,
                    speed: d.speed,
                });
            }

            let (mount_point, size) = if let Some(mp) = &d.mount_point {
                if !used_mount_points.contains(mp) {
                    used_mount_points.insert(mp.clone());
                    let sz = disks_info
                        .list()
                        .iter()
                        .find(|disk| disk.mount_point().to_string_lossy() == *mp)
                        .map(|disk| disk.total_space());
                    (Some(mp.clone()), sz)
                } else {
                    let alt = available_usb_mounts
                        .iter()
                        .find(|(m, _)| !used_mount_points.contains(m))
                        .map(|(m, s)| (m.clone(), *s));
                    if let Some((alt_mp, alt_sz)) = alt {
                        used_mount_points.insert(alt_mp.clone());
                        (Some(alt_mp), Some(alt_sz))
                    } else {
                        (None, None)
                    }
                }
            } else {
                let alt = available_usb_mounts
                    .iter()
                    .find(|(m, _)| !used_mount_points.contains(m))
                    .map(|(m, s)| (m.clone(), *s));
                if let Some((alt_mp, alt_sz)) = alt {
                    used_mount_points.insert(alt_mp.clone());
                    (Some(alt_mp), Some(alt_sz))
                } else {
                    (None, None)
                }
            };

            Some(UsbDevice {
                name: d.name,
                vendor_id: d.vendor_id,
                product_id: d.product_id,
                manufacturer: Some(d.manufacturer),
                device_class: d.device_class,
                mount_point,
                size,
                serial: d.serial,
                speed: d.speed,
            })
        })
        .collect()
}

#[cfg(not(target_os = "linux"))]
fn detect_usb_devices() -> Vec<UsbDevice> {
    Vec::new()
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn get_mount_size(mount_point: &str) -> Option<u64> {
    let disks_info = Disks::new_with_refreshed_list();

    for disk in disks_info.list() {
        if disk.mount_point().to_string_lossy() == mount_point {
            return Some(disk.total_space());
        }
    }
    None
}

/// 检测网络接口
fn detect_network_interfaces() -> Vec<NetworkInterfaceInfo> {
    let networks = Networks::new_with_refreshed_list();
    let mut interfaces = Vec::new();

    for (name, data) in networks.iter() {
        let mac_address = data.mac_address().to_string();

        // 获取 IP 地址和接口详情
        let (ip_addresses, is_up, speed_mbps, interface_type) = get_interface_info(name);

        interfaces.push(NetworkInterfaceInfo {
            name: name.clone(),
            mac_address,
            ip_addresses,
            is_up,
            speed_mbps,
            interface_type,
            rx_bytes: data.total_received(),
            tx_bytes: data.total_transmitted(),
        });
    }

    // 按类型排序
    interfaces.sort_by(|a, b| {
        let type_order = |t: &str| match t {
            "Ethernet" => 0,
            "WiFi" => 1,
            "Bridge" => 2,
            _ => 3,
        };
        type_order(&a.interface_type).cmp(&type_order(&b.interface_type))
    });

    interfaces
}

#[cfg(target_os = "linux")]
fn get_interface_info(name: &str) -> (Vec<String>, bool, Option<u64>, String) {
    let sys_path = format!("/sys/class/net/{}", name);
    let mut ips = Vec::new();

    // 获取 IP 地址
    if let Ok(output) = std::process::Command::new("ip")
        .args(["addr", "show", name])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if line.starts_with("inet ") {
                if let Some(ip) = line.split_whitespace().nth(1) {
                    ips.push(ip.split('/').next().unwrap_or(ip).to_string());
                }
            }
        }
    }

    // 检查接口状态
    let is_up = fs::read_to_string(format!("{}/operstate", sys_path))
        .map(|s| s.trim() == "up")
        .unwrap_or(false);

    // 获取速度
    let speed_mbps = fs::read_to_string(format!("{}/speed", sys_path))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&s| s > 0 && s < 1000000);

    // 判断接口类型
    let interface_type = if name == "lo" {
        "Loopback"
    } else if name.starts_with("eth") || name.starts_with("en") {
        "Ethernet"
    } else if name.starts_with("wlan") || name.starts_with("wl") {
        "WiFi"
    } else if name.starts_with("br") || name.starts_with("docker") {
        "Bridge"
    } else if name.starts_with("veth") || name.starts_with("tap") {
        "Virtual"
    } else {
        "Unknown"
    }
    .to_string();

    (ips, is_up, speed_mbps, interface_type)
}

#[cfg(not(target_os = "linux"))]
fn get_interface_info(_name: &str) -> (Vec<String>, bool, Option<u64>, String) {
    (Vec::new(), false, None, "Unknown".to_string())
}

#[allow(dead_code)]
pub async fn get_hardware_capabilities() -> Result<impl Responder, AppError> {
    let capabilities = crate::hardware::detect_hardware();
    Ok(HttpResponse::Ok().json(capabilities))
}
