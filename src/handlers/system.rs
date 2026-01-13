use actix_web::{HttpResponse, Responder};
use serde::Serialize;
use sysinfo::{Disks, Networks, System};

#[cfg(target_os = "linux")]
use std::fs;

use crate::error::AppError;
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

#[derive(Debug, Serialize)]
pub struct CpuInfo {
    pub name: String,
    pub vendor: String,
    pub brand: String,
    pub frequency: u64,
    pub cores: usize,
    pub usage: f32,
    pub temperature: Option<f32>,
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

    let cpu_info = CpuInfo {
        name: cpu.name().to_string(),
        vendor: cpu.vendor_id().to_string(),
        brand: cpu.brand().to_string(),
        frequency: cpu.frequency(),
        cores: cpus.len(),
        usage: total_usage,
        temperature: get_cpu_temperature(),
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
    let disks_info = Disks::new_with_refreshed_list();
    let mut disks = Vec::new();
    let mut seen_devices: std::collections::HashSet<(u64, String)> = std::collections::HashSet::new();

    for disk in disks_info.list() {
        let total_space = disk.total_space();
        let available_space = disk.available_space();
        let used_space = total_space - available_space;
        let usage_percentage = if total_space > 0 {
            (used_space as f64 / total_space as f64) * 100.0
        } else {
            0.0
        };

        let mount_point = disk.mount_point().to_string_lossy().to_string();
        let is_removable = disk.is_removable();
        let disk_type = format!("{:?}", disk.kind());
        let name = disk.name().to_string_lossy().to_string();
        let file_system = disk.file_system().to_string_lossy().to_string();

        // 跳过虚拟文件系统和特殊挂载点
        if mount_point.starts_with("/sys") 
            || mount_point.starts_with("/proc") 
            || mount_point.starts_with("/dev") && !mount_point.starts_with("/dev/shm")
            || mount_point.starts_with("/run")
            || mount_point.contains("/snap/")
            || file_system == "squashfs"
            || file_system == "tmpfs"
            || file_system == "devtmpfs"
            || file_system == "overlay"
        {
            continue;
        }

        // 使用设备大小和文件系统作为唯一标识，避免重复（如 /var/log.hdd 和 / 指向同一设备）
        let device_key = (total_space, file_system.clone());
        if seen_devices.contains(&device_key) && total_space > 0 {
            // 如果已经有相同大小和文件系统的设备，优先保留根目录或更短的挂载点
            let existing_idx = disks.iter().position(|d: &DiskInfo| {
                d.total_space == total_space && d.file_system == file_system
            });
            if let Some(idx) = existing_idx {
                // 如果当前挂载点是根目录或更短，替换现有的
                if mount_point == "/" || mount_point.len() < disks[idx].mount_point.len() {
                    disks[idx] = DiskInfo {
                        name: name.clone(),
                        mount_point: mount_point.clone(),
                        file_system: file_system.clone(),
                        total_space,
                        available_space,
                        used_space,
                        usage_percentage,
                        is_removable,
                        disk_type: disk_type.clone(),
                    };
                }
            }
            continue;
        }
        seen_devices.insert(device_key);

        disks.push(DiskInfo {
            name,
            mount_point,
            file_system,
            total_space,
            available_space,
            used_space,
            usage_percentage,
            is_removable,
            disk_type,
        });
    }

    // 按挂载点排序：根目录优先，然后是 /boot，最后是其他
    disks.sort_by(|a, b| {
        if a.mount_point == "/" { return std::cmp::Ordering::Less; }
        if b.mount_point == "/" { return std::cmp::Ordering::Greater; }
        if a.mount_point == "/boot" { return std::cmp::Ordering::Less; }
        if b.mount_point == "/boot" { return std::cmp::Ordering::Greater; }
        a.mount_point.cmp(&b.mount_point)
    });

    Ok(HttpResponse::Ok().json(disks))
}

pub async fn get_usb_devices() -> Result<impl Responder, AppError> {
    let usb_devices = detect_usb_devices();
    Ok(HttpResponse::Ok().json(usb_devices))
}

/// 获取网络接口信息
pub async fn get_network_interfaces() -> Result<impl Responder, AppError> {
    let interfaces = detect_network_interfaces();
    Ok(HttpResponse::Ok().json(interfaces))
}

/// 获取块设备信息（包括未挂载的）
pub async fn get_block_devices() -> Result<impl Responder, AppError> {
    let devices = hardware::get_all_block_devices();
    Ok(HttpResponse::Ok().json(devices))
}

pub async fn get_hardware_info() -> Result<impl Responder, AppError> {
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

    let cpus = sys.cpus();
    let cpu = cpus.first().ok_or(AppError::InternalError)?;
    let total_usage: f32 = cpus.iter().map(|c| c.cpu_usage()).sum::<f32>() / cpus.len() as f32;

    let cpu_info = CpuInfo {
        name: cpu.name().to_string(),
        vendor: cpu.vendor_id().to_string(),
        brand: cpu.brand().to_string(),
        frequency: cpu.frequency(),
        cores: cpus.len(),
        usage: total_usage,
        temperature: get_cpu_temperature(),
    };

    let total_mem = sys.total_memory();
    let used_mem = sys.used_memory();
    let available_mem = sys.available_memory();
    let usage_percentage = (used_mem as f64 / total_mem as f64) * 100.0;

    let memory_info = MemoryInfo {
        total: total_mem,
        used: used_mem,
        available: available_mem,
        usage_percentage,
        swap_total: sys.total_swap(),
        swap_used: sys.used_swap(),
    };

    let disks_info = Disks::new_with_refreshed_list();
    let mut disks = Vec::new();
    for disk in disks_info.list() {
        let total_space = disk.total_space();
        let available_space = disk.available_space();
        let used_space = total_space - available_space;
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

    let usb_devices = detect_usb_devices();
    let network_interfaces = detect_network_interfaces();

    let hardware_info = HardwareInfo {
        system: system_info,
        cpu: cpu_info,
        memory: memory_info,
        disks,
        usb_devices,
        network_interfaces,
    };

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
    
    // 首先收集所有可用的 USB 存储挂载点
    let mut available_usb_mounts: Vec<(String, u64)> = Vec::new();
    for disk in disks_info.list() {
        let mount_point = disk.mount_point().to_string_lossy().to_string();
        if disk.is_removable() && (mount_point.starts_with("/mnt/") || mount_point.starts_with("/media/")) {
            available_usb_mounts.push((mount_point, disk.total_space()));
        }
    }
    
    detailed.into_iter().filter_map(|d| {
        // 只处理存储设备
        if d.device_class != "Mass Storage" && !d.device_class.contains("Storage") {
            // 非存储设备，直接返回
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
        
        // 对于存储设备，查找挂载点
        let (mount_point, size) = if let Some(mp) = &d.mount_point {
            if !used_mount_points.contains(mp) {
                used_mount_points.insert(mp.clone());
                let sz = disks_info.list().iter()
                    .find(|disk| disk.mount_point().to_string_lossy() == *mp)
                    .map(|disk| disk.total_space());
                (Some(mp.clone()), sz)
            } else {
                // 挂载点已被使用，尝试找另一个可用的挂载点
                let alt = available_usb_mounts.iter()
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
            // 没有挂载点，尝试从可用列表中分配一个
            let alt = available_usb_mounts.iter()
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
    }).collect()
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
    }.to_string();
    
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
