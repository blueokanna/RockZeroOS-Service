use actix_web::{HttpResponse, Responder};
use serde::Serialize;
use std::fs;
use sysinfo::System;

use crate::error::AppError;

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
    pub mount_point: Option<String>,
    pub size: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct HardwareInfo {
    pub system: SystemInfo,
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub disks: Vec<DiskInfo>,
    pub usb_devices: Vec<UsbDevice>,
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
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut disks = Vec::new();

    for disk in sys.disks() {
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

        disks.push(DiskInfo {
            name: disk.name().to_string_lossy().to_string(),
            mount_point,
            file_system: String::from_utf8_lossy(disk.file_system()).to_string(),
            total_space,
            available_space,
            used_space,
            usage_percentage,
            is_removable,
            disk_type,
        });
    }

    Ok(HttpResponse::Ok().json(disks))
}

pub async fn get_usb_devices() -> Result<impl Responder, AppError> {
    let usb_devices = detect_usb_devices();
    Ok(HttpResponse::Ok().json(usb_devices))
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

    let mut disks = Vec::new();
    for disk in sys.disks() {
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
            file_system: String::from_utf8_lossy(disk.file_system()).to_string(),
            total_space,
            available_space,
            used_space,
            usage_percentage: disk_usage_percentage,
            is_removable: disk.is_removable(),
            disk_type: format!("{:?}", disk.kind()),
        });
    }

    let usb_devices = detect_usb_devices();

    let hardware_info = HardwareInfo {
        system: system_info,
        cpu: cpu_info,
        memory: memory_info,
        disks,
        usb_devices,
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
    let mut devices = Vec::new();

    if let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") {
        for entry in entries.flatten() {
            let path = entry.path();
            
            let vendor_id = fs::read_to_string(path.join("idVendor"))
                .unwrap_or_default()
                .trim()
                .to_string();
            
            let product_id = fs::read_to_string(path.join("idProduct"))
                .unwrap_or_default()
                .trim()
                .to_string();
            
            let product_name = fs::read_to_string(path.join("product"))
                .unwrap_or_else(|_| "Unknown USB Device".to_string())
                .trim()
                .to_string();

            if !vendor_id.is_empty() && !product_id.is_empty() {
                let mount_point = find_usb_mount_point(&vendor_id, &product_id);
                let size = mount_point.as_ref().and_then(|mp| get_mount_size(mp));

                devices.push(UsbDevice {
                    name: product_name,
                    vendor_id,
                    product_id,
                    mount_point,
                    size,
                });
            }
        }
    }

    devices
}

#[cfg(not(target_os = "linux"))]
fn detect_usb_devices() -> Vec<UsbDevice> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn find_usb_mount_point(_vendor_id: &str, _product_id: &str) -> Option<String> {
    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let device = parts[0];
                let mount_point = parts[1];
                
                if device.starts_with("/dev/sd") || device.starts_with("/dev/mmcblk") {
                    if mount_point.starts_with("/media") || mount_point.starts_with("/mnt") {
                        return Some(mount_point.to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn get_mount_size(mount_point: &str) -> Option<u64> {
    let mut sys = System::new_all();
    sys.refresh_all();
    
    for disk in sys.disks() {
        if disk.mount_point().to_string_lossy() == mount_point {
            return Some(disk.total_space());
        }
    }
    None
}

pub async fn get_hardware_capabilities() -> Result<impl Responder, AppError> {
    let capabilities = crate::hardware::detect_hardware();
    Ok(HttpResponse::Ok().json(capabilities))
}
