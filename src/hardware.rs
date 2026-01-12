use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareCapabilities {
    pub architecture: String,
    pub cpu_model: String,
    pub cpu_cores: usize,
    pub total_memory: u64,
    pub video_acceleration: Vec<VideoAccelerator>,
    pub audio_devices: Vec<AudioDevice>,
    pub storage_devices: Vec<StorageDevice>,
    pub usb_controllers: Vec<UsbController>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoAccelerator {
    pub name: String,
    pub device_path: String,
    pub codec_support: Vec<String>,
    pub max_resolution: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioDevice {
    pub name: String,
    pub device_path: String,
    pub channels: u32,
    pub sample_rates: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageDevice {
    pub name: String,
    pub device_path: String,
    pub mount_point: Option<String>,
    pub total_size: u64,
    pub available_size: u64,
    pub device_type: StorageType,
    pub is_removable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageType {
    HDD,
    SSD,
    NVMe,
    MMC,
    USB,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbController {
    pub name: String,
    pub version: String,
    pub ports: u32,
}

pub fn detect_hardware() -> HardwareCapabilities {
    let mut sys = System::new_all();
    sys.refresh_all();

    let architecture = std::env::consts::ARCH.to_string();
    
    let cpu_model = sys.cpus()
        .first()
        .map(|cpu| cpu.brand().to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    
    let cpu_cores = sys.cpus().len();
    let total_memory = sys.total_memory();

    let video_acceleration = detect_video_accelerators(&architecture);
    let audio_devices = detect_audio_devices();
    let storage_devices = detect_storage_devices(&mut sys);
    let usb_controllers = detect_usb_controllers();

    HardwareCapabilities {
        architecture,
        cpu_model,
        cpu_cores,
        total_memory,
        video_acceleration,
        audio_devices,
        storage_devices,
        usb_controllers,
    }
}

fn detect_video_accelerators(arch: &str) -> Vec<VideoAccelerator> {
    let mut accelerators = Vec::new();

    match arch {
        "aarch64" | "arm" | "armv7" => {
            if Path::new("/dev/video10").exists() {
                accelerators.push(VideoAccelerator {
                    name: "Rockchip MPP".to_string(),
                    device_path: "/dev/video10".to_string(),
                    codec_support: vec![
                        "H.264".to_string(),
                        "H.265".to_string(),
                        "VP8".to_string(),
                        "VP9".to_string(),
                    ],
                    max_resolution: "4K@60fps".to_string(),
                });
            }

            if Path::new("/dev/meson-vdec").exists() {
                accelerators.push(VideoAccelerator {
                    name: "Amlogic VDEC".to_string(),
                    device_path: "/dev/meson-vdec".to_string(),
                    codec_support: vec![
                        "H.264".to_string(),
                        "H.265".to_string(),
                        "VP9".to_string(),
                        "AV1".to_string(),
                    ],
                    max_resolution: "4K@60fps".to_string(),
                });
            }

            if Path::new("/dev/video-codec").exists() {
                accelerators.push(VideoAccelerator {
                    name: "V4L2 M2M".to_string(),
                    device_path: "/dev/video-codec".to_string(),
                    codec_support: vec!["H.264".to_string(), "MPEG4".to_string()],
                    max_resolution: "1080p@30fps".to_string(),
                });
            }
        }
        "x86_64" | "x86" => {
            if Path::new("/dev/dri/renderD128").exists() {
                accelerators.push(VideoAccelerator {
                    name: "Intel VAAPI".to_string(),
                    device_path: "/dev/dri/renderD128".to_string(),
                    codec_support: vec![
                        "H.264".to_string(),
                        "H.265".to_string(),
                        "VP8".to_string(),
                        "VP9".to_string(),
                        "AV1".to_string(),
                    ],
                    max_resolution: "8K@60fps".to_string(),
                });
            }

            if Path::new("/dev/nvidia0").exists() {
                accelerators.push(VideoAccelerator {
                    name: "NVIDIA NVENC".to_string(),
                    device_path: "/dev/nvidia0".to_string(),
                    codec_support: vec![
                        "H.264".to_string(),
                        "H.265".to_string(),
                        "AV1".to_string(),
                    ],
                    max_resolution: "8K@60fps".to_string(),
                });
            }
        }
        _ => {}
    }

    accelerators
}

fn detect_audio_devices() -> Vec<AudioDevice> {
    let mut devices = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = fs::read_dir("/dev/snd") {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = path.file_name().unwrap().to_string_lossy().to_string();
                
                if name.starts_with("pcm") {
                    devices.push(AudioDevice {
                        name: format!("ALSA PCM Device {}", name),
                        device_path: path.to_string_lossy().to_string(),
                        channels: 2,
                        sample_rates: vec![44100, 48000, 96000, 192000],
                    });
                }
            }
        }
    }

    if devices.is_empty() {
        devices.push(AudioDevice {
            name: "Default Audio Device".to_string(),
            device_path: "/dev/snd/pcmC0D0p".to_string(),
            channels: 2,
            sample_rates: vec![44100, 48000],
        });
    }

    devices
}

fn detect_storage_devices(sys: &mut System) -> Vec<StorageDevice> {
    let mut devices = Vec::new();

    for disk in sys.disks() {
        let name = disk.name().to_string_lossy().to_string();
        let device_path = name.clone();
        let mount_point = Some(disk.mount_point().to_string_lossy().to_string());
        let total_size = disk.total_space();
        let available_size = disk.available_space();
        let is_removable = disk.is_removable();

        let device_type = if is_removable {
            StorageType::USB
        } else if name.contains("nvme") {
            StorageType::NVMe
        } else if name.contains("mmc") {
            StorageType::MMC
        } else if name.contains("sd") {
            StorageType::SSD
        } else {
            StorageType::Unknown
        };

        devices.push(StorageDevice {
            name,
            device_path,
            mount_point,
            total_size,
            available_size,
            device_type,
            is_removable,
        });
    }

    devices
}

fn detect_usb_controllers() -> Vec<UsbController> {
    let mut controllers = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") {
            for entry in entries.flatten() {
                let path = entry.path();
                
                if let Ok(version) = fs::read_to_string(path.join("version")) {
                    let version = version.trim().to_string();
                    
                    if let Ok(max_child) = fs::read_to_string(path.join("maxchild")) {
                        if let Ok(ports) = max_child.trim().parse::<u32>() {
                            if ports > 0 {
                                controllers.push(UsbController {
                                    name: format!("USB {} Controller", version),
                                    version,
                                    ports,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    if controllers.is_empty() {
        controllers.push(UsbController {
            name: "USB Controller".to_string(),
            version: "2.0".to_string(),
            ports: 4,
        });
    }

    controllers
}

#[cfg(target_os = "linux")]
pub fn detect_usb_devices_detailed() -> Vec<UsbDeviceInfo> {
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

            let manufacturer = fs::read_to_string(path.join("manufacturer"))
                .unwrap_or_else(|_| "Unknown".to_string())
                .trim()
                .to_string();

            if !vendor_id.is_empty() && !product_id.is_empty() {
                devices.push(UsbDeviceInfo {
                    name: product_name,
                    vendor_id,
                    product_id,
                    manufacturer,
                    device_class: detect_device_class(&path),
                    mount_point: find_device_mount_point(&vendor_id, &product_id),
                });
            }
        }
    }

    devices
}

#[cfg(not(target_os = "linux"))]
pub fn detect_usb_devices_detailed() -> Vec<UsbDeviceInfo> {
    Vec::new()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDeviceInfo {
    pub name: String,
    pub vendor_id: String,
    pub product_id: String,
    pub manufacturer: String,
    pub device_class: String,
    pub mount_point: Option<String>,
}

#[cfg(target_os = "linux")]
fn detect_device_class(device_path: &Path) -> String {
    if let Ok(class) = fs::read_to_string(device_path.join("bDeviceClass")) {
        let class_code = class.trim();
        match class_code {
            "00" => "Device".to_string(),
            "01" => "Audio".to_string(),
            "02" => "Communications".to_string(),
            "03" => "HID".to_string(),
            "05" => "Physical".to_string(),
            "06" => "Image".to_string(),
            "07" => "Printer".to_string(),
            "08" => "Mass Storage".to_string(),
            "09" => "Hub".to_string(),
            "0a" => "CDC-Data".to_string(),
            "0b" => "Smart Card".to_string(),
            "0d" => "Content Security".to_string(),
            "0e" => "Video".to_string(),
            "0f" => "Personal Healthcare".to_string(),
            "dc" => "Diagnostic".to_string(),
            "e0" => "Wireless".to_string(),
            "ef" => "Miscellaneous".to_string(),
            "fe" => "Application Specific".to_string(),
            "ff" => "Vendor Specific".to_string(),
            _ => format!("Unknown ({})", class_code),
        }
    } else {
        "Unknown".to_string()
    }
}

#[cfg(target_os = "linux")]
fn find_device_mount_point(_vendor_id: &str, _product_id: &str) -> Option<String> {
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
