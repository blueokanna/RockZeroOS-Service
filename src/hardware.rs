use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use sysinfo::{Disks, Networks, System};

#[cfg(target_os = "linux")]
use std::fs;

// ============ ARM CPU Part ID 映射表 ============

/// ARM CPU Part ID 到核心名称的映射
#[allow(dead_code)]
fn get_arm_cpu_part_map() -> HashMap<u64, &'static str> {
    let mut map = HashMap::new();
    // ARM Holdings
    map.insert(0x810, "ARM810");
    map.insert(0x920, "ARM920");
    map.insert(0x922, "ARM922");
    map.insert(0x926, "ARM926");
    map.insert(0x940, "ARM940");
    map.insert(0x946, "ARM946");
    map.insert(0x966, "ARM966");
    map.insert(0xa20, "ARM1020");
    map.insert(0xa22, "ARM1022");
    map.insert(0xa26, "ARM1026");
    map.insert(0xb02, "ARM11 MPCore");
    map.insert(0xb36, "ARM1136");
    map.insert(0xb56, "ARM1156");
    map.insert(0xb76, "ARM1176");
    // Cortex-A 系列
    map.insert(0xc05, "Cortex-A5");
    map.insert(0xc07, "Cortex-A7");
    map.insert(0xc08, "Cortex-A8");
    map.insert(0xc09, "Cortex-A9");
    map.insert(0xc0d, "Cortex-A12");
    map.insert(0xc0e, "Cortex-A17");
    map.insert(0xc0f, "Cortex-A15");
    map.insert(0xc14, "Cortex-R4");
    map.insert(0xc15, "Cortex-R5");
    map.insert(0xc17, "Cortex-R7");
    map.insert(0xc18, "Cortex-R8");
    // Cortex-M 系列
    map.insert(0xc20, "Cortex-M0");
    map.insert(0xc21, "Cortex-M1");
    map.insert(0xc23, "Cortex-M3");
    map.insert(0xc24, "Cortex-M4");
    map.insert(0xc27, "Cortex-M7");
    map.insert(0xc60, "Cortex-M0+");
    // ARMv8 Cortex-A 系列
    map.insert(0xd01, "Cortex-A32");
    map.insert(0xd02, "Cortex-A34");
    map.insert(0xd03, "Cortex-A53");
    map.insert(0xd04, "Cortex-A35");
    map.insert(0xd05, "Cortex-A55");
    map.insert(0xd06, "Cortex-A65");
    map.insert(0xd07, "Cortex-A57");
    map.insert(0xd08, "Cortex-A72");
    map.insert(0xd09, "Cortex-A73");
    map.insert(0xd0a, "Cortex-A75");
    map.insert(0xd0b, "Cortex-A76");
    map.insert(0xd0c, "Neoverse-N1");
    map.insert(0xd0d, "Cortex-A77");
    map.insert(0xd0e, "Cortex-A76AE");
    map.insert(0xd13, "Cortex-R52");
    map.insert(0xd20, "Cortex-M23");
    map.insert(0xd21, "Cortex-M33");
    map.insert(0xd40, "Neoverse-V1");
    map.insert(0xd41, "Cortex-A78");
    map.insert(0xd42, "Cortex-A78AE");
    map.insert(0xd43, "Cortex-A65AE");
    map.insert(0xd44, "Cortex-X1");
    map.insert(0xd46, "Cortex-A510");
    map.insert(0xd47, "Cortex-A710");
    map.insert(0xd48, "Cortex-X2");
    map.insert(0xd49, "Neoverse-N2");
    map.insert(0xd4a, "Neoverse-E1");
    map.insert(0xd4b, "Cortex-A78C");
    map.insert(0xd4c, "Cortex-X1C");
    map.insert(0xd4d, "Cortex-A715");
    map.insert(0xd4e, "Cortex-X3");
    map.insert(0xd4f, "Neoverse-V2");
    map.insert(0xd80, "Cortex-A520");
    map.insert(0xd81, "Cortex-A720");
    map.insert(0xd82, "Cortex-X4");
    map.insert(0xd84, "Neoverse-V3");
    map.insert(0xd85, "Cortex-X925");
    map.insert(0xd87, "Cortex-A725");
    map.insert(0xd8e, "Neoverse-N3");
    map
}

// ============ 数据结构定义 ============

/// CPU 核心信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuCoreInfo {
    /// 核心架构名称 (如 Cortex-A55, Cortex-A76)
    pub core_name: String,
    /// CPU Part ID (十六进制)
    pub part_id: String,
    /// 该类型核心的数量
    pub count: usize,
    /// CPU 实现者
    pub implementer: Option<String>,
    /// CPU 变体
    pub variant: Option<String>,
    /// CPU 修订版本
    pub revision: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareCapabilities {
    pub architecture: String,
    pub cpu_model: String,
    pub cpu_cores: usize,
    pub cpu_core_types: Vec<CpuCoreInfo>,
    pub total_memory: u64,
    pub video_acceleration: Vec<VideoAccelerator>,
    pub audio_devices: Vec<AudioDevice>,
    pub storage_devices: Vec<StorageDevice>,
    pub usb_controllers: Vec<UsbController>,
    pub network_interfaces: Vec<NetworkInterface>,
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
    pub serial: Option<String>,
    pub model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub enum StorageType {
    HDD,
    SSD,
    NVMe,
    MMC,
    USB,
    SATA,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbController {
    pub name: String,
    pub version: String,
    pub ports: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub mac_address: String,
    pub ip_addresses: Vec<String>,
    pub is_up: bool,
    pub speed: Option<u64>,
    pub interface_type: NetworkType,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkType {
    Ethernet,
    WiFi,
    Bridge,
    Virtual,
    Loopback,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct UsbDeviceInfo {
    pub name: String,
    pub vendor_id: String,
    pub product_id: String,
    pub manufacturer: String,
    pub device_class: String,
    pub mount_point: Option<String>,
    pub serial: Option<String>,
    pub speed: Option<String>,
}

// ============ 主检测函数 ============

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

    // 检测 CPU 核心类型（仅在 ARM 架构上）
    let cpu_core_types = detect_cpu_core_types(&architecture);

    let video_acceleration = detect_video_accelerators(&architecture);
    let audio_devices = detect_audio_devices();
    let storage_devices = detect_storage_devices();
    let usb_controllers = detect_usb_controllers();
    let network_interfaces = detect_network_interfaces();

    HardwareCapabilities {
        architecture,
        cpu_model,
        cpu_cores,
        cpu_core_types,
        total_memory,
        video_acceleration,
        audio_devices,
        storage_devices,
        usb_controllers,
        network_interfaces,
    }
}

// ============ CPU 核心类型检测 ============

/// 检测 CPU 核心类型（主要用于 ARM 架构）
fn detect_cpu_core_types(arch: &str) -> Vec<CpuCoreInfo> {
    match arch {
        "aarch64" | "arm" | "armv7" => {
            #[cfg(target_os = "linux")]
            {
                detect_arm_cpu_cores_linux()
            }
            #[cfg(not(target_os = "linux"))]
            {
                Vec::new()
            }
        }
        "x86_64" | "x86" => {
            // x86 架构返回简单信息
            detect_x86_cpu_info()
        }
        _ => Vec::new(),
    }
}

/// 在 Linux 上检测 ARM CPU 核心类型
#[cfg(target_os = "linux")]
fn detect_arm_cpu_cores_linux() -> Vec<CpuCoreInfo> {
    use std::collections::HashMap;
    
    let mut core_counts: HashMap<String, (String, String, Option<String>, Option<String>, Option<String>, usize)> = HashMap::new();
    let arm_part_map = get_arm_cpu_part_map();
    
    // 读取 /proc/cpuinfo
    if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
        let mut current_part: Option<String> = None;
        let mut current_implementer: Option<String> = None;
        let mut current_variant: Option<String> = None;
        let mut current_revision: Option<String> = None;
        
        for line in cpuinfo.lines() {
            let line = line.trim();
            
            if line.starts_with("CPU implementer") {
                if let Some(value) = line.split(':').nth(1) {
                    current_implementer = Some(value.trim().to_string());
                }
            } else if line.starts_with("CPU variant") {
                if let Some(value) = line.split(':').nth(1) {
                    current_variant = Some(value.trim().to_string());
                }
            } else if line.starts_with("CPU part") {
                if let Some(value) = line.split(':').nth(1) {
                    current_part = Some(value.trim().to_string());
                }
            } else if line.starts_with("CPU revision") {
                if let Some(value) = line.split(':').nth(1) {
                    current_revision = Some(value.trim().to_string());
                }
            } else if line.is_empty() {
                // 处理器条目结束，记录信息
                if let Some(ref part) = current_part {
                    let part_id = part.trim_start_matches("0x");
                    let part_num = u64::from_str_radix(part_id, 16).unwrap_or(0);
                    
                    let core_name = arm_part_map
                        .get(&part_num)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("Unknown (0x{:x})", part_num));
                    
                    let key = part.clone();
                    let entry = core_counts.entry(key).or_insert((
                        core_name,
                        part.clone(),
                        current_implementer.clone(),
                        current_variant.clone(),
                        current_revision.clone(),
                        0,
                    ));
                    entry.5 += 1;
                }
                
                // 重置当前处理器信息
                current_part = None;
                current_implementer = None;
                current_variant = None;
                current_revision = None;
            }
        }
        
        // 处理最后一个处理器（如果没有空行结尾）
        if let Some(ref part) = current_part {
            let part_id = part.trim_start_matches("0x");
            let part_num = u64::from_str_radix(part_id, 16).unwrap_or(0);
            
            let core_name = arm_part_map
                .get(&part_num)
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("Unknown (0x{:x})", part_num));
            
            let key = part.clone();
            let entry = core_counts.entry(key).or_insert((
                core_name,
                part.clone(),
                current_implementer.clone(),
                current_variant.clone(),
                current_revision.clone(),
                0,
            ));
            entry.5 += 1;
        }
    }
    
    // 转换为 Vec 并按核心数量排序
    let mut cores: Vec<CpuCoreInfo> = core_counts
        .into_iter()
        .map(|(_, (core_name, part_id, implementer, variant, revision, count))| {
            CpuCoreInfo {
                core_name,
                part_id,
                count,
                implementer: implementer.map(|i| get_implementer_name(&i)),
                variant,
                revision,
            }
        })
        .collect();
    
    // 按核心数量降序排序
    cores.sort_by(|a, b| b.count.cmp(&a.count));
    
    cores
}

/// 获取 CPU 实现者名称
#[cfg(target_os = "linux")]
fn get_implementer_name(implementer: &str) -> String {
    let code = implementer.trim_start_matches("0x");
    let num = u64::from_str_radix(code, 16).unwrap_or(0);
    
    match num {
        0x41 => "ARM".to_string(),
        0x42 => "Broadcom".to_string(),
        0x43 => "Cavium".to_string(),
        0x44 => "DEC".to_string(),
        0x46 => "Fujitsu".to_string(),
        0x48 => "HiSilicon".to_string(),
        0x49 => "Infineon".to_string(),
        0x4d => "Motorola/Freescale".to_string(),
        0x4e => "NVIDIA".to_string(),
        0x50 => "APM".to_string(),
        0x51 => "Qualcomm".to_string(),
        0x53 => "Samsung".to_string(),
        0x56 => "Marvell".to_string(),
        0x61 => "Apple".to_string(),
        0x66 => "Faraday".to_string(),
        0x69 => "Intel".to_string(),
        0x6d => "Microsoft".to_string(),
        0x70 => "Phytium".to_string(),
        0xc0 => "Ampere".to_string(),
        _ => format!("Unknown ({})", implementer),
    }
}

/// 检测 x86 CPU 信息
fn detect_x86_cpu_info() -> Vec<CpuCoreInfo> {
    let mut sys = System::new_all();
    sys.refresh_all();
    
    if let Some(cpu) = sys.cpus().first() {
        let brand = cpu.brand().to_string();
        let core_count = sys.cpus().len();
        
        vec![CpuCoreInfo {
            core_name: brand,
            part_id: "x86_64".to_string(),
            count: core_count,
            implementer: Some(cpu.vendor_id().to_string()),
            variant: None,
            revision: None,
        }]
    } else {
        Vec::new()
    }
}

// ============ 视频加速检测 ============

fn detect_video_accelerators(arch: &str) -> Vec<VideoAccelerator> {
    let mut accelerators = Vec::new();

    match arch {
        "aarch64" | "arm" | "armv7" => {
            // Rockchip MPP (RK3588, RK3399, etc.)
            if Path::new("/dev/video10").exists() || Path::new("/dev/mpp_service").exists() {
                accelerators.push(VideoAccelerator {
                    name: "Rockchip MPP".to_string(),
                    device_path: "/dev/mpp_service".to_string(),
                    codec_support: vec![
                        "H.264".to_string(), "H.265".to_string(),
                        "VP8".to_string(), "VP9".to_string(), "AV1".to_string(),
                    ],
                    max_resolution: "8K@30fps / 4K@120fps".to_string(),
                });
            }

            // Amlogic VDEC
            if Path::new("/dev/amvideo").exists() || Path::new("/dev/meson-vdec").exists() {
                accelerators.push(VideoAccelerator {
                    name: "Amlogic VDEC".to_string(),
                    device_path: "/dev/amvideo".to_string(),
                    codec_support: vec![
                        "H.264".to_string(), "H.265".to_string(),
                        "VP9".to_string(), "AV1".to_string(),
                    ],
                    max_resolution: "4K@60fps".to_string(),
                });
            }

            // V4L2 M2M (通用)
            for i in 0..10 {
                let path = format!("/dev/video{}", i);
                if Path::new(&path).exists() {
                    #[cfg(target_os = "linux")]
                    if is_v4l2_m2m_device(&path) {
                        accelerators.push(VideoAccelerator {
                            name: "V4L2 M2M Codec".to_string(),
                            device_path: path,
                            codec_support: vec!["H.264".to_string(), "MPEG4".to_string()],
                            max_resolution: "1080p@30fps".to_string(),
                        });
                        break;
                    }
                }
            }
        }
        "x86_64" | "x86" => {
            // Intel VAAPI
            if Path::new("/dev/dri/renderD128").exists() {
                accelerators.push(VideoAccelerator {
                    name: "Intel/AMD VAAPI".to_string(),
                    device_path: "/dev/dri/renderD128".to_string(),
                    codec_support: vec![
                        "H.264".to_string(), "H.265".to_string(),
                        "VP8".to_string(), "VP9".to_string(), "AV1".to_string(),
                    ],
                    max_resolution: "8K@60fps".to_string(),
                });
            }

            // NVIDIA NVENC
            if Path::new("/dev/nvidia0").exists() {
                accelerators.push(VideoAccelerator {
                    name: "NVIDIA NVENC/NVDEC".to_string(),
                    device_path: "/dev/nvidia0".to_string(),
                    codec_support: vec![
                        "H.264".to_string(), "H.265".to_string(), "AV1".to_string(),
                    ],
                    max_resolution: "8K@60fps".to_string(),
                });
            }
        }
        _ => {}
    }

    accelerators
}

#[cfg(target_os = "linux")]
fn is_v4l2_m2m_device(path: &str) -> bool {
    // 检查是否是 M2M 设备
    let caps_path = format!("/sys/class/video4linux/{}/device/capabilities", 
        Path::new(path).file_name().unwrap_or_default().to_string_lossy());
    if let Ok(caps) = fs::read_to_string(&caps_path) {
        return caps.contains("m2m") || caps.contains("codec");
    }
    false
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn is_v4l2_m2m_device(_path: &str) -> bool {
    false
}

// ============ 音频设备检测 ============

fn detect_audio_devices() -> Vec<AudioDevice> {
    let mut devices = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // 检测 ALSA 设备
        if let Ok(entries) = fs::read_dir("/dev/snd") {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = path.file_name().unwrap().to_string_lossy().to_string();
                
                if name.starts_with("pcmC") && name.contains("D") && name.ends_with("p") {
                    let card_num = name.chars()
                        .skip(4)
                        .take_while(|c| c.is_ascii_digit())
                        .collect::<String>();
                    
                    let card_name = get_alsa_card_name(&card_num);
                    
                    devices.push(AudioDevice {
                        name: card_name,
                        device_path: path.to_string_lossy().to_string(),
                        channels: 2,
                        sample_rates: vec![44100, 48000, 96000, 192000],
                    });
                }
            }
        }

        // 检测 PulseAudio/PipeWire
        if Path::new("/run/user/1000/pulse").exists() || Path::new("/run/user/1000/pipewire-0").exists() {
            devices.push(AudioDevice {
                name: "PulseAudio/PipeWire".to_string(),
                device_path: "pulse".to_string(),
                channels: 8,
                sample_rates: vec![44100, 48000, 96000, 192000, 384000],
            });
        }
    }

    if devices.is_empty() {
        devices.push(AudioDevice {
            name: "Default Audio".to_string(),
            device_path: "default".to_string(),
            channels: 2,
            sample_rates: vec![44100, 48000],
        });
    }

    devices
}

#[cfg(target_os = "linux")]
fn get_alsa_card_name(card_num: &str) -> String {
    let id_path = format!("/proc/asound/card{}/id", card_num);
    if let Ok(id) = fs::read_to_string(&id_path) {
        return format!("ALSA: {}", id.trim());
    }
    format!("ALSA Card {}", card_num)
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn get_alsa_card_name(_card_num: &str) -> String {
    "Audio Device".to_string()
}

// ============ 存储设备检测 ============

fn detect_storage_devices() -> Vec<StorageDevice> {
    let mut devices = Vec::new();
    let disks_info = Disks::new_with_refreshed_list();

    for disk in disks_info.list() {
        let name = disk.name().to_string_lossy().to_string();
        let mount_point = disk.mount_point().to_string_lossy().to_string();
        let total_size = disk.total_space();
        let available_size = disk.available_space();
        let is_removable = disk.is_removable();

        // 获取设备路径和详细信息
        let (device_path, serial, model, device_type) = get_storage_details(&name, is_removable);

        devices.push(StorageDevice {
            name: name.clone(),
            device_path,
            mount_point: Some(mount_point),
            total_size,
            available_size,
            device_type,
            is_removable,
            serial,
            model,
        });
    }

    // 检测未挂载的块设备
    #[cfg(target_os = "linux")]
    {
        detect_unmounted_block_devices(&mut devices);
    }

    devices
}

#[cfg(target_os = "linux")]
fn get_storage_details(name: &str, is_removable: bool) -> (String, Option<String>, Option<String>, StorageType) {
    let base_name = name.trim_start_matches("/dev/")
        .chars()
        .take_while(|c| !c.is_ascii_digit())
        .collect::<String>();
    
    let device_path = if name.starts_with("/dev/") {
        name.to_string()
    } else {
        format!("/dev/{}", name)
    };

    let sys_path = format!("/sys/block/{}", base_name);
    
    // 读取序列号
    let serial = fs::read_to_string(format!("{}/device/serial", sys_path))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    
    // 读取型号
    let model = fs::read_to_string(format!("{}/device/model", sys_path))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // 判断设备类型
    let device_type = if is_removable {
        StorageType::USB
    } else if base_name.starts_with("nvme") {
        StorageType::NVMe
    } else if base_name.starts_with("mmc") {
        StorageType::MMC
    } else if base_name.starts_with("sd") {
        // 检查是否是 SSD
        let rotational_path = format!("{}/queue/rotational", sys_path);
        if let Ok(rotational) = fs::read_to_string(&rotational_path) {
            if rotational.trim() == "0" {
                StorageType::SSD
            } else {
                StorageType::HDD
            }
        } else {
            StorageType::SATA
        }
    } else {
        StorageType::Unknown
    };

    (device_path, serial, model, device_type)
}

#[cfg(not(target_os = "linux"))]
fn get_storage_details(name: &str, is_removable: bool) -> (String, Option<String>, Option<String>, StorageType) {
    let device_type = if is_removable {
        StorageType::USB
    } else {
        StorageType::Unknown
    };
    (name.to_string(), None, None, device_type)
}

#[cfg(target_os = "linux")]
fn detect_unmounted_block_devices(devices: &mut Vec<StorageDevice>) {
    if let Ok(entries) = fs::read_dir("/sys/block") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            
            // 跳过虚拟设备
            if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("dm-") {
                continue;
            }

            // 检查是否已经在列表中
            if devices.iter().any(|d| d.name.contains(&name) || d.device_path.contains(&name)) {
                continue;
            }

            let sys_path = format!("/sys/block/{}", name);
            
            // 读取设备大小
            let size = fs::read_to_string(format!("{}/size", sys_path))
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .map(|sectors| sectors * 512)
                .unwrap_or(0);

            if size == 0 {
                continue;
            }

            let (device_path, serial, model, device_type) = get_storage_details(&name, false);

            devices.push(StorageDevice {
                name: name.clone(),
                device_path,
                mount_point: None,
                total_size: size,
                available_size: size,
                device_type,
                is_removable: false,
                serial,
                model,
            });
        }
    }
}

// ============ USB 控制器检测 ============

fn detect_usb_controllers() -> Vec<UsbController> {
    let mut controllers = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        if let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = path.file_name().unwrap().to_string_lossy().to_string();
                
                // 只处理根集线器 (usb1, usb2, etc.)
                if !name.starts_with("usb") {
                    continue;
                }

                if let Ok(version) = fs::read_to_string(path.join("version")) {
                    let version = version.trim().to_string();
                    
                    // 避免重复
                    if seen.contains(&version) {
                        continue;
                    }
                    
                    if let Ok(max_child) = fs::read_to_string(path.join("maxchild")) {
                        if let Ok(ports) = max_child.trim().parse::<u32>() {
                            if ports > 0 {
                                seen.insert(version.clone());
                                
                                let usb_name = match version.as_str() {
                                    v if v.starts_with("1.") => "USB 1.1 Controller (UHCI/OHCI)",
                                    v if v.starts_with("2.") => "USB 2.0 Controller (EHCI)",
                                    v if v.starts_with("3.0") => "USB 3.0 Controller (xHCI)",
                                    v if v.starts_with("3.1") => "USB 3.1 Controller (xHCI)",
                                    v if v.starts_with("3.2") => "USB 3.2 Controller (xHCI)",
                                    _ => "USB Controller",
                                };
                                
                                controllers.push(UsbController {
                                    name: usb_name.to_string(),
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

    // 按版本排序
    controllers.sort_by(|a: &UsbController, b: &UsbController| b.version.cmp(&a.version));

    if controllers.is_empty() {
        controllers.push(UsbController {
            name: "USB Controller".to_string(),
            version: "2.0".to_string(),
            ports: 4,
        });
    }

    controllers
}

// ============ 网络接口检测 ============

fn detect_network_interfaces() -> Vec<NetworkInterface> {
    let mut interfaces = Vec::new();
    let networks = Networks::new_with_refreshed_list();

    for (name, data) in networks.iter() {
        let mac_address = data.mac_address().to_string();
        
        // 获取 IP 地址
        let ip_addresses = get_interface_ips(name);
        
        // 判断接口类型和状态
        let (interface_type, is_up, speed) = get_interface_details(name);

        interfaces.push(NetworkInterface {
            name: name.clone(),
            mac_address,
            ip_addresses,
            is_up,
            speed,
            interface_type,
            rx_bytes: data.total_received(),
            tx_bytes: data.total_transmitted(),
        });
    }

    // 按类型排序：物理接口优先
    interfaces.sort_by(|a, b| {
        let type_order = |t: &NetworkType| match t {
            NetworkType::Ethernet => 0,
            NetworkType::WiFi => 1,
            NetworkType::Bridge => 2,
            NetworkType::Virtual => 3,
            NetworkType::Loopback => 4,
            NetworkType::Unknown => 5,
        };
        type_order(&a.interface_type).cmp(&type_order(&b.interface_type))
    });

    interfaces
}

#[cfg(target_os = "linux")]
fn get_interface_ips(name: &str) -> Vec<String> {
    let mut ips = Vec::new();
    
    // 从 /sys/class/net 读取
    let addr_path = format!("/sys/class/net/{}/address", name);
    if Path::new(&addr_path).exists() {
        // 使用 ip 命令获取 IP
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
                } else if line.starts_with("inet6 ") {
                    if let Some(ip) = line.split_whitespace().nth(1) {
                        let ip_only = ip.split('/').next().unwrap_or(ip);
                        // 跳过链路本地地址
                        if !ip_only.starts_with("fe80") {
                            ips.push(ip_only.to_string());
                        }
                    }
                }
            }
        }
    }
    
    ips
}

#[cfg(not(target_os = "linux"))]
fn get_interface_ips(_name: &str) -> Vec<String> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn get_interface_details(name: &str) -> (NetworkType, bool, Option<u64>) {
    let sys_path = format!("/sys/class/net/{}", name);
    
    // 检查接口状态
    let is_up = fs::read_to_string(format!("{}/operstate", sys_path))
        .map(|s| s.trim() == "up")
        .unwrap_or(false);
    
    // 获取速度 (Mbps)
    let speed = fs::read_to_string(format!("{}/speed", sys_path))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&s| s > 0 && s < 1000000); // 过滤无效值
    
    // 判断接口类型
    let interface_type = if name == "lo" {
        NetworkType::Loopback
    } else if name.starts_with("eth") || name.starts_with("en") {
        NetworkType::Ethernet
    } else if name.starts_with("wlan") || name.starts_with("wl") {
        NetworkType::WiFi
    } else if name.starts_with("br") || name.starts_with("docker") || name.starts_with("virbr") {
        NetworkType::Bridge
    } else if name.starts_with("veth") || name.starts_with("tap") || name.starts_with("tun") {
        NetworkType::Virtual
    } else {
        // 检查是否是物理设备
        let device_path = format!("{}/device", sys_path);
        if Path::new(&device_path).exists() {
            // 检查是否是无线设备
            let wireless_path = format!("{}/wireless", sys_path);
            if Path::new(&wireless_path).exists() {
                NetworkType::WiFi
            } else {
                NetworkType::Ethernet
            }
        } else {
            NetworkType::Virtual
        }
    };
    
    (interface_type, is_up, speed)
}

#[cfg(not(target_os = "linux"))]
fn get_interface_details(_name: &str) -> (NetworkType, bool, Option<u64>) {
    (NetworkType::Unknown, false, None)
}

// ============ USB 设备详细检测 ============

/// 检测所有 USB 设备的详细信息
#[allow(dead_code)]
pub fn detect_usb_devices_detailed() -> Vec<UsbDeviceInfo> {
    #[cfg(target_os = "linux")]
    {
        detect_usb_devices_linux()
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
fn detect_usb_devices_linux() -> Vec<UsbDeviceInfo> {
    let mut devices = Vec::new();
    // 使用 bus_path 作为唯一标识，而不是 vendor:product，这样相同型号的多个设备都能显示
    let mut seen_paths = std::collections::HashSet::new();

    if let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") {
        for entry in entries.flatten() {
            let path = entry.path();
            let dir_name = path.file_name().unwrap().to_string_lossy().to_string();
            
            // 跳过根集线器和接口
            if dir_name.starts_with("usb") || dir_name.contains(":") {
                continue;
            }
            
            let vendor_id = fs::read_to_string(path.join("idVendor"))
                .unwrap_or_default()
                .trim()
                .to_string();
            
            let product_id = fs::read_to_string(path.join("idProduct"))
                .unwrap_or_default()
                .trim()
                .to_string();
            
            // 跳过无效条目
            if vendor_id.is_empty() || product_id.is_empty() {
                continue;
            }

            // 使用设备路径作为唯一标识，允许相同型号的多个设备
            if seen_paths.contains(&dir_name) {
                continue;
            }
            seen_paths.insert(dir_name.clone());

            let product_name = fs::read_to_string(path.join("product"))
                .unwrap_or_else(|_| "Unknown USB Device".to_string())
                .trim()
                .to_string();

            let manufacturer = fs::read_to_string(path.join("manufacturer"))
                .unwrap_or_else(|_| "Unknown".to_string())
                .trim()
                .to_string();

            let serial = fs::read_to_string(path.join("serial"))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            let speed = fs::read_to_string(path.join("speed"))
                .ok()
                .map(|s| format!("{} Mbps", s.trim()));

            let device_class = detect_usb_device_class(&path);
            
            // 使用设备路径查找挂载点，支持多个相同型号设备
            let mount_point = find_usb_device_mount_by_path(&dir_name, &vendor_id, &product_id, &serial);

            devices.push(UsbDeviceInfo {
                name: product_name,
                vendor_id,
                product_id,
                manufacturer,
                device_class,
                mount_point,
                serial,
                speed,
            });
        }
    }

    devices
}

#[cfg(target_os = "linux")]
fn detect_usb_device_class(device_path: &Path) -> String {
    if let Ok(class) = fs::read_to_string(device_path.join("bDeviceClass")) {
        let class_code = class.trim();
        match class_code {
            "00" => "Composite Device".to_string(),
            "01" => "Audio".to_string(),
            "02" => "Communications (CDC)".to_string(),
            "03" => "HID (Keyboard/Mouse)".to_string(),
            "05" => "Physical".to_string(),
            "06" => "Image (Camera/Scanner)".to_string(),
            "07" => "Printer".to_string(),
            "08" => "Mass Storage".to_string(),
            "09" => "Hub".to_string(),
            "0a" => "CDC-Data".to_string(),
            "0b" => "Smart Card".to_string(),
            "0d" => "Content Security".to_string(),
            "0e" => "Video".to_string(),
            "0f" => "Personal Healthcare".to_string(),
            "10" => "Audio/Video".to_string(),
            "11" => "Billboard".to_string(),
            "dc" => "Diagnostic".to_string(),
            "e0" => "Wireless (Bluetooth/WiFi)".to_string(),
            "ef" => "Miscellaneous".to_string(),
            "fe" => "Application Specific".to_string(),
            "ff" => "Vendor Specific".to_string(),
            _ => format!("Class 0x{}", class_code),
        }
    } else {
        "Unknown".to_string()
    }
}

#[cfg(target_os = "linux")]
fn find_usb_device_mount(vendor_id: &str, product_id: &str) -> Option<String> {
    // 首先尝试通过 /proc/mounts 查找
    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let device = parts[0];
                let mount_point = parts[1];
                
                // 检查是否是 USB 存储设备
                if device.starts_with("/dev/sd") {
                    // 尝试匹配设备
                    let dev_name = device.trim_start_matches("/dev/");
                    let base_dev = dev_name.chars()
                        .take_while(|c| !c.is_ascii_digit())
                        .collect::<String>();
                    
                    // 检查设备的 vendor/product ID
                    let usb_device_path = format!("/sys/block/{}/device/../../../", base_dev);
                    if let Ok(vid) = fs::read_to_string(format!("{}idVendor", usb_device_path)) {
                        if let Ok(pid) = fs::read_to_string(format!("{}idProduct", usb_device_path)) {
                            if vid.trim() == vendor_id && pid.trim() == product_id {
                                return Some(mount_point.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    
    // 备用方案：检查 /media 和 /mnt 目录
    for base in &["/media", "/mnt"] {
        if let Ok(entries) = fs::read_dir(base) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    // 检查是否有挂载
                    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
                        let path_str = path.to_string_lossy();
                        if mounts.contains(&*path_str) {
                            return Some(path_str.to_string());
                        }
                    }
                }
            }
        }
    }
    
    None
}

/// 通过 USB 设备路径查找挂载点，支持多个相同型号的设备
#[cfg(target_os = "linux")]
fn find_usb_device_mount_by_path(
    usb_path: &str,
    vendor_id: &str,
    product_id: &str,
    serial: &Option<String>,
) -> Option<String> {
    // 查找该 USB 设备下的所有块设备
    let usb_sys_path = format!("/sys/bus/usb/devices/{}", usb_path);
    
    // 遍历查找 block 设备
    fn find_block_device(path: &std::path::Path) -> Option<String> {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let entry_path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                
                // 检查是否是块设备目录
                if name.starts_with("sd") && !name.contains(':') {
                    return Some(name);
                }
                
                // 递归查找子目录
                if entry_path.is_dir() && !name.starts_with('.') {
                    if let Some(dev) = find_block_device(&entry_path) {
                        return Some(dev);
                    }
                }
            }
        }
        None
    }
    
    // 尝试从 USB 设备路径找到对应的块设备
    if let Some(block_dev) = find_block_device(std::path::Path::new(&usb_sys_path)) {
        // 查找该块设备的挂载点
        if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let device = parts[0];
                    let mount_point = parts[1];
                    
                    // 匹配设备名（包括分区，如 sda1, sdb1）
                    if device.contains(&block_dev) {
                        return Some(mount_point.to_string());
                    }
                }
            }
        }
    }
    
    // 备用方案：通过 vendor/product ID 和序列号匹配
    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let device = parts[0];
                let mount_point = parts[1];
                
                if device.starts_with("/dev/sd") {
                    let dev_name = device.trim_start_matches("/dev/");
                    let base_dev: String = dev_name.chars()
                        .take_while(|c| !c.is_ascii_digit())
                        .collect();
                    
                    // 检查设备的 vendor/product ID
                    let usb_device_path = format!("/sys/block/{}/device/../../../", base_dev);
                    if let Ok(vid) = fs::read_to_string(format!("{}idVendor", usb_device_path)) {
                        if let Ok(pid) = fs::read_to_string(format!("{}idProduct", usb_device_path)) {
                            if vid.trim() == vendor_id && pid.trim() == product_id {
                                // 如果有序列号，进一步验证
                                if let Some(ref s) = serial {
                                    if let Ok(dev_serial) = fs::read_to_string(format!("{}serial", usb_device_path)) {
                                        if dev_serial.trim() == s {
                                            return Some(mount_point.to_string());
                                        }
                                    }
                                } else {
                                    return Some(mount_point.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    None
}

// ============ 公开 API 函数 ============

/// 获取所有块设备信息（包括未挂载的）
pub fn get_all_block_devices() -> Vec<BlockDeviceInfo> {
    #[cfg(target_os = "linux")]
    {
        get_block_devices_linux()
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockDeviceInfo {
    pub name: String,
    pub device_path: String,
    pub size: u64,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub device_type: String,
    pub is_removable: bool,
    pub partitions: Vec<PartitionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionInfo {
    pub name: String,
    pub device_path: String,
    pub size: u64,
    pub mount_point: Option<String>,
    pub file_system: Option<String>,
    pub label: Option<String>,
    pub uuid: Option<String>,
}

#[cfg(target_os = "linux")]
fn get_block_devices_linux() -> Vec<BlockDeviceInfo> {
    let mut devices = Vec::new();

    if let Ok(entries) = fs::read_dir("/sys/block") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            
            // 跳过虚拟设备
            if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("dm-") {
                continue;
            }

            let sys_path = format!("/sys/block/{}", name);
            let device_path = format!("/dev/{}", name);
            
            // 读取设备大小
            let size = fs::read_to_string(format!("{}/size", sys_path))
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .map(|sectors| sectors * 512)
                .unwrap_or(0);

            if size == 0 {
                continue;
            }

            // 读取设备信息
            let model = fs::read_to_string(format!("{}/device/model", sys_path))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            let serial = fs::read_to_string(format!("{}/device/serial", sys_path))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            let is_removable = fs::read_to_string(format!("{}/removable", sys_path))
                .map(|s| s.trim() == "1")
                .unwrap_or(false);

            // 判断设备类型
            let device_type = if name.starts_with("nvme") {
                "NVMe SSD"
            } else if name.starts_with("mmc") {
                "eMMC/SD Card"
            } else if name.starts_with("sd") {
                let rotational = fs::read_to_string(format!("{}/queue/rotational", sys_path))
                    .map(|s| s.trim() == "1")
                    .unwrap_or(true);
                if is_removable {
                    "USB Storage"
                } else if rotational {
                    "HDD"
                } else {
                    "SATA SSD"
                }
            } else {
                "Unknown"
            }.to_string();

            // 获取分区信息
            let partitions = get_partitions(&name);

            devices.push(BlockDeviceInfo {
                name: name.clone(),
                device_path,
                size,
                model,
                serial,
                device_type,
                is_removable,
                partitions,
            });
        }
    }

    devices
}

#[cfg(target_os = "linux")]
fn get_partitions(device_name: &str) -> Vec<PartitionInfo> {
    let mut partitions = Vec::new();
    let sys_path = format!("/sys/block/{}", device_name);

    if let Ok(entries) = fs::read_dir(&sys_path) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            
            // 分区名称以设备名开头
            if !name.starts_with(device_name) {
                continue;
            }

            let part_sys_path = format!("{}/{}", sys_path, name);
            let device_path = format!("/dev/{}", name);

            // 读取分区大小
            let size = fs::read_to_string(format!("{}/size", part_sys_path))
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .map(|sectors| sectors * 512)
                .unwrap_or(0);

            // 获取挂载点和文件系统信息
            let (mount_point, file_system) = get_mount_info(&device_path);
            
            // 获取 UUID 和 Label
            let (uuid, label) = get_partition_identifiers(&device_path);

            partitions.push(PartitionInfo {
                name: name.clone(),
                device_path,
                size,
                mount_point,
                file_system,
                label,
                uuid,
            });
        }
    }

    partitions
}

#[cfg(target_os = "linux")]
fn get_mount_info(device_path: &str) -> (Option<String>, Option<String>) {
    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[0] == device_path {
                return (Some(parts[1].to_string()), Some(parts[2].to_string()));
            }
        }
    }
    (None, None)
}

#[cfg(target_os = "linux")]
fn get_partition_identifiers(device_path: &str) -> (Option<String>, Option<String>) {
    let dev_name = device_path.trim_start_matches("/dev/");
    
    // 尝试从 /dev/disk/by-uuid 获取 UUID
    let uuid = fs::read_dir("/dev/disk/by-uuid")
        .ok()
        .and_then(|entries| {
            for entry in entries.flatten() {
                if let Ok(link) = fs::read_link(entry.path()) {
                    if link.to_string_lossy().ends_with(dev_name) {
                        return Some(entry.file_name().to_string_lossy().to_string());
                    }
                }
            }
            None
        });

    // 尝试从 /dev/disk/by-label 获取 Label
    let label = fs::read_dir("/dev/disk/by-label")
        .ok()
        .and_then(|entries| {
            for entry in entries.flatten() {
                if let Ok(link) = fs::read_link(entry.path()) {
                    if link.to_string_lossy().ends_with(dev_name) {
                        return Some(entry.file_name().to_string_lossy().to_string());
                    }
                }
            }
            None
        });

    (uuid, label)
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn get_block_devices_linux() -> Vec<BlockDeviceInfo> {
    Vec::new()
}
