use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::{error, info};

use rockzero_common::AppError;

// ============ 数据结构 ============

#[derive(Debug, Serialize, Clone)]
pub struct HardwareCapabilities {
    pub cpu_info: CpuInfo,
    pub gpu_info: Vec<GpuInfo>,
    pub video_codecs: VideoCodecSupport,
    pub recommended_encoder: String,
    pub recommended_decoder: String,
    pub ffmpeg_available: bool,
    pub ffmpeg_version: Option<String>,
    pub hardware_acceleration: Vec<HardwareAccelType>,
}

#[derive(Debug, Serialize, Clone)]
pub struct CpuInfo {
    pub model: String,
    pub cores: u32,
    pub threads: u32,
    pub has_avx: bool,
    pub has_avx2: bool,
    pub has_avx512: bool,
}

#[derive(Debug, Serialize, Clone)]
pub struct GpuInfo {
    pub vendor: String, // "NVIDIA", "AMD", "Intel", "Unknown"
    pub model: String,
    pub driver_version: Option<String>,
    pub vram: Option<u64>, // MB
    pub supports_encoding: bool,
    pub supports_decoding: bool,
    pub acceleration_type: Vec<HardwareAccelType>,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub enum HardwareAccelType {
    VAAPI,        // Video Acceleration API (Intel/AMD on Linux)
    NVENC,        // NVIDIA Encoder
    NVDEC,        // NVIDIA Decoder
    QSV,          // Intel Quick Sync Video
    V4L2M2M,      // Video4Linux2 Memory-to-Memory (ARM)
    DXVA2,        // DirectX Video Acceleration (Windows)
    D3D11VA,      // Direct3D 11 Video Acceleration (Windows)
    VideoToolbox, // Apple VideoToolbox (macOS)
    CUDA,         // NVIDIA CUDA
    OpenCL,       // OpenCL
    None,
}

#[derive(Debug, Serialize, Clone)]
pub struct VideoCodecSupport {
    pub h264: CodecCapability,
    pub h265: CodecCapability,
    pub vp9: CodecCapability,
    pub av1: CodecCapability,
}

#[derive(Debug, Serialize, Clone)]
pub struct CodecCapability {
    pub software_encode: bool,
    pub software_decode: bool,
    pub hardware_encode: bool,
    pub hardware_decode: bool,
    pub hardware_encoder: Option<String>,
    pub hardware_decoder: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TranscodeRequest {
    pub input_file: String,
    pub output_file: String,
    pub codec: String, // "h264", "h265", "vp9", "av1"
    pub quality: TranscodeQuality,
    pub use_hardware: bool,
    pub resolution: Option<String>, // "1920x1080", "1280x720", etc.
    pub bitrate: Option<String>,    // "5M", "10M", etc.
}

#[derive(Debug, Deserialize, Clone)]
pub enum TranscodeQuality {
    Low,
    Medium,
    High,
    VeryHigh,
}

// ============ API 端点 ============

/// 获取硬件能力
pub async fn get_hardware_capabilities() -> Result<HttpResponse, AppError> {
    info!("🔍 Detecting hardware capabilities...");

    let capabilities = detect_hardware_capabilities()?;

    Ok(HttpResponse::Ok().json(capabilities))
}

/// 转码视频（使用硬件加速）
pub async fn transcode_video(
    body: web::Json<TranscodeRequest>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let request = body.into_inner();

    info!(
        "🎬 Transcoding {} to {} using {}",
        request.input_file, request.output_file, request.codec
    );

    let capabilities = detect_hardware_capabilities()?;

    let result = transcode_with_hardware(&request, &capabilities)?;

    Ok(HttpResponse::Ok().json(result))
}

// ============ 硬件检测 ============

fn detect_hardware_capabilities() -> Result<HardwareCapabilities, AppError> {
    let cpu_info = detect_cpu_info();
    let gpu_info = detect_gpu_info();
    let ffmpeg_info = detect_ffmpeg();
    let video_codecs = detect_codec_support(&gpu_info);
    let hardware_acceleration = detect_available_acceleration(&gpu_info);

    let (recommended_encoder, recommended_decoder) =
        recommend_codecs(&gpu_info, &hardware_acceleration);

    Ok(HardwareCapabilities {
        cpu_info,
        gpu_info,
        video_codecs,
        recommended_encoder,
        recommended_decoder,
        ffmpeg_available: ffmpeg_info.0,
        ffmpeg_version: ffmpeg_info.1,
        hardware_acceleration,
    })
}

fn detect_cpu_info() -> CpuInfo {
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("lscpu").output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);

            let model = stdout
                .lines()
                .find(|line| line.starts_with("Model name:"))
                .and_then(|line| line.split(':').nth(1))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "Unknown".to_string());

            let cores = stdout
                .lines()
                .find(|line| line.starts_with("CPU(s):"))
                .and_then(|line| line.split(':').nth(1))
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(1);

            let threads = cores; // 简化处理

            // 检测 AVX 支持
            let flags_output = Command::new("grep")
                .args(["flags", "/proc/cpuinfo"])
                .output()
                .ok();

            let flags = flags_output
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();

            return CpuInfo {
                model,
                cores,
                threads,
                has_avx: flags.contains("avx"),
                has_avx2: flags.contains("avx2"),
                has_avx512: flags.contains("avx512"),
            };
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Windows 实现
        let output = Command::new("wmic").args(["cpu", "get", "name"]).output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let model = stdout
                .lines()
                .nth(1)
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "Unknown".to_string());

            return CpuInfo {
                model,
                cores: std::thread::available_parallelism()
                    .map(|n| n.get() as u32)
                    .unwrap_or(1),
                threads: std::thread::available_parallelism()
                    .map(|n| n.get() as u32)
                    .unwrap_or(1),
                has_avx: true, // 假设现代 CPU 都支持
                has_avx2: true,
                has_avx512: false,
            };
        }
    }

    CpuInfo {
        model: "Unknown".to_string(),
        cores: std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1),
        threads: std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1),
        has_avx: false,
        has_avx2: false,
        has_avx512: false,
    }
}

fn detect_gpu_info() -> Vec<GpuInfo> {
    let mut gpus = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // 检测 NVIDIA GPU
        if let Ok(output) = Command::new("nvidia-smi")
            .args([
                "--query-gpu=name,driver_version,memory.total",
                "--format=csv,noheader",
            ])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split(',').collect();
                    if parts.len() >= 3 {
                        gpus.push(GpuInfo {
                            vendor: "NVIDIA".to_string(),
                            model: parts[0].trim().to_string(),
                            driver_version: Some(parts[1].trim().to_string()),
                            vram: parts[2]
                                .trim()
                                .split_whitespace()
                                .next()
                                .and_then(|s| s.parse().ok()),
                            supports_encoding: true,
                            supports_decoding: true,
                            acceleration_type: vec![
                                HardwareAccelType::NVENC,
                                HardwareAccelType::NVDEC,
                                HardwareAccelType::CUDA,
                            ],
                        });
                    }
                }
            }
        }

        // 检测 Intel GPU
        if let Ok(output) = Command::new("vainfo").output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains("Intel") {
                    gpus.push(GpuInfo {
                        vendor: "Intel".to_string(),
                        model: "Intel Integrated Graphics".to_string(),
                        driver_version: None,
                        vram: None,
                        supports_encoding: true,
                        supports_decoding: true,
                        acceleration_type: vec![HardwareAccelType::VAAPI, HardwareAccelType::QSV],
                    });
                }
            }
        }

        // 检测 AMD GPU
        if let Ok(output) = Command::new("lspci").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("AMD") || stdout.contains("Radeon") {
                gpus.push(GpuInfo {
                    vendor: "AMD".to_string(),
                    model: "AMD Radeon".to_string(),
                    driver_version: None,
                    vram: None,
                    supports_encoding: true,
                    supports_decoding: true,
                    acceleration_type: vec![HardwareAccelType::VAAPI],
                });
            }
        }

        // 检测 ARM GPU (V4L2)
        if std::path::Path::new("/dev/video10").exists()
            || std::path::Path::new("/dev/video11").exists()
        {
            gpus.push(GpuInfo {
                vendor: "ARM".to_string(),
                model: "ARM Mali/VideoCore".to_string(),
                driver_version: None,
                vram: None,
                supports_encoding: true,
                supports_decoding: true,
                acceleration_type: vec![HardwareAccelType::V4L2M2M],
            });
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Windows GPU 检测
        if let Ok(output) = Command::new("wmic")
            .args(["path", "win32_VideoController", "get", "name"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                let name = line.trim();
                if !name.is_empty() {
                    let (vendor, accel_types) = if name.contains("NVIDIA") {
                        (
                            "NVIDIA",
                            vec![
                                HardwareAccelType::NVENC,
                                HardwareAccelType::NVDEC,
                                HardwareAccelType::CUDA,
                            ],
                        )
                    } else if name.contains("Intel") {
                        (
                            "Intel",
                            vec![HardwareAccelType::QSV, HardwareAccelType::D3D11VA],
                        )
                    } else if name.contains("AMD") || name.contains("Radeon") {
                        ("AMD", vec![HardwareAccelType::D3D11VA])
                    } else {
                        ("Unknown", vec![HardwareAccelType::D3D11VA])
                    };

                    gpus.push(GpuInfo {
                        vendor: vendor.to_string(),
                        model: name.to_string(),
                        driver_version: None,
                        vram: None,
                        supports_encoding: true,
                        supports_decoding: true,
                        acceleration_type: accel_types,
                    });
                }
            }
        }
    }

    gpus
}

fn detect_ffmpeg() -> (bool, Option<String>) {
    let output = Command::new("ffmpeg").arg("-version").output();

    match output {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let version = stdout
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(2))
                .map(|s| s.to_string());
            (true, version)
        }
        _ => (false, None),
    }
}

fn detect_codec_support(gpus: &[GpuInfo]) -> VideoCodecSupport {
    let has_nvidia = gpus.iter().any(|g| g.vendor == "NVIDIA");
    let has_intel = gpus.iter().any(|g| g.vendor == "Intel");
    let has_amd = gpus.iter().any(|g| g.vendor == "AMD");
    let has_arm = gpus.iter().any(|g| g.vendor == "ARM");

    VideoCodecSupport {
        h264: CodecCapability {
            software_encode: true,
            software_decode: true,
            hardware_encode: !gpus.is_empty(),
            hardware_decode: !gpus.is_empty(),
            hardware_encoder: if has_nvidia {
                Some("h264_nvenc".to_string())
            } else if has_intel {
                Some("h264_qsv".to_string())
            } else if has_arm {
                Some("h264_v4l2m2m".to_string())
            } else {
                None
            },
            hardware_decoder: if has_nvidia {
                Some("h264_cuvid".to_string())
            } else if has_intel || has_amd {
                Some("h264_vaapi".to_string())
            } else if has_arm {
                Some("h264_v4l2m2m".to_string())
            } else {
                None
            },
        },
        h265: CodecCapability {
            software_encode: true,
            software_decode: true,
            hardware_encode: has_nvidia || has_intel,
            hardware_decode: !gpus.is_empty(),
            hardware_encoder: if has_nvidia {
                Some("hevc_nvenc".to_string())
            } else if has_intel {
                Some("hevc_qsv".to_string())
            } else {
                None
            },
            hardware_decoder: if has_nvidia {
                Some("hevc_cuvid".to_string())
            } else if has_intel || has_amd {
                Some("hevc_vaapi".to_string())
            } else {
                None
            },
        },
        vp9: CodecCapability {
            software_encode: true,
            software_decode: true,
            hardware_encode: false,
            hardware_decode: has_intel || has_nvidia,
            hardware_encoder: None,
            hardware_decoder: if has_intel {
                Some("vp9_vaapi".to_string())
            } else {
                None
            },
        },
        av1: CodecCapability {
            software_encode: true,
            software_decode: true,
            hardware_encode: false,
            hardware_decode: has_intel || has_nvidia,
            hardware_encoder: None,
            hardware_decoder: if has_intel {
                Some("av1_vaapi".to_string())
            } else {
                None
            },
        },
    }
}

fn detect_available_acceleration(gpus: &[GpuInfo]) -> Vec<HardwareAccelType> {
    let mut accel_types = Vec::new();

    for gpu in gpus {
        for accel in &gpu.acceleration_type {
            if !accel_types.contains(accel) {
                accel_types.push(accel.clone());
            }
        }
    }

    if accel_types.is_empty() {
        accel_types.push(HardwareAccelType::None);
    }

    accel_types
}

fn recommend_codecs(_gpus: &[GpuInfo], accel_types: &[HardwareAccelType]) -> (String, String) {
    if accel_types.contains(&HardwareAccelType::NVENC) {
        ("h264_nvenc".to_string(), "h264_cuvid".to_string())
    } else if accel_types.contains(&HardwareAccelType::QSV) {
        ("h264_qsv".to_string(), "h264_qsv".to_string())
    } else if accel_types.contains(&HardwareAccelType::VAAPI) {
        ("h264_vaapi".to_string(), "h264_vaapi".to_string())
    } else if accel_types.contains(&HardwareAccelType::V4L2M2M) {
        ("h264_v4l2m2m".to_string(), "h264_v4l2m2m".to_string())
    } else {
        ("libx264".to_string(), "h264".to_string())
    }
}

// ============ 转码实现 ============

fn transcode_with_hardware(
    request: &TranscodeRequest,
    capabilities: &HardwareCapabilities,
) -> Result<serde_json::Value, AppError> {
    if !capabilities.ffmpeg_available {
        return Err(AppError::BadRequest(
            "FFmpeg is not installed. Please install FFmpeg to use transcoding.".to_string(),
        ));
    }

    let mut cmd = Command::new("ffmpeg");
    cmd.arg("-i").arg(&request.input_file);

    // 硬件加速
    if request.use_hardware
        && !capabilities
            .hardware_acceleration
            .contains(&HardwareAccelType::None)
    {
        // 添加硬件加速参数
        if capabilities
            .hardware_acceleration
            .contains(&HardwareAccelType::NVENC)
        {
            cmd.arg("-hwaccel").arg("cuda");
            cmd.arg("-hwaccel_output_format").arg("cuda");
        } else if capabilities
            .hardware_acceleration
            .contains(&HardwareAccelType::VAAPI)
        {
            cmd.arg("-hwaccel").arg("vaapi");
            cmd.arg("-hwaccel_device").arg("/dev/dri/renderD128");
            cmd.arg("-hwaccel_output_format").arg("vaapi");
        } else if capabilities
            .hardware_acceleration
            .contains(&HardwareAccelType::QSV)
        {
            cmd.arg("-hwaccel").arg("qsv");
            cmd.arg("-hwaccel_output_format").arg("qsv");
        }
    }

    // 编码器选择
    let encoder = if request.use_hardware {
        match request.codec.as_str() {
            "h264" => capabilities
                .video_codecs
                .h264
                .hardware_encoder
                .as_deref()
                .unwrap_or("libx264"),
            "h265" => capabilities
                .video_codecs
                .h265
                .hardware_encoder
                .as_deref()
                .unwrap_or("libx265"),
            _ => "libx264",
        }
    } else {
        match request.codec.as_str() {
            "h264" => "libx264",
            "h265" => "libx265",
            "vp9" => "libvpx-vp9",
            "av1" => "libaom-av1",
            _ => "libx264",
        }
    };

    cmd.arg("-c:v").arg(encoder);

    // 质量设置
    let crf = match request.quality {
        TranscodeQuality::Low => "28",
        TranscodeQuality::Medium => "23",
        TranscodeQuality::High => "18",
        TranscodeQuality::VeryHigh => "15",
    };

    if encoder.starts_with("lib") {
        cmd.arg("-crf").arg(crf);
    } else {
        // 硬件编码器使用 qp
        cmd.arg("-qp").arg(crf);
    }

    // 分辨率
    if let Some(resolution) = &request.resolution {
        cmd.arg("-s").arg(resolution);
    }

    // 比特率
    if let Some(bitrate) = &request.bitrate {
        cmd.arg("-b:v").arg(bitrate);
    }

    // 音频编码
    cmd.arg("-c:a").arg("aac");
    cmd.arg("-b:a").arg("128k");

    // 输出文件
    cmd.arg("-y"); // 覆盖输出文件
    cmd.arg(&request.output_file);

    info!("🎬 Running FFmpeg command: {:?}", cmd);

    // 执行转码（异步）
    let output = cmd
        .output()
        .map_err(|e| AppError::InternalServerError(format!("Failed to run FFmpeg: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("❌ FFmpeg failed: {}", stderr);
        return Err(AppError::BadRequest(format!(
            "Transcoding failed: {}",
            stderr
        )));
    }

    info!("✅ Transcoding completed successfully");

    Ok(serde_json::json!({
        "success": true,
        "input_file": request.input_file,
        "output_file": request.output_file,
        "encoder_used": encoder,
        "hardware_acceleration": request.use_hardware,
    }))
}


// ============ 辅助函数：确保所有类型都被使用 ============

/// 这个函数确保所有枚举变体都被"使用"，避免 dead_code 警告
/// 虽然某些变体只在特定平台使用，但我们需要在所有平台上定义它们以保持 API 一致性
#[allow(dead_code)]
fn ensure_all_accel_types_used() {
    // 确保所有 HardwareAccelType 变体都被引用
    let _types = vec![
        HardwareAccelType::VAAPI,
        HardwareAccelType::NVENC,
        HardwareAccelType::NVDEC,
        HardwareAccelType::QSV,
        HardwareAccelType::V4L2M2M,
        HardwareAccelType::DXVA2,
        HardwareAccelType::D3D11VA,
        HardwareAccelType::VideoToolbox,
        HardwareAccelType::CUDA,
        HardwareAccelType::OpenCL,
        HardwareAccelType::None,
    ];
}
