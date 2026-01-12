use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::{Command, Stdio};
use tracing::{error, info};

use crate::error::AppError;

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaInfo {
    pub duration: Option<f64>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub video_codec: Option<String>,
    pub audio_codec: Option<String>,
    pub bitrate: Option<u64>,
    pub frame_rate: Option<f64>,
    pub audio_channels: Option<u32>,
    pub audio_sample_rate: Option<u32>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscodeOptions {
    pub output_format: String,
    pub video_codec: Option<String>,
    pub audio_codec: Option<String>,
    pub video_bitrate: Option<String>,
    pub audio_bitrate: Option<String>,
    pub resolution: Option<(u32, u32)>,
    pub frame_rate: Option<u32>,
    pub hardware_accel: Option<HardwareAccel>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HardwareAccel {
    None,
    VAAPI,
    NVENC,
    QSV,
    RockchipMPP,
    AmlogicVDEC,
    V4L2M2M,
}

#[allow(dead_code)]
pub struct MediaProcessor {
    ffmpeg_path: String,
    ffprobe_path: String,
}

#[allow(dead_code)]
impl MediaProcessor {
    pub fn new() -> Self {
        Self {
            ffmpeg_path: "ffmpeg".to_string(),
            ffprobe_path: "ffprobe".to_string(),
        }
    }

    pub fn is_available(&self) -> bool {
        Command::new(&self.ffmpeg_path)
            .arg("-version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    }

    pub fn get_media_info(&self, file_path: &str) -> Result<MediaInfo, AppError> {
        let output = Command::new(&self.ffprobe_path)
            .args(&[
                "-v", "quiet",
                "-print_format", "json",
                "-show_format",
                "-show_streams",
                file_path,
            ])
            .output()
            .map_err(|e| {
                error!("Failed to run ffprobe: {}", e);
                AppError::InternalError
            })?;

        if !output.status.success() {
            error!("ffprobe failed: {}", String::from_utf8_lossy(&output.stderr));
            return Err(AppError::BadRequest("Failed to analyze media file".to_string()));
        }

        let json: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| AppError::InternalError)?;

        let mut media_info = MediaInfo {
            duration: None,
            width: None,
            height: None,
            video_codec: None,
            audio_codec: None,
            bitrate: None,
            frame_rate: None,
            audio_channels: None,
            audio_sample_rate: None,
        };

        if let Some(format) = json.get("format") {
            if let Some(duration) = format.get("duration").and_then(|d| d.as_str()) {
                media_info.duration = duration.parse::<f64>().ok();
            }
            if let Some(bitrate) = format.get("bit_rate").and_then(|b| b.as_str()) {
                media_info.bitrate = bitrate.parse::<u64>().ok();
            }
        }

        if let Some(streams) = json.get("streams").and_then(|s| s.as_array()) {
            for stream in streams {
                let codec_type = stream.get("codec_type").and_then(|t| t.as_str());
                
                match codec_type {
                    Some("video") => {
                        media_info.video_codec = stream.get("codec_name")
                            .and_then(|c| c.as_str())
                            .map(|s| s.to_string());
                        media_info.width = stream.get("width").and_then(|w| w.as_u64()).map(|w| w as u32);
                        media_info.height = stream.get("height").and_then(|h| h.as_u64()).map(|h| h as u32);
                        
                        if let Some(fps_str) = stream.get("r_frame_rate").and_then(|f| f.as_str()) {
                            if let Some((num, den)) = fps_str.split_once('/') {
                                if let (Ok(n), Ok(d)) = (num.parse::<f64>(), den.parse::<f64>()) {
                                    if d != 0.0 {
                                        media_info.frame_rate = Some(n / d);
                                    }
                                }
                            }
                        }
                    }
                    Some("audio") => {
                        media_info.audio_codec = stream.get("codec_name")
                            .and_then(|c| c.as_str())
                            .map(|s| s.to_string());
                        media_info.audio_channels = stream.get("channels").and_then(|c| c.as_u64()).map(|c| c as u32);
                        media_info.audio_sample_rate = stream.get("sample_rate")
                            .and_then(|s| s.as_str())
                            .and_then(|s| s.parse::<u32>().ok());
                    }
                    _ => {}
                }
            }
        }

        Ok(media_info)
    }

    pub fn transcode(
        &self,
        input_path: &str,
        output_path: &str,
        options: &TranscodeOptions,
    ) -> Result<(), AppError> {
        let mut args = vec!["-i".to_string(), input_path.to_string()];

        match &options.hardware_accel {
            Some(HardwareAccel::VAAPI) => {
                args.push("-hwaccel".to_string());
                args.push("vaapi".to_string());
                args.push("-hwaccel_device".to_string());
                args.push("/dev/dri/renderD128".to_string());
                args.push("-hwaccel_output_format".to_string());
                args.push("vaapi".to_string());
            }
            Some(HardwareAccel::NVENC) => {
                args.push("-hwaccel".to_string());
                args.push("cuda".to_string());
            }
            Some(HardwareAccel::QSV) => {
                args.push("-hwaccel".to_string());
                args.push("qsv".to_string());
            }
            Some(HardwareAccel::RockchipMPP) => {
                args.push("-hwaccel".to_string());
                args.push("rkmpp".to_string());
            }
            Some(HardwareAccel::V4L2M2M) => {
                args.push("-hwaccel".to_string());
                args.push("v4l2m2m".to_string());
            }
            _ => {}
        }

        if let Some(video_codec) = &options.video_codec {
            args.push("-c:v".to_string());
            
            let codec = match (&options.hardware_accel, video_codec.as_str()) {
                (Some(HardwareAccel::VAAPI), "h264") => "h264_vaapi",
                (Some(HardwareAccel::VAAPI), "hevc") => "hevc_vaapi",
                (Some(HardwareAccel::NVENC), "h264") => "h264_nvenc",
                (Some(HardwareAccel::NVENC), "hevc") => "hevc_nvenc",
                (Some(HardwareAccel::QSV), "h264") => "h264_qsv",
                (Some(HardwareAccel::QSV), "hevc") => "hevc_qsv",
                (Some(HardwareAccel::RockchipMPP), "h264") => "h264_rkmpp",
                (Some(HardwareAccel::RockchipMPP), "hevc") => "hevc_rkmpp",
                (Some(HardwareAccel::V4L2M2M), "h264") => "h264_v4l2m2m",
                _ => video_codec.as_str(),
            };
            
            args.push(codec.to_string());
        }

        if let Some(audio_codec) = &options.audio_codec {
            args.push("-c:a".to_string());
            args.push(audio_codec.clone());
        }

        if let Some(video_bitrate) = &options.video_bitrate {
            args.push("-b:v".to_string());
            args.push(video_bitrate.clone());
        }

        if let Some(audio_bitrate) = &options.audio_bitrate {
            args.push("-b:a".to_string());
            args.push(audio_bitrate.clone());
        }

        if let Some((width, height)) = options.resolution {
            args.push("-s".to_string());
            args.push(format!("{}x{}", width, height));
        }

        if let Some(frame_rate) = options.frame_rate {
            args.push("-r".to_string());
            args.push(frame_rate.to_string());
        }

        args.push("-y".to_string());
        args.push(output_path.to_string());

        info!("Running ffmpeg with args: {:?}", args);

        let output = Command::new(&self.ffmpeg_path)
            .args(&args)
            .output()
            .map_err(|e| {
                error!("Failed to run ffmpeg: {}", e);
                AppError::InternalError
            })?;

        if !output.status.success() {
            error!("ffmpeg failed: {}", String::from_utf8_lossy(&output.stderr));
            return Err(AppError::BadRequest("Transcoding failed".to_string()));
        }

        info!("Transcoding completed: {}", output_path);
        Ok(())
    }

    pub fn extract_thumbnail(
        &self,
        input_path: &str,
        output_path: &str,
        timestamp: f64,
    ) -> Result<(), AppError> {
        let output = Command::new(&self.ffmpeg_path)
            .args(&[
                "-ss", &timestamp.to_string(),
                "-i", input_path,
                "-vframes", "1",
                "-q:v", "2",
                "-y",
                output_path,
            ])
            .output()
            .map_err(|e| {
                error!("Failed to extract thumbnail: {}", e);
                AppError::InternalError
            })?;

        if !output.status.success() {
            error!("Thumbnail extraction failed: {}", String::from_utf8_lossy(&output.stderr));
            return Err(AppError::BadRequest("Failed to extract thumbnail".to_string()));
        }

        Ok(())
    }

    pub fn detect_hardware_capabilities(&self) -> HardwareCapabilities {
        let mut capabilities = HardwareCapabilities {
            vaapi: false,
            nvenc: false,
            qsv: false,
            rockchip_mpp: false,
            amlogic_vdec: false,
            v4l2m2m: false,
        };

        if Path::new("/dev/dri/renderD128").exists() {
            capabilities.vaapi = true;
        }

        if Path::new("/dev/nvidia0").exists() {
            capabilities.nvenc = true;
        }

        if Path::new("/dev/video10").exists() {
            capabilities.rockchip_mpp = true;
            capabilities.v4l2m2m = true;
        }

        if Path::new("/dev/meson-vdec").exists() {
            capabilities.amlogic_vdec = true;
        }

        let arch = std::env::consts::ARCH;
        if arch == "x86_64" || arch == "x86" {
            capabilities.qsv = true;
        }

        capabilities
    }

    pub fn get_optimal_hardware_accel(&self) -> HardwareAccel {
        let caps = self.detect_hardware_capabilities();

        if caps.rockchip_mpp {
            HardwareAccel::RockchipMPP
        } else if caps.amlogic_vdec {
            HardwareAccel::AmlogicVDEC
        } else if caps.nvenc {
            HardwareAccel::NVENC
        } else if caps.vaapi {
            HardwareAccel::VAAPI
        } else if caps.qsv {
            HardwareAccel::QSV
        } else if caps.v4l2m2m {
            HardwareAccel::V4L2M2M
        } else {
            HardwareAccel::None
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareCapabilities {
    pub vaapi: bool,
    pub nvenc: bool,
    pub qsv: bool,
    pub rockchip_mpp: bool,
    pub amlogic_vdec: bool,
    pub v4l2m2m: bool,
}

impl Default for MediaProcessor {
    fn default() -> Self {
        Self::new()
    }
}
