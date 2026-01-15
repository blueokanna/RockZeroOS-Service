use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::{Command, Stdio, Child};
use std::io::Read;
use tracing::{error, info, warn};

use crate::error::AppError;

/// Audio codecs that require transcoding for mobile/web playback
pub const UNSUPPORTED_AUDIO_CODECS: &[&str] = &[
    "dts", "dca", "dts-hd", "dtshd", "dts_hd",
    "truehd", "mlp",
    "ac3", "eac3", "ac-3", "e-ac-3",
    "pcm_bluray", "pcm_dvd",
];

/// Check if audio codec needs transcoding
pub fn needs_audio_transcode(codec: &str) -> bool {
    let codec_lower = codec.to_lowercase();
    UNSUPPORTED_AUDIO_CODECS.iter().any(|&c| codec_lower.contains(c))
}

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
    #[serde(default)]
    pub needs_audio_transcode: bool,
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
#[allow(clippy::upper_case_acronyms)]
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
            .args([
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
            needs_audio_transcode: false,
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
            .args([
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

/// Audio transcoding stream for DTS/AC3/TrueHD to AAC conversion
#[allow(dead_code)]
pub struct AudioTranscodeStream {
    child: Child,
    buffer: Vec<u8>,
}

#[allow(dead_code)]
impl AudioTranscodeStream {
    /// Create a new audio transcoding stream
    /// Converts DTS/AC3/TrueHD audio to AAC while keeping video stream intact
    pub fn new(
        input_path: &str,
        start_position: Option<f64>,
        hardware_accel: Option<&HardwareAccel>,
    ) -> Result<Self, AppError> {
        let mut args: Vec<String> = Vec::new();
        
        // Hardware acceleration for decoding
        match hardware_accel {
            Some(HardwareAccel::VAAPI) => {
                args.extend_from_slice(&[
                    "-hwaccel".to_string(), 
                    "vaapi".to_string(), 
                    "-hwaccel_device".to_string(), 
                    "/dev/dri/renderD128".to_string()
                ]);
            }
            Some(HardwareAccel::NVENC) => {
                args.extend_from_slice(&["-hwaccel".to_string(), "cuda".to_string()]);
            }
            Some(HardwareAccel::RockchipMPP) => {
                args.extend_from_slice(&["-hwaccel".to_string(), "rkmpp".to_string()]);
            }
            Some(HardwareAccel::V4L2M2M) => {
                args.extend_from_slice(&["-hwaccel".to_string(), "v4l2m2m".to_string()]);
            }
            _ => {}
        }
        
        // Seek position if specified
        if let Some(pos) = start_position {
            args.push("-ss".to_string());
            args.push(pos.to_string());
        }
        
        // Input file
        args.push("-i".to_string());
        args.push(input_path.to_string());
        
        // Copy video stream, transcode audio to AAC
        args.extend_from_slice(&[
            "-c:v".to_string(), "copy".to_string(),           // Copy video without re-encoding
            "-c:a".to_string(), "aac".to_string(),            // Transcode audio to AAC
            "-b:a".to_string(), "256k".to_string(),           // Audio bitrate
            "-ac".to_string(), "2".to_string(),               // Stereo output (for compatibility)
            "-ar".to_string(), "48000".to_string(),           // Sample rate
            "-movflags".to_string(), "frag_keyframe+empty_moov+faststart".to_string(), // Streaming-friendly MP4
            "-f".to_string(), "mp4".to_string(),              // Output format
            "-".to_string(),                                   // Output to stdout
        ]);
        
        info!("Starting audio transcode with args: {:?}", args);
        
        let child = Command::new("ffmpeg")
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                error!("Failed to start ffmpeg transcode: {}", e);
                AppError::InternalError
            })?;
        
        Ok(Self {
            child,
            buffer: vec![0u8; 64 * 1024], // 64KB buffer
        })
    }
    
    /// Read next chunk from the transcoding stream
    pub fn read_chunk(&mut self) -> Option<Vec<u8>> {
        if let Some(ref mut stdout) = self.child.stdout {
            match stdout.read(&mut self.buffer) {
                Ok(0) => None, // EOF
                Ok(n) => Some(self.buffer[..n].to_vec()),
                Err(e) => {
                    warn!("Error reading transcode stream: {}", e);
                    None
                }
            }
        } else {
            None
        }
    }
    
    /// Check if the process is still running
    pub fn is_running(&mut self) -> bool {
        match self.child.try_wait() {
            Ok(Some(_)) => false,
            Ok(None) => true,
            Err(_) => false,
        }
    }
}

impl Drop for AudioTranscodeStream {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

/// Streaming transcoder that outputs to a pipe for HTTP streaming
pub struct StreamingTranscoder {
    ffmpeg_path: String,
}

impl StreamingTranscoder {
    pub fn new() -> Self {
        Self {
            ffmpeg_path: "ffmpeg".to_string(),
        }
    }
    
    /// Start a streaming transcode process for DTS/AC3 audio
    /// Returns a Child process with stdout as the transcoded stream
    pub fn start_audio_transcode(
        &self,
        input_path: &str,
        seek_seconds: Option<f64>,
        audio_bitrate: Option<&str>,
        channels: Option<u32>,
    ) -> Result<Child, AppError> {
        let mut args: Vec<String> = vec![
            "-hide_banner".to_string(),
            "-loglevel".to_string(), 
            "error".to_string(),
        ];
        
        // Seek position
        if let Some(pos) = seek_seconds {
            args.push("-ss".to_string());
            args.push(pos.to_string());
        }
        
        // Input
        args.push("-i".to_string());
        args.push(input_path.to_string());
        
        // Video: copy (no re-encoding)
        args.push("-c:v".to_string());
        args.push("copy".to_string());
        
        // Audio: transcode to AAC
        args.push("-c:a".to_string());
        args.push("aac".to_string());
        
        // Audio bitrate
        args.push("-b:a".to_string());
        args.push(audio_bitrate.unwrap_or("256k").to_string());
        
        // Channels (default to stereo for compatibility)
        args.push("-ac".to_string());
        args.push(channels.unwrap_or(2).to_string());
        
        // Sample rate
        args.push("-ar".to_string());
        args.push("48000".to_string());
        
        // Streaming-optimized MP4
        args.push("-movflags".to_string());
        args.push("frag_keyframe+empty_moov+faststart+default_base_moof".to_string());
        
        // Output format and destination
        args.push("-f".to_string());
        args.push("mp4".to_string());
        args.push("-".to_string());
        
        info!("Starting streaming transcode: ffmpeg {:?}", args);
        
        Command::new(&self.ffmpeg_path)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                error!("Failed to start streaming transcode: {}", e);
                AppError::InternalError
            })
    }
    
    /// Start HLS transcode for better seeking support
    #[allow(dead_code)]
    pub fn start_hls_transcode(
        &self,
        input_path: &str,
        output_dir: &str,
        segment_duration: u32,
    ) -> Result<Child, AppError> {
        let playlist_path = format!("{}/playlist.m3u8", output_dir);
        let segment_pattern = format!("{}/segment_%03d.ts", output_dir);
        let segment_duration_str = segment_duration.to_string();
        
        let args: Vec<&str> = vec![
            "-hide_banner",
            "-loglevel", "error",
            "-i", input_path,
            "-c:v", "copy",
            "-c:a", "aac",
            "-b:a", "256k",
            "-ac", "2",
            "-ar", "48000",
            "-f", "hls",
            "-hls_time", &segment_duration_str,
            "-hls_list_size", "0",
            "-hls_segment_filename", &segment_pattern,
            &playlist_path,
        ];
        
        info!("Starting HLS transcode: ffmpeg {:?}", args);
        
        Command::new(&self.ffmpeg_path)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                error!("Failed to start HLS transcode: {}", e);
                AppError::InternalError
            })
    }
}

impl Default for StreamingTranscoder {
    fn default() -> Self {
        Self::new()
    }
}
