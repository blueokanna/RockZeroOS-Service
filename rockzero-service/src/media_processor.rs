use std::io::{BufReader, Read};
use std::path::Path;
use std::process::{Child, Command, Stdio};

pub const UNSUPPORTED_AUDIO_CODECS: &[&str] = &["dts", "ac3", "truehd", "eac3", "dca"];

pub fn needs_audio_transcode(codec: &str) -> bool {
    let codec_lower = codec.to_lowercase();
    UNSUPPORTED_AUDIO_CODECS.iter().any(|&c| codec_lower.contains(c))
}

pub struct MediaProcessor {
    available: bool,
    hw_capabilities: HardwareCapabilities,
}

#[derive(Debug, Clone)]
pub struct HardwareCapabilities {
    pub has_rkmpp: bool,
    pub has_vaapi: bool,
    pub has_cuda: bool,
    pub has_videotoolbox: bool,
}

impl MediaProcessor {
    pub fn new() -> Self {
        let available = Self::check_ffmpeg_available();
        let hw_capabilities = if available {
            Self::detect_hardware()
        } else {
            HardwareCapabilities::default()
        };

        Self {
            available,
            hw_capabilities,
        }
    }

    fn check_ffmpeg_available() -> bool {
        if let Some(path) = crate::ffmpeg_manager::get_global_ffmpeg_path() {
            Command::new(path)
                .arg("-version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        } else {
            Command::new("ffmpeg")
                .arg("-version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
    }

    fn detect_hardware() -> HardwareCapabilities {
        let mut caps = HardwareCapabilities::default();

        caps.has_rkmpp = cfg!(target_arch = "aarch64") && Path::new("/dev/video10").exists();
        caps.has_vaapi = Path::new("/dev/dri/renderD128").exists();
        
        if cfg!(target_os = "macos") {
            caps.has_videotoolbox = true;
        }

        if let Ok(output) = Command::new("nvidia-smi").output() {
            caps.has_cuda = output.status.success();
        }

        caps
    }

    pub fn is_available(&self) -> bool {
        self.available
    }

    pub fn detect_hardware_capabilities(&self) -> HardwareCapabilities {
        self.hw_capabilities.clone()
    }
}

impl Default for HardwareCapabilities {
    fn default() -> Self {
        Self {
            has_rkmpp: false,
            has_vaapi: false,
            has_cuda: false,
            has_videotoolbox: false,
        }
    }
}

#[allow(dead_code)]
pub struct StreamingTranscoder;

impl StreamingTranscoder {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self
    }

    #[allow(dead_code)]
    pub fn start_audio_transcode(
        &self,
        input_path: &str,
        seek: Option<f64>,
        bitrate: Option<&str>,
        channels: Option<u8>,
    ) -> Result<Child, std::io::Error> {
        let ffmpeg_cmd = crate::ffmpeg_manager::get_global_ffmpeg_path()
            .unwrap_or_else(|| "ffmpeg".to_string());

        let mut args = vec!["-hide_banner".to_string()];

        if let Some(s) = seek {
            args.push("-ss".to_string());
            args.push(s.to_string());
        }

        args.extend_from_slice(&[
            "-i".to_string(),
            input_path.to_string(),
            "-c:v".to_string(),
            "copy".to_string(),
            "-c:a".to_string(),
            "aac".to_string(),
            "-b:a".to_string(),
            bitrate.unwrap_or("192k").to_string(),
        ]);

        if let Some(ch) = channels {
            args.push("-ac".to_string());
            args.push(ch.to_string());
        }

        args.extend_from_slice(&[
            "-f".to_string(),
            "mp4".to_string(),
            "-movflags".to_string(),
            "frag_keyframe+empty_moov".to_string(),
            "pipe:1".to_string(),
        ]);

        Command::new(&ffmpeg_cmd)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
    }
}

#[allow(dead_code)]
pub struct TranscodeStream {
    child: Child,
    reader: Option<BufReader<std::process::ChildStdout>>,
}

impl TranscodeStream {
    #[allow(dead_code)]
    pub fn new(mut child: Child) -> Self {
        let reader = child.stdout.take().map(BufReader::new);
        Self { child, reader }
    }
}

impl futures::Stream for TranscodeStream {
    type Item = Result<bytes::Bytes, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        if let Some(ref mut reader) = self.reader {
            let mut buffer = vec![0u8; 32 * 1024];
            match reader.read(&mut buffer) {
                Ok(0) => std::task::Poll::Ready(None),
                Ok(n) => {
                    buffer.truncate(n);
                    std::task::Poll::Ready(Some(Ok(bytes::Bytes::from(buffer))))
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::task::Poll::Pending
                }
                Err(e) => std::task::Poll::Ready(Some(Err(e))),
            }
        } else {
            std::task::Poll::Ready(None)
        }
    }
}

impl Drop for TranscodeStream {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
