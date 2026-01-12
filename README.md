# RockZero Secure Service

**Cross-Platform | Hardware Acceleration | Zero-Knowledge Proof | FIDO2 Authentication**

[中文文档](README_CN.md) | [Deployment Guide](DEPLOYMENT.md) | [API Documentation](API_COMPLETE.md)

## Features

### 🔐 Security
- Zero-Knowledge Proof (Bulletproofs)
- FIDO2/WebAuthn hardware key support
- End-to-end encryption (AES-256-GCM)
- JWT authentication
- Anti-tampering invite code system

### 🎬 Media Processing
- Hardware-accelerated encoding/decoding
  - Rockchip MPP (RK3588, RK3568)
  - Amlogic VDEC (A311D)
  - Intel VAAPI
  - NVIDIA NVENC
  - V4L2 M2M
- Multi-format support: H.264, H.265, VP8, VP9, AV1
- Real-time transcoding with 4K@60fps
- Audio processing: AAC, MP3, Opus, FLAC

### 💻 Cross-Platform
- ✅ x86_64 (AMD64)
- ✅ x86 (i386)
- ✅ aarch64 (ARM64)
- ✅ armv7
- ✅ armv8

### 🔧 Hardware Detection
- Accurate CPU detection (model, cores, frequency, temperature)
- Real-time memory monitoring
- Storage device identification (HDD/SSD/NVMe/MMC/USB)
- USB hot-plug detection
- GPU/VPU auto-detection and configuration

### 📦 App Store
- CasaOS AppStore Play integration
- Docker container management
- One-click install/start/stop
- Automatic updates

## Quick Start

```bash
# Clone repository
git clone https://github.com/your-org/rockzero.git
cd rockzero

# Install dependencies (auto-detects platform)
chmod +x scripts/install-dependencies.sh
./scripts/install-dependencies.sh

# Configure environment
cp .env.example .env
nano .env  # Edit JWT_SECRET and ENCRYPTION_KEY

# Start with Docker (recommended)
docker-compose -f docker-compose.multiarch.yml up -d

# Or build and run natively
cargo build --release
./target/release/rockzero-service
```

## Documentation

- [中文部署指南](DEPLOYMENT.md)
- [API Documentation](API_COMPLETE.md)
- [Production Ready Guide](PRODUCTION_READY.md)

## Supported Hardware

### ARM Boards
- Orange Pi 5 Plus (RK3588) - 8K video
- Radxa Rock 5B (RK3588) - 8K video
- Khadas VIM3 (A311D) - 4K video
- Raspberry Pi 4/5 - 1080p video
- Odroid N2+ (S922X) - 4K video

### x86 Devices
- Intel NUC (all models)
- Standard PC/Servers
- Virtual Machines (VMware, VirtualBox, KVM)

## API Examples

```bash
# Health check
curl http://localhost:8443/health

# Register user
curl -X POST http://localhost:8443/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@example.com","password":"SecurePass123!"}'

# Login
curl -X POST http://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"SecurePass123!"}'

# Get hardware info
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8443/api/v1/system/hardware

# Get codec support
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8443/api/v1/media/codecs
```

## License

MIT License - see [LICENSE](LICENSE) file

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

## Acknowledgments

- [CasaOS AppStore Play](https://github.com/Cp0204/CasaOS-AppStore-Play)
- [Actix Web](https://actix.rs/)
- [FFmpeg](https://ffmpeg.org/)
- [WebAuthn-rs](https://github.com/kanidm/webauthn-rs)
- [Bulletproofs](https://github.com/dalek-cryptography/bulletproofs)

---

Made with ❤️ by RockZero Team
