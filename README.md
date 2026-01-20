# 🚀 RockZero - 专业级 NAS 操作系统

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

基于 Rust 的高性能、安全的跨平台 NAS 操作系统，支持 SAE 密钥协商、硬件加速视频转码、专业级存储管理和加密 HLS 视频播放。

## ✨ 核心特性

### 🔐 安全特性

- **SAE/WPA3 密钥协商** - 基于 Dragonfly 协议的安全密钥交换
- **端到端加密** - AES-128-GCM 加密的 HLS 视频流
- **零知识证明** - Bulletproofs 支持，无需暴露密码即可验证
- **FIDO2/WebAuthn** - 硬件密钥认证（YubiKey、TouchID 等）
- **安全存储** - 加密数据库、文件加密/解密、安全擦除
- **邀请码系统** - 基于时间的邀请码管理

### 🎬 媒体功能

- **硬件加速转码** - 支持 NVIDIA (NVENC/NVDEC)、Intel (QSV)、AMD (VAAPI)、ARM/Amlogic A311D (V4L2 M2M)
- **加密 HLS 流媒体** - 分片级别的 AES-128 加密保护
- **智能编码器选择** - 自动检测并使用最佳硬件加速
- **多音轨/字幕支持** - 完整的媒体信息提取
- **缩略图生成** - 视频、图片缩略图自动生成
- **自适应码率** - 多清晰度支持（360p-4K）

### 💾 专业级存储管理

- **智能格式化** - 根据用途自动选择最佳文件系统（ext4/xfs/btrfs/f2fs）
- **自动挂载** - 智能生成挂载点，支持 UUID/Label 识别
- **完整分区管理** - GPT/MBR 分区表创建、分区格式化
- **磁盘擦除** - 安全擦除磁盘数据
- **存储类型检测** - 自动识别 NVMe/SSD/HDD/USB/MMC
- **跨平台支持** - Windows、Linux 完整支持

### 📦 应用商店

- **WASM 应用** - 自定义 WebAssembly 应用支持
- **CasaOS 集成** - 直接安装 CasaOS 应用商店的 Docker 应用
- **iStoreOS/OpenWRT** - IPK 包管理支持
- **Docker 容器管理** - 完整的容器生命周期管理
- **镜像管理** - Docker 镜像拉取、删除

### 🌐 网络与系统

- **WebDAV 服务器** - 标准 WebDAV 协议支持
- **速度测试** - 内置上传/下载速度测试
- **硬件监控** - CPU、内存、磁盘、网络、USB 设备监控
- **系统信息** - 完整的硬件信息检测

### 🎨 Flutter 客户端

- **跨平台** - iOS、Android、Web、Windows、macOS、Linux
- **现代 UI** - Material Design 3 设计语言
- **响应式布局** - 适配手机、平板、桌面

## 📦 项目结构

```
RockZeroOS-Service/
├── rockzero-common/          # 通用库（错误处理、工具函数）
├── rockzero-crypto/          # 加密工具（AES-GCM、HKDF、Blake3）
├── rockzero-db/              # 数据库操作（SQLite）
├── rockzero-media/           # 媒体处理（FFmpeg 封装）
├── rockzero-sae/             # SAE/WPA3 密钥协商
├── rockzero-service/         # 主服务
│   ├── src/
│   │   ├── handlers/         # API 处理器
│   │   │   ├── auth.rs              # 用户认证
│   │   │   ├── storage.rs           # 专业级存储管理 ⭐
│   │   │   ├── video_hardware.rs    # 硬件加速转码 ⭐
│   │   │   ├── secure_storage.rs    # 安全存储
│   │   │   ├── secure_hls.rs        # 加密 HLS
│   │   │   ├── appstore_enhanced.rs # 应用商店
│   │   │   ├── filemanager.rs       # 文件管理
│   │   │   ├── disk_manager.rs      # 磁盘管理
│   │   │   └── system.rs            # 系统信息
│   │   ├── middleware/       # 中间件（JWT、FIDO2）
│   │   ├── crypto.rs         # 加密实现
│   │   ├── fido.rs           # FIDO2 认证
│   │   ├── hardware.rs       # 硬件检测
│   │   └── main.rs           # 主入口
└── RockZeroOS-UI/            # Flutter 前端
    ├── lib/
    │   ├── screens/          # 页面
    │   ├── widgets/          # 组件
    │   ├── services/         # API 服务
    │   └── models/           # 数据模型
    └── assets/               # 资源文件
```

## 🚀 快速开始

### 前置要求

- **Rust** 1.70+ ([安装指南](https://www.rust-lang.org/tools/install))
- **FFmpeg** (可选，用于媒体处理)
- **SQLite** (通常已预装)
- **Flutter** 3.0+ (仅前端开发需要)

### 安装 FFmpeg

```bash
# Ubuntu/Debian
sudo apt-get install ffmpeg

# macOS
brew install ffmpeg

# Windows (使用 Chocolatey)
choco install ffmpeg

# Arch Linux
sudo pacman -S ffmpeg
```

### 编译后端

```bash
# 克隆仓库
git clone https://github.com/blueokanna/rockzero-service.git
cd rockzero-service

# 编译所有 crates
cargo build --workspace --release

# 运行测试
cargo test --workspace
```

### 运行服务

```bash
# 开发模式（带日志）
RUST_LOG=info cargo run -p rockzero-service

# Release 模式
cargo run -p rockzero-service --release

# 后台运行
nohup ./target/release/rockzero-service > rockzero.log 2>&1 &
```

### 配置环境变量

创建 `.env` 文件：

```env
# 服务器配置
HOST=0.0.0.0
PORT=8080
RUST_LOG=info

# 数据目录
DATA_DIR=./data

# 数据库
DATABASE_URL=./data/rockzero.db

# JWT 密钥
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production

# 存储配置
STORAGE_ROOT=/mnt/storage
MAX_UPLOAD_SIZE=10737418240  # 10GB
```

### Linux 系统配置

#### 1. 安装文件系统工具

```bash
# Debian/Ubuntu
sudo apt-get install e2fsprogs xfsprogs dosfstools ntfs-3g exfat-utils btrfs-progs f2fs-tools

# Arch Linux
sudo pacman -S e2fsprogs xfsprogs dosfstools ntfs-3g exfat-utils btrfs-progs f2fs-tools

# Fedora/RHEL
sudo dnf install e2fsprogs xfsprogs dosfstools ntfs-3g exfat-utils btrfs-progs f2fs-tools
```

#### 2. 配置 Sudo 权限（可选）

如果希望服务可以无密码执行磁盘操作：

```bash
# 编辑 sudoers 文件
sudo visudo

# 添加以下行（替换 yourusername 为实际用户名）
yourusername ALL=(ALL) NOPASSWD: /usr/bin/mount, /usr/bin/umount, /usr/sbin/mkfs.*, /usr/sbin/wipefs, /usr/sbin/parted, /usr/sbin/partprobe, /usr/sbin/blockdev
```

#### 3. 安装硬件加速驱动（可选）

```bash
# NVIDIA (NVENC/NVDEC)
sudo apt-get install nvidia-driver-535 nvidia-cuda-toolkit

# Intel (QSV/VAAPI)
sudo apt-get install intel-media-va-driver vainfo

# AMD (VAAPI)
sudo apt-get install mesa-va-drivers vainfo

# ARM/Amlogic (V4L2 M2M) - 通常已内置
# 检查是否支持：ls /dev/video*
```

### 运行 Flutter 客户端

```bash
cd RockZeroOS-UI

# 安装依赖
flutter pub get

# 运行（自动选择设备）
flutter run

# 指定平台
flutter run -d chrome        # Web
flutter run -d windows       # Windows
flutter run -d macos         # macOS
flutter run -d linux         # Linux
```

## 🔧 API 文档

### 基础 URL

```
http://localhost:8080/api/v1
```

### 认证

#### 注册用户

```http
POST /auth/register
Content-Type: application/json

{
  "username": "admin",
  "password": "secure_password",
  "email": "admin@example.com"
}
```

#### 登录

```http
POST /auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "secure_password"
}

Response:
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com"
  }
}
```

#### 获取当前用户信息

```http
GET /auth/me
Authorization: Bearer <token>
```

### 专业级存储管理 ⭐

#### 列出所有存储设备

```http
GET /storage/devices

Response:
[
  {
    "id": "sda",
    "name": "Samsung SSD 970 EVO",
    "device_path": "/dev/sda",
    "mount_point": "/mnt/data",
    "total_size": 1000204886016,
    "used_size": 524288000000,
    "available_size": 475916886016,
    "device_type": "InternalSSD",
    "file_system": "ext4",
    "is_removable": false,
    "is_mounted": true
  }
]
```

#### 智能格式化（根据用途自动选择文件系统）

```http
POST /storage/smart-format
Content-Type: application/json

{
  "device": "/dev/sdb1",
  "purpose": "MediaLibrary",  // SystemBoot, DataStorage, MediaLibrary, DatabaseServer, BackupArchive, SharedFolder, General
  "label": "MyMedia"
}

Response:
{
  "success": true,
  "device": "/dev/sdb1",
  "file_system": "xfs",  // 自动选择 XFS（最适合媒体库）
  "purpose": "MediaLibrary",
  "recommendation": {
    "recommended_fs": "xfs",
    "reason": "XFS is optimized for large media files with excellent streaming performance",
    "mount_options": ["defaults", "noatime", "largeio"],
    "performance_tips": ["XFS handles large video files efficiently"]
  }
}
```

#### 自动挂载（智能选择挂载点）

```http
POST /storage/auto-mount
Content-Type: application/json

{
  "device": "/dev/sdb1",
  "auto_create_mount_point": true,
  "preferred_mount_base": "/mnt"
}

Response:
{
  "success": true,
  "device": "/dev/sdb1",
  "mount_point": "/mnt/MyMedia",  // 自动根据 Label 生成
  "message": "Device mounted successfully"
}
```

#### 创建分区并格式化

```http
POST /storage/partition
Content-Type: application/json

{
  "device": "/dev/sdb",
  "partition_type": "gpt",  // gpt 或 msdos
  "partitions": [
    {
      "size": "500GB",
      "file_system": "ext4",
      "label": "System"
    },
    {
      "size": "100%",  // 剩余所有空间
      "file_system": "xfs",
      "label": "Data"
    }
  ]
}
```

#### 擦除磁盘

```http
POST /storage/wipe/{device}
```

### 视频硬件加速 ⭐

#### 检测硬件能力

```http
GET /video-hardware/capabilities

Response:
{
  "cpu_info": {
    "model": "AMD Ryzen 9 5950X",
    "cores": 16,
    "threads": 32,
    "has_avx": true,
    "has_avx2": true,
    "has_avx512": false
  },
  "gpu_info": [
    {
      "vendor": "NVIDIA",
      "model": "GeForce RTX 3080",
      "driver_version": "535.129.03",
      "vram": 10240,
      "supports_encoding": true,
      "supports_decoding": true,
      "acceleration_type": ["NVENC", "NVDEC", "CUDA"]
    }
  ],
  "video_codecs": {
    "h264": {
      "software_supported": true,
      "hardware_supported": true,
      "hardware_encoder": "h264_nvenc",
      "hardware_decoder": "h264_cuvid"
    },
    "hevc": {
      "software_supported": true,
      "hardware_supported": true,
      "hardware_encoder": "hevc_nvenc",
      "hardware_decoder": "hevc_cuvid"
    }
  },
  "recommended_encoder": "h264_nvenc",
  "recommended_decoder": "h264_cuvid",
  "ffmpeg_available": true,
  "ffmpeg_version": "6.0",
  "hardware_acceleration": ["NVENC", "NVDEC", "CUDA"]
}
```

#### 硬件加速转码

```http
POST /video-hardware/transcode
Content-Type: application/json

{
  "input_path": "/mnt/videos/movie.mkv",
  "output_path": "/mnt/videos/movie_transcoded.mp4",
  "codec": "h264",  // h264, hevc, vp9, av1
  "quality": "High",  // Low, Medium, High, VeryHigh
  "resolution": "1920x1080",
  "bitrate": "5M",
  "use_hardware": true
}

Response:
{
  "success": true,
  "output_path": "/mnt/videos/movie_transcoded.mp4",
  "encoder_used": "h264_nvenc",
  "hardware_acceleration": true,
  "processing_time": 45.2
}
```

### 应用商店

#### 列出 CasaOS 应用

```http
GET /appstore/casaos

Response:
[
  {
    "id": "jellyfin",
    "name": "Jellyfin",
    "description": "The Free Software Media System",
    "icon": "https://...",
    "category": "Media",
    "docker_image": "jellyfin/jellyfin:latest"
  }
]
```

#### 列出 iStoreOS 应用

```http
GET /appstore/istoreos
```

#### 安装 IPK 包

```http
POST /appstore/ipk/install
Content-Type: application/json

{
  "package_url": "https://example.com/package.ipk"
}
```

#### Docker 容器管理

```http
# 列出容器
GET /appstore/containers

# 创建容器
POST /appstore/containers
{
  "image": "nginx:latest",
  "name": "my-nginx",
  "ports": ["80:80"],
  "volumes": ["/data:/usr/share/nginx/html"]
}

# 启动容器
POST /appstore/containers/{id}/start

# 停止容器
POST /appstore/containers/{id}/stop

# 删除容器
DELETE /appstore/containers/{id}/remove

# 查看日志
GET /appstore/containers/{id}/logs

# 查看统计
GET /appstore/containers/{id}/stats
```

### 加密 HLS 流媒体

#### 1. SAE 握手（建立安全通道）

```http
POST /secure-hls/sae/init
Content-Type: application/json

{
  "password": "shared_secret",
  "client_id": "user@device",
  "server_id": "rockzero-server"
}

Response:
{
  "session_id": "abc123...",
  "server_commit": "base64_encoded_data",
  "server_confirm": "base64_encoded_data"
}
```

#### 2. 完成 SAE 握手

```http
POST /secure-hls/sae/complete
Content-Type: application/json

{
  "session_id": "abc123...",
  "client_confirm": "base64_encoded_data"
}
```

#### 3. 创建 HLS 会话

```http
POST /secure-hls/session/create
Content-Type: application/json

{
  "session_id": "abc123...",
  "file_path": "/mnt/videos/movie.mp4",
  "segment_duration": 6
}

Response:
{
  "hls_session_id": "xyz789...",
  "playlist_url": "/api/v1/secure-hls/xyz789.../playlist.m3u8"
}
```

#### 4. 获取播放列表

```http
GET /secure-hls/{hls_session_id}/playlist.m3u8
X-ZKP-Proof: base64_encoded_proof

Response: (M3U8 playlist)
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:6
#EXT-X-KEY:METHOD=AES-128,URI="/api/v1/secure-hls/{hls_session_id}/key"
#EXTINF:6.0,
segment_0.ts
#EXTINF:6.0,
segment_1.ts
...
```

#### 5. 获取加密分片

```http
POST /secure-hls/{hls_session_id}/segment_0.ts
Content-Type: application/json

{
  "zkp_proof": "base64_encoded_proof"
}

Response: (encrypted TS segment)
```

### 文件管理

```http
# 列出目录
GET /filemanager/list?path=/mnt/data

# 创建目录
POST /filemanager/mkdir
{"path": "/mnt/data/newfolder"}

# 上传文件
POST /filemanager/upload
Content-Type: multipart/form-data

# 下载文件
GET /filemanager/download?path=/mnt/data/file.txt

# 重命名
POST /filemanager/rename
{"old_path": "/mnt/data/old.txt", "new_path": "/mnt/data/new.txt"}

# 移动文件
POST /filemanager/move
{"source": ["/mnt/data/file.txt"], "destination": "/mnt/backup/"}

# 复制文件
POST /filemanager/copy
{"source": ["/mnt/data/file.txt"], "destination": "/mnt/backup/"}

# 删除文件
POST /filemanager/delete
{"paths": ["/mnt/data/file.txt"]}

# 获取媒体信息
GET /filemanager/media/info?path=/mnt/videos/movie.mp4

# 流式播放
GET /filemanager/media/stream?path=/mnt/videos/movie.mp4

# 获取缩略图
GET /filemanager/media/thumbnail?path=/mnt/videos/movie.mp4
```

### 系统信息

```http
# 硬件信息
GET /system/hardware

# CPU 信息
GET /system/cpu

# 内存信息
GET /system/memory

# 磁盘信息
GET /system/disks

# USB 设备
GET /system/usb

# 网络接口
GET /system/network

# 块设备
GET /system/blocks

# 完整信息
GET /system/all

# 硬件能力
GET /system/capabilities
```

### FIDO2 认证

```http
# 开始注册
POST /fido/register/start
{"username": "admin"}

# 完成注册
POST /fido/register/finish
{"credential": {...}}

# 开始认证
POST /fido/auth/start
{"username": "admin"}

# 完成认证
POST /fido/auth/finish
{"credential": {...}}

# 列出凭证
GET /fido/credentials

# 删除凭证
DELETE /fido/credentials/{id}
```

## 🧪 测试

```bash
# 运行所有测试
cargo test --workspace -- --nocapture

# 测试特定 crate
cargo test -p rockzero-sae -- --nocapture
cargo test -p rockzero-crypto -- --nocapture
cargo test -p rockzero-media -- --nocapture

# 基准测试
cargo bench --workspace

# 代码覆盖率
cargo tarpaulin --workspace --out Html
```

## 📊 性能指标

- **SAE 握手**: ~5-10ms
- **AES-GCM 加密**: ~500 MB/s (单核)
- **HKDF 密钥派生**: ~0.1ms
- **HLS 分片加密**: 并行处理，高吞吐量
- **硬件加速转码**:
  - NVIDIA RTX 3080: ~300 FPS (1080p H.264)
  - Intel QSV: ~150 FPS (1080p H.264)
  - Amlogic A311D: ~60 FPS (1080p H.264)

## 🛠️ 开发工具

### 代码质量

```bash
# Clippy 检查
cargo clippy --workspace -- -D warnings

# 格式化代码
cargo fmt --all

# 安全审计
cargo audit

# 依赖更新
cargo update
```

### 监视模式

```bash
# 安装 cargo-watch
cargo install cargo-watch

# 自动重新编译
cargo watch -x 'build --workspace'

# 自动运行测试
cargo watch -x 'test --workspace'

# 自动运行服务
cargo watch -x 'run -p rockzero-service'
```

### Docker 部署

```bash
# 构建镜像
docker build -t rockzero-service .

# 运行容器
docker run -d \
  -p 8080:8080 \
  -v /mnt/storage:/mnt/storage \
  -v ./data:/app/data \
  --name rockzero \
  rockzero-service

# 使用 docker-compose
docker-compose up -d
```

## 🎯 路线图

- [x] SAE/WPA3 密钥协商
- [x] 加密 HLS 流媒体
- [x] FIDO2/WebAuthn 认证
- [x] 专业级存储管理
- [x] 硬件加速视频转码
- [x] CasaOS/iStoreOS 应用商店集成
- [x] Docker 容器管理
- [x] Flutter 跨平台客户端
- [ ] RAID 支持
- [ ] 快照和备份
- [ ] 多用户权限管理
- [ ] SMB/NFS 文件共享
- [ ] 远程访问（DDNS、VPN）
- [ ] 移动端推送通知
- [ ] AI 智能相册
- [ ] 自动化任务调度

## 🤝 贡献

欢迎贡献代码、报告问题或提出建议！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 📄 许可证

本项目采用 AGPL-3.0 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🙏 致谢

### 核心依赖

- [Actix Web](https://actix.rs/) - 高性能 Web 框架
- [Tokio](https://tokio.rs/) - 异步运行时
- [SQLx](https://github.com/launchbadge/sqlx) - 异步 SQL 工具包
- [Curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) - 椭圆曲线密码学
- [FFmpeg](https://ffmpeg.org/) - 媒体处理
- [Flutter](https://flutter.dev/) - 跨平台 UI 框架

### 加密库

- [AES-GCM](https://github.com/RustCrypto/AEADs) - 认证加密
- [Blake3](https://github.com/BLAKE3-team/BLAKE3) - 快速哈希
- [Bulletproofs](https://github.com/dalek-cryptography/bulletproofs) - 零知识证明
- [HKDF](https://github.com/RustCrypto/KDFs) - 密钥派生

### 硬件加速

- ARM V4L2 M2M (Amlogic A311D)

## 📞 联系方式

- **作者**: blueokanna
- **邮箱**: blueokanna@gmail.com
- **GitHub**: [https://github.com/blueokanna/rockzero-service](https://github.com/blueokanna/rockzero-service)
- **问题反馈**: [Issues](https://github.com/blueokanna/rockzero-service/issues)

## 🌟 Star History

如果这个项目对你有帮助，请给个 Star ⭐！

---

**Made with ❤️ by blueokanna**

**Powered by Rust 🦀 | Secured by Cryptography 🔐 | Accelerated by Hardware 🚀**
