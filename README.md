# 🚀 RockZero - 安全的跨平台 NAS 服务

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

基于 Rust 的高性能、安全的跨平台 NAS 服务，支持 SAE 密钥协商和加密 HLS 视频播放。

## ✨ 特性

### 🔐 安全特性
- **SAE 密钥协商** - 基于 Dragonfly 协议的安全密钥交换
- **端到端加密** - AES-128-GCM 加密的 HLS 视频流
- **零知识证明** - Bulletproofs 支持
- **FIDO2/WebAuthn** - 硬件密钥认证

### 🎬 媒体功能
- **HLS 流媒体** - 支持所有视频格式（FFmpeg 转码）
- **加密播放** - 分片级别的加密保护
- **多音轨支持** - 音轨和字幕切换
- **自适应码率** - 多清晰度支持

### 💾 存储管理
- **文件管理** - 完整的文件系统操作
- **磁盘管理** - 硬盘检测和管理（Linux）
- **WebDAV** - 标准 WebDAV 协议支持
- **Docker 集成** - 容器管理和应用商店

### 🌐 跨平台
- **Windows** - 完整支持
- **Linux** - 完整支持（包括硬件管理）
- **macOS** - 完整支持
- **Flutter 客户端** - iOS、Android、Web、Desktop

## 📦 项目结构

```
rockzero/
├── crates/
│   ├── rockzero-common/      # 通用库
│   ├── rockzero-sae/         # SAE 密钥协商
│   ├── rockzero-crypto/      # 加密工具
│   ├── rockzero-hls/         # 加密 HLS
│   ├── rockzero-ffi/         # Flutter FFI
│   └── rockzero-service/     # 主服务
└── RockZeroOS-UI/            # Flutter 前端
```

## 🚀 快速开始

### 前置要求

- Rust 1.70+
- FFmpeg（用于媒体处理）
- SQLite

### 编译

```bash
# 克隆仓库
git clone https://github.com/yourusername/rockzero.git
cd rockzero

# 编译所有 crates
cargo build --workspace --release

# 运行测试
cargo test --workspace
```

### 运行服务

```bash
# 开发模式
cargo run -p rockzero-service

# Release 模式
cargo run -p rockzero-service --release

# 指定配置
cargo run -p rockzero-service -- --config config.toml
```

### 配置

创建 `.env` 文件：

```env
RUST_LOG=info
DATABASE_URL=sqlite:./data/rockzero.db
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
JWT_SECRET=your-secret-key-here
```

## 📚 文档

- **[FINAL_SUMMARY.md](FINAL_SUMMARY.md)** - 项目总结和快速开始 ⭐
- **[BUILD_GUIDE.md](BUILD_GUIDE.md)** - 详细的构建指南
- **[SECURE_HLS_ARCHITECTURE.md](SECURE_HLS_ARCHITECTURE.md)** - 架构设计文档
- **[SAE_QUICK_START.md](SAE_QUICK_START.md)** - SAE 和 HLS 快速开始
- **[MIGRATION_COMPLETE.md](MIGRATION_COMPLETE.md)** - 迁移说明

## 🔐 SAE 密钥协商

基于 Dragonfly/SAE 协议的安全密钥交换：

```rust
use rockzero_sae::{SaeClient, SaeServer};

// 客户端
let mut client = SaeClient::new(password, client_id, server_id);
let commit = client.generate_commit()?;

// 服务端
let mut server = SaeServer::new(password, server_id, client_id);
let (server_commit, server_confirm) = server.process_commit(&commit)?;

// 完成握手
let client_confirm = client.process_commit(&server_commit)?;
client.verify_confirm(&server_confirm)?;
server.verify_confirm(&client_confirm)?;

// 获取共享密钥
let pmk = client.get_pmk()?;
```

## 🎬 加密 HLS

安全的 HLS 视频流：

```rust
use rockzero_hls::{HlsSession, PlaylistGenerator};

// 创建会话
let session = HlsSession::new(user_id, file_path, pmk, 1000)?;

// 加密分片
let encrypted = session.encrypt_segment(&ts_data)?;

// 生成播放列表
let generator = PlaylistGenerator::new(session_id, base_url);
let playlist = generator.generate_media_playlist(100, 6.0, true);
```

## 🔧 API 端点

### 认证
- `POST /api/v1/auth/register` - 用户注册
- `POST /api/v1/auth/login` - 用户登录
- `POST /api/v1/auth/refresh` - 刷新 Token

### SAE 握手
- `POST /api/v1/sae/init` - 初始化 SAE 握手
- `POST /api/v1/sae/commit` - 交换 Commit
- `POST /api/v1/sae/confirm` - 确认握手

### 加密 HLS
- `POST /api/v1/secure-hls/start` - 启动加密 HLS 会话
- `GET /api/v1/secure-hls/{id}/master.m3u8` - 主播放列表
- `GET /api/v1/secure-hls/{id}/playlist.m3u8` - 媒体播放列表
- `GET /api/v1/secure-hls/{id}/key` - 获取加密密钥
- `GET /api/v1/secure-hls/{id}/segment_{n}.ts` - 获取加密分片

### 文件管理
- `GET /api/v1/filemanager/list` - 列出文件
- `POST /api/v1/filemanager/upload` - 上传文件
- `GET /api/v1/filemanager/download` - 下载文件
- `DELETE /api/v1/filemanager/delete` - 删除文件

## 🧪 测试

```bash
# 运行所有测试
cargo test --workspace -- --nocapture

# 测试 SAE
cargo test -p rockzero-sae -- --nocapture

# 测试 HLS
cargo test -p rockzero-hls -- --nocapture

# 基准测试
cargo bench --workspace
```

## 📊 性能

- **SAE 握手**: ~5-10ms
- **AES-GCM 加密**: ~500 MB/s (单核)
- **HKDF 密钥派生**: ~0.1ms
- **HLS 分片加密**: 并行处理，高吞吐量

## 🛠️ 开发

### 代码检查

```bash
# Clippy
cargo clippy --workspace -- -D warnings

# 格式化
cargo fmt --all

# 审计
cargo audit
```

### 监视模式

```bash
# 自动重新编译
cargo watch -x 'build --workspace'

# 自动运行测试
cargo watch -x 'test --workspace'
```

## 🤝 贡献

欢迎贡献！请查看 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🙏 致谢

- [Actix Web](https://actix.rs/) - Web 框架
- [Curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) - 椭圆曲线密码学
- [FFmpeg](https://ffmpeg.org/) - 媒体处理
- [Flutter](https://flutter.dev/) - 跨平台 UI

## 📞 联系

- 项目主页: [https://github.com/yourusername/rockzero](https://github.com/yourusername/rockzero)
- 问题反馈: [Issues](https://github.com/yourusername/rockzero/issues)

---

**⭐ 如果这个项目对你有帮助，请给个 Star！**

Made with ❤️ by RockZero Team
