# RockZero

一个安全、跨平台的个人云服务系统，专为 ARM 开发板和 x86 设备设计。

## 这是什么？

RockZero 是一个类似于群晖 NAS 的开源替代方案，让你可以在自己的硬件上搭建私有云。它包含：

- **后端服务** (Rust) - 提供文件管理、用户认证、媒体处理等 API
- **移动/桌面客户端** (Flutter) - 跨平台的图形界面应用

你可以用它来：
- 📁 管理和浏览你的文件
- 🎬 在线播放视频和音乐（支持硬件加速转码）
- 🔐 安全地存储敏感数据
- 📱 通过手机随时访问你的文件
- 🏠 搭建家庭媒体中心

## 支持的硬件

### ARM 开发板（推荐）
| 设备 | 芯片 | 视频能力 |
|------|------|----------|
| Orange Pi 5 Plus | RK3588 | 8K 硬件编解码 |
| Radxa Rock 5B | RK3588 | 8K 硬件编解码 |
| Khadas VIM3 | A311D | 4K 硬件编解码 |
| Raspberry Pi 4/5 | BCM2711/2712 | 1080p 硬件解码 |

### x86 设备
- Intel NUC
- 普通 PC / 服务器
- 虚拟机 (VMware, VirtualBox, Proxmox)

## 快速开始

### 方式一：Docker 部署（推荐新手）

这是最简单的方式，不需要安装任何开发工具。

```bash
# 1. 下载项目
git clone https://github.com/Blueokanna/RockZeroOS-Service.git
cd RockZeroOS-Service

# 2. 创建配置文件
cp .env.example .env

# 3. 编辑配置（重要！）
# Windows 用户用记事本打开，Linux/Mac 用 nano 或 vim
# 必须修改 JWT_SECRET 和 ENCRYPTION_KEY 为随机字符串

# 4. 启动服务
docker-compose up -d

# 5. 查看日志确认启动成功
docker-compose logs -f
```

服务启动后，访问 `http://你的IP:8080` 即可。

### 方式二：源码编译

适合想要自定义或开发的用户。

**前置要求：**
- Rust 1.70+（[安装指南](https://rustup.rs/)）
- SQLite3
- FFmpeg（可选，用于媒体处理）

```bash
# 1. 安装 Rust（如果没有）
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# 2. 下载项目
git clone https://github.com/Blueokanna/RockZeroOS-Service.git
cd RockZeroOS-Service

# 3. 安装系统依赖
# Ubuntu/Debian:
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev sqlite3

# Arch Linux:
sudo pacman -S base-devel openssl sqlite

# macOS:
brew install openssl sqlite

# 4. 创建配置文件
cp .env.example .env
# 编辑 .env 文件，修改 JWT_SECRET 和 ENCRYPTION_KEY

# 5. 编译并运行
cargo build --release
./target/release/rockzero-service
```

## 配置说明

编辑 `.env` 文件来配置服务：

```bash
# 服务器地址和端口
HOST=0.0.0.0          # 监听所有网卡，改成 127.0.0.1 只允许本机访问
PORT=8080             # 服务端口

# 数据库（默认使用 SQLite，无需额外配置）
DATABASE_URL=sqlite://rockzero.db

# 安全配置（必须修改！）
JWT_SECRET=这里填一个至少32位的随机字符串
ENCRYPTION_KEY=这里也填一个32位的随机字符串

# JWT 令牌有效期
JWT_EXPIRATION_HOURS=24           # 访问令牌24小时过期
REFRESH_TOKEN_EXPIRATION_DAYS=30  # 刷新令牌30天过期

# HTTPS 配置（生产环境建议开启）
TLS_ENABLED=false
TLS_CERT_PATH=./certs/cert.pem
TLS_KEY_PATH=./certs/key.pem

# 日志级别：error, warn, info, debug, trace
RUST_LOG=info
```

**生成随机密钥的方法：**
```bash
# Linux/macOS
openssl rand -hex 32

# 或者用 Python
python3 -c "import secrets; print(secrets.token_hex(32))"
```

## API 使用指南

### 基础概念

RockZero 使用 JWT (JSON Web Token) 进行身份验证。流程是：
1. 注册账号
2. 登录获取 token
3. 后续请求在 Header 中带上 token

### 常用 API 示例

#### 1. 检查服务状态
```bash
curl http://localhost:8080/health
```
返回 `{"status":"ok"}` 表示服务正常。

#### 2. 注册新用户
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "myname",
    "email": "me@example.com",
    "password": "MySecurePassword123!"
  }'
```

> 注意：第一个注册的用户自动成为管理员，后续用户需要邀请码。

#### 3. 登录
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "me@example.com",
    "password": "MySecurePassword123!"
  }'
```

成功后返回：
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": "xxx",
    "username": "myname",
    "email": "me@example.com",
    "role": "admin"
  }
}
```

#### 4. 使用 Token 访问 API

把登录返回的 `access_token` 放到请求头中：

```bash
# 保存 token 到变量（方便后续使用）
TOKEN="eyJhbGciOiJIUzI1NiIs..."

# 获取系统硬件信息
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/system/hardware

# 列出文件目录
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/files/list?path=/

# 获取磁盘信息
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/disk/info
```

### 完整 API 列表

| 模块 | 端点 | 方法 | 说明 |
|------|------|------|------|
| **认证** | `/api/v1/auth/register` | POST | 注册新用户 |
| | `/api/v1/auth/login` | POST | 用户登录 |
| | `/api/v1/auth/refresh` | POST | 刷新 token |
| | `/api/v1/auth/logout` | POST | 退出登录 |
| **文件** | `/api/v1/files/list` | GET | 列出目录内容 |
| | `/api/v1/files/upload` | POST | 上传文件 |
| | `/api/v1/files/download/{path}` | GET | 下载文件 |
| | `/api/v1/files/delete` | DELETE | 删除文件 |
| | `/api/v1/files/mkdir` | POST | 创建文件夹 |
| | `/api/v1/files/rename` | POST | 重命名文件 |
| **系统** | `/api/v1/system/hardware` | GET | 硬件信息 |
| | `/api/v1/system/status` | GET | 系统状态 |
| **磁盘** | `/api/v1/disk/info` | GET | 磁盘列表 |
| | `/api/v1/disk/usage` | GET | 磁盘使用情况 |
| **媒体** | `/api/v1/media/codecs` | GET | 支持的编解码器 |
| | `/api/v1/media/stream/{path}` | GET | 流媒体播放 |
| **应用商店** | `/api/v1/appstore/list` | GET | 可用应用列表 |
| | `/api/v1/appstore/install` | POST | 安装应用 |
| | `/api/v1/docker/containers` | GET | 容器列表 |

## Flutter 客户端

项目包含一个 Flutter 编写的跨平台客户端，位于 `RockZeroOS-UI` 目录。

### 编译客户端

```bash
cd RockZeroOS-UI

# 安装依赖
flutter pub get

# 运行开发版本
flutter run

# 编译 Android APK
flutter build apk --release

# 编译 iOS（需要 macOS）
flutter build ios --release

# 编译 Windows 桌面版
flutter build windows --release

# 编译 Linux 桌面版
flutter build linux --release

# 编译 macOS 桌面版
flutter build macos --release
```

### 客户端功能

- 🏠 仪表盘 - 实时显示 CPU、内存、网络状态
- 📁 文件管理 - 浏览、上传、下载、删除文件
- 🎬 媒体播放 - 内置图片查看器和视频播放器
- 🛒 应用商店 - 一键安装 Docker 应用
- ⚙️ 设置 - 主题切换、安全设置、FIDO2 密钥管理

## 安全特性

RockZero 注重安全性，内置多种保护机制：

- **端到端加密** - 使用 AES-256-GCM 加密敏感数据
- **零知识证明** - 基于 Bulletproofs 的隐私保护
- **FIDO2/Passkey** - 支持硬件安全密钥和生物识别
- **JWT 认证** - 无状态的身份验证机制
- **邀请码系统** - 防止未授权注册

## 常见问题

### Q: 启动时报错 "address already in use"
端口被占用了，修改 `.env` 中的 `PORT` 为其他端口，如 8081。

### Q: 如何开启 HTTPS？
1. 准备 SSL 证书（可以用 Let's Encrypt 免费申请）
2. 修改 `.env`：
   ```
   TLS_ENABLED=true
   TLS_CERT_PATH=/path/to/cert.pem
   TLS_KEY_PATH=/path/to/key.pem
   ```

### Q: 忘记密码怎么办？
目前需要直接操作数据库重置，后续版本会添加密码重置功能。

### Q: 如何备份数据？
备份 `rockzero.db` 文件和你的文件存储目录即可。

### Q: ARM 设备上视频转码很慢？
确保 FFmpeg 正确配置了硬件加速。RK3588 设备需要安装 `librockchip-mpp`。

## 项目结构

```
RockZeroOS-Service/
├── src/                    # Rust 后端源码
│   ├── main.rs            # 程序入口
│   ├── auth.rs            # 认证逻辑
│   ├── crypto.rs          # 加密模块
│   ├── handlers/          # API 处理器
│   │   ├── auth.rs        # 认证 API
│   │   ├── files.rs       # 文件 API
│   │   ├── media.rs       # 媒体 API
│   │   └── ...
│   └── ...
├── RockZeroOS-UI/          # Flutter 客户端
│   ├── lib/
│   │   ├── main.dart      # 应用入口
│   │   ├── core/          # 核心模块
│   │   └── features/      # 功能模块
│   └── ...
├── scripts/                # 部署脚本
├── docker-compose.yml      # Docker 配置
├── Cargo.toml             # Rust 依赖配置
└── .env.example           # 配置模板
```

## 贡献指南

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建你的功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

## 开源协议

本项目采用 MIT 协议开源，详见 [LICENSE](LICENSE) 文件。

## 致谢

- [Actix Web](https://actix.rs/) - 高性能 Rust Web 框架
- [Flutter](https://flutter.dev/) - 跨平台 UI 框架
- [FFmpeg](https://ffmpeg.org/) - 多媒体处理
- [CasaOS AppStore Play](https://github.com/Cp0204/CasaOS-AppStore-Play) - 应用商店数据

---

Made with ❤️ by [Blueokanna](https://github.com/Blueokanna)

如有问题，欢迎提 [Issue](https://github.com/Blueokanna/RockZeroOS-Service/issues) 或加入讨论！
