# Windows 开发环境说明

## 重要提示

**RockZero 是为 Linux 生产环境设计的跨平台服务。**

本项目针对以下 Linux 平台进行了优化：
- x86_64 (AMD64)
- aarch64 (ARM64) - Rockchip, Amlogic等
- armv7/armv8
- x86 (i386)

## Windows 环境限制

在 Windows 上开发时会遇到以下限制：

### 1. OpenSSL 依赖
```
error: failed to run custom build command for `openssl-sys`
```

**解决方案**:
- 安装 [vcpkg](https://github.com/microsoft/vcpkg)
- 运行: `vcpkg install openssl:x64-windows`
- 设置环境变量: `OPENSSL_DIR=C:\vcpkg\installed\x64-windows`

或使用 WSL2 (推荐):
```bash
wsl --install
wsl
cd /mnt/d/RustProject/RockZeroOS
./scripts/install-dependencies.sh
cargo build --release
```

### 2. FFmpeg 依赖
Windows 上 `ffmpeg-next` 需要手动安装 FFmpeg 开发库。

**解决方案**:
- 下载 [FFmpeg Windows builds](https://www.gyan.dev/ffmpeg/builds/)
- 设置环境变量指向 FFmpeg 路径

### 3. 硬件检测功能
以下功能仅在 Linux 上可用：
- USB 设备详细检测 (`/sys/bus/usb/devices`)
- CPU 温度读取 (`/sys/class/thermal`)
- 硬件加速设备 (`/dev/video*`, `/dev/dri/*`)
- V4L2/MPP/VAAPI 支持

### 4. FIDO2/WebAuthn
`pcscd` 服务和智能卡支持在 Windows 上需要额外配置。

## 推荐的开发方式

### 方式 1: WSL2 (最佳)
```bash
# 在 Windows PowerShell 中
wsl --install Ubuntu-22.04

# 进入 WSL
wsl

# 安装依赖
cd /mnt/d/RustProject/RockZeroOS
chmod +x scripts/install-dependencies.sh
./scripts/install-dependencies.sh

# 编译和运行
cargo build --release
./target/release/rockzero-service
```

### 方式 2: Docker Desktop
```bash
# 在 Windows PowerShell 中
docker-compose -f docker-compose.multiarch.yml build
docker-compose -f docker-compose.multiarch.yml up
```

### 方式 3: 远程 Linux 开发
使用 VS Code Remote SSH 连接到 Linux 服务器进行开发。

## 仅代码编辑

如果只需要在 Windows 上编辑代码（不编译），可以：

1. 使用 VS Code 或其他 IDE 进行代码编辑
2. 使用 `rust-analyzer` 进行代码补全和检查
3. 通过 Git 推送到 Linux 服务器进行实际编译和测试

## 生产部署

**生产环境必须使用 Linux 系统**，推荐：

- Ubuntu 20.04+ / Debian 11+
- CentOS 8+ / Rocky Linux 8+
- Armbian (ARM 设备)
- Raspberry Pi OS

参见 [DEPLOYMENT.md](DEPLOYMENT.md) 获取完整部署指南。

## 跨平台构建

在 Linux 环境中使用提供的脚本构建所有平台：

```bash
# 在 Linux 上
./build-cross-platform.sh

# 输出文件
./dist/rockzero-service-x86_64-unknown-linux-gnu.tar.gz
./dist/rockzero-service-aarch64-unknown-linux-gnu.tar.gz
./dist/rockzero-service-armv7-unknown-linux-gnueabihf.tar.gz
./dist/rockzero-service-i686-unknown-linux-gnu.tar.gz
```

## 总结

- ✅ Windows: 代码编辑、查看、Git 操作
- ❌ Windows: 完整编译、硬件检测、媒体处理
- ✅ WSL2: 完整开发和测试
- ✅ Linux: 生产部署和完整功能

如有问题，请参考 [DEPLOYMENT.md](DEPLOYMENT.md) 或提交 Issue。
