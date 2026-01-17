#!/bin/bash

set -e

echo "=== RockZero 跨平台依赖安装 ==="
echo ""

detect_platform() {
    ARCH=$(uname -m)
    OS=$(uname -s)
    
    echo "检测到系统: $OS $ARCH"
    
    case "$ARCH" in
        x86_64|amd64)
            PLATFORM="x86_64"
            RUST_TARGET="x86_64-unknown-linux-gnu"
            ;;
        aarch64|arm64)
            PLATFORM="aarch64"
            RUST_TARGET="aarch64-unknown-linux-gnu"
            ;;
        armv7l|armv7)
            PLATFORM="armv7"
            RUST_TARGET="armv7-unknown-linux-gnueabihf"
            ;;
        armv8l|armv8)
            PLATFORM="armv8"
            RUST_TARGET="aarch64-unknown-linux-gnu"
            ;;
        i686|i386|i586)
            PLATFORM="x86"
            RUST_TARGET="i686-unknown-linux-gnu"
            ;;
        *)
            echo "不支持的架构: $ARCH"
            exit 1
            ;;
    esac
    
    echo "平台: $PLATFORM"
    echo "Rust目标: $RUST_TARGET"
}

install_rust() {
    if command -v rustc &> /dev/null; then
        echo "✓ Rust 已安装: $(rustc --version)"
        return
    fi
    
    echo "安装 Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    
    rustup target add $RUST_TARGET
    
    echo "✓ Rust 安装完成"
}

install_ffmpeg() {
    echo "安装 FFmpeg 和媒体编解码器..."
    
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y \
            ffmpeg \
            libavcodec-dev \
            libavformat-dev \
            libavutil-dev \
            libavfilter-dev \
            libswscale-dev \
            libswresample-dev \
            pkg-config
        
        # ARM 特定编解码器
        if [ "$PLATFORM" = "aarch64" ] || [ "$PLATFORM" = "armv7" ] || [ "$PLATFORM" = "armv8" ]; then
            echo "安装 ARM 硬件加速支持..."
            
            # Rockchip MPP (RK3588, RK3568等)
            if [ -e /dev/video10 ]; then
                sudo apt-get install -y \
                    librockchip-mpp-dev \
                    librockchip-vpu-dev \
                    rockchip-mpp-demos \
                    || echo "Rockchip MPP 包不可用，跳过..."
            fi
            
            # Amlogic 解码器 (A311D等)
            if [ -e /dev/meson-vdec ]; then
                sudo apt-get install -y \
                    amlogic-meson-vdec \
                    || echo "Amlogic 解码器包不可用，跳过..."
            fi
            
            # V4L2 M2M 通用支持
            sudo apt-get install -y \
                v4l-utils \
                libv4l-dev \
                || echo "V4L2 包不可用，跳过..."
        fi
        
        # x86/x86_64 特定编解码器
        if [ "$PLATFORM" = "x86_64" ] || [ "$PLATFORM" = "x86" ]; then
            echo "安装 x86 硬件加速支持..."
            
            # Intel VAAPI
            sudo apt-get install -y \
                vainfo \
                intel-media-va-driver \
                i965-va-driver \
                libva-dev \
                libva-drm2 \
                || echo "Intel VAAPI 包不可用，跳过..."
            
            # NVIDIA NVENC (如果有NVIDIA显卡)
            if lspci | grep -i nvidia &> /dev/null; then
                sudo apt-get install -y \
                    nvidia-cuda-toolkit \
                    libnvidia-encode1 \
                    || echo "NVIDIA 包不可用，跳过..."
            fi
        fi
        
    elif command -v yum &> /dev/null; then
        sudo yum install -y \
            ffmpeg \
            ffmpeg-devel \
            v4l-utils
        
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm \
            ffmpeg \
            v4l-utils
        
    else
        echo "不支持的包管理器，请手动安装 FFmpeg"
        exit 1
    fi
    
    echo "✓ FFmpeg 安装完成"
    ffmpeg -version | head -n1
}

install_docker() {
    if command -v docker &> /dev/null; then
        echo "✓ Docker 已安装: $(docker --version)"
        return
    fi
    
    echo "安装 Docker..."
    
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
    
    # 启动 Docker 服务
    sudo systemctl enable docker
    sudo systemctl start docker
    
    echo "✓ Docker 安装完成"
}

install_system_tools() {
    echo "安装系统工具..."
    
    if command -v apt-get &> /dev/null; then
        sudo apt-get install -y \
            curl \
            wget \
            git \
            build-essential \
            pkg-config \
            libssl-dev \
            libsqlite3-dev \
            usbutils \
            pciutils \
            lsof \
            htop \
            net-tools \
            sysstat \
            xfsprogs \
            btrfs-progs \
            e2fsprogs \
            dosfstools \
            exfatprogs \
            ntfs-3g \
            f2fs-tools \
            parted \
            gdisk
            
    elif command -v yum &> /dev/null; then
        sudo yum install -y \
            curl \
            wget \
            git \
            gcc \
            gcc-c++ \
            make \
            openssl-devel \
            sqlite-devel \
            usbutils \
            pciutils \
            lsof \
            htop \
            xfsprogs \
            btrfs-progs \
            e2fsprogs \
            dosfstools \
            exfat-utils \
            ntfs-3g \
            f2fs-tools \
            parted \
            gdisk
            
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm \
            curl \
            wget \
            git \
            base-devel \
            openssl \
            sqlite \
            usbutils \
            pciutils \
            lsof \
            htop \
            xfsprogs \
            btrfs-progs \
            e2fsprogs \
            dosfstools \
            exfatprogs \
            ntfs-3g \
            f2fs-tools \
            parted \
            gptfdisk
    fi
    
    echo "✓ 系统工具安装完成"
}

setup_hardware_access() {
    echo "配置硬件访问权限..."
    
    # ARM 硬件加速设备
    if [ "$PLATFORM" = "aarch64" ] || [ "$PLATFORM" = "armv7" ] || [ "$PLATFORM" = "armv8" ]; then
        echo "配置 ARM 硬件加速..."
        
        # Rockchip MPP
        if [ -e /dev/video10 ]; then
            sudo chmod 666 /dev/video10 /dev/video11 /dev/video12 2>/dev/null || true
            sudo usermod -aG video $USER
            echo "✓ Rockchip MPP 设备已配置"
        fi
        
        # Amlogic 解码器
        if [ -e /dev/meson-vdec ]; then
            sudo chmod 666 /dev/meson-vdec 2>/dev/null || true
            echo "✓ Amlogic 解码器已配置"
        fi
        
        # Mali GPU
        if [ -e /dev/mali0 ]; then
            sudo chmod 666 /dev/mali0 2>/dev/null || true
            sudo usermod -aG video $USER
            echo "✓ Mali GPU 已配置"
        fi
    fi
    
    # x86 硬件加速设备
    if [ "$PLATFORM" = "x86_64" ] || [ "$PLATFORM" = "x86" ]; then
        echo "配置 x86 硬件加速..."
        
        # Intel/AMD GPU (DRI)
        if [ -e /dev/dri ]; then
            sudo chmod -R 666 /dev/dri/* 2>/dev/null || true
            sudo usermod -aG video $USER
            sudo usermod -aG render $USER
            echo "✓ DRI 设备已配置"
        fi
        
        # NVIDIA GPU
        if [ -e /dev/nvidia0 ]; then
            sudo chmod 666 /dev/nvidia* 2>/dev/null || true
            echo "✓ NVIDIA 设备已配置"
        fi
    fi
    
    # USB 设备访问
    sudo usermod -aG plugdev $USER 2>/dev/null || true
    
    echo "✓ 硬件访问权限配置完成"
}

create_directories() {
    echo "创建应用目录..."
    
    sudo mkdir -p /opt/rockzero
    sudo mkdir -p /DATA/AppData/rockzero/{data,uploads,storage,media,cache}
    sudo chown -R $USER:$USER /opt/rockzero
    sudo chown -R $USER:$USER /DATA/AppData/rockzero
    
    # 创建本地目录
    mkdir -p ./uploads
    mkdir -p ./data
    mkdir -p ./certs
    
    echo "✓ 目录创建完成"
}

setup_casaos_appstore() {
    echo "配置 CasaOS AppStore Play..."
    
    if [ ! -d "./casaos-appstore-play" ]; then
        git clone https://github.com/Cp0204/CasaOS-AppStore-Play.git casaos-appstore-play
        echo "✓ CasaOS AppStore Play 已克隆"
    else
        echo "✓ CasaOS AppStore Play 已存在"
    fi
}

install_fido2_support() {
    echo "安装 FIDO2/WebAuthn 支持..."
    
    if command -v apt-get &> /dev/null; then
        sudo apt-get install -y \
            libpcsclite-dev \
            pcscd \
            libusb-1.0-0-dev \
            libudev-dev
        
        sudo systemctl enable pcscd
        sudo systemctl start pcscd
        
    elif command -v yum &> /dev/null; then
        sudo yum install -y \
            pcsc-lite-devel \
            pcsc-lite \
            libusb-devel \
            systemd-devel
        
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm \
            pcsclite \
            libusb \
            systemd-libs
    fi
    
    echo "✓ FIDO2 支持安装完成"
}

verify_installation() {
    echo ""
    echo "=== 验证安装 ==="
    echo ""
    
    echo "平台信息:"
    echo "  架构: $PLATFORM"
    echo "  Rust: $(rustc --version 2>/dev/null || echo '未安装')"
    echo "  FFmpeg: $(ffmpeg -version 2>/dev/null | head -n1 || echo '未安装')"
    echo "  Docker: $(docker --version 2>/dev/null || echo '未安装')"
    echo ""
    
    echo "硬件加速支持:"
    if [ -e /dev/video10 ]; then
        echo "  ✓ Rockchip MPP"
    fi
    if [ -e /dev/meson-vdec ]; then
        echo "  ✓ Amlogic VDEC"
    fi
    if [ -e /dev/dri/renderD128 ]; then
        echo "  ✓ Intel/AMD VAAPI"
    fi
    if [ -e /dev/nvidia0 ]; then
        echo "  ✓ NVIDIA NVENC"
    fi
    echo ""
    
    echo "USB 设备:"
    lsusb 2>/dev/null | head -n5 || echo "  无法列出 USB 设备"
    echo ""
}

main() {
    detect_platform
    install_system_tools
    install_rust
    install_ffmpeg
    install_docker
    install_fido2_support
    setup_hardware_access
    create_directories
    setup_casaos_appstore
    verify_installation
    
    echo ""
    echo "=== 安装完成 ==="
    echo ""
    echo "下一步:"
    echo "1. 设置环境变量 (复制 .env.example 到 .env)"
    echo "2. 生成 TLS 证书 (如需要)"
    echo "3. 编译项目: cargo build --release --target $RUST_TARGET"
    echo "4. 或使用 Docker: docker-compose up -d"
    echo ""
    echo "注意: 某些权限更改需要重新登录才能生效"
    echo ""
}

main
