#!/bin/bash

# FFmpeg 自动设置脚本

set -e

echo "=== FFmpeg 自动设置脚本 ==="
echo ""

# 检测架构
ARCH=$(uname -m)
echo "检测到系统架构: $ARCH"

# 检查是否已有系统 FFmpeg
if command -v ffmpeg &> /dev/null; then
    echo "✓ 系统已安装 FFmpeg"
    ffmpeg -version | head -n 1
    exit 0
fi

# 创建目录
mkdir -p ./data/ffmpeg

# 检查本地是否已有压缩包
if [ -f "ffmpeg-release-arm64-static.tar.xz" ]; then
    echo "✓ 发现本地 ARM64 FFmpeg 压缩包"
    ARCHIVE="ffmpeg-release-arm64-static.tar.xz"
elif [ -f "ffmpeg-release-amd64-static.tar.xz" ]; then
    echo "✓ 发现本地 AMD64 FFmpeg 压缩包"
    ARCHIVE="ffmpeg-release-amd64-static.tar.xz"
else
    echo "未找到本地 FFmpeg 压缩包，开始下载..."
    
    # 根据架构选择下载链接
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
        URL="https://johnvansickle.com/ffmpeg/releases/ffmpeg-release-arm64-static.tar.xz"
        ARCHIVE="ffmpeg-release-arm64-static.tar.xz"
    elif [ "$ARCH" = "x86_64" ]; then
        URL="https://johnvansickle.com/ffmpeg/releases/ffmpeg-release-amd64-static.tar.xz"
        ARCHIVE="ffmpeg-release-amd64-static.tar.xz"
    else
        echo "✗ 不支持的架构: $ARCH"
        echo "请手动安装 FFmpeg:"
        echo "  Ubuntu/Debian: sudo apt install ffmpeg"
        echo "  CentOS/RHEL: sudo yum install ffmpeg"
        exit 1
    fi
    
    echo "下载链接: $URL"
    
    if command -v wget &> /dev/null; then
        wget -O "$ARCHIVE" "$URL"
    elif command -v curl &> /dev/null; then
        curl -L -o "$ARCHIVE" "$URL"
    else
        echo "✗ 未找到 wget 或 curl，无法下载"
        exit 1
    fi
fi

# 解压
echo "正在解压 $ARCHIVE ..."
tar -xJf "$ARCHIVE" -C ./data/ffmpeg

# 查找并设置权限
echo "设置可执行权限..."
find ./data/ffmpeg -name ffmpeg -type f -exec chmod +x {} \;
find ./data/ffmpeg -name ffprobe -type f -exec chmod +x {} \;

# 查找 FFmpeg 路径
FFMPEG_PATH=$(find ./data/ffmpeg -name ffmpeg -type f | head -n 1)
FFPROBE_PATH=$(find ./data/ffmpeg -name ffprobe -type f | head -n 1)

if [ -n "$FFMPEG_PATH" ]; then
    echo ""
    echo "✓ FFmpeg 安装成功！"
    echo "FFmpeg 路径: $FFMPEG_PATH"
    echo "FFprobe 路径: $FFPROBE_PATH"
    echo ""
    
    # 显示版本
    $FFMPEG_PATH -version | head -n 1
    echo ""
    echo "你现在可以运行服务了："
    echo "  cargo run"
else
    echo "✗ 安装失败，未找到 FFmpeg 可执行文件"
    exit 1
fi
