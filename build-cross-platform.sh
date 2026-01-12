#!/bin/bash

set -e

echo "=== RockZero 跨平台构建脚本 ==="
echo ""

# 支持的目标平台
TARGETS=(
    "x86_64-unknown-linux-gnu"
    "i686-unknown-linux-gnu"
    "aarch64-unknown-linux-gnu"
    "armv7-unknown-linux-gnueabihf"
)

# 检查 cross 工具
if ! command -v cross &> /dev/null; then
    echo "安装 cross 工具..."
    cargo install cross --git https://github.com/cross-rs/cross
fi

# 创建输出目录
mkdir -p ./dist

# 构建所有目标
for TARGET in "${TARGETS[@]}"; do
    echo ""
    echo "=== 构建目标: $TARGET ==="
    echo ""
    
    cross build --release --target $TARGET
    
    # 复制二进制文件
    BINARY_NAME="rockzero-service"
    if [ -f "./target/$TARGET/release/$BINARY_NAME" ]; then
        cp "./target/$TARGET/release/$BINARY_NAME" "./dist/${BINARY_NAME}-${TARGET}"
        echo "✓ 二进制文件已复制到: ./dist/${BINARY_NAME}-${TARGET}"
        
        # 压缩
        cd ./dist
        tar -czf "${BINARY_NAME}-${TARGET}.tar.gz" "${BINARY_NAME}-${TARGET}"
        echo "✓ 已压缩: ${BINARY_NAME}-${TARGET}.tar.gz"
        cd ..
    else
        echo "✗ 构建失败: $TARGET"
    fi
done

echo ""
echo "=== 构建完成 ==="
echo ""
echo "输出文件位于 ./dist/ 目录"
ls -lh ./dist/
echo ""
