#!/bin/bash
set -e

echo "🚀 RockZero Armbian A311D 部署脚本"
echo "==================================="

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 检查是否为 root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}请使用 root 权限运行此脚本${NC}"
    exit 1
fi

echo -e "${GREEN}[1/6] 更新系统...${NC}"
apt update && apt upgrade -y

echo -e "${GREEN}[2/6] 安装依赖...${NC}"
apt install -y \
    curl \
    wget \
    git \
    docker.io \
    docker-compose \
    openssl \
    htop \
    iotop

echo -e "${GREEN}[3/6] 配置 Docker...${NC}"
systemctl enable docker
systemctl start docker

# 添加当前用户到 docker 组
if [ -n "$SUDO_USER" ]; then
    usermod -aG docker $SUDO_USER
fi

echo -e "${GREEN}[4/6] 安装 Tailscale (可选)...${NC}"
read -p "是否安装 Tailscale VPN? (y/n): " install_tailscale
if [ "$install_tailscale" = "y" ]; then
    curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg | \
        tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
    
    curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.tailscale-keyring.list | \
        tee /etc/apt/sources.list.d/tailscale.list
    
    apt update && apt install -y tailscale
    
    echo -e "${YELLOW}运行 'tailscale up' 来连接 Tailscale 网络${NC}"
fi

echo -e "${GREEN}[5/6] 配置防火墙...${NC}"
if command -v ufw &> /dev/null; then
    ufw allow 8080/tcp
    ufw allow 443/tcp
    ufw allow 80/tcp
    echo -e "${GREEN}✅ 防火墙规则已添加${NC}"
fi

echo -e "${GREEN}[6/6] 创建服务目录...${NC}"
mkdir -p /opt/rockzero
cd /opt/rockzero

# 运行设置脚本
if [ -f scripts/setup.sh ]; then
    chmod +x scripts/setup.sh
    ./scripts/setup.sh
fi

echo ""
echo -e "${GREEN}==================================${NC}"
echo -e "${GREEN}✅ Armbian 部署准备完成!${NC}"
echo ""
echo "后续步骤:"
echo "  1. 将项目文件复制到 /opt/rockzero"
echo "  2. 运行: cd /opt/rockzero && ./scripts/setup.sh"
echo "  3. 启动服务: docker-compose up -d"
echo ""
echo "如果使用 Tailscale:"
echo "  1. 运行: tailscale up"
echo "  2. 获取 IP: tailscale ip -4"
echo "  3. 更新 .env 中的 CORS_ORIGINS"
echo ""
