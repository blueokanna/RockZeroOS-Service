#!/bin/bash
set -e

echo "🚀 RockZero 服务部署脚本"
echo "========================"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查是否为 root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}建议使用 root 权限运行此脚本${NC}"
fi

# 创建必要目录
echo -e "${GREEN}创建目录结构...${NC}"
mkdir -p nginx/certs
mkdir -p data

# 生成环境配置
if [ ! -f .env ]; then
    echo -e "${GREEN}生成环境配置文件...${NC}"
    
    # 生成随机密钥
    JWT_SECRET=$(openssl rand -base64 64 | tr -d '\n')
    ENCRYPTION_KEY=$(openssl rand -base64 32)
    
    cat > .env << EOF
# 服务器配置
HOST=0.0.0.0
PORT=8080

# 数据库配置
DATABASE_URL=sqlite:./data/rockzero.db?mode=rwc

# JWT 配置 (自动生成)
JWT_SECRET=${JWT_SECRET}
JWT_EXPIRATION_HOURS=24
REFRESH_TOKEN_EXPIRATION_DAYS=30

# 加密密钥 (自动生成)
ENCRYPTION_KEY=${ENCRYPTION_KEY}

# CORS 配置
CORS_ORIGINS=http://localhost:3000,http://localhost:8080

# 日志级别
RUST_LOG=info,actix_web=info
EOF
    
    echo -e "${GREEN}✅ .env 文件已生成${NC}"
else
    echo -e "${YELLOW}⚠️  .env 文件已存在，跳过生成${NC}"
fi

# 生成自签名证书 (用于开发/测试)
if [ ! -f nginx/certs/server.crt ]; then
    echo -e "${GREEN}生成自签名 SSL 证书...${NC}"
    
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout nginx/certs/server.key \
        -out nginx/certs/server.crt \
        -subj "/CN=localhost/O=RockZero/C=CN" \
        2>/dev/null
    
    chmod 600 nginx/certs/server.key
    chmod 644 nginx/certs/server.crt
    
    echo -e "${GREEN}✅ SSL 证书已生成${NC}"
else
    echo -e "${YELLOW}⚠️  SSL 证书已存在，跳过生成${NC}"
fi

echo ""
echo -e "${GREEN}========================${NC}"
echo -e "${GREEN}✅ 设置完成!${NC}"
echo ""
echo "下一步操作:"
echo "  1. 编辑 .env 文件，根据需要修改配置"
echo "  2. 运行: docker-compose up -d"
echo "  3. 查看日志: docker-compose logs -f"
echo ""
echo "API 端点:"
echo "  - 健康检查: http://localhost:8080/health"
echo "  - 注册: POST http://localhost:8080/api/v1/auth/register"
echo "  - 登录: POST http://localhost:8080/api/v1/auth/login"
echo ""
