# 多阶段构建 - 生产级优化
FROM rust:1.75-slim as builder

WORKDIR /app

# 安装构建依赖
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY Cargo.toml Cargo.lock ./

# 创建虚拟源文件以缓存依赖
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# 复制实际源代码
COPY src ./src

# 构建应用（依赖已缓存）
RUN touch src/main.rs && \
    cargo build --release --locked

# 运行时镜像 - 最小化
FROM debian:bookworm-slim

WORKDIR /app

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# 创建非root用户
RUN useradd -m -u 1000 rockzero && \
    mkdir -p /app/uploads /app/data && \
    chown -R rockzero:rockzero /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/target/release/rockzero-service /app/rockzero-service

# 切换到非root用户
USER rockzero

# 暴露端口
EXPOSE 8443

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8443/health || exit 1

# 启动应用
CMD ["/app/rockzero-service"]
