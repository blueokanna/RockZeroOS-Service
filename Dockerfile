# 多阶段构建 - 生产级优化
FROM rust:1.75-slim as builder

WORKDIR /app

# 安装构建依赖
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY Cargo.toml Cargo.lock ./
COPY rockzero-common ./rockzero-common
COPY rockzero-crypto ./rockzero-crypto
COPY rockzero-db ./rockzero-db
COPY rockzero-media ./rockzero-media
COPY rockzero-sae ./rockzero-sae
COPY rockzero-service ./rockzero-service

# 构建应用
RUN cargo build --release --locked

# 运行时镜像 - 最小化
FROM debian:bookworm-slim

WORKDIR /app

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libsqlite3-0 \
    ffmpeg \
    xz-utils \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 创建非root用户
RUN useradd -m -u 1000 rockzero && \
    mkdir -p /app/uploads /app/data /app/data/ffmpeg /app/data/hls_cache /app/assets && \
    chown -R rockzero:rockzero /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/target/release/rockzero-service /app/rockzero-service

# 复制 assets 目录（包含静态编译的 FFmpeg）
COPY --chown=rockzero:rockzero assets /app/assets

# 设置环境变量
ENV DATA_DIR=/app/data
ENV FFMPEG_ASSETS_PATH=/app/assets
ENV HLS_CACHE_PATH=/app/data/hls_cache

# 切换到非root用户
USER rockzero

# 暴露端口
EXPOSE 8443

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8443/health || exit 1

# 启动应用
CMD ["/app/rockzero-service"]
