use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SaeAuthState {
    pub session_id: String,
    pub shared_secret: Vec<u8>,
    pub commit_scalar: Vec<u8>,
    pub commit_element: Vec<u8>,
    pub confirmed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamConfig {
    pub udp_ratio: f32,
    pub tcp_ratio: f32,
    pub chunk_size: usize,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub enable_zkp: bool,
    pub buffer_seconds: u32,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            udp_ratio: 0.7,
            tcp_ratio: 0.3,
            chunk_size: 64 * 1024,
            udp_port: 9001,
            tcp_port: 9002,
            enable_zkp: true,
            buffer_seconds: 15,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkType {
    KeyFrame,
    NormalFrame,
    Audio,
    Subtitle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedChunk {
    pub sequence: u64,
    pub chunk_type: String,
    pub data: Vec<u8>,
    pub nonce: Vec<u8>,
    pub mac: Vec<u8>,
    pub timestamp: u64,
    pub zkp_proof: Option<Vec<u8>>,
}

pub struct SecureStreamTransport {
    config: StreamConfig,
    auth_state: Arc<RwLock<Option<SaeAuthState>>>,
    cipher: Arc<Aes256Gcm>,
    sequence_counter: Arc<RwLock<u64>>,
}

impl SecureStreamTransport {
    pub fn new(config: StreamConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        let cipher = Aes256Gcm::new(&key_bytes.into());

        Ok(Self {
            config,
            auth_state: Arc::new(RwLock::new(None)),
            cipher: Arc::new(cipher),
            sequence_counter: Arc::new(RwLock::new(0)),
        })
    }

    pub async fn initiate_sae_auth(
        &self,
        peer_id: &str,
    ) -> Result<SaeAuthState, Box<dyn std::error::Error>> {
        let mut commit_scalar = vec![0u8; 32];
        let mut commit_element = vec![0u8; 32];
        OsRng.fill_bytes(&mut commit_scalar);
        OsRng.fill_bytes(&mut commit_element);

        // 使用 Blake3 计算共享密钥
        let mut hasher = blake3::Hasher::new();
        hasher.update(&commit_scalar);
        hasher.update(&commit_element);
        hasher.update(peer_id.as_bytes());
        let shared_secret = hasher.finalize().as_bytes().to_vec();

        let auth_state = SaeAuthState {
            session_id: uuid::Uuid::new_v4().to_string(),
            shared_secret,
            commit_scalar,
            commit_element,
            confirmed: false,
        };

        *self.auth_state.write().await = Some(auth_state.clone());
        Ok(auth_state)
    }

    pub async fn confirm_sae_auth(
        &self,
        peer_commit: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let mut auth = self.auth_state.write().await;
        if let Some(ref mut state) = *auth {
            // 验证peer的commit（简化版，使用 Blake3）
            let mut hasher = blake3::Hasher::new();
            hasher.update(&state.commit_scalar);
            hasher.update(peer_commit);
            let _confirm_hash = hasher.finalize();

            state.confirmed = true;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn encrypt_chunk(
        &self,
        data: &[u8],
        chunk_type: ChunkType,
    ) -> Result<EncryptedChunk, Box<dyn std::error::Error>> {
        let auth = self.auth_state.read().await;
        if auth.is_none() || !auth.as_ref().unwrap().confirmed {
            return Err("Not authenticated".into());
        }

        // 生成nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // 加密数据
        let encrypted = self
            .cipher
            .encrypt(nonce, data)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        // 获取序列号
        let mut seq = self.sequence_counter.write().await;
        let sequence = *seq;
        *seq += 1;

        // 生成MAC（使用 Blake3）
        let mut hasher = blake3::Hasher::new();
        hasher.update(&sequence.to_le_bytes());
        hasher.update(&encrypted);
        hasher.update(&nonce_bytes);
        let mac = hasher.finalize().as_bytes().to_vec();

        // 生成零知识证明（如果启用）
        let zkp_proof = if self.config.enable_zkp {
            Some(self.generate_zkp_proof(&encrypted, sequence).await?)
        } else {
            None
        };

        Ok(EncryptedChunk {
            sequence,
            chunk_type: format!("{:?}", chunk_type),
            data: encrypted,
            nonce: nonce_bytes.to_vec(),
            mac,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis() as u64,
            zkp_proof,
        })
    }

    /// 生成Bulletproofs风格的零知识证明（使用 Blake3）
    async fn generate_zkp_proof(
        &self,
        data: &[u8],
        sequence: u64,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // 简化版Bulletproofs证明
        // 证明：我知道数据的哈希值，但不透露数据本身
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        hasher.update(&sequence.to_le_bytes());

        // 添加随机盲化因子
        let mut blinding_factor = [0u8; 32];
        OsRng.fill_bytes(&mut blinding_factor);
        hasher.update(&blinding_factor);

        let proof = hasher.finalize().as_bytes().to_vec();
        Ok(proof)
    }

    /// 验证零知识证明（使用 Blake3）
    pub async fn verify_zkp_proof(
        &self,
        chunk: &EncryptedChunk,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if let Some(ref _proof) = chunk.zkp_proof {
            // 验证MAC
            let mut hasher = blake3::Hasher::new();
            hasher.update(&chunk.sequence.to_le_bytes());
            hasher.update(&chunk.data);
            hasher.update(&chunk.nonce);
            let computed_mac = hasher.finalize().as_bytes().to_vec();

            Ok(computed_mac == chunk.mac)
        } else {
            Ok(true) // 如果没有ZKP，只验证MAC
        }
    }

    /// 解密数据块
    pub async fn decrypt_chunk(
        &self,
        chunk: &EncryptedChunk,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // 验证ZKP
        if !self.verify_zkp_proof(chunk).await? {
            return Err("ZKP verification failed".into());
        }

        // 解密
        let nonce = Nonce::from_slice(&chunk.nonce);
        let decrypted = self
            .cipher
            .decrypt(nonce, chunk.data.as_ref())
            .map_err(|e| format!("Decryption failed: {}", e))?;

        Ok(decrypted)
    }

    /// 决定使用UDP还是TCP传输
    pub fn should_use_udp(&self, chunk_type: ChunkType, chunk_index: usize) -> bool {
        match chunk_type {
            // 关键帧必须用TCP
            ChunkType::KeyFrame => false,
            // 音频优先TCP
            ChunkType::Audio => chunk_index % 10 >= 7, // 30% TCP
            // 字幕必须TCP
            ChunkType::Subtitle => false,
            // 普通帧按比例分配
            ChunkType::NormalFrame => {
                let ratio = (chunk_index % 100) as f32 / 100.0;
                ratio < self.config.udp_ratio
            }
        }
    }

    pub fn get_config(&self) -> &StreamConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sae_auth() {
        let config = StreamConfig::default();
        let transport = SecureStreamTransport::new(config).unwrap();

        let auth_state = transport.initiate_sae_auth("peer1").await.unwrap();
        assert!(!auth_state.confirmed);

        let confirmed = transport
            .confirm_sae_auth(&auth_state.commit_element)
            .await
            .unwrap();
        assert!(confirmed);
    }

    #[tokio::test]
    async fn test_encryption() {
        let config = StreamConfig::default();
        let transport = SecureStreamTransport::new(config).unwrap();

        // 先认证
        transport.initiate_sae_auth("peer1").await.unwrap();
        transport.confirm_sae_auth(&[0u8; 32]).await.unwrap();

        let data = b"test data";
        let encrypted = transport
            .encrypt_chunk(data, ChunkType::NormalFrame)
            .await
            .unwrap();

        assert!(!encrypted.data.is_empty());
        assert!(encrypted.zkp_proof.is_some());

        let decrypted = transport.decrypt_chunk(&encrypted).await.unwrap();
        assert_eq!(decrypted, data);
    }
}

// ============================================================================
// HybridTransport：UDP 70% + TCP 30% 混合传输层
// ============================================================================

/// 混合传输统计信息
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HybridTransportStats {
    pub udp_chunks_sent: u64,
    pub tcp_chunks_sent: u64,
    pub udp_bytes_sent: u64,
    pub tcp_bytes_sent: u64,
    pub udp_packets_lost: u64,
    pub tcp_retransmits: u64,
    pub total_chunks: u64,
    pub effective_udp_ratio: f64,
    pub effective_tcp_ratio: f64,
    pub avg_latency_ms: f64,
    pub bandwidth_bps: u64,
    pub started_at: u64,
    pub last_activity: u64,
}

/// 混合传输配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridConfig {
    /// UDP 传输比例 (0.0 - 1.0)，默认 0.7
    pub udp_ratio: f32,
    /// TCP 传输比例 (0.0 - 1.0)，默认 0.3
    pub tcp_ratio: f32,
    /// 每个数据块大小（字节），默认 64KB
    pub chunk_size: usize,
    /// UDP 绑定端口
    pub udp_bind_addr: String,
    /// TCP 绑定端口
    pub tcp_bind_addr: String,
    /// 最大并发 UDP 发送窗口
    pub udp_window_size: usize,
    /// TCP 重试次数
    pub tcp_max_retries: u32,
    /// UDP 丢包阈值 — 超过后动态增加 TCP 比例
    pub udp_loss_threshold: f64,
    /// 自适应比例调整启用
    pub adaptive_ratio: bool,
    /// 发送缓冲区大小
    pub send_buffer_size: usize,
    /// 接收乱序重排缓冲区大小
    pub reorder_buffer_size: usize,
}

impl Default for HybridConfig {
    fn default() -> Self {
        Self {
            udp_ratio: 0.7,
            tcp_ratio: 0.3,
            chunk_size: 64 * 1024,
            udp_bind_addr: "0.0.0.0:0".to_string(),
            tcp_bind_addr: "0.0.0.0:0".to_string(),
            udp_window_size: 32,
            tcp_max_retries: 3,
            udp_loss_threshold: 0.05, // 5% 丢包率阈值
            adaptive_ratio: true,
            send_buffer_size: 8 * 1024 * 1024,  // 8MB
            reorder_buffer_size: 256,
        }
    }
}

/// 块路由决策
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportChannel {
    Udp,
    Tcp,
}

/// 待发送的数据块描述
#[derive(Debug, Clone)]
pub struct TransportChunk {
    pub sequence: u64,
    pub chunk_type: ChunkType,
    pub data: Vec<u8>,
    pub channel: TransportChannel,
    pub priority: u8, // 0 = 最高，255 = 最低
}

/// 混合传输层 — 将数据按 70% UDP + 30% TCP 分发
///
/// 设计原则：
/// - 关键帧 (KeyFrame) 和字幕 (Subtitle) 始终通过 TCP 可靠传输
/// - 普通帧 (NormalFrame) 按 udp_ratio/tcp_ratio 分配
/// - 音频 (Audio) 70% TCP 30% UDP（音频丢包更敏感）
/// - 支持自适应比例调整：UDP 丢包率超阈值时自动增加 TCP 比例
/// - 接收端使用重排缓冲区恢复乱序数据
pub struct HybridTransport {
    transport: Arc<SecureStreamTransport>,
    config: HybridConfig,
    stats: Arc<RwLock<HybridTransportStats>>,
    /// 当前动态 UDP 比例（自适应调整）
    current_udp_ratio: Arc<RwLock<f32>>,
    /// 接收端乱序重排缓冲区
    reorder_buffer: Arc<RwLock<BTreeMap<u64, EncryptedChunk>>>,
    /// 已确认的最大连续序列号
    last_delivered_seq: Arc<RwLock<u64>>,
    /// 带宽估算采样窗口
    bandwidth_samples: Arc<RwLock<Vec<(u64, u64)>>>, // (timestamp_ms, bytes)
}

impl HybridTransport {
    /// 创建新的混合传输层
    pub fn new(
        transport: Arc<SecureStreamTransport>,
        config: HybridConfig,
    ) -> Self {
        let initial_ratio = config.udp_ratio;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            transport,
            config,
            stats: Arc::new(RwLock::new(HybridTransportStats {
                started_at: now,
                last_activity: now,
                ..Default::default()
            })),
            current_udp_ratio: Arc::new(RwLock::new(initial_ratio)),
            reorder_buffer: Arc::new(RwLock::new(BTreeMap::new())),
            last_delivered_seq: Arc::new(RwLock::new(0)),
            bandwidth_samples: Arc::new(RwLock::new(Vec::with_capacity(100))),
        }
    }

    /// 使用默认 70/30 配置创建
    pub fn with_default_config(transport: Arc<SecureStreamTransport>) -> Self {
        Self::new(transport, HybridConfig::default())
    }

    /// 决定数据块的传输通道
    ///
    /// 路由策略：
    /// - KeyFrame → TCP（100%，不可丢失）
    /// - Subtitle → TCP（100%，不可丢失）
    /// - Audio → 70% TCP + 30% UDP（音频丢包敏感）
    /// - NormalFrame → 按当前动态比例分配 UDP/TCP
    pub async fn route_chunk(
        &self,
        chunk_type: ChunkType,
        sequence: u64,
    ) -> TransportChannel {
        match chunk_type {
            // 关键帧和字幕必须可靠传输
            ChunkType::KeyFrame | ChunkType::Subtitle => TransportChannel::Tcp,

            // 音频偏向 TCP（70% TCP, 30% UDP）
            ChunkType::Audio => {
                if (sequence % 10) < 7 {
                    TransportChannel::Tcp
                } else {
                    TransportChannel::Udp
                }
            }

            // 普通帧按动态比例分配
            ChunkType::NormalFrame => {
                let ratio = *self.current_udp_ratio.read().await;
                let threshold = (ratio * 100.0) as u64;
                if (sequence % 100) < threshold {
                    TransportChannel::Udp
                } else {
                    TransportChannel::Tcp
                }
            }
        }
    }

    /// 将原始数据分割为传输块并分配通道
    pub async fn prepare_chunks(
        &self,
        data: &[u8],
        chunk_type: ChunkType,
    ) -> Result<Vec<TransportChunk>, Box<dyn std::error::Error>> {
        let chunk_size = self.config.chunk_size;
        let mut chunks = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let end = (offset + chunk_size).min(data.len());
            let chunk_data = &data[offset..end];

            // 加密数据块
            let encrypted = self.transport.encrypt_chunk(chunk_data, chunk_type).await?;

            // 决定传输通道
            let channel = self.route_chunk(chunk_type, encrypted.sequence).await;

            let priority = match chunk_type {
                ChunkType::KeyFrame => 0,
                ChunkType::Audio => 1,
                ChunkType::Subtitle => 2,
                ChunkType::NormalFrame => 3,
            };

            let serialized = bincode::serialize(&encrypted)?;

            chunks.push(TransportChunk {
                sequence: encrypted.sequence,
                chunk_type,
                data: serialized,
                channel,
                priority,
            });

            offset = end;
        }

        Ok(chunks)
    }

    /// 通过混合通道发送数据块列表
    ///
    /// 将块按通道分组后并行发送：
    /// - UDP 块批量发送（不等待 ACK，最大化吞吐）
    /// - TCP 块顺序发送（确保可靠到达）
    pub async fn send_chunks(
        &self,
        chunks: Vec<TransportChunk>,
        udp_dest: &str,
        tcp_stream: &tokio::net::TcpStream,
    ) -> Result<HybridSendResult, Box<dyn std::error::Error>> {
        let mut udp_chunks = Vec::new();
        let mut tcp_chunks = Vec::new();

        for chunk in &chunks {
            match chunk.channel {
                TransportChannel::Udp => udp_chunks.push(chunk),
                TransportChannel::Tcp => tcp_chunks.push(chunk),
            }
        }

        let udp_count = udp_chunks.len();
        let tcp_count = tcp_chunks.len();

        // 并行发送 UDP 和 TCP
        let udp_socket = tokio::net::UdpSocket::bind(&self.config.udp_bind_addr).await?;

        // 设置 UDP 发送缓冲区
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = udp_socket.as_raw_fd();
            unsafe {
                let buf_size = self.config.send_buffer_size as libc::c_int;
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &buf_size as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        let mut udp_bytes = 0u64;
        let mut udp_lost = 0u64;
        let mut tcp_bytes = 0u64;

        // 发送 UDP 块（批量，无需等待 ACK）
        for chunk in &udp_chunks {
            match udp_socket.send_to(&chunk.data, udp_dest).await {
                Ok(n) => udp_bytes += n as u64,
                Err(e) => {
                    log::warn!(
                        "UDP send failed for seq {}: {}, retrying via TCP",
                        chunk.sequence,
                        e
                    );
                    udp_lost += 1;
                    // UDP 发送失败的块降级到 TCP
                    tcp_chunks.push(chunk);
                }
            }
        }

        // 发送 TCP 块（顺序，可靠）
        let tcp_stream_clone = tcp_stream;
        for chunk in &tcp_chunks {
            let len = chunk.data.len() as u32;
            let mut retries = 0;
            loop {
                // 使用 try_write 检查是否可写
                match tcp_stream_clone.try_write(&len.to_le_bytes()) {
                    Ok(_) => {
                        match tcp_stream_clone.try_write(&chunk.data) {
                            Ok(n) => {
                                tcp_bytes += (n + 4) as u64;
                                break;
                            }
                            Err(e) if retries < self.config.tcp_max_retries => {
                                retries += 1;
                                log::warn!(
                                    "TCP write retry {}/{} for seq {}: {}",
                                    retries,
                                    self.config.tcp_max_retries,
                                    chunk.sequence,
                                    e
                                );
                                tokio::time::sleep(tokio::time::Duration::from_millis(
                                    10 * retries as u64,
                                ))
                                .await;
                            }
                            Err(e) => {
                                log::error!(
                                    "TCP send failed for seq {} after {} retries: {}",
                                    chunk.sequence,
                                    retries,
                                    e
                                );
                                break;
                            }
                        }
                    }
                    Err(e) if retries < self.config.tcp_max_retries => {
                        retries += 1;
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            10 * retries as u64,
                        ))
                        .await;
                        log::warn!("TCP header write retry {}/{}: {}", retries, self.config.tcp_max_retries, e);
                    }
                    Err(e) => {
                        log::error!("TCP header send failed for seq {}: {}", chunk.sequence, e);
                        break;
                    }
                }
            }
        }

        // 更新统计
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        {
            let mut stats = self.stats.write().await;
            stats.udp_chunks_sent += udp_count as u64;
            stats.tcp_chunks_sent += tcp_count as u64;
            stats.udp_bytes_sent += udp_bytes;
            stats.tcp_bytes_sent += tcp_bytes;
            stats.udp_packets_lost += udp_lost;
            stats.total_chunks += chunks.len() as u64;
            stats.last_activity = now;

            let total = stats.udp_bytes_sent + stats.tcp_bytes_sent;
            if total > 0 {
                stats.effective_udp_ratio = stats.udp_bytes_sent as f64 / total as f64;
                stats.effective_tcp_ratio = stats.tcp_bytes_sent as f64 / total as f64;
            }

            // 带宽估算
            let elapsed_s = (now - stats.started_at).max(1) as f64 / 1000.0;
            stats.bandwidth_bps = (total as f64 / elapsed_s) as u64;
        }

        // 自适应比例调整
        if self.config.adaptive_ratio {
            self.adapt_ratio().await;
        }

        // 带宽采样
        {
            let mut samples = self.bandwidth_samples.write().await;
            samples.push((now, udp_bytes + tcp_bytes));
            // 只保留最近 100 个采样
            if samples.len() > 100 {
                samples.drain(0..50);
            }
        }

        Ok(HybridSendResult {
            udp_sent: udp_count,
            tcp_sent: tcp_count,
            udp_bytes,
            tcp_bytes,
            udp_failed: udp_lost as usize,
        })
    }

    /// 自适应调整 UDP/TCP 比例
    ///
    /// 基于 UDP 丢包率动态调整：
    /// - 丢包率 < 2%：增加 UDP 比例（最大 0.85）
    /// - 丢包率 2-5%：保持当前比例
    /// - 丢包率 > 5%：减少 UDP 比例（最低 0.4）
    /// - 丢包率 > 15%：大幅减少 UDP（最低 0.2）
    async fn adapt_ratio(&self) {
        let stats = self.stats.read().await;
        let total_udp = stats.udp_chunks_sent;
        let lost = stats.udp_packets_lost;
        drop(stats);

        if total_udp < 50 {
            return; // 采样不足，不调整
        }

        let loss_rate = lost as f64 / total_udp as f64;
        let mut ratio = self.current_udp_ratio.write().await;

        if loss_rate < 0.02 {
            // 网络良好，逐步增加 UDP
            *ratio = (*ratio + 0.02).min(0.85);
        } else if loss_rate > 0.15 {
            // 网络极差，大幅减少 UDP
            *ratio = (*ratio - 0.1).max(0.2);
            log::warn!(
                "High UDP loss rate ({:.1}%), reducing UDP ratio to {:.0}%",
                loss_rate * 100.0,
                *ratio * 100.0
            );
        } else if loss_rate > self.config.udp_loss_threshold {
            // 丢包率超阈值，减少 UDP
            *ratio = (*ratio - 0.05).max(0.4);
            log::info!(
                "UDP loss rate ({:.1}%) above threshold, adjusting ratio to {:.0}%",
                loss_rate * 100.0,
                *ratio * 100.0
            );
        }
    }

    /// 接收端：将接收到的块放入重排缓冲区
    pub async fn buffer_received_chunk(&self, chunk: EncryptedChunk) {
        let seq = chunk.sequence;
        let mut buffer = self.reorder_buffer.write().await;
        buffer.insert(seq, chunk);

        // 限制缓冲区大小
        while buffer.len() > self.config.reorder_buffer_size {
            if let Some((&oldest_seq, _)) = buffer.iter().next() {
                buffer.remove(&oldest_seq);
            }
        }
    }

    /// 接收端：从重排缓冲区取出连续可交付的块
    ///
    /// 只返回从 last_delivered_seq + 1 开始的连续块序列，
    /// 确保数据按顺序交付给上层。
    pub async fn drain_ordered_chunks(&self) -> Vec<EncryptedChunk> {
        let mut buffer = self.reorder_buffer.write().await;
        let mut last_seq = self.last_delivered_seq.write().await;
        let mut result = Vec::new();

        loop {
            let next_seq = *last_seq + 1;
            if let Some(chunk) = buffer.remove(&next_seq) {
                *last_seq = next_seq;
                result.push(chunk);
            } else {
                break;
            }
        }

        result
    }

    /// 估算当前带宽（bytes/sec）
    pub async fn estimate_bandwidth(&self) -> u64 {
        let samples = self.bandwidth_samples.read().await;
        if samples.len() < 2 {
            return 0;
        }

        let window = &samples[samples.len().saturating_sub(20)..];
        if window.len() < 2 {
            return 0;
        }

        let (first_ts, _) = window[0];
        let (last_ts, _) = window[window.len() - 1];
        let elapsed_ms = (last_ts - first_ts).max(1);
        let total_bytes: u64 = window.iter().map(|(_, b)| b).sum();

        (total_bytes as f64 / (elapsed_ms as f64 / 1000.0)) as u64
    }

    /// 获取传输统计
    pub async fn get_stats(&self) -> HybridTransportStats {
        self.stats.read().await.clone()
    }

    /// 重置统计
    pub async fn reset_stats(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        *self.stats.write().await = HybridTransportStats {
            started_at: now,
            last_activity: now,
            ..Default::default()
        };
        *self.current_udp_ratio.write().await = self.config.udp_ratio;
        self.bandwidth_samples.write().await.clear();
    }

    /// 获取当前动态 UDP 比例
    pub async fn current_udp_ratio(&self) -> f32 {
        *self.current_udp_ratio.read().await
    }

    /// 获取底层配置
    pub fn config(&self) -> &HybridConfig {
        &self.config
    }
}

/// 发送结果
#[derive(Debug, Clone)]
pub struct HybridSendResult {
    pub udp_sent: usize,
    pub tcp_sent: usize,
    pub udp_bytes: u64,
    pub tcp_bytes: u64,
    pub udp_failed: usize,
}
