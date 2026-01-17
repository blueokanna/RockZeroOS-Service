use super::secure_transport::{EncryptedChunk, SecureStreamTransport};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

/// UDP流发送器 - 70%的数据通过UDP传输
#[allow(dead_code)]
pub struct UdpStreamSender {
    socket: Arc<UdpSocket>,
    transport: Arc<SecureStreamTransport>,
    stats: Arc<RwLock<UdpStats>>,
}

#[derive(Debug, Default, Clone)]
pub struct UdpStats {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_lost: u64,
    pub retransmissions: u64,
}

impl UdpStreamSender {
    pub async fn new(
        bind_addr: &str,
        transport: Arc<SecureStreamTransport>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let socket = UdpSocket::bind(bind_addr).await?;

        // 设置UDP socket选项以优化性能
        socket.set_broadcast(false)?;

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            unsafe {
                let buf_size: libc::c_int = 5 * 1024 * 1024;
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &buf_size as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        Ok(Self {
            socket: Arc::new(socket),
            transport,
            stats: Arc::new(RwLock::new(UdpStats::default())),
        })
    }

    /// 发送加密的数据块
    pub async fn send_chunk(
        &self,
        chunk: &EncryptedChunk,
        dest_addr: &str,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        // 序列化chunk
        let serialized = bincode::serialize(chunk)?;

        // 发送数据
        let bytes_sent = self.socket.send_to(&serialized, dest_addr).await?;

        // 更新统计
        let mut stats = self.stats.write().await;
        stats.packets_sent += 1;
        stats.bytes_sent += bytes_sent as u64;

        Ok(bytes_sent)
    }

    /// 批量发送数据块（提高效率）
    pub async fn send_chunks_batch(
        &self,
        chunks: &[EncryptedChunk],
        dest_addr: &str,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let mut total_sent = 0;

        for chunk in chunks {
            match self.send_chunk(chunk, dest_addr).await {
                Ok(sent) => total_sent += sent,
                Err(e) => {
                    log::warn!("Failed to send UDP chunk {}: {}", chunk.sequence, e);
                    let mut stats = self.stats.write().await;
                    stats.packets_lost += 1;
                }
            }
        }

        Ok(total_sent)
    }

    /// 获取统计信息
    pub async fn get_stats(&self) -> UdpStats {
        self.stats.read().await.clone()
    }

    /// 重置统计信息
    pub async fn reset_stats(&self) {
        *self.stats.write().await = UdpStats::default();
    }
}

/// UDP流接收器
pub struct UdpStreamReceiver {
    socket: Arc<UdpSocket>,
    transport: Arc<SecureStreamTransport>,
    buffer: Arc<RwLock<Vec<EncryptedChunk>>>,
}

impl UdpStreamReceiver {
    pub async fn new(
        bind_addr: &str,
        transport: Arc<SecureStreamTransport>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let socket = UdpSocket::bind(bind_addr).await?;

        // 设置接收缓冲区大小（4MB）
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            unsafe {
                let buf_size: libc::c_int = 4 * 1024 * 1024;
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &buf_size as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        Ok(Self {
            socket: Arc::new(socket),
            transport,
            buffer: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// 接收数据块
    pub async fn receive_chunk(&self) -> Result<EncryptedChunk, Box<dyn std::error::Error>> {
        let mut buf = vec![0u8; 128 * 1024]; // 128KB buffer
        let (len, _addr) = self.socket.recv_from(&mut buf).await?;

        // 反序列化
        let chunk: EncryptedChunk = bincode::deserialize(&buf[..len])?;

        // 验证和解密
        self.transport.verify_zkp_proof(&chunk).await?;

        Ok(chunk)
    }

    /// 持续接收并缓冲数据
    pub async fn start_receiving(&self) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            match self.receive_chunk().await {
                Ok(chunk) => {
                    let mut buffer = self.buffer.write().await;
                    buffer.push(chunk);

                    // 保持缓冲区大小（最多1000个块）
                    if buffer.len() > 1000 {
                        buffer.drain(0..100);
                    }
                }
                Err(e) => {
                    log::error!("UDP receive error: {}", e);
                }
            }
        }
    }

    /// 获取缓冲的数据块
    pub async fn get_buffered_chunks(&self) -> Vec<EncryptedChunk> {
        let mut buffer = self.buffer.write().await;
        let chunks = buffer.clone();
        buffer.clear();
        chunks
    }
}
