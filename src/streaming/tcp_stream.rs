use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use tokio::sync::RwLock;
use super::secure_transport::{EncryptedChunk, SecureStreamTransport};

/// TCP流发送器 - 30%的数据通过TCP传输（关键帧、音频、字幕）
#[allow(dead_code)]
pub struct TcpStreamSender {
    stream: Arc<RwLock<TcpStream>>,
    transport: Arc<SecureStreamTransport>,
    stats: Arc<RwLock<TcpStats>>,
}

#[derive(Debug, Default, Clone)]
pub struct TcpStats {
    pub chunks_sent: u64,
    pub bytes_sent: u64,
    pub connection_errors: u64,
}

impl TcpStreamSender {
    pub async fn new(
        stream: TcpStream,
        transport: Arc<SecureStreamTransport>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // 设置TCP选项以优化性能
        stream.set_nodelay(true)?; // 禁用Nagle算法，减少延迟
        
        Ok(Self {
            stream: Arc::new(RwLock::new(stream)),
            transport,
            stats: Arc::new(RwLock::new(TcpStats::default())),
        })
    }

    /// 发送加密的数据块
    pub async fn send_chunk(
        &self,
        chunk: &EncryptedChunk,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        // 序列化chunk
        let serialized = bincode::serialize(chunk)?;
        let len = serialized.len() as u32;
        
        // 发送长度前缀（4字节）+ 数据
        let mut stream = self.stream.write().await;
        stream.write_all(&len.to_le_bytes()).await?;
        stream.write_all(&serialized).await?;
        stream.flush().await?;
        
        // 更新统计
        let mut stats = self.stats.write().await;
        stats.chunks_sent += 1;
        stats.bytes_sent += (len + 4) as u64;
        
        Ok((len + 4) as usize)
    }

    /// 批量发送数据块
    pub async fn send_chunks_batch(
        &self,
        chunks: &[EncryptedChunk],
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let mut total_sent = 0;
        
        for chunk in chunks {
            match self.send_chunk(chunk).await {
                Ok(sent) => total_sent += sent,
                Err(e) => {
                    log::error!("Failed to send TCP chunk {}: {}", chunk.sequence, e);
                    let mut stats = self.stats.write().await;
                    stats.connection_errors += 1;
                    return Err(e);
                }
            }
        }
        
        Ok(total_sent)
    }

    /// 获取统计信息
    pub async fn get_stats(&self) -> TcpStats {
        self.stats.read().await.clone()
    }
}

/// TCP流接收器
pub struct TcpStreamReceiver {
    stream: Arc<RwLock<TcpStream>>,
    transport: Arc<SecureStreamTransport>,
}

impl TcpStreamReceiver {
    pub async fn new(
        stream: TcpStream,
        transport: Arc<SecureStreamTransport>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        stream.set_nodelay(true)?;
        
        Ok(Self {
            stream: Arc::new(RwLock::new(stream)),
            transport,
        })
    }

    /// 接收数据块
    pub async fn receive_chunk(&self) -> Result<EncryptedChunk, Box<dyn std::error::Error>> {
        let mut stream = self.stream.write().await;
        
        // 读取长度前缀
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        
        // 读取数据
        let mut data_buf = vec![0u8; len];
        stream.read_exact(&mut data_buf).await?;
        
        // 反序列化
        let chunk: EncryptedChunk = bincode::deserialize(&data_buf)?;
        
        // 验证
        self.transport.verify_zkp_proof(&chunk).await?;
        
        Ok(chunk)
    }

    /// 持续接收数据
    pub async fn start_receiving(
        &self,
        callback: impl Fn(EncryptedChunk) + Send + 'static,
    ) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            match self.receive_chunk().await {
                Ok(chunk) => {
                    callback(chunk);
                }
                Err(e) => {
                    log::error!("TCP receive error: {}", e);
                    return Err(e);
                }
            }
        }
    }
}

/// TCP流服务器
pub struct TcpStreamServer {
    listener: TcpListener,
    transport: Arc<SecureStreamTransport>,
}

impl TcpStreamServer {
    pub async fn new(
        bind_addr: &str,
        transport: Arc<SecureStreamTransport>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(bind_addr).await?;
        
        Ok(Self {
            listener,
            transport,
        })
    }

    /// 接受新连接
    pub async fn accept(&self) -> Result<TcpStreamReceiver, Box<dyn std::error::Error>> {
        let (stream, _addr) = self.listener.accept().await?;
        TcpStreamReceiver::new(stream, self.transport.clone()).await
    }
}
