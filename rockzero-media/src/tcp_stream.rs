use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use tokio::sync::RwLock;
use super::secure_transport::{EncryptedChunk, SecureStreamTransport};

pub struct TcpStreamSender {
    stream: Arc<RwLock<TcpStream>>,
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
    ) -> Result<Self, Box<dyn std::error::Error>> {
        stream.set_nodelay(true)?;
        
        Ok(Self {
            stream: Arc::new(RwLock::new(stream)),
            stats: Arc::new(RwLock::new(TcpStats::default())),
        })
    }

    pub async fn send_chunk(
        &self,
        chunk: &EncryptedChunk,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let serialized = bincode::serialize(chunk)?;
        let len = serialized.len() as u32;
        
        let mut stream = self.stream.write().await;
        stream.write_all(&len.to_le_bytes()).await?;
        stream.write_all(&serialized).await?;
        stream.flush().await?;
        
        let mut stats = self.stats.write().await;
        stats.chunks_sent += 1;
        stats.bytes_sent += (len + 4) as u64;
        
        Ok((len + 4) as usize)
    }

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

    pub async fn get_stats(&self) -> TcpStats {
        self.stats.read().await.clone()
    }
}

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

    pub async fn receive_chunk(&self) -> Result<EncryptedChunk, Box<dyn std::error::Error>> {
        let mut stream = self.stream.write().await;
        
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        
        let mut data_buf = vec![0u8; len];
        stream.read_exact(&mut data_buf).await?;
        
        let chunk: EncryptedChunk = bincode::deserialize(&data_buf)?;
        
        self.transport.verify_zkp_proof(&chunk).await?;
        
        Ok(chunk)
    }

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

    pub async fn accept(&self) -> Result<TcpStreamReceiver, Box<dyn std::error::Error>> {
        let (stream, _addr) = self.listener.accept().await?;
        TcpStreamReceiver::new(stream, self.transport.clone()).await
    }
}
