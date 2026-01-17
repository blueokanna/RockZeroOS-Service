use std::collections::{VecDeque, BTreeMap};
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use tokio::time::{Duration, Instant};
use super::secure_transport::EncryptedChunk;

/// 数据块管理器 - 管理UDP/TCP混合传输的数据块
/// 支持乱序包重组、自动重传、随点随播
#[allow(dead_code)]
pub struct ChunkManager {
    /// 接收缓冲区 - 使用BTreeMap保证有序
    receive_buffer: Arc<RwLock<BTreeMap<u64, ChunkEntry>>>,
    /// 发送队列
    send_queue: Arc<RwLock<VecDeque<EncryptedChunk>>>,
    /// 下一个期望的序列号
    next_expected_seq: Arc<RwLock<u64>>,
    /// 缓冲区大小限制
    max_buffer_size: usize,
    /// 统计信息
    stats: Arc<RwLock<ChunkStats>>,
    /// 重传请求队列
    retransmit_queue: Arc<Mutex<VecDeque<RetransmitRequest>>>,
    /// 乱序容忍窗口大小
    reorder_window: usize,
    /// 最大等待时间（毫秒）
    max_wait_time: u64,
}

/// 数据块条目（包含接收时间）
#[derive(Debug, Clone)]
pub struct ChunkEntry {
    pub chunk: EncryptedChunk,
    pub received_at: Instant,
    pub from_udp: bool,
}

/// 重传请求
#[derive(Debug, Clone)]
pub struct RetransmitRequest {
    pub sequence: u64,
    pub requested_at: Instant,
    pub retry_count: u32,
    pub max_retries: u32,
}

#[derive(Debug, Default, Clone)]
pub struct ChunkStats {
    pub total_received: u64,
    pub total_sent: u64,
    pub out_of_order: u64,
    pub duplicates: u64,
    pub missing: u64,
    pub udp_chunks: u64,
    pub tcp_chunks: u64,
}

impl ChunkManager {
    pub fn new(max_buffer_size: usize) -> Self {
        Self {
            receive_buffer: Arc::new(RwLock::new(BTreeMap::new())),
            send_queue: Arc::new(RwLock::new(VecDeque::new())),
            next_expected_seq: Arc::new(RwLock::new(0)),
            max_buffer_size,
            stats: Arc::new(RwLock::new(ChunkStats::default())),
            retransmit_queue: Arc::new(Mutex::new(VecDeque::new())),
            reorder_window: 100, // 允许100个包的乱序
            max_wait_time: 500,  // 最多等待500ms
        }
    }

    /// 创建支持随点随播的管理器
    pub fn new_with_seek_support(max_buffer_size: usize, reorder_window: usize) -> Self {
        Self {
            receive_buffer: Arc::new(RwLock::new(BTreeMap::new())),
            send_queue: Arc::new(RwLock::new(VecDeque::new())),
            next_expected_seq: Arc::new(RwLock::new(0)),
            max_buffer_size,
            stats: Arc::new(RwLock::new(ChunkStats::default())),
            retransmit_queue: Arc::new(Mutex::new(VecDeque::new())),
            reorder_window,
            max_wait_time: 1000, // 随点随播需要更长的等待时间
        }
    }

    /// 添加接收到的数据块（支持乱序重组）
    pub async fn add_received_chunk(&self, chunk: EncryptedChunk, from_udp: bool) -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = self.receive_buffer.write().await;
        let mut stats = self.stats.write().await;
        
        // 检查是否是重复块
        if buffer.contains_key(&chunk.sequence) {
            stats.duplicates += 1;
            return Ok(());
        }

        let next_seq = *self.next_expected_seq.read().await;
        
        // 检查是否在重排序窗口内
        if chunk.sequence < next_seq {
            // 太旧的包，丢弃
            stats.out_of_order += 1;
            return Ok(());
        }
        
        if chunk.sequence > next_seq + self.reorder_window as u64 {
            // 太新的包，可能是网络问题，暂时丢弃
            log::warn!("Chunk {} is too far ahead (expected {}), dropping", chunk.sequence, next_seq);
            return Ok(());
        }

        // 检查缓冲区大小
        if buffer.len() >= self.max_buffer_size {
            // 移除最旧的块
            if let Some((&min_seq, _)) = buffer.iter().next() {
                buffer.remove(&min_seq);
            }
        }

        // 检查是否乱序
        if chunk.sequence > next_seq {
            stats.out_of_order += 1;
            
            // 请求缺失的块
            for missing_seq in next_seq..chunk.sequence {
                if !buffer.contains_key(&missing_seq) {
                    self.request_retransmit(missing_seq).await;
                }
            }
        }

        // 统计UDP/TCP
        if from_udp {
            stats.udp_chunks += 1;
        } else {
            stats.tcp_chunks += 1;
        }

        // 添加到缓冲区
        let entry = ChunkEntry {
            chunk,
            received_at: Instant::now(),
            from_udp,
        };
        
        buffer.insert(entry.chunk.sequence, entry);
        stats.total_received += 1;

        Ok(())
    }

    /// 请求重传缺失的块
    async fn request_retransmit(&self, sequence: u64) {
        let mut queue = self.retransmit_queue.lock().await;
        
        // 检查是否已经在队列中
        if queue.iter().any(|r| r.sequence == sequence) {
            return;
        }
        
        queue.push_back(RetransmitRequest {
            sequence,
            requested_at: Instant::now(),
            retry_count: 0,
            max_retries: 3,
        });
    }

    /// 获取待重传的序列号列表
    pub async fn get_retransmit_requests(&self) -> Vec<u64> {
        let mut queue = self.retransmit_queue.lock().await;
        let now = Instant::now();
        let mut requests = Vec::new();
        
        // 清理过期的请求
        queue.retain(|req| {
            if req.retry_count >= req.max_retries {
                false
            } else if now.duration_since(req.requested_at).as_millis() > 200 {
                // 超过200ms没有收到，重新请求
                requests.push(req.sequence);
                false
            } else {
                true
            }
        });
        
        requests
    }

    /// 获取下一个连续的数据块（支持超时等待）
    pub async fn get_next_chunk(&self) -> Option<EncryptedChunk> {
        let mut buffer = self.receive_buffer.write().await;
        let mut next_seq = self.next_expected_seq.write().await;

        if let Some(entry) = buffer.remove(&*next_seq) {
            *next_seq += 1;
            Some(entry.chunk)
        } else {
            None
        }
    }

    /// 获取下一个连续的数据块（带超时等待）
    pub async fn get_next_chunk_with_timeout(&self, timeout_ms: u64) -> Option<EncryptedChunk> {
        let start = Instant::now();
        
        loop {
            if let Some(chunk) = self.get_next_chunk().await {
                return Some(chunk);
            }
            
            // 检查超时
            if start.elapsed().as_millis() > timeout_ms as u128 {
                break;
            }
            
            // 短暂等待
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        
        None
    }

    /// 随点随播：跳转到指定序列号
    pub async fn seek_to(&self, target_seq: u64) -> Result<(), Box<dyn std::error::Error>> {
        let mut next_seq = self.next_expected_seq.write().await;
        let mut buffer = self.receive_buffer.write().await;
        
        // 清空旧的缓冲区
        buffer.retain(|&seq, _| seq >= target_seq);
        
        // 更新期望序列号
        *next_seq = target_seq;
        
        // 清空重传队列
        self.retransmit_queue.lock().await.clear();
        
        log::info!("Seeked to sequence {}", target_seq);
        Ok(())
    }

    /// 检查是否有足够的数据可以播放
    pub async fn has_enough_data(&self, min_chunks: usize) -> bool {
        let buffer = self.receive_buffer.read().await;
        let next_seq = *self.next_expected_seq.read().await;
        
        // 计算从next_seq开始的连续块数量
        let mut count = 0;
        for seq in next_seq.. {
            if buffer.contains_key(&seq) {
                count += 1;
                if count >= min_chunks {
                    return true;
                }
            } else {
                break;
            }
        }
        
        false
    }

    /// 获取多个连续的数据块
    pub async fn get_next_chunks(&self, count: usize) -> Vec<EncryptedChunk> {
        let mut chunks = Vec::new();
        
        for _ in 0..count {
            if let Some(chunk) = self.get_next_chunk().await {
                chunks.push(chunk);
            } else {
                break;
            }
        }
        
        chunks
    }

    /// 检查是否有缺失的数据块
    pub async fn get_missing_sequences(&self) -> Vec<u64> {
        let buffer = self.receive_buffer.read().await;
        let next_seq = *self.next_expected_seq.read().await;
        
        if buffer.is_empty() {
            return Vec::new();
        }

        let max_seq = *buffer.keys().max().unwrap();
        let mut missing = Vec::new();

        for seq in next_seq..=max_seq {
            if !buffer.contains_key(&seq) {
                missing.push(seq);
            }
        }

        // 更新统计
        if !missing.is_empty() {
            let mut stats = self.stats.write().await;
            stats.missing += missing.len() as u64;
        }

        missing
    }

    /// 添加到发送队列
    pub async fn enqueue_for_send(&self, chunk: EncryptedChunk) {
        let mut queue = self.send_queue.write().await;
        queue.push_back(chunk);
        
        let mut stats = self.stats.write().await;
        stats.total_sent += 1;
    }

    /// 从发送队列获取数据块
    pub async fn dequeue_for_send(&self) -> Option<EncryptedChunk> {
        let mut queue = self.send_queue.write().await;
        queue.pop_front()
    }

    /// 批量从发送队列获取数据块
    pub async fn dequeue_batch(&self, count: usize) -> Vec<EncryptedChunk> {
        let mut queue = self.send_queue.write().await;
        let mut chunks = Vec::new();
        
        for _ in 0..count {
            if let Some(chunk) = queue.pop_front() {
                chunks.push(chunk);
            } else {
                break;
            }
        }
        
        chunks
    }

    /// 获取缓冲区状态
    pub async fn get_buffer_status(&self) -> BufferStatus {
        let buffer = self.receive_buffer.read().await;
        let next_seq = *self.next_expected_seq.read().await;
        let queue = self.send_queue.read().await;

        BufferStatus {
            receive_buffer_size: buffer.len(),
            send_queue_size: queue.len(),
            next_expected_sequence: next_seq,
            buffer_utilization: (buffer.len() as f32 / self.max_buffer_size as f32) * 100.0,
        }
    }

    /// 获取统计信息
    pub async fn get_stats(&self) -> ChunkStats {
        self.stats.read().await.clone()
    }

    /// 重置统计信息
    pub async fn reset_stats(&self) {
        *self.stats.write().await = ChunkStats::default();
    }

    /// 清空缓冲区
    pub async fn clear_buffers(&self) {
        self.receive_buffer.write().await.clear();
        self.send_queue.write().await.clear();
        *self.next_expected_seq.write().await = 0;
    }

    /// 请求重传缺失的数据块
    pub async fn request_retransmission(&self) -> Vec<u64> {
        self.get_missing_sequences().await
    }
}

#[derive(Debug, Clone)]
pub struct BufferStatus {
    pub receive_buffer_size: usize,
    pub send_queue_size: usize,
    pub next_expected_sequence: u64,
    pub buffer_utilization: f32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::streaming::secure_transport::EncryptedChunk;

    fn create_test_chunk(sequence: u64) -> EncryptedChunk {
        EncryptedChunk {
            sequence,
            chunk_type: "NormalFrame".to_string(),
            data: vec![0u8; 1024],
            nonce: vec![0u8; 12],
            mac: vec![0u8; 32],
            timestamp: 0,
            zkp_proof: None,
        }
    }

    #[tokio::test]
    async fn test_sequential_chunks() {
        let manager = ChunkManager::new(100);
        
        // 添加连续的块
        for i in 0..5 {
            manager.add_received_chunk(create_test_chunk(i), false).await.unwrap();
        }

        // 获取块
        for i in 0..5 {
            let chunk = manager.get_next_chunk().await.unwrap();
            assert_eq!(chunk.sequence, i);
        }
    }

    #[tokio::test]
    async fn test_out_of_order_chunks() {
        let manager = ChunkManager::new(100);
        
        // 乱序添加块
        manager.add_received_chunk(create_test_chunk(2), false).await.unwrap();
        manager.add_received_chunk(create_test_chunk(0), false).await.unwrap();
        manager.add_received_chunk(create_test_chunk(1), false).await.unwrap();

        // 应该按顺序获取
        assert_eq!(manager.get_next_chunk().await.unwrap().sequence, 0);
        assert_eq!(manager.get_next_chunk().await.unwrap().sequence, 1);
        assert_eq!(manager.get_next_chunk().await.unwrap().sequence, 2);
    }

    #[tokio::test]
    async fn test_missing_sequences() {
        let manager = ChunkManager::new(100);
        
        // 添加不连续的块
        manager.add_received_chunk(create_test_chunk(0), false).await.unwrap();
        manager.add_received_chunk(create_test_chunk(2), false).await.unwrap();
        manager.add_received_chunk(create_test_chunk(4), false).await.unwrap();

        // 获取第一个块
        manager.get_next_chunk().await;

        // 检查缺失的序列号
        let missing = manager.get_missing_sequences().await;
        assert_eq!(missing, vec![1, 3]);
    }
}
