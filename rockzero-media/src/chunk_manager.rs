use super::secure_transport::EncryptedChunk;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{Duration, Instant};

pub struct ChunkManager {
    receive_buffer: Arc<RwLock<BTreeMap<u64, ChunkEntry>>>,
    send_queue: Arc<RwLock<VecDeque<EncryptedChunk>>>,
    next_expected_seq: Arc<RwLock<u64>>,
    max_buffer_size: usize,
    stats: Arc<RwLock<ChunkStats>>,
    retransmit_queue: Arc<Mutex<VecDeque<RetransmitRequest>>>,
    reorder_window: usize,
}

#[derive(Debug, Clone)]
pub struct ChunkEntry {
    pub chunk: EncryptedChunk,
    pub received_at: Instant,
    pub from_udp: bool,
}

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
            reorder_window: 30,
        }
    }

    pub fn new_with_seek_support(max_buffer_size: usize, reorder_window: usize) -> Self {
        Self {
            receive_buffer: Arc::new(RwLock::new(BTreeMap::new())),
            send_queue: Arc::new(RwLock::new(VecDeque::new())),
            next_expected_seq: Arc::new(RwLock::new(0)),
            max_buffer_size,
            stats: Arc::new(RwLock::new(ChunkStats::default())),
            retransmit_queue: Arc::new(Mutex::new(VecDeque::new())),
            reorder_window,
        }
    }

    pub async fn add_received_chunk(
        &self,
        chunk: EncryptedChunk,
        from_udp: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = self.receive_buffer.write().await;
        let mut stats = self.stats.write().await;

        if buffer.contains_key(&chunk.sequence) {
            stats.duplicates += 1;
            return Ok(());
        }

        let next_seq = *self.next_expected_seq.read().await;

        if chunk.sequence < next_seq {
            stats.out_of_order += 1;
            return Ok(());
        }

        if chunk.sequence > next_seq + self.reorder_window as u64 {
            log::warn!(
                "Chunk {} is too far ahead (expected {}), dropping",
                chunk.sequence,
                next_seq
            );
            return Ok(());
        }

        if buffer.len() >= self.max_buffer_size {
            if let Some((&min_seq, _)) = buffer.iter().next() {
                buffer.remove(&min_seq);
            }
        }

        if chunk.sequence > next_seq {
            stats.out_of_order += 1;

            for missing_seq in next_seq..chunk.sequence {
                if !buffer.contains_key(&missing_seq) {
                    self.request_retransmit(missing_seq).await;
                }
            }
        }

        if from_udp {
            stats.udp_chunks += 1;
        } else {
            stats.tcp_chunks += 1;
        }

        let entry = ChunkEntry {
            chunk,
            received_at: Instant::now(),
            from_udp,
        };

        buffer.insert(entry.chunk.sequence, entry);
        stats.total_received += 1;

        Ok(())
    }

    async fn request_retransmit(&self, sequence: u64) {
        let mut queue = self.retransmit_queue.lock().await;

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

    pub async fn get_retransmit_requests(&self) -> Vec<u64> {
        let mut queue = self.retransmit_queue.lock().await;
        let now = Instant::now();
        let mut requests = Vec::new();

        queue.retain(|req| {
            if req.retry_count >= req.max_retries {
                false
            } else if now.duration_since(req.requested_at).as_millis() > 200 {
                requests.push(req.sequence);
                false
            } else {
                true
            }
        });

        requests
    }

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

    pub async fn get_next_chunk_with_timeout(&self, timeout_ms: u64) -> Option<EncryptedChunk> {
        let start = Instant::now();

        loop {
            if let Some(chunk) = self.get_next_chunk().await {
                return Some(chunk);
            }

            if start.elapsed().as_millis() > timeout_ms as u128 {
                break;
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        None
    }

    pub async fn seek_to(&self, target_seq: u64) -> Result<(), Box<dyn std::error::Error>> {
        let mut next_seq = self.next_expected_seq.write().await;
        let mut buffer = self.receive_buffer.write().await;

        buffer.retain(|&seq, _| seq >= target_seq);

        *next_seq = target_seq;

        self.retransmit_queue.lock().await.clear();

        log::info!("Seeked to sequence {}", target_seq);
        Ok(())
    }

    pub async fn has_enough_data(&self, min_chunks: usize) -> bool {
        let buffer = self.receive_buffer.read().await;
        let next_seq = *self.next_expected_seq.read().await;

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

        if !missing.is_empty() {
            let mut stats = self.stats.write().await;
            stats.missing += missing.len() as u64;
        }

        missing
    }

    pub async fn enqueue_for_send(&self, chunk: EncryptedChunk) {
        let mut queue = self.send_queue.write().await;
        queue.push_back(chunk);

        let mut stats = self.stats.write().await;
        stats.total_sent += 1;
    }

    pub async fn dequeue_for_send(&self) -> Option<EncryptedChunk> {
        let mut queue = self.send_queue.write().await;
        queue.pop_front()
    }

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

    pub async fn get_stats(&self) -> ChunkStats {
        self.stats.read().await.clone()
    }

    pub async fn reset_stats(&self) {
        *self.stats.write().await = ChunkStats::default();
    }

    pub async fn clear_buffers(&self) {
        self.receive_buffer.write().await.clear();
        self.send_queue.write().await.clear();
        *self.next_expected_seq.write().await = 0;
    }

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
    use crate::secure_transport::EncryptedChunk;

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

        for i in 0..5 {
            manager
                .add_received_chunk(create_test_chunk(i), false)
                .await
                .unwrap();
        }

        for i in 0..5 {
            let chunk = manager.get_next_chunk().await.unwrap();
            assert_eq!(chunk.sequence, i);
        }
    }

    #[tokio::test]
    async fn test_out_of_order_chunks() {
        let manager = ChunkManager::new(100);

        manager
            .add_received_chunk(create_test_chunk(2), false)
            .await
            .unwrap();
        manager
            .add_received_chunk(create_test_chunk(0), false)
            .await
            .unwrap();
        manager
            .add_received_chunk(create_test_chunk(1), false)
            .await
            .unwrap();

        assert_eq!(manager.get_next_chunk().await.unwrap().sequence, 0);
        assert_eq!(manager.get_next_chunk().await.unwrap().sequence, 1);
        assert_eq!(manager.get_next_chunk().await.unwrap().sequence, 2);
    }

    #[tokio::test]
    async fn test_missing_sequences() {
        let manager = ChunkManager::new(100);

        manager
            .add_received_chunk(create_test_chunk(0), false)
            .await
            .unwrap();
        manager
            .add_received_chunk(create_test_chunk(2), false)
            .await
            .unwrap();
        manager
            .add_received_chunk(create_test_chunk(4), false)
            .await
            .unwrap();

        manager.get_next_chunk().await;

        let missing = manager.get_missing_sequences().await;
        assert_eq!(missing, vec![1, 3]);
    }
}
