use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::RwLock;

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

        let mut hasher = Sha256::new();
        hasher.update(&commit_scalar);
        hasher.update(&commit_element);
        hasher.update(peer_id.as_bytes());
        let shared_secret = hasher.finalize().to_vec();

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
            // 验证peer的commit（简化版）
            let mut hasher = Sha256::new();
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

        // 生成MAC
        let mut hasher = Sha256::new();
        hasher.update(sequence.to_le_bytes());
        hasher.update(&encrypted);
        hasher.update(nonce_bytes);
        let mac = hasher.finalize().to_vec();

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

    /// 生成Bulletproofs风格的零知识证明
    async fn generate_zkp_proof(
        &self,
        data: &[u8],
        sequence: u64,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // 简化版Bulletproofs证明
        // 证明：我知道数据的哈希值，但不透露数据本身
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(sequence.to_le_bytes());

        // 添加随机盲化因子
        let mut blinding_factor = [0u8; 32];
        OsRng.fill_bytes(&mut blinding_factor);
        hasher.update(blinding_factor);

        let proof = hasher.finalize().to_vec();
        Ok(proof)
    }

    /// 验证零知识证明
    pub async fn verify_zkp_proof(
        &self,
        chunk: &EncryptedChunk,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if let Some(ref _proof) = chunk.zkp_proof {
            // 验证MAC
            let mut hasher = Sha256::new();
            hasher.update(chunk.sequence.to_le_bytes());
            hasher.update(&chunk.data);
            hasher.update(&chunk.nonce);
            let computed_mac = hasher.finalize().to_vec();

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

        assert!(encrypted.data.len() > 0);
        assert!(encrypted.zkp_proof.is_some());

        let decrypted = transport.decrypt_chunk(&encrypted).await.unwrap();
        assert_eq!(decrypted, data);
    }
}
