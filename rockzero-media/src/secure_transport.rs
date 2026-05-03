use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use rockzero_crypto::{EnhancedPasswordProof, PasswordRegistration, ZkpContext};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;

fn blake3_hash_bytes(data: &[u8]) -> [u8; 32] {
    let digest = blake3::hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

fn chunk_type_name(chunk_type: ChunkType) -> &'static str {
    match chunk_type {
        ChunkType::KeyFrame => "KeyFrame",
        ChunkType::NormalFrame => "NormalFrame",
        ChunkType::Audio => "Audio",
        ChunkType::Subtitle => "Subtitle",
    }
}

fn chunk_aad(sequence: u64, chunk_type: &str, timestamp: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(24 + chunk_type.len());
    aad.extend_from_slice(&sequence.to_le_bytes());
    aad.extend_from_slice(&timestamp.to_le_bytes());
    aad.extend_from_slice(chunk_type.as_bytes());
    aad
}

fn derive_mac_key(shared_secret: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + shared_secret.len());
    input.extend_from_slice(b"rockzero-secure-stream-mac-v1");
    input.extend_from_slice(shared_secret);
    blake3_hash_bytes(&input)
}

fn compute_chunk_mac(
    shared_secret: &[u8],
    sequence: u64,
    chunk_type: &str,
    timestamp: u64,
    nonce: &[u8],
    data: &[u8],
) -> Vec<u8> {
    let mut mac_input = chunk_aad(sequence, chunk_type, timestamp);
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(data);
    blake3::keyed_hash(&derive_mac_key(shared_secret), &mac_input)
        .as_bytes()
        .to_vec()
}

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
            enable_zkp: false,
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
    cipher: Arc<RwLock<ChaCha20Poly1305>>,
    sequence_counter: Arc<RwLock<u64>>,
    zkp_registration: Arc<RwLock<Option<PasswordRegistration>>>,
    zkp_password: Arc<RwLock<Option<String>>>,
    sae_psk: Arc<RwLock<Option<[u8; 32]>>>,
}

impl SecureStreamTransport {
    pub fn new(config: StreamConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        let cipher = ChaCha20Poly1305::new(&key_bytes.into());

        Ok(Self {
            config,
            auth_state: Arc::new(RwLock::new(None)),
            cipher: Arc::new(RwLock::new(cipher)),
            sequence_counter: Arc::new(RwLock::new(0)),
            zkp_registration: Arc::new(RwLock::new(None)),
            zkp_password: Arc::new(RwLock::new(None)),
            sae_psk: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn configure_zkp_auth(&self, password: String, registration: PasswordRegistration) {
        *self.zkp_password.write().await = Some(password);
        *self.zkp_registration.write().await = Some(registration);
    }

    pub async fn configure_sae_psk(&self, psk: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        if psk.len() < 32 {
            return Err("SAE PSK must be at least 32 bytes".into());
        }
        let mut input = Vec::with_capacity(32 + psk.len());
        input.extend_from_slice(b"rockzero-sae-psk-derive-v1");
        input.extend_from_slice(psk);
        let derived = blake3_hash_bytes(&input);
        let mut key = [0u8; 32];
        key.copy_from_slice(&derived[..32]);
        *self.sae_psk.write().await = Some(key);
        Ok(())
    }

    pub async fn initiate_sae_auth(
        &self,
        peer_id: &str,
    ) -> Result<SaeAuthState, Box<dyn std::error::Error>> {
        let psk = {
            let guard = self.sae_psk.read().await;
            (*guard)
                .ok_or("SAE PSK not configured; call configure_sae_psk before initiate_sae_auth")?
        };

        let mut commit_scalar = vec![0u8; 32];
        let mut commit_element = vec![0u8; 32];
        OsRng.fill_bytes(&mut commit_scalar);
        OsRng.fill_bytes(&mut commit_element);

        let mut secret_input = Vec::with_capacity(
            psk.len() + commit_scalar.len() + commit_element.len() + peer_id.len() + 32,
        );
        secret_input.extend_from_slice(b"rockzero-sae-shared-secret-v2");
        secret_input.extend_from_slice(&psk);
        secret_input.extend_from_slice(&commit_scalar);
        secret_input.extend_from_slice(&commit_element);
        secret_input.extend_from_slice(peer_id.as_bytes());
        let shared_secret = blake3_hash_bytes(&secret_input).to_vec();

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
            let mut expected_commit_input = Vec::with_capacity(
                state.shared_secret.len() + state.commit_scalar.len() + state.commit_element.len(),
            );
            expected_commit_input.extend_from_slice(&state.shared_secret);
            expected_commit_input.extend_from_slice(&state.commit_scalar);
            expected_commit_input.extend_from_slice(&state.commit_element);
            let expected_peer_commit = blake3_hash_bytes(&expected_commit_input);

            if peer_commit != expected_peer_commit.as_slice() {
                return Ok(false);
            }

            let mut confirm_input =
                Vec::with_capacity(state.commit_scalar.len() + peer_commit.len());
            confirm_input.extend_from_slice(&state.commit_scalar);
            confirm_input.extend_from_slice(peer_commit);
            let confirm_hash = blake3_hash_bytes(&confirm_input);

            let mut key_input = Vec::with_capacity(64 + state.shared_secret.len());
            key_input.extend_from_slice(b"rockzero-secure-stream-chacha-key-v1");
            key_input.extend_from_slice(&state.shared_secret);
            key_input.extend_from_slice(&confirm_hash);
            let derived_key = blake3_hash_bytes(&key_input);
            let rekeyed_cipher = ChaCha20Poly1305::new(&derived_key.into());
            *self.cipher.write().await = rekeyed_cipher;

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
        let auth_state = auth.as_ref().ok_or("Not authenticated")?;
        if !auth_state.confirmed {
            return Err("Not authenticated".into());
        }

        let mut seq = self.sequence_counter.write().await;
        let sequence = *seq;
        *seq += 1;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as u64;
        let chunk_type_name = chunk_type_name(chunk_type).to_string();
        let aad = chunk_aad(sequence, &chunk_type_name, timestamp);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = self
            .cipher
            .read()
            .await
            .encrypt(
                nonce,
                Payload {
                    msg: data,
                    aad: &aad,
                },
            )
            .map_err(|e| format!("Encryption failed: {}", e))?;

        let mac = compute_chunk_mac(
            &auth_state.shared_secret,
            sequence,
            &chunk_type_name,
            timestamp,
            &nonce_bytes,
            &encrypted,
        );

        let zkp_proof = if self.config.enable_zkp {
            Some(self.generate_zkp_proof(sequence).await?)
        } else {
            None
        };

        Ok(EncryptedChunk {
            sequence,
            chunk_type: chunk_type_name,
            data: encrypted,
            nonce: nonce_bytes.to_vec(),
            mac,
            timestamp,
            zkp_proof,
        })
    }

    async fn generate_zkp_proof(
        &self,
        sequence: u64,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let maybe_password = self.zkp_password.read().await.clone();
        let maybe_registration = self.zkp_registration.read().await.clone();

        if let (Some(password), Some(registration)) = (maybe_password, maybe_registration) {
            let zkp_ctx = ZkpContext::new();
            let context = format!("secure_stream_chunk:{}", sequence);
            let proof = zkp_ctx.generate_enhanced_proof(&password, &registration, &context)?;
            return Ok(serde_json::to_vec(&proof)?);
        }

        Err("ZKP auth is enabled but registration/password is not configured".into())
    }

    pub async fn verify_zkp_proof(
        &self,
        chunk: &EncryptedChunk,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let auth = self.auth_state.read().await;
        let auth_state = auth.as_ref().ok_or("Missing auth state")?;
        if !auth_state.confirmed {
            return Err("Not authenticated".into());
        }

        let computed_mac = compute_chunk_mac(
            &auth_state.shared_secret,
            chunk.sequence,
            &chunk.chunk_type,
            chunk.timestamp,
            &chunk.nonce,
            &chunk.data,
        );
        if computed_mac != chunk.mac {
            return Ok(false);
        }

        if self.config.enable_zkp {
            let proof = chunk
                .zkp_proof
                .as_ref()
                .ok_or("Missing ZKP proof while ZKP is enabled")?;

            let registration = self
                .zkp_registration
                .read()
                .await
                .clone()
                .ok_or("Missing ZKP registration while ZKP is enabled")?;

            let parsed_proof: EnhancedPasswordProof = serde_json::from_slice(proof)
                .map_err(|_| "Invalid EnhancedPasswordProof payload")?;
            let context = format!("secure_stream_chunk:{}", chunk.sequence);
            let zkp_ctx = ZkpContext::new();
            return zkp_ctx
                .verify_enhanced_proof(&parsed_proof, &registration, &context, 300)
                .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) });
        }

        Ok(true)
    }

    pub async fn decrypt_chunk(
        &self,
        chunk: &EncryptedChunk,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if !self.verify_zkp_proof(chunk).await? {
            return Err("ZKP verification failed".into());
        }

        let nonce = Nonce::from_slice(&chunk.nonce);
        let aad = chunk_aad(chunk.sequence, &chunk.chunk_type, chunk.timestamp);
        let decrypted = self
            .cipher
            .read()
            .await
            .decrypt(
                nonce,
                Payload {
                    msg: chunk.data.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|e| format!("Decryption failed: {}", e))?;

        Ok(decrypted)
    }

    pub fn should_use_udp(&self, chunk_type: ChunkType, chunk_index: usize) -> bool {
        match chunk_type {
            ChunkType::KeyFrame => false,
            ChunkType::Audio => chunk_index % 10 >= 7,
            ChunkType::Subtitle => false,
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
    use chrono::Utc;

    async fn setup_authenticated_transport(enable_zkp: bool) -> SecureStreamTransport {
        let config = StreamConfig {
            enable_zkp,
            ..StreamConfig::default()
        };
        let transport = SecureStreamTransport::new(config).unwrap();
        transport.configure_sae_psk(&[0xA5u8; 32]).await.unwrap();
        let auth_state = transport.initiate_sae_auth("peer1").await.unwrap();
        let mut expected_commit_input = Vec::new();
        expected_commit_input.extend_from_slice(&auth_state.shared_secret);
        expected_commit_input.extend_from_slice(&auth_state.commit_scalar);
        expected_commit_input.extend_from_slice(&auth_state.commit_element);
        let expected_commit = blake3_hash_bytes(&expected_commit_input);
        transport.confirm_sae_auth(&expected_commit).await.unwrap();
        transport
    }

    async fn setup_transport_with_zkp_auth() -> (SecureStreamTransport, String, PasswordRegistration)
    {
        let transport = setup_authenticated_transport(true).await;
        let password = "SecureTestPassword123!@#".to_string();
        let zkp_ctx = ZkpContext::new();
        let registration = zkp_ctx.register_password(&password).unwrap();
        transport
            .configure_zkp_auth(password.clone(), registration.clone())
            .await;
        (transport, password, registration)
    }

    #[tokio::test]
    async fn test_sae_auth() {
        let config = StreamConfig::default();
        let transport = SecureStreamTransport::new(config).unwrap();
        transport.configure_sae_psk(&[0xA5u8; 32]).await.unwrap();

        let auth_state = transport.initiate_sae_auth("peer1").await.unwrap();
        assert!(!auth_state.confirmed);

        let confirmed = transport
            .confirm_sae_auth(&blake3_hash_bytes(
                &[
                    auth_state.shared_secret.as_slice(),
                    auth_state.commit_scalar.as_slice(),
                    auth_state.commit_element.as_slice(),
                ]
                .concat(),
            ))
            .await
            .unwrap();
        assert!(confirmed);
    }

    #[tokio::test]
    async fn test_encryption() {
        let (transport, _, _) = setup_transport_with_zkp_auth().await;

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

    #[tokio::test]
    async fn test_encrypt_fails_when_zkp_registration_missing() {
        let transport = setup_authenticated_transport(true).await;
        let result = transport
            .encrypt_chunk(b"test data", ChunkType::NormalFrame)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_fails_when_proof_missing() {
        let (transport, _, _) = setup_transport_with_zkp_auth().await;
        let mut chunk = transport
            .encrypt_chunk(b"test data", ChunkType::NormalFrame)
            .await
            .unwrap();
        chunk.zkp_proof = None;

        let result = transport.verify_zkp_proof(&chunk).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_fails_for_fake_proof() {
        let (transport, _, _) = setup_transport_with_zkp_auth().await;
        let mut chunk = transport
            .encrypt_chunk(b"test data", ChunkType::NormalFrame)
            .await
            .unwrap();
        chunk.zkp_proof = Some(b"{\"fake\":true}".to_vec());

        let result = transport.verify_zkp_proof(&chunk).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_fails_for_expired_proof() {
        let (transport, _, _) = setup_transport_with_zkp_auth().await;
        let mut chunk = transport
            .encrypt_chunk(b"test data", ChunkType::NormalFrame)
            .await
            .unwrap();

        let mut proof: EnhancedPasswordProof =
            serde_json::from_slice(chunk.zkp_proof.as_ref().unwrap()).unwrap();
        proof.timestamp = Utc::now().timestamp() - 3600;
        chunk.zkp_proof = Some(serde_json::to_vec(&proof).unwrap());

        let result = transport.verify_zkp_proof(&chunk).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_fails_for_context_mismatch() {
        let (transport, _, _) = setup_transport_with_zkp_auth().await;
        let mut chunk = transport
            .encrypt_chunk(b"test data", ChunkType::NormalFrame)
            .await
            .unwrap();

        let mut proof: EnhancedPasswordProof =
            serde_json::from_slice(chunk.zkp_proof.as_ref().unwrap()).unwrap();
        proof.context = "secure_stream_chunk:wrong".to_string();
        chunk.zkp_proof = Some(serde_json::to_vec(&proof).unwrap());

        let result = transport.verify_zkp_proof(&chunk).await;
        assert!(result.is_err());
    }
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridConfig {
    pub udp_ratio: f32,

    pub tcp_ratio: f32,

    pub chunk_size: usize,

    pub udp_bind_addr: String,

    pub tcp_bind_addr: String,

    pub udp_window_size: usize,

    pub tcp_max_retries: u32,

    pub udp_loss_threshold: f64,

    pub adaptive_ratio: bool,

    #[serde(default = "default_udp_min_ratio")]
    pub udp_min_ratio: f32,

    #[serde(default = "default_udp_max_ratio")]
    pub udp_max_ratio: f32,

    pub send_buffer_size: usize,

    pub reorder_buffer_size: usize,
}

fn default_udp_min_ratio() -> f32 {
    0.10
}

fn default_udp_max_ratio() -> f32 {
    0.70
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
            udp_loss_threshold: 0.05,
            adaptive_ratio: true,
            udp_min_ratio: 0.10,
            udp_max_ratio: 0.70,
            send_buffer_size: 8 * 1024 * 1024,
            reorder_buffer_size: 256,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportChannel {
    Udp,
    Tcp,
}

#[derive(Debug, Clone)]
pub struct TransportChunk {
    pub sequence: u64,
    pub chunk_type: ChunkType,
    pub data: Vec<u8>,
    pub channel: TransportChannel,
    pub priority: u8,
}

pub struct HybridTransport {
    transport: Arc<SecureStreamTransport>,
    config: HybridConfig,
    stats: Arc<RwLock<HybridTransportStats>>,

    current_udp_ratio: Arc<RwLock<f32>>,

    reorder_buffer: Arc<RwLock<BTreeMap<u64, EncryptedChunk>>>,

    last_delivered_seq: Arc<RwLock<u64>>,

    bandwidth_samples: Arc<RwLock<Vec<(u64, u64)>>>,
}

impl HybridTransport {
    pub fn new(transport: Arc<SecureStreamTransport>, mut config: HybridConfig) -> Self {
        if config.udp_min_ratio < 0.0 {
            config.udp_min_ratio = 0.0;
        }
        if config.udp_max_ratio > 1.0 {
            config.udp_max_ratio = 1.0;
        }
        if config.udp_min_ratio > config.udp_max_ratio {
            std::mem::swap(&mut config.udp_min_ratio, &mut config.udp_max_ratio);
        }

        let initial_ratio = config
            .udp_ratio
            .clamp(config.udp_min_ratio, config.udp_max_ratio);
        config.udp_ratio = initial_ratio;
        config.tcp_ratio = 1.0 - initial_ratio;
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

    pub fn with_default_config(transport: Arc<SecureStreamTransport>) -> Self {
        Self::new(transport, HybridConfig::default())
    }

    pub async fn route_chunk(&self, chunk_type: ChunkType, sequence: u64) -> TransportChannel {
        match chunk_type {
            ChunkType::KeyFrame | ChunkType::Subtitle => TransportChannel::Tcp,

            ChunkType::Audio => {
                if (sequence % 10) < 7 {
                    TransportChannel::Tcp
                } else {
                    TransportChannel::Udp
                }
            }

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

            let encrypted = self.transport.encrypt_chunk(chunk_data, chunk_type).await?;

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

        let udp_socket = tokio::net::UdpSocket::bind(&self.config.udp_bind_addr).await?;

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

                    tcp_chunks.push(chunk);
                }
            }
        }

        let tcp_stream_clone = tcp_stream;
        for chunk in &tcp_chunks {
            let len = chunk.data.len() as u32;
            let mut retries = 0;
            loop {
                match tcp_stream_clone.try_write(&len.to_le_bytes()) {
                    Ok(_) => match tcp_stream_clone.try_write(&chunk.data) {
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
                    },
                    Err(e) if retries < self.config.tcp_max_retries => {
                        retries += 1;
                        tokio::time::sleep(tokio::time::Duration::from_millis(10 * retries as u64))
                            .await;
                        log::warn!(
                            "TCP header write retry {}/{}: {}",
                            retries,
                            self.config.tcp_max_retries,
                            e
                        );
                    }
                    Err(e) => {
                        log::error!("TCP header send failed for seq {}: {}", chunk.sequence, e);
                        break;
                    }
                }
            }
        }

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

            let elapsed_s = (now - stats.started_at).max(1) as f64 / 1000.0;
            stats.bandwidth_bps = (total as f64 / elapsed_s) as u64;
        }

        if self.config.adaptive_ratio {
            self.adapt_ratio().await;
        }

        {
            let mut samples = self.bandwidth_samples.write().await;
            samples.push((now, udp_bytes + tcp_bytes));

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

    async fn adapt_ratio(&self) {
        let stats = self.stats.read().await;
        let total_udp = stats.udp_chunks_sent;
        let lost = stats.udp_packets_lost;
        drop(stats);

        if total_udp < 50 {
            return;
        }

        let loss_rate = lost as f64 / total_udp as f64;
        let mut ratio = self.current_udp_ratio.write().await;
        let min_udp = self.config.udp_min_ratio;
        let max_udp = self.config.udp_max_ratio;

        if loss_rate < 0.02 {
            *ratio = (*ratio + 0.02).clamp(min_udp, max_udp);
        } else if loss_rate > 0.15 {
            *ratio = (*ratio - 0.10).clamp(min_udp, max_udp);
            log::warn!(
                "High UDP loss rate ({:.1}%), reducing UDP ratio to {:.0}%",
                loss_rate * 100.0,
                *ratio * 100.0
            );
        } else if loss_rate > self.config.udp_loss_threshold {
            *ratio = (*ratio - 0.05).clamp(min_udp, max_udp);
            log::info!(
                "UDP loss rate ({:.1}%) above threshold, adjusting ratio to {:.0}%",
                loss_rate * 100.0,
                *ratio * 100.0
            );
        }

        let current_tcp = 1.0 - *ratio;
        debug_assert!((0.30..=0.90).contains(&current_tcp));
    }

    pub async fn buffer_received_chunk(&self, chunk: EncryptedChunk) {
        let seq = chunk.sequence;
        let mut buffer = self.reorder_buffer.write().await;
        buffer.insert(seq, chunk);

        while buffer.len() > self.config.reorder_buffer_size {
            if let Some((&oldest_seq, _)) = buffer.iter().next() {
                buffer.remove(&oldest_seq);
            }
        }
    }

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

    pub async fn get_stats(&self) -> HybridTransportStats {
        self.stats.read().await.clone()
    }

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

    pub async fn current_udp_ratio(&self) -> f32 {
        *self.current_udp_ratio.read().await
    }

    pub fn config(&self) -> &HybridConfig {
        &self.config
    }
}

#[derive(Debug, Clone)]
pub struct HybridSendResult {
    pub udp_sent: usize,
    pub tcp_sent: usize,
    pub udp_bytes: u64,
    pub tcp_bytes: u64,
    pub udp_failed: usize,
}
