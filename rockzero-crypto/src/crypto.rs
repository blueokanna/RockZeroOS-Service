// Service 特有的加密功能
use rockzero_common::AppError as ServiceAppError;
use crate::crc32_checksum;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub const NONCE_SIZE: usize = 12;

// ============ BLAKE3 哈希宏 (Service 特有) ============

#[macro_export]
macro_rules! blake3_hash {
    ($($data:expr),+ $(,)?) => {{
        let mut hasher = blake3::Hasher::new();
        $(hasher.update($data);)+
        hasher.finalize()
    }};
}

#[macro_export]
macro_rules! blake3_domain_hash {
    ($domain:expr, $($data:expr),+ $(,)?) => {{
        let mut hasher = blake3::Hasher::new_derive_key($domain);
        $(hasher.update($data);)+
        hasher.finalize()
    }};
}

#[macro_export]
macro_rules! blake3_derive_key {
    ($context:expr, $($data:expr),+ $(,)?) => {{
        let mut hasher = blake3::Hasher::new_derive_key($context);
        $(hasher.update($data);)+
        let hash = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(hash.as_bytes());
        key
    }};
}

// ============ 加密上下文 (Service 特有) ============

pub struct CryptoContext {
    cipher: Aes256Gcm,
    key_id: String,
}

impl CryptoContext {
    pub fn new(master_key: &str) -> Result<Self, ServiceAppError> {
        let key = blake3_derive_key!("RockZero-CryptoContext-v1", master_key.as_bytes());

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| ServiceAppError::CryptoError("Failed to create cipher".to_string()))?;

        let key_hash = blake3_hash!(&key);
        let key_id = hex::encode(&key_hash.as_bytes()[..8]);

        Ok(Self { cipher, key_id })
    }

    pub fn from_key(key: &[u8; 32]) -> Result<Self, ServiceAppError> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| ServiceAppError::CryptoError("Failed to create cipher".to_string()))?;

        let key_hash = blake3_hash!(key);
        let key_id = hex::encode(&key_hash.as_bytes()[..8]);

        Ok(Self { cipher, key_id })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData, ServiceAppError> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|_| ServiceAppError::CryptoError("Failed to generate nonce".to_string()))?;

        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| ServiceAppError::CryptoError("Encryption failed".to_string()))?;

        Ok(EncryptedData {
            ciphertext,
            nonce: nonce_bytes,
            key_id: self.key_id.clone(),
        })
    }

    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>, ServiceAppError> {
        if encrypted.key_id != self.key_id {
            return Err(ServiceAppError::CryptoError("Key mismatch".to_string()));
        }

        let nonce = Nonce::from_slice(&encrypted.nonce);

        let plaintext = self
            .cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|_| ServiceAppError::CryptoError("Decryption failed".to_string()))?;

        Ok(plaintext)
    }

    pub fn encrypt_string(&self, plaintext: &str) -> Result<String, ServiceAppError> {
        let encrypted = self.encrypt(plaintext.as_bytes())?;
        Ok(encrypted.to_base64())
    }

    pub fn decrypt_string(&self, encrypted_base64: &str) -> Result<String, ServiceAppError> {
        let encrypted = EncryptedData::from_base64(encrypted_base64)?;
        let plaintext = self.decrypt(&encrypted)?;
        String::from_utf8(plaintext).map_err(|_| ServiceAppError::CryptoError("Invalid UTF-8".to_string()))
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

// ============ 加密数据结构 (Service 特有) ============

#[derive(Debug, Clone)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; NONCE_SIZE],
    pub key_id: String,
}

impl EncryptedData {
    pub fn to_base64(&self) -> String {
        let mut bytes = Vec::new();
        bytes.push(1); // 版本号
        bytes.push(self.key_id.len() as u8);
        bytes.extend_from_slice(self.key_id.as_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        BASE64.encode(&bytes)
    }

    pub fn from_base64(encoded: &str) -> Result<Self, ServiceAppError> {
        let bytes = BASE64
            .decode(encoded)
            .map_err(|_| ServiceAppError::CryptoError("Invalid Base64".to_string()))?;

        if bytes.len() < 14 {
            return Err(ServiceAppError::CryptoError("Invalid encrypted data".to_string()));
        }

        let mut offset = 0;
        let version = bytes[offset];
        offset += 1;

        if version != 1 {
            return Err(ServiceAppError::CryptoError("Unsupported version".to_string()));
        }

        let key_id_len = bytes[offset] as usize;
        offset += 1;

        if bytes.len() < offset + key_id_len + NONCE_SIZE {
            return Err(ServiceAppError::CryptoError("Invalid encrypted data".to_string()));
        }

        let key_id = String::from_utf8(bytes[offset..offset + key_id_len].to_vec())
            .map_err(|_| ServiceAppError::CryptoError("Invalid key ID".to_string()))?;
        offset += key_id_len;

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[offset..offset + NONCE_SIZE]);
        offset += NONCE_SIZE;

        let ciphertext = bytes[offset..].to_vec();

        Ok(Self {
            ciphertext,
            nonce,
            key_id,
        })
    }
}

// ============ 文件传输状态管理 (Service 特有) ============

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferState {
    Transferring,
    PendingEncryption,
    Encrypted,
    EncryptionFailed(String),
}

#[derive(Debug, Clone)]
pub struct TransferInfo {
    pub path: String,
    pub state: TransferState,
    pub expected_size: u64,
    pub current_size: u64,
    pub started_at: i64,
    pub updated_at: i64,
    pub crc32: Option<u32>,
}

pub struct TransferManager {
    transfers: Arc<RwLock<HashMap<String, TransferInfo>>>,
}

impl TransferManager {
    pub fn new() -> Self {
        Self {
            transfers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn start_transfer(&self, path: &str, expected_size: u64) -> Result<(), ServiceAppError> {
        let now = chrono::Utc::now().timestamp();
        let info = TransferInfo {
            path: path.to_string(),
            state: TransferState::Transferring,
            expected_size,
            current_size: 0,
            started_at: now,
            updated_at: now,
            crc32: None,
        };

        let mut transfers = self.transfers.write().await;
        transfers.insert(path.to_string(), info);
        Ok(())
    }

    pub async fn update_progress(&self, path: &str, current_size: u64) -> Result<(), ServiceAppError> {
        let mut transfers = self.transfers.write().await;
        if let Some(info) = transfers.get_mut(path) {
            info.current_size = current_size;
            info.updated_at = chrono::Utc::now().timestamp();

            if current_size >= info.expected_size {
                info.state = TransferState::PendingEncryption;
            }
        }
        Ok(())
    }

    pub async fn complete_transfer(&self, path: &str, crc32: u32) -> Result<(), ServiceAppError> {
        let mut transfers = self.transfers.write().await;
        if let Some(info) = transfers.get_mut(path) {
            info.state = TransferState::PendingEncryption;
            info.crc32 = Some(crc32);
            info.updated_at = chrono::Utc::now().timestamp();
        }
        Ok(())
    }

    pub async fn mark_encrypted(&self, path: &str) -> Result<(), ServiceAppError> {
        let mut transfers = self.transfers.write().await;
        if let Some(info) = transfers.get_mut(path) {
            info.state = TransferState::Encrypted;
            info.updated_at = chrono::Utc::now().timestamp();
        }
        Ok(())
    }

    pub async fn mark_encryption_failed(&self, path: &str, error: &str) -> Result<(), ServiceAppError> {
        let mut transfers = self.transfers.write().await;
        if let Some(info) = transfers.get_mut(path) {
            info.state = TransferState::EncryptionFailed(error.to_string());
            info.updated_at = chrono::Utc::now().timestamp();
        }
        Ok(())
    }

    pub async fn can_encrypt(&self, path: &str) -> bool {
        let transfers = self.transfers.read().await;
        if let Some(info) = transfers.get(path) {
            matches!(info.state, TransferState::PendingEncryption)
        } else {
            true
        }
    }

    pub async fn is_transferring(&self, path: &str) -> bool {
        let transfers = self.transfers.read().await;
        if let Some(info) = transfers.get(path) {
            matches!(info.state, TransferState::Transferring)
        } else {
            false
        }
    }

    pub async fn get_transfer_info(&self, path: &str) -> Option<TransferInfo> {
        let transfers = self.transfers.read().await;
        transfers.get(path).cloned()
    }

    pub async fn get_active_transfers(&self) -> Vec<TransferInfo> {
        let transfers = self.transfers.read().await;
        transfers
            .values()
            .filter(|info| matches!(info.state, TransferState::Transferring))
            .cloned()
            .collect()
    }

    pub async fn cleanup_completed(&self, max_age_seconds: i64) {
        let now = chrono::Utc::now().timestamp();
        let mut transfers = self.transfers.write().await;
        transfers.retain(|_, info| {
            if matches!(info.state, TransferState::Encrypted) {
                now - info.updated_at < max_age_seconds
            } else {
                true
            }
        });
    }

    pub async fn remove_transfer(&self, path: &str) {
        let mut transfers = self.transfers.write().await;
        transfers.remove(path);
    }
}

impl Default for TransferManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============ 辅助函数 (使用 rockzero-crypto 的实现) ============

pub fn blake3_hash_bytes(data: &[u8]) -> [u8; 32] {
    let hash = blake3::hash(data);
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

pub fn blake3_keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let hash = blake3::keyed_hash(key, data);
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}


// ============ 密钥派生器 (Service 特有) ============

pub struct KeyDeriver {
    // 不使用 SAE，直接使用 BLAKE3
}

impl KeyDeriver {
    pub fn new() -> Self {
        Self {}
    }

    pub fn derive_key(&self, password: &str, context: &str) -> [u8; 32] {
        // 使用 BLAKE3 派生密钥
        blake3_derive_key!(context, password.as_bytes())
    }

    pub fn derive_keys(&self, password: &str, contexts: &[&str]) -> Vec<[u8; 32]> {
        contexts
            .iter()
            .map(|ctx| self.derive_key(password, ctx))
            .collect()
    }

    pub fn derive_db_encryption_key(&self, password: &str) -> [u8; 32] {
        self.derive_key(password, "database-encryption")
    }

    pub fn derive_file_encryption_key(&self, password: &str) -> [u8; 32] {
        self.derive_key(password, "file-encryption")
    }

    pub fn derive_session_key(&self, password: &str, session_id: &str) -> [u8; 32] {
        let context = format!("session-{}", session_id);
        self.derive_key(password, &context)
    }
}

impl Default for KeyDeriver {
    fn default() -> Self {
        Self::new()
    }
}

// ============ 安全文件加密器 (Service 特有) ============

pub struct SecureFileEncryptor {
    key_deriver: KeyDeriver,
    transfer_manager: Arc<TransferManager>,
}

impl SecureFileEncryptor {
    pub fn new(transfer_manager: Arc<TransferManager>) -> Self {
        Self {
            key_deriver: KeyDeriver::new(),
            transfer_manager,
        }
    }

    pub async fn encrypt_file(
        &self,
        path: &str,
        data: &[u8],
        password: &str,
    ) -> Result<EncryptedFileData, ServiceAppError> {
        if self.transfer_manager.is_transferring(path).await {
            return Err(ServiceAppError::BadRequest(
                "Cannot encrypt file while transfer is in progress".to_string(),
            ));
        }

        let key = self.key_deriver.derive_file_encryption_key(password);
        let ctx = CryptoContext::from_key(&key)?;

        let crc32 = crc32_checksum(data);
        let encrypted = ctx.encrypt(data)?;
        self.transfer_manager.mark_encrypted(path).await?;

        Ok(EncryptedFileData {
            encrypted_data: encrypted,
            original_crc32: crc32,
            original_size: data.len() as u64,
        })
    }

    pub fn decrypt_file(
        &self,
        encrypted: &EncryptedFileData,
        password: &str,
    ) -> Result<Vec<u8>, ServiceAppError> {
        let key = self.key_deriver.derive_file_encryption_key(password);
        let ctx = CryptoContext::from_key(&key)?;
        let decrypted = ctx.decrypt(&encrypted.encrypted_data)?;
        let crc32 = crc32_checksum(&decrypted);
        if crc32 != encrypted.original_crc32 {
            return Err(ServiceAppError::CryptoError(
                "Data integrity check failed".to_string(),
            ));
        }

        Ok(decrypted)
    }

    pub async fn can_safely_encrypt(&self, path: &str) -> bool {
        self.transfer_manager.can_encrypt(path).await
    }
}

// ============ 加密文件数据 (Service 特有) ============

#[derive(Debug, Clone)]
pub struct EncryptedFileData {
    pub encrypted_data: EncryptedData,
    pub original_crc32: u32,
    pub original_size: u64,
}

// ============ WPA3-SAE 简化实现 (Service 特有) ============

pub struct Wpa3Sae {
    state_hash: [u8; 32],
}

impl Wpa3Sae {
    pub fn new() -> Self {
        let mut seed = [0u8; 32];
        let _ = getrandom::getrandom(&mut seed);
        let state_hash = blake3_derive_key!("WPA3-SAE-State-Init-v1", &seed);
        Self { state_hash }
    }

    pub fn with_seed(seed: &[u8]) -> Self {
        let state_hash = blake3_derive_key!("WPA3-SAE-State-Init-v1", seed);
        Self { state_hash }
    }

    pub fn derive_pmk(&self, password: &str, ssid: &str) -> [u8; 32] {
        blake3_derive_key!(
            "WPA3-SAE-PMK",
            &self.state_hash,
            password.as_bytes(),
            ssid.as_bytes()
        )
    }

    pub fn derive_session_key(&self, pmk: &[u8; 32], context: &[u8]) -> [u8; 32] {
        blake3_derive_key!(
            "WPA3-SAE-SESSION",
            &self.state_hash,
            pmk,
            context
        )
    }

    pub fn derive_db_key(&self, master_password: &str, db_identifier: &str) -> [u8; 32] {
        let pmk = self.derive_pmk(master_password, db_identifier);
        self.derive_session_key(&pmk, b"DATABASE-ENCRYPTION-KEY")
    }

    pub fn derive_file_key(&self, master_password: &str, file_identifier: &str) -> [u8; 32] {
        let pmk = self.derive_pmk(master_password, file_identifier);
        self.derive_session_key(&pmk, b"FILE-ENCRYPTION-KEY")
    }

    pub fn derive_auth_key(&self, master_password: &str, context: &str) -> [u8; 32] {
        let pmk = self.derive_pmk(master_password, context);
        self.derive_session_key(&pmk, b"AUTHENTICATION-KEY")
    }
}

impl Default for Wpa3Sae {
    fn default() -> Self {
        Self::new()
    }
}
