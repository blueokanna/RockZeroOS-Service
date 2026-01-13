use crate::error::AppError;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;

// ============ BLAKE3 哈希宏 ============

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

// ============ 加密上下文 ============

pub struct CryptoContext {
    cipher: Aes256Gcm,
    key_id: String,
}

impl CryptoContext {
    pub fn new(master_key: &str) -> Result<Self, AppError> {
        let key = blake3_derive_key!("RockZero-CryptoContext-v1", master_key.as_bytes());

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| AppError::CryptoError("Failed to create cipher".to_string()))?;

        let key_hash = blake3_hash!(&key);
        let key_id = hex::encode(&key_hash.as_bytes()[..8]);

        Ok(Self { cipher, key_id })
    }

    pub fn from_key(key: &[u8; 32]) -> Result<Self, AppError> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| AppError::CryptoError("Failed to create cipher".to_string()))?;

        let key_hash = blake3_hash!(key);
        let key_id = hex::encode(&key_hash.as_bytes()[..8]);

        Ok(Self { cipher, key_id })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData, AppError> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|_| AppError::CryptoError("Failed to generate nonce".to_string()))?;

        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| AppError::CryptoError("Encryption failed".to_string()))?;

        Ok(EncryptedData {
            ciphertext,
            nonce: nonce_bytes,
            key_id: self.key_id.clone(),
        })
    }

    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>, AppError> {
        if encrypted.key_id != self.key_id {
            return Err(AppError::CryptoError("Key mismatch".to_string()));
        }

        let nonce = Nonce::from_slice(&encrypted.nonce);

        let plaintext = self
            .cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|_| AppError::CryptoError("Decryption failed".to_string()))?;

        Ok(plaintext)
    }

    pub fn encrypt_string(&self, plaintext: &str) -> Result<String, AppError> {
        let encrypted = self.encrypt(plaintext.as_bytes())?;
        Ok(encrypted.to_base64())
    }

    pub fn decrypt_string(&self, encrypted_base64: &str) -> Result<String, AppError> {
        let encrypted = EncryptedData::from_base64(encrypted_base64)?;
        let plaintext = self.decrypt(&encrypted)?;
        String::from_utf8(plaintext).map_err(|_| AppError::CryptoError("Invalid UTF-8".to_string()))
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

// ============ 加密数据结构 ============

#[derive(Debug, Clone)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; NONCE_SIZE],
    pub key_id: String,
}

impl EncryptedData {
    /// 序列化为 Base64 字符串
    pub fn to_base64(&self) -> String {
        let mut bytes = Vec::new();

        // 版本号 (1 byte)
        bytes.push(1);

        // 密钥 ID 长度 (1 byte) + 密钥 ID
        bytes.push(self.key_id.len() as u8);
        bytes.extend_from_slice(self.key_id.as_bytes());

        // Nonce (12 bytes)
        bytes.extend_from_slice(&self.nonce);

        // 密文
        bytes.extend_from_slice(&self.ciphertext);

        BASE64.encode(&bytes)
    }

    /// 从 Base64 字符串反序列化
    pub fn from_base64(encoded: &str) -> Result<Self, AppError> {
        let bytes = BASE64
            .decode(encoded)
            .map_err(|_| AppError::CryptoError("Invalid Base64".to_string()))?;

        if bytes.len() < 14 {
            return Err(AppError::CryptoError("Invalid encrypted data".to_string()));
        }

        let mut offset = 0;

        // 版本号
        let version = bytes[offset];
        offset += 1;

        if version != 1 {
            return Err(AppError::CryptoError("Unsupported version".to_string()));
        }

        // 密钥 ID
        let key_id_len = bytes[offset] as usize;
        offset += 1;

        if bytes.len() < offset + key_id_len + NONCE_SIZE {
            return Err(AppError::CryptoError("Invalid encrypted data".to_string()));
        }

        let key_id = String::from_utf8(bytes[offset..offset + key_id_len].to_vec())
            .map_err(|_| AppError::CryptoError("Invalid key ID".to_string()))?;
        offset += key_id_len;

        // Nonce
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[offset..offset + NONCE_SIZE]);
        offset += NONCE_SIZE;

        // 密文
        let ciphertext = bytes[offset..].to_vec();

        Ok(Self {
            ciphertext,
            nonce,
            key_id,
        })
    }
}

// ============ WPA3-SAE 密钥派生 ============

/// WPA3-SAE 迭代次数（安全性与性能平衡）
const SAE_ITERATIONS: u32 = 4096;

/// Dragonfly 算法的 hunting-and-pecking 最大尝试次数
const DRAGONFLY_K: u8 = 40;

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

    fn hunting_and_pecking(&self, password: &[u8], identifier: &[u8]) -> [u8; 32] {
        let mut result = [0u8; 32];
        let mut found = false;

        for counter in 1..=DRAGONFLY_K {
            let hash = blake3_domain_hash!(
                "WPA3-SAE-HuntingPecking-v1",
                &self.state_hash,
                identifier,
                password,
                &[counter]
            );
            let is_valid = hash.as_bytes()[0] < 0x80;

            if !found && (counter == DRAGONFLY_K || is_valid) {
                result.copy_from_slice(hash.as_bytes());
                found = true;
            }
        }

        result
    }

    pub fn derive_pmk(&self, password: &str, ssid: &str) -> [u8; 32] {
        let password_element = self.hunting_and_pecking(password.as_bytes(), ssid.as_bytes());
        let mut pmk = password_element;
        for iteration in 0..SAE_ITERATIONS {
            let hash = blake3_domain_hash!(
                "WPA3-SAE-PMK-Derivation-v1",
                &pmk,
                &iteration.to_le_bytes(),
                ssid.as_bytes()
            );
            pmk.copy_from_slice(hash.as_bytes());
        }

        pmk
    }

    pub fn derive_session_key(&self, pmk: &[u8; 32], context: &[u8]) -> [u8; 32] {
        blake3_derive_key!("WPA3-SAE-SessionKey-v1", pmk, context, &self.state_hash)
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

// ============ 密钥派生器 ============
pub struct KeyDeriver {
    sae: Wpa3Sae,
}

impl KeyDeriver {
    pub fn new() -> Self {
        Self {
            sae: Wpa3Sae::new(),
        }
    }

    pub fn with_seed(seed: &[u8]) -> Self {
        Self {
            sae: Wpa3Sae::with_seed(seed),
        }
    }

    pub fn derive_key(&self, password: &str, context: &str) -> [u8; 32] {
        self.sae.derive_db_key(password, context)
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

// ============ 文件传输状态管理 ============

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

    pub async fn start_transfer(&self, path: &str, expected_size: u64) -> Result<(), AppError> {
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

    pub async fn update_progress(&self, path: &str, current_size: u64) -> Result<(), AppError> {
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

    pub async fn complete_transfer(&self, path: &str, crc32: u32) -> Result<(), AppError> {
        let mut transfers = self.transfers.write().await;
        if let Some(info) = transfers.get_mut(path) {
            info.state = TransferState::PendingEncryption;
            info.crc32 = Some(crc32);
            info.updated_at = chrono::Utc::now().timestamp();
        }
        Ok(())
    }

    pub async fn mark_encrypted(&self, path: &str) -> Result<(), AppError> {
        let mut transfers = self.transfers.write().await;
        if let Some(info) = transfers.get_mut(path) {
            info.state = TransferState::Encrypted;
            info.updated_at = chrono::Utc::now().timestamp();
        }
        Ok(())
    }

    pub async fn mark_encryption_failed(&self, path: &str, error: &str) -> Result<(), AppError> {
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

// ============ 安全文件加密器 ============
pub struct SecureFileEncryptor {
    key_deriver: KeyDeriver,
    transfer_manager: Arc<TransferManager>,
}

impl SecureFileEncryptor {
    /// 创建新的文件加密器
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
    ) -> Result<EncryptedFileData, AppError> {
        if self.transfer_manager.is_transferring(path).await {
            return Err(AppError::BadRequest(
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
            file_path: path.to_string(),
        })
    }

    pub fn decrypt_file(
        &self,
        encrypted: &EncryptedFileData,
        password: &str,
    ) -> Result<Vec<u8>, AppError> {
        let key = self.key_deriver.derive_file_encryption_key(password);
        let ctx = CryptoContext::from_key(&key)?;
        let decrypted = ctx.decrypt(&encrypted.encrypted_data)?;
        let crc32 = crc32_checksum(&decrypted);
        if crc32 != encrypted.original_crc32 {
            return Err(AppError::CryptoError(
                "Data integrity check failed".to_string(),
            ));
        }

        Ok(decrypted)
    }

    pub async fn can_safely_encrypt(&self, path: &str) -> bool {
        self.transfer_manager.can_encrypt(path).await
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedFileData {
    pub encrypted_data: EncryptedData,
    pub original_crc32: u32,
    pub original_size: u64,
    pub file_path: String,
}

impl EncryptedFileData {
    /// 序列化为字节
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // 版本 (1 byte)
        bytes.push(1);

        // 原始 CRC32 (4 bytes)
        bytes.extend_from_slice(&self.original_crc32.to_le_bytes());

        // 原始大小 (8 bytes)
        bytes.extend_from_slice(&self.original_size.to_le_bytes());

        // 文件路径长度 (2 bytes) + 路径
        let path_bytes = self.file_path.as_bytes();
        bytes.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
        bytes.extend_from_slice(path_bytes);

        // 加密数据（Base64 编码）
        let encrypted_base64 = self.encrypted_data.to_base64();
        let encrypted_bytes = encrypted_base64.as_bytes();
        bytes.extend_from_slice(&(encrypted_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(encrypted_bytes);

        bytes
    }

    /// 从字节反序列化
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AppError> {
        if bytes.len() < 16 {
            return Err(AppError::CryptoError(
                "Invalid encrypted file data".to_string(),
            ));
        }

        let mut offset = 0;

        // 版本
        let version = bytes[offset];
        offset += 1;

        if version != 1 {
            return Err(AppError::CryptoError("Unsupported version".to_string()));
        }

        // 原始 CRC32
        let original_crc32 = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;

        // 原始大小
        let original_size = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        // 文件路径
        let path_len = u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;

        if bytes.len() < offset + path_len {
            return Err(AppError::CryptoError(
                "Invalid encrypted file data".to_string(),
            ));
        }

        let file_path = String::from_utf8(bytes[offset..offset + path_len].to_vec())
            .map_err(|_| AppError::CryptoError("Invalid file path".to_string()))?;
        offset += path_len;

        // 加密数据
        if bytes.len() < offset + 4 {
            return Err(AppError::CryptoError(
                "Invalid encrypted file data".to_string(),
            ));
        }

        let encrypted_len =
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        if bytes.len() < offset + encrypted_len {
            return Err(AppError::CryptoError(
                "Invalid encrypted file data".to_string(),
            ));
        }

        let encrypted_base64 = String::from_utf8(bytes[offset..offset + encrypted_len].to_vec())
            .map_err(|_| AppError::CryptoError("Invalid encrypted data".to_string()))?;

        let encrypted_data = EncryptedData::from_base64(&encrypted_base64)?;

        Ok(Self {
            encrypted_data,
            original_crc32,
            original_size,
            file_path,
        })
    }
}

// ============ 辅助函数 ============

pub fn secure_random_bytes(len: usize) -> Result<Vec<u8>, AppError> {
    let mut bytes = vec![0u8; len];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| AppError::CryptoError("Failed to generate random bytes".to_string()))?;
    Ok(bytes)
}

pub fn secure_random_base64(len: usize) -> Result<String, AppError> {
    let bytes = secure_random_bytes(len)?;
    Ok(BASE64.encode(&bytes))
}

pub fn secure_random_hex(len: usize) -> Result<String, AppError> {
    let bytes = secure_random_bytes(len)?;
    Ok(hex::encode(&bytes))
}

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

pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

const CRC32_POLYNOMIAL: u32 = 0xEDB88320;
pub fn crc32_checksum(data: &[u8]) -> u32 {
    let mut crc = 0xFFFFFFFF_u32;

    for byte in data {
        let index = ((crc ^ (*byte as u32)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[index];
    }

    !crc
}

pub fn crc32_verify(data: &[u8], expected: u32) -> bool {
    crc32_checksum(data) == expected
}

static CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ CRC32_POLYNOMIAL
            } else {
                crc >> 1
            };
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

pub fn secure_zero(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

pub fn secure_zero_key(key: &mut [u8; 32]) {
    secure_zero(key);
}

// ============ 测试 ============

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let ctx = CryptoContext::new("test-master-key").unwrap();
        let plaintext = b"Hello, World!";

        let encrypted = ctx.encrypt(plaintext).unwrap();
        let decrypted = ctx.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_string() {
        let ctx = CryptoContext::new("test-master-key").unwrap();
        let plaintext = "Hello, World!";

        let encrypted = ctx.encrypt_string(plaintext).unwrap();
        let decrypted = ctx.decrypt_string(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_crypto_context_from_key() {
        let key = [0x42u8; 32];
        let ctx = CryptoContext::from_key(&key).unwrap();

        let plaintext = b"Test data";
        let encrypted = ctx.encrypt(plaintext).unwrap();
        let decrypted = ctx.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_key_derivation() {
        let deriver = KeyDeriver::new();

        let key1 = deriver.derive_key("password", "context1");
        let key2 = deriver.derive_key("password", "context2");
        let _key3 = deriver.derive_key("password", "context1");

        // 相同输入应产生相同输出（使用相同种子）
        // 注意：由于 KeyDeriver::new() 使用随机种子，这里需要使用 with_seed
        let deriver_seeded = KeyDeriver::with_seed(b"test-seed");
        let key_a = deriver_seeded.derive_key("password", "context1");
        let key_b = deriver_seeded.derive_key("password", "context1");
        assert_eq!(key_a, key_b);

        // 不同上下文应产生不同密钥
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_key_deriver_methods() {
        let deriver = KeyDeriver::with_seed(b"test-seed");

        let db_key = deriver.derive_db_encryption_key("password");
        let file_key = deriver.derive_file_encryption_key("password");
        let session_key = deriver.derive_session_key("password", "session-123");

        // 不同用途的密钥应该不同
        assert_ne!(db_key, file_key);
        assert_ne!(db_key, session_key);
        assert_ne!(file_key, session_key);
    }

    #[test]
    fn test_derive_keys_batch() {
        let deriver = KeyDeriver::with_seed(b"test-seed");
        let contexts = ["ctx1", "ctx2", "ctx3"];

        let keys = deriver.derive_keys("password", &contexts);

        assert_eq!(keys.len(), 3);
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
    }

    #[test]
    fn test_wpa3_sae_deterministic() {
        let sae1 = Wpa3Sae::with_seed(b"test-seed");
        let sae2 = Wpa3Sae::with_seed(b"test-seed");

        let pmk1 = sae1.derive_pmk("password", "ssid");
        let pmk2 = sae2.derive_pmk("password", "ssid");

        assert_eq!(pmk1, pmk2);
    }

    #[test]
    fn test_wpa3_sae_different_inputs() {
        let sae = Wpa3Sae::with_seed(b"test-seed");

        let pmk1 = sae.derive_pmk("password1", "ssid");
        let pmk2 = sae.derive_pmk("password2", "ssid");
        let pmk3 = sae.derive_pmk("password1", "ssid2");

        assert_ne!(pmk1, pmk2);
        assert_ne!(pmk1, pmk3);
    }

    #[test]
    fn test_wpa3_sae_key_types() {
        let sae = Wpa3Sae::with_seed(b"test-seed");

        let db_key = sae.derive_db_key("password", "db-id");
        let file_key = sae.derive_file_key("password", "file-id");
        let auth_key = sae.derive_auth_key("password", "auth-ctx");

        assert_ne!(db_key, file_key);
        assert_ne!(db_key, auth_key);
        assert_ne!(file_key, auth_key);
    }

    #[test]
    fn test_constant_time_compare() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";

        assert!(constant_time_compare(a, b));
        assert!(!constant_time_compare(a, c));
    }

    #[test]
    fn test_constant_time_compare_different_lengths() {
        let a = b"hello";
        let b = b"hello world";

        assert!(!constant_time_compare(a, b));
    }

    #[test]
    fn test_blake3_macros() {
        let hash1 = blake3_hash!(b"test data");
        let hash2 = blake3_hash!(b"test ", b"data");

        // 连续数据应产生相同哈希
        assert_eq!(hash1, hash2);

        let key = blake3_derive_key!("test-context", b"password");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_blake3_domain_hash() {
        let hash1 = blake3_domain_hash!("domain1", b"data");
        let hash2 = blake3_domain_hash!("domain2", b"data");

        // 不同域应产生不同哈希
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_crc32() {
        let data = b"Hello, World!";
        let checksum = crc32_checksum(data);

        assert!(crc32_verify(data, checksum));
        assert!(!crc32_verify(data, checksum + 1));
    }

    #[test]
    fn test_crc32_known_value() {
        // 已知的 CRC32 测试向量
        let data = b"123456789";
        let expected = 0xCBF43926;

        assert_eq!(crc32_checksum(data), expected);
    }

    #[test]
    fn test_secure_random() {
        let bytes1 = secure_random_bytes(32).unwrap();
        let bytes2 = secure_random_bytes(32).unwrap();

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_secure_random_base64() {
        let b64 = secure_random_base64(32).unwrap();
        assert!(!b64.is_empty());

        // 验证是有效的 Base64
        assert!(BASE64.decode(&b64).is_ok());
    }

    #[test]
    fn test_secure_random_hex() {
        let hex_str = secure_random_hex(16).unwrap();
        assert_eq!(hex_str.len(), 32); // 16 bytes = 32 hex chars

        // 验证是有效的十六进制
        assert!(hex::decode(&hex_str).is_ok());
    }

    #[test]
    fn test_blake3_hash_bytes() {
        let data = b"test data";
        let hash = blake3_hash_bytes(data);

        assert_eq!(hash.len(), 32);

        // 相同数据应产生相同哈希
        let hash2 = blake3_hash_bytes(data);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_blake3_keyed_hash() {
        let key = [0x42u8; 32];
        let data = b"test data";

        let hash1 = blake3_keyed_hash(&key, data);
        let hash2 = blake3_keyed_hash(&key, data);

        assert_eq!(hash1, hash2);

        // 不同密钥应产生不同哈希
        let key2 = [0x43u8; 32];
        let hash3 = blake3_keyed_hash(&key2, data);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_secure_zero() {
        let mut data = [0x42u8; 32];
        secure_zero(&mut data);

        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_zero_key() {
        let mut key = [0x42u8; 32];
        secure_zero_key(&mut key);

        assert!(key.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_encrypted_data_serialization() {
        let ctx = CryptoContext::new("test-key").unwrap();
        let plaintext = b"Test data for serialization";

        let encrypted = ctx.encrypt(plaintext).unwrap();
        let base64 = encrypted.to_base64();
        let restored = EncryptedData::from_base64(&base64).unwrap();

        assert_eq!(encrypted.ciphertext, restored.ciphertext);
        assert_eq!(encrypted.nonce, restored.nonce);
        assert_eq!(encrypted.key_id, restored.key_id);
    }

    #[tokio::test]
    async fn test_transfer_manager() {
        let manager = TransferManager::new();

        // 开始传输
        manager
            .start_transfer("/test/file.txt", 1000)
            .await
            .unwrap();

        // 检查状态
        assert!(manager.is_transferring("/test/file.txt").await);
        assert!(!manager.can_encrypt("/test/file.txt").await);

        // 更新进度
        manager
            .update_progress("/test/file.txt", 500)
            .await
            .unwrap();
        assert!(manager.is_transferring("/test/file.txt").await);

        // 完成传输
        manager
            .complete_transfer("/test/file.txt", 0x12345678)
            .await
            .unwrap();
        assert!(!manager.is_transferring("/test/file.txt").await);
        assert!(manager.can_encrypt("/test/file.txt").await);

        // 标记加密完成
        manager.mark_encrypted("/test/file.txt").await.unwrap();
        let info = manager.get_transfer_info("/test/file.txt").await.unwrap();
        assert_eq!(info.state, TransferState::Encrypted);
    }

    #[tokio::test]
    async fn test_transfer_manager_active_transfers() {
        let manager = TransferManager::new();

        manager.start_transfer("/file1.txt", 100).await.unwrap();
        manager.start_transfer("/file2.txt", 200).await.unwrap();
        manager.start_transfer("/file3.txt", 300).await.unwrap();

        // 完成一个传输
        manager.complete_transfer("/file2.txt", 0).await.unwrap();

        let active = manager.get_active_transfers().await;
        assert_eq!(active.len(), 2);
    }

    #[tokio::test]
    async fn test_secure_file_encryptor() {
        let transfer_manager = Arc::new(TransferManager::new());
        let encryptor = SecureFileEncryptor::new(transfer_manager.clone());

        let data = b"Test file content";
        let password = "test-password";
        let path = "/test/file.txt";

        // 加密
        let encrypted = encryptor.encrypt_file(path, data, password).await.unwrap();

        // 验证元数据
        assert_eq!(encrypted.original_size, data.len() as u64);
        assert_eq!(encrypted.file_path, path);

        // 解密
        let decrypted = encryptor.decrypt_file(&encrypted, password).unwrap();
        assert_eq!(data.to_vec(), decrypted);
    }

    #[tokio::test]
    async fn test_secure_file_encryptor_transfer_in_progress() {
        let transfer_manager = Arc::new(TransferManager::new());
        let encryptor = SecureFileEncryptor::new(transfer_manager.clone());

        let path = "/test/file.txt";

        // 开始传输
        transfer_manager.start_transfer(path, 1000).await.unwrap();

        // 尝试加密应该失败
        let result = encryptor.encrypt_file(path, b"data", "password").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_file_data_serialization() {
        let ctx = CryptoContext::new("test-key").unwrap();
        let encrypted_data = ctx.encrypt(b"test data").unwrap();

        let file_data = EncryptedFileData {
            encrypted_data,
            original_crc32: 0x12345678,
            original_size: 100,
            file_path: "/test/file.txt".to_string(),
        };

        let bytes = file_data.to_bytes();
        let restored = EncryptedFileData::from_bytes(&bytes).unwrap();

        assert_eq!(file_data.original_crc32, restored.original_crc32);
        assert_eq!(file_data.original_size, restored.original_size);
        assert_eq!(file_data.file_path, restored.file_path);
    }
}
