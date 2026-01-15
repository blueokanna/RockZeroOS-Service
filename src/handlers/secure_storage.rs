//! 安全存储处理器 - 加密数据存储 API
//!
//! 提供安全的数据存储功能：
//! - 零知识加密存储
//! - CRC32 完整性校验
//! - Reed-Solomon 自动修复
//! - 文件加密/解密
//! - 安全密钥派生

use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::auth::Claims;
use crate::crypto::{
    CryptoContext, EncryptedData, KeyDeriver, TransferManager, SecureFileEncryptor,
    Wpa3Sae, secure_random_bytes, secure_random_base64, secure_random_hex,
    blake3_hash_bytes, blake3_keyed_hash, crc32_checksum, crc32_verify,
    secure_zero, secure_zero_key, constant_time_compare,
};
use crate::error::AppError;
use crate::secure_db::SecureDatabase;

/// 安全存储管理器
pub struct SecureStorageManager {
    databases: RwLock<std::collections::HashMap<String, Arc<SecureDatabase>>>,
    base_path: PathBuf,
    transfer_manager: Arc<TransferManager>,
    file_encryptor: Arc<SecureFileEncryptor>,
}

impl SecureStorageManager {
    pub fn new(base_path: PathBuf) -> Self {
        let transfer_manager = Arc::new(TransferManager::new());
        let file_encryptor = Arc::new(SecureFileEncryptor::new(transfer_manager.clone()));
        
        Self {
            databases: RwLock::new(std::collections::HashMap::new()),
            base_path,
            transfer_manager,
            file_encryptor,
        }
    }

    /// 获取或创建用户的安全数据库
    pub async fn get_or_create_db(
        &self,
        user_id: &str,
        master_password: &str,
    ) -> Result<Arc<SecureDatabase>, AppError> {
        let mut dbs = self.databases.write().await;
        
        if let Some(db) = dbs.get(user_id) {
            return Ok(db.clone());
        }
        
        let db_path = self.base_path.join(format!("{}.securedb", user_id));
        let db = SecureDatabase::new(&db_path, master_password)?;
        db.load().await?;
        
        let db = Arc::new(db);
        dbs.insert(user_id.to_string(), db.clone());
        
        Ok(db)
    }

    /// 关闭用户的数据库连接
    pub async fn close_db(&self, user_id: &str) {
        let mut dbs = self.databases.write().await;
        dbs.remove(user_id);
    }

    /// 获取传输管理器
    pub fn transfer_manager(&self) -> Arc<TransferManager> {
        self.transfer_manager.clone()
    }

    /// 获取文件加密器
    pub fn file_encryptor(&self) -> Arc<SecureFileEncryptor> {
        self.file_encryptor.clone()
    }
}

// ============ 请求/响应结构 ============

#[derive(Debug, Deserialize)]
pub struct InitDatabaseRequest {
    pub master_password: String,
}

#[derive(Debug, Deserialize)]
pub struct StoreDataRequest {
    pub master_password: String,
    pub data: String, // Base64 编码的数据
}

#[derive(Debug, Serialize)]
pub struct StoreDataResponse {
    pub block_id: u64,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct RetrieveDataRequest {
    pub master_password: String,
    pub block_id: u64,
}

#[derive(Debug, Serialize)]
pub struct RetrieveDataResponse {
    pub data: String, // Base64 编码的数据
    pub block_id: u64,
}

#[derive(Debug, Deserialize)]
pub struct DeleteDataRequest {
    pub master_password: String,
    pub block_id: u64,
}

#[derive(Debug, Serialize)]
pub struct IntegrityCheckResponse {
    pub total_blocks: usize,
    pub corrupted_blocks: Vec<u64>,
    pub is_healthy: bool,
}

#[derive(Debug, Serialize)]
pub struct RepairResponse {
    pub repaired_count: usize,
    pub message: String,
}

// ============ API 处理器 ============

/// 初始化安全数据库
pub async fn init_secure_database(
    storage: web::Data<Arc<SecureStorageManager>>,
    claims: web::ReqData<Claims>,
    body: web::Json<InitDatabaseRequest>,
) -> Result<impl Responder, AppError> {
    let db = storage.get_or_create_db(&claims.sub, &body.master_password).await?;
    let stats = db.stats().await;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Secure database initialized",
        "stats": stats
    })))
}

/// 存储加密数据
pub async fn store_secure_data(
    storage: web::Data<Arc<SecureStorageManager>>,
    claims: web::ReqData<Claims>,
    body: web::Json<StoreDataRequest>,
) -> Result<impl Responder, AppError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    
    let db = storage.get_or_create_db(&claims.sub, &body.master_password).await?;
    
    let data = BASE64.decode(&body.data)
        .map_err(|_| AppError::BadRequest("Invalid Base64 data".to_string()))?;
    
    let block_id = db.store(&data).await?;
    
    Ok(HttpResponse::Created().json(StoreDataResponse {
        block_id,
        message: "Data stored securely with CRC32 and Reed-Solomon protection".to_string(),
    }))
}

/// 读取加密数据
pub async fn retrieve_secure_data(
    storage: web::Data<Arc<SecureStorageManager>>,
    claims: web::ReqData<Claims>,
    body: web::Json<RetrieveDataRequest>,
) -> Result<impl Responder, AppError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    
    let db = storage.get_or_create_db(&claims.sub, &body.master_password).await?;
    
    let data = db.retrieve(body.block_id).await?;
    
    Ok(HttpResponse::Ok().json(RetrieveDataResponse {
        data: BASE64.encode(&data),
        block_id: body.block_id,
    }))
}

/// 删除加密数据
pub async fn delete_secure_data(
    storage: web::Data<Arc<SecureStorageManager>>,
    claims: web::ReqData<Claims>,
    body: web::Json<DeleteDataRequest>,
) -> Result<impl Responder, AppError> {
    let db = storage.get_or_create_db(&claims.sub, &body.master_password).await?;
    
    let deleted = db.delete(body.block_id).await?;
    
    if deleted {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Data deleted successfully"
        })))
    } else {
        Err(AppError::NotFound("Block not found".to_string()))
    }
}

/// 检查数据完整性
pub async fn check_integrity(
    storage: web::Data<Arc<SecureStorageManager>>,
    claims: web::ReqData<Claims>,
    body: web::Json<InitDatabaseRequest>,
) -> Result<impl Responder, AppError> {
    let db = storage.get_or_create_db(&claims.sub, &body.master_password).await?;
    
    let corrupted = db.verify_integrity().await?;
    let stats = db.stats().await;
    
    Ok(HttpResponse::Ok().json(IntegrityCheckResponse {
        total_blocks: stats.total_blocks,
        corrupted_blocks: corrupted.clone(),
        is_healthy: corrupted.is_empty(),
    }))
}

/// 修复损坏的数据
pub async fn repair_data(
    storage: web::Data<Arc<SecureStorageManager>>,
    claims: web::ReqData<Claims>,
    body: web::Json<InitDatabaseRequest>,
) -> Result<impl Responder, AppError> {
    let db = storage.get_or_create_db(&claims.sub, &body.master_password).await?;
    
    let repaired = db.repair_all().await?;
    
    Ok(HttpResponse::Ok().json(RepairResponse {
        repaired_count: repaired,
        message: format!("Successfully repaired {} blocks using Reed-Solomon recovery", repaired),
    }))
}

/// 获取数据库统计信息
pub async fn get_database_stats(
    storage: web::Data<Arc<SecureStorageManager>>,
    claims: web::ReqData<Claims>,
    body: web::Json<InitDatabaseRequest>,
) -> Result<impl Responder, AppError> {
    let db = storage.get_or_create_db(&claims.sub, &body.master_password).await?;
    
    let stats = db.stats().await;
    
    Ok(HttpResponse::Ok().json(stats))
}

/// 关闭数据库连接
pub async fn close_database(
    storage: web::Data<Arc<SecureStorageManager>>,
    claims: web::ReqData<Claims>,
) -> Result<impl Responder, AppError> {
    storage.close_db(&claims.sub).await;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Database connection closed"
    })))
}


// ============ 加密工具 API ============

/// 加密数据请求
#[derive(Debug, Deserialize)]
pub struct EncryptDataRequest {
    pub password: String,
    pub data: String, // Base64 编码
}

/// 加密数据响应
#[derive(Debug, Serialize)]
pub struct EncryptDataResponse {
    pub encrypted: String, // Base64 编码
    pub key_id: String,
}

/// 解密数据请求
#[derive(Debug, Deserialize)]
pub struct DecryptDataRequest {
    pub password: String,
    pub encrypted: String, // Base64 编码
}

/// 解密数据响应
#[derive(Debug, Serialize)]
pub struct DecryptDataResponse {
    pub data: String, // Base64 编码
}

/// 使用密码加密数据
pub async fn encrypt_data(
    _claims: web::ReqData<Claims>,
    body: web::Json<EncryptDataRequest>,
) -> Result<impl Responder, AppError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    
    let ctx = CryptoContext::new(&body.password)?;
    
    let data = BASE64.decode(&body.data)
        .map_err(|_| AppError::BadRequest("Invalid Base64 data".to_string()))?;
    
    let encrypted = ctx.encrypt(&data)?;
    
    Ok(HttpResponse::Ok().json(EncryptDataResponse {
        encrypted: encrypted.to_base64(),
        key_id: ctx.key_id().to_string(),
    }))
}

/// 使用密码解密数据
pub async fn decrypt_data(
    _claims: web::ReqData<Claims>,
    body: web::Json<DecryptDataRequest>,
) -> Result<impl Responder, AppError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    
    let ctx = CryptoContext::new(&body.password)?;
    let encrypted = EncryptedData::from_base64(&body.encrypted)?;
    let decrypted = ctx.decrypt(&encrypted)?;
    
    Ok(HttpResponse::Ok().json(DecryptDataResponse {
        data: BASE64.encode(&decrypted),
    }))
}

/// 密钥派生请求
#[derive(Debug, Deserialize)]
pub struct DeriveKeyRequest {
    pub password: String,
    pub context: String,
    #[serde(default)]
    pub use_wpa3_sae: bool,
}

/// 密钥派生响应
#[derive(Debug, Serialize)]
pub struct DeriveKeyResponse {
    pub key: String, // Hex 编码
    pub method: String,
}

/// 派生加密密钥
pub async fn derive_key(
    _claims: web::ReqData<Claims>,
    body: web::Json<DeriveKeyRequest>,
) -> Result<impl Responder, AppError> {
    let (key, method) = if body.use_wpa3_sae {
        let sae = Wpa3Sae::new();
        let key = sae.derive_db_key(&body.password, &body.context);
        (key, "WPA3-SAE")
    } else {
        let deriver = KeyDeriver::new();
        let key = deriver.derive_key(&body.password, &body.context);
        (key, "BLAKE3-KDF")
    };
    
    Ok(HttpResponse::Ok().json(DeriveKeyResponse {
        key: hex::encode(key),
        method: method.to_string(),
    }))
}

/// 批量密钥派生请求
#[derive(Debug, Deserialize)]
pub struct DeriveBatchKeysRequest {
    pub password: String,
    pub contexts: Vec<String>,
}

/// 批量密钥派生响应
#[derive(Debug, Serialize)]
pub struct DeriveBatchKeysResponse {
    pub keys: Vec<DerivedKey>,
}

#[derive(Debug, Serialize)]
pub struct DerivedKey {
    pub context: String,
    pub key: String, // Hex 编码
}

/// 批量派生密钥
pub async fn derive_batch_keys(
    _claims: web::ReqData<Claims>,
    body: web::Json<DeriveBatchKeysRequest>,
) -> Result<impl Responder, AppError> {
    let deriver = KeyDeriver::new();
    let contexts: Vec<&str> = body.contexts.iter().map(|s| s.as_str()).collect();
    let keys = deriver.derive_keys(&body.password, &contexts);
    
    let derived_keys: Vec<DerivedKey> = body.contexts.iter()
        .zip(keys.iter())
        .map(|(ctx, key)| DerivedKey {
            context: ctx.clone(),
            key: hex::encode(key),
        })
        .collect();
    
    Ok(HttpResponse::Ok().json(DeriveBatchKeysResponse {
        keys: derived_keys,
    }))
}

/// 生成随机数据请求
#[derive(Debug, Deserialize)]
pub struct GenerateRandomRequest {
    pub length: usize,
    #[serde(default = "default_format")]
    pub format: String, // "hex", "base64", "bytes"
}

fn default_format() -> String {
    "hex".to_string()
}

/// 生成随机数据响应
#[derive(Debug, Serialize)]
pub struct GenerateRandomResponse {
    pub data: String,
    pub format: String,
    pub length: usize,
}

/// 生成安全随机数据
pub async fn generate_random(
    _claims: web::ReqData<Claims>,
    body: web::Json<GenerateRandomRequest>,
) -> Result<impl Responder, AppError> {
    if body.length > 1024 * 1024 {
        return Err(AppError::BadRequest("Length too large (max 1MB)".to_string()));
    }
    
    let data = match body.format.as_str() {
        "hex" => secure_random_hex(body.length)?,
        "base64" => secure_random_base64(body.length)?,
        "bytes" => {
            use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
            let bytes = secure_random_bytes(body.length)?;
            BASE64.encode(&bytes)
        }
        _ => return Err(AppError::BadRequest("Invalid format".to_string())),
    };
    
    Ok(HttpResponse::Ok().json(GenerateRandomResponse {
        data,
        format: body.format.clone(),
        length: body.length,
    }))
}

/// 哈希数据请求
#[derive(Debug, Deserialize)]
pub struct HashDataRequest {
    pub data: String, // Base64 编码
    #[serde(default)]
    pub key: Option<String>, // Hex 编码的密钥（可选，用于 keyed hash）
}

/// 哈希数据响应
#[derive(Debug, Serialize)]
pub struct HashDataResponse {
    pub hash: String, // Hex 编码
    pub algorithm: String,
}

/// 计算 BLAKE3 哈希
pub async fn hash_data(
    _claims: web::ReqData<Claims>,
    body: web::Json<HashDataRequest>,
) -> Result<impl Responder, AppError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    
    let data = BASE64.decode(&body.data)
        .map_err(|_| AppError::BadRequest("Invalid Base64 data".to_string()))?;
    
    let (hash, algorithm) = if let Some(key_hex) = &body.key {
        let key_bytes = hex::decode(key_hex)
            .map_err(|_| AppError::BadRequest("Invalid hex key".to_string()))?;
        
        if key_bytes.len() != 32 {
            return Err(AppError::BadRequest("Key must be 32 bytes".to_string()));
        }
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        let hash = blake3_keyed_hash(&key, &data);
        (hash, "BLAKE3-Keyed")
    } else {
        let hash = blake3_hash_bytes(&data);
        (hash, "BLAKE3")
    };
    
    Ok(HttpResponse::Ok().json(HashDataResponse {
        hash: hex::encode(hash),
        algorithm: algorithm.to_string(),
    }))
}

/// CRC32 校验请求
#[derive(Debug, Deserialize)]
pub struct Crc32Request {
    pub data: String, // Base64 编码
    #[serde(default)]
    pub expected: Option<u32>,
}

/// CRC32 校验响应
#[derive(Debug, Serialize)]
pub struct Crc32Response {
    pub checksum: u32,
    pub checksum_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid: Option<bool>,
}

/// 计算或验证 CRC32
pub async fn crc32_check(
    _claims: web::ReqData<Claims>,
    body: web::Json<Crc32Request>,
) -> Result<impl Responder, AppError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    
    let data = BASE64.decode(&body.data)
        .map_err(|_| AppError::BadRequest("Invalid Base64 data".to_string()))?;
    
    let checksum = crc32_checksum(&data);
    let valid = body.expected.map(|expected| crc32_verify(&data, expected));
    
    Ok(HttpResponse::Ok().json(Crc32Response {
        checksum,
        checksum_hex: format!("{:08X}", checksum),
        valid,
    }))
}

/// 常量时间比较请求
#[derive(Debug, Deserialize)]
pub struct ConstantTimeCompareRequest {
    pub a: String, // Hex 编码
    pub b: String, // Hex 编码
}

/// 常量时间比较响应
#[derive(Debug, Serialize)]
pub struct ConstantTimeCompareResponse {
    pub equal: bool,
}

/// 常量时间比较（防止时序攻击）
pub async fn constant_time_compare_endpoint(
    _claims: web::ReqData<Claims>,
    body: web::Json<ConstantTimeCompareRequest>,
) -> Result<impl Responder, AppError> {
    let a = hex::decode(&body.a)
        .map_err(|_| AppError::BadRequest("Invalid hex data for 'a'".to_string()))?;
    let b = hex::decode(&body.b)
        .map_err(|_| AppError::BadRequest("Invalid hex data for 'b'".to_string()))?;
    
    let equal = constant_time_compare(&a, &b);
    
    Ok(HttpResponse::Ok().json(ConstantTimeCompareResponse { equal }))
}

/// 文件传输状态请求
#[derive(Debug, Deserialize)]
pub struct TransferStatusRequest {
    pub path: String,
}

/// 文件传输状态响应
#[derive(Debug, Serialize)]
pub struct TransferStatusResponse {
    pub path: String,
    pub is_transferring: bool,
    pub can_encrypt: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_size: Option<u64>,
}

/// 获取文件传输状态
pub async fn get_transfer_status(
    storage: web::Data<Arc<SecureStorageManager>>,
    _claims: web::ReqData<Claims>,
    body: web::Json<TransferStatusRequest>,
) -> Result<impl Responder, AppError> {
    let tm = storage.transfer_manager();
    let is_transferring = tm.is_transferring(&body.path).await;
    let can_encrypt = tm.can_encrypt(&body.path).await;
    
    let (current_size, expected_size) = if let Some(info) = tm.get_transfer_info(&body.path).await {
        (Some(info.current_size), Some(info.expected_size))
    } else {
        (None, None)
    };
    
    Ok(HttpResponse::Ok().json(TransferStatusResponse {
        path: body.path.clone(),
        is_transferring,
        can_encrypt,
        current_size,
        expected_size,
    }))
}

/// 开始文件传输请求
#[derive(Debug, Deserialize)]
pub struct StartTransferRequest {
    pub path: String,
    pub expected_size: u64,
}

/// 开始文件传输
pub async fn start_transfer(
    storage: web::Data<Arc<SecureStorageManager>>,
    _claims: web::ReqData<Claims>,
    body: web::Json<StartTransferRequest>,
) -> Result<impl Responder, AppError> {
    let tm = storage.transfer_manager();
    tm.start_transfer(&body.path, body.expected_size).await?;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Transfer started",
        "path": body.path
    })))
}

/// 完成文件传输请求
#[derive(Debug, Deserialize)]
pub struct CompleteTransferRequest {
    pub path: String,
    pub crc32: u32,
}

/// 完成文件传输
pub async fn complete_transfer(
    storage: web::Data<Arc<SecureStorageManager>>,
    _claims: web::ReqData<Claims>,
    body: web::Json<CompleteTransferRequest>,
) -> Result<impl Responder, AppError> {
    let tm = storage.transfer_manager();
    tm.complete_transfer(&body.path, body.crc32).await?;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Transfer completed, file ready for encryption",
        "path": body.path
    })))
}

/// 加密文件请求
#[derive(Debug, Deserialize)]
pub struct EncryptFileRequest {
    pub path: String,
    pub password: String,
    pub data: String, // Base64 编码
}

/// 加密文件响应
#[derive(Debug, Serialize)]
pub struct EncryptFileResponse {
    pub encrypted: String, // Base64 编码
    pub original_crc32: u32,
    pub original_size: u64,
}

/// 加密文件数据
pub async fn encrypt_file(
    storage: web::Data<Arc<SecureStorageManager>>,
    _claims: web::ReqData<Claims>,
    body: web::Json<EncryptFileRequest>,
) -> Result<impl Responder, AppError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    
    let encryptor = storage.file_encryptor();
    
    let data = BASE64.decode(&body.data)
        .map_err(|_| AppError::BadRequest("Invalid Base64 data".to_string()))?;
    
    let encrypted = encryptor.encrypt_file(&body.path, &data, &body.password).await?;
    
    Ok(HttpResponse::Ok().json(EncryptFileResponse {
        encrypted: BASE64.encode(encrypted.encrypted_data.to_base64().as_bytes()),
        original_crc32: encrypted.original_crc32,
        original_size: encrypted.original_size,
    }))
}

/// 获取活跃传输列表
pub async fn list_active_transfers(
    storage: web::Data<Arc<SecureStorageManager>>,
    _claims: web::ReqData<Claims>,
) -> Result<impl Responder, AppError> {
    let tm = storage.transfer_manager();
    let transfers = tm.get_active_transfers().await;
    
    let response: Vec<serde_json::Value> = transfers.iter()
        .map(|t| serde_json::json!({
            "path": t.path,
            "expected_size": t.expected_size,
            "current_size": t.current_size,
            "started_at": t.started_at,
            "updated_at": t.updated_at
        }))
        .collect();
    
    Ok(HttpResponse::Ok().json(response))
}

/// 清理已完成的传输
pub async fn cleanup_transfers(
    storage: web::Data<Arc<SecureStorageManager>>,
    _claims: web::ReqData<Claims>,
) -> Result<impl Responder, AppError> {
    let tm = storage.transfer_manager();
    tm.cleanup_completed(3600).await; // 清理 1 小时前完成的传输
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Completed transfers cleaned up"
    })))
}

/// 安全擦除请求
#[derive(Debug, Deserialize)]
pub struct SecureEraseRequest {
    pub data: String, // Hex 编码
}

/// 安全擦除响应
#[derive(Debug, Serialize)]
pub struct SecureEraseResponse {
    pub success: bool,
    pub message: String,
}

/// 安全擦除数据（演示用）
pub async fn secure_erase_demo(
    _claims: web::ReqData<Claims>,
    body: web::Json<SecureEraseRequest>,
) -> Result<impl Responder, AppError> {
    let mut data = hex::decode(&body.data)
        .map_err(|_| AppError::BadRequest("Invalid hex data".to_string()))?;
    
    // 安全擦除数据
    secure_zero(&mut data);
    
    // 如果是 32 字节，也可以作为密钥擦除
    if data.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&data);
        secure_zero_key(&mut key);
    }
    
    Ok(HttpResponse::Ok().json(SecureEraseResponse {
        success: true,
        message: "Data securely erased from memory".to_string(),
    }))
}


// ============ 字符串加密 API ============

/// 加密字符串请求
#[derive(Debug, Deserialize)]
pub struct EncryptStringRequest {
    pub password: String,
    pub plaintext: String,
}

/// 加密字符串响应
#[derive(Debug, Serialize)]
pub struct EncryptStringResponse {
    pub encrypted: String,
    pub key_id: String,
}

/// 加密字符串
pub async fn encrypt_string(
    _claims: web::ReqData<Claims>,
    body: web::Json<EncryptStringRequest>,
) -> Result<impl Responder, AppError> {
    let ctx = CryptoContext::new(&body.password)?;
    let encrypted = ctx.encrypt_string(&body.plaintext)?;
    
    Ok(HttpResponse::Ok().json(EncryptStringResponse {
        encrypted,
        key_id: ctx.key_id().to_string(),
    }))
}

/// 解密字符串请求
#[derive(Debug, Deserialize)]
pub struct DecryptStringRequest {
    pub password: String,
    pub encrypted: String,
}

/// 解密字符串响应
#[derive(Debug, Serialize)]
pub struct DecryptStringResponse {
    pub plaintext: String,
}

/// 解密字符串
pub async fn decrypt_string(
    _claims: web::ReqData<Claims>,
    body: web::Json<DecryptStringRequest>,
) -> Result<impl Responder, AppError> {
    let ctx = CryptoContext::new(&body.password)?;
    let plaintext = ctx.decrypt_string(&body.encrypted)?;
    
    Ok(HttpResponse::Ok().json(DecryptStringResponse {
        plaintext,
    }))
}

// ============ WPA3-SAE 高级 API ============

/// WPA3-SAE 密钥派生请求
#[derive(Debug, Deserialize)]
pub struct Wpa3SaeKeyRequest {
    pub password: String,
    pub identifier: String,
    #[serde(default = "default_key_type")]
    pub key_type: String, // "db", "file", "auth", "session"
}

fn default_key_type() -> String {
    "db".to_string()
}

/// WPA3-SAE 密钥派生响应
#[derive(Debug, Serialize)]
pub struct Wpa3SaeKeyResponse {
    pub key: String, // Hex 编码
    pub key_type: String,
    pub algorithm: String,
}

/// 使用 WPA3-SAE 派生特定类型的密钥
pub async fn derive_wpa3_sae_key(
    _claims: web::ReqData<Claims>,
    body: web::Json<Wpa3SaeKeyRequest>,
) -> Result<impl Responder, AppError> {
    let sae = Wpa3Sae::new();
    
    let key = match body.key_type.as_str() {
        "db" => sae.derive_db_key(&body.password, &body.identifier),
        "file" => sae.derive_file_key(&body.password, &body.identifier),
        "auth" => sae.derive_auth_key(&body.password, &body.identifier),
        "session" => {
            let pmk = sae.derive_pmk(&body.password, &body.identifier);
            sae.derive_session_key(&pmk, body.identifier.as_bytes())
        }
        _ => return Err(AppError::BadRequest("Invalid key_type".to_string())),
    };
    
    Ok(HttpResponse::Ok().json(Wpa3SaeKeyResponse {
        key: hex::encode(key),
        key_type: body.key_type.clone(),
        algorithm: "WPA3-SAE-Dragonfly".to_string(),
    }))
}

// ============ KeyDeriver 高级 API ============

/// KeyDeriver 特定密钥请求
#[derive(Debug, Deserialize)]
pub struct KeyDeriverRequest {
    pub password: String,
    #[serde(default = "default_deriver_key_type")]
    pub key_type: String, // "db", "file", "session"
    #[serde(default)]
    pub session_id: Option<String>,
}

fn default_deriver_key_type() -> String {
    "db".to_string()
}

/// KeyDeriver 特定密钥响应
#[derive(Debug, Serialize)]
pub struct KeyDeriverResponse {
    pub key: String, // Hex 编码
    pub key_type: String,
}

/// 使用 KeyDeriver 派生特定类型的密钥
pub async fn derive_specific_key(
    _claims: web::ReqData<Claims>,
    body: web::Json<KeyDeriverRequest>,
) -> Result<impl Responder, AppError> {
    let deriver = KeyDeriver::new();
    
    let key = match body.key_type.as_str() {
        "db" => deriver.derive_db_encryption_key(&body.password),
        "file" => deriver.derive_file_encryption_key(&body.password),
        "session" => {
            let session_id = body.session_id.as_ref()
                .ok_or_else(|| AppError::BadRequest("session_id required for session key".to_string()))?;
            deriver.derive_session_key(&body.password, session_id)
        }
        _ => return Err(AppError::BadRequest("Invalid key_type".to_string())),
    };
    
    Ok(HttpResponse::Ok().json(KeyDeriverResponse {
        key: hex::encode(key),
        key_type: body.key_type.clone(),
    }))
}

// ============ 文件解密 API ============

/// 解密文件请求
#[derive(Debug, Deserialize)]
pub struct DecryptFileRequest {
    pub password: String,
    pub encrypted: String, // Base64 编码的加密数据
    pub original_crc32: u32,
    pub original_size: u64,
    pub file_path: String,
}

/// 解密文件响应
#[derive(Debug, Serialize)]
pub struct DecryptFileResponse {
    pub data: String, // Base64 编码
    pub verified: bool,
}

/// 解密文件数据
pub async fn decrypt_file(
    storage: web::Data<Arc<SecureStorageManager>>,
    _claims: web::ReqData<Claims>,
    body: web::Json<DecryptFileRequest>,
) -> Result<impl Responder, AppError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use crate::crypto::EncryptedFileData;
    
    let encryptor = storage.file_encryptor();
    
    // 解码加密数据
    let encrypted_base64 = String::from_utf8(
        BASE64.decode(&body.encrypted)
            .map_err(|_| AppError::BadRequest("Invalid Base64 data".to_string()))?
    ).map_err(|_| AppError::BadRequest("Invalid encrypted data".to_string()))?;
    
    let encrypted_data = EncryptedData::from_base64(&encrypted_base64)?;
    
    let file_data = EncryptedFileData {
        encrypted_data,
        original_crc32: body.original_crc32,
        original_size: body.original_size,
        file_path: body.file_path.clone(),
    };
    
    let decrypted = encryptor.decrypt_file(&file_data, &body.password)?;
    
    Ok(HttpResponse::Ok().json(DecryptFileResponse {
        data: BASE64.encode(&decrypted),
        verified: true,
    }))
}

/// 检查文件是否可以安全加密
pub async fn can_safely_encrypt(
    storage: web::Data<Arc<SecureStorageManager>>,
    _claims: web::ReqData<Claims>,
    body: web::Json<TransferStatusRequest>,
) -> Result<impl Responder, AppError> {
    let encryptor = storage.file_encryptor();
    let can_encrypt = encryptor.can_safely_encrypt(&body.path).await;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "path": body.path,
        "can_safely_encrypt": can_encrypt
    })))
}

// ============ 传输管理高级 API ============

/// 更新传输进度请求
#[derive(Debug, Deserialize)]
pub struct UpdateProgressRequest {
    pub path: String,
    pub current_size: u64,
}

/// 更新传输进度
pub async fn update_transfer_progress(
    storage: web::Data<Arc<SecureStorageManager>>,
    _claims: web::ReqData<Claims>,
    body: web::Json<UpdateProgressRequest>,
) -> Result<impl Responder, AppError> {
    let tm = storage.transfer_manager();
    tm.update_progress(&body.path, body.current_size).await?;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "path": body.path,
        "current_size": body.current_size
    })))
}

/// 标记加密失败请求
#[derive(Debug, Deserialize)]
pub struct MarkEncryptionFailedRequest {
    pub path: String,
    pub error: String,
}

/// 标记加密失败
pub async fn mark_encryption_failed(
    storage: web::Data<Arc<SecureStorageManager>>,
    _claims: web::ReqData<Claims>,
    body: web::Json<MarkEncryptionFailedRequest>,
) -> Result<impl Responder, AppError> {
    let tm = storage.transfer_manager();
    tm.mark_encryption_failed(&body.path, &body.error).await?;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "path": body.path,
        "error": body.error
    })))
}

/// 移除传输记录请求
#[derive(Debug, Deserialize)]
pub struct RemoveTransferRequest {
    pub path: String,
}

/// 移除传输记录
pub async fn remove_transfer(
    storage: web::Data<Arc<SecureStorageManager>>,
    _claims: web::ReqData<Claims>,
    body: web::Json<RemoveTransferRequest>,
) -> Result<impl Responder, AppError> {
    let tm = storage.transfer_manager();
    tm.remove_transfer(&body.path).await;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "path": body.path,
        "message": "Transfer record removed"
    })))
}
