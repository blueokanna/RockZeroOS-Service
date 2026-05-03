use actix_web::{web, HttpRequest, HttpResponse, Responder};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{
    aead::{Aead, AeadCore, OsRng},
    ChaCha20Poly1305, Key, KeyInit, Nonce,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::crypto::{
    blake3_hash_bytes, blake3_keyed_hash, constant_time_compare, crc32_checksum, crc32_verify,
    secure_random_base64, secure_random_bytes, secure_random_hex, secure_zero, secure_zero_key,
    CryptoContext, EncryptedData, KeyDeriver, SecureFileEncryptor, TransferManager, Wpa3Sae,
};
use crate::handlers::auth::Claims;
use crate::secure_db::SecureDatabase;
use rockzero_common::AppError;
use tracing::info;

const PRIVATE_SPACE_VERSION: u8 = 1;
const PRIVATE_SPACE_SALT_LEN: usize = 32;
const PRIVATE_SPACE_MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;

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

    pub async fn close_db(&self, user_id: &str) {
        let mut dbs = self.databases.write().await;
        dbs.remove(user_id);
    }

    pub fn transfer_manager(&self) -> Arc<TransferManager> {
        self.transfer_manager.clone()
    }

    pub fn file_encryptor(&self) -> Arc<SecureFileEncryptor> {
        self.file_encryptor.clone()
    }

    fn private_space_dir(&self) -> PathBuf {
        self.base_path.join("private_space").join("items")
    }

    fn private_item_path(&self, id: &str) -> Result<PathBuf, AppError> {
        if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(AppError::BadRequest("Invalid private item id".to_string()));
        }
        Ok(self.private_space_dir().join(format!("{}.rzp", id)))
    }

    fn derive_private_space_key(password: &str, salt: &[u8]) -> Result<[u8; 32], AppError> {
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| AppError::CryptoError(format!("Argon2id key derivation failed: {}", e)))?;
        Ok(key)
    }

    fn private_space_cipher(key: &[u8; 32]) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(key))
    }

    fn collect_private_files(path: PathBuf) -> Result<Vec<(PathBuf, String)>, AppError> {
        let metadata = fs::metadata(&path)?;
        if metadata.is_file() {
            let relative = path
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or_else(|| AppError::BadRequest("Invalid source file name".to_string()))?
                .to_string();
            return Ok(vec![(path, relative)]);
        }

        if !metadata.is_dir() {
            return Err(AppError::BadRequest(
                "Only regular files and directories can be imported".to_string(),
            ));
        }

        let root_name = path
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or_else(|| AppError::BadRequest("Invalid source directory name".to_string()))?
            .to_string();
        let root = path.canonicalize()?;
        let mut files = Vec::new();
        for entry in walkdir::WalkDir::new(&root)
            .into_iter()
            .filter_map(Result::ok)
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let file_path = entry.path().to_path_buf();
            let rel = file_path
                .strip_prefix(&root)
                .map_err(|_| AppError::InternalError)?
                .to_string_lossy()
                .replace('\\', "/");
            files.push((file_path, format!("{}/{}", root_name, rel)));
        }
        files.sort_by(|a, b| a.1.cmp(&b.1));
        Ok(files)
    }

    fn encrypt_private_file(
        &self,
        password: &str,
        file_path: PathBuf,
        relative_path: String,
    ) -> Result<PrivateSpaceItemSummary, AppError> {
        let metadata = fs::metadata(&file_path)?;
        if metadata.len() > PRIVATE_SPACE_MAX_FILE_BYTES {
            return Err(AppError::BadRequest(format!(
                "File exceeds private space item limit: {}",
                file_path.display()
            )));
        }

        let original_path = file_path.canonicalize()?.to_string_lossy().to_string();
        let file_name = file_path
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or_else(|| AppError::BadRequest("Invalid source file name".to_string()))?
            .to_string();
        let content = fs::read(&file_path)?;
        let modified_unix_ms = metadata
            .modified()
            .ok()
            .and_then(|v| v.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|v| v.as_millis());
        let payload = PrivateSpacePayload {
            original_path: original_path.clone(),
            relative_path: relative_path.clone(),
            file_name: file_name.clone(),
            content: BASE64.encode(content),
            modified_unix_ms,
        };

        let mut salt = [0u8; PRIVATE_SPACE_SALT_LEN];
        getrandom::getrandom(&mut salt)
            .map_err(|e| AppError::CryptoError(format!("Secure random failed: {}", e)))?;
        let key = Self::derive_private_space_key(password, &salt)?;
        let cipher = Self::private_space_cipher(&key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| AppError::InternalServerError(e.to_string()))?;
        let ciphertext = cipher
            .encrypt(&nonce, payload_bytes.as_slice())
            .map_err(|e| AppError::CryptoError(format!("ChaCha20-Poly1305 failed: {}", e)))?;

        let id = uuid::Uuid::new_v4().to_string();
        let encrypted_at = chrono::Utc::now().to_rfc3339();
        let path_hash = hex::encode(blake3_hash_bytes(original_path.as_bytes()));
        let envelope = PrivateSpaceEnvelope {
            version: PRIVATE_SPACE_VERSION,
            id: id.clone(),
            salt: BASE64.encode(salt),
            nonce: BASE64.encode(nonce),
            path_hash: path_hash.clone(),
            size: metadata.len(),
            encrypted_at: encrypted_at.clone(),
            ciphertext: BASE64.encode(ciphertext),
        };

        fs::create_dir_all(self.private_space_dir())?;
        let item_path = self.private_item_path(&id)?;
        let serialized = serde_json::to_vec_pretty(&envelope)
            .map_err(|e| AppError::InternalServerError(e.to_string()))?;
        fs::write(item_path, serialized)?;

        Ok(PrivateSpaceItemSummary {
            id,
            original_path,
            relative_path,
            file_name,
            size: metadata.len(),
            encrypted_at,
            path_hash,
        })
    }

    fn read_private_envelope(&self, id: &str) -> Result<PrivateSpaceEnvelope, AppError> {
        let path = self.private_item_path(id)?;
        if !path.exists() {
            return Err(AppError::NotFound(
                "Private space item not found".to_string(),
            ));
        }
        let data = fs::read(path)?;
        serde_json::from_slice(&data).map_err(|e| AppError::InternalServerError(e.to_string()))
    }

    fn decrypt_private_payload(
        envelope: &PrivateSpaceEnvelope,
        password: &str,
    ) -> Result<PrivateSpacePayload, AppError> {
        if envelope.version != PRIVATE_SPACE_VERSION {
            return Err(AppError::BadRequest(
                "Unsupported private space item version".to_string(),
            ));
        }
        let salt = BASE64
            .decode(&envelope.salt)
            .map_err(|_| AppError::CryptoError("Invalid private item salt".to_string()))?;
        let nonce_bytes = BASE64
            .decode(&envelope.nonce)
            .map_err(|_| AppError::CryptoError("Invalid private item nonce".to_string()))?;
        if nonce_bytes.len() != 12 {
            return Err(AppError::CryptoError(
                "Invalid private item nonce length".to_string(),
            ));
        }
        let ciphertext = BASE64
            .decode(&envelope.ciphertext)
            .map_err(|_| AppError::CryptoError("Invalid private item ciphertext".to_string()))?;
        let key = Self::derive_private_space_key(password, &salt)?;
        let cipher = Self::private_space_cipher(&key);
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_slice())
            .map_err(|_| AppError::Unauthorized("Invalid private space password".to_string()))?;
        serde_json::from_slice(&plaintext).map_err(|e| AppError::InternalServerError(e.to_string()))
    }

    fn list_private_items(&self, password: &str) -> Result<Vec<PrivateSpaceItemSummary>, AppError> {
        let dir = self.private_space_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut items = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|v| v.to_str()) != Some("rzp") {
                continue;
            }
            let data = fs::read(entry.path())?;
            let envelope: PrivateSpaceEnvelope = serde_json::from_slice(&data)
                .map_err(|e| AppError::InternalServerError(e.to_string()))?;
            let payload = Self::decrypt_private_payload(&envelope, password)?;
            items.push(PrivateSpaceItemSummary {
                id: envelope.id,
                original_path: payload.original_path,
                relative_path: payload.relative_path,
                file_name: payload.file_name,
                size: envelope.size,
                encrypted_at: envelope.encrypted_at,
                path_hash: envelope.path_hash,
            });
        }
        items.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
        Ok(items)
    }

    fn private_space_status(&self) -> Result<PrivateSpaceStatusResponse, AppError> {
        let dir = self.private_space_dir();
        if !dir.exists() {
            return Ok(PrivateSpaceStatusResponse {
                item_count: 0,
                encrypted_bytes: 0,
                vault_path: dir.to_string_lossy().to_string(),
            });
        }
        let mut item_count = 0usize;
        let mut encrypted_bytes = 0u64;
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|v| v.to_str()) == Some("rzp") {
                item_count += 1;
                encrypted_bytes += entry.metadata()?.len();
            }
        }
        Ok(PrivateSpaceStatusResponse {
            item_count,
            encrypted_bytes,
            vault_path: dir.to_string_lossy().to_string(),
        })
    }
}

fn ensure_private_space_admin(claims: &Claims) -> Result<(), AppError> {
    if claims.role.eq_ignore_ascii_case("admin") {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "Administrator access is required for private space".to_string(),
        ))
    }
}

#[derive(Debug, Deserialize)]
pub struct InitDatabaseRequest {
    pub master_password: String,
}

#[derive(Debug, Deserialize)]
pub struct PrivateSpaceImportRequest {
    pub master_password: String,
    pub paths: Vec<String>,
    pub delete_original: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct PrivateSpacePasswordRequest {
    pub master_password: String,
}

#[derive(Debug, Deserialize)]
pub struct PrivateSpaceExportRequest {
    pub master_password: String,
    pub id: String,
    pub target_directory: String,
    pub overwrite: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct PrivateSpaceDeleteRequest {
    pub master_password: String,
    pub id: String,
}

#[derive(Debug, Serialize)]
pub struct PrivateSpaceImportResponse {
    pub imported: Vec<PrivateSpaceItemSummary>,
}

#[derive(Debug, Serialize)]
pub struct PrivateSpaceStatusResponse {
    pub item_count: usize,
    pub encrypted_bytes: u64,
    pub vault_path: String,
}

#[derive(Debug, Serialize)]
pub struct PrivateSpaceListResponse {
    pub items: Vec<PrivateSpaceItemSummary>,
}

#[derive(Debug, Serialize)]
pub struct PrivateSpaceExportResponse {
    pub id: String,
    pub restored_path: String,
    pub bytes_written: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateSpaceItemSummary {
    pub id: String,
    pub original_path: String,
    pub relative_path: String,
    pub file_name: String,
    pub size: u64,
    pub encrypted_at: String,
    pub path_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PrivateSpaceEnvelope {
    version: u8,
    id: String,
    salt: String,
    nonce: String,
    path_hash: String,
    size: u64,
    encrypted_at: String,
    ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PrivateSpacePayload {
    original_path: String,
    relative_path: String,
    file_name: String,
    content: String,
    modified_unix_ms: Option<u128>,
}

#[derive(Debug, Deserialize)]
pub struct StoreDataRequest {
    pub master_password: String,
    pub data: String,
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
    pub data: String,
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

pub async fn init_secure_database(
    storage: web::Data<Arc<SecureStorageManager>>,
    claims: web::ReqData<Claims>,
    body: web::Json<InitDatabaseRequest>,
) -> Result<impl Responder, AppError> {
    let db = storage
        .get_or_create_db(&claims.sub, &body.master_password)
        .await?;
    let stats = db.stats().await;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Secure database initialized",
        "stats": stats
    })))
}

pub async fn store_secure_data(
    storage: web::Data<Arc<SecureStorageManager>>,
    claims: web::ReqData<Claims>,
    body: web::Json<StoreDataRequest>,
) -> Result<impl Responder, AppError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    let db = storage
        .get_or_create_db(&claims.sub, &body.master_password)
        .await?;

    let data = BASE64
        .decode(&body.data)
        .map_err(|_| AppError::BadRequest("Invalid Base64 data".to_string()))?;

    let block_id = db.store(&data).await?;

    Ok(HttpResponse::Created().json(StoreDataResponse {
        block_id,
        message: "Data stored securely with CRC32 and Reed-Solomon protection".to_string(),
    }))
}

pub async fn retrieve_secure_data(
    storage: web::Data<Arc<SecureStorageManager>>,
    claims: web::ReqData<Claims>,
    body: web::Json<RetrieveDataRequest>,
) -> Result<impl Responder, AppError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    let db = storage
        .get_or_create_db(&claims.sub, &body.master_password)
        .await?;

    let data = db.retrieve(body.block_id).await?;

    Ok(HttpResponse::Ok().json(RetrieveDataResponse {
        data: BASE64.encode(&data),
        block_id: body.block_id,
    }))
}

pub async fn delete_secure_data(
    storage: web::Data<Arc<SecureStorageManager>>,
    claims: web::ReqData<Claims>,
    body: web::Json<DeleteDataRequest>,
) -> Result<impl Responder, AppError> {
    let db = storage
        .get_or_create_db(&claims.sub, &body.master_password)
        .await?;

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

pub async fn check_integrity(
    storage: web::Data<Arc<SecureStorageManager>>,
    claims: web::ReqData<Claims>,
    body: web::Json<InitDatabaseRequest>,
) -> Result<impl Responder, AppError> {
    let db = storage
        .get_or_create_db(&claims.sub, &body.master_password)
        .await?;

    let corrupted = db.verify_integrity().await?;
    let stats = db.stats().await;

    Ok(HttpResponse::Ok().json(IntegrityCheckResponse {
        total_blocks: stats.total_blocks,
        corrupted_blocks: corrupted.clone(),
        is_healthy: corrupted.is_empty(),
    }))
}

pub async fn repair_data(
    storage: web::Data<Arc<SecureStorageManager>>,
    claims: web::ReqData<Claims>,
    body: web::Json<InitDatabaseRequest>,
) -> Result<impl Responder, AppError> {
    let db = storage
        .get_or_create_db(&claims.sub, &body.master_password)
        .await?;

    let repaired = db.repair_all().await?;

    Ok(HttpResponse::Ok().json(RepairResponse {
        repaired_count: repaired,
        message: format!(
            "Successfully repaired {} blocks using Reed-Solomon recovery",
            repaired
        ),
    }))
}

pub async fn get_database_stats(
    storage: web::Data<Arc<SecureStorageManager>>,
    claims: web::ReqData<Claims>,
    body: web::Json<InitDatabaseRequest>,
) -> Result<impl Responder, AppError> {
    let db = storage
        .get_or_create_db(&claims.sub, &body.master_password)
        .await?;

    let stats = db.stats().await;

    Ok(HttpResponse::Ok().json(stats))
}

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

pub async fn private_space_status(
    storage: web::Data<Arc<SecureStorageManager>>,
    claims: web::ReqData<Claims>,
    req: HttpRequest,
) -> Result<impl Responder, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    ensure_private_space_admin(&claims)?;
    Ok(HttpResponse::Ok().json(storage.private_space_status()?))
}

pub async fn import_private_space_items(
    storage: web::Data<Arc<SecureStorageManager>>,
    claims: web::ReqData<Claims>,
    req: HttpRequest,
    body: web::Json<PrivateSpaceImportRequest>,
) -> Result<impl Responder, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    ensure_private_space_admin(&claims)?;
    if body.master_password.len() < 12 {
        return Err(AppError::BadRequest(
            "Private space password must be at least 12 characters".to_string(),
        ));
    }
    if body.paths.is_empty() {
        return Err(AppError::BadRequest(
            "At least one file or directory is required".to_string(),
        ));
    }

    let mut imported = Vec::new();
    for source in &body.paths {
        let source_path = PathBuf::from(source);
        if !source_path.exists() {
            return Err(AppError::NotFound(format!(
                "Source path not found: {}",
                source
            )));
        }
        let files = SecureStorageManager::collect_private_files(source_path)?;
        for (file_path, relative_path) in files {
            let summary = storage.encrypt_private_file(
                &body.master_password,
                file_path.clone(),
                relative_path,
            )?;
            if body.delete_original.unwrap_or(false) {
                fs::remove_file(file_path)?;
            }
            imported.push(summary);
        }
    }

    Ok(HttpResponse::Created().json(PrivateSpaceImportResponse { imported }))
}

pub async fn list_private_space_items(
    storage: web::Data<Arc<SecureStorageManager>>,
    claims: web::ReqData<Claims>,
    req: HttpRequest,
    body: web::Json<PrivateSpacePasswordRequest>,
) -> Result<impl Responder, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    ensure_private_space_admin(&claims)?;
    let items = storage.list_private_items(&body.master_password)?;
    Ok(HttpResponse::Ok().json(PrivateSpaceListResponse { items }))
}

pub async fn export_private_space_item(
    storage: web::Data<Arc<SecureStorageManager>>,
    claims: web::ReqData<Claims>,
    req: HttpRequest,
    body: web::Json<PrivateSpaceExportRequest>,
) -> Result<impl Responder, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    ensure_private_space_admin(&claims)?;
    let envelope = storage.read_private_envelope(&body.id)?;
    let payload = SecureStorageManager::decrypt_private_payload(&envelope, &body.master_password)?;
    let content = BASE64
        .decode(&payload.content)
        .map_err(|_| AppError::CryptoError("Invalid private item payload".to_string()))?;
    let target_root = PathBuf::from(&body.target_directory);
    fs::create_dir_all(&target_root)?;
    let relative = PathBuf::from(&payload.relative_path);
    if relative.components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        )
    }) {
        return Err(AppError::BadRequest(
            "Invalid private item relative path".to_string(),
        ));
    }
    let target_path = target_root.join(relative);
    if target_path.exists() && !body.overwrite.unwrap_or(false) {
        return Err(AppError::Conflict(format!(
            "Target file already exists: {}",
            target_path.display()
        )));
    }
    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&target_path, &content)?;
    Ok(HttpResponse::Ok().json(PrivateSpaceExportResponse {
        id: body.id.clone(),
        restored_path: target_path.to_string_lossy().to_string(),
        bytes_written: content.len() as u64,
    }))
}

pub async fn delete_private_space_item(
    storage: web::Data<Arc<SecureStorageManager>>,
    claims: web::ReqData<Claims>,
    req: HttpRequest,
    body: web::Json<PrivateSpaceDeleteRequest>,
) -> Result<impl Responder, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;
    ensure_private_space_admin(&claims)?;
    let envelope = storage.read_private_envelope(&body.id)?;
    let _ = SecureStorageManager::decrypt_private_payload(&envelope, &body.master_password)?;
    fs::remove_file(storage.private_item_path(&body.id)?)?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "id": body.id
    })))
}

#[derive(Debug, Deserialize)]
pub struct EncryptDataRequest {
    pub password: String,
    pub data: String,
}

#[derive(Debug, Serialize)]
pub struct EncryptDataResponse {
    pub encrypted: String,
    pub key_id: String,
}

#[derive(Debug, Deserialize)]
pub struct DecryptDataRequest {
    pub password: String,
    pub encrypted: String,
}

#[derive(Debug, Serialize)]
pub struct DecryptDataResponse {
    pub data: String,
}

pub async fn encrypt_data(
    _claims: web::ReqData<Claims>,
    body: web::Json<EncryptDataRequest>,
) -> Result<impl Responder, AppError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    let ctx = CryptoContext::new(&body.password)?;

    let data = BASE64
        .decode(&body.data)
        .map_err(|_| AppError::BadRequest("Invalid Base64 data".to_string()))?;

    let encrypted = ctx.encrypt(&data)?;

    Ok(HttpResponse::Ok().json(EncryptDataResponse {
        encrypted: BASE64.encode(&encrypted.ciphertext),
        key_id: "default".to_string(),
    }))
}

pub async fn decrypt_data(
    _claims: web::ReqData<Claims>,
    body: web::Json<DecryptDataRequest>,
) -> Result<impl Responder, AppError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    let ctx = CryptoContext::new(&body.password)?;
    let ciphertext = BASE64
        .decode(&body.encrypted)
        .map_err(|_| AppError::BadRequest("Invalid Base64 encrypted data".to_string()))?;
    let encrypted = EncryptedData {
        ciphertext,
        nonce: vec![],
        tag: None,
    };
    let decrypted = ctx.decrypt(&encrypted)?;

    Ok(HttpResponse::Ok().json(DecryptDataResponse {
        data: BASE64.encode(&decrypted),
    }))
}

#[derive(Debug, Deserialize)]
pub struct DeriveKeyRequest {
    pub password: String,
    pub context: String,
    #[serde(default)]
    pub use_wpa3_sae: bool,
}

#[derive(Debug, Serialize)]
pub struct DeriveKeyResponse {
    pub key: String,
    pub method: String,
}

pub async fn derive_key(
    _claims: web::ReqData<Claims>,
    body: web::Json<DeriveKeyRequest>,
) -> Result<impl Responder, AppError> {
    let (key, method) = if body.use_wpa3_sae {
        let sae = Wpa3Sae::new();
        let key = sae.derive_key(&body.password, &body.context, "")?;
        (key, "WPA3-SAE")
    } else {
        let deriver = KeyDeriver::new();
        let key = deriver.derive(&body.password, body.context.as_bytes())?;
        (key.to_vec(), "BLAKE3-KDF")
    };

    Ok(HttpResponse::Ok().json(DeriveKeyResponse {
        key: hex::encode(key),
        method: method.to_string(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct DeriveBatchKeysRequest {
    pub password: String,
    pub contexts: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DeriveBatchKeysResponse {
    pub keys: Vec<DerivedKey>,
}

#[derive(Debug, Serialize)]
pub struct DerivedKey {
    pub context: String,
    pub key: String,
}

pub async fn derive_batch_keys(
    _claims: web::ReqData<Claims>,
    body: web::Json<DeriveBatchKeysRequest>,
) -> Result<impl Responder, AppError> {
    let deriver = KeyDeriver::new();
    let keys = deriver.derive_keys(&body.password, &body.contexts)?;

    let derived_keys: Vec<DerivedKey> = body
        .contexts
        .iter()
        .zip(keys.iter())
        .map(|(ctx, key)| DerivedKey {
            context: ctx.clone(),
            key: key.clone(),
        })
        .collect();

    Ok(HttpResponse::Ok().json(DeriveBatchKeysResponse { keys: derived_keys }))
}

#[derive(Debug, Deserialize)]
pub struct GenerateRandomRequest {
    pub length: usize,
    #[serde(default = "default_format")]
    pub format: String,
}

fn default_format() -> String {
    "hex".to_string()
}

#[derive(Debug, Serialize)]
pub struct GenerateRandomResponse {
    pub data: String,
    pub format: String,
    pub length: usize,
}

pub async fn generate_random(
    _claims: web::ReqData<Claims>,
    body: web::Json<GenerateRandomRequest>,
) -> Result<impl Responder, AppError> {
    if body.length > 1024 * 1024 {
        return Err(AppError::BadRequest(
            "Length too large (max 1MB)".to_string(),
        ));
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

#[derive(Debug, Deserialize)]
pub struct HashDataRequest {
    pub data: String,
    #[serde(default)]
    pub key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HashDataResponse {
    pub hash: String,
    pub algorithm: String,
}

pub async fn hash_data(
    _claims: web::ReqData<Claims>,
    body: web::Json<HashDataRequest>,
) -> Result<impl Responder, AppError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    let data = BASE64
        .decode(&body.data)
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

#[derive(Debug, Deserialize)]
pub struct Crc32Request {
    pub data: String,
    #[serde(default)]
    pub expected: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct Crc32Response {
    pub checksum: u32,
    pub checksum_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid: Option<bool>,
}

pub async fn crc32_check(
    _claims: web::ReqData<Claims>,
    body: web::Json<Crc32Request>,
) -> Result<impl Responder, AppError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    let data = BASE64
        .decode(&body.data)
        .map_err(|_| AppError::BadRequest("Invalid Base64 data".to_string()))?;

    let checksum = crc32_checksum(&data);
    let valid = body.expected.map(|expected| crc32_verify(&data, expected));

    Ok(HttpResponse::Ok().json(Crc32Response {
        checksum,
        checksum_hex: format!("{:08X}", checksum),
        valid,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ConstantTimeCompareRequest {
    pub a: String,
    pub b: String,
}

#[derive(Debug, Serialize)]
pub struct ConstantTimeCompareResponse {
    pub equal: bool,
}

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

#[derive(Debug, Deserialize)]
pub struct TransferStatusRequest {
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct TransferStatusResponse {
    pub path: String,
    pub is_transferring: bool,
    pub can_encrypt: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transferred_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_size: Option<u64>,
}

pub async fn get_transfer_status(
    storage: web::Data<Arc<SecureStorageManager>>,
    _claims: web::ReqData<Claims>,
    body: web::Json<TransferStatusRequest>,
) -> Result<impl Responder, AppError> {
    let tm = storage.transfer_manager();
    let is_transferring = tm.is_transferring(&body.path).await;
    let can_encrypt = tm.can_encrypt(&body.path).await;

    let (transfer_id, total_bytes, transferred_bytes, status, current_size, expected_size) =
        if let Some(info) = tm.get_transfer_info(&body.path).await {
            (
                Some(info.id.clone()),
                Some(info.total_bytes),
                Some(info.transferred_bytes),
                Some(info.status.clone()),
                Some(info.current_size),
                Some(info.expected_size),
            )
        } else {
            (None, None, None, None, None, None)
        };

    Ok(HttpResponse::Ok().json(TransferStatusResponse {
        path: body.path.clone(),
        is_transferring,
        can_encrypt,
        transfer_id,
        total_bytes,
        transferred_bytes,
        status,
        current_size,
        expected_size,
    }))
}

#[derive(Debug, Deserialize)]
pub struct StartTransferRequest {
    pub path: String,
    pub expected_size: u64,
}

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

#[derive(Debug, Deserialize)]
pub struct CompleteTransferRequest {
    pub path: String,
    pub crc32: u32,
}

pub async fn complete_transfer(
    storage: web::Data<Arc<SecureStorageManager>>,
    _claims: web::ReqData<Claims>,
    body: web::Json<CompleteTransferRequest>,
) -> Result<impl Responder, AppError> {
    let tm = storage.transfer_manager();
    tm.complete_transfer(&body.path).await?;
    info!(path = %body.path, crc32 = body.crc32, "transfer completed with CRC");

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Transfer completed, file ready for encryption",
        "path": body.path
    })))
}

#[derive(Debug, Deserialize)]
pub struct EncryptFileRequest {
    pub path: String,
    pub password: String,
    pub data: String,
}

#[derive(Debug, Serialize)]
pub struct EncryptFileResponse {
    pub encrypted: String,
    pub original_crc32: u32,
    pub original_size: u64,
}

pub async fn encrypt_file(
    storage: web::Data<Arc<SecureStorageManager>>,
    _claims: web::ReqData<Claims>,
    body: web::Json<EncryptFileRequest>,
) -> Result<impl Responder, AppError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    let encryptor = storage.file_encryptor();

    let data = BASE64
        .decode(&body.data)
        .map_err(|_| AppError::BadRequest("Invalid Base64 data".to_string()))?;

    let key_context = format!("{}::{}", body.password, body.path);
    let encrypted = encryptor.encrypt_data(&data, &key_context).await?;

    let original_crc32 = crc32fast::hash(&data);

    Ok(HttpResponse::Ok().json(EncryptFileResponse {
        encrypted: BASE64.encode(&encrypted.ciphertext),
        original_crc32,
        original_size: data.len() as u64,
    }))
}

pub async fn list_active_transfers(
    storage: web::Data<Arc<SecureStorageManager>>,
    _claims: web::ReqData<Claims>,
) -> Result<impl Responder, AppError> {
    let tm = storage.transfer_manager();
    let transfers = tm.get_active_transfers().await;

    let response: Vec<serde_json::Value> = transfers
        .iter()
        .map(|t| {
            serde_json::json!({
                "path": t.path,
                "id": t.id,
                "total_bytes": t.total_bytes,
                "transferred_bytes": t.transferred_bytes,
                "expected_size": t.expected_size,
                "current_size": t.current_size,
                "status": t.status,
                "started_at": t.started_at,
                "updated_at": t.updated_at
            })
        })
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

pub async fn cleanup_transfers(
    storage: web::Data<Arc<SecureStorageManager>>,
    _claims: web::ReqData<Claims>,
) -> Result<impl Responder, AppError> {
    let tm = storage.transfer_manager();
    tm.cleanup_completed()?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Completed transfers cleaned up"
    })))
}

#[derive(Debug, Deserialize)]
pub struct SecureEraseRequest {
    pub data: String,
}

#[derive(Debug, Serialize)]
pub struct SecureEraseResponse {
    pub success: bool,
    pub message: String,
}

pub async fn secure_erase_demo(
    _claims: web::ReqData<Claims>,
    body: web::Json<SecureEraseRequest>,
) -> Result<impl Responder, AppError> {
    let mut data = hex::decode(&body.data)
        .map_err(|_| AppError::BadRequest("Invalid hex data".to_string()))?;

    secure_zero(&mut data);

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

#[derive(Debug, Deserialize)]
pub struct EncryptStringRequest {
    pub password: String,
    pub plaintext: String,
}

#[derive(Debug, Serialize)]
pub struct EncryptStringResponse {
    pub encrypted: String,
    pub key_id: String,
}

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

#[derive(Debug, Deserialize)]
pub struct DecryptStringRequest {
    pub password: String,
    pub encrypted: String,
}

#[derive(Debug, Serialize)]
pub struct DecryptStringResponse {
    pub plaintext: String,
}

pub async fn decrypt_string(
    _claims: web::ReqData<Claims>,
    body: web::Json<DecryptStringRequest>,
) -> Result<impl Responder, AppError> {
    let ctx = CryptoContext::new(&body.password)?;
    let plaintext = ctx.decrypt_string(&body.encrypted)?;

    Ok(HttpResponse::Ok().json(DecryptStringResponse { plaintext }))
}

#[derive(Debug, Deserialize)]
pub struct Wpa3SaeKeyRequest {
    pub password: String,
    pub identifier: String,
    #[serde(default = "default_key_type")]
    pub key_type: String,
}

fn default_key_type() -> String {
    "db".to_string()
}

#[derive(Debug, Serialize)]
pub struct Wpa3SaeKeyResponse {
    pub key: String,
    pub key_type: String,
    pub algorithm: String,
}

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

#[derive(Debug, Deserialize)]
pub struct KeyDeriverRequest {
    pub password: String,
    #[serde(default = "default_deriver_key_type")]
    pub key_type: String,
    #[serde(default)]
    pub session_id: Option<String>,
}

fn default_deriver_key_type() -> String {
    "db".to_string()
}

#[derive(Debug, Serialize)]
pub struct KeyDeriverResponse {
    pub key: String,
    pub key_type: String,
}

pub async fn derive_specific_key(
    _claims: web::ReqData<Claims>,
    body: web::Json<KeyDeriverRequest>,
) -> Result<impl Responder, AppError> {
    let deriver = KeyDeriver::new();

    let key = match body.key_type.as_str() {
        "db" => deriver.derive_db_encryption_key(&body.password),
        "file" => deriver.derive_file_encryption_key(&body.password),
        "session" => {
            let session_id = body.session_id.as_ref().ok_or_else(|| {
                AppError::BadRequest("session_id required for session key".to_string())
            })?;
            deriver.derive_session_key(&body.password, session_id)
        }
        _ => return Err(AppError::BadRequest("Invalid key_type".to_string())),
    };

    Ok(HttpResponse::Ok().json(KeyDeriverResponse {
        key: hex::encode(key),
        key_type: body.key_type.clone(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct DecryptFileRequest {
    pub password: String,
    pub encrypted: String,
    pub original_crc32: u32,
    pub original_size: u64,
}

#[derive(Debug, Serialize)]
pub struct DecryptFileResponse {
    pub data: String,
    pub verified: bool,
}

pub async fn decrypt_file(
    storage: web::Data<Arc<SecureStorageManager>>,
    _claims: web::ReqData<Claims>,
    body: web::Json<DecryptFileRequest>,
) -> Result<impl Responder, AppError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    let encryptor = storage.file_encryptor();

    let encrypted_data = BASE64
        .decode(&body.encrypted)
        .map_err(|_| AppError::BadRequest("Invalid Base64 data".to_string()))?;

    let encrypted = crate::crypto::EncryptedData {
        ciphertext: encrypted_data,
        nonce: vec![0; 12],
        tag: None,
    };

    let decrypted = encryptor.decrypt_data(&encrypted, &body.password).await?;

    let verified_crc = crc32fast::hash(&decrypted);
    let size_matches = decrypted.len() as u64 == body.original_size;
    let is_valid = verified_crc == body.original_crc32 && size_matches;

    Ok(HttpResponse::Ok().json(DecryptFileResponse {
        data: BASE64.encode(&decrypted),
        verified: is_valid,
    }))
}

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

#[derive(Debug, Deserialize)]
pub struct UpdateProgressRequest {
    pub path: String,
    pub current_size: u64,
}

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

#[derive(Debug, Deserialize)]
pub struct MarkEncryptionFailedRequest {
    pub path: String,
    pub error: String,
}

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

#[derive(Debug, Deserialize)]
pub struct RemoveTransferRequest {
    pub path: String,
}

pub async fn remove_transfer(
    storage: web::Data<Arc<SecureStorageManager>>,
    _claims: web::ReqData<Claims>,
    body: web::Json<RemoveTransferRequest>,
) -> Result<impl Responder, AppError> {
    let tm = storage.transfer_manager();
    tm.remove_transfer(&body.path).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "path": body.path,
        "message": "Transfer record removed"
    })))
}
