use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::crypto::{Wpa3Sae, crc32_checksum, crc32_verify, secure_random_bytes};
use crate::error::AppError;

// ============ 常量定义 ============

const DATA_SHARDS: usize = 4;             // 数据分片数
const PARITY_SHARDS: usize = 2;           // 校验分片数（类似 RAID6 的双校验）
const TOTAL_SHARDS: usize = DATA_SHARDS + PARITY_SHARDS;

// ============ CRC32 实现（使用 crypto 模块） ============

/// CRC32 校验和计算器（包装 crypto 模块的实现）
pub struct Crc32;

impl Crc32 {
    pub fn new() -> Self {
        Self
    }

    /// 计算数据的 CRC32 校验和
    pub fn checksum(&self, data: &[u8]) -> u32 {
        crc32_checksum(data)
    }

    /// 验证数据的 CRC32 校验和
    pub fn verify(&self, data: &[u8], expected: u32) -> bool {
        crc32_verify(data, expected)
    }
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

// ============ Galois Field (GF(2^8)) 运算 - Reed-Solomon 基础 ============

/// GF(2^8) 有限域运算，用于 Reed-Solomon 编码
pub struct GaloisField {
    exp_table: [u8; 512],
    log_table: [u8; 256],
}

impl GaloisField {
    pub fn new() -> Self {
        let mut exp_table = [0u8; 512];
        let mut log_table = [0u8; 256];
        
        // 使用原始多项式 0x11D (x^8 + x^4 + x^3 + x^2 + 1)
        let mut x: u16 = 1;
        for i in 0..255 {
            exp_table[i] = x as u8;
            exp_table[i + 255] = x as u8;
            log_table[x as usize] = i as u8;
            
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11D;
            }
        }
        log_table[0] = 0;
        
        Self { exp_table, log_table }
    }

    /// GF(2^8) 乘法
    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let log_a = self.log_table[a as usize] as usize;
        let log_b = self.log_table[b as usize] as usize;
        self.exp_table[log_a + log_b]
    }

    /// GF(2^8) 幂运算
    pub fn pow(&self, a: u8, n: u8) -> u8 {
        if n == 0 {
            return 1;
        }
        if a == 0 {
            return 0;
        }
        let log_a = self.log_table[a as usize] as usize;
        let exp = (log_a * n as usize) % 255;
        self.exp_table[exp]
    }

    /// GF(2^8) 逆元
    pub fn inv(&self, a: u8) -> u8 {
        if a == 0 {
            panic!("Cannot invert zero in GF(2^8)");
        }
        let log_a = self.log_table[a as usize] as i16;
        self.exp_table[(255 - log_a) as usize]
    }
}

impl Default for GaloisField {
    fn default() -> Self {
        Self::new()
    }
}

// ============ Reed-Solomon 编码器 ============

/// Reed-Solomon 纠删码编码器（类似 RAID6）
pub struct ReedSolomon {
    gf: GaloisField,
    data_shards: usize,
    parity_shards: usize,
    generator_matrix: Vec<Vec<u8>>,
}

#[allow(clippy::needless_range_loop)]
impl ReedSolomon {
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        let gf = GaloisField::new();
        let total = data_shards + parity_shards;
        
        // 构建 Vandermonde 矩阵作为生成矩阵
        let mut generator_matrix = vec![vec![0u8; data_shards]; total];
        
        // 单位矩阵部分（数据分片）
        for i in 0..data_shards {
            generator_matrix[i][i] = 1;
        }
        
        // Vandermonde 矩阵部分（校验分片）
        for i in 0..parity_shards {
            for j in 0..data_shards {
                generator_matrix[data_shards + i][j] = gf.pow((i + 1) as u8, j as u8);
            }
        }
        
        Self {
            gf,
            data_shards,
            parity_shards,
            generator_matrix,
        }
    }

    /// 编码数据，生成校验分片
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>, AppError> {
        let shard_size = data.len().div_ceil(self.data_shards);
        let mut shards = vec![vec![0u8; shard_size]; self.data_shards + self.parity_shards];
        
        // 填充数据分片
        for (i, chunk) in data.chunks(shard_size).enumerate() {
            if i < self.data_shards {
                shards[i][..chunk.len()].copy_from_slice(chunk);
            }
        }
        
        // 计算校验分片
        for byte_idx in 0..shard_size {
            for parity_idx in 0..self.parity_shards {
                let mut parity_byte = 0u8;
                for data_idx in 0..self.data_shards {
                    let coeff = self.generator_matrix[self.data_shards + parity_idx][data_idx];
                    parity_byte ^= self.gf.mul(coeff, shards[data_idx][byte_idx]);
                }
                shards[self.data_shards + parity_idx][byte_idx] = parity_byte;
            }
        }
        
        Ok(shards)
    }

    /// 从分片重建数据（可容忍最多 parity_shards 个分片丢失）
    pub fn reconstruct(&self, shards: &mut [Option<Vec<u8>>]) -> Result<Vec<u8>, AppError> {
        let mut available_indices = Vec::new();
        let mut shard_size = 0;
        
        for (i, shard) in shards.iter().enumerate() {
            if let Some(s) = shard {
                available_indices.push(i);
                shard_size = s.len();
            }
        }
        
        if available_indices.len() < self.data_shards {
            return Err(AppError::CryptoError(
                "Not enough shards to reconstruct data".to_string()
            ));
        }
        
        // 选择前 data_shards 个可用分片
        let selected: Vec<usize> = available_indices.iter().take(self.data_shards).copied().collect();
        
        // 构建子矩阵
        let mut sub_matrix = vec![vec![0u8; self.data_shards]; self.data_shards];
        for (i, &shard_idx) in selected.iter().enumerate() {
            for j in 0..self.data_shards {
                sub_matrix[i][j] = self.generator_matrix[shard_idx][j];
            }
        }
        
        // 计算逆矩阵
        let inv_matrix = self.invert_matrix(&sub_matrix)?;
        
        // 重建数据
        let mut result = vec![0u8; shard_size * self.data_shards];
        
        for byte_idx in 0..shard_size {
            for data_idx in 0..self.data_shards {
                let mut value = 0u8;
                for (i, &shard_idx) in selected.iter().enumerate() {
                    if let Some(shard) = &shards[shard_idx] {
                        value ^= self.gf.mul(inv_matrix[data_idx][i], shard[byte_idx]);
                    }
                }
                let result_idx = data_idx * shard_size + byte_idx;
                if result_idx < result.len() {
                    result[result_idx] = value;
                }
            }
        }
        
        Ok(result)
    }

    /// 矩阵求逆（高斯-约旦消元法）
    fn invert_matrix(&self, matrix: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, AppError> {
        let n = matrix.len();
        let mut work = vec![vec![0u8; n * 2]; n];
        
        // 构建增广矩阵 [A | I]
        for i in 0..n {
            for j in 0..n {
                work[i][j] = matrix[i][j];
            }
            work[i][n + i] = 1;
        }
        
        // 高斯-约旦消元
        for col in 0..n {
            // 找主元
            let mut pivot_row = col;
            for row in col + 1..n {
                if work[row][col] != 0 {
                    pivot_row = row;
                    break;
                }
            }
            
            if work[pivot_row][col] == 0 {
                return Err(AppError::CryptoError("Matrix is singular".to_string()));
            }
            
            // 交换行
            if pivot_row != col {
                work.swap(col, pivot_row);
            }
            
            // 归一化主元行
            let pivot_val = work[col][col];
            let pivot_inv = self.gf.inv(pivot_val);
            for j in 0..n * 2 {
                work[col][j] = self.gf.mul(work[col][j], pivot_inv);
            }
            
            // 消元
            for row in 0..n {
                if row != col && work[row][col] != 0 {
                    let factor = work[row][col];
                    for j in 0..n * 2 {
                        work[row][j] ^= self.gf.mul(factor, work[col][j]);
                    }
                }
            }
        }
        
        // 提取逆矩阵
        let mut result = vec![vec![0u8; n]; n];
        for i in 0..n {
            for j in 0..n {
                result[i][j] = work[i][n + j];
            }
        }
        
        Ok(result)
    }
}

// ============ 安全数据块 ============

/// 安全数据块，包含加密数据、CRC32 校验和、Reed-Solomon 校验
#[derive(Clone)]
pub struct SecureBlock {
    pub id: u64,
    pub encrypted_data: Vec<u8>,
    pub crc32: u32,
    pub nonce: [u8; 12],
    pub parity_shards: Vec<Vec<u8>>,
}

impl SecureBlock {
    /// 序列化为字节
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // ID (8 bytes)
        bytes.extend_from_slice(&self.id.to_le_bytes());
        
        // Nonce (12 bytes)
        bytes.extend_from_slice(&self.nonce);
        
        // CRC32 (4 bytes)
        bytes.extend_from_slice(&self.crc32.to_le_bytes());
        
        // 加密数据长度 (4 bytes) + 数据
        bytes.extend_from_slice(&(self.encrypted_data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.encrypted_data);
        
        // 校验分片数量 (2 bytes)
        bytes.extend_from_slice(&(self.parity_shards.len() as u16).to_le_bytes());
        
        // 每个校验分片
        for shard in &self.parity_shards {
            bytes.extend_from_slice(&(shard.len() as u32).to_le_bytes());
            bytes.extend_from_slice(shard);
        }
        
        bytes
    }

    /// 从字节反序列化
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AppError> {
        if bytes.len() < 28 {
            return Err(AppError::CryptoError("Invalid block data".to_string()));
        }
        
        let mut offset = 0;
        
        // ID
        let id = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;
        
        // Nonce
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[offset..offset + 12]);
        offset += 12;
        
        // CRC32
        let crc32 = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;
        
        // 加密数据
        let data_len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        
        if bytes.len() < offset + data_len {
            return Err(AppError::CryptoError("Invalid block data length".to_string()));
        }
        
        let encrypted_data = bytes[offset..offset + data_len].to_vec();
        offset += data_len;
        
        // 校验分片
        let mut parity_shards = Vec::new();
        if bytes.len() > offset + 2 {
            let shard_count = u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;
            
            for _ in 0..shard_count {
                if bytes.len() < offset + 4 {
                    break;
                }
                let shard_len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
                offset += 4;
                
                if bytes.len() < offset + shard_len {
                    break;
                }
                parity_shards.push(bytes[offset..offset + shard_len].to_vec());
                offset += shard_len;
            }
        }
        
        Ok(Self {
            id,
            encrypted_data,
            crc32,
            nonce,
            parity_shards,
        })
    }
}

// ============ 恢复数据结构 ============

/// 恢复数据结构
struct RecoveryData {
    block_id: u64,
    original_crc: u32,
    shard_crcs: Vec<u32>,
    parity_crcs: Vec<u32>,
}

impl RecoveryData {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        bytes.extend_from_slice(&self.block_id.to_le_bytes());
        bytes.extend_from_slice(&self.original_crc.to_le_bytes());
        
        bytes.extend_from_slice(&(self.shard_crcs.len() as u16).to_le_bytes());
        for crc in &self.shard_crcs {
            bytes.extend_from_slice(&crc.to_le_bytes());
        }
        
        bytes.extend_from_slice(&(self.parity_crcs.len() as u16).to_le_bytes());
        for crc in &self.parity_crcs {
            bytes.extend_from_slice(&crc.to_le_bytes());
        }
        
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, AppError> {
        if bytes.len() < 14 {
            return Err(AppError::CryptoError("Invalid recovery data".to_string()));
        }
        
        let mut offset = 0;
        
        let block_id = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;
        
        let original_crc = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;
        
        let shard_count = u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        
        let mut shard_crcs = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            if bytes.len() < offset + 4 {
                return Err(AppError::CryptoError("Invalid recovery data".to_string()));
            }
            shard_crcs.push(u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()));
            offset += 4;
        }
        
        if bytes.len() < offset + 2 {
            return Err(AppError::CryptoError("Invalid recovery data".to_string()));
        }
        
        let parity_count = u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        
        let mut parity_crcs = Vec::with_capacity(parity_count);
        for _ in 0..parity_count {
            if bytes.len() < offset + 4 {
                return Err(AppError::CryptoError("Invalid recovery data".to_string()));
            }
            parity_crcs.push(u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()));
            offset += 4;
        }
        
        Ok(Self {
            block_id,
            original_crc,
            shard_crcs,
            parity_crcs,
        })
    }
}

/// 数据库统计信息
#[derive(Debug, Clone, serde::Serialize)]
pub struct DatabaseStats {
    pub total_blocks: usize,
    pub total_size: usize,
    pub db_path: String,
    pub recovery_path: String,
}

// ============ 安全数据库管理器 ============

/// 安全数据库管理器
/// 提供加密存储、完整性校验和自动修复功能
pub struct SecureDatabase {
    db_path: PathBuf,
    recovery_path: PathBuf,
    cipher: Aes256Gcm,
    crc: Crc32,
    rs: ReedSolomon,
    blocks: Arc<RwLock<HashMap<u64, SecureBlock>>>,
    next_block_id: Arc<RwLock<u64>>,
}

impl SecureDatabase {
    /// 创建新的安全数据库
    pub fn new(db_path: &Path, master_password: &str) -> Result<Self, AppError> {
        let sae = Wpa3Sae::new();
        let db_identifier = db_path.to_string_lossy().to_string();
        let key = sae.derive_db_key(master_password, &db_identifier);
        
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| AppError::CryptoError("Failed to create cipher".to_string()))?;
        
        let recovery_path = db_path.with_extension("recovery");
        
        Ok(Self {
            db_path: db_path.to_path_buf(),
            recovery_path,
            cipher,
            crc: Crc32::new(),
            rs: ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS),
            blocks: Arc::new(RwLock::new(HashMap::new())),
            next_block_id: Arc::new(RwLock::new(1)),
        })
    }

    /// 加密并存储数据
    pub async fn store(&self, data: &[u8]) -> Result<u64, AppError> {
        // 使用 crypto 模块生成随机 nonce
        let nonce_vec = secure_random_bytes(12)?;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&nonce_vec);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // 加密数据
        let encrypted_data = self.cipher
            .encrypt(nonce, data)
            .map_err(|_| AppError::CryptoError("Encryption failed".to_string()))?;
        
        // 计算 CRC32
        let crc32 = self.crc.checksum(&encrypted_data);
        
        // 生成 Reed-Solomon 校验分片
        let shards = self.rs.encode(&encrypted_data)?;
        let parity_shards: Vec<Vec<u8>> = shards[DATA_SHARDS..].to_vec();
        
        // 获取新的块 ID
        let block_id = {
            let mut id = self.next_block_id.write().await;
            let current = *id;
            *id += 1;
            current
        };
        
        let block = SecureBlock {
            id: block_id,
            encrypted_data,
            crc32,
            nonce: nonce_bytes,
            parity_shards,
        };
        
        // 存储到内存
        {
            let mut blocks = self.blocks.write().await;
            blocks.insert(block_id, block.clone());
        }
        
        // 持久化到文件
        self.persist_block(&block).await?;
        
        // 更新恢复文件
        self.update_recovery_file(&block).await?;
        
        Ok(block_id)
    }

    /// 读取并解密数据
    pub async fn retrieve(&self, block_id: u64) -> Result<Vec<u8>, AppError> {
        let blocks = self.blocks.read().await;
        let block = blocks.get(&block_id)
            .ok_or_else(|| AppError::NotFound("Block not found".to_string()))?;
        
        // 验证 CRC32
        if !self.crc.verify(&block.encrypted_data, block.crc32) {
            // CRC 校验失败，尝试修复
            drop(blocks);
            return self.repair_and_retrieve(block_id).await;
        }
        
        // 解密数据
        let nonce = Nonce::from_slice(&block.nonce);
        let decrypted = self.cipher
            .decrypt(nonce, block.encrypted_data.as_ref())
            .map_err(|_| AppError::CryptoError("Decryption failed".to_string()))?;
        
        Ok(decrypted)
    }

    /// 修复损坏的数据块并读取
    async fn repair_and_retrieve(&self, block_id: u64) -> Result<Vec<u8>, AppError> {
        tracing::warn!("Block {} CRC check failed, attempting repair", block_id);
        
        // 从恢复文件读取校验数据
        let recovery_data = self.read_recovery_data(block_id).await?;
        
        let mut blocks = self.blocks.write().await;
        let block = blocks.get_mut(&block_id)
            .ok_or_else(|| AppError::NotFound("Block not found".to_string()))?;
        
        // 准备分片用于重建
        let shard_size = block.encrypted_data.len().div_ceil(DATA_SHARDS);
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
        
        // 尝试使用现有数据分片
        for (i, chunk) in block.encrypted_data.chunks(shard_size).enumerate() {
            if i < DATA_SHARDS {
                // 验证每个分片的局部 CRC
                let shard_crc = self.crc.checksum(chunk);
                if let Some(expected_crc) = recovery_data.shard_crcs.get(i) {
                    if shard_crc == *expected_crc {
                        shards[i] = Some(chunk.to_vec());
                    }
                }
            }
        }
        
        // 添加校验分片
        for (i, parity) in block.parity_shards.iter().enumerate() {
            shards[DATA_SHARDS + i] = Some(parity.clone());
        }
        
        // 使用 Reed-Solomon 重建数据
        let reconstructed = self.rs.reconstruct(&mut shards)?;
        
        // 截断到原始长度
        let original_len = block.encrypted_data.len();
        let repaired_data: Vec<u8> = reconstructed.into_iter().take(original_len).collect();
        
        // 验证修复后的数据
        let new_crc = self.crc.checksum(&repaired_data);
        if new_crc != recovery_data.original_crc {
            return Err(AppError::CryptoError("Data repair failed".to_string()));
        }
        
        // 更新块数据
        block.encrypted_data = repaired_data.clone();
        block.crc32 = new_crc;
        
        // 解密
        let nonce = Nonce::from_slice(&block.nonce);
        let decrypted = self.cipher
            .decrypt(nonce, repaired_data.as_ref())
            .map_err(|_| AppError::CryptoError("Decryption failed after repair".to_string()))?;
        
        tracing::info!("Block {} successfully repaired", block_id);
        
        Ok(decrypted)
    }

    /// 持久化数据块到文件
    async fn persist_block(&self, block: &SecureBlock) -> Result<(), AppError> {
        let block_bytes = block.to_bytes();
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.db_path)
            .map_err(|e| AppError::IoError(e.to_string()))?;
        
        // 写入块大小和数据
        let size = block_bytes.len() as u32;
        file.write_all(&size.to_le_bytes())
            .map_err(|e| AppError::IoError(e.to_string()))?;
        file.write_all(&block_bytes)
            .map_err(|e| AppError::IoError(e.to_string()))?;
        
        file.sync_all()
            .map_err(|e| AppError::IoError(e.to_string()))?;
        
        Ok(())
    }

    /// 更新恢复文件
    async fn update_recovery_file(&self, block: &SecureBlock) -> Result<(), AppError> {
        let recovery_data = RecoveryData {
            block_id: block.id,
            original_crc: block.crc32,
            shard_crcs: self.calculate_shard_crcs(&block.encrypted_data),
            parity_crcs: block.parity_shards.iter()
                .map(|s| self.crc.checksum(s))
                .collect(),
        };
        
        let recovery_bytes = recovery_data.to_bytes();
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.recovery_path)
            .map_err(|e| AppError::IoError(e.to_string()))?;
        
        let size = recovery_bytes.len() as u32;
        file.write_all(&size.to_le_bytes())
            .map_err(|e| AppError::IoError(e.to_string()))?;
        file.write_all(&recovery_bytes)
            .map_err(|e| AppError::IoError(e.to_string()))?;
        
        file.sync_all()
            .map_err(|e| AppError::IoError(e.to_string()))?;
        
        Ok(())
    }

    /// 计算数据分片的 CRC
    fn calculate_shard_crcs(&self, data: &[u8]) -> Vec<u32> {
        let shard_size = data.len().div_ceil(DATA_SHARDS);
        data.chunks(shard_size)
            .map(|chunk| self.crc.checksum(chunk))
            .collect()
    }

    /// 从恢复文件读取恢复数据
    async fn read_recovery_data(&self, block_id: u64) -> Result<RecoveryData, AppError> {
        if !self.recovery_path.exists() {
            return Err(AppError::NotFound("Recovery file not found".to_string()));
        }
        
        let mut file = File::open(&self.recovery_path)
            .map_err(|e| AppError::IoError(e.to_string()))?;
        
        loop {
            let mut size_bytes = [0u8; 4];
            if file.read_exact(&mut size_bytes).is_err() {
                break;
            }
            
            let size = u32::from_le_bytes(size_bytes) as usize;
            let mut data = vec![0u8; size];
            
            if file.read_exact(&mut data).is_err() {
                break;
            }
            
            if let Ok(recovery) = RecoveryData::from_bytes(&data) {
                if recovery.block_id == block_id {
                    return Ok(recovery);
                }
            }
        }
        
        Err(AppError::NotFound("Recovery data not found for block".to_string()))
    }

    /// 从文件加载数据库
    pub async fn load(&self) -> Result<(), AppError> {
        if !self.db_path.exists() {
            return Ok(());
        }
        
        let mut file = File::open(&self.db_path)
            .map_err(|e| AppError::IoError(e.to_string()))?;
        
        let mut blocks = self.blocks.write().await;
        let mut max_id = 0u64;
        
        loop {
            let mut size_bytes = [0u8; 4];
            if file.read_exact(&mut size_bytes).is_err() {
                break;
            }
            
            let size = u32::from_le_bytes(size_bytes) as usize;
            let mut data = vec![0u8; size];
            
            if file.read_exact(&mut data).is_err() {
                break;
            }
            
            if let Ok(block) = SecureBlock::from_bytes(&data) {
                if block.id > max_id {
                    max_id = block.id;
                }
                blocks.insert(block.id, block);
            }
        }
        
        drop(blocks);
        
        let mut next_id = self.next_block_id.write().await;
        *next_id = max_id + 1;
        
        Ok(())
    }

    /// 验证所有数据块的完整性
    pub async fn verify_integrity(&self) -> Result<Vec<u64>, AppError> {
        let blocks = self.blocks.read().await;
        let mut corrupted = Vec::new();
        
        for (id, block) in blocks.iter() {
            if !self.crc.verify(&block.encrypted_data, block.crc32) {
                corrupted.push(*id);
            }
        }
        
        Ok(corrupted)
    }

    /// 修复所有损坏的数据块
    pub async fn repair_all(&self) -> Result<usize, AppError> {
        let corrupted = self.verify_integrity().await?;
        let mut repaired = 0;
        
        for block_id in corrupted {
            if self.repair_and_retrieve(block_id).await.is_ok() {
                repaired += 1;
            }
        }
        
        Ok(repaired)
    }

    /// 删除数据块
    pub async fn delete(&self, block_id: u64) -> Result<bool, AppError> {
        let mut blocks = self.blocks.write().await;
        Ok(blocks.remove(&block_id).is_some())
    }

    /// 获取数据库统计信息
    pub async fn stats(&self) -> DatabaseStats {
        let blocks = self.blocks.read().await;
        let total_blocks = blocks.len();
        let total_size: usize = blocks.values()
            .map(|b| b.encrypted_data.len())
            .sum();
        
        DatabaseStats {
            total_blocks,
            total_size,
            db_path: self.db_path.to_string_lossy().to_string(),
            recovery_path: self.recovery_path.to_string_lossy().to_string(),
        }
    }
}

// ============ 测试 ============

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32() {
        let crc = Crc32::new();
        let data = b"Hello, World!";
        let checksum = crc.checksum(data);
        assert!(crc.verify(data, checksum));
        assert!(!crc.verify(data, checksum + 1));
    }

    #[test]
    fn test_galois_field() {
        let gf = GaloisField::new();
        
        // 测试乘法
        assert_eq!(gf.mul(0, 5), 0);
        assert_eq!(gf.mul(1, 5), 5);
        
        // 测试逆元
        let a = 42u8;
        let a_inv = gf.inv(a);
        assert_eq!(gf.mul(a, a_inv), 1);
    }

    #[test]
    fn test_reed_solomon() {
        let rs = ReedSolomon::new(4, 2);
        let data = b"Hello, World! This is a test of Reed-Solomon encoding.";
        
        // 编码
        let shards = rs.encode(data).unwrap();
        assert_eq!(shards.len(), 6);
        
        // 模拟丢失两个分片
        let mut recovery_shards: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        recovery_shards[0] = None;
        recovery_shards[1] = None;
        
        // 重建
        let reconstructed = rs.reconstruct(&mut recovery_shards).unwrap();
        assert!(reconstructed.starts_with(data));
    }
}
