//! Key derivation - Derive application keys from PMK (using Blake3)

use crate::error::{Result, SaeError};

/// 密钥派生器 (使用 Blake3)
pub struct KeyDerivation {
    pmk: [u8; 32],
}

impl KeyDerivation {
    /// 创建新的密钥派生器
    pub fn new(pmk: [u8; 32]) -> Self {
        Self { pmk }
    }

    /// 派生 AES-256 密钥 (使用 HKDF-Blake3)
    /// 
    /// # 参数
    /// 
    /// * `info` - 上下文信息 (例如: "hls-encryption", "segment-0")
    /// * `salt` - 可选的盐值
    pub fn derive_aes256_key(&self, info: &[u8], salt: Option<&[u8]>) -> Result<[u8; 32]> {
        // Extract: PRK = Blake3(salt || PMK)
        let salt_key: [u8; 32] = match salt {
            Some(s) if s.len() == 32 => {
                let mut key = [0u8; 32];
                key.copy_from_slice(s);
                key
            }
            Some(s) => *blake3::hash(s).as_bytes(),
            None => [0u8; 32],
        };
        
        // PRK = Blake3(salt || PMK)
        let mut extract_input = Vec::with_capacity(32 + 32);
        extract_input.extend_from_slice(&salt_key);
        extract_input.extend_from_slice(&self.pmk);
        let prk = *blake3::hash(&extract_input).as_bytes();
        
        // Expand: OKM = Blake3(PRK || info || 0x01)
        let mut expand_input = Vec::with_capacity(32 + info.len() + 1);
        expand_input.extend_from_slice(&prk);
        expand_input.extend_from_slice(info);
        expand_input.push(1);
        
        Ok(*blake3::hash(&expand_input).as_bytes())
    }

    /// 派生多个 AES-256 密钥
    pub fn derive_multiple_keys(&self, base_info: &[u8], count: usize) -> Result<Vec<[u8; 32]>> {
        let mut keys = Vec::with_capacity(count);
        
        for i in 0..count {
            let mut info = base_info.to_vec();
            info.extend_from_slice(&i.to_le_bytes());
            
            let key = self.derive_aes256_key(&info, None)?;
            keys.push(key);
        }
        
        Ok(keys)
    }

    /// 派生 HMAC-Blake3 密钥
    pub fn derive_hmac_key(&self, info: &[u8]) -> Result<[u8; 32]> {
        self.derive_aes256_key(info, None)
    }

    /// 派生会话密钥
    pub fn derive_session_key(&self, session_id: &str) -> Result<[u8; 32]> {
        let info = format!("session-key-{}", session_id);
        self.derive_aes256_key(info.as_bytes(), None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let pmk = [0x42u8; 32];
        let kd = KeyDerivation::new(pmk);

        // 测试 AES-256 密钥派生
        let key1 = kd.derive_aes256_key(b"test-context-1", None).unwrap();
        let key2 = kd.derive_aes256_key(b"test-context-2", None).unwrap();
        
        // 不同的 info 应该产生不同的密钥
        assert_ne!(key1, key2);

        // 相同的 info 应该产生相同的密钥
        let key1_again = kd.derive_aes256_key(b"test-context-1", None).unwrap();
        assert_eq!(key1, key1_again);
    }

    #[test]
    fn test_multiple_keys() {
        let pmk = [0x42u8; 32];
        let kd = KeyDerivation::new(pmk);

        let keys = kd.derive_multiple_keys(b"hls-segment", 10).unwrap();
        
        assert_eq!(keys.len(), 10);
        
        // 所有密钥应该不同
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j]);
            }
        }
    }
}
