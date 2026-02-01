use rockzero_common::AppError;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

// ============ CRC32 实现 ============

const CRC32_POLYNOMIAL: u32 = 0xEDB88320;

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

// ============ 随机数生成 ============

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

// ============ 安全内存清零 ============

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

// ============ 常量时间比较 ============

pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ============ 测试 ============

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32() {
        let data = b"Hello, World!";
        let checksum = crc32_checksum(data);

        assert!(crc32_verify(data, checksum));
        assert!(!crc32_verify(data, checksum + 1));
    }

    #[test]
    fn test_crc32_known_value() {
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
        assert!(BASE64.decode(&b64).is_ok());
    }

    #[test]
    fn test_secure_random_hex() {
        let hex_str = secure_random_hex(16).unwrap();
        assert_eq!(hex_str.len(), 32);
        assert!(hex::decode(&hex_str).is_ok());
    }

    #[test]
    fn test_constant_time_compare() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";

        assert!(constant_time_compare(a, b));
        assert!(!constant_time_compare(a, c));
        assert!(!constant_time_compare(a, b"hello world"));
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
}
