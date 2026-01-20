use blake3;
use sha3::{Digest, Sha3_256};

pub fn blake3_hash(data: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for chunk in data {
        hasher.update(chunk);
    }
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

pub fn blake3_hash_single(data: &[u8]) -> [u8; 32] {
    let hash = blake3::hash(data);
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

pub fn sha3_256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha3_256_hash_multi(data: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    for chunk in data {
        hasher.update(chunk);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3() {
        let data = b"test data";
        let hash = blake3_hash(&[data]);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_blake3_single() {
        let data = b"test data";
        let hash = blake3_hash_single(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha3_256() {
        let data = b"test data";
        let hash = sha3_256_hash(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha3_256_multi() {
        let data1 = b"test";
        let data2 = b" data";
        let hash = sha3_256_hash_multi(&[data1, data2]);
        assert_eq!(hash.len(), 32);
    }
}
