use blake3;
use sha2::{Sha256, Sha512, Digest};

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

pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha512_hash(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
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
    fn test_sha256() {
        let data = b"test data";
        let hash = sha256_hash(data);
        assert_eq!(hash.len(), 32);
    }
}
