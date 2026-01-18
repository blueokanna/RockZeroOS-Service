use crate::error::{HlsError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;

pub struct HlsEncryptor {
    cipher: Aes256Gcm,
}

impl HlsEncryptor {
    pub fn new(key: &[u8; 32]) -> Result<Self> {
        let cipher = Aes256Gcm::new(key.into());
        Ok(Self { cipher })
    }

    pub fn encrypt_segment(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| HlsError::EncryptionError(format!("AES-GCM encryption failed: {}", e)))?;

        Ok((nonce_bytes.to_vec(), ciphertext))
    }

    pub fn decrypt_segment(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != 12 {
            return Err(HlsError::DecryptionError(
                "Invalid nonce length".to_string(),
            ));
        }

        let nonce = Nonce::from_slice(nonce);

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| HlsError::DecryptionError(format!("AES-GCM decryption failed: {}", e)))?;

        Ok(plaintext)
    }

    pub fn encrypt_segment_combined(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let (nonce, ciphertext) = self.encrypt_segment(plaintext)?;

        let mut combined = Vec::with_capacity(nonce.len() + ciphertext.len());
        combined.extend_from_slice(&nonce);
        combined.extend_from_slice(&ciphertext);

        Ok(combined)
    }

    pub fn decrypt_segment_combined(&self, combined: &[u8]) -> Result<Vec<u8>> {
        if combined.len() < 12 {
            return Err(HlsError::DecryptionError("Data too short".to_string()));
        }

        let (nonce, ciphertext) = combined.split_at(12);
        self.decrypt_segment(nonce, ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0x42u8; 32];
        let encryptor = HlsEncryptor::new(&key).unwrap();
        let plaintext = b"This is a test TS segment data";
        let (nonce, ciphertext) = encryptor.encrypt_segment(plaintext).unwrap();
        let decrypted = encryptor.decrypt_segment(&nonce, &ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());

        let combined = encryptor.encrypt_segment_combined(plaintext).unwrap();
        let decrypted2 = encryptor.decrypt_segment_combined(&combined).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted2.as_slice());
    }

    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];

        let encryptor1 = HlsEncryptor::new(&key1).unwrap();
        let encryptor2 = HlsEncryptor::new(&key2).unwrap();

        let plaintext = b"test data";

        let (_, ciphertext1) = encryptor1.encrypt_segment(plaintext).unwrap();
        let (_, ciphertext2) = encryptor2.encrypt_segment(plaintext).unwrap();

        assert_ne!(ciphertext1, ciphertext2);
    }
}
