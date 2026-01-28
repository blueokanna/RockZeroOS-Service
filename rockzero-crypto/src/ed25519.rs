use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use rockzero_common::error::AppError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ed25519KeyPair {
    pub public_key: String,
    pub secret_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ed25519Signature {
    pub signature: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    pub message: String,
    pub signature: Ed25519Signature,
    pub timestamp: i64,
}

pub struct Ed25519Context {
    signing_key: Option<SigningKey>,
    verifying_key: Option<VerifyingKey>,
}

impl Ed25519Context {
    pub fn new() -> Self {
        Self {
            signing_key: None,
            verifying_key: None,
        }
    }

    pub fn generate_keypair() -> Result<Ed25519KeyPair, AppError> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        Ok(Ed25519KeyPair {
            public_key: BASE64.encode(verifying_key.as_bytes()),
            secret_key: BASE64.encode(signing_key.to_bytes()),
        })
    }

    pub fn from_keypair(keypair: &Ed25519KeyPair) -> Result<Self, AppError> {
        let secret_bytes = BASE64
            .decode(&keypair.secret_key)
            .map_err(|_| AppError::CryptoError("Invalid secret key encoding".to_string()))?;

        if secret_bytes.len() != SECRET_KEY_LENGTH {
            return Err(AppError::CryptoError("Invalid secret key length".to_string()));
        }

        let mut secret_array = [0u8; SECRET_KEY_LENGTH];
        secret_array.copy_from_slice(&secret_bytes);

        let signing_key = SigningKey::from_bytes(&secret_array);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key: Some(signing_key),
            verifying_key: Some(verifying_key),
        })
    }

    pub fn from_public_key(public_key: &str) -> Result<Self, AppError> {
        let public_bytes = BASE64
            .decode(public_key)
            .map_err(|_| AppError::CryptoError("Invalid public key encoding".to_string()))?;

        if public_bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(AppError::CryptoError("Invalid public key length".to_string()));
        }

        let mut public_array = [0u8; PUBLIC_KEY_LENGTH];
        public_array.copy_from_slice(&public_bytes);

        let verifying_key = VerifyingKey::from_bytes(&public_array)
            .map_err(|e| AppError::CryptoError(format!("Invalid public key: {}", e)))?;

        Ok(Self {
            signing_key: None,
            verifying_key: Some(verifying_key),
        })
    }

    pub fn sign(&self, message: &[u8]) -> Result<Ed25519Signature, AppError> {
        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or_else(|| AppError::CryptoError("No signing key available".to_string()))?;

        let verifying_key = self
            .verifying_key
            .as_ref()
            .ok_or_else(|| AppError::CryptoError("No verifying key available".to_string()))?;

        let signature = signing_key.sign(message);

        Ok(Ed25519Signature {
            signature: BASE64.encode(signature.to_bytes()),
            public_key: BASE64.encode(verifying_key.as_bytes()),
        })
    }

    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> Result<bool, AppError> {
        let public_bytes = BASE64
            .decode(&signature.public_key)
            .map_err(|_| AppError::CryptoError("Invalid public key encoding".to_string()))?;

        if public_bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(AppError::CryptoError("Invalid public key length".to_string()));
        }

        let mut public_array = [0u8; PUBLIC_KEY_LENGTH];
        public_array.copy_from_slice(&public_bytes);

        let verifying_key = VerifyingKey::from_bytes(&public_array)
            .map_err(|e| AppError::CryptoError(format!("Invalid public key: {}", e)))?;

        let sig_bytes = BASE64
            .decode(&signature.signature)
            .map_err(|_| AppError::CryptoError("Invalid signature encoding".to_string()))?;

        if sig_bytes.len() != SIGNATURE_LENGTH {
            return Err(AppError::CryptoError("Invalid signature length".to_string()));
        }

        let mut sig_array = [0u8; SIGNATURE_LENGTH];
        sig_array.copy_from_slice(&sig_bytes);

        let signature = Signature::from_bytes(&sig_array);

        match verifying_key.verify(message, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub fn sign_message(&self, message: &str) -> Result<SignedMessage, AppError> {
        let timestamp = chrono::Utc::now().timestamp();
        let data_to_sign = format!("{}:{}", message, timestamp);
        let signature = self.sign(data_to_sign.as_bytes())?;

        Ok(SignedMessage {
            message: message.to_string(),
            signature,
            timestamp,
        })
    }

    pub fn verify_signed_message(
        &self,
        signed_message: &SignedMessage,
        max_age_seconds: i64,
    ) -> Result<bool, AppError> {
        let now = chrono::Utc::now().timestamp();
        if now - signed_message.timestamp > max_age_seconds {
            return Err(AppError::CryptoError("Message expired".to_string()));
        }

        if signed_message.timestamp > now + 60 {
            return Err(AppError::CryptoError("Message timestamp in future".to_string()));
        }

        let data_to_verify = format!("{}:{}", signed_message.message, signed_message.timestamp);
        self.verify(data_to_verify.as_bytes(), &signed_message.signature)
    }

    pub fn get_public_key(&self) -> Result<String, AppError> {
        let verifying_key = self
            .verifying_key
            .as_ref()
            .ok_or_else(|| AppError::CryptoError("No public key available".to_string()))?;

        Ok(BASE64.encode(verifying_key.as_bytes()))
    }
}

impl Default for Ed25519Context {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = Ed25519Context::generate_keypair().unwrap();
        assert!(!keypair.public_key.is_empty());
        assert!(!keypair.secret_key.is_empty());
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = Ed25519Context::generate_keypair().unwrap();
        let ctx = Ed25519Context::from_keypair(&keypair).unwrap();

        let message = b"test message";
        let signature = ctx.sign(message).unwrap();

        let result = ctx.verify(message, &signature).unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_with_wrong_message() {
        let keypair = Ed25519Context::generate_keypair().unwrap();
        let ctx = Ed25519Context::from_keypair(&keypair).unwrap();

        let message = b"test message";
        let signature = ctx.sign(message).unwrap();

        let wrong_message = b"wrong message";
        let result = ctx.verify(wrong_message, &signature).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_signed_message() {
        let keypair = Ed25519Context::generate_keypair().unwrap();
        let ctx = Ed25519Context::from_keypair(&keypair).unwrap();

        let signed = ctx.sign_message("hello world").unwrap();
        let result = ctx.verify_signed_message(&signed, 300).unwrap();
        assert!(result);
    }
}
