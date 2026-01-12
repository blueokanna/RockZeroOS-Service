use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::AppError;

pub struct ZkpContext;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordProofData {
    pub commitment: String,
    pub challenge: String,
    pub response: String,
}

impl ZkpContext {
    pub fn new() -> Self {
        Self
    }

    fn password_to_scalar(password: &str) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Scalar::from_bytes_mod_order(bytes)
    }

    pub fn generate_password_proof(&self, password: &str) -> Result<PasswordProofData, AppError> {
        let password_scalar = Self::password_to_scalar(password);
        let commitment_point = RistrettoPoint::mul_base(&password_scalar);
        let commitment = BASE64.encode(commitment_point.compress().as_bytes());

        let mut rng = OsRng;
        let random_scalar = Scalar::random(&mut rng);
        let random_point = RistrettoPoint::mul_base(&random_scalar);

        let mut hasher = Sha256::new();
        hasher.update(commitment_point.compress().as_bytes());
        hasher.update(random_point.compress().as_bytes());
        let challenge_hash = hasher.finalize();
        let mut challenge_bytes = [0u8; 32];
        challenge_bytes.copy_from_slice(&challenge_hash);
        let challenge_scalar = Scalar::from_bytes_mod_order(challenge_bytes);

        let response_scalar = random_scalar + (challenge_scalar * password_scalar);

        Ok(PasswordProofData {
            commitment,
            challenge: BASE64.encode(challenge_scalar.as_bytes()),
            response: BASE64.encode(response_scalar.as_bytes()),
        })
    }

    pub fn verify_password_proof(
        &self,
        proof: &PasswordProofData,
        stored_commitment: &str,
    ) -> Result<bool, AppError> {
        let commitment_bytes = BASE64
            .decode(stored_commitment)
            .map_err(|_| AppError::CryptoError("Invalid commitment".to_string()))?;
        let commitment_point = CompressedRistretto::from_slice(&commitment_bytes)
            .map_err(|_| AppError::CryptoError("Invalid commitment point".to_string()))?
            .decompress()
            .ok_or_else(|| AppError::CryptoError("Cannot decompress commitment point".to_string()))?;

        let challenge_bytes = BASE64
            .decode(&proof.challenge)
            .map_err(|_| AppError::CryptoError("Invalid challenge".to_string()))?;
        let mut challenge_array = [0u8; 32];
        challenge_array.copy_from_slice(&challenge_bytes);
        let challenge_scalar = Scalar::from_bytes_mod_order(challenge_array);

        let response_bytes = BASE64
            .decode(&proof.response)
            .map_err(|_| AppError::CryptoError("Invalid response".to_string()))?;
        let mut response_array = [0u8; 32];
        response_array.copy_from_slice(&response_bytes);
        let response_scalar = Scalar::from_bytes_mod_order(response_array);

        let left = RistrettoPoint::mul_base(&response_scalar);
        let right = commitment_point * challenge_scalar;

        Ok(left == right)
    }
}
