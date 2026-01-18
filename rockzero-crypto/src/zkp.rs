use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use rockzero_common::error::AppError;

const PROOF_LABEL: &[u8] = b"RockZero-ZKP-v1";
const PASSWORD_DOMAIN: &str = "RockZero-Password-ZKP-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordProofData {
    pub commitment: String,
    pub challenge: String,
    pub response: String,
    pub blinding_commitment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedPasswordProof {
    pub schnorr_proof: PasswordProofData,
    pub strength_proof: Option<String>,
    pub timestamp: i64,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeProofData {
    pub proof: String,
    pub commitment: String,
    pub n_bits: usize,
}

// ============ ZKP 上下文 ============

pub struct ZkpContext {
    pedersen_gens: PedersenGens,
    bulletproof_gens: BulletproofGens,
}

impl ZkpContext {
    pub fn new() -> Self {
        Self {
            pedersen_gens: PedersenGens::default(),
            bulletproof_gens: BulletproofGens::new(64, 1),
        }
    }

    fn password_to_scalar(password: &str) -> Scalar {
        let hash = blake3::Hasher::new_derive_key(PASSWORD_DOMAIN)
            .update(password.as_bytes())
            .finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());
        Scalar::from_bytes_mod_order(bytes)
    }

    pub fn calculate_password_entropy(password: &str) -> u64 {
        let mut charset_size = 0u64;
        let mut has_lower = false;
        let mut has_upper = false;
        let mut has_digit = false;
        let mut has_special = false;

        for c in password.chars() {
            if c.is_ascii_lowercase() && !has_lower {
                has_lower = true;
                charset_size += 26;
            } else if c.is_ascii_uppercase() && !has_upper {
                has_upper = true;
                charset_size += 26;
            } else if c.is_ascii_digit() && !has_digit {
                has_digit = true;
                charset_size += 10;
            } else if !c.is_ascii_alphanumeric() && !has_special {
                has_special = true;
                charset_size += 32;
            }
        }

        let length = password.len() as f64;
        let entropy = if charset_size > 0 {
            length * (charset_size as f64).log2()
        } else {
            0.0
        };

        (entropy * 100.0) as u64
    }

    pub fn generate_password_proof(&self, password: &str) -> Result<PasswordProofData, AppError> {
        let mut rng = OsRng;
        let password_scalar = Self::password_to_scalar(password);
        let blinding = Scalar::random(&mut rng);

        // 计算 Pedersen 承诺: C = g^password * h^blinding
        let commitment_point = self.pedersen_gens.commit(password_scalar, blinding);
        let commitment = BASE64.encode(commitment_point.compress().as_bytes());

        let k = Scalar::random(&mut rng);
        let k_blinding = Scalar::random(&mut rng);
        let blinding_commitment_point = self.pedersen_gens.commit(k, k_blinding);
        let blinding_commitment = BASE64.encode(blinding_commitment_point.compress().as_bytes());

        let challenge_hash = crate::hash::blake3_hash(&[
            commitment_point.compress().as_bytes(),
            blinding_commitment_point.compress().as_bytes(),
            PROOF_LABEL,
        ]);

        let mut challenge_bytes = [0u8; 32];
        challenge_bytes.copy_from_slice(&challenge_hash);
        let challenge_scalar = Scalar::from_bytes_mod_order(challenge_bytes);

        // 计算响应: s = k + e * password, s_blinding = k_blinding + e * blinding
        let response_scalar = k + (challenge_scalar * password_scalar);
        let response_blinding = k_blinding + (challenge_scalar * blinding);

        // 组合响应
        let mut response_bytes = [0u8; 64];
        response_bytes[..32].copy_from_slice(response_scalar.as_bytes());
        response_bytes[32..].copy_from_slice(response_blinding.as_bytes());

        Ok(PasswordProofData {
            commitment,
            challenge: BASE64.encode(challenge_scalar.as_bytes()),
            response: BASE64.encode(response_bytes),
            blinding_commitment,
        })
    }

    pub fn generate_enhanced_proof(
        &self,
        password: &str,
    ) -> Result<EnhancedPasswordProof, AppError> {
        let schnorr_proof = self.generate_password_proof(password)?;

        let entropy = Self::calculate_password_entropy(password);
        let strength_proof = self.generate_range_proof(entropy, 16)?;
        let timestamp = chrono::Utc::now().timestamp();
        let mut nonce_bytes = [0u8; 16];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|_| AppError::CryptoError("Failed to generate nonce".to_string()))?;
        let nonce = BASE64.encode(nonce_bytes);

        Ok(EnhancedPasswordProof {
            schnorr_proof,
            strength_proof: Some(
                serde_json::to_string(&strength_proof)
                    .map_err(|_| AppError::CryptoError("Failed to serialize proof".to_string()))?,
            ),
            timestamp,
            nonce,
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
            .ok_or_else(|| AppError::CryptoError("Cannot decompress commitment".to_string()))?;

        let blinding_commitment_bytes = BASE64
            .decode(&proof.blinding_commitment)
            .map_err(|_| AppError::CryptoError("Invalid blinding commitment".to_string()))?;

        let blinding_commitment_point = CompressedRistretto::from_slice(&blinding_commitment_bytes)
            .map_err(|_| AppError::CryptoError("Invalid blinding commitment point".to_string()))?
            .decompress()
            .ok_or_else(|| {
                AppError::CryptoError("Cannot decompress blinding commitment".to_string())
            })?;

        let challenge_bytes = BASE64
            .decode(&proof.challenge)
            .map_err(|_| AppError::CryptoError("Invalid challenge".to_string()))?;
        let mut challenge_array = [0u8; 32];
        if challenge_bytes.len() != 32 {
            return Err(AppError::CryptoError(
                "Invalid challenge length".to_string(),
            ));
        }
        challenge_array.copy_from_slice(&challenge_bytes);
        let challenge_scalar = Scalar::from_bytes_mod_order(challenge_array);
        let response_bytes = BASE64
            .decode(&proof.response)
            .map_err(|_| AppError::CryptoError("Invalid response".to_string()))?;

        if response_bytes.len() != 64 {
            return Err(AppError::CryptoError("Invalid response length".to_string()));
        }

        let mut response_array = [0u8; 32];
        let mut response_blinding_array = [0u8; 32];
        response_array.copy_from_slice(&response_bytes[..32]);
        response_blinding_array.copy_from_slice(&response_bytes[32..]);

        let response_scalar = Scalar::from_bytes_mod_order(response_array);
        let response_blinding = Scalar::from_bytes_mod_order(response_blinding_array);

        let left = self
            .pedersen_gens
            .commit(response_scalar, response_blinding);
        let right = blinding_commitment_point + (commitment_point * challenge_scalar);
        let expected_challenge = crate::hash::blake3_hash(&[
            commitment_point.compress().as_bytes(),
            blinding_commitment_point.compress().as_bytes(),
            PROOF_LABEL,
        ]);

        let mut expected_challenge_array = [0u8; 32];
        expected_challenge_array.copy_from_slice(&expected_challenge);
        let expected_challenge_scalar = Scalar::from_bytes_mod_order(expected_challenge_array);

        Ok(left == right && challenge_scalar == expected_challenge_scalar)
    }

    pub fn verify_enhanced_proof(
        &self,
        proof: &EnhancedPasswordProof,
        stored_commitment: &str,
        max_age_seconds: i64,
    ) -> Result<bool, AppError> {
        let now = chrono::Utc::now().timestamp();
        if now - proof.timestamp > max_age_seconds {
            return Err(AppError::CryptoError("Proof expired".to_string()));
        }

        if !self.verify_password_proof(&proof.schnorr_proof, stored_commitment)? {
            return Ok(false);
        }

        if let Some(strength_proof_str) = &proof.strength_proof {
            let strength_proof: RangeProofData = serde_json::from_str(strength_proof_str)
                .map_err(|_| AppError::CryptoError("Invalid strength proof".to_string()))?;

            if !self.verify_range_proof(&strength_proof)? {
                return Err(AppError::CryptoError(
                    "Password strength too weak".to_string(),
                ));
            }
        }

        Ok(true)
    }

    pub fn generate_range_proof(
        &self,
        value: u64,
        n_bits: usize,
    ) -> Result<RangeProofData, AppError> {
        let mut rng = OsRng;
        let blinding = Scalar::random(&mut rng);
        let mut transcript = Transcript::new(b"RockZero-RangeProof-v1");

        let (proof, commitment) = RangeProof::prove_single(
            &self.bulletproof_gens,
            &self.pedersen_gens,
            &mut transcript,
            value,
            &blinding,
            n_bits,
        )
        .map_err(|_| AppError::CryptoError("Failed to generate range proof".to_string()))?;

        Ok(RangeProofData {
            proof: BASE64.encode(proof.to_bytes()),
            commitment: BASE64.encode(commitment.as_bytes()),
            n_bits,
        })
    }

    pub fn verify_range_proof(&self, proof_data: &RangeProofData) -> Result<bool, AppError> {
        let proof_bytes = BASE64
            .decode(&proof_data.proof)
            .map_err(|_| AppError::CryptoError("Invalid proof".to_string()))?;

        let proof = RangeProof::from_bytes(&proof_bytes)
            .map_err(|_| AppError::CryptoError("Invalid range proof format".to_string()))?;

        let commitment_bytes = BASE64
            .decode(&proof_data.commitment)
            .map_err(|_| AppError::CryptoError("Invalid commitment".to_string()))?;

        let commitment = CompressedRistretto::from_slice(&commitment_bytes)
            .map_err(|_| AppError::CryptoError("Invalid commitment point".to_string()))?;

        let mut transcript = Transcript::new(b"RockZero-RangeProof-v1");
        let result = proof.verify_single(
            &self.bulletproof_gens,
            &self.pedersen_gens,
            &mut transcript,
            &commitment,
            proof_data.n_bits,
        );

        Ok(result.is_ok())
    }

    pub fn generate_commitment(&self, password: &str) -> Result<(String, String), AppError> {
        let mut rng = OsRng;
        let password_scalar = Self::password_to_scalar(password);
        let blinding = Scalar::random(&mut rng);

        let commitment = self.pedersen_gens.commit(password_scalar, blinding);

        Ok((
            BASE64.encode(commitment.compress().as_bytes()),
            BASE64.encode(blinding.as_bytes()),
        ))
    }
}

impl Default for ZkpContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_proof() {
        let ctx = ZkpContext::new();
        let password = "SecurePassword123!@#";
        let proof = ctx.generate_password_proof(password).unwrap();
        let result = ctx.verify_password_proof(&proof, &proof.commitment).unwrap();
        assert!(result);
    }

    #[test]
    fn test_wrong_password() {
        let ctx = ZkpContext::new();
        let password = "SecurePassword123!@#";
        let wrong_password = "WrongPassword456!@#";

        let (commitment, _) = ctx.generate_commitment(password).unwrap();
        let proof = ctx.generate_password_proof(wrong_password).unwrap();
        let result = ctx.verify_password_proof(&proof, &commitment).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_range_proof() {
        let ctx = ZkpContext::new();
        let proof = ctx.generate_range_proof(1000, 16).unwrap();
        let result = ctx.verify_range_proof(&proof).unwrap();
        assert!(result);
    }

    #[test]
    fn test_enhanced_proof() {
        let ctx = ZkpContext::new();
        let password = "SecurePassword123!@#$%";
        let proof = ctx.generate_enhanced_proof(password).unwrap();
        let result = ctx.verify_enhanced_proof(&proof, &proof.schnorr_proof.commitment, 300).unwrap();
        assert!(result);
    }
}
