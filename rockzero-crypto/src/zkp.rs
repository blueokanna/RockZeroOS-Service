use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rockzero_common::error::AppError;

const PASSWORD_DOMAIN: &str = "RockZero-Password-ZKP-v1";
const BLINDING_DOMAIN: &str = "RockZero-Blinding-Derive-v1";
const MIN_PASSWORD_ENTROPY_BITS: u64 = 28;
const NONCE_EXPIRY_SECONDS: u64 = 600;
const PBKDF_ITERATIONS: u32 = 100_000;

lazy_static::lazy_static! {
    static ref USED_NONCES: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new());
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordRegistration {
    pub commitment: String,
    pub salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeProofData {
    pub proof: String,
    pub commitment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedPasswordProof {
    pub password_range_proof: RangeProofData,
    pub entropy_range_proof: RangeProofData,
    pub timestamp: i64,
    pub nonce: String,
    pub context: String,
}

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

    fn password_to_scalar(password: &str, salt: &[u8]) -> Scalar {
        let mut hasher = blake3::Hasher::new_derive_key(PASSWORD_DOMAIN);
        hasher.update(salt);
        hasher.update(password.as_bytes());
        
        let mut hash = hasher.finalize();
        for _ in 0..PBKDF_ITERATIONS {
            hash = blake3::hash(hash.as_bytes());
        }
        
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());
        Scalar::from_bytes_mod_order(bytes)
    }

    fn derive_blinding(password: &str, salt: &[u8]) -> Scalar {
        let mut hasher = blake3::Hasher::new_derive_key(BLINDING_DOMAIN);
        hasher.update(salt);
        hasher.update(password.as_bytes());
        hasher.update(b"blinding");
        
        let mut hash = hasher.finalize();
        for _ in 0..PBKDF_ITERATIONS {
            hash = blake3::hash(hash.as_bytes());
        }
        
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());
        Scalar::from_bytes_mod_order(bytes)
    }

    fn password_to_u64(password: &str, salt: &[u8]) -> u64 {
        let scalar = Self::password_to_scalar(password, salt);
        let bytes = scalar.as_bytes();
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }

    fn generate_random_scalar() -> Result<Scalar, AppError> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|_| AppError::CryptoError("Failed to generate random scalar".to_string()))?;
        Ok(Scalar::from_bytes_mod_order(bytes))
    }

    fn generate_salt() -> Result<[u8; 32], AppError> {
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut salt)
            .map_err(|_| AppError::CryptoError("Failed to generate salt".to_string()))?;
        Ok(salt)
    }

    pub fn calculate_password_entropy(password: &str) -> u64 {
        if password.is_empty() {
            return 0;
        }
        
        let mut char_counts: HashMap<char, usize> = HashMap::new();
        for c in password.chars() {
            *char_counts.entry(c).or_insert(0) += 1;
        }
        
        let length = password.len() as f64;
        let mut entropy = 0.0;
        for count in char_counts.values() {
            let probability = (*count as f64) / length;
            entropy -= probability * probability.log2();
        }
        
        let total_entropy = entropy * length;
        (total_entropy * 0.7) as u64
    }

    pub fn register_password(&self, password: &str) -> Result<PasswordRegistration, AppError> {
        let entropy = Self::calculate_password_entropy(password);
        if entropy < MIN_PASSWORD_ENTROPY_BITS {
            return Err(AppError::CryptoError(format!(
                "Password entropy too low: {} bits (minimum {} bits required)",
                entropy, MIN_PASSWORD_ENTROPY_BITS
            )));
        }

        let salt = Self::generate_salt()?;
        let password_scalar = Self::password_to_scalar(password, &salt);
        let blinding = Self::derive_blinding(password, &salt);
        let commitment = self.pedersen_gens.commit(password_scalar, blinding);
        
        Ok(PasswordRegistration {
            commitment: BASE64.encode(commitment.compress().as_bytes()),
            salt: BASE64.encode(salt),
        })
    }

    fn create_range_proof_for_value(
        &self,
        value: u64,
        transcript: &mut Transcript,
    ) -> Result<RangeProofData, AppError> {
        let blinding = Self::generate_random_scalar()?;

        let (proof, commitment) = RangeProof::prove_single(
            &self.bulletproof_gens,
            &self.pedersen_gens,
            transcript,
            value,
            &blinding,
            64,
        )
        .map_err(|e| AppError::CryptoError(format!("Range proof generation failed: {:?}", e)))?;

        Ok(RangeProofData {
            proof: BASE64.encode(proof.to_bytes()),
            commitment: BASE64.encode(commitment.as_bytes()),
        })
    }

    fn verify_range_proof_data(
        &self,
        proof_data: &RangeProofData,
        transcript: &mut Transcript,
    ) -> Result<bool, AppError> {
        let proof_bytes = BASE64
            .decode(&proof_data.proof)
            .map_err(|_| AppError::CryptoError("Invalid proof encoding".to_string()))?;

        let commitment_bytes = BASE64
            .decode(&proof_data.commitment)
            .map_err(|_| AppError::CryptoError("Invalid commitment encoding".to_string()))?;

        let proof = RangeProof::from_bytes(&proof_bytes)
            .map_err(|_| AppError::CryptoError("Invalid proof format".to_string()))?;

        let commitment = CompressedRistretto::from_slice(&commitment_bytes)
            .map_err(|_| AppError::CryptoError("Invalid commitment format".to_string()))?;

        proof
            .verify_single(
                &self.bulletproof_gens,
                &self.pedersen_gens,
                transcript,
                &commitment,
                64,
            )
            .map_err(|e| AppError::CryptoError(format!("Range proof verification failed: {:?}", e)))?;

        Ok(true)
    }

    pub fn generate_enhanced_proof(
        &self,
        password: &str,
        registration: &PasswordRegistration,
        context: &str,
    ) -> Result<EnhancedPasswordProof, AppError> {
        let salt = BASE64
            .decode(&registration.salt)
            .map_err(|_| AppError::CryptoError("Invalid registration salt".to_string()))?;
        
        let password_scalar = Self::password_to_scalar(password, &salt);
        let blinding = Self::derive_blinding(password, &salt);
        let commitment_point = self.pedersen_gens.commit(password_scalar, blinding);
        let computed_commitment = BASE64.encode(commitment_point.compress().as_bytes());
        
        if computed_commitment != registration.commitment {
            return Err(AppError::CryptoError("Invalid password".to_string()));
        }

        let timestamp = chrono::Utc::now().timestamp();
        let mut nonce_bytes = [0u8; 32];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|_| AppError::CryptoError("Failed to generate nonce".to_string()))?;
        let nonce = BASE64.encode(nonce_bytes);

        let mut transcript = Transcript::new(b"RockZero-Enhanced-Password-Proof");
        transcript.append_message(b"context", context.as_bytes());
        transcript.append_message(b"timestamp", &timestamp.to_le_bytes());
        transcript.append_message(b"nonce", nonce.as_bytes());
        transcript.append_message(b"stored_commitment", registration.commitment.as_bytes());

        let password_value = Self::password_to_u64(password, &salt);
        let password_range_proof = self.create_range_proof_for_value(password_value, &mut transcript)?;

        let entropy = Self::calculate_password_entropy(password);
        let entropy_range_proof = self.create_range_proof_for_value(entropy, &mut transcript)?;

        Ok(EnhancedPasswordProof {
            password_range_proof,
            entropy_range_proof,
            timestamp,
            nonce,
            context: context.to_string(),
        })
    }

    pub fn verify_enhanced_proof(
        &self,
        proof: &EnhancedPasswordProof,
        registration: &PasswordRegistration,
        expected_context: &str,
        max_age_seconds: i64,
    ) -> Result<bool, AppError> {
        if proof.context != expected_context {
            return Err(AppError::CryptoError("Context mismatch".to_string()));
        }

        let now = chrono::Utc::now().timestamp();
        if now - proof.timestamp > max_age_seconds {
            return Err(AppError::CryptoError("Proof expired".to_string()));
        }
        if proof.timestamp > now + 60 {
            return Err(AppError::CryptoError("Proof timestamp in future".to_string()));
        }

        {
            let mut used_nonces = USED_NONCES
                .lock()
                .map_err(|_| AppError::CryptoError("Failed to lock nonce tracker".to_string()))?;
            
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            used_nonces.retain(|_, &mut expiry| expiry > current_time);
            
            if used_nonces.contains_key(&proof.nonce) {
                return Err(AppError::CryptoError(
                    "Nonce already used (replay attack detected)".to_string(),
                ));
            }
            used_nonces.insert(proof.nonce.clone(), current_time + NONCE_EXPIRY_SECONDS);
        }

        let mut transcript = Transcript::new(b"RockZero-Enhanced-Password-Proof");
        transcript.append_message(b"context", proof.context.as_bytes());
        transcript.append_message(b"timestamp", &proof.timestamp.to_le_bytes());
        transcript.append_message(b"nonce", proof.nonce.as_bytes());
        transcript.append_message(b"stored_commitment", registration.commitment.as_bytes());

        self.verify_range_proof_data(&proof.password_range_proof, &mut transcript)?;
        self.verify_range_proof_data(&proof.entropy_range_proof, &mut transcript)?;

        Ok(true)
    }

    #[cfg(test)]
    pub fn clear_nonces() {
        if let Ok(mut nonces) = USED_NONCES.lock() {
            nonces.clear();
        }
    }
}

impl Default for ZkpContext {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorrProof {
    pub a_point: String,
    pub challenge: String,
    pub response_password: String,
    pub response_blinding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundStrengthProof {
    pub entropy_value_commitment: String,
    pub range_proof: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration_creates_deterministic_commitment() {
        let ctx = ZkpContext::new();
        let password = "SecurePassword123!@#";

        let registration = ctx.register_password(password).unwrap();
        
        let salt = BASE64.decode(&registration.salt).unwrap();
        let password_scalar = ZkpContext::password_to_scalar(password, &salt);
        let blinding = ZkpContext::derive_blinding(password, &salt);
        let expected_commitment = ctx.pedersen_gens.commit(password_scalar, blinding);
        
        assert_eq!(
            registration.commitment,
            BASE64.encode(expected_commitment.compress().as_bytes())
        );
    }

    #[test]
    fn test_password_proof_with_registration() {
        ZkpContext::clear_nonces();
        let ctx = ZkpContext::new();
        let password = "SecurePassword123!@#";
        let registration = ctx.register_password(password).unwrap();
        let proof = ctx.generate_enhanced_proof(password, &registration, "login").unwrap();
        let result = ctx
            .verify_enhanced_proof(&proof, &registration, "login", 300)
            .unwrap();
        assert!(result);
    }

    #[test]
    fn test_wrong_password_fails() {
        ZkpContext::clear_nonces();
        let ctx = ZkpContext::new();
        let correct_password = "SecurePassword123!@#";
        let wrong_password = "WrongPassword456!@#";
        
        let registration = ctx.register_password(correct_password).unwrap();
        let result = ctx.generate_enhanced_proof(wrong_password, &registration, "login");
        assert!(result.is_err());
        if let Err(AppError::CryptoError(msg)) = result {
            assert!(msg.contains("Invalid password"));
        }
    }

    #[test]
    fn test_weak_password_rejected_on_registration() {
        let ctx = ZkpContext::new();
        let weak_password = "123";
        
        let result = ctx.register_password(weak_password);
        assert!(result.is_err());
        if let Err(AppError::CryptoError(msg)) = result {
            assert!(msg.contains("entropy too low"));
        }
    }

    #[test]
    fn test_context_mismatch_fails() {
        ZkpContext::clear_nonces();
        let ctx = ZkpContext::new();
        let password = "SecurePassword123!@#$%";
        
        let registration = ctx.register_password(password).unwrap();
        let proof = ctx.generate_enhanced_proof(password, &registration, "login").unwrap();
        
        let result = ctx.verify_enhanced_proof(&proof, &registration, "register", 300);
        assert!(result.is_err());
        if let Err(AppError::CryptoError(msg)) = result {
            assert!(msg.contains("Context mismatch"));
        }
    }

    #[test]
    fn test_replay_attack_prevented() {
        ZkpContext::clear_nonces();
        let ctx = ZkpContext::new();
        let password = "SecurePassword123!@#$%";
        
        let registration = ctx.register_password(password).unwrap();
        let proof = ctx.generate_enhanced_proof(password, &registration, "login").unwrap();
        
        let result1 = ctx
            .verify_enhanced_proof(&proof, &registration, "login", 300)
            .unwrap();
        assert!(result1);
        
        let result2 = ctx.verify_enhanced_proof(&proof, &registration, "login", 300);
        assert!(result2.is_err());
        if let Err(AppError::CryptoError(msg)) = result2 {
            assert!(msg.contains("replay attack"));
        }
    }

    #[test]
    fn test_expired_proof_rejected() {
        ZkpContext::clear_nonces();
        let ctx = ZkpContext::new();
        let password = "SecurePassword123!@#$%";
        
        let registration = ctx.register_password(password).unwrap();
        let mut proof = ctx.generate_enhanced_proof(password, &registration, "login").unwrap();
        
        proof.timestamp = chrono::Utc::now().timestamp() - 400;
        
        let result = ctx.verify_enhanced_proof(&proof, &registration, "login", 300);
        assert!(result.is_err());
        if let Err(AppError::CryptoError(msg)) = result {
            assert!(msg.contains("expired"));
        }
    }

    #[test]
    fn test_entropy_calculation() {
        let weak = ZkpContext::calculate_password_entropy("abc");
        assert!(weak < MIN_PASSWORD_ENTROPY_BITS);
        
        let strong = ZkpContext::calculate_password_entropy("Str0ng!P@ssw0rd#2024");
        assert!(strong >= MIN_PASSWORD_ENTROPY_BITS);
    }

    #[test]
    fn test_multiple_registrations_different_salts() {
        let ctx = ZkpContext::new();
        let password = "SecurePassword123!@#";
        
        let reg1 = ctx.register_password(password).unwrap();
        let reg2 = ctx.register_password(password).unwrap();
        
        assert_ne!(reg1.salt, reg2.salt);
        assert_ne!(reg1.commitment, reg2.commitment);
    }

    #[test]
    fn test_proof_works_with_correct_registration() {
        ZkpContext::clear_nonces();
        let ctx = ZkpContext::new();
        let password = "SecurePassword123!@#";
        
        let reg1 = ctx.register_password(password).unwrap();
        let reg2 = ctx.register_password(password).unwrap();
        
        let proof = ctx.generate_enhanced_proof(password, &reg1, "login").unwrap();
        
        let result1 = ctx.verify_enhanced_proof(&proof, &reg1, "login", 300).unwrap();
        assert!(result1);
        
        ZkpContext::clear_nonces();
        
        let result2 = ctx.verify_enhanced_proof(&proof, &reg2, "login", 300).unwrap();
        assert!(!result2);
    }
}
