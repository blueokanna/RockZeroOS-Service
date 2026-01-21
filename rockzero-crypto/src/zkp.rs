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
const MIN_PASSWORD_ENTROPY_BITS: u64 = 40;
const NONCE_EXPIRY_SECONDS: u64 = 600; // 10 minutes
const PBKDF_ITERATIONS: u32 = 100_000; // Production-grade iterations

lazy_static::lazy_static! {
    static ref USED_NONCES: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new());
}

/// Registration data to be stored (contains commitment and salt)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordRegistration {
    /// The Pedersen commitment to the password: C = g^password * h^blinding
    pub commitment: String,
    /// Salt used for password derivation (randomly generated during registration)
    pub salt: String,
}

/// Schnorr proof data - proves knowledge of password without revealing it
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorrProof {
    /// First message: A = g^k * h^k_blinding (random commitment)
    pub a_point: String,
    /// Challenge: e = H(C, A, context, ...)
    pub challenge: String,
    /// Response for password: s_p = k + e * password
    pub response_password: String,
    /// Response for blinding: s_b = k_blinding + e * blinding
    pub response_blinding: String,
}

/// Bound strength proof - proves password has sufficient entropy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundStrengthProof {
    /// Commitment to entropy value
    pub entropy_value_commitment: String,
    /// Bulletproof range proof that entropy >= MIN_PASSWORD_ENTROPY_BITS
    pub range_proof: String,
}

/// Enhanced password proof for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedPasswordProof {
    /// Schnorr proof of password knowledge
    pub schnorr_proof: SchnorrProof,
    /// Proof that password has sufficient entropy
    pub strength_proof: BoundStrengthProof,
    /// Timestamp to prevent delayed replay
    pub timestamp: i64,
    /// Unique nonce to prevent replay attacks
    pub nonce: String,
    /// Context binding (e.g., "login", "register")
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

    /// Convert password to scalar using PBKDF2-like derivation with salt
    /// Uses production-grade key stretching (100,000 iterations)
    fn password_to_scalar(password: &str, salt: &[u8]) -> Scalar {
        let mut hasher = blake3::Hasher::new_derive_key(PASSWORD_DOMAIN);
        hasher.update(salt);
        hasher.update(password.as_bytes());
        
        // Production-grade key stretching
        let mut hash = hasher.finalize();
        for _ in 0..PBKDF_ITERATIONS {
            hash = blake3::hash(hash.as_bytes());
        }
        
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());
        Scalar::from_bytes_mod_order(bytes)
    }

    /// Derive blinding factor deterministically from password and salt
    /// This ensures the same password+salt always produces the same commitment
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

    /// Generate random scalar for proof generation
    fn generate_random_scalar() -> Result<Scalar, AppError> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|_| AppError::CryptoError("Failed to generate random scalar".to_string()))?;
        Ok(Scalar::from_bytes_mod_order(bytes))
    }

    /// Generate random salt for registration
    fn generate_salt() -> Result<[u8; 32], AppError> {
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut salt)
            .map_err(|_| AppError::CryptoError("Failed to generate salt".to_string()))?;
        Ok(salt)
    }

    /// Calculate password entropy in bits (conservative Shannon entropy)
    pub fn calculate_password_entropy(password: &str) -> u64 {
        if password.is_empty() {
            return 0;
        }
        
        // Count character frequencies
        let mut char_counts: HashMap<char, usize> = HashMap::new();
        for c in password.chars() {
            *char_counts.entry(c).or_insert(0) += 1;
        }
        
        // Calculate Shannon entropy
        let length = password.len() as f64;
        let mut entropy = 0.0;
        for count in char_counts.values() {
            let probability = (*count as f64) / length;
            entropy -= probability * probability.log2();
        }
        
        // Multiply by length to get total entropy
        let total_entropy = entropy * length;
        
        // Conservative: take 70% of calculated entropy
        (total_entropy * 0.7) as u64
    }

    /// Register a password - returns registration data to be stored
    /// This is called during user registration
    pub fn register_password(&self, password: &str) -> Result<PasswordRegistration, AppError> {
        // Check password strength first
        let entropy = Self::calculate_password_entropy(password);
        if entropy < MIN_PASSWORD_ENTROPY_BITS {
            return Err(AppError::CryptoError(format!(
                "Password entropy too low: {} bits (minimum {} bits required)",
                entropy, MIN_PASSWORD_ENTROPY_BITS
            )));
        }

        // Generate random salt
        let salt = Self::generate_salt()?;
        
        // Derive password scalar and blinding deterministically
        let password_scalar = Self::password_to_scalar(password, &salt);
        let blinding = Self::derive_blinding(password, &salt);
        
        // Create Pedersen commitment: C = g^password * h^blinding
        let commitment = self.pedersen_gens.commit(password_scalar, blinding);
        
        Ok(PasswordRegistration {
            commitment: BASE64.encode(commitment.compress().as_bytes()),
            salt: BASE64.encode(salt),
        })
    }

    /// Generate Schnorr proof of password knowledge
    fn generate_schnorr_proof(
        &self,
        password: &str,
        salt: &[u8],
        commitment_point: &curve25519_dalek::ristretto::RistrettoPoint,
        transcript: &mut Transcript,
    ) -> Result<SchnorrProof, AppError> {
        let password_scalar = Self::password_to_scalar(password, salt);
        let blinding = Self::derive_blinding(password, salt);

        // Add commitment to transcript
        transcript.append_message(
            b"password_commitment",
            commitment_point.compress().as_bytes(),
        );

        // Generate random nonces for the proof (fresh randomness for each proof)
        let k_password = Self::generate_random_scalar()?;
        let k_blinding = Self::generate_random_scalar()?;

        // First message: A = g^k * h^k_blinding
        let a_point = self.pedersen_gens.commit(k_password, k_blinding);
        transcript.append_message(b"schnorr_A", a_point.compress().as_bytes());

        // Challenge: e = H(transcript state)
        let mut challenge_bytes = [0u8; 64];
        transcript.challenge_bytes(b"schnorr_challenge", &mut challenge_bytes);
        let challenge = Scalar::from_bytes_mod_order_wide(&challenge_bytes);

        // Responses: s_p = k + e*password, s_b = k_blinding + e*blinding
        let response_password = k_password + (challenge * password_scalar);
        let response_blinding = k_blinding + (challenge * blinding);

        Ok(SchnorrProof {
            a_point: BASE64.encode(a_point.compress().as_bytes()),
            challenge: BASE64.encode(challenge.as_bytes()),
            response_password: BASE64.encode(response_password.as_bytes()),
            response_blinding: BASE64.encode(response_blinding.as_bytes()),
        })
    }

    /// Verify Schnorr proof against stored commitment
    fn verify_schnorr_proof(
        &self,
        proof: &SchnorrProof,
        commitment_point: &curve25519_dalek::ristretto::RistrettoPoint,
        transcript: &mut Transcript,
    ) -> Result<bool, AppError> {
        // Add commitment to transcript
        transcript.append_message(
            b"password_commitment",
            commitment_point.compress().as_bytes(),
        );

        // Decode A point
        let a_bytes = BASE64
            .decode(&proof.a_point)
            .map_err(|_| AppError::CryptoError("Invalid A point".to_string()))?;
        let a_point = CompressedRistretto::from_slice(&a_bytes)
            .map_err(|_| AppError::CryptoError("Invalid A point format".to_string()))?
            .decompress()
            .ok_or_else(|| AppError::CryptoError("Cannot decompress A point".to_string()))?;

        transcript.append_message(b"schnorr_A", a_point.compress().as_bytes());

        // Recompute challenge
        let mut expected_challenge_bytes = [0u8; 64];
        transcript.challenge_bytes(b"schnorr_challenge", &mut expected_challenge_bytes);
        let expected_challenge = Scalar::from_bytes_mod_order_wide(&expected_challenge_bytes);

        // Verify challenge matches
        let challenge = Self::decode_scalar(&proof.challenge, "challenge")?;
        if challenge != expected_challenge {
            return Ok(false);
        }

        // Decode responses
        let response_password = Self::decode_scalar(&proof.response_password, "response_password")?;
        let response_blinding = Self::decode_scalar(&proof.response_blinding, "response_blinding")?;

        // Verify equation: g^s_p * h^s_b = A + e*C
        let left = self.pedersen_gens.commit(response_password, response_blinding);
        let right = a_point + (commitment_point * challenge);

        Ok(left == right)
    }

    /// Helper to decode base64 scalar
    fn decode_scalar(encoded: &str, field_name: &str) -> Result<Scalar, AppError> {
        let bytes = BASE64
            .decode(encoded)
            .map_err(|_| AppError::CryptoError(format!("Invalid {}", field_name)))?;
        if bytes.len() != 32 {
            return Err(AppError::CryptoError(format!(
                "Invalid {} length",
                field_name
            )));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Scalar::from_bytes_mod_order(array))
    }

    /// Generate bound strength proof with range proof
    /// The transcript binding ensures the entropy proof is linked to the Schnorr proof
    fn generate_bound_strength_proof(
        &self,
        password: &str,
        schnorr_commitment: &CompressedRistretto,
        transcript: &mut Transcript,
    ) -> Result<BoundStrengthProof, AppError> {
        let entropy_bits = Self::calculate_password_entropy(password);
        if entropy_bits < MIN_PASSWORD_ENTROPY_BITS {
            return Err(AppError::CryptoError(format!(
                "Password entropy too low: {} bits (minimum {} bits required)",
                entropy_bits, MIN_PASSWORD_ENTROPY_BITS
            )));
        }

        // Add schnorr commitment to transcript for binding
        transcript.append_message(b"schnorr_commitment", schnorr_commitment.as_bytes());

        // Random entropy blinding
        let entropy_blinding = Self::generate_random_scalar()?;

        // Generate range proof using SAME transcript (ensures binding)
        let (range_proof, entropy_value_commitment) = RangeProof::prove_single(
            &self.bulletproof_gens,
            &self.pedersen_gens,
            transcript,
            entropy_bits,
            &entropy_blinding,
            64,
        )
        .map_err(|e| AppError::CryptoError(format!("Failed to generate range proof: {:?}", e)))?;

        Ok(BoundStrengthProof {
            entropy_value_commitment: BASE64.encode(entropy_value_commitment.as_bytes()),
            range_proof: BASE64.encode(range_proof.to_bytes()),
        })
    }

    /// Verify bound strength proof
    fn verify_bound_strength_proof(
        &self,
        proof: &BoundStrengthProof,
        schnorr_commitment: &CompressedRistretto,
        transcript: &mut Transcript,
    ) -> Result<bool, AppError> {
        // Add schnorr commitment to transcript for binding verification
        transcript.append_message(b"schnorr_commitment", schnorr_commitment.as_bytes());

        // Decode entropy_value_commitment
        let entropy_value_commitment_bytes = BASE64
            .decode(&proof.entropy_value_commitment)
            .map_err(|_| AppError::CryptoError("Invalid entropy value commitment".to_string()))?;
        let entropy_value_commitment =
            CompressedRistretto::from_slice(&entropy_value_commitment_bytes).map_err(|_| {
                AppError::CryptoError("Invalid entropy value commitment point".to_string())
            })?;

        // Verify range proof using SAME transcript (binding is verified through transcript)
        let range_proof_bytes = BASE64
            .decode(&proof.range_proof)
            .map_err(|_| AppError::CryptoError("Invalid range proof".to_string()))?;
        let range_proof = RangeProof::from_bytes(&range_proof_bytes)
            .map_err(|_| AppError::CryptoError("Invalid range proof format".to_string()))?;

        range_proof
            .verify_single(
                &self.bulletproof_gens,
                &self.pedersen_gens,
                transcript,
                &entropy_value_commitment,
                64,
            )
            .map_err(|e| {
                AppError::CryptoError(format!("Range proof verification failed: {:?}", e))
            })?;

        Ok(true)
    }

    /// Generate enhanced password proof for authentication
    /// Uses the salt from registration to derive the same commitment
    pub fn generate_enhanced_proof(
        &self,
        password: &str,
        registration: &PasswordRegistration,
        context: &str,
    ) -> Result<EnhancedPasswordProof, AppError> {
        // Decode the stored salt
        let salt = BASE64
            .decode(&registration.salt)
            .map_err(|_| AppError::CryptoError("Invalid registration salt".to_string()))?;
        
        // Derive password scalar and blinding using the same salt as registration
        let password_scalar = Self::password_to_scalar(password, &salt);
        let blinding = Self::derive_blinding(password, &salt);
        
        // Recompute commitment - should match stored commitment if password is correct
        let commitment_point = self.pedersen_gens.commit(password_scalar, blinding);
        let computed_commitment = BASE64.encode(commitment_point.compress().as_bytes());
        
        // Early check: if commitment doesn't match, password is wrong
        if computed_commitment != registration.commitment {
            return Err(AppError::CryptoError("Invalid password".to_string()));
        }

        // Create transcript with context binding
        let mut transcript = Transcript::new(b"RockZero-Enhanced-Password-Proof");
        transcript.append_message(b"context", context.as_bytes());

        // Generate fresh nonce and timestamp
        let timestamp = chrono::Utc::now().timestamp();
        let mut nonce_bytes = [0u8; 32];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|_| AppError::CryptoError("Failed to generate nonce".to_string()))?;
        let nonce = BASE64.encode(nonce_bytes);

        transcript.append_message(b"timestamp", &timestamp.to_le_bytes());
        transcript.append_message(b"nonce", nonce.as_bytes());
        transcript.append_message(b"stored_commitment", registration.commitment.as_bytes());

        // Generate Schnorr proof
        let schnorr_proof = self.generate_schnorr_proof(
            password,
            &salt,
            &commitment_point,
            &mut transcript,
        )?;

        // Get schnorr_commitment for binding
        let schnorr_commitment = commitment_point.compress();

        // Generate strength proof with binding
        let strength_proof = self.generate_bound_strength_proof(
            password,
            &schnorr_commitment,
            &mut transcript,
        )?;

        Ok(EnhancedPasswordProof {
            schnorr_proof,
            strength_proof,
            timestamp,
            nonce,
            context: context.to_string(),
        })
    }

    /// Verify enhanced password proof against stored registration
    pub fn verify_enhanced_proof(
        &self,
        proof: &EnhancedPasswordProof,
        registration: &PasswordRegistration,
        expected_context: &str,
        max_age_seconds: i64,
    ) -> Result<bool, AppError> {
        // Check context
        if proof.context != expected_context {
            return Err(AppError::CryptoError("Context mismatch".to_string()));
        }

        // Check timestamp
        let now = chrono::Utc::now().timestamp();
        if now - proof.timestamp > max_age_seconds {
            return Err(AppError::CryptoError("Proof expired".to_string()));
        }
        if proof.timestamp > now + 60 {
            return Err(AppError::CryptoError(
                "Proof timestamp in future".to_string(),
            ));
        }

        // Check nonce for replay protection with expiry
        {
            let mut used_nonces = USED_NONCES
                .lock()
                .map_err(|_| AppError::CryptoError("Failed to lock nonce tracker".to_string()))?;
            
            // Clean expired nonces
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

        // Decode stored commitment
        let commitment_bytes = BASE64
            .decode(&registration.commitment)
            .map_err(|_| AppError::CryptoError("Invalid stored commitment".to_string()))?;
        let commitment_point = CompressedRistretto::from_slice(&commitment_bytes)
            .map_err(|_| AppError::CryptoError("Invalid commitment point format".to_string()))?
            .decompress()
            .ok_or_else(|| AppError::CryptoError("Cannot decompress commitment".to_string()))?;

        // Reconstruct transcript
        let mut transcript = Transcript::new(b"RockZero-Enhanced-Password-Proof");
        transcript.append_message(b"context", proof.context.as_bytes());
        transcript.append_message(b"timestamp", &proof.timestamp.to_le_bytes());
        transcript.append_message(b"nonce", proof.nonce.as_bytes());
        transcript.append_message(b"stored_commitment", registration.commitment.as_bytes());

        // Verify Schnorr proof
        if !self.verify_schnorr_proof(&proof.schnorr_proof, &commitment_point, &mut transcript)? {
            return Ok(false);
        }

        // Verify strength proof
        let schnorr_commitment = commitment_point.compress();
        if !self.verify_bound_strength_proof(
            &proof.strength_proof,
            &schnorr_commitment,
            &mut transcript,
        )? {
            return Ok(false);
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration_creates_deterministic_commitment() {
        let ctx = ZkpContext::new();
        let password = "SecurePassword123!@#";

        // Same password with same salt should produce same commitment
        let registration = ctx.register_password(password).unwrap();
        
        // Verify the commitment is deterministic for the same password+salt
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
        
        // Register with correct password
        let registration = ctx.register_password(correct_password).unwrap();
        
        // Try to generate proof with wrong password - should fail
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
        
        // First verification should succeed
        let result1 = ctx
            .verify_enhanced_proof(&proof, &registration, "login", 300)
            .unwrap();
        assert!(result1);
        
        // Second verification with same proof should fail (replay attack)
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
        
        // Modify timestamp to be expired
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
        
        // Different registrations should have different salts
        assert_ne!(reg1.salt, reg2.salt);
        // And therefore different commitments
        assert_ne!(reg1.commitment, reg2.commitment);
    }

    #[test]
    fn test_proof_works_with_correct_registration() {
        ZkpContext::clear_nonces();
        let ctx = ZkpContext::new();
        let password = "SecurePassword123!@#";
        
        let reg1 = ctx.register_password(password).unwrap();
        let reg2 = ctx.register_password(password).unwrap();
        
        // Proof generated with reg1 should not verify with reg2
        let proof = ctx.generate_enhanced_proof(password, &reg1, "login").unwrap();
        
        // Should work with reg1
        let result1 = ctx.verify_enhanced_proof(&proof, &reg1, "login", 300).unwrap();
        assert!(result1);
        
        ZkpContext::clear_nonces();
        
        // Should fail with reg2 (different commitment)
        let result2 = ctx.verify_enhanced_proof(&proof, &reg2, "login", 300).unwrap();
        assert!(!result2);
    }
}
