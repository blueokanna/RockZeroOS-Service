use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use rockzero_common::error::AppError;

const RANGE_PROOF_BITS: usize = 64;
const MIN_VALUE: u64 = 0;
const MAX_VALUE: u64 = u64::MAX;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(C)]
pub struct BulletproofsRangeProof {
    pub proof: String,
    pub commitment: String,
    pub value_blinding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(C)]
pub struct BulletproofsVerifyResult {
    pub valid: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(C)]
pub struct VideoStreamProof {
    pub session_id: String,
    pub segment_index: u64,
    pub timestamp: i64,
    pub range_proof: BulletproofsRangeProof,
    pub content_hash: String,
    pub signature: String,
}

pub struct BulletproofsContext {
    pedersen_gens: PedersenGens,
    bulletproof_gens: BulletproofGens,
}

impl BulletproofsContext {
    pub fn new() -> Self {
        Self {
            pedersen_gens: PedersenGens::default(),
            bulletproof_gens: BulletproofGens::new(RANGE_PROOF_BITS, 1),
        }
    }

    pub fn create_range_proof(&self, value: u64) -> Result<BulletproofsRangeProof, AppError> {
        if value < MIN_VALUE || value > MAX_VALUE {
            return Err(AppError::CryptoError(format!(
                "Value {} out of range [{}, {}]",
                value, MIN_VALUE, MAX_VALUE
            )));
        }

        let blinding = Self::generate_random_scalar()?;

        let mut transcript = Transcript::new(b"RockZero-Bulletproofs-RangeProof");

        let (proof, commitment) = RangeProof::prove_single(
            &self.bulletproof_gens,
            &self.pedersen_gens,
            &mut transcript,
            value,
            &blinding,
            RANGE_PROOF_BITS,
        )
        .map_err(|e| AppError::CryptoError(format!("Range proof generation failed: {:?}", e)))?;

        Ok(BulletproofsRangeProof {
            proof: BASE64.encode(proof.to_bytes()),
            commitment: BASE64.encode(commitment.as_bytes()),
            value_blinding: BASE64.encode(blinding.as_bytes()),
        })
    }

    pub fn verify_range_proof(
        &self,
        proof_data: &BulletproofsRangeProof,
    ) -> Result<BulletproofsVerifyResult, AppError> {
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

        let mut transcript = Transcript::new(b"RockZero-Bulletproofs-RangeProof");

        match proof.verify_single(
            &self.bulletproof_gens,
            &self.pedersen_gens,
            &mut transcript,
            &commitment,
            RANGE_PROOF_BITS,
        ) {
            Ok(_) => Ok(BulletproofsVerifyResult {
                valid: true,
                error_message: None,
            }),
            Err(e) => Ok(BulletproofsVerifyResult {
                valid: false,
                error_message: Some(format!("{:?}", e)),
            }),
        }
    }

    pub fn create_video_stream_proof(
        &self,
        session_id: &str,
        segment_index: u64,
        content: &[u8],
        signing_key: &[u8; 32],
    ) -> Result<VideoStreamProof, AppError> {
        let timestamp = chrono::Utc::now().timestamp();

        let range_proof = self.create_range_proof(segment_index)?;

        let content_hash = blake3::hash(content);
        let content_hash_str = BASE64.encode(content_hash.as_bytes());

        let signature_data = format!(
            "{}:{}:{}:{}",
            session_id, segment_index, timestamp, content_hash_str
        );

        let signature = self.sign_with_hmac(signing_key, signature_data.as_bytes())?;

        Ok(VideoStreamProof {
            session_id: session_id.to_string(),
            segment_index,
            timestamp,
            range_proof,
            content_hash: content_hash_str,
            signature,
        })
    }

    pub fn verify_video_stream_proof(
        &self,
        proof: &VideoStreamProof,
        expected_session_id: &str,
        signing_key: &[u8; 32],
        max_age_seconds: i64,
    ) -> Result<bool, AppError> {
        if proof.session_id != expected_session_id {
            return Err(AppError::CryptoError("Session ID mismatch".to_string()));
        }

        let now = chrono::Utc::now().timestamp();
        if now - proof.timestamp > max_age_seconds {
            return Err(AppError::CryptoError("Proof expired".to_string()));
        }

        if proof.timestamp > now + 60 {
            return Err(AppError::CryptoError("Proof timestamp in future".to_string()));
        }

        let range_result = self.verify_range_proof(&proof.range_proof)?;
        if !range_result.valid {
            return Err(AppError::CryptoError(format!(
                "Range proof invalid: {:?}",
                range_result.error_message
            )));
        }

        let signature_data = format!(
            "{}:{}:{}:{}",
            proof.session_id, proof.segment_index, proof.timestamp, proof.content_hash
        );

        let expected_signature = self.sign_with_hmac(signing_key, signature_data.as_bytes())?;

        if !constant_time_compare(&proof.signature, &expected_signature) {
            return Err(AppError::CryptoError("Invalid signature".to_string()));
        }

        Ok(true)
    }

    fn generate_random_scalar() -> Result<Scalar, AppError> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|_| AppError::CryptoError("Failed to generate random scalar".to_string()))?;
        Ok(Scalar::from_bytes_mod_order(bytes))
    }

    fn sign_with_hmac(&self, key: &[u8; 32], message: &[u8]) -> Result<String, AppError> {
        let mut input = Vec::with_capacity(32 + message.len());
        input.extend_from_slice(key);
        input.extend_from_slice(message);
        let hash = blake3::hash(&input);
        Ok(BASE64.encode(hash.as_bytes()))
    }
}

impl Default for BulletproofsContext {
    fn default() -> Self {
        Self::new()
    }
}

fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

#[no_mangle]
pub extern "C" fn bulletproofs_create_range_proof(
    value: u64,
    out_proof: *mut *mut u8,
    out_proof_len: *mut usize,
) -> i32 {
    let ctx = BulletproofsContext::new();

    match ctx.create_range_proof(value) {
        Ok(proof) => {
            let json = match serde_json::to_string(&proof) {
                Ok(j) => j,
                Err(_) => return -2,
            };

            let bytes = json.into_bytes();
            let len = bytes.len();
            let ptr = bytes.as_ptr();

            unsafe {
                *out_proof = ptr as *mut u8;
                *out_proof_len = len;
            }

            std::mem::forget(bytes);
            0
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn bulletproofs_verify_range_proof(
    proof_json: *const u8,
    proof_json_len: usize,
) -> i32 {
    let json_slice = unsafe { std::slice::from_raw_parts(proof_json, proof_json_len) };

    let json_str = match std::str::from_utf8(json_slice) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let proof: BulletproofsRangeProof = match serde_json::from_str(json_str) {
        Ok(p) => p,
        Err(_) => return -2,
    };

    let ctx = BulletproofsContext::new();

    match ctx.verify_range_proof(&proof) {
        Ok(result) => {
            if result.valid {
                1
            } else {
                0
            }
        }
        Err(_) => -3,
    }
}

#[no_mangle]
pub extern "C" fn bulletproofs_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            let _ = Vec::from_raw_parts(ptr, len, len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_proof_creation_and_verification() {
        let ctx = BulletproofsContext::new();

        let value = 42u64;
        let proof = ctx.create_range_proof(value).unwrap();

        let result = ctx.verify_range_proof(&proof).unwrap();
        assert!(result.valid);
    }

    #[test]
    fn test_video_stream_proof() {
        let ctx = BulletproofsContext::new();

        let session_id = "test-session-123";
        let segment_index = 5u64;
        let content = b"video segment data";
        let signing_key = [0x42u8; 32];

        let proof = ctx
            .create_video_stream_proof(session_id, segment_index, content, &signing_key)
            .unwrap();

        let result = ctx
            .verify_video_stream_proof(&proof, session_id, &signing_key, 300)
            .unwrap();

        assert!(result);
    }

    #[test]
    fn test_video_stream_proof_wrong_session() {
        let ctx = BulletproofsContext::new();

        let session_id = "test-session-123";
        let segment_index = 5u64;
        let content = b"video segment data";
        let signing_key = [0x42u8; 32];

        let proof = ctx
            .create_video_stream_proof(session_id, segment_index, content, &signing_key)
            .unwrap();

        let result = ctx.verify_video_stream_proof(&proof, "wrong-session", &signing_key, 300);

        assert!(result.is_err());
    }

    #[test]
    fn test_range_proof_large_value() {
        let ctx = BulletproofsContext::new();

        let value = 1_000_000u64;
        let proof = ctx.create_range_proof(value).unwrap();

        let result = ctx.verify_range_proof(&proof).unwrap();
        assert!(result.valid);
    }
}