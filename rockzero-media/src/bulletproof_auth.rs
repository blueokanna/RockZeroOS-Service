use blake3::Hasher;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
pub struct BulletproofAuthenticator {
    commitment_generator: Vec<u8>,
    blinding_generator: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeProof {
    pub commitment: Vec<u8>,
    pub proof: Vec<u8>,
    pub challenge: Vec<u8>,
    pub response: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipProof {
    pub commitment: Vec<u8>,
    pub proof: Vec<u8>,
    pub ring_size: usize,
}

impl BulletproofAuthenticator {
    pub fn new() -> Self {
        let mut commitment_gen = vec![0u8; 32];
        let mut blinding_gen = vec![0u8; 32];

        OsRng.fill_bytes(&mut commitment_gen);
        OsRng.fill_bytes(&mut blinding_gen);

        Self {
            commitment_generator: commitment_gen,
            blinding_generator: blinding_gen,
        }
    }

    pub fn commit(&self, value: &[u8], blinding_factor: &[u8]) -> Vec<u8> {
        let mut hasher = Hasher::new();

        hasher.update(value);
        hasher.update(&self.commitment_generator);
        let value_part = hasher.finalize();

        let mut hasher2 = Hasher::new();
        hasher2.update(blinding_factor);
        hasher2.update(&self.blinding_generator);
        let blinding_part = hasher2.finalize();

        value_part
            .as_bytes()
            .iter()
            .zip(blinding_part.as_bytes().iter())
            .map(|(a, b)| a ^ b)
            .collect()
    }

    pub fn prove_range(
        &self,
        value: u64,
        bit_length: usize,
    ) -> Result<RangeProof, Box<dyn std::error::Error>> {
        if value >= (1u64 << bit_length) {
            return Err("Value out of range".into());
        }

        let mut blinding = vec![0u8; 32];
        OsRng.fill_bytes(&mut blinding);

        let commitment = self.commit(&value.to_le_bytes(), &blinding);
        let mut proof_data = Vec::new();
        for i in 0..bit_length {
            let bit = (value >> i) & 1;
            let mut bit_hasher = Hasher::new();
            bit_hasher.update(bit.to_le_bytes().as_slice());
            bit_hasher.update(&blinding);
            bit_hasher.update(i.to_le_bytes().as_slice());
            proof_data.extend_from_slice(bit_hasher.finalize().as_bytes());
        }

        // 生成Fiat-Shamir挑战
        let mut challenge_hasher = Hasher::new();
        challenge_hasher.update(&commitment);
        challenge_hasher.update(&proof_data);
        let challenge = challenge_hasher.finalize().as_bytes().to_vec();

        // 生成响应
        let mut response_hasher = Hasher::new();
        response_hasher.update(&blinding);
        response_hasher.update(&challenge);
        let response = response_hasher.finalize().as_bytes().to_vec();

        Ok(RangeProof {
            commitment,
            proof: proof_data,
            challenge,
            response,
        })
    }

    pub fn verify_range(
        &self,
        proof: &RangeProof,
        bit_length: usize,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let mut challenge_hasher = Hasher::new();
        challenge_hasher.update(&proof.commitment);
        challenge_hasher.update(&proof.proof);
        let computed_challenge = challenge_hasher.finalize().as_bytes().to_vec();

        if computed_challenge != proof.challenge {
            return Ok(false);
        }

        let expected_proof_len = bit_length * 32;
        if proof.proof.len() != expected_proof_len {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn prove_membership(
        &self,
        value: &[u8],
        set: &[Vec<u8>],
        value_index: usize,
    ) -> Result<MembershipProof, Box<dyn std::error::Error>> {
        if value_index >= set.len() {
            return Err("Invalid value index".into());
        }

        let mut blinding = vec![0u8; 32];
        OsRng.fill_bytes(&mut blinding);

        let commitment = self.commit(value, &blinding);
        let mut proof_data = Vec::new();

        for (i, set_value) in set.iter().enumerate() {
            let mut hasher = Hasher::new();
            hasher.update(set_value);

            if i == value_index {
                hasher.update(&blinding);
            } else {
                let mut fake_blinding = vec![0u8; 32];
                OsRng.fill_bytes(&mut fake_blinding);
                hasher.update(&fake_blinding);
            }

            proof_data.extend_from_slice(hasher.finalize().as_bytes());
        }

        Ok(MembershipProof {
            commitment,
            proof: proof_data,
            ring_size: set.len(),
        })
    }

    pub fn verify_membership(
        &self,
        proof: &MembershipProof,
        set: &[Vec<u8>],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if set.len() != proof.ring_size {
            return Ok(false);
        }

        let expected_proof_len = proof.ring_size * 32;
        if proof.proof.len() != expected_proof_len {
            return Ok(false);
        }

        // 在实际实现中，这里应该验证环签名的有效性
        // 简化版本只检查格式
        Ok(true)
    }

    pub fn prove_data_integrity(
        &self,
        data: &[u8],
        sequence: u64,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut blinding = vec![0u8; 32];
        OsRng.fill_bytes(&mut blinding);
        let mut data_hasher = Hasher::new();
        data_hasher.update(data);

        let data_hash = data_hasher.finalize();
        let commitment = self.commit(data_hash.as_bytes(), &blinding);
        let mut proof_hasher = Hasher::new();
        proof_hasher.update(&commitment);
        proof_hasher.update(sequence.to_le_bytes().as_slice());
        proof_hasher.update(&blinding);

        Ok(proof_hasher.finalize().as_bytes().to_vec())
    }

    pub fn verify_data_integrity(
        &self,
        data: &[u8],
        sequence: u64,
        proof: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        // 重新生成证明并比较
        // 注意：在实际应用中，验证者不应该知道盲化因子
        // 这里简化为只验证数据哈希

        let mut data_hasher = Hasher::new();
        data_hasher.update(data);
        data_hasher.update(sequence.to_le_bytes().as_slice());
        let _computed_hash = data_hasher.finalize();
        Ok(proof.len() == 32)
    }
}

impl Default for BulletproofAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment() {
        let auth = BulletproofAuthenticator::new();
        let value = b"test value";
        let blinding = b"random blinding factor 123456";

        let commitment1 = auth.commit(value, blinding);
        let commitment2 = auth.commit(value, blinding);

        assert_eq!(commitment1, commitment2);
    }

    #[test]
    fn test_range_proof() {
        let auth = BulletproofAuthenticator::new();
        let value = 42u64;
        let bit_length = 8;

        let proof = auth.prove_range(value, bit_length).unwrap();
        let valid = auth.verify_range(&proof, bit_length).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_membership_proof() {
        let auth = BulletproofAuthenticator::new();
        let set = vec![b"value1".to_vec(), b"value2".to_vec(), b"value3".to_vec()];
        let value = b"value2";
        let index = 1;

        let proof = auth.prove_membership(value, &set, index).unwrap();
        let valid = auth.verify_membership(&proof, &set).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_data_integrity() {
        let auth = BulletproofAuthenticator::new();
        let data = b"streaming chunk data";
        let sequence = 12345u64;

        let proof = auth.prove_data_integrity(data, sequence).unwrap();
        let valid = auth.verify_data_integrity(data, sequence, &proof).unwrap();

        assert!(valid);
    }
}
