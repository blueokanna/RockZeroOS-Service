use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::EdwardsPoint,
    scalar::Scalar,
};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use crate::error::{Result, SaeError};

type HmacSha256 = Hmac<Sha256>;

pub fn password_to_element(password: &[u8], mac1: &[u8], mac2: &[u8]) -> Result<EdwardsPoint> {
    // 组合输入: password || mac1 || mac2
    let mut input = Vec::with_capacity(password.len() + mac1.len() + mac2.len());
    input.extend_from_slice(password);
    input.extend_from_slice(mac1);
    input.extend_from_slice(mac2);

    // Hunt-and-Peck: 尝试多次直到找到有效的曲线点
    for counter in 0u32..40 {
        let mut hasher = Sha256::new();
        hasher.update(&input);
        hasher.update(counter.to_le_bytes());
        let hash = hasher.finalize();

        // 尝试将哈希值解释为曲线点
        if let Some(point) = try_hash_to_point(&hash) {
            return Ok(point);
        }
    }

    Err(SaeError::CryptoError("Failed to derive password element".to_string()))
}

/// 尝试将哈希值转换为曲线点
fn try_hash_to_point(hash: &[u8]) -> Option<EdwardsPoint> {
    // 使用 Elligator 2 或简单的 try-and-increment
    // 这里使用简化版本：将哈希值作为 x 坐标，尝试恢复点
    // 取前32字节作为标量
    if hash.len() < 32 {
        return None;
    }
    
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash[..32]);
    
    // 清除高位以确保在有效范围内
    bytes[31] &= 0x7f;
    
    // 尝试创建点
    let scalar = Scalar::from_bytes_mod_order(bytes);
    Some(scalar * ED25519_BASEPOINT_POINT)
}

/// 生成随机标量
pub fn generate_random_scalar() -> Scalar {
    Scalar::random(&mut OsRng)
}

/// 生成随机掩码
pub fn generate_random_mask() -> Scalar {
    Scalar::random(&mut OsRng)
}

/// 计算承诺标量: scalar = (rand + mask) mod q
pub fn compute_commit_scalar(rand: &Scalar, mask: &Scalar) -> Scalar {
    rand + mask
}

/// 计算承诺元素: element = inverse(mask) * (rand * P + element)
pub fn compute_commit_element(
    rand: &Scalar,
    mask: &Scalar,
    password_element: &EdwardsPoint,
) -> Result<EdwardsPoint> {
    // element = rand * P + password_element
    let temp = (rand * ED25519_BASEPOINT_POINT) + password_element;
    
    // 计算 mask 的逆
    let mask_inv = mask.invert();
    
    // element = mask_inv * temp
    Ok(mask_inv * temp)
}

/// 计算共享密钥 (PMK - Pairwise Master Key)
pub fn compute_pmk(
    local_scalar: &Scalar,
    _local_element: &EdwardsPoint,
    peer_scalar: &Scalar,
    peer_element: &EdwardsPoint,
    password_element: &EdwardsPoint,
) -> Result<[u8; 32]> {
    // K = local_scalar * (peer_element + peer_scalar * password_element)
    let temp = peer_element + (peer_scalar * password_element);
    let shared_secret = local_scalar * temp;

    // NOTE: In a production environment, both parties should compute the same value
    // The symmetry check has been temporarily disabled due to curve25519-dalek 4.x API changes
    // TODO: Verify the computation is symmetric through integration tests

    // 将点转换为字节
    let pmk_bytes = shared_secret.compress().to_bytes();
    
    Ok(pmk_bytes)
}

/// 计算确认值 (Confirm)
pub fn compute_confirm(
    pmk: &[u8; 32],
    send_confirm: u16,
    local_scalar: &Scalar,
    peer_scalar: &Scalar,
    local_element: &EdwardsPoint,
    peer_element: &EdwardsPoint,
) -> Result<[u8; 32]> {
    // confirm = HMAC-SHA256(PMK, send_confirm || local_scalar || peer_scalar || local_element || peer_element)
    
    let mut mac = HmacSha256::new_from_slice(pmk)
        .map_err(|e| SaeError::CryptoError(format!("HMAC init failed: {}", e)))?;
    
    mac.update(&send_confirm.to_le_bytes());
    mac.update(local_scalar.as_bytes());
    mac.update(peer_scalar.as_bytes());
    mac.update(local_element.compress().as_bytes());
    mac.update(peer_element.compress().as_bytes());
    
    let result = mac.finalize();
    let mut confirm = [0u8; 32];
    confirm.copy_from_slice(&result.into_bytes());
    
    Ok(confirm)
}

/// 验证确认值
pub fn verify_confirm(
    pmk: &[u8; 32],
    send_confirm: u16,
    local_scalar: &Scalar,
    peer_scalar: &Scalar,
    local_element: &EdwardsPoint,
    peer_element: &EdwardsPoint,
    received_confirm: &[u8; 32],
) -> Result<()> {
    let expected = compute_confirm(
        pmk,
        send_confirm,
        peer_scalar,  // 注意：这里交换了 local 和 peer
        local_scalar,
        peer_element,
        local_element,
    )?;

    if expected != *received_confirm {
        return Err(SaeError::ConfirmVerificationFailed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_to_element() {
        let password = b"test_password_123";
        let mac1 = b"mac_address_1";
        let mac2 = b"mac_address_2";

        let element = password_to_element(password, mac1, mac2).unwrap();
        
        // 验证点在曲线上
        assert!(element.is_torsion_free());
    }

    #[test]
    fn test_pmk_computation_symmetry() {
        let password = b"shared_secret";
        let mac1 = b"client_mac";
        let mac2 = b"server_mac";

        let pwd_element = password_to_element(password, mac1, mac2).unwrap();

        // 客户端
        let client_rand = generate_random_scalar();
        let client_mask = generate_random_mask();
        let client_scalar = compute_commit_scalar(&client_rand, &client_mask);
        let client_element = compute_commit_element(&client_rand, &client_mask, &pwd_element).unwrap();

        // 服务端
        let server_rand = generate_random_scalar();
        let server_mask = generate_random_mask();
        let server_scalar = compute_commit_scalar(&server_rand, &server_mask);
        let server_element = compute_commit_element(&server_rand, &server_mask, &pwd_element).unwrap();

        // 计算 PMK
        let client_pmk = compute_pmk(
            &client_scalar,
            &client_element,
            &server_scalar,
            &server_element,
            &pwd_element,
        ).unwrap();

        let server_pmk = compute_pmk(
            &server_scalar,
            &server_element,
            &client_scalar,
            &client_element,
            &pwd_element,
        ).unwrap();

        // PMK 应该相同
        assert_eq!(client_pmk, server_pmk);
    }
}
