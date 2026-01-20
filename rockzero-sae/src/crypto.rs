use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use rand::rngs::OsRng;
use rand::RngCore;
use sha3::Sha3_256;
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use crate::error::{Result, SaeError};

type HmacSha3_256 = Hmac<Sha3_256>;

const SAE_MAX_PWE_LOOP: u32 = 40;

/// SAE 密码元素派生（Hunt-and-Peck 方法，使用 Blake3）
/// 
/// 这是 SAE 标准的核心算法，用于从密码派生椭圆曲线点
/// 使用 Blake3 替代 SHA256 以提供更好的性能和安全性
pub fn password_to_element(password: &[u8], device_id1: &[u8], device_id2: &[u8]) -> Result<EdwardsPoint> {
    // 确保设备ID顺序正确（字典序）
    let (id1, id2) = if device_id1 < device_id2 {
        (device_id1, device_id2)
    } else {
        (device_id2, device_id1)
    };

    // Hunt-and-Peck 算法（使用 Blake3）
    for counter in 1..=SAE_MAX_PWE_LOOP {
        // PWE = Blake3(id1 || id2 || password || counter)
        let mut hasher = blake3::Hasher::new();
        hasher.update(id1);
        hasher.update(id2);
        hasher.update(password);
        hasher.update(&counter.to_le_bytes());
        let hash = hasher.finalize();
        
        // 使用 Blake3 的 XOF 模式生成更多随机性
        // 尝试多个偏移量以增加找到有效点的概率
        for offset in 0u32..8 {
            let mut seed = [0u8; 32];
            let xof = hash.as_bytes();
            
            // 使用不同的偏移量生成不同的种子
            if offset == 0 {
                seed.copy_from_slice(xof);
            } else {
                // 使用 Blake3 派生更多随机数据
                let mut derived_hasher = blake3::Hasher::new();
                derived_hasher.update(xof);
                derived_hasher.update(&offset.to_le_bytes());
                let derived = derived_hasher.finalize();
                seed.copy_from_slice(derived.as_bytes());
            }
            
            // 尝试将种子转换为有效的曲线点
            if let Some(point) = try_seed_to_point(&seed) {
                // 验证点在曲线上且不是小阶点
                if is_valid_pwe(&point) {
                    return Ok(point);
                }
            }
        }
    }

    Err(SaeError::CryptoError("Failed to derive PWE after maximum iterations".to_string()))
}

/// 尝试将种子转换为曲线点
fn try_seed_to_point(seed: &[u8]) -> Option<EdwardsPoint> {
    // 使用 Elligator 2 映射或 hash-to-curve
    // 这里使用简化的方法：将哈希值作为 y 坐标压缩点
    if seed.len() < 32 {
        return None;
    }

    let mut y_bytes = [0u8; 32];
    y_bytes.copy_from_slice(&seed[..32]);
    
    // 尝试解压缩点
    let compressed = CompressedEdwardsY(y_bytes);
    compressed.decompress()
}

/// 验证 PWE 是否有效
fn is_valid_pwe(point: &EdwardsPoint) -> bool {
    // 检查点不是单位元
    if point.is_identity() {
        return false;
    }

    // 检查点是否有小阶（torsion-free）
    point.is_torsion_free()
}

/// 生成随机标量（rand）
pub fn generate_random_scalar() -> Scalar {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}

/// 生成随机掩码（mask）
pub fn generate_random_mask() -> Scalar {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}

/// 计算承诺标量: commit_scalar = (rand + mask) mod q
pub fn compute_commit_scalar(rand: &Scalar, mask: &Scalar) -> Scalar {
    rand + mask
}

/// 计算承诺元素: commit_element = inverse(mask * PWE) = -mask * PWE
/// 
/// 根据 SAE 标准:
/// 1. 计算 mask * PWE
/// 2. 取反（inverse）得到 commit_element
/// 
/// 注意：这里的 inverse 是点的反元素（negation），不是标量的逆
pub fn compute_commit_element(
    _rand: &Scalar,  // 不使用 rand，仅为保持接口一致
    mask: &Scalar,
    password_element: &EdwardsPoint,
) -> Result<EdwardsPoint> {
    // element = mask * PWE
    let temp = mask * password_element;
    
    // commit_element = -temp (点的反元素)
    Ok(-temp)
}

/// 计算共享密钥 (Shared Secret)
/// 
/// 这是 SAE 握手的核心：双方使用对方的 commit 计算相同的共享密钥
/// 
/// 根据 SAE 标准:
/// K = local_rand * (peer_element + peer_scalar * PWE)
/// 
/// 注意：这里使用 local_rand（私钥），而不是 local_scalar（commit scalar）
/// - local_scalar = rand + mask（用于 commit 消息）
/// - local_rand = 私钥（用于计算共享密钥）
/// 
/// 参数说明：
/// - local_rand: 本地私钥（rand，不是 scalar）
/// - peer_scalar: 对方的 commit scalar
/// - peer_element: 对方的 commit element
/// - password_element: PWE（密码元素）
pub fn compute_pmk(
    local_rand: &Scalar,
    peer_scalar: &Scalar,
    peer_element: &EdwardsPoint,
    password_element: &EdwardsPoint,
) -> Result<[u8; 32]> {
    // 1. 计算 peer_scalar * PWE
    let peer_scalar_pwe = peer_scalar * password_element;
    
    // 2. 计算 peer_element + peer_scalar * PWE
    let temp = peer_element + peer_scalar_pwe;
    
    // 3. 计算 K = local_rand * temp
    let shared_secret = local_rand * temp;
    
    // 4. 将共享密钥点转换为字节（使用 x 坐标）
    let k_bytes = shared_secret.compress().to_bytes();
    
    Ok(k_bytes)
}

/// 从共享密钥派生 KCK 和 PMK（使用 SHA3-256）
/// 
/// 根据 SAE 标准（改进版使用 SHA3-256）:
/// 1. keyseed = HMAC-SHA3-256(zero_key, shared_secret)
/// 2. value = (local_scalar + peer_scalar) mod q
/// 3. KCK || PMK = HKDF-SHA3-256(keyseed, "SAE KCK and PMK", value)
/// 
/// 注意：(local_scalar + peer_scalar) 是可交换的，所以双方计算结果相同
pub fn derive_kck_pmk(
    shared_secret: &[u8; 32],
    local_scalar: &Scalar,
    peer_scalar: &Scalar,
    _local_element: &EdwardsPoint,  // 不使用，仅为保持接口一致
    _peer_element: &EdwardsPoint,   // 不使用，仅为保持接口一致
) -> Result<([u8; 32], [u8; 32])> {
    // 1. 计算 keyseed = HMAC-SHA3-256(zero_key, shared_secret)
    let zero_key = [0u8; 32];
    let mut mac = HmacSha3_256::new_from_slice(&zero_key)
        .map_err(|e| SaeError::CryptoError(format!("HMAC init failed: {}", e)))?;
    mac.update(shared_secret);
    let keyseed = mac.finalize().into_bytes();

    // 2. 计算 value = (local_scalar + peer_scalar) mod q
    // 注意：Scalar 的加法自动 mod q
    let value = local_scalar + peer_scalar;
    let value_bytes = value.to_bytes();

    // 3. 使用 HKDF-SHA3-256 派生 KCK 和 PMK
    // KCK || PMK = HKDF(keyseed, "SAE KCK and PMK", value)
    let hk = Hkdf::<Sha3_256>::new(None, &keyseed);
    
    let mut kck_pmk = [0u8; 64]; // 32 bytes KCK + 32 bytes PMK
    hk.expand_multi_info(&[b"SAE KCK and PMK", &value_bytes], &mut kck_pmk)
        .map_err(|e| SaeError::CryptoError(format!("HKDF expand failed: {}", e)))?;

    let mut kck = [0u8; 32];
    let mut pmk = [0u8; 32];
    kck.copy_from_slice(&kck_pmk[0..32]);
    pmk.copy_from_slice(&kck_pmk[32..64]);

    Ok((kck, pmk))
}

/// 计算确认值 (Confirm) 使用 HMAC-SHA3-256
/// 
/// confirm = HMAC-SHA3-256(KCK, send_confirm || scalar1 || scalar2 || element1 || element2)
/// 
/// 注意：参数顺序很重要！
/// - 发送方：使用 (my_scalar, peer_scalar, my_element, peer_element)
/// - 接收方验证：使用 (peer_scalar, my_scalar, peer_element, my_element)
pub fn compute_confirm(
    kck: &[u8; 32],
    send_confirm: u16,
    scalar1: &Scalar,
    scalar2: &Scalar,
    element1: &EdwardsPoint,
    element2: &EdwardsPoint,
) -> Result<[u8; 32]> {
    let mut mac = HmacSha3_256::new_from_slice(kck)
        .map_err(|e| SaeError::CryptoError(format!("HMAC init failed: {}", e)))?;
    
    // 添加所有输入（顺序很重要！）
    mac.update(&send_confirm.to_le_bytes());
    mac.update(scalar1.as_bytes());
    mac.update(scalar2.as_bytes());
    mac.update(element1.compress().as_bytes());
    mac.update(element2.compress().as_bytes());
    
    let result = mac.finalize();
    let mut confirm = [0u8; 32];
    confirm.copy_from_slice(&result.into_bytes());
    
    Ok(confirm)
}

/// 验证确认值
/// 
/// 验证对方发送的 confirm 是否正确
pub fn verify_confirm(
    kck: &[u8; 32],
    send_confirm: u16,
    my_scalar: &Scalar,
    peer_scalar: &Scalar,
    my_element: &EdwardsPoint,
    peer_element: &EdwardsPoint,
    received_confirm: &[u8; 32],
) -> Result<()> {
    // 对方生成 confirm 时使用的顺序是：
    // (peer_scalar, my_scalar, peer_element, my_element)
    // 所以我们验证时也要用相同的顺序
    let expected = compute_confirm(
        kck,
        send_confirm,
        peer_scalar,  // 对方的 scalar 在前
        my_scalar,    // 我的 scalar 在后
        peer_element, // 对方的 element 在前
        my_element,   // 我的 element 在后
    )?;

    // 使用常量时间比较
    use subtle::ConstantTimeEq;
    if expected.ct_eq(received_confirm).into() {
        Ok(())
    } else {
        Err(SaeError::ConfirmVerificationFailed)
    }
}

/// 计算 PMKID 使用 HMAC-SHA3-256
/// 
/// PMKID = HMAC-SHA3-256(PMK, "PMK Name" || device_id1 || device_id2)
pub fn compute_pmkid(
    pmk: &[u8; 32],
    device_id1: &[u8],
    device_id2: &[u8],
) -> Result<[u8; 16]> {
    let mut mac = HmacSha3_256::new_from_slice(pmk)
        .map_err(|e| SaeError::CryptoError(format!("HMAC init failed: {}", e)))?;
    
    mac.update(b"PMK Name");
    mac.update(device_id1);
    mac.update(device_id2);
    
    let result = mac.finalize();
    let mut pmkid = [0u8; 16];
    pmkid.copy_from_slice(&result.into_bytes()[..16]);
    
    Ok(pmkid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_to_element() {
        use curve25519_dalek::traits::IsIdentity;
        
        let password = b"test_password_123";
        let device_id1 = [0x01; 32];
        let device_id2 = [0x02; 32];

        let element = password_to_element(password, &device_id1, &device_id2).unwrap();
        
        // 验证点在曲线上
        assert!(element.is_torsion_free());
        assert!(!element.is_identity());
    }

    #[test]
    fn test_pmk_computation_symmetry() {
        let password = b"shared_secret";
        let device_id1 = [0x01; 32];
        let device_id2 = [0x02; 32];

        let pwd_element = password_to_element(password, &device_id1, &device_id2).unwrap();

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

        // 计算 PMK（使用 rand 而不是 scalar）
        let client_pmk = compute_pmk(
            &client_rand,
            &server_scalar,
            &server_element,
            &pwd_element,
        ).unwrap();

        let server_pmk = compute_pmk(
            &server_rand,
            &client_scalar,
            &client_element,
            &pwd_element,
        ).unwrap();

        // PMK 应该相同
        assert_eq!(client_pmk, server_pmk);
    }

    #[test]
    fn test_confirm_verification() {
        let password = b"test_password";
        let device_id1 = [0x01; 32];
        let device_id2 = [0x02; 32];

        let pwd_element = password_to_element(password, &device_id1, &device_id2).unwrap();

        // 生成双方的 commit
        let client_rand = generate_random_scalar();
        let client_mask = generate_random_mask();
        let client_scalar = compute_commit_scalar(&client_rand, &client_mask);
        let client_element = compute_commit_element(&client_rand, &client_mask, &pwd_element).unwrap();

        let server_rand = generate_random_scalar();
        let server_mask = generate_random_mask();
        let server_scalar = compute_commit_scalar(&server_rand, &server_mask);
        let server_element = compute_commit_element(&server_rand, &server_mask, &pwd_element).unwrap();

        // 计算共享密钥（使用 rand 而不是 scalar）
        let shared_secret = compute_pmk(
            &client_rand,
            &server_scalar,
            &server_element,
            &pwd_element,
        ).unwrap();

        // 派生 KCK
        let (kck, _pmk) = derive_kck_pmk(
            &shared_secret,
            &client_scalar,
            &server_scalar,
            &client_element,
            &server_element,
        ).unwrap();

        // 客户端计算 confirm
        let send_confirm = 1u16;
        let client_confirm = compute_confirm(
            &kck,
            send_confirm,
            &client_scalar,
            &server_scalar,
            &client_element,
            &server_element,
        ).unwrap();

        // 服务端验证 confirm
        let result = verify_confirm(
            &kck,
            send_confirm,
            &server_scalar,
            &client_scalar,
            &server_element,
            &client_element,
            &client_confirm,
        );

        assert!(result.is_ok());
    }
}
