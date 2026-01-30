use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use rand::rngs::OsRng;
use rand::RngCore;
use crate::error::{Result, SaeError};

const SAE_MAX_PWE_LOOP: u32 = 40;

pub fn password_to_element(password: &[u8], device_id1: &[u8], device_id2: &[u8]) -> Result<EdwardsPoint> {
    let (id1, id2) = if device_id1 < device_id2 {
        (device_id1, device_id2)
    } else {
        (device_id2, device_id1)
    };

    for counter in 1..=SAE_MAX_PWE_LOOP {
        let mut hasher = blake3::Hasher::new();
        hasher.update(id1);
        hasher.update(id2);
        hasher.update(password);
        hasher.update(&counter.to_le_bytes());
        let hash = hasher.finalize();

        for offset in 0u32..8 {
            let mut seed = [0u8; 32];
            let xof = hash.as_bytes();

            if offset == 0 {
                seed.copy_from_slice(xof);
            } else {
                let mut derived_hasher = blake3::Hasher::new();
                derived_hasher.update(xof);
                derived_hasher.update(&offset.to_le_bytes());
                let derived = derived_hasher.finalize();
                seed.copy_from_slice(derived.as_bytes());
            }

            if let Some(point) = try_seed_to_point(&seed) {
                if is_valid_pwe(&point) {
                    return Ok(point);
                }
            }
        }
    }

    Err(SaeError::CryptoError("Failed to derive PWE after maximum iterations".to_string()))
}

fn try_seed_to_point(seed: &[u8]) -> Option<EdwardsPoint> {
    if seed.len() < 32 {
        return None;
    }

    let mut y_bytes = [0u8; 32];
    y_bytes.copy_from_slice(&seed[..32]);

    let compressed = CompressedEdwardsY(y_bytes);
    compressed.decompress()
}

fn is_valid_pwe(point: &EdwardsPoint) -> bool {
    if point.is_identity() {
        return false;
    }

    point.is_torsion_free()
}

pub fn generate_random_scalar() -> Scalar {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}

pub fn generate_random_mask() -> Scalar {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}

pub fn compute_commit_scalar(rand: &Scalar, mask: &Scalar) -> Scalar {
    rand + mask
}

pub fn compute_commit_element(
    _rand: &Scalar,
    mask: &Scalar,
    password_element: &EdwardsPoint,
) -> Result<EdwardsPoint> {
    let temp = mask * password_element;

    Ok(-temp)
}

pub fn compute_pmk(
    local_rand: &Scalar,
    peer_scalar: &Scalar,
    peer_element: &EdwardsPoint,
    password_element: &EdwardsPoint,
) -> Result<[u8; 32]> {
    let peer_scalar_pwe = peer_scalar * password_element;

    let temp = peer_element + peer_scalar_pwe;

    let shared_secret = local_rand * temp;

    let k_bytes = shared_secret.compress().to_bytes();

    Ok(k_bytes)
}

pub fn derive_kck_pmk(
    shared_secret: &[u8; 32],
    local_scalar: &Scalar,
    peer_scalar: &Scalar,
    _local_element: &EdwardsPoint,
    _peer_element: &EdwardsPoint,
) -> Result<([u8; 32], [u8; 32])> {
    let zero_key = [0u8; 32];
    let keyseed = blake3_keyed_hash(&zero_key, shared_secret);

    let value = local_scalar + peer_scalar;
    let value_bytes = value.to_bytes();

    let mut info = Vec::with_capacity(16 + 32);
    info.extend_from_slice(b"SAE KCK and PMK");
    info.extend_from_slice(&value_bytes);

    let kck_pmk = hkdf_blake3_expand(&keyseed, &info, 64)?;

    let mut kck = [0u8; 32];
    let mut pmk = [0u8; 32];
    kck.copy_from_slice(&kck_pmk[0..32]);
    pmk.copy_from_slice(&kck_pmk[32..64]);

    Ok((kck, pmk))
}

fn blake3_keyed_hash(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + message.len());
    input.extend_from_slice(key);
    input.extend_from_slice(message);
    *blake3::hash(&input).as_bytes()
}

fn hkdf_blake3_expand(prk: &[u8; 32], info: &[u8], length: usize) -> Result<Vec<u8>> {
    if length == 0 {
        return Ok(Vec::new());
    }

    let mut output = Vec::with_capacity(length);
    let mut t = Vec::new();
    let mut counter: u8 = 1;

    while output.len() < length {
        let mut input = Vec::with_capacity(t.len() + info.len() + 1);
        input.extend_from_slice(&t);
        input.extend_from_slice(info);
        input.push(counter);

        let hash = blake3_keyed_hash(prk, &input);
        t = hash.to_vec();

        let copy_len = std::cmp::min(32, length - output.len());
        output.extend_from_slice(&t[..copy_len]);

        counter = counter.checked_add(1)
            .ok_or_else(|| SaeError::CryptoError("HKDF counter overflow".to_string()))?;
    }

    Ok(output)
}

pub fn compute_confirm(
    kck: &[u8; 32],
    send_confirm: u16,
    scalar1: &Scalar,
    scalar2: &Scalar,
    element1: &EdwardsPoint,
    element2: &EdwardsPoint,
) -> Result<[u8; 32]> {
    let mut data = Vec::with_capacity(2 + 32 + 32 + 32 + 32);
    data.extend_from_slice(&send_confirm.to_le_bytes());
    data.extend_from_slice(scalar1.as_bytes());
    data.extend_from_slice(scalar2.as_bytes());
    data.extend_from_slice(element1.compress().as_bytes());
    data.extend_from_slice(element2.compress().as_bytes());

    Ok(blake3_keyed_hash(kck, &data))
}

pub fn verify_confirm(
    kck: &[u8; 32],
    send_confirm: u16,
    my_scalar: &Scalar,
    peer_scalar: &Scalar,
    my_element: &EdwardsPoint,
    peer_element: &EdwardsPoint,
    received_confirm: &[u8; 32],
) -> Result<()> {
    let expected = compute_confirm(
        kck,
        send_confirm,
        peer_scalar,
        my_scalar,
        peer_element,
        my_element,
    )?;

    use subtle::ConstantTimeEq;
    if expected.ct_eq(received_confirm).into() {
        Ok(())
    } else {
        Err(SaeError::ConfirmVerificationFailed)
    }
}

pub fn compute_pmkid(
    pmk: &[u8; 32],
    device_id1: &[u8],
    device_id2: &[u8],
) -> Result<[u8; 16]> {
    let mut data = Vec::with_capacity(8 + device_id1.len() + device_id2.len());
    data.extend_from_slice(b"PMK Name");
    data.extend_from_slice(device_id1);
    data.extend_from_slice(device_id2);

    let hash = blake3_keyed_hash(pmk, &data);
    let mut pmkid = [0u8; 16];
    pmkid.copy_from_slice(&hash[..16]);

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

        assert!(element.is_torsion_free());
        assert!(!element.is_identity());
    }

    #[test]
    fn test_pmk_computation_symmetry() {
        let password = b"shared_secret";
        let device_id1 = [0x01; 32];
        let device_id2 = [0x02; 32];

        let pwd_element = password_to_element(password, &device_id1, &device_id2).unwrap();

        let client_rand = generate_random_scalar();
        let client_mask = generate_random_mask();
        let client_scalar = compute_commit_scalar(&client_rand, &client_mask);
        let client_element = compute_commit_element(&client_rand, &client_mask, &pwd_element).unwrap();

        let server_rand = generate_random_scalar();
        let server_mask = generate_random_mask();
        let server_scalar = compute_commit_scalar(&server_rand, &server_mask);
        let server_element = compute_commit_element(&server_rand, &server_mask, &pwd_element).unwrap();

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

        assert_eq!(client_pmk, server_pmk);
    }

    #[test]
    fn test_confirm_verification() {
        let password = b"test_password";
        let device_id1 = [0x01; 32];
        let device_id2 = [0x02; 32];

        let pwd_element = password_to_element(password, &device_id1, &device_id2).unwrap();

        let client_rand = generate_random_scalar();
        let client_mask = generate_random_mask();
        let client_scalar = compute_commit_scalar(&client_rand, &client_mask);
        let client_element = compute_commit_element(&client_rand, &client_mask, &pwd_element).unwrap();

        let server_rand = generate_random_scalar();
        let server_mask = generate_random_mask();
        let server_scalar = compute_commit_scalar(&server_rand, &server_mask);
        let server_element = compute_commit_element(&server_rand, &server_mask, &pwd_element).unwrap();

        let shared_secret = compute_pmk(
            &client_rand,
            &server_scalar,
            &server_element,
            &pwd_element,
        ).unwrap();

        let (kck, _pmk) = derive_kck_pmk(
            &shared_secret,
            &client_scalar,
            &server_scalar,
            &client_element,
            &server_element,
        ).unwrap();

        let send_confirm = 1u16;
        let client_confirm = compute_confirm(
            &kck,
            send_confirm,
            &client_scalar,
            &server_scalar,
            &client_element,
            &server_element,
        ).unwrap();

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