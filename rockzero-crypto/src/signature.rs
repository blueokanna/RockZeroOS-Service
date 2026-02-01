use ed25519_dalek::{Signer, Verifier, Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng{});
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}

pub fn verify(verifying_key: &VerifyingKey, message: &[u8], signature: &Signature) -> Result<()> {
    verifying_key.verify(message, signature)
        .map_err(|e| format!("Signature verification failed: {}", e).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let (signing_key, verifying_key) = generate_keypair();
        let message = b"test message";
        
        let signature = sign(&signing_key, message);
        verify(&verifying_key, message, &signature).unwrap();
    }
}
