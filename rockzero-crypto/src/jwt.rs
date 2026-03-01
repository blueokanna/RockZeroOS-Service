use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use rockzero_common::error::AppError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtHeader {
    pub alg: String,
    pub typ: String,
}

impl Default for JwtHeader {
    fn default() -> Self {
        Self {
            alg: "EdDSA".to_string(),
            typ: "JWT".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String,
    pub email: String,
    pub role: String,
    pub iat: u64,
    pub exp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
}

impl JwtClaims {
    pub fn new(sub: String, email: String, role: String, expires_in_seconds: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            sub,
            email,
            role,
            iat: now,
            exp: now + expires_in_seconds,
            jti: None,
            iss: None,
            aud: None,
        }
    }

    pub fn with_jti(mut self, jti: String) -> Self {
        self.jti = Some(jti);
        self
    }

    pub fn with_issuer(mut self, iss: String) -> Self {
        self.iss = Some(iss);
        self
    }

    pub fn with_audience(mut self, aud: String) -> Self {
        self.aud = Some(aud);
        self
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.exp < now
    }
}

pub fn derive_signing_key_from_password(password: &str) -> SigningKey {
    let hash = blake3::hash(password.as_bytes());
    let mut seed = [0u8; SECRET_KEY_LENGTH];
    seed.copy_from_slice(hash.as_bytes());
    SigningKey::from_bytes(&seed)
}

pub fn signing_key_to_pem(signing_key: &SigningKey) -> String {
    let private_key_bytes = signing_key.to_bytes();
    let base64_key = base64::engine::general_purpose::STANDARD.encode(private_key_bytes);
    format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        base64_key
    )
}

pub fn signing_key_from_pem(pem: &str) -> Result<SigningKey, AppError> {
    let pem_content = pem
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replace(['\n', '\r'], "")
        .trim()
        .to_string();

    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&pem_content)
        .map_err(|_| AppError::CryptoError("Invalid PEM encoding".to_string()))?;

    if key_bytes.len() != SECRET_KEY_LENGTH {
        return Err(AppError::CryptoError(format!(
            "Invalid private key length: expected {}, got {}",
            SECRET_KEY_LENGTH,
            key_bytes.len()
        )));
    }

    let mut seed = [0u8; SECRET_KEY_LENGTH];
    seed.copy_from_slice(&key_bytes);
    Ok(SigningKey::from_bytes(&seed))
}

pub struct JwtEncoder {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl JwtEncoder {
    pub fn from_password(password: &str) -> Self {
        let signing_key = derive_signing_key_from_password(password);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn from_pem(pem: &str) -> Result<Self, AppError> {
        let signing_key = signing_key_from_pem(pem)?;
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    pub fn from_bytes(secret_key: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret_key);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn get_private_key_pem(&self) -> String {
        signing_key_to_pem(&self.signing_key)
    }

    pub fn get_public_key_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.verifying_key.as_bytes())
    }

    pub fn encode<T: Serialize>(&self, claims: &T) -> Result<String, AppError> {
        let header = JwtHeader::default();
        let header_json = serde_json::to_string(&header)
            .map_err(|e| AppError::CryptoError(format!("Header serialization failed: {}", e)))?;
        let header_b64 = BASE64URL.encode(header_json.as_bytes());

        let claims_json = serde_json::to_string(claims)
            .map_err(|e| AppError::CryptoError(format!("Claims serialization failed: {}", e)))?;
        let claims_b64 = BASE64URL.encode(claims_json.as_bytes());

        let message = format!("{}.{}", header_b64, claims_b64);
        let signature: Signature = self.signing_key.sign(message.as_bytes());
        let signature_b64 = BASE64URL.encode(signature.to_bytes());

        Ok(format!("{}.{}", message, signature_b64))
    }

    pub fn decode<T: DeserializeOwned>(&self, token: &str) -> Result<T, AppError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AppError::CryptoError("Invalid JWT format".to_string()));
        }

        let header_json = BASE64URL
            .decode(parts[0])
            .map_err(|_| AppError::CryptoError("Invalid header encoding".to_string()))?;
        let header: JwtHeader = serde_json::from_slice(&header_json)
            .map_err(|_| AppError::CryptoError("Invalid header format".to_string()))?;

        if header.alg != "EdDSA" {
            return Err(AppError::CryptoError(format!(
                "Unsupported algorithm: {}. Expected EdDSA",
                header.alg
            )));
        }

        let message = format!("{}.{}", parts[0], parts[1]);

        let signature_bytes = BASE64URL
            .decode(parts[2])
            .map_err(|_| AppError::CryptoError("Invalid signature encoding".to_string()))?;

        if signature_bytes.len() != 64 {
            return Err(AppError::CryptoError("Invalid signature length".to_string()));
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&signature_bytes);
        let signature = Signature::from_bytes(&sig_array);

        self.verifying_key
            .verify(message.as_bytes(), &signature)
            .map_err(|_| AppError::CryptoError("Invalid signature".to_string()))?;

        let claims_json = BASE64URL
            .decode(parts[1])
            .map_err(|_| AppError::CryptoError("Invalid claims encoding".to_string()))?;

        let claims: T = serde_json::from_slice(&claims_json)
            .map_err(|e| AppError::CryptoError(format!("Claims deserialization failed: {}", e)))?;

        Ok(claims)
    }

    pub fn verify(&self, token: &str) -> Result<JwtClaims, AppError> {
        let claims: JwtClaims = self.decode(token)?;

        if claims.is_expired() {
            return Err(AppError::Unauthorized("Token expired".to_string()));
        }

        Ok(claims)
    }

    pub fn generate_access_token(
        &self,
        user_id: &str,
        email: &str,
        role: &str,
        expires_in_seconds: u64,
    ) -> Result<String, AppError> {
        let claims = JwtClaims::new(
            user_id.to_string(),
            email.to_string(),
            role.to_string(),
            expires_in_seconds,
        );
        self.encode(&claims)
    }

    pub fn generate_refresh_token(
        &self,
        user_id: &str,
        email: &str,
        role: &str,
        expires_in_seconds: u64,
    ) -> Result<String, AppError> {
        let jti = generate_token_id()?;
        let claims = JwtClaims::new(
            user_id.to_string(),
            email.to_string(),
            role.to_string(),
            expires_in_seconds,
        )
        .with_jti(jti);
        self.encode(&claims)
    }
}

pub struct JwtVerifier {
    verifying_key: VerifyingKey,
}

impl JwtVerifier {
    pub fn from_public_key_bytes(public_key: &[u8; 32]) -> Result<Self, AppError> {
        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(|e| AppError::CryptoError(format!("Invalid public key: {}", e)))?;
        Ok(Self { verifying_key })
    }

    pub fn from_public_key_base64(public_key_b64: &str) -> Result<Self, AppError> {
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(public_key_b64)
            .map_err(|_| AppError::CryptoError("Invalid public key encoding".to_string()))?;

        if key_bytes.len() != 32 {
            return Err(AppError::CryptoError("Invalid public key length".to_string()));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);
        Self::from_public_key_bytes(&key_array)
    }

    pub fn verify(&self, token: &str) -> Result<JwtClaims, AppError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AppError::CryptoError("Invalid JWT format".to_string()));
        }

        let header_json = BASE64URL
            .decode(parts[0])
            .map_err(|_| AppError::CryptoError("Invalid header encoding".to_string()))?;
        let header: JwtHeader = serde_json::from_slice(&header_json)
            .map_err(|_| AppError::CryptoError("Invalid header format".to_string()))?;

        if header.alg != "EdDSA" {
            return Err(AppError::CryptoError(format!(
                "Unsupported algorithm: {}. Expected EdDSA",
                header.alg
            )));
        }

        let message = format!("{}.{}", parts[0], parts[1]);

        let signature_bytes = BASE64URL
            .decode(parts[2])
            .map_err(|_| AppError::CryptoError("Invalid signature encoding".to_string()))?;

        if signature_bytes.len() != 64 {
            return Err(AppError::CryptoError("Invalid signature length".to_string()));
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&signature_bytes);
        let signature = Signature::from_bytes(&sig_array);

        self.verifying_key
            .verify(message.as_bytes(), &signature)
            .map_err(|_| AppError::CryptoError("Invalid signature".to_string()))?;

        let claims_json = BASE64URL
            .decode(parts[1])
            .map_err(|_| AppError::CryptoError("Invalid claims encoding".to_string()))?;

        let claims: JwtClaims = serde_json::from_slice(&claims_json)
            .map_err(|e| AppError::CryptoError(format!("Claims deserialization failed: {}", e)))?;

        if claims.is_expired() {
            return Err(AppError::Unauthorized("Token expired".to_string()));
        }

        Ok(claims)
    }
}

fn generate_token_id() -> Result<String, AppError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| AppError::CryptoError("Failed to generate token ID".to_string()))?;
    Ok(hex::encode(bytes))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

pub struct TokenManager {
    access_encoder: JwtEncoder,
    refresh_encoder: JwtEncoder,
    access_expires_in: u64,
    refresh_expires_in: u64,
}

impl TokenManager {
    pub fn new(
        access_secret: &str,
        refresh_secret: &str,
        access_expires_in: u64,
        refresh_expires_in: u64,
    ) -> Self {
        Self {
            access_encoder: JwtEncoder::from_password(access_secret),
            refresh_encoder: JwtEncoder::from_password(refresh_secret),
            access_expires_in,
            refresh_expires_in,
        }
    }

    pub fn generate_tokens(
        &self,
        user_id: &str,
        email: &str,
        role: &str,
    ) -> Result<TokenPair, AppError> {
        let access_token = self.access_encoder.generate_access_token(
            user_id,
            email,
            role,
            self.access_expires_in,
        )?;

        let refresh_token = self.refresh_encoder.generate_refresh_token(
            user_id,
            email,
            role,
            self.refresh_expires_in,
        )?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.access_expires_in,
        })
    }

    pub fn verify_access_token(&self, token: &str) -> Result<JwtClaims, AppError> {
        self.access_encoder.verify(token)
    }

    pub fn verify_refresh_token(&self, token: &str) -> Result<JwtClaims, AppError> {
        self.refresh_encoder.verify(token)
    }

    pub fn refresh_tokens(&self, refresh_token: &str) -> Result<TokenPair, AppError> {
        let claims = self.verify_refresh_token(refresh_token)?;
        self.generate_tokens(&claims.sub, &claims.email, &claims.role)
    }

    pub fn get_access_public_key(&self) -> String {
        self.access_encoder.get_public_key_base64()
    }

    pub fn get_refresh_public_key(&self) -> String {
        self.refresh_encoder.get_public_key_base64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_eddsa_encode_decode() {
        let encoder = JwtEncoder::from_password("test-secret-password");
        let claims = JwtClaims::new(
            "user123".to_string(),
            "test@example.com".to_string(),
            "user".to_string(),
            3600,
        );

        let token = encoder.encode(&claims).unwrap();
        
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header_json = BASE64URL.decode(parts[0]).unwrap();
        let header: JwtHeader = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header.alg, "EdDSA");
        assert_eq!(header.typ, "JWT");

        let decoded: JwtClaims = encoder.decode(&token).unwrap();
        assert_eq!(decoded.sub, "user123");
        assert_eq!(decoded.email, "test@example.com");
        assert_eq!(decoded.role, "user");
    }

    #[test]
    fn test_jwt_verify() {
        let encoder = JwtEncoder::from_password("test-secret-password");
        let claims = JwtClaims::new(
            "user123".to_string(),
            "test@example.com".to_string(),
            "user".to_string(),
            3600,
        );

        let token = encoder.encode(&claims).unwrap();
        let verified = encoder.verify(&token).unwrap();

        assert_eq!(verified.sub, "user123");
    }

    #[test]
    fn test_token_manager_eddsa() {
        let manager = TokenManager::new(
            "access-secret-password",
            "refresh-secret-password",
            3600,
            86400,
        );

        let tokens = manager
            .generate_tokens("user123", "test@example.com", "user")
            .unwrap();

        assert!(!tokens.access_token.is_empty());
        assert!(!tokens.refresh_token.is_empty());

        let claims = manager.verify_access_token(&tokens.access_token).unwrap();
        assert_eq!(claims.sub, "user123");
    }

    #[test]
    fn test_invalid_signature() {
        let encoder1 = JwtEncoder::from_password("password1");
        let encoder2 = JwtEncoder::from_password("password2");

        let claims = JwtClaims::new(
            "user123".to_string(),
            "test@example.com".to_string(),
            "user".to_string(),
            3600,
        );

        let token = encoder1.encode(&claims).unwrap();
        let result = encoder2.verify(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_pem_encoding() {
        let encoder = JwtEncoder::from_password("test-password");
        let pem = encoder.get_private_key_pem();

        assert!(pem.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(pem.contains("-----END PRIVATE KEY-----"));

        let encoder2 = JwtEncoder::from_pem(&pem).unwrap();

        let claims = JwtClaims::new(
            "user123".to_string(),
            "test@example.com".to_string(),
            "user".to_string(),
            3600,
        );

        let token1 = encoder.encode(&claims).unwrap();
        let token2 = encoder2.encode(&claims).unwrap();

        assert!(encoder.verify(&token2).is_ok());
        assert!(encoder2.verify(&token1).is_ok());
    }

    #[test]
    fn test_public_key_verification() {
        let encoder = JwtEncoder::from_password("test-password");
        let public_key_b64 = encoder.get_public_key_base64();

        let claims = JwtClaims::new(
            "user123".to_string(),
            "test@example.com".to_string(),
            "user".to_string(),
            3600,
        );

        let token = encoder.encode(&claims).unwrap();

        let verifier = JwtVerifier::from_public_key_base64(&public_key_b64).unwrap();
        let verified = verifier.verify(&token).unwrap();

        assert_eq!(verified.sub, "user123");
    }

    #[test]
    fn test_derive_signing_key_deterministic() {
        let password = "test-password";
        let key1 = derive_signing_key_from_password(password);
        let key2 = derive_signing_key_from_password(password);

        assert_eq!(key1.to_bytes(), key2.to_bytes());
    }
}
