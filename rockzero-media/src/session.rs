use crate::{
    error::{HlsError, Result},
    HlsEncryptor,
};
use chrono::{DateTime, Duration, Utc};
use rockzero_crypto::PasswordRegistration;
use rockzero_sae::SaeServer;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub struct HlsSession {
    pub session_id: String,
    pub user_id: String,
    pub file_path: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub pmk: [u8; 32],
    pub encryption_key: [u8; 32],
    pub encryptor: HlsEncryptor,
    pub segment_keys: Vec<[u8; 32]>,
    pub zkp_registration: Option<PasswordRegistration>,
}

/// HKDF-Blake3 key derivation
/// 
/// This implementation uses Blake3 for both extract and expand phases.
/// Salt is derived from session_id for per-session uniqueness.
struct HkdfBlake3 {
    prk: [u8; 32],
}

impl HkdfBlake3 {
    /// Create HKDF instance with salt derived from session_id
    fn new_with_session_salt(session_id: &str, ikm: &[u8]) -> Self {
        // Derive salt from session_id: blake3("hls-session-salt:" + session_id)
        let salt_input = format!("hls-session-salt:{}", session_id);
        let salt_input_bytes = salt_input.as_bytes();
        let salt = *blake3::hash(salt_input_bytes).as_bytes();

        // PRK = blake3(salt + ikm)
        let mut input = Vec::with_capacity(32 + ikm.len());
        input.extend_from_slice(&salt);
        input.extend_from_slice(ikm);
        let prk = *blake3::hash(&input).as_bytes();

        Self { prk }
    }

    /// Legacy constructor for backward compatibility (uses zero salt or provided salt)
    #[allow(dead_code)]
    fn new(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
        let salt_key: [u8; 32] = match salt {
            Some(s) if s.len() == 32 => {
                let mut key = [0u8; 32];
                key.copy_from_slice(s);
                key
            }
            Some(s) => *blake3::hash(s).as_bytes(),
            None => [0u8; 32],
        };

        let mut input = Vec::with_capacity(32 + ikm.len());
        input.extend_from_slice(&salt_key);
        input.extend_from_slice(ikm);
        let prk = *blake3::hash(&input).as_bytes();

        Self { prk }
    }

    /// Expand PRK to derive output key material
    /// 
    /// T(i) = blake3(PRK + T(i-1) + info + counter)
    fn expand(&self, info: &[u8], okm: &mut [u8]) -> std::result::Result<(), &'static str> {
        if okm.is_empty() {
            return Ok(());
        }

        let mut t = Vec::new();
        let mut counter: u8 = 1;
        let mut offset = 0;

        while offset < okm.len() {
            let mut input = Vec::with_capacity(32 + t.len() + info.len() + 1);
            input.extend_from_slice(&self.prk);
            input.extend_from_slice(&t);
            input.extend_from_slice(info);
            input.push(counter);

            let hash = blake3::hash(&input);
            t = hash.as_bytes().to_vec();

            let copy_len = std::cmp::min(32, okm.len() - offset);
            okm[offset..offset + copy_len].copy_from_slice(&t[..copy_len]);
            offset += copy_len;

            counter = counter.checked_add(1).ok_or("HKDF counter overflow")?;
        }

        let info_str = String::from_utf8_lossy(info);
        tracing::debug!("[HKDF] Expand info: \"{}\"", info_str);

        Ok(())
    }
}

impl HlsSession {
    pub fn new(
        user_id: String,
        file_path: String,
        pmk: [u8; 32],
        max_segments: usize,
    ) -> Result<Self> {
        Self::new_with_registration(user_id, file_path, pmk, max_segments, None)
    }

    pub fn new_with_registration(
        user_id: String,
        file_path: String,
        pmk: [u8; 32],
        max_segments: usize,
        zkp_registration: Option<PasswordRegistration>,
    ) -> Result<Self> {
        let session_id = Uuid::new_v4().to_string();
        let created_at = Utc::now();
        let expires_at = created_at + Duration::hours(3);

        tracing::info!("[HlsSession] Creating session: {}", session_id);

        // Use session-derived salt for HKDF
        let hk = HkdfBlake3::new_with_session_salt(&session_id, &pmk);

        let mut encryption_key = [0u8; 32];
        hk.expand(b"hls-master-key", &mut encryption_key)
            .map_err(|e| HlsError::EncryptionError(format!("HKDF expand failed: {}", e)))?;

        tracing::debug!("[HlsSession] Encryption key derived");

        let mut segment_keys = Vec::with_capacity(max_segments);
        for i in 0..max_segments {
            let mut key = [0u8; 32];
            let info = format!("hls-segment-{}", i);
            hk.expand(info.as_bytes(), &mut key)
                .map_err(|e| HlsError::EncryptionError(format!("HKDF expand failed: {}", e)))?;
            segment_keys.push(key);
        }

        let encryptor = HlsEncryptor::new(&encryption_key)?;

        Ok(Self {
            session_id,
            user_id,
            file_path,
            created_at,
            expires_at,
            pmk,
            encryption_key,
            encryptor,
            segment_keys,
            zkp_registration,
        })
    }

    pub fn set_zkp_registration(&mut self, registration: PasswordRegistration) {
        self.zkp_registration = Some(registration);
    }

    pub fn get_zkp_registration(&self) -> Option<&PasswordRegistration> {
        self.zkp_registration.as_ref()
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn get_segment_key(&self, segment_index: usize) -> Option<&[u8; 32]> {
        self.segment_keys.get(segment_index)
    }

    pub fn encrypt_segment(&self, segment_data: &[u8]) -> Result<Vec<u8>> {
        self.encryptor.encrypt_segment_combined(segment_data)
    }

    pub fn decrypt_segment(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        self.encryptor.decrypt_segment_combined(encrypted_data)
    }
}

pub struct HlsSessionManager {
    pub sessions: Arc<Mutex<HashMap<String, HlsSession>>>,
    pub sae_servers: Arc<Mutex<HashMap<String, SaeServer>>>,
}

impl HlsSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            sae_servers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn init_sae_handshake(&self, user_id: String, password: Vec<u8>) -> Result<String> {
        let temp_session_id = Uuid::new_v4().to_string();

        let server_id = blake3::hash(b"rockzero-server-device-id").into();

        let client_id = blake3::hash(user_id.as_bytes()).into();

        let sae_server = SaeServer::new(password, server_id, client_id);

        let mut servers = self.sae_servers.lock().unwrap();
        servers.insert(temp_session_id.clone(), sae_server);

        Ok(temp_session_id)
    }

    pub fn complete_sae_handshake(
        &self,
        temp_session_id: &str,
        user_id: String,
        file_path: String,
    ) -> Result<String> {
        self.complete_sae_handshake_with_registration(temp_session_id, user_id, file_path, None)
    }

    pub fn complete_sae_handshake_with_registration(
        &self,
        temp_session_id: &str,
        user_id: String,
        file_path: String,
        zkp_registration: Option<PasswordRegistration>,
    ) -> Result<String> {
        let mut servers = self.sae_servers.lock().unwrap();
        let sae_server = servers
            .remove(temp_session_id)
            .ok_or_else(|| HlsError::SessionNotFound(temp_session_id.to_string()))?;
        drop(servers);

        if !sae_server.is_authenticated() {
            return Err(HlsError::SaeError(rockzero_sae::SaeError::ProtocolState(
                "SAE handshake not completed".to_string(),
            )));
        }

        let pmk = sae_server.get_pmk()?;
        
        let session =
            HlsSession::new_with_registration(user_id, file_path, pmk, 1000, zkp_registration)?;
        let session_id = session.session_id.clone();

        tracing::info!("Created HLS session: {}", session_id);

        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session_id.clone(), session);

        Ok(session_id)
    }

    pub fn set_session_zkp_registration(
        &self,
        session_id: &str,
        registration: PasswordRegistration,
    ) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| HlsError::SessionNotFound(session_id.to_string()))?;

        session.set_zkp_registration(registration);
        Ok(())
    }

    pub fn get_session(&self, session_id: &str) -> Result<HlsSession> {
        let sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get(session_id)
            .ok_or_else(|| HlsError::SessionNotFound(session_id.to_string()))?;

        if session.is_expired() {
            return Err(HlsError::SessionExpired(session_id.to_string()));
        }

        Ok(HlsSession {
            session_id: session.session_id.clone(),
            user_id: session.user_id.clone(),
            file_path: session.file_path.clone(),
            created_at: session.created_at,
            expires_at: session.expires_at,
            pmk: session.pmk,
            encryption_key: session.encryption_key,
            encryptor: HlsEncryptor::new(&session.encryption_key)?,
            segment_keys: session.segment_keys.clone(),
            zkp_registration: session.zkp_registration.clone(),
        })
    }

    pub fn remove_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions
            .remove(session_id)
            .ok_or_else(|| HlsError::SessionNotFound(session_id.to_string()))?;
        Ok(())
    }

    pub fn remove_session_with_cleanup(
        &self,
        session_id: &str,
        hls_cache_dir: &std::path::Path,
    ) -> Result<Option<std::path::PathBuf>> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .remove(session_id)
            .ok_or_else(|| HlsError::SessionNotFound(session_id.to_string()))?;

        let video_hash = blake3::hash(session.file_path.as_bytes());
        let video_id = hex::encode(&video_hash.as_bytes()[..8]);
        let cache_dir = hls_cache_dir.join(&video_id);

        if cache_dir.exists() {
            return Ok(Some(cache_dir));
        }

        Ok(None)
    }

    pub fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, session| !session.is_expired());
    }

    pub fn cleanup_expired_sessions_with_cache(
        &self,
        hls_cache_dir: &std::path::Path,
    ) -> Vec<std::path::PathBuf> {
        let mut sessions = self.sessions.lock().unwrap();
        let mut cache_dirs_to_remove = Vec::new();

        let expired_sessions: Vec<_> = sessions
            .iter()
            .filter(|(_, session)| session.is_expired())
            .map(|(id, session)| (id.clone(), session.file_path.clone()))
            .collect();

        for (session_id, file_path) in expired_sessions {
            let video_hash = blake3::hash(file_path.as_bytes());
            let video_id = hex::encode(&video_hash.as_bytes()[..8]);
            let cache_dir = hls_cache_dir.join(&video_id);

            if cache_dir.exists() {
                cache_dirs_to_remove.push(cache_dir);
            }

            sessions.remove(&session_id);
        }

        cache_dirs_to_remove
    }

    pub fn session_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }
}

impl Default for HlsSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_blake3_with_session_salt() {
        // Test that HKDF-Blake3 with session salt produces consistent results
        let pmk = [0x42u8; 32];
        let session_id = "test-session-123";

        let hk = HkdfBlake3::new_with_session_salt(session_id, &pmk);

        let mut key1 = [0u8; 32];
        hk.expand(b"hls-master-key", &mut key1).unwrap();

        let mut key2 = [0u8; 32];
        hk.expand(b"hls-master-key", &mut key2).unwrap();

        // Same input should produce same output
        assert_eq!(key1, key2);

        // Test with different session_id
        let hk2 = HkdfBlake3::new_with_session_salt("different-session", &pmk);
        let mut key3 = [0u8; 32];
        hk2.expand(b"hls-master-key", &mut key3).unwrap();

        // Different session_id should produce different key
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_hkdf_blake3_legacy() {
        // Test legacy HKDF-Blake3 with zero salt
        let pmk = [0x42u8; 32];

        let hk = HkdfBlake3::new(None, &pmk);

        let mut key1 = [0u8; 32];
        hk.expand(b"hls-master-key", &mut key1).unwrap();

        let mut key2 = [0u8; 32];
        hk.expand(b"hls-master-key", &mut key2).unwrap();

        // Same input should produce same output
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_session_creation() {
        let pmk = [0x42u8; 32];
        let session = HlsSession::new(
            "user123".to_string(),
            "/path/to/video.mp4".to_string(),
            pmk,
            10,
        )
        .unwrap();

        assert!(!session.is_expired());
        assert_eq!(session.segment_keys.len(), 10);
    }

    #[test]
    fn test_session_manager() {
        let password = b"shared_secret_password_123".to_vec();
        let user_id = "user123".to_string();
        let file_path = "/videos/demo.mp4".to_string();

        let client_device_id = [0x01; 32];
        let server_device_id = [0x02; 32];

        let mut client =
            rockzero_sae::SaeClient::new(password.clone(), client_device_id, server_device_id);
        let mut server = rockzero_sae::SaeServer::new(password, server_device_id, client_device_id);

        let client_commit = client.generate_commit().unwrap();
        let (server_commit, server_confirm) = server.process_client_commit(&client_commit).unwrap();
        client.process_commit(&server_commit).unwrap();
        let client_confirm = client.generate_confirm().unwrap();
        client.verify_confirm(&server_confirm).unwrap();
        server.verify_client_confirm(&client_confirm).unwrap();

        assert!(client.is_authenticated());
        assert!(server.is_authenticated());

        let pmk = server.get_pmk().unwrap();

        let manager = HlsSessionManager::new();
        assert_eq!(manager.session_count(), 0);

        let session = HlsSession::new(user_id.clone(), file_path.clone(), pmk, 5).unwrap();
        let session_id = session.session_id.clone();
        {
            let mut sessions = manager.sessions.lock().unwrap();
            sessions.insert(session_id.clone(), session);
        }

        assert_eq!(manager.session_count(), 1);

        let fetched = manager.get_session(&session_id).unwrap();
        assert_eq!(fetched.user_id, user_id);
        assert_eq!(fetched.file_path, file_path);

        let mut expired =
            HlsSession::new("expired_user".into(), "/tmp/old.mp4".into(), pmk, 1).unwrap();
        expired.expires_at = Utc::now() - Duration::hours(1);
        {
            let mut sessions = manager.sessions.lock().unwrap();
            sessions.insert("expired-session".into(), expired);
        }

        manager.cleanup_expired_sessions();
        assert_eq!(manager.session_count(), 1);

        manager.remove_session(&session_id).unwrap();
        assert_eq!(manager.session_count(), 0);
    }
}
