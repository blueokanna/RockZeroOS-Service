use crate::{
    error::{HlsError, Result},
    HlsEncryptor,
};
use chrono::{DateTime, Duration, Utc};
use rockzero_sae::{KeyDerivation, SaeServer};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// HLS 会话
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
}

impl HlsSession {
    pub fn new(
        user_id: String,
        file_path: String,
        pmk: [u8; 32],
        max_segments: usize,
    ) -> Result<Self> {
        let session_id = Uuid::new_v4().to_string();
        let created_at = Utc::now();
        let expires_at = created_at + Duration::hours(3);

        let kd = KeyDerivation::new(pmk);
        let encryption_key = kd.derive_aes256_key(b"hls-master-key", None)?;
        let segment_keys = kd.derive_multiple_keys(b"hls-segment", max_segments)?;

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
        })
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

/// HLS 会话管理器
pub struct HlsSessionManager {
    sessions: Arc<Mutex<HashMap<String, HlsSession>>>,
    sae_servers: Arc<Mutex<HashMap<String, SaeServer>>>,
}

impl HlsSessionManager {
    /// 创建新的会话管理器
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            sae_servers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 初始化 SAE 握手
    ///
    /// 返回临时会话ID，用于后续的握手步骤
    pub fn init_sae_handshake(&self, user_id: String, password: Vec<u8>) -> Result<String> {
        let temp_session_id = Uuid::new_v4().to_string();

        let server_id = b"rockzero-server".to_vec();
        let client_id = user_id.as_bytes().to_vec();

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
        let session = HlsSession::new(user_id, file_path, pmk, 1000)?;
        let session_id = session.session_id.clone();

        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session_id.clone(), session);

        Ok(session_id)
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
        })
    }

    pub fn remove_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions
            .remove(session_id)
            .ok_or_else(|| HlsError::SessionNotFound(session_id.to_string()))?;
        Ok(())
    }

    pub fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, session| !session.is_expired());
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
        let client_mac = b"client_mac_address".to_vec();
        let server_mac = b"server_mac_address".to_vec();

        // 先完成一次真实 SAE 握手，获取 PMK
        let mut client = rockzero_sae::SaeClient::new(password.clone(), client_mac.clone(), server_mac.clone());
        let mut server = rockzero_sae::SaeServer::new(password, server_mac, client_mac);

        let client_commit = client.generate_commit().unwrap();
        let (server_commit, server_confirm) = server.process_commit(&client_commit).unwrap();
        let client_confirm = client.process_commit(&server_commit).unwrap();
        client.verify_confirm(&server_confirm).unwrap();
        server.verify_confirm(&client_confirm).unwrap();

        assert!(client.is_authenticated());
        assert!(server.is_authenticated());
        let pmk = server.get_pmk().unwrap();

        let manager = HlsSessionManager::new();
        assert_eq!(manager.session_count(), 0);

        // 插入一条有效会话
        let session = HlsSession::new(user_id.clone(), file_path.clone(), pmk, 5).unwrap();
        let session_id = session.session_id.clone();
        {
            let mut sessions = manager.sessions.lock().unwrap();
            sessions.insert(session_id.clone(), session);
        }

        assert_eq!(manager.session_count(), 1);

        // 读取并校验会话
        let fetched = manager.get_session(&session_id).unwrap();
        assert_eq!(fetched.user_id, user_id);
        assert_eq!(fetched.file_path, file_path);

        // 插入一条已过期的会话并清理
        let mut expired = HlsSession::new("expired_user".into(), "/tmp/old.mp4".into(), pmk, 1).unwrap();
        expired.expires_at = Utc::now() - Duration::hours(1);
        {
            let mut sessions = manager.sessions.lock().unwrap();
            sessions.insert("expired-session".into(), expired);
        }

        manager.cleanup_expired_sessions();
        assert_eq!(manager.session_count(), 1);

        // 删除有效会话
        manager.remove_session(&session_id).unwrap();
        assert_eq!(manager.session_count(), 0);
    }
}
