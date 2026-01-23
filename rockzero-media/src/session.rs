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
use hkdf::Hkdf;
use sha3::Sha3_256;

/// HLS 会话
/// 
/// 包含完整的会话状态，支持：
/// - SAE 密钥交换派生的 PMK
/// - ZKP 密码验证所需的注册数据
/// - AES-256-GCM 加密密钥
/// - 每段独立的加密密钥（密钥轮换）
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
    /// 用户密码注册数据（用于验证 ZKP 证明）
    pub zkp_registration: Option<PasswordRegistration>,
}

impl HlsSession {
    /// 创建新的 HLS 会话
    /// 
    /// # 参数
    /// - `user_id`: 用户标识
    /// - `file_path`: 视频文件路径
    /// - `pmk`: SAE 握手派生的主密钥 (Pairwise Master Key)
    /// - `max_segments`: 预生成的最大分片密钥数量
    /// - `zkp_registration`: 可选的 ZKP 密码注册数据，用于验证客户端证明
    /// 
    /// # 密钥派生
    /// 使用 HKDF-SHA3-256 从 PMK 派生：
    /// - 主加密密钥（用于 AES-256-GCM）
    /// - 每个分片的独立密钥（支持密钥轮换）
    pub fn new(
        user_id: String,
        file_path: String,
        pmk: [u8; 32],
        max_segments: usize,
    ) -> Result<Self> {
        Self::new_with_registration(user_id, file_path, pmk, max_segments, None)
    }

    /// 创建带有 ZKP 注册数据的 HLS 会话
    /// 
    /// 当需要验证客户端的 ZKP 证明时，必须使用此方法创建会话
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

        // 使用 HKDF-SHA3-256 从 PMK 派生密钥
        let hk = Hkdf::<Sha3_256>::new(None, &pmk);
        
        // 派生主加密密钥（AES-256-GCM）
        let mut encryption_key = [0u8; 32];
        hk.expand(b"hls-master-key", &mut encryption_key)
            .map_err(|e| HlsError::EncryptionError(format!("HKDF expand failed: {}", e)))?;
        
        // 派生分片密钥（每段使用独立密钥，支持密钥轮换）
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

    /// 设置 ZKP 注册数据
    pub fn set_zkp_registration(&mut self, registration: PasswordRegistration) {
        self.zkp_registration = Some(registration);
    }

    /// 获取 ZKP 注册数据的引用
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

/// HLS 会话管理器
pub struct HlsSessionManager {
    pub sessions: Arc<Mutex<HashMap<String, HlsSession>>>,
    pub sae_servers: Arc<Mutex<HashMap<String, SaeServer>>>,
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

        // 使用 Blake3 从字符串生成 32 字节设备ID
        let server_id = blake3::hash(b"rockzero-server-device-id").into();
        
        // 从 user_id 生成 32 字节设备ID
        let client_id = blake3::hash(user_id.as_bytes()).into();

        let sae_server = SaeServer::new(password, server_id, client_id);

        let mut servers = self.sae_servers.lock().unwrap();
        servers.insert(temp_session_id.clone(), sae_server);

        Ok(temp_session_id)
    }

    /// 完成 SAE 握手并创建 HLS 会话
    /// 
    /// # 参数
    /// - `temp_session_id`: 临时会话ID（由 init_sae_handshake 返回）
    /// - `user_id`: 用户标识
    /// - `file_path`: 视频文件路径
    /// 
    /// # 返回
    /// 成功时返回新创建的会话ID
    pub fn complete_sae_handshake(
        &self,
        temp_session_id: &str,
        user_id: String,
        file_path: String,
    ) -> Result<String> {
        self.complete_sae_handshake_with_registration(temp_session_id, user_id, file_path, None)
    }

    /// 完成 SAE 握手并创建带有 ZKP 注册数据的 HLS 会话
    /// 
    /// 当需要验证客户端的 ZKP 证明时，使用此方法
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
        let session = HlsSession::new_with_registration(
            user_id, 
            file_path, 
            pmk, 
            1000,
            zkp_registration,
        )?;
        let session_id = session.session_id.clone();

        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session_id.clone(), session);

        Ok(session_id)
    }

    /// 为现有会话设置 ZKP 注册数据
    /// 
    /// 用于在会话创建后添加 ZKP 验证能力
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

    /// 获取会话的克隆
    /// 
    /// 注意：这会创建会话的完整副本，包括 ZKP 注册数据
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

    /// 移除会话
    /// 
    /// 注意：此方法仅移除内存中的会话状态。
    /// 要同时清理 HLS 缓存文件，请使用 `remove_session_with_cleanup`。
    pub fn remove_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions
            .remove(session_id)
            .ok_or_else(|| HlsError::SessionNotFound(session_id.to_string()))?;
        Ok(())
    }

    /// 移除会话并清理关联的 HLS 缓存文件
    /// 
    /// # 参数
    /// - `session_id`: 要移除的会话ID
    /// - `hls_cache_dir`: HLS 缓存根目录路径
    /// 
    /// 该方法会：
    /// 1. 移除内存中的会话状态
    /// 2. 根据视频文件路径计算缓存目录
    /// 3. 删除对应的缓存目录及其内容
    pub fn remove_session_with_cleanup(
        &self,
        session_id: &str,
        hls_cache_dir: &std::path::Path,
    ) -> Result<Option<std::path::PathBuf>> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .remove(session_id)
            .ok_or_else(|| HlsError::SessionNotFound(session_id.to_string()))?;
        
        // 计算视频文件对应的缓存目录
        let video_hash = blake3::hash(session.file_path.as_bytes());
        let video_id = hex::encode(&video_hash.as_bytes()[..8]);
        let cache_dir = hls_cache_dir.join(&video_id);
        
        // 异步删除缓存目录（返回路径供调用者处理）
        if cache_dir.exists() {
            return Ok(Some(cache_dir));
        }
        
        Ok(None)
    }

    /// 清理过期会话
    /// 
    /// 注意：此方法仅清理内存中的过期会话。
    /// 要同时清理 HLS 缓存文件，请使用 `cleanup_expired_sessions_with_cache`。
    pub fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, session| !session.is_expired());
    }

    /// 清理过期会话并返回需要清理的缓存目录列表
    /// 
    /// # 参数
    /// - `hls_cache_dir`: HLS 缓存根目录路径
    /// 
    /// # 返回
    /// 返回需要删除的缓存目录列表，调用者应异步删除这些目录
    pub fn cleanup_expired_sessions_with_cache(
        &self,
        hls_cache_dir: &std::path::Path,
    ) -> Vec<std::path::PathBuf> {
        let mut sessions = self.sessions.lock().unwrap();
        let mut cache_dirs_to_remove = Vec::new();
        
        // 找出所有过期的会话
        let expired_sessions: Vec<_> = sessions
            .iter()
            .filter(|(_, session)| session.is_expired())
            .map(|(id, session)| (id.clone(), session.file_path.clone()))
            .collect();
        
        // 计算需要清理的缓存目录
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
        
        // 使用 32 字节设备ID
        let client_device_id = [0x01; 32];
        let server_device_id = [0x02; 32];

        // 先完成一次真实 SAE 握手，获取 PMK
        let mut client = rockzero_sae::SaeClient::new(password.clone(), client_device_id, server_device_id);
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
