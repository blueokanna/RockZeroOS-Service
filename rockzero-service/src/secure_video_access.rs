//! Secure video access module with ZKP-based authentication
//! This module provides secure video token management for protected content.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use tracing::{info, warn};

use rockzero_crypto::{ZkpContext, PasswordRegistration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoAccessToken {
    pub token_id: String,
    pub user_id: String,
    pub file_path: PathBuf,
    #[serde(skip, default = "Instant::now")]
    pub created_at: Instant,
    #[serde(skip, default = "default_expires_at")]
    pub expires_at: Instant,
    pub sae_key: Vec<u8>,
    pub proof: Vec<u8>,
    pub registration: PasswordRegistration,
    pub signature: String,
    pub permissions: Vec<VideoPermission>,
}

fn default_expires_at() -> Instant {
    Instant::now() + Duration::from_secs(3600)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VideoPermission {
    Read,
    Stream,
    Download,
    Transcode,
}

impl VideoAccessToken {
    /// Create a new access token
    pub fn new(
        user_id: String,
        file_path: PathBuf,
        password: &str,
        permissions: Vec<VideoPermission>,
        ttl_seconds: u64,
    ) -> Result<Self, String> {
        let token_id = uuid::Uuid::new_v4().to_string();
        let created_at = Instant::now();
        let expires_at = created_at + Duration::from_secs(ttl_seconds);
        
        // Simplified key derivation (based on password and context) using Blake3
        let mut hasher = blake3::Hasher::new();
        hasher.update(password.as_bytes());
        hasher.update(user_id.as_bytes());
        hasher.update(file_path.to_string_lossy().as_bytes());
        hasher.update(token_id.as_bytes());
        let key_hash = hasher.finalize();
        let sae_key = key_hash.as_bytes().to_vec();
        
        // Use ZkpContext to register password and generate Bulletproofs proof
        let zkp_ctx = ZkpContext::new();
        let registration = zkp_ctx.register_password(password)
            .map_err(|e| format!("Password registration failed: {}", e))?;
        let enhanced_proof = zkp_ctx.generate_enhanced_proof(password, &registration, "video_access")
            .map_err(|e| format!("Proof generation failed: {}", e))?;
        let proof = serde_json::to_vec(&enhanced_proof)
            .map_err(|e| format!("Proof serialization failed: {}", e))?;
        
        // Generate signature using Blake3
        let mut hasher = blake3::Hasher::new();
        hasher.update(token_id.as_bytes());
        hasher.update(user_id.as_bytes());
        hasher.update(file_path.to_string_lossy().as_bytes());
        hasher.update(&sae_key);
        let signature = hex::encode(hasher.finalize().as_bytes());
        
        Ok(Self {
            token_id,
            user_id,
            file_path,
            created_at,
            expires_at,
            sae_key,
            proof,
            registration,
            signature,
            permissions,
        })
    }
    
    /// Verify the token
    pub fn verify(&self, password: &str) -> bool {
        // Check if expired
        if Instant::now() > self.expires_at {
            warn!("Token expired: {}", self.token_id);
            return false;
        }
        
        // Verify key (using same derivation method with Blake3)
        let mut hasher = blake3::Hasher::new();
        hasher.update(password.as_bytes());
        hasher.update(self.user_id.as_bytes());
        hasher.update(self.file_path.to_string_lossy().as_bytes());
        hasher.update(self.token_id.as_bytes());
        let key_hash = hasher.finalize();
        let expected_key = key_hash.as_bytes().to_vec();
        
        if expected_key != self.sae_key {
            warn!("Key mismatch for token: {}", self.token_id);
            return false;
        }
        
        // Generate new proof to verify password correctness
        let zkp_ctx = ZkpContext::new();
        
        // Try to generate proof with given password - succeeds if password is correct
        match zkp_ctx.generate_enhanced_proof(password, &self.registration, "video_access") {
            Ok(_) => {
                // Password correct, can generate valid proof
            }
            Err(e) => {
                warn!("Password verification failed: {}", e);
                return false;
            }
        }
        
        // Verify signature using Blake3
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.token_id.as_bytes());
        hasher.update(self.user_id.as_bytes());
        hasher.update(self.file_path.to_string_lossy().as_bytes());
        hasher.update(&self.sae_key);
        let computed_signature = hex::encode(hasher.finalize().as_bytes());
        
        if computed_signature != self.signature {
            warn!("Signature mismatch for token: {}", self.token_id);
            return false;
        }
        
        true
    }
    
    /// Check if has specific permission
    pub fn has_permission(&self, permission: &VideoPermission) -> bool {
        self.permissions.contains(permission)
    }
    
    /// Check if can access specific file
    pub fn can_access_file(&self, file_path: &Path) -> bool {
        self.file_path == file_path
    }
}

/// Video access manager
pub struct VideoAccessManager {
    /// Active access tokens
    tokens: Arc<RwLock<HashMap<String, VideoAccessToken>>>,
    /// User file access permissions
    user_permissions: Arc<RwLock<HashMap<String, Vec<PathBuf>>>>,
}

impl VideoAccessManager {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            user_permissions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Create access token
    pub async fn create_token(
        &self,
        user_id: String,
        file_path: PathBuf,
        password: &str,
        permissions: Vec<VideoPermission>,
        ttl_seconds: u64,
    ) -> Result<String, String> {
        // Check if user has permission to access the file
        if !self.check_user_permission(&user_id, &file_path).await {
            return Err("User does not have permission to access this file".to_string());
        }
        
        // Create token
        let token = VideoAccessToken::new(
            user_id.clone(),
            file_path.clone(),
            password,
            permissions,
            ttl_seconds,
        )?;
        
        let token_id = token.token_id.clone();
        
        // Store token
        let mut tokens = self.tokens.write().await;
        tokens.insert(token_id.clone(), token);
        
        info!("Created video access token {} for user {} on file {:?}", 
            token_id, user_id, file_path);
        
        Ok(token_id)
    }
    
    /// Verify access token
    pub async fn verify_token(
        &self,
        token_id: &str,
        password: &str,
        file_path: &Path,
        required_permission: &VideoPermission,
    ) -> Result<(), String> {
        let tokens = self.tokens.read().await;
        
        let token = tokens.get(token_id)
            .ok_or_else(|| "Invalid token".to_string())?;
        
        // 验证令牌
        if !token.verify(password) {
            return Err("Token verification failed".to_string());
        }
        
        // 检查文件访问权限
        if !token.can_access_file(file_path) {
            return Err("Token does not grant access to this file".to_string());
        }
        
        // 检查操作权限
        if !token.has_permission(required_permission) {
            return Err(format!("Token does not have {:?} permission", required_permission));
        }
        
        Ok(())
    }
    
    /// 撤销令牌
    pub async fn revoke_token(&self, token_id: &str) {
        let mut tokens = self.tokens.write().await;
        tokens.remove(token_id);
        info!("Revoked video access token: {}", token_id);
    }
    
    /// 授予用户文件访问权限
    pub async fn grant_permission(&self, user_id: String, file_path: PathBuf) {
        let mut perms = self.user_permissions.write().await;
        perms.entry(user_id.clone())
            .or_insert_with(Vec::new)
            .push(file_path.clone());
        info!("Granted permission to user {} for file {:?}", user_id, file_path);
    }
    
    /// 撤销用户文件访问权限
    pub async fn revoke_permission(&self, user_id: &str, file_path: &Path) {
        let mut perms = self.user_permissions.write().await;
        if let Some(files) = perms.get_mut(user_id) {
            files.retain(|f| f != file_path);
        }
        info!("Revoked permission from user {} for file {:?}", user_id, file_path);
    }
    
    /// 检查用户权限
    pub async fn check_user_permission(&self, user_id: &str, file_path: &Path) -> bool {
        let perms = self.user_permissions.read().await;
        if let Some(files) = perms.get(user_id) {
            files.iter().any(|f| f == file_path)
        } else {
            false
        }
    }
    
    /// 清理过期令牌
    pub async fn cleanup_expired_tokens(&self) {
        let mut tokens = self.tokens.write().await;
        let now = Instant::now();
        let before_count = tokens.len();
        
        tokens.retain(|_, token| now < token.expires_at);
        
        let removed = before_count - tokens.len();
        if removed > 0 {
            info!("Cleaned up {} expired video access tokens", removed);
        }
    }
    
    /// 启动后台清理任务
    pub fn start_cleanup_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                self.cleanup_expired_tokens().await;
            }
        });
    }
    
    /// 获取用户的所有令牌
    pub async fn get_user_tokens(&self, user_id: &str) -> Vec<VideoAccessToken> {
        let tokens = self.tokens.read().await;
        tokens.values()
            .filter(|t| t.user_id == user_id)
            .cloned()
            .collect()
    }
}

impl Default for VideoAccessManager {
    fn default() -> Self {
        Self::new()
    }
}

/// 全局视频访问管理器 (使用 OnceLock 确保线程安全)
static GLOBAL_VIDEO_ACCESS_MANAGER: OnceLock<Arc<VideoAccessManager>> = OnceLock::new();

pub fn init_global_video_access_manager() -> Arc<VideoAccessManager> {
    GLOBAL_VIDEO_ACCESS_MANAGER
        .get_or_init(|| {
            let manager = Arc::new(VideoAccessManager::new());
            manager.clone().start_cleanup_task();
            info!("Video access manager initialized with security features");
            manager
        })
        .clone()
}

pub fn get_global_video_access_manager() -> Option<Arc<VideoAccessManager>> {
    GLOBAL_VIDEO_ACCESS_MANAGER.get().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_video_access_token() {
        // Use a strong password that meets entropy requirements
        let password = "SecureTestPassword123!@#";
        
        let token = VideoAccessToken::new(
            "user123".to_string(),
            PathBuf::from("/videos/test.mp4"),
            password,
            vec![VideoPermission::Read, VideoPermission::Stream],
            3600,
        ).unwrap();
        
        assert!(token.verify(password));
        assert!(!token.verify("WrongPassword456!@#"));
        assert!(token.has_permission(&VideoPermission::Read));
        assert!(!token.has_permission(&VideoPermission::Download));
    }

    #[tokio::test]
    async fn test_video_access_manager() {
        let manager = Arc::new(VideoAccessManager::new());
        let file_path = PathBuf::from("/videos/test.mp4");
        // Use a strong password that meets entropy requirements
        let password = "SecureTestPassword123!@#";
        
        // 授予权限
        manager.grant_permission("user123".to_string(), file_path.clone()).await;
        
        // 创建令牌
        let token_id = manager.create_token(
            "user123".to_string(),
            file_path.clone(),
            password,
            vec![VideoPermission::Stream],
            3600,
        ).await.unwrap();
        
        // 验证令牌
        let result = manager.verify_token(
            &token_id,
            password,
            &file_path,
            &VideoPermission::Stream,
        ).await;
        assert!(result.is_ok());
        
        // 撤销令牌
        manager.revoke_token(&token_id).await;
        
        // 验证应该失败
        let result = manager.verify_token(
            &token_id,
            password,
            &file_path,
            &VideoPermission::Stream,
        ).await;
        assert!(result.is_err());
    }
}
