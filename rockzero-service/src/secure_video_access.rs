

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
        

        let mut hasher = blake3::Hasher::new();
        hasher.update(password.as_bytes());
        hasher.update(user_id.as_bytes());
        hasher.update(file_path.to_string_lossy().as_bytes());
        hasher.update(token_id.as_bytes());
        let key_hash = hasher.finalize();
        let sae_key = key_hash.as_bytes().to_vec();
        

        let zkp_ctx = ZkpContext::new();
        let registration = zkp_ctx.register_password(password)
            .map_err(|e| format!("Password registration failed: {}", e))?;
        let enhanced_proof = zkp_ctx.generate_enhanced_proof(password, &registration, "video_access")
            .map_err(|e| format!("Proof generation failed: {}", e))?;
        let proof = serde_json::to_vec(&enhanced_proof)
            .map_err(|e| format!("Proof serialization failed: {}", e))?;
        

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
    

    pub fn verify(&self, password: &str) -> bool {

        if Instant::now() > self.expires_at {
            warn!("Token expired: {}", self.token_id);
            return false;
        }
        

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
        

        let zkp_ctx = ZkpContext::new();
        

        match zkp_ctx.generate_enhanced_proof(password, &self.registration, "video_access") {
            Ok(_) => {

            }
            Err(e) => {
                warn!("Password verification failed: {}", e);
                return false;
            }
        }
        

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
    

    pub fn has_permission(&self, permission: &VideoPermission) -> bool {
        self.permissions.contains(permission)
    }
    

    pub fn can_access_file(&self, file_path: &Path) -> bool {
        self.file_path == file_path
    }
}


pub struct VideoAccessManager {

    tokens: Arc<RwLock<HashMap<String, VideoAccessToken>>>,

    user_permissions: Arc<RwLock<HashMap<String, Vec<PathBuf>>>>,
}

impl VideoAccessManager {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            user_permissions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    

    pub async fn create_token(
        &self,
        user_id: String,
        file_path: PathBuf,
        password: &str,
        permissions: Vec<VideoPermission>,
        ttl_seconds: u64,
    ) -> Result<String, String> {

        if !self.check_user_permission(&user_id, &file_path).await {
            return Err("User does not have permission to access this file".to_string());
        }
        

        let password = password.to_string();
        let user_id_clone = user_id.clone();
        let file_path_clone = file_path.clone();
        let token = tokio::task::spawn_blocking(move || {
            VideoAccessToken::new(
                user_id_clone,
                file_path_clone,
                &password,
                permissions,
                ttl_seconds,
            )
        })
        .await
        .map_err(|e| format!("Token creation task failed: {}", e))??;
        
        let token_id = token.token_id.clone();
        

        let mut tokens = self.tokens.write().await;
        tokens.insert(token_id.clone(), token);
        
        info!("Created video access token {} for user {} on file {:?}", 
            token_id, user_id, file_path);
        
        Ok(token_id)
    }
    

    pub async fn verify_token(
        &self,
        token_id: &str,
        password: &str,
        file_path: &Path,
        required_permission: &VideoPermission,
    ) -> Result<(), String> {
        let tokens = self.tokens.read().await;
        
        let token = tokens.get(token_id)
            .ok_or_else(|| "Invalid token".to_string())?
            .clone();
        

        let password = password.to_string();
        let verified = tokio::task::spawn_blocking(move || {
            token.verify(&password)
        })
        .await
        .map_err(|e| format!("Verification task failed: {}", e))?;
        
        if !verified {
            return Err("Token verification failed".to_string());
        }
        

        let tokens = self.tokens.read().await;
        let token = tokens.get(token_id)
            .ok_or_else(|| "Invalid token".to_string())?;
        

        if !token.can_access_file(file_path) {
            return Err("Token does not grant access to this file".to_string());
        }
        

        if !token.has_permission(required_permission) {
            return Err(format!("Token does not have {:?} permission", required_permission));
        }
        
        Ok(())
    }
    

    pub async fn revoke_token(&self, token_id: &str) {
        let mut tokens = self.tokens.write().await;
        tokens.remove(token_id);
        info!("Revoked video access token: {}", token_id);
    }
    

    pub async fn grant_permission(&self, user_id: String, file_path: PathBuf) {
        let mut perms = self.user_permissions.write().await;
        perms.entry(user_id.clone())
            .or_insert_with(Vec::new)
            .push(file_path.clone());
        info!("Granted permission to user {} for file {:?}", user_id, file_path);
    }
    

    pub async fn revoke_permission(&self, user_id: &str, file_path: &Path) {
        let mut perms = self.user_permissions.write().await;
        if let Some(files) = perms.get_mut(user_id) {
            files.retain(|f| f != file_path);
        }
        info!("Revoked permission from user {} for file {:?}", user_id, file_path);
    }
    

    pub async fn check_user_permission(&self, user_id: &str, file_path: &Path) -> bool {
        let perms = self.user_permissions.read().await;
        if let Some(files) = perms.get(user_id) {
            files.iter().any(|f| f == file_path)
        } else {
            false
        }
    }
    

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
    

    pub fn start_cleanup_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                self.cleanup_expired_tokens().await;
            }
        });
    }
    

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

        let password = "SecureTestPassword123!@#";
        

        manager.grant_permission("user123".to_string(), file_path.clone()).await;
        

        let token_id = manager.create_token(
            "user123".to_string(),
            file_path.clone(),
            password,
            vec![VideoPermission::Stream],
            3600,
        ).await.unwrap();
        

        let result = manager.verify_token(
            &token_id,
            password,
            &file_path,
            &VideoPermission::Stream,
        ).await;
        assert!(result.is_ok());
        

        manager.revoke_token(&token_id).await;
        

        let result = manager.verify_token(
            &token_id,
            password,
            &file_path,
            &VideoPermission::Stream,
        ).await;
        assert!(result.is_err());
    }
}
