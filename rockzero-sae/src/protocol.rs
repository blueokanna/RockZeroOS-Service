//! SAE protocol implementation

use curve25519_dalek::{edwards::{CompressedEdwardsY, EdwardsPoint}, scalar::Scalar};
use serde::{Deserialize, Serialize};
use crate::{
    crypto::{
        compute_commit_element, compute_commit_scalar, compute_confirm, compute_pmk,
        generate_random_mask, generate_random_scalar, password_to_element, verify_confirm,
    },
    error::{Result, SaeError},
};

/// SAE Commit 消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaeCommit {
    /// 承诺标量 (scalar)
    pub scalar: [u8; 32],
    /// 承诺元素 (element)
    pub element: [u8; 32],
}

/// SAE Confirm 消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaeConfirm {
    /// 发送确认计数器
    pub send_confirm: u16,
    /// 确认值
    pub confirm: [u8; 32],
}

/// SAE 协议状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SaeState {
    Init,
    Committed,
    Confirmed,
    Accepted,
}

/// SAE 客户端
pub struct SaeClient {
    state: SaeState,
    password: Vec<u8>,
    mac_self: Vec<u8>,
    mac_peer: Vec<u8>,
    
    // 本地密钥材料
    rand: Option<Scalar>,
    mask: Option<Scalar>,
    scalar: Option<Scalar>,
    element: Option<EdwardsPoint>,
    
    // 对端密钥材料
    peer_scalar: Option<Scalar>,
    peer_element: Option<EdwardsPoint>,
    
    // 共享密钥
    pmk: Option<[u8; 32]>,
    
    // 确认计数器
    send_confirm: u16,
}

impl SaeClient {
    /// 创建新的 SAE 客户端
    /// 
    /// # 参数
    /// 
    /// * `password` - 共享密码 (app_id + user_token + salt)
    /// * `mac_self` - 客户端 MAC 地址或标识符
    /// * `mac_peer` - 服务端 MAC 地址或标识符
    pub fn new(password: Vec<u8>, mac_self: Vec<u8>, mac_peer: Vec<u8>) -> Self {
        Self {
            state: SaeState::Init,
            password,
            mac_self,
            mac_peer,
            rand: None,
            mask: None,
            scalar: None,
            element: None,
            peer_scalar: None,
            peer_element: None,
            pmk: None,
            send_confirm: 1,
        }
    }

    /// 生成 Commit 消息
    pub fn generate_commit(&mut self) -> Result<SaeCommit> {
        if self.state != SaeState::Init {
            return Err(SaeError::ProtocolState("Already committed".to_string()));
        }

        // 派生密码元素
        let pwd_element = password_to_element(&self.password, &self.mac_self, &self.mac_peer)?;

        // 生成随机数和掩码
        let rand = generate_random_scalar();
        let mask = generate_random_mask();

        // 计算承诺值
        let scalar = compute_commit_scalar(&rand, &mask);
        let element = compute_commit_element(&rand, &mask, &pwd_element)?;

        // 保存状态
        self.rand = Some(rand);
        self.mask = Some(mask);
        self.scalar = Some(scalar);
        self.element = Some(element);
        self.state = SaeState::Committed;

        Ok(SaeCommit {
            scalar: scalar.to_bytes(),
            element: element.compress().to_bytes(),
        })
    }

    /// 处理服务端的 Commit 消息并生成 Confirm
    pub fn process_commit(&mut self, peer_commit: &SaeCommit) -> Result<SaeConfirm> {
        if self.state != SaeState::Committed {
            return Err(SaeError::ProtocolState("Not in committed state".to_string()));
        }

        // 解析对端的承诺值
        let peer_scalar = Scalar::from_bytes_mod_order(peer_commit.scalar);
        let compressed = CompressedEdwardsY(peer_commit.element);
        let peer_element = compressed.decompress()
            .ok_or(SaeError::InvalidPoint)?;

        // 保存对端密钥材料
        self.peer_scalar = Some(peer_scalar);
        self.peer_element = Some(peer_element);

        // 计算共享密钥（使用 rand 而不是 scalar）
        let pwd_element = password_to_element(&self.password, &self.mac_self, &self.mac_peer)?;
        let shared_secret = compute_pmk(
            self.rand.as_ref().unwrap(),
            &peer_scalar,
            &peer_element,
            &pwd_element,
        )?;

        // 派生 KCK 和 PMK
        let (kck, pmk) = derive_kck_pmk(
            &shared_secret,
            self.scalar.as_ref().unwrap(),
            &peer_scalar,
            self.element.as_ref().unwrap(),
            &peer_element,
        )?;

        self.pmk = Some(pmk);

        // 计算确认值
        let confirm = compute_confirm(
            &kck,
            self.send_confirm,
            self.scalar.as_ref().unwrap(),
            &peer_scalar,
            self.element.as_ref().unwrap(),
            &peer_element,
        )?;

        self.state = SaeState::Confirmed;

        Ok(SaeConfirm {
            send_confirm: self.send_confirm,
            confirm,
        })
    }

    /// 验证服务端的 Confirm 消息
    pub fn verify_confirm(&mut self, peer_confirm: &SaeConfirm) -> Result<()> {
        if self.state != SaeState::Confirmed {
            return Err(SaeError::ProtocolState("Not in confirmed state".to_string()));
        }

        let pmk = self.pmk.as_ref().ok_or(SaeError::ProtocolState("PMK not computed".to_string()))?;

        verify_confirm(
            pmk,
            peer_confirm.send_confirm,
            self.scalar.as_ref().unwrap(),
            self.peer_scalar.as_ref().unwrap(),
            self.element.as_ref().unwrap(),
            self.peer_element.as_ref().unwrap(),
            &peer_confirm.confirm,
        )?;

        self.state = SaeState::Accepted;
        Ok(())
    }

    /// 获取 PMK (Pairwise Master Key)
    pub fn get_pmk(&self) -> Result<[u8; 32]> {
        self.pmk.ok_or(SaeError::ProtocolState("PMK not available".to_string()))
    }

    /// 检查是否已完成认证
    pub fn is_authenticated(&self) -> bool {
        self.state == SaeState::Accepted
    }
}

/// SAE 服务端
pub struct SaeServer {
    state: SaeState,
    password: Vec<u8>,
    mac_self: Vec<u8>,
    mac_peer: Vec<u8>,
    
    // 本地密钥材料
    rand: Option<Scalar>,
    mask: Option<Scalar>,
    scalar: Option<Scalar>,
    element: Option<EdwardsPoint>,
    
    // 对端密钥材料
    peer_scalar: Option<Scalar>,
    peer_element: Option<EdwardsPoint>,
    
    // 共享密钥
    pmk: Option<[u8; 32]>,
    
    // 确认计数器
    send_confirm: u16,
}

impl SaeServer {
    /// 创建新的 SAE 服务端
    pub fn new(password: Vec<u8>, mac_self: Vec<u8>, mac_peer: Vec<u8>) -> Self {
        Self {
            state: SaeState::Init,
            password,
            mac_self,
            mac_peer,
            rand: None,
            mask: None,
            scalar: None,
            element: None,
            peer_scalar: None,
            peer_element: None,
            pmk: None,
            send_confirm: 1,
        }
    }

    /// 处理客户端的 Commit 并生成服务端的 Commit 和 Confirm
    pub fn process_commit(&mut self, peer_commit: &SaeCommit) -> Result<(SaeCommit, SaeConfirm)> {
        if self.state != SaeState::Init {
            return Err(SaeError::ProtocolState("Already committed".to_string()));
        }

        // 解析对端的承诺值
        let peer_scalar = Scalar::from_bytes_mod_order(peer_commit.scalar);
        let compressed = CompressedEdwardsY(peer_commit.element);
        let peer_element = compressed.decompress()
            .ok_or(SaeError::InvalidPoint)?;

        self.peer_scalar = Some(peer_scalar);
        self.peer_element = Some(peer_element);

        // 派生密码元素
        let pwd_element = password_to_element(&self.password, &self.mac_self, &self.mac_peer)?;

        // 生成本地承诺
        let rand = generate_random_scalar();
        let mask = generate_random_mask();
        let scalar = compute_commit_scalar(&rand, &mask);
        let element = compute_commit_element(&rand, &mask, &pwd_element)?;

        self.rand = Some(rand);
        self.mask = Some(mask);
        self.scalar = Some(scalar);
        self.element = Some(element);

        // 计算共享密钥（使用 rand 而不是 scalar）
        let shared_secret = compute_pmk(
            &rand,
            &peer_scalar,
            &peer_element,
            &pwd_element,
        )?;

        // 派生 KCK 和 PMK
        let (kck, pmk) = derive_kck_pmk(
            &shared_secret,
            &scalar,
            &peer_scalar,
            &element,
            &peer_element,
        )?;

        self.pmk = Some(pmk);

        // 生成确认值
        let confirm = compute_confirm(
            &kck,
            self.send_confirm,
            &scalar,
            &peer_scalar,
            &element,
            &peer_element,
        )?;

        self.state = SaeState::Confirmed;

        let server_commit = SaeCommit {
            scalar: scalar.to_bytes(),
            element: element.compress().to_bytes(),
        };

        let server_confirm = SaeConfirm {
            send_confirm: self.send_confirm,
            confirm,
        };

        Ok((server_commit, server_confirm))
    }

    /// 验证客户端的 Confirm 消息
    pub fn verify_confirm(&mut self, peer_confirm: &SaeConfirm) -> Result<()> {
        if self.state != SaeState::Confirmed {
            return Err(SaeError::ProtocolState("Not in confirmed state".to_string()));
        }

        let pmk = self.pmk.as_ref().ok_or(SaeError::ProtocolState("PMK not computed".to_string()))?;

        verify_confirm(
            pmk,
            peer_confirm.send_confirm,
            self.scalar.as_ref().unwrap(),
            self.peer_scalar.as_ref().unwrap(),
            self.element.as_ref().unwrap(),
            self.peer_element.as_ref().unwrap(),
            &peer_confirm.confirm,
        )?;

        self.state = SaeState::Accepted;
        Ok(())
    }

    /// 获取 PMK
    pub fn get_pmk(&self) -> Result<[u8; 32]> {
        self.pmk.ok_or(SaeError::ProtocolState("PMK not available".to_string()))
    }

    /// 检查是否已完成认证
    pub fn is_authenticated(&self) -> bool {
        self.state == SaeState::Accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sae_handshake() {
        let password = b"shared_secret_password_123".to_vec();
        let client_mac = b"client_mac_address".to_vec();
        let server_mac = b"server_mac_address".to_vec();

        // 创建客户端和服务端
        let mut client = SaeClient::new(password.clone(), client_mac.clone(), server_mac.clone());
        let mut server = SaeServer::new(password, server_mac, client_mac);

        // 1. 客户端生成 Commit
        let client_commit = client.generate_commit().unwrap();

        // 2. 服务端处理客户端 Commit，生成服务端 Commit 和 Confirm
        let (server_commit, server_confirm) = server.process_commit(&client_commit).unwrap();

        // 3. 客户端处理服务端 Commit，生成客户端 Confirm
        let client_confirm = client.process_commit(&server_commit).unwrap();

        // 4. 客户端验证服务端 Confirm
        client.verify_confirm(&server_confirm).unwrap();

        // 5. 服务端验证客户端 Confirm
        server.verify_confirm(&client_confirm).unwrap();

        // 6. 验证双方都已认证
        assert!(client.is_authenticated());
        assert!(server.is_authenticated());

        // 7. 验证双方的 PMK 相同
        let client_pmk = client.get_pmk().unwrap();
        let server_pmk = server.get_pmk().unwrap();
        assert_eq!(client_pmk, server_pmk);
    }
}
