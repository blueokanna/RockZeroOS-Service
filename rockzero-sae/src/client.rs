use crate::crypto::*;
use crate::error::{Result, SaeError};
use crate::types::*;
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};

/// SAE 客户端状态机
#[derive(Debug, Clone, PartialEq)]
pub enum SaeClientState {
    Nothing,
    Committed,
    Confirmed,
    Accepted,
}

/// SAE 客户端
pub struct SaeClient {
    // 配置
    password: Vec<u8>,
    device_id_self: [u8; 32],
    device_id_peer: [u8; 32],

    // 状态
    state: SaeClientState,

    // 密码元素
    pwe: Option<EdwardsPoint>,

    // 本地 commit 数据
    rand: Option<Scalar>,
    mask: Option<Scalar>,
    scalar: Option<Scalar>,
    element: Option<EdwardsPoint>,

    // 对方 commit 数据
    peer_scalar: Option<Scalar>,
    peer_element: Option<EdwardsPoint>,

    // 派生的密钥
    kck: Option<[u8; 32]>,
    pmk: Option<[u8; 32]>,
    pmkid: Option<[u8; 16]>,

    // Confirm 数据
    send_confirm: u16,
    peer_confirm: Option<[u8; 32]>,

    // 同步计数器
    sync: u32,
    max_sync: u32,
}

impl SaeClient {
    /// 创建新的 SAE 客户端
    /// 
    /// 参数：
    /// - password: 共享密码
    /// - device_id_self: 本地设备ID（32字节）
    /// - device_id_peer: 对方设备ID（32字节）
    pub fn new(password: Vec<u8>, device_id_self: [u8; 32], device_id_peer: [u8; 32]) -> Self {
        Self {
            password,
            device_id_self,
            device_id_peer,
            state: SaeClientState::Nothing,
            pwe: None,
            rand: None,
            mask: None,
            scalar: None,
            element: None,
            peer_scalar: None,
            peer_element: None,
            kck: None,
            pmk: None,
            pmkid: None,
            send_confirm: 1,
            peer_confirm: None,
            sync: 0,
            max_sync: 3,
        }
    }

    /// 生成 Commit 消息
    pub fn generate_commit(&mut self) -> Result<SaeCommit> {
        if self.state != SaeClientState::Nothing {
            return Err(SaeError::InvalidState(format!(
                "Cannot generate commit in state {:?}",
                self.state
            )));
        }

        // 1. 派生密码元素（PWE）
        if self.pwe.is_none() {
            let pwe = password_to_element(&self.password, &self.device_id_self, &self.device_id_peer)?;
            self.pwe = Some(pwe);
        }

        let pwe = self.pwe.as_ref().unwrap();

        // 2. 生成随机数和掩码
        let rand = generate_random_scalar();
        let mask = generate_random_mask();

        // 3. 计算 commit scalar 和 element
        let scalar = compute_commit_scalar(&rand, &mask);
        let element = compute_commit_element(&rand, &mask, pwe)?;

        // 4. 保存状态
        self.rand = Some(rand);
        self.mask = Some(mask);
        self.scalar = Some(scalar);
        self.element = Some(element);

        // 5. 更新状态
        self.state = SaeClientState::Committed;

        Ok(SaeCommit {
            group_id: 19, // Curve25519
            scalar: scalar.to_bytes(),
            element: element.compress().to_bytes(),
        })
    }

    /// 处理对方的 Commit 消息
    pub fn process_commit(&mut self, peer_commit: &SaeCommit) -> Result<()> {
        if self.state != SaeClientState::Committed {
            return Err(SaeError::InvalidState(format!(
                "Cannot process commit in state {:?}",
                self.state
            )));
        }

        // 1. 验证 group ID
        if peer_commit.group_id != 19 {
            return Err(SaeError::UnsupportedGroup(peer_commit.group_id));
        }

        // 2. 解析对方的 scalar 和 element
        let peer_scalar = Scalar::from_bytes_mod_order(peer_commit.scalar);

        let peer_element = {
            use curve25519_dalek::edwards::CompressedEdwardsY;
            let compressed = CompressedEdwardsY(peer_commit.element);
            compressed
                .decompress()
                .ok_or_else(|| SaeError::InvalidCommit("Invalid peer element".to_string()))?
        };

        // 3. 验证对方的 scalar 和 element 不等于自己的
        if peer_scalar == self.scalar.unwrap() {
            return Err(SaeError::InvalidCommit(
                "Peer scalar equals own scalar".to_string(),
            ));
        }

        if peer_element == self.element.unwrap() {
            return Err(SaeError::InvalidCommit(
                "Peer element equals own element".to_string(),
            ));
        }

        // 4. 保存对方的数据
        self.peer_scalar = Some(peer_scalar);
        self.peer_element = Some(peer_element);

        // 5. 计算共享密钥（使用 rand 而不是 scalar）
        let shared_secret = compute_pmk(
            &self.rand.unwrap(),
            &peer_scalar,
            &peer_element,
            self.pwe.as_ref().unwrap(),
        )?;

        // 6. 派生 KCK 和 PMK
        let (kck, pmk) = derive_kck_pmk(
            &shared_secret,
            &self.scalar.unwrap(),
            &peer_scalar,
            &self.element.unwrap(),
            &peer_element,
        )?;

        self.kck = Some(kck);
        self.pmk = Some(pmk);

        // 7. 计算 PMKID
        let pmkid = compute_pmkid(&pmk, &self.device_id_peer, &self.device_id_self)?;
        self.pmkid = Some(pmkid);

        Ok(())
    }

    /// 生成 Confirm 消息
    pub fn generate_confirm(&mut self) -> Result<SaeConfirm> {
        if self.state != SaeClientState::Committed {
            return Err(SaeError::InvalidState(format!(
                "Cannot generate confirm in state {:?}",
                self.state
            )));
        }

        if self.kck.is_none() {
            return Err(SaeError::InvalidState("KCK not derived yet".to_string()));
        }

        // 计算 confirm
        let confirm = compute_confirm(
            &self.kck.unwrap(),
            self.send_confirm,
            &self.scalar.unwrap(),
            &self.peer_scalar.unwrap(),
            &self.element.unwrap(),
            &self.peer_element.unwrap(),
        )?;

        // 注意：状态不变，等待验证对方的 confirm 后再变成 Accepted

        Ok(SaeConfirm {
            send_confirm: self.send_confirm,
            confirm,
        })
    }

    /// 验证对方的 Confirm 消息
    pub fn verify_confirm(&mut self, peer_confirm: &SaeConfirm) -> Result<()> {
        if self.state != SaeClientState::Committed {
            return Err(SaeError::InvalidState(format!(
                "Cannot verify confirm in state {:?}",
                self.state
            )));
        }

        if self.kck.is_none() {
            return Err(SaeError::InvalidState("KCK not derived yet".to_string()));
        }

        // 验证 confirm
        verify_confirm(
            &self.kck.unwrap(),
            peer_confirm.send_confirm,
            &self.scalar.unwrap(),
            &self.peer_scalar.unwrap(),
            &self.element.unwrap(),
            &self.peer_element.unwrap(),
            &peer_confirm.confirm,
        )?;
        self.peer_confirm = Some(peer_confirm.confirm);
        self.state = SaeClientState::Accepted;

        Ok(())
    }

    /// 获取 PMK（用于 AES-256-GCM 加密）
    pub fn get_pmk(&self) -> Result<[u8; 32]> {
        self.pmk
            .ok_or_else(|| SaeError::InvalidState("PMK not derived yet".to_string()))
    }

    /// 获取 PMKID
    pub fn get_pmkid(&self) -> Result<[u8; 16]> {
        self.pmkid
            .ok_or_else(|| SaeError::InvalidState("PMKID not derived yet".to_string()))
    }

    /// 获取当前状态
    pub fn state(&self) -> &SaeClientState {
        &self.state
    }

    /// 重置客户端（用于重试）
    pub fn reset(&mut self) {
        self.state = SaeClientState::Nothing;
        self.pwe = None;
        self.rand = None;
        self.mask = None;
        self.scalar = None;
        self.element = None;
        self.peer_scalar = None;
        self.peer_element = None;
        self.kck = None;
        self.pmk = None;
        self.pmkid = None;
        self.peer_confirm = None;
        self.sync += 1;
    }

    /// 检查是否超过最大重试次数
    pub fn is_max_sync_reached(&self) -> bool {
        self.sync >= self.max_sync
    }

    /// 检查是否已完成认证
    pub fn is_authenticated(&self) -> bool {
        self.state == SaeClientState::Accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sae_client_full_handshake() {
        let password = b"test_password_123".to_vec();
        let device_id_client = [0x01; 32];
        let device_id_server = [0x02; 32];

        let mut client = SaeClient::new(password.clone(), device_id_client, device_id_server);

        // 1. 生成 commit
        let client_commit = client.generate_commit().unwrap();
        assert_eq!(client.state(), &SaeClientState::Committed);

        // 2. 模拟服务器的 commit
        let mut server = SaeClient::new(password, device_id_server, device_id_client);
        let server_commit = server.generate_commit().unwrap();

        // 3. 处理服务器的 commit
        client.process_commit(&server_commit).unwrap();

        // 4. 生成 confirm
        let _client_confirm = client.generate_confirm().unwrap();
        // 注意：生成 confirm 后状态仍然是 Committed

        // 5. 模拟服务器的 confirm
        server.process_commit(&client_commit).unwrap();
        let server_confirm = server.generate_confirm().unwrap();

        // 6. 验证服务器的 confirm
        client.verify_confirm(&server_confirm).unwrap();
        assert_eq!(client.state(), &SaeClientState::Accepted);

        // 7. 验证 PMK 相同
        let client_pmk = client.get_pmk().unwrap();
        let server_pmk = server.get_pmk().unwrap();
        assert_eq!(client_pmk, server_pmk);
    }
}
