use crate::crypto::*;
use crate::error::{Result, SaeError};
use crate::types::*;
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};

/// SAE 服务器状态机
#[derive(Debug, Clone, PartialEq)]
pub enum SaeServerState {
    Nothing,
    Committed,
    Confirmed,
    Accepted,
}

/// SAE 服务器
pub struct SaeServer {
    // 配置
    password: Vec<u8>,
    device_id_self: [u8; 32],
    device_id_peer: [u8; 32],

    // 状态
    state: SaeServerState,

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
}

impl SaeServer {
    /// 创建新的 SAE 服务器
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
            state: SaeServerState::Nothing,
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
        }
    }

    /// 处理客户端的 Commit 消息并生成服务器的 Commit
    pub fn process_client_commit(
        &mut self,
        client_commit: &SaeCommit,
    ) -> Result<(SaeCommit, SaeConfirm)> {
        if self.state != SaeServerState::Nothing {
            return Err(SaeError::InvalidState(format!(
                "Cannot process commit in state {:?}",
                self.state
            )));
        }

        // 1. 验证 group ID
        if client_commit.group_id != 19 {
            return Err(SaeError::UnsupportedGroup(client_commit.group_id));
        }

        // 2. 派生密码元素（PWE）
        let pwe = password_to_element(&self.password, &self.device_id_self, &self.device_id_peer)?;
        self.pwe = Some(pwe);

        // 3. 生成服务器的 commit
        let rand = generate_random_scalar();
        let mask = generate_random_mask();
        let scalar = compute_commit_scalar(&rand, &mask);
        let element = compute_commit_element(&rand, &mask, &pwe)?;

        self.rand = Some(rand);
        self.mask = Some(mask);
        self.scalar = Some(scalar);
        self.element = Some(element);

        // 4. 解析客户端的 scalar 和 element
        let peer_scalar = Scalar::from_bytes_mod_order(client_commit.scalar);

        let peer_element = {
            use curve25519_dalek::edwards::CompressedEdwardsY;
            let compressed = CompressedEdwardsY(client_commit.element);
            compressed
                .decompress()
                .ok_or_else(|| SaeError::InvalidCommit("Invalid peer element".to_string()))?
        };

        // 5. 验证客户端的 scalar 和 element 不等于自己的
        if peer_scalar == scalar {
            return Err(SaeError::InvalidCommit(
                "Peer scalar equals own scalar".to_string(),
            ));
        }

        if peer_element == element {
            return Err(SaeError::InvalidCommit(
                "Peer element equals own element".to_string(),
            ));
        }

        self.peer_scalar = Some(peer_scalar);
        self.peer_element = Some(peer_element);

        // 6. 计算共享密钥（使用 rand 而不是 scalar）
        let shared_secret = compute_pmk(&rand, &peer_scalar, &peer_element, &pwe)?;

        // 7. 派生 KCK 和 PMK
        let (kck, pmk) = derive_kck_pmk(
            &shared_secret,
            &scalar,
            &peer_scalar,
            &element,
            &peer_element,
        )?;

        self.kck = Some(kck);
        self.pmk = Some(pmk);

        // 8. 计算 PMKID
        let pmkid = compute_pmkid(&pmk, &self.device_id_self, &self.device_id_peer)?;
        self.pmkid = Some(pmkid);

        // 9. 更新状态
        self.state = SaeServerState::Committed;

        // 10. 生成服务器的 commit
        let server_commit = SaeCommit {
            group_id: 19,
            scalar: scalar.to_bytes(),
            element: element.compress().to_bytes(),
        };

        // 11. 生成服务器的 confirm
        let confirm = compute_confirm(
            &kck,
            self.send_confirm,
            &scalar,
            &peer_scalar,
            &element,
            &peer_element,
        )?;

        self.state = SaeServerState::Confirmed;

        let server_confirm = SaeConfirm {
            send_confirm: self.send_confirm,
            confirm,
        };

        Ok((server_commit, server_confirm))
    }

    pub fn verify_client_confirm(&mut self, client_confirm: &SaeConfirm) -> Result<()> {
        if self.state != SaeServerState::Confirmed {
            return Err(SaeError::InvalidState(format!(
                "Cannot verify confirm in state {:?}",
                self.state
            )));
        }

        if self.kck.is_none() {
            return Err(SaeError::InvalidState("KCK not derived yet".to_string()));
        }

        verify_confirm(
            &self.kck.unwrap(),
            client_confirm.send_confirm,
            &self.scalar.unwrap(),
            &self.peer_scalar.unwrap(),
            &self.element.unwrap(),
            &self.peer_element.unwrap(),
            &client_confirm.confirm,
        )?;

        self.peer_confirm = Some(client_confirm.confirm);
        self.state = SaeServerState::Accepted;

        Ok(())
    }

    pub fn get_pmk(&self) -> Result<[u8; 32]> {
        self.pmk
            .ok_or_else(|| SaeError::InvalidState("PMK not derived yet".to_string()))
    }

    pub fn get_pmkid(&self) -> Result<[u8; 16]> {
        self.pmkid
            .ok_or_else(|| SaeError::InvalidState("PMKID not derived yet".to_string()))
    }

    pub fn state(&self) -> &SaeServerState {
        &self.state
    }

    pub fn is_authenticated(&self) -> bool {
        self.state == SaeServerState::Accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::SaeClient;

    #[test]
    fn test_sae_server_full_handshake() {
        let password = b"test_password_123".to_vec();
        let device_id_client = [0x01; 32];
        let device_id_server = [0x02; 32];

        let mut client = SaeClient::new(password.clone(), device_id_client, device_id_server);
        let client_commit = client.generate_commit().unwrap();

        let mut server = SaeServer::new(password, device_id_server, device_id_client);
        let (server_commit, server_confirm) = server.process_client_commit(&client_commit).unwrap();
        assert_eq!(server.state(), &SaeServerState::Confirmed);

        client.process_commit(&server_commit).unwrap();
        let client_confirm = client.generate_confirm().unwrap();

        server.verify_client_confirm(&client_confirm).unwrap();
        assert_eq!(server.state(), &SaeServerState::Accepted);

        client.verify_confirm(&server_confirm).unwrap();

        let client_pmk = client.get_pmk().unwrap();
        let server_pmk = server.get_pmk().unwrap();
        assert_eq!(client_pmk, server_pmk);

        let client_pmkid = client.get_pmkid().unwrap();
        let server_pmkid = server.get_pmkid().unwrap();
        assert_eq!(client_pmkid, server_pmkid);
    }
}
