use serde::{Deserialize, Serialize};

/// SAE Commit 消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaeCommit {
    /// 椭圆曲线组 ID (19 = Curve25519)
    pub group_id: u16,
    
    /// Commit scalar (32 bytes)
    pub scalar: [u8; 32],
    
    /// Commit element (32 bytes compressed point)
    pub element: [u8; 32],
}

/// SAE Confirm 消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaeConfirm {
    /// Send-Confirm 计数器
    pub send_confirm: u16,
    
    /// Confirm 值 (32 bytes HMAC)
    pub confirm: [u8; 32],
}

/// SAE 握手完整消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaeHandshake {
    pub commit: SaeCommit,
    pub confirm: SaeConfirm,
}

impl SaeCommit {
    /// 序列化为字节
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.group_id.to_le_bytes());
        bytes.extend_from_slice(&self.scalar);
        bytes.extend_from_slice(&self.element);
        bytes
    }

    /// 从字节反序列化
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 66 {
            return None;
        }

        let group_id = u16::from_le_bytes([bytes[0], bytes[1]]);
        let mut scalar = [0u8; 32];
        let mut element = [0u8; 32];
        
        scalar.copy_from_slice(&bytes[2..34]);
        element.copy_from_slice(&bytes[34..66]);

        Some(Self {
            group_id,
            scalar,
            element,
        })
    }
}

impl SaeConfirm {
    /// 序列化为字节
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.send_confirm.to_le_bytes());
        bytes.extend_from_slice(&self.confirm);
        bytes
    }

    /// 从字节反序列化
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 34 {
            return None;
        }

        let send_confirm = u16::from_le_bytes([bytes[0], bytes[1]]);
        let mut confirm = [0u8; 32];
        confirm.copy_from_slice(&bytes[2..34]);

        Some(Self {
            send_confirm,
            confirm,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_serialization() {
        let commit = SaeCommit {
            group_id: 19,
            scalar: [1u8; 32],
            element: [2u8; 32],
        };

        let bytes = commit.to_bytes();
        let decoded = SaeCommit::from_bytes(&bytes).unwrap();

        assert_eq!(commit.group_id, decoded.group_id);
        assert_eq!(commit.scalar, decoded.scalar);
        assert_eq!(commit.element, decoded.element);
    }

    #[test]
    fn test_confirm_serialization() {
        let confirm = SaeConfirm {
            send_confirm: 1,
            confirm: [3u8; 32],
        };

        let bytes = confirm.to_bytes();
        let decoded = SaeConfirm::from_bytes(&bytes).unwrap();

        assert_eq!(confirm.send_confirm, decoded.send_confirm);
        assert_eq!(confirm.confirm, decoded.confirm);
    }
}
