//! # RockZero SAE (Simultaneous Authentication of Equals)
//! 
//! 这是一个基于 SAE 标准的安全认证库，专门用于保护数据流（如 HLS 视频流）的安全。
//! 
//! ## 概述
//! 
//! SAE (Simultaneous Authentication of Equals) 提供：
//! - 抗字典攻击的密码认证
//! - 前向保密性 (Forward Secrecy)
//! - 对等认证（双方地位平等）
//! 
//! 本实现基于 Curve25519 椭圆曲线，适用于：
//! - **安全视频流传输** (HLS with AES-256-GCM encryption)
//! - 点对点安全通信
//! - 需要强密码认证的场景
//! 
//! ## 使用场景
//! 
//! 本实现专注于通用设备认证和数据流安全：
//! - 不依赖特定硬件或驱动
//! - 可用于任何需要安全密钥交换的场景
//! - 特别优化用于 HLS 视频加密密钥派生（AES-256-GCM）
//! 
//! ## 使用示例
//! 
//! ### 客户端-服务器握手
//! 
//! ```no_run
//! use rockzero_sae::{SaeClient, SaeServer};
//! 
//! // 共享密码和设备标识符（32字节）
//! let password = b"secure_password_123".to_vec();
//! let client_id = [0x01; 32]; // 客户端设备ID
//! let server_id = [0x02; 32]; // 服务器设备ID
//! 
//! // 1. 客户端生成 commit
//! let mut client = SaeClient::new(password.clone(), client_id, server_id);
//! let client_commit = client.generate_commit().unwrap();
//! 
//! // 2. 服务器处理 commit 并生成响应
//! let mut server = SaeServer::new(password, server_id, client_id);
//! let (server_commit, server_confirm) = server.process_client_commit(&client_commit).unwrap();
//! 
//! // 3. 客户端处理服务器的 commit
//! client.process_commit(&server_commit).unwrap();
//! 
//! // 4. 客户端生成 confirm
//! let client_confirm = client.generate_confirm().unwrap();
//! 
//! // 5. 双方验证 confirm
//! server.verify_client_confirm(&client_confirm).unwrap();
//! client.verify_confirm(&server_confirm).unwrap();
//! 
//! // 6. 获取派生的 PMK（用于 AES-256-GCM 加密数据流）
//! let client_pmk = client.get_pmk().unwrap();
//! let server_pmk = server.get_pmk().unwrap();
//! assert_eq!(client_pmk, server_pmk);
//! ```
//! 
//! ## 安全特性
//! 
//! - **Hunt-and-Peck PWE 派生**: 抗离线字典攻击（使用 Blake3）
//! - **Curve25519**: 128-bit 安全强度
//! - **前向保密**: 每次握手使用新的随机数
//! - **双向认证**: 双方都验证对方的身份
//! - **常量时间操作**: 防止时序攻击
//! 
//! ## 密钥派生
//! 
//! SAE 握手成功后，双方获得相同的 PMK (Pairwise Master Key)，可用于：
//! - AES-256-GCM 加密（HLS 视频流）
//! - HMAC-SHA3-256 消息认证
//! - 进一步的密钥派生（KDF）
//! 
//! ## 参考标准
//! 
//! - RFC 7664 (Dragonfly Key Exchange)
//! - Curve25519 椭圆曲线密码学

pub mod crypto;
pub mod client;
pub mod server;
pub mod error;
pub mod types;

pub use client::{SaeClient, SaeClientState};
pub use server::{SaeServer, SaeServerState};
pub use error::{SaeError, Result};
pub use types::{SaeCommit, SaeConfirm, SaeHandshake};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_sae_handshake() {
        let password = b"test_password_123".to_vec();
        let device_id_client = [0x01; 32];
        let device_id_server = [0x02; 32];

        // 客户端
        let mut client = SaeClient::new(password.clone(), device_id_client, device_id_server);
        let client_commit = client.generate_commit().unwrap();

        // 服务器
        let mut server = SaeServer::new(password, device_id_server, device_id_client);
        let (server_commit, server_confirm) = server.process_client_commit(&client_commit).unwrap();

        // 客户端处理服务器响应
        client.process_commit(&server_commit).unwrap();
        let client_confirm = client.generate_confirm().unwrap();

        // 服务器验证客户端 confirm
        server.verify_client_confirm(&client_confirm).unwrap();

        // 客户端验证服务器 confirm
        client.verify_confirm(&server_confirm).unwrap();

        // 验证双方 PMK 相同
        let client_pmk = client.get_pmk().unwrap();
        let server_pmk = server.get_pmk().unwrap();
        assert_eq!(client_pmk, server_pmk);

        println!("✅ SAE handshake completed successfully!");
        println!("PMK: {:?}", hex::encode(client_pmk));
    }
}
