//! # RockZero SAE (Simultaneous Authentication of Equals)
//! 
//! 基于 Dragonfly/SAE 协议的安全密钥协商实现
//! 用于客户端和服务端之间建立安全的共享密钥
//! 
//! ## 协议流程
//! 
//! 1. **初始化**: 双方使用共享密码 (app_id + user_token + salt)
//! 2. **Commit**: 双方生成随机数和掩码，交换承诺值
//! 3. **Confirm**: 双方验证对方的承诺，确认密钥
//! 4. **密钥派生**: 使用 HKDF 从 PMK 派生应用密钥

pub mod error;
pub mod protocol;
pub mod crypto;
pub mod key_derivation;

pub use error::{SaeError, Result};
pub use protocol::{SaeClient, SaeServer, SaeCommit, SaeConfirm};
pub use key_derivation::KeyDerivation;

#[cfg(test)]
mod tests;
