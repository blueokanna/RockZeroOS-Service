//! # RockZero SAE (Simultaneous Authentication of Equals)
//!
//! A secure authentication library based on SAE standard for protecting data streams (e.g., HLS video).
//!
//! ## Overview
//!
//! SAE (Simultaneous Authentication of Equals) provides:
//! - Dictionary attack resistant password authentication
//! - Forward Secrecy
//! - Peer authentication (both parties are equal)
//!
//! This implementation is based on Curve25519 elliptic curve, suitable for:
//! - Secure video streaming (HLS with AES-256-GCM encryption)
//! - Point-to-point secure communication
//! - Scenarios requiring strong password authentication
//!
//! ## Use Cases
//!
//! This implementation focuses on general device authentication and data stream security:
//! - No dependency on specific hardware or drivers
//! - Can be used for any scenario requiring secure key exchange
//! - Optimized for HLS video encryption key derivation (AES-256-GCM)
//!
//! ## Example
//!
//! ### Client-Server Handshake
//!
//! ```no_run
//! use rockzero_sae::{SaeClient, SaeServer};
//!
//! let password = b"secure_password_123".to_vec();
//! let client_id = [0x01; 32];
//! let server_id = [0x02; 32];
//!
//! let mut client = SaeClient::new(password.clone(), client_id, server_id);
//! let client_commit = client.generate_commit().unwrap();
//!
//! let mut server = SaeServer::new(password, server_id, client_id);
//! let (server_commit, server_confirm) = server.process_client_commit(&client_commit).unwrap();
//!
//! client.process_commit(&server_commit).unwrap();
//! let client_confirm = client.generate_confirm().unwrap();
//!
//! server.verify_client_confirm(&client_confirm).unwrap();
//! client.verify_confirm(&server_confirm).unwrap();
//!
//! let client_pmk = client.get_pmk().unwrap();
//! let server_pmk = server.get_pmk().unwrap();
//! assert_eq!(client_pmk, server_pmk);
//! ```
//!
//! ## Security Features
//!
//! - Hunt-and-Peck PWE derivation: Offline dictionary attack resistant (using Blake3)
//! - Curve25519: 128-bit security strength
//! - Forward secrecy: Fresh randomness for each handshake
//! - Mutual authentication: Both parties verify each other
//! - Constant-time operations: Timing attack resistant
//!
//! ## Key Derivation
//!
//! After successful SAE handshake, both parties obtain the same PMK (Pairwise Master Key):
//! - AES-256-GCM encryption (HLS video streams)
//! - HMAC-SHA3-256 message authentication
//! - Further key derivation (KDF)
//!
//! ## References
//!
//! - RFC 7664 (Dragonfly Key Exchange)
//! - Curve25519 elliptic curve cryptography

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

        let mut client = SaeClient::new(password.clone(), device_id_client, device_id_server);
        let client_commit = client.generate_commit().unwrap();

        let mut server = SaeServer::new(password, device_id_server, device_id_client);
        let (server_commit, server_confirm) = server.process_client_commit(&client_commit).unwrap();

        client.process_commit(&server_commit).unwrap();
        let client_confirm = client.generate_confirm().unwrap();

        server.verify_client_confirm(&client_confirm).unwrap();
        client.verify_confirm(&server_confirm).unwrap();

        let client_pmk = client.get_pmk().unwrap();
        let server_pmk = server.get_pmk().unwrap();
        assert_eq!(client_pmk, server_pmk);

        println!("SAE handshake completed successfully!");
        println!("PMK: {:?}", hex::encode(client_pmk));
    }
}
