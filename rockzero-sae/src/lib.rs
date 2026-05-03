pub mod client;
pub mod crypto;
pub mod error;
pub mod server;
pub mod types;

pub use client::{SaeClient, SaeClientState};
pub use error::{Result, SaeError};
pub use server::{SaeServer, SaeServerState};
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
