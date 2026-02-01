//! Integration tests

#[cfg(test)]
mod integration_tests {
    use crate::{SaeClient, SaeServer, KeyDerivation};

    #[test]
    fn test_full_sae_workflow() {
        // Simulate complete SAE handshake and key derivation flow
        
        // 1. Prepare shared password (app_id + user_token + salt)
        let app_id = "rockzero-app";
        let user_token = "user_secret_token_12345";
        let salt = "random_salt_67890";
        let password = format!("{}{}{}", app_id, user_token, salt).into_bytes();

        let client_id = b"client_device_001".to_vec();
        let server_id = b"server_instance_001".to_vec();

        // 2. Create client and server
        let mut client = SaeClient::new(password.clone(), client_id.clone(), server_id.clone());
        let mut server = SaeServer::new(password, server_id, client_id);

        // 3. SAE handshake
        let client_commit = client.generate_commit().unwrap();
        let (server_commit, server_confirm) = server.process_commit(&client_commit).unwrap();
        let client_confirm = client.process_commit(&server_commit).unwrap();
        
        client.verify_confirm(&server_confirm).unwrap();
        server.verify_confirm(&client_confirm).unwrap();

        // 4. Get PMK
        let client_pmk = client.get_pmk().unwrap();
        let server_pmk = server.get_pmk().unwrap();
        
        assert_eq!(client_pmk, server_pmk);

        // 5. Derive application keys
        let client_kd = KeyDerivation::new(client_pmk);
        let server_kd = KeyDerivation::new(server_pmk);

        // Derive HLS encryption key (AES-256)
        let client_hls_key = client_kd.derive_aes256_key(b"hls-encryption", None).unwrap();
        let server_hls_key = server_kd.derive_aes256_key(b"hls-encryption", None).unwrap();
        
        assert_eq!(client_hls_key, server_hls_key);

        // Derive multiple segment keys
        let client_segment_keys = client_kd.derive_multiple_keys(b"hls-segment", 5).unwrap();
        let server_segment_keys = server_kd.derive_multiple_keys(b"hls-segment", 5).unwrap();
        
        assert_eq!(client_segment_keys, server_segment_keys);

        println!("✅ Full SAE workflow test passed!");
        println!("   PMK: {}", hex::encode(client_pmk));
        println!("   HLS Key: {}", hex::encode(client_hls_key));
        println!("   Segment Keys: {} keys generated", client_segment_keys.len());
    }

    #[test]
    fn test_wrong_password() {
        let client_password = b"correct_password".to_vec();
        let server_password = b"wrong_password".to_vec();

        let client_id = b"client".to_vec();
        let server_id = b"server".to_vec();

        let mut client = SaeClient::new(client_password, client_id.clone(), server_id.clone());
        let mut server = SaeServer::new(server_password, server_id, client_id);

        let client_commit = client.generate_commit().unwrap();
        let (server_commit, server_confirm) = server.process_commit(&client_commit).unwrap();
        let client_confirm = client.process_commit(&server_commit).unwrap();

        // Verification should fail
        let client_result = client.verify_confirm(&server_confirm);
        let server_result = server.verify_confirm(&client_confirm);

        assert!(client_result.is_err() || server_result.is_err());
        println!("✅ Wrong password test passed - authentication failed as expected");
    }
}
