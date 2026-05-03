use crate::crypto::*;
use crate::error::{Result, SaeError};
use crate::types::*;
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};

#[derive(Debug, Clone, PartialEq)]
pub enum SaeServerState {
    Nothing,
    Committed,
    Confirmed,
    Accepted,
}

pub struct SaeServer {
    password: Vec<u8>,
    device_id_self: [u8; 32],
    device_id_peer: [u8; 32],

    state: SaeServerState,

    pwe: Option<EdwardsPoint>,

    rand: Option<Scalar>,
    mask: Option<Scalar>,
    scalar: Option<Scalar>,
    element: Option<EdwardsPoint>,

    peer_scalar: Option<Scalar>,
    peer_element: Option<EdwardsPoint>,

    kck: Option<[u8; 32]>,
    pmk: Option<[u8; 32]>,
    pmkid: Option<[u8; 16]>,

    send_confirm: u16,
    peer_confirm: Option<[u8; 32]>,
}

impl SaeServer {
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

        if client_commit.group_id != 19 {
            return Err(SaeError::UnsupportedGroup(client_commit.group_id));
        }

        let pwe = password_to_element(&self.password, &self.device_id_self, &self.device_id_peer)?;
        self.pwe = Some(pwe);

        let rand = generate_random_scalar();
        let mask = generate_random_mask();
        let scalar = compute_commit_scalar(&rand, &mask);
        let element = compute_commit_element(&rand, &mask, &pwe)?;

        self.rand = Some(rand);
        self.mask = Some(mask);
        self.scalar = Some(scalar);
        self.element = Some(element);

        let peer_scalar = Scalar::from_bytes_mod_order(client_commit.scalar);

        let peer_element = {
            use curve25519_dalek::edwards::CompressedEdwardsY;

            let element_bytes = if client_commit.element.len() == 32 {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&client_commit.element);
                bytes
            } else if client_commit.element.len() == 33 {
                let mut y_bytes = [0u8; 32];
                y_bytes.copy_from_slice(&client_commit.element[1..33]);
                y_bytes
            } else {
                return Err(SaeError::InvalidCommit(format!(
                    "Invalid element length: {} (expected 32 or 33)",
                    client_commit.element.len()
                )));
            };

            let compressed = CompressedEdwardsY(element_bytes);
            compressed.decompress().ok_or_else(|| {
                SaeError::InvalidCommit("Invalid peer element - decompression failed".to_string())
            })?
        };

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

        let shared_secret = compute_pmk(&rand, &peer_scalar, &peer_element, &pwe)?;

        let (kck, pmk) = derive_kck_pmk(
            &shared_secret,
            &scalar,
            &peer_scalar,
            &element,
            &peer_element,
        )?;

        self.kck = Some(kck);
        self.pmk = Some(pmk);

        let pmkid = compute_pmkid(&pmk, &self.device_id_self, &self.device_id_peer)?;
        self.pmkid = Some(pmkid);

        self.state = SaeServerState::Committed;

        let server_commit = SaeCommit {
            group_id: 19,
            scalar: scalar.to_bytes(),
            element: element.compress().to_bytes().to_vec(),
        };

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

    pub fn get_server_confirm(&self) -> Result<SaeConfirm> {
        if self.state != SaeServerState::Confirmed && self.state != SaeServerState::Accepted {
            return Err(SaeError::InvalidState(format!(
                "Cannot get server confirm in state {:?}",
                self.state
            )));
        }

        let kck = self
            .kck
            .ok_or_else(|| SaeError::InvalidState("KCK not derived yet".to_string()))?;
        let scalar = self
            .scalar
            .ok_or_else(|| SaeError::InvalidState("Scalar not set".to_string()))?;
        let peer_scalar = self
            .peer_scalar
            .ok_or_else(|| SaeError::InvalidState("Peer scalar not set".to_string()))?;
        let element = self
            .element
            .ok_or_else(|| SaeError::InvalidState("Element not set".to_string()))?;
        let peer_element = self
            .peer_element
            .ok_or_else(|| SaeError::InvalidState("Peer element not set".to_string()))?;

        let confirm = compute_confirm(
            &kck,
            self.send_confirm,
            &scalar,
            &peer_scalar,
            &element,
            &peer_element,
        )?;

        Ok(SaeConfirm {
            send_confirm: self.send_confirm,
            confirm,
        })
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
