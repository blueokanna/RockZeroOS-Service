use crate::crypto::*;
use crate::error::{Result, SaeError};
use crate::types::*;
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};

#[derive(Debug, Clone, PartialEq)]
pub enum SaeClientState {
    Nothing,
    Committed,
    Confirmed,
    Accepted,
}

pub struct SaeClient {
    password: Vec<u8>,
    device_id_self: [u8; 32],
    device_id_peer: [u8; 32],

    state: SaeClientState,

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

    sync: u32,
    max_sync: u32,
}

impl SaeClient {
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

    pub fn generate_commit(&mut self) -> Result<SaeCommit> {
        if self.state != SaeClientState::Nothing {
            return Err(SaeError::InvalidState(format!(
                "Cannot generate commit in state {:?}",
                self.state
            )));
        }

        if self.pwe.is_none() {
            let pwe =
                password_to_element(&self.password, &self.device_id_self, &self.device_id_peer)?;
            self.pwe = Some(pwe);
        }

        let pwe = self.pwe.as_ref().unwrap();

        let rand = generate_random_scalar();
        let mask = generate_random_mask();

        let scalar = compute_commit_scalar(&rand, &mask);
        let element = compute_commit_element(&rand, &mask, pwe)?;

        self.rand = Some(rand);
        self.mask = Some(mask);
        self.scalar = Some(scalar);
        self.element = Some(element);

        self.state = SaeClientState::Committed;

        Ok(SaeCommit {
            group_id: 19,
            scalar: scalar.to_bytes(),
            element: element.compress().to_bytes().to_vec(),
        })
    }

    pub fn process_commit(&mut self, peer_commit: &SaeCommit) -> Result<()> {
        if self.state != SaeClientState::Committed {
            return Err(SaeError::InvalidState(format!(
                "Cannot process commit in state {:?}",
                self.state
            )));
        }

        if peer_commit.group_id != 19 {
            return Err(SaeError::UnsupportedGroup(peer_commit.group_id));
        }

        let peer_scalar = Scalar::from_bytes_mod_order(peer_commit.scalar);

        let peer_element = {
            use curve25519_dalek::edwards::CompressedEdwardsY;

            let element_bytes = if peer_commit.element.len() == 32 {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&peer_commit.element);
                bytes
            } else if peer_commit.element.len() == 33 {
                let mut y_bytes = [0u8; 32];
                y_bytes.copy_from_slice(&peer_commit.element[1..33]);
                y_bytes
            } else {
                return Err(SaeError::InvalidCommit(format!(
                    "Invalid element length: {} (expected 32 or 33)",
                    peer_commit.element.len()
                )));
            };

            let compressed = CompressedEdwardsY(element_bytes);
            compressed.decompress().ok_or_else(|| {
                SaeError::InvalidCommit("Invalid peer element - decompression failed".to_string())
            })?
        };

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

        self.peer_scalar = Some(peer_scalar);
        self.peer_element = Some(peer_element);

        let shared_secret = compute_pmk(
            &self.rand.unwrap(),
            &peer_scalar,
            &peer_element,
            self.pwe.as_ref().unwrap(),
        )?;

        let (kck, pmk) = derive_kck_pmk(
            &shared_secret,
            &self.scalar.unwrap(),
            &peer_scalar,
            &self.element.unwrap(),
            &peer_element,
        )?;

        self.kck = Some(kck);
        self.pmk = Some(pmk);

        let pmkid = compute_pmkid(&pmk, &self.device_id_peer, &self.device_id_self)?;
        self.pmkid = Some(pmkid);

        Ok(())
    }

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

        let confirm = compute_confirm(
            &self.kck.unwrap(),
            self.send_confirm,
            &self.scalar.unwrap(),
            &self.peer_scalar.unwrap(),
            &self.element.unwrap(),
            &self.peer_element.unwrap(),
        )?;

        Ok(SaeConfirm {
            send_confirm: self.send_confirm,
            confirm,
        })
    }

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

    pub fn get_pmk(&self) -> Result<[u8; 32]> {
        self.pmk
            .ok_or_else(|| SaeError::InvalidState("PMK not derived yet".to_string()))
    }

    pub fn get_pmkid(&self) -> Result<[u8; 16]> {
        self.pmkid
            .ok_or_else(|| SaeError::InvalidState("PMKID not derived yet".to_string()))
    }

    pub fn state(&self) -> &SaeClientState {
        &self.state
    }

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

    pub fn is_max_sync_reached(&self) -> bool {
        self.sync >= self.max_sync
    }

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

        let client_commit = client.generate_commit().unwrap();
        assert_eq!(client.state(), &SaeClientState::Committed);

        let mut server = SaeClient::new(password, device_id_server, device_id_client);
        let server_commit = server.generate_commit().unwrap();

        client.process_commit(&server_commit).unwrap();

        let _client_confirm = client.generate_confirm().unwrap();

        server.process_commit(&client_commit).unwrap();
        let server_confirm = server.generate_confirm().unwrap();

        client.verify_confirm(&server_confirm).unwrap();
        assert_eq!(client.state(), &SaeClientState::Accepted);

        let client_pmk = client.get_pmk().unwrap();
        let server_pmk = server.get_pmk().unwrap();
        assert_eq!(client_pmk, server_pmk);
    }
}
