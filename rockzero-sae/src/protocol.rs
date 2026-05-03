

use curve25519_dalek::{edwards::{CompressedEdwardsY, EdwardsPoint}, scalar::Scalar};
use serde::{Deserialize, Serialize};
use crate::{
    crypto::{
        compute_commit_element, compute_commit_scalar, compute_confirm, compute_pmk,
        generate_random_mask, generate_random_scalar, password_to_element, verify_confirm,
    },
    error::{Result, SaeError},
};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaeCommit {

    pub scalar: [u8; 32],

    pub element: [u8; 32],
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaeConfirm {

    pub send_confirm: u16,

    pub confirm: [u8; 32],
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SaeState {
    Init,
    Committed,
    Confirmed,
    Accepted,
}


pub struct SaeClient {
    state: SaeState,
    password: Vec<u8>,
    mac_self: Vec<u8>,
    mac_peer: Vec<u8>,
    

    rand: Option<Scalar>,
    mask: Option<Scalar>,
    scalar: Option<Scalar>,
    element: Option<EdwardsPoint>,
    

    peer_scalar: Option<Scalar>,
    peer_element: Option<EdwardsPoint>,
    

    pmk: Option<[u8; 32]>,
    

    send_confirm: u16,
}

impl SaeClient {







    pub fn new(password: Vec<u8>, mac_self: Vec<u8>, mac_peer: Vec<u8>) -> Self {
        Self {
            state: SaeState::Init,
            password,
            mac_self,
            mac_peer,
            rand: None,
            mask: None,
            scalar: None,
            element: None,
            peer_scalar: None,
            peer_element: None,
            pmk: None,
            send_confirm: 1,
        }
    }


    pub fn generate_commit(&mut self) -> Result<SaeCommit> {
        if self.state != SaeState::Init {
            return Err(SaeError::ProtocolState("Already committed".to_string()));
        }


        let pwd_element = password_to_element(&self.password, &self.mac_self, &self.mac_peer)?;


        let rand = generate_random_scalar();
        let mask = generate_random_mask();


        let scalar = compute_commit_scalar(&rand, &mask);
        let element = compute_commit_element(&rand, &mask, &pwd_element)?;


        self.rand = Some(rand);
        self.mask = Some(mask);
        self.scalar = Some(scalar);
        self.element = Some(element);
        self.state = SaeState::Committed;

        Ok(SaeCommit {
            scalar: scalar.to_bytes(),
            element: element.compress().to_bytes(),
        })
    }


    pub fn process_commit(&mut self, peer_commit: &SaeCommit) -> Result<SaeConfirm> {
        if self.state != SaeState::Committed {
            return Err(SaeError::ProtocolState("Not in committed state".to_string()));
        }


        let peer_scalar = Scalar::from_bytes_mod_order(peer_commit.scalar);
        let compressed = CompressedEdwardsY(peer_commit.element);
        let peer_element = compressed.decompress()
            .ok_or(SaeError::InvalidPoint)?;


        self.peer_scalar = Some(peer_scalar);
        self.peer_element = Some(peer_element);


        let pwd_element = password_to_element(&self.password, &self.mac_self, &self.mac_peer)?;
        let shared_secret = compute_pmk(
            self.rand.as_ref().unwrap(),
            &peer_scalar,
            &peer_element,
            &pwd_element,
        )?;


        let (kck, pmk) = derive_kck_pmk(
            &shared_secret,
            self.scalar.as_ref().unwrap(),
            &peer_scalar,
            self.element.as_ref().unwrap(),
            &peer_element,
        )?;

        self.pmk = Some(pmk);


        let confirm = compute_confirm(
            &kck,
            self.send_confirm,
            self.scalar.as_ref().unwrap(),
            &peer_scalar,
            self.element.as_ref().unwrap(),
            &peer_element,
        )?;

        self.state = SaeState::Confirmed;

        Ok(SaeConfirm {
            send_confirm: self.send_confirm,
            confirm,
        })
    }


    pub fn verify_confirm(&mut self, peer_confirm: &SaeConfirm) -> Result<()> {
        if self.state != SaeState::Confirmed {
            return Err(SaeError::ProtocolState("Not in confirmed state".to_string()));
        }

        let pmk = self.pmk.as_ref().ok_or(SaeError::ProtocolState("PMK not computed".to_string()))?;

        verify_confirm(
            pmk,
            peer_confirm.send_confirm,
            self.scalar.as_ref().unwrap(),
            self.peer_scalar.as_ref().unwrap(),
            self.element.as_ref().unwrap(),
            self.peer_element.as_ref().unwrap(),
            &peer_confirm.confirm,
        )?;

        self.state = SaeState::Accepted;
        Ok(())
    }


    pub fn get_pmk(&self) -> Result<[u8; 32]> {
        self.pmk.ok_or(SaeError::ProtocolState("PMK not available".to_string()))
    }


    pub fn is_authenticated(&self) -> bool {
        self.state == SaeState::Accepted
    }
}


pub struct SaeServer {
    state: SaeState,
    password: Vec<u8>,
    mac_self: Vec<u8>,
    mac_peer: Vec<u8>,
    

    rand: Option<Scalar>,
    mask: Option<Scalar>,
    scalar: Option<Scalar>,
    element: Option<EdwardsPoint>,
    

    peer_scalar: Option<Scalar>,
    peer_element: Option<EdwardsPoint>,
    

    pmk: Option<[u8; 32]>,
    

    send_confirm: u16,
}

impl SaeServer {

    pub fn new(password: Vec<u8>, mac_self: Vec<u8>, mac_peer: Vec<u8>) -> Self {
        Self {
            state: SaeState::Init,
            password,
            mac_self,
            mac_peer,
            rand: None,
            mask: None,
            scalar: None,
            element: None,
            peer_scalar: None,
            peer_element: None,
            pmk: None,
            send_confirm: 1,
        }
    }


    pub fn process_commit(&mut self, peer_commit: &SaeCommit) -> Result<(SaeCommit, SaeConfirm)> {
        if self.state != SaeState::Init {
            return Err(SaeError::ProtocolState("Already committed".to_string()));
        }


        let peer_scalar = Scalar::from_bytes_mod_order(peer_commit.scalar);
        let compressed = CompressedEdwardsY(peer_commit.element);
        let peer_element = compressed.decompress()
            .ok_or(SaeError::InvalidPoint)?;

        self.peer_scalar = Some(peer_scalar);
        self.peer_element = Some(peer_element);


        let pwd_element = password_to_element(&self.password, &self.mac_self, &self.mac_peer)?;


        let rand = generate_random_scalar();
        let mask = generate_random_mask();
        let scalar = compute_commit_scalar(&rand, &mask);
        let element = compute_commit_element(&rand, &mask, &pwd_element)?;

        self.rand = Some(rand);
        self.mask = Some(mask);
        self.scalar = Some(scalar);
        self.element = Some(element);


        let shared_secret = compute_pmk(
            &rand,
            &peer_scalar,
            &peer_element,
            &pwd_element,
        )?;


        let (kck, pmk) = derive_kck_pmk(
            &shared_secret,
            &scalar,
            &peer_scalar,
            &element,
            &peer_element,
        )?;

        self.pmk = Some(pmk);


        let confirm = compute_confirm(
            &kck,
            self.send_confirm,
            &scalar,
            &peer_scalar,
            &element,
            &peer_element,
        )?;

        self.state = SaeState::Confirmed;

        let server_commit = SaeCommit {
            scalar: scalar.to_bytes(),
            element: element.compress().to_bytes(),
        };

        let server_confirm = SaeConfirm {
            send_confirm: self.send_confirm,
            confirm,
        };

        Ok((server_commit, server_confirm))
    }


    pub fn verify_confirm(&mut self, peer_confirm: &SaeConfirm) -> Result<()> {
        if self.state != SaeState::Confirmed {
            return Err(SaeError::ProtocolState("Not in confirmed state".to_string()));
        }

        let pmk = self.pmk.as_ref().ok_or(SaeError::ProtocolState("PMK not computed".to_string()))?;

        verify_confirm(
            pmk,
            peer_confirm.send_confirm,
            self.scalar.as_ref().unwrap(),
            self.peer_scalar.as_ref().unwrap(),
            self.element.as_ref().unwrap(),
            self.peer_element.as_ref().unwrap(),
            &peer_confirm.confirm,
        )?;

        self.state = SaeState::Accepted;
        Ok(())
    }


    pub fn get_pmk(&self) -> Result<[u8; 32]> {
        self.pmk.ok_or(SaeError::ProtocolState("PMK not available".to_string()))
    }


    pub fn is_authenticated(&self) -> bool {
        self.state == SaeState::Accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sae_handshake() {
        let password = b"shared_secret_password_123".to_vec();
        let client_mac = b"client_mac_address".to_vec();
        let server_mac = b"server_mac_address".to_vec();


        let mut client = SaeClient::new(password.clone(), client_mac.clone(), server_mac.clone());
        let mut server = SaeServer::new(password, server_mac, client_mac);


        let client_commit = client.generate_commit().unwrap();


        let (server_commit, server_confirm) = server.process_commit(&client_commit).unwrap();


        let client_confirm = client.process_commit(&server_commit).unwrap();


        client.verify_confirm(&server_confirm).unwrap();


        server.verify_confirm(&client_confirm).unwrap();


        assert!(client.is_authenticated());
        assert!(server.is_authenticated());


        let client_pmk = client.get_pmk().unwrap();
        let server_pmk = server.get_pmk().unwrap();
        assert_eq!(client_pmk, server_pmk);
    }
}
