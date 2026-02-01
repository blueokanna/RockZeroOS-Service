use serde::{Deserialize, Deserializer, Serialize, Serializer};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

/// SAE Commit message (using Base64 encoding for JSON serialization)
#[derive(Debug, Clone)]
pub struct SaeCommit {
    /// Elliptic curve group ID (19 = Curve25519)
    pub group_id: u16,
    
    /// Commit scalar (32 bytes)
    pub scalar: [u8; 32],
    
    /// Commit element (33 bytes compressed point for secp256r1)
    pub element: Vec<u8>,
}

/// SAE Confirm message (using Base64 encoding for JSON serialization)
#[derive(Debug, Clone)]
pub struct SaeConfirm {
    /// Send-Confirm counter
    pub send_confirm: u16,
    
    /// Confirm value (32 bytes HMAC)
    pub confirm: [u8; 32],
}

// ============ Custom Serialization/Deserialization (using Base64) ============

impl Serialize for SaeCommit {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        
        let mut state = serializer.serialize_struct("SaeCommit", 3)?;
        state.serialize_field("group_id", &self.group_id)?;
        state.serialize_field("scalar", &BASE64.encode(self.scalar))?;
        state.serialize_field("element", &BASE64.encode(&self.element))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SaeCommit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            GroupId,
            Scalar,
            Element,
        }

        struct SaeCommitVisitor;

        impl<'de> Visitor<'de> for SaeCommitVisitor {
            type Value = SaeCommit;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct SaeCommit")
            }

            fn visit_map<V>(self, mut map: V) -> Result<SaeCommit, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut group_id = None;
                let mut scalar = None;
                let mut element = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::GroupId => {
                            if group_id.is_some() {
                                return Err(de::Error::duplicate_field("group_id"));
                            }
                            group_id = Some(map.next_value()?);
                        }
                        Field::Scalar => {
                            if scalar.is_some() {
                                return Err(de::Error::duplicate_field("scalar"));
                            }
                            let scalar_str: String = map.next_value()?;
                            let scalar_bytes = BASE64
                                .decode(&scalar_str)
                                .map_err(|e| de::Error::custom(format!("Invalid base64 for scalar: {}", e)))?;
                            if scalar_bytes.len() != 32 {
                                return Err(de::Error::custom(format!(
                                    "Scalar must be 32 bytes, got {}",
                                    scalar_bytes.len()
                                )));
                            }
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&scalar_bytes);
                            scalar = Some(arr);
                        }
                        Field::Element => {
                            if element.is_some() {
                                return Err(de::Error::duplicate_field("element"));
                            }
                            let element_str: String = map.next_value()?;
                            let element_bytes = BASE64
                                .decode(&element_str)
                                .map_err(|e| de::Error::custom(format!("Invalid base64 for element: {}", e)))?;
                            // Support 32 bytes (Curve25519) or 33 bytes (secp256r1 compressed point)
                            if element_bytes.len() != 32 && element_bytes.len() != 33 {
                                return Err(de::Error::custom(format!(
                                    "Element must be 32 or 33 bytes, got {}",
                                    element_bytes.len()
                                )));
                            }
                            element = Some(element_bytes);
                        }
                    }
                }

                let group_id = group_id.ok_or_else(|| de::Error::missing_field("group_id"))?;
                let scalar = scalar.ok_or_else(|| de::Error::missing_field("scalar"))?;
                let element = element.ok_or_else(|| de::Error::missing_field("element"))?;

                Ok(SaeCommit {
                    group_id,
                    scalar,
                    element,
                })
            }
        }

        const FIELDS: &[&str] = &["group_id", "scalar", "element"];
        deserializer.deserialize_struct("SaeCommit", FIELDS, SaeCommitVisitor)
    }
}

impl Serialize for SaeConfirm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        
        let mut state = serializer.serialize_struct("SaeConfirm", 2)?;
        state.serialize_field("send_confirm", &self.send_confirm)?;
        state.serialize_field("confirm", &BASE64.encode(self.confirm))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SaeConfirm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            SendConfirm,
            Confirm,
        }

        struct SaeConfirmVisitor;

        impl<'de> Visitor<'de> for SaeConfirmVisitor {
            type Value = SaeConfirm;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct SaeConfirm")
            }

            fn visit_map<V>(self, mut map: V) -> Result<SaeConfirm, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut send_confirm = None;
                let mut confirm = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::SendConfirm => {
                            if send_confirm.is_some() {
                                return Err(de::Error::duplicate_field("send_confirm"));
                            }
                            send_confirm = Some(map.next_value()?);
                        }
                        Field::Confirm => {
                            if confirm.is_some() {
                                return Err(de::Error::duplicate_field("confirm"));
                            }
                            let confirm_str: String = map.next_value()?;
                            let confirm_bytes = BASE64
                                .decode(&confirm_str)
                                .map_err(|e| de::Error::custom(format!("Invalid base64 for confirm: {}", e)))?;
                            if confirm_bytes.len() != 32 {
                                return Err(de::Error::custom(format!(
                                    "Confirm must be 32 bytes, got {}",
                                    confirm_bytes.len()
                                )));
                            }
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&confirm_bytes);
                            confirm = Some(arr);
                        }
                    }
                }

                let send_confirm = send_confirm.ok_or_else(|| de::Error::missing_field("send_confirm"))?;
                let confirm = confirm.ok_or_else(|| de::Error::missing_field("confirm"))?;

                Ok(SaeConfirm {
                    send_confirm,
                    confirm,
                })
            }
        }

        const FIELDS: &[&str] = &["send_confirm", "confirm"];
        deserializer.deserialize_struct("SaeConfirm", FIELDS, SaeConfirmVisitor)
    }
}

/// SAE handshake complete message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaeHandshake {
    pub commit: SaeCommit,
    pub confirm: SaeConfirm,
}

impl SaeCommit {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.group_id.to_le_bytes());
        bytes.extend_from_slice(&self.scalar);
        bytes.extend_from_slice(&self.element);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 66 {
            return None;
        }

        let group_id = u16::from_le_bytes([bytes[0], bytes[1]]);
        let mut scalar = [0u8; 32];
        
        scalar.copy_from_slice(&bytes[2..34]);
        let element = bytes[34..].to_vec();

        Some(Self {
            group_id,
            scalar,
            element,
        })
    }
}

impl SaeConfirm {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.send_confirm.to_le_bytes());
        bytes.extend_from_slice(&self.confirm);
        bytes
    }

    /// Deserialize from bytes
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
            element: vec![2u8; 32],
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
