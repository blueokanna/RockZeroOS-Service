pub mod aes;
pub mod bulletproofs_ffi;
pub mod crypto;
pub mod ed25519;
pub mod hash;
pub mod jwt;
pub mod signature;
pub mod tls;
pub mod utils;
pub mod zkp;

pub use aes::{decrypt_aes256_gcm, encrypt_aes256_gcm};
pub use hash::{blake3_hash, blake3_hash_single, sha3_256_hash, sha3_256_hash_multi};
pub use signature::{generate_keypair, sign, verify};
pub use tls::{load_rustls_config, TlsConfig};
pub use utils::{
    constant_time_compare, crc32_checksum, crc32_verify, secure_random_base64, secure_random_bytes,
    secure_random_hex, secure_zero, secure_zero_key,
};
pub use zkp::{
    EnhancedPasswordProof, SchnorrProof, BoundStrengthProof, PasswordRegistration, ZkpContext,
};

pub use bulletproofs_ffi::{BulletproofsContext, BulletproofsRangeProof, VideoStreamProof};
pub use jwt::JwtEncoder;
pub use rockzero_sae::{SaeClient, SaeCommit, SaeConfirm, SaeServer};
