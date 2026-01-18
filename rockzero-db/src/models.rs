use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseStats {
    pub total_blocks: usize,
    pub total_size: usize,
    pub db_path: String,
    pub recovery_path: String,
}

pub use rockzero_common::{FileMetadata, InviteCode, MediaItem, User, Widget};
