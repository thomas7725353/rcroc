use serde::{Deserialize, Serialize};

pub const COMM_MAGIC: &[u8; 4] = b"croc";
pub const COMM_MAX_FRAME_LEN: usize = 32 * 1024 * 1024;
pub const CHUNK_SIZE: usize = 32 * 1024;
pub const PBKDF2_ITERS: u32 = 100;
pub const DISCOVERY_ADDR: &str = "239.255.255.250:35678";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMeta {
    pub relative_path: String,
    pub size: u64,
    pub mod_time_unix: i64,
    pub hash_hex: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithm {
    Sha256,
    Xxh3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferPlan {
    pub files: Vec<FileMeta>,
    pub empty_dirs: Vec<String>,
    pub chunk_size: usize,
    pub transfers: usize,
    pub no_compress: bool,
    pub hash_algorithm: HashAlgorithm,
    #[serde(default)]
    pub sender_local_relay_addrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRequest {
    pub file_index: u32,
    pub missing_chunks: Vec<ChunkRange>,
    #[serde(default)]
    pub transfers: Option<usize>,
    #[serde(default)]
    pub data_relay_addr: Option<String>,
}
