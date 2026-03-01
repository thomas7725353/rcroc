use std::{
    io::Read,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use tokio::task;
use xxhash_rust::xxh3::Xxh3;

use crate::{
    error::{RcrocError, Result},
    models::HashAlgorithm,
};

const HASH_BUF_SIZE: usize = 256 * 1024;

pub async fn hash_file(path: PathBuf, algorithm: HashAlgorithm) -> Result<String> {
    task::spawn_blocking(move || hash_file_blocking(&path, algorithm))
        .await
        .map_err(|e| RcrocError::Protocol(format!("hash worker join failed: {e}")))?
}

pub fn hash_file_blocking(path: &Path, algorithm: HashAlgorithm) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut buf = vec![0u8; HASH_BUF_SIZE];

    match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
        HashAlgorithm::Xxh3 => {
            let mut hasher = Xxh3::new();
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            let digest = hasher.digest();
            Ok(format!("{digest:016x}"))
        }
    }
}
