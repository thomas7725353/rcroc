use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    error::Result,
    models::{CHUNK_SIZE, ChunkRange, FileMeta},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResumeManifest {
    size: u64,
    chunk_size: usize,
    chunks: Vec<bool>,
}

pub struct ResumeState {
    manifest_path: PathBuf,
    manifest: ResumeManifest,
    dirty_updates: usize,
}

impl ResumeState {
    pub async fn load_or_init(target_path: &Path, meta: &FileMeta, enabled: bool) -> Result<Self> {
        let total_chunks = total_chunks(meta.size);
        let manifest_path = manifest_path_for(target_path);

        if !enabled {
            return Ok(Self {
                manifest_path,
                manifest: ResumeManifest {
                    size: meta.size,
                    chunk_size: CHUNK_SIZE,
                    chunks: vec![false; total_chunks],
                },
                dirty_updates: 0,
            });
        }

        if let Ok(raw) = tokio::fs::read(&manifest_path).await
            && let Ok(existing) = serde_json::from_slice::<ResumeManifest>(&raw)
            && existing.size == meta.size
            && existing.chunk_size == CHUNK_SIZE
            && existing.chunks.len() == total_chunks
        {
            return Ok(Self {
                manifest_path,
                manifest: existing,
                dirty_updates: 0,
            });
        }

        let mut chunks = vec![false; total_chunks];

        if let Ok(m) = tokio::fs::metadata(target_path).await {
            let len = m.len();
            if len == meta.size && meta.size > 0 {
                chunks.fill(true);
            } else if len > 0 {
                let full = (len / CHUNK_SIZE as u64) as usize;
                let up_to = full.min(chunks.len());
                for v in chunks.iter_mut().take(up_to) {
                    *v = true;
                }
            }
        }

        Ok(Self {
            manifest_path,
            manifest: ResumeManifest {
                size: meta.size,
                chunk_size: CHUNK_SIZE,
                chunks,
            },
            dirty_updates: 0,
        })
    }

    pub fn missing_ranges(&self) -> Vec<ChunkRange> {
        let mut ranges = Vec::new();
        let mut i = 0usize;
        while i < self.manifest.chunks.len() {
            if self.manifest.chunks[i] {
                i += 1;
                continue;
            }

            let start = i;
            i += 1;
            while i < self.manifest.chunks.len() && !self.manifest.chunks[i] {
                i += 1;
            }

            ranges.push(ChunkRange {
                start: start as u64,
                end: i as u64,
            });
        }
        ranges
    }

    pub fn is_complete(&self) -> bool {
        self.manifest.chunks.iter().all(|v| *v)
    }

    pub fn reset_all(&mut self) {
        self.manifest.chunks.fill(false);
        self.dirty_updates = 0;
    }

    pub async fn mark_chunk(&mut self, chunk_index: usize) -> Result<()> {
        if let Some(v) = self.manifest.chunks.get_mut(chunk_index)
            && !*v
        {
            *v = true;
            self.dirty_updates += 1;
        }

        if self.dirty_updates >= 64 {
            self.persist().await?;
        }

        Ok(())
    }

    pub async fn persist(&mut self) -> Result<()> {
        let raw = serde_json::to_vec(&self.manifest)?;
        tokio::fs::write(&self.manifest_path, raw).await?;
        self.dirty_updates = 0;
        Ok(())
    }

    pub async fn complete_and_cleanup(&mut self) -> Result<()> {
        self.manifest.chunks.fill(true);
        self.persist().await?;
        let _ = tokio::fs::remove_file(&self.manifest_path).await;
        Ok(())
    }
}

pub fn total_chunks(size: u64) -> usize {
    if size == 0 {
        return 0;
    }
    size.div_ceil(CHUNK_SIZE as u64) as usize
}

fn manifest_path_for(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| "file".into());
    name.push(".rcroc.resume.json");
    path.with_file_name(name)
}
