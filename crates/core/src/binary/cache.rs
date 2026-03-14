//! Content-addressed cache for binary analysis results.
//! Ghidra analysis takes minutes - never redo it for the same binary.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use crate::binary::types::GhidraAnalysis;

pub struct AnalysisCache {
    cache_dir: PathBuf,
}

impl AnalysisCache {
    pub fn new(cache_dir: PathBuf) -> Self {
        Self { cache_dir }
    }

    pub fn get_json(&self, binary_path: &Path, max_bytes: u64) -> Option<serde_json::Value> {
        let hash = self.cache_key(binary_path)?;
        let cache_path = self.cache_dir.join(&hash).join("analysis.json");
        if cache_path.exists() {
            let metadata = std::fs::metadata(&cache_path).ok()?;
            if metadata.len() > max_bytes {
                tracing::warn!(
                    "Ignoring oversized cached Ghidra analysis at {} ({} bytes > {} bytes)",
                    cache_path.display(),
                    metadata.len(),
                    max_bytes,
                );
                return None;
            }
            let data = std::fs::read_to_string(&cache_path).ok()?;
            serde_json::from_str(&data).ok()
        } else {
            None
        }
    }

    pub fn put(&self, binary_path: &Path, analysis: &GhidraAnalysis) -> anyhow::Result<()> {
        let hash = self
            .cache_key(binary_path)
            .ok_or_else(|| anyhow::anyhow!("Cannot hash binary"))?;
        let dir = self.cache_dir.join(&hash);
        std::fs::create_dir_all(&dir)?;
        let data = serde_json::to_string_pretty(analysis)?;
        std::fs::write(dir.join("analysis.json"), data)?;
        Ok(())
    }

    pub fn has(&self, binary_path: &Path) -> bool {
        self.cache_key(binary_path)
            .map(|hash| self.cache_dir.join(hash).join("analysis.json").exists())
            .unwrap_or(false)
    }

    pub fn cache_key(&self, path: &Path) -> Option<String> {
        let data = std::fs::read(path).ok()?;
        let hash = Sha256::digest(&data);
        Some(format!("{:x}", hash))
    }
}
