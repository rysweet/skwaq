//! Benchmark data download, integrity verification, and extraction.

use sha2::{Digest, Sha256};
use std::path::Path;

/// Download a file, verify its SHA-256, and extract it.
/// SHA-256 verification is mandatory -- empty checksums are rejected.
pub async fn download_and_extract(
    url: &str,
    expected_sha256: &str,
    dest: &Path,
) -> anyhow::Result<()> {
    // Mandatory SHA-256 (review finding #1).
    if expected_sha256.is_empty() {
        anyhow::bail!(
            "SHA-256 checksum is required for download: {}. \
             Add the hash to the ground truth manifest.",
            url
        );
    }

    std::fs::create_dir_all(dest)?;

    let tmp = tempfile::NamedTempFile::new()?;
    let tmp_path = tmp.path().to_path_buf();

    tracing::info!("Downloading {}...", url);
    let response = reqwest::get(url).await?;
    let bytes = response.bytes().await?;
    std::fs::write(&tmp_path, &bytes)?;

    // Verify SHA-256.
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = format!("{:x}", hasher.finalize());
    if hash != expected_sha256 {
        anyhow::bail!(
            "SHA-256 mismatch for {}:\n  expected: {}\n  got:      {}",
            url,
            expected_sha256,
            hash
        );
    }

    // Extract based on extension, with safe path validation.
    if url.ends_with(".zip") {
        extract_zip(&tmp_path, dest)?;
    } else if url.ends_with(".tar.gz") || url.ends_with(".tgz") {
        extract_tar_gz(&tmp_path, dest)?;
    } else {
        let filename = url.rsplit('/').next().unwrap_or("data");
        std::fs::copy(&tmp_path, dest.join(filename))?;
    }

    Ok(())
}

fn extract_zip(archive: &Path, dest: &Path) -> anyhow::Result<()> {
    let file = std::fs::File::open(archive)?;
    let mut zip = zip::ZipArchive::new(file)?;

    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry.name().to_string();

        // Safe extraction: reject paths with .. or absolute paths (review finding #7).
        if name.contains("..") || Path::new(&name).is_absolute() {
            anyhow::bail!(
                "Unsafe path in zip archive: '{}'. Rejecting extraction.",
                name
            );
        }

        let out_path = dest.join(&name);
        if entry.is_dir() {
            std::fs::create_dir_all(&out_path)?;
        } else {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut outfile = std::fs::File::create(&out_path)?;
            std::io::copy(&mut entry, &mut outfile)?;
        }
    }
    Ok(())
}

fn extract_tar_gz(archive: &Path, dest: &Path) -> anyhow::Result<()> {
    let file = std::fs::File::open(archive)?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut tar = tar::Archive::new(gz);

    for entry in tar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        let path_str = path.to_string_lossy();

        // Safe extraction: reject paths with .. or absolute paths (review finding #7).
        if path_str.contains("..") || path.is_absolute() {
            anyhow::bail!(
                "Unsafe path in tar archive: '{}'. Rejecting extraction.",
                path_str
            );
        }

        entry.unpack_in(dest)?;
    }
    Ok(())
}
