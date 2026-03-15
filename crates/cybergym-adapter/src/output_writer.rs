//! Isolated per-run output directory creation and result writing.
//!
//! Each scan run gets a unique output directory identified by run ID.
//! Directories are created with restricted permissions (0o750) and files
//! with 0o640. Symlinks in the output path are rejected.

use crate::types::{AdapterError, Report, ScanResult};
use std::path::{Path, PathBuf};

/// Maximum number of findings written to output. Excess findings are truncated.
pub const MAX_FINDINGS: usize = 10_000;

/// Create an isolated output directory for a scan run.
///
/// The directory is created under `base_dir/cybergym-runs/<run_id>/`.
/// On Unix, permissions are set to 0o750 immediately at creation.
pub fn create_run_dir(base_dir: &Path, run_id: &str) -> Result<PathBuf, AdapterError> {
    // Validate run_id: must be alphanumeric + hyphens only
    if !run_id.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return Err(AdapterError::OutputFailed {
            message: "run_id contains invalid characters".to_string(),
        });
    }

    let run_root = base_dir.join("cybergym-runs");
    ensure_directory(&run_root)?;

    let run_dir = run_root.join(run_id);
    create_secure_directory(&run_dir)?;

    Ok(run_dir)
}

/// Write scan results to the output directory as JSON.
///
/// On Unix, the file is created with 0o640 permissions atomically via `OpenOptions`.
pub fn write_results(run_dir: &Path, result: &ScanResult) -> Result<PathBuf, AdapterError> {
    let output_path = run_dir.join("results.json");

    let json = serde_json::to_string_pretty(result).map_err(|e| {
        tracing::debug!("failed to serialize results: {}", e);
        AdapterError::OutputFailed {
            message: "failed to serialize scan results".to_string(),
        }
    })?;

    write_with_permissions(&output_path, json.as_bytes())?;
    Ok(output_path)
}

/// Write a report to the output directory as JSON.
pub fn write_report(run_dir: &Path, report: &Report) -> Result<PathBuf, AdapterError> {
    let output_path = run_dir.join("report.json");

    let json = serde_json::to_string_pretty(report).map_err(|e| {
        tracing::debug!("failed to serialize report: {}", e);
        AdapterError::OutputFailed {
            message: "failed to serialize report".to_string(),
        }
    })?;

    write_with_permissions(&output_path, json.as_bytes())?;
    Ok(output_path)
}

/// Write data to a file with restricted permissions (0o640 on Unix).
///
/// On Unix, uses `OpenOptions` with mode to create the file with correct
/// permissions atomically — no window where the file is world-readable.
fn write_with_permissions(path: &Path, data: &[u8]) -> Result<(), AdapterError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(path)
            .map_err(|e| {
                tracing::debug!("failed to create file {}: {}", path.display(), e);
                AdapterError::OutputFailed {
                    message: if e.kind() == std::io::ErrorKind::AlreadyExists {
                        "output file already exists".to_string()
                    } else {
                        "failed to create output file".to_string()
                    },
                }
            })?;
        file.write_all(data).map_err(|e| {
            tracing::debug!("failed to write to {}: {}", path.display(), e);
            AdapterError::OutputFailed {
                message: "failed to write output file".to_string(),
            }
        })?;
    }

    #[cfg(not(unix))]
    {
        if path.exists() {
            return Err(AdapterError::OutputFailed {
                message: "output file already exists".to_string(),
            });
        }
        std::fs::write(path, data).map_err(|e| {
            tracing::debug!("failed to write to {}: {}", path.display(), e);
            AdapterError::OutputFailed {
                message: "failed to write output file".to_string(),
            }
        })?;
    }

    Ok(())
}

fn ensure_directory(path: &Path) -> Result<(), AdapterError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(AdapterError::OutputFailed {
                    message: "output path is a symlink".to_string(),
                });
            }
            if !metadata.is_dir() {
                return Err(AdapterError::OutputFailed {
                    message: "output path is not a directory".to_string(),
                });
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            create_secure_directory(path)?;
        }
        Err(e) => {
            tracing::debug!("failed to inspect {}: {}", path.display(), e);
            return Err(AdapterError::OutputFailed {
                message: "failed to inspect output directory".to_string(),
            });
        }
    }

    Ok(())
}

fn create_secure_directory(path: &Path) -> Result<(), AdapterError> {
    std::fs::create_dir(path).map_err(|e| {
        tracing::debug!("failed to create directory {}: {}", path.display(), e);
        AdapterError::OutputFailed {
            message: if e.kind() == std::io::ErrorKind::AlreadyExists {
                "output directory already exists".to_string()
            } else {
                "failed to create output directory".to_string()
            },
        }
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o750);
        std::fs::set_permissions(path, perms).map_err(|e| {
            tracing::debug!("failed to set directory permissions: {}", e);
            AdapterError::OutputFailed {
                message: "failed to set directory permissions".to_string(),
            }
        })?;
    }

    let metadata = std::fs::symlink_metadata(path).map_err(|e| {
        tracing::debug!("failed to re-read metadata {}: {}", path.display(), e);
        AdapterError::OutputFailed {
            message: "failed to inspect output directory".to_string(),
        }
    })?;
    if metadata.file_type().is_symlink() {
        return Err(AdapterError::OutputFailed {
            message: "output path is a symlink".to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Finding, ScanStatus};

    #[test]
    fn create_run_dir_creates_directory() {
        let temp = tempfile::tempdir().unwrap();
        let run_dir = create_run_dir(temp.path(), "test-run-123").unwrap();
        assert!(run_dir.exists());
        assert!(run_dir.is_dir());
    }

    #[test]
    fn create_run_dir_rejects_invalid_run_id() {
        let temp = tempfile::tempdir().unwrap();
        let result = create_run_dir(temp.path(), "bad/id");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid characters"));
    }

    #[test]
    fn create_run_dir_rejects_traversal_in_run_id() {
        let temp = tempfile::tempdir().unwrap();
        let result = create_run_dir(temp.path(), "..");
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn create_run_dir_sets_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let run_dir = create_run_dir(temp.path(), "perm-test").unwrap();
        let mode = std::fs::metadata(&run_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o750);
    }

    #[test]
    fn write_results_creates_json_file() {
        let temp = tempfile::tempdir().unwrap();
        let run_dir = create_run_dir(temp.path(), "write-test").unwrap();
        let result = ScanResult {
            run_id: "write-test".to_string(),
            target: "/tmp/test.c".to_string(),
            status: ScanStatus::Complete,
            findings: vec![Finding::new(
                "f1".into(),
                vec![79],
                "high".into(),
                "injection".into(),
                "test.c".into(),
                "main".into(),
                Some(1),
                "injection".into(),
            )],
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
            truncated_count: 0,
        };
        let path = write_results(&run_dir, &result).unwrap();
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("cybergym-adapter"));
    }

    #[test]
    fn create_run_dir_rejects_existing_directory() {
        let temp = tempfile::tempdir().unwrap();
        let existing = temp.path().join("cybergym-runs");
        std::fs::create_dir(&existing).unwrap();
        std::fs::create_dir(existing.join("existing-run")).unwrap();

        let result = create_run_dir(temp.path(), "existing-run");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[cfg(unix)]
    #[test]
    fn create_run_dir_rejects_symlinked_root() {
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, temp.path().join("cybergym-runs")).unwrap();

        let result = create_run_dir(temp.path(), "symlink-root");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn write_results_sets_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let run_dir = create_run_dir(temp.path(), "file-perm-test").unwrap();
        let result = ScanResult {
            run_id: "file-perm-test".to_string(),
            target: "/tmp/test.c".to_string(),
            status: ScanStatus::Complete,
            findings: vec![],
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
            truncated_count: 0,
        };
        let path = write_results(&run_dir, &result).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }

    #[test]
    fn write_results_rejects_existing_file() {
        let temp = tempfile::tempdir().unwrap();
        let run_dir = create_run_dir(temp.path(), "duplicate-write-test").unwrap();
        let result = ScanResult {
            run_id: "duplicate-write-test".to_string(),
            target: "/tmp/test.c".to_string(),
            status: ScanStatus::Complete,
            findings: vec![],
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
            truncated_count: 0,
        };

        let first_path = write_results(&run_dir, &result).unwrap();
        assert!(first_path.exists());
        let second = write_results(&run_dir, &result);
        assert!(second.is_err());
        assert!(second.unwrap_err().to_string().contains("already exists"));
    }
}
