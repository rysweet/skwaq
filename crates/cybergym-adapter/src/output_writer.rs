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
    if !run_id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-')
    {
        return Err(AdapterError::OutputFailed {
            message: "run_id contains invalid characters".to_string(),
        });
    }

    let run_dir = base_dir.join("cybergym-runs").join(run_id);

    // Reject if path already exists as a symlink
    if run_dir.symlink_metadata().is_ok() {
        let meta =
            std::fs::symlink_metadata(&run_dir).map_err(|e| AdapterError::OutputFailed {
                message: format!("failed to read metadata: {}", e),
            })?;
        if meta.file_type().is_symlink() {
            return Err(AdapterError::OutputFailed {
                message: "output path is a symlink".to_string(),
            });
        }
    }

    std::fs::create_dir_all(&run_dir).map_err(|e| {
        tracing::debug!("failed to create run directory {}: {}", run_dir.display(), e);
        AdapterError::OutputFailed {
            message: "failed to create output directory".to_string(),
        }
    })?;

    // Set directory permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o750);
        std::fs::set_permissions(&run_dir, perms).map_err(|e| {
            tracing::debug!("failed to set directory permissions: {}", e);
            AdapterError::OutputFailed {
                message: "failed to set directory permissions".to_string(),
            }
        })?;
    }

    Ok(run_dir)
}

/// Write scan results to the output directory as JSON.
///
/// File permissions are set to 0o640 on Unix.
pub fn write_results(run_dir: &Path, result: &ScanResult) -> Result<PathBuf, AdapterError> {
    let output_path = run_dir.join("results.json");

    let json = serde_json::to_string_pretty(result).map_err(|e| {
        tracing::debug!("failed to serialize results: {}", e);
        AdapterError::OutputFailed {
            message: "failed to serialize scan results".to_string(),
        }
    })?;

    std::fs::write(&output_path, &json).map_err(|e| {
        tracing::debug!("failed to write results to {}: {}", output_path.display(), e);
        AdapterError::OutputFailed {
            message: "failed to write results file".to_string(),
        }
    })?;

    set_file_permissions(&output_path)?;
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

    std::fs::write(&output_path, &json).map_err(|e| {
        tracing::debug!("failed to write report to {}: {}", output_path.display(), e);
        AdapterError::OutputFailed {
            message: "failed to write report file".to_string(),
        }
    })?;

    set_file_permissions(&output_path)?;
    Ok(output_path)
}

/// Set file permissions to 0o640 on Unix.
#[cfg(unix)]
fn set_file_permissions(path: &Path) -> Result<(), AdapterError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o640);
    std::fs::set_permissions(path, perms).map_err(|e| {
        tracing::debug!("failed to set file permissions on {}: {}", path.display(), e);
        AdapterError::OutputFailed {
            message: "failed to set file permissions".to_string(),
        }
    })
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) -> Result<(), AdapterError> {
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
        assert!(result.unwrap_err().to_string().contains("invalid characters"));
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
}
