//! Trust boundary defense for scan targets and configuration.
//!
//! Validates all inputs before any agent execution begins.
//! Rejects path traversal, symlinks to outside allowed roots,
//! oversized strings, and nonexistent targets.

use crate::types::AdapterError;
use std::path::Path;

/// Maximum allowed string length for target paths and config values.
const MAX_STRING_LEN: usize = 4096;

/// Validate a scan target path.
///
/// Checks:
/// - String length within bounds
/// - Path exists
/// - Path resolves to a real location (canonicalize)
/// - No symlinks pointing outside the canonical path's parent
/// - No path traversal components
pub fn validate_target(target: &str) -> Result<std::path::PathBuf, AdapterError> {
    // Length check
    if target.len() > MAX_STRING_LEN {
        return Err(AdapterError::InputValidation {
            message: format!(
                "target path exceeds maximum length of {} characters",
                MAX_STRING_LEN
            ),
        });
    }

    // Empty check
    if target.is_empty() {
        return Err(AdapterError::InputValidation {
            message: "target path is empty".to_string(),
        });
    }

    // Reject obvious traversal patterns before touching the filesystem
    if target.contains("..") {
        return Err(AdapterError::InputValidation {
            message: "target path contains traversal component".to_string(),
        });
    }

    // Reject null bytes (could bypass C-level path checks)
    if target.contains('\0') {
        return Err(AdapterError::InputValidation {
            message: "target path contains null byte".to_string(),
        });
    }

    let path = Path::new(target);

    let metadata = std::fs::symlink_metadata(path).map_err(|_| AdapterError::InputValidation {
        message: "target does not exist".to_string(),
    })?;

    if metadata.file_type().is_symlink() {
        return Err(AdapterError::InputValidation {
            message: "target path must not be a symlink".to_string(),
        });
    }

    // Must be a file or directory
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(AdapterError::InputValidation {
            message: "target is not a file or directory".to_string(),
        });
    }

    // Canonicalize only after rejecting symlinks on the original user input.
    let canonical = path
        .canonicalize()
        .map_err(|_| AdapterError::InputValidation {
            message: "unable to resolve target path".to_string(),
        })?;

    Ok(canonical)
}

/// Validate a timeout value in seconds.
pub fn validate_timeout(timeout_secs: u64) -> Result<(), AdapterError> {
    // Maximum 30 minutes
    const MAX_TIMEOUT: u64 = 1800;
    if timeout_secs == 0 {
        return Err(AdapterError::InputValidation {
            message: "timeout must be greater than zero".to_string(),
        });
    }
    if timeout_secs > MAX_TIMEOUT {
        return Err(AdapterError::InputValidation {
            message: format!("timeout exceeds maximum of {}s", MAX_TIMEOUT),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_target() {
        let result = validate_target("");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("empty"),
            "should mention empty"
        );
    }

    #[test]
    fn rejects_path_traversal() {
        let result = validate_target("/tmp/../etc/passwd");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("traversal"));
    }

    #[test]
    fn rejects_null_byte() {
        let result = validate_target("/tmp/foo\0bar");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("null byte"));
    }

    #[test]
    fn rejects_oversized_target() {
        let long = "a".repeat(MAX_STRING_LEN + 1);
        let result = validate_target(&long);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("maximum length"));
    }

    #[test]
    fn rejects_nonexistent_target() {
        let result = validate_target("/nonexistent/path/to/file.c");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_target() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("real.c");
        let link = temp.path().join("link.c");
        std::fs::write(&target, "int main(void) { return 0; }\n").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = validate_target(link.to_str().unwrap());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must not be a symlink"));
    }

    #[test]
    fn accepts_valid_file() {
        // /tmp always exists
        let result = validate_target("/tmp");
        assert!(result.is_ok());
    }

    #[test]
    fn validate_timeout_rejects_zero() {
        assert!(validate_timeout(0).is_err());
    }

    #[test]
    fn validate_timeout_rejects_too_large() {
        assert!(validate_timeout(1801).is_err());
    }

    #[test]
    fn validate_timeout_accepts_valid() {
        assert!(validate_timeout(300).is_ok());
        assert!(validate_timeout(1800).is_ok());
    }
}
