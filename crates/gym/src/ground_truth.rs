//! Ground truth data model and TOML manifest loader.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// A single test case with its expected vulnerabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    /// Unique identifier within the suite.
    pub id: String,
    /// Relative path to the test file/binary within the benchmark data directory.
    pub path: String,
    /// CWE IDs that SHOULD be detected in this test case.
    pub expected_cwes: Vec<u32>,
    /// Whether this is a "good" (patched) variant that should have NO findings.
    pub is_negative: bool,
    /// Language of the test case (c, cpp, java, python, etc.).
    pub language: String,
}

/// Ground truth for an entire benchmark suite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruth {
    /// Suite name (juliet, cgc, cyberseceval, fixtures).
    pub suite: String,
    /// Version or commit hash of the benchmark data.
    pub version: String,
    /// URL to download the benchmark data (empty for fixtures).
    #[serde(default)]
    pub download_url: String,
    /// SHA-256 of the download archive for integrity verification.
    #[serde(default)]
    pub download_sha256: String,
    /// All test cases in this suite.
    pub cases: Vec<TestCase>,
}

impl GroundTruth {
    /// Load from a TOML manifest file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let gt: Self = toml::from_str(&text)?;

        // Validate: reject paths with .. or absolute paths.
        for case in &gt.cases {
            if case.path.contains("..") || Path::new(&case.path).is_absolute() {
                anyhow::bail!(
                    "Invalid path in manifest case '{}': {}. Paths must be relative without '..'",
                    case.id,
                    case.path
                );
            }
            // Restrict case IDs to safe characters.
            if !case
                .id
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
            {
                anyhow::bail!(
                    "Invalid case ID '{}': must be alphanumeric, underscore, hyphen, or dot",
                    case.id
                );
            }
        }

        Ok(gt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_manifest() {
        let toml = r#"
suite = "test"
version = "1.0"
download_url = ""
download_sha256 = ""

[[cases]]
id = "test_case_1"
path = "src/test.c"
expected_cwes = [121]
is_negative = false
language = "c"

[[cases]]
id = "test_case_1_good"
path = "src/test_good.c"
expected_cwes = []
is_negative = true
language = "c"
"#;
        let gt: GroundTruth = toml::from_str(toml).unwrap();
        assert_eq!(gt.suite, "test");
        assert_eq!(gt.cases.len(), 2);
        assert_eq!(gt.cases[0].expected_cwes, vec![121]);
        assert!(gt.cases[1].is_negative);
    }

    #[test]
    fn test_reject_path_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("bad.toml");
        std::fs::write(
            &manifest,
            r#"
suite = "bad"
version = "1.0"

[[cases]]
id = "evil"
path = "../../etc/passwd"
expected_cwes = [22]
is_negative = false
language = "c"
"#,
        )
        .unwrap();

        let result = GroundTruth::load(&manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains(".."));
    }
}
