//! Ground truth data model and TOML manifest loader.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// A single test case with its expected vulnerabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    /// Unique identifier within the suite.
    pub id: String,
    /// Relative path to the test file/binary within the benchmark data directory.
    pub path: String,
    /// Relative path to the compiled binary for binary analysis mode.
    #[serde(default)]
    pub binary_path: Option<String>,
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
            if let Some(bp) = &case.binary_path {
                if bp.contains("..") || Path::new(bp).is_absolute() {
                    anyhow::bail!(
                        "Invalid binary_path in manifest case '{}': {}. Paths must be relative without '..'",
                        case.id,
                        bp
                    );
                }
            }
            // Restrict case IDs to safe characters (colons allowed for CyberGym task IDs like arvo:1065).
            if !case
                .id
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.' || c == ':')
            {
                anyhow::bail!(
                    "Invalid case ID '{}': must be alphanumeric, underscore, hyphen, dot, or colon",
                    case.id
                );
            }
        }

        Ok(gt)
    }
}

/// Select up to `max_cases` from `cases` with proportional representation of each CWE.
///
/// Without stratification, `take(max_cases)` grabs from the front of the manifest,
/// biasing toward whichever CWEs appear first (e.g., Juliet starts with 672 CWE-114
/// cases, so small `max_cases` values see only CWE-114).
///
/// This function groups cases by their primary CWE, allocates slots proportionally,
/// and round-robins through CWE buckets until `max_cases` is reached. Cases with
/// multiple expected CWEs are grouped by the first CWE. Cases with no expected CWEs
/// (negative cases) are placed in a separate bucket.
pub fn stratified_sample<'a>(cases: &[&'a TestCase], max_cases: usize) -> Vec<&'a TestCase> {
    if cases.len() <= max_cases {
        return cases.to_vec();
    }

    // Group by primary CWE (first expected CWE, or 0 for negative cases).
    let mut buckets: HashMap<u32, Vec<&'a TestCase>> = HashMap::new();
    for case in cases {
        let key = case.expected_cwes.first().copied().unwrap_or(0);
        buckets.entry(key).or_default().push(case);
    }

    // Sort bucket keys for deterministic ordering.
    let mut keys: Vec<u32> = buckets.keys().copied().collect();
    keys.sort();

    // Allocate proportionally, minimum 1 per CWE that has cases.
    let total = cases.len();
    let mut allocations: Vec<(u32, usize)> = keys
        .iter()
        .map(|&k| {
            let bucket_size = buckets[&k].len();
            let alloc = ((bucket_size as f64 / total as f64) * max_cases as f64).floor() as usize;
            (k, alloc.max(1))
        })
        .collect();

    // Distribute remaining slots by largest-remainder method.
    let allocated: usize = allocations.iter().map(|(_, a)| *a).sum();
    if allocated < max_cases {
        let mut remainders: Vec<(usize, f64)> = keys
            .iter()
            .enumerate()
            .map(|(i, &k)| {
                let bucket_size = buckets[&k].len();
                let exact = (bucket_size as f64 / total as f64) * max_cases as f64;
                let floored = allocations[i].1 as f64;
                (i, exact - floored)
            })
            .collect();
        remainders.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let mut extra = max_cases - allocated;
        for (idx, _) in remainders {
            if extra == 0 {
                break;
            }
            // Don't allocate more than the bucket has.
            if allocations[idx].1 < buckets[&allocations[idx].0].len() {
                allocations[idx].1 += 1;
                extra -= 1;
            }
        }
    }

    // Collect cases from each bucket up to its allocation.
    let mut result = Vec::with_capacity(max_cases);
    for (cwe, count) in &allocations {
        let bucket = &buckets[cwe];
        let take = (*count).min(bucket.len());
        result.extend_from_slice(&bucket[..take]);
    }

    // Trim to exact max_cases in case rounding overallocated.
    result.truncate(max_cases);
    result
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
        assert!(gt.cases[0].binary_path.is_none());
        assert!(gt.cases[1].is_negative);
    }

    #[test]
    fn test_load_manifest_with_binary_path() {
        let toml = r#"
suite = "test"
version = "1.0"

[[cases]]
id = "test_bin"
path = "src/test.c"
binary_path = "binaries/test_O0"
expected_cwes = [121]
is_negative = false
language = "c"
"#;
        let gt: GroundTruth = toml::from_str(toml).unwrap();
        assert_eq!(gt.cases[0].binary_path.as_deref(), Some("binaries/test_O0"));
    }

    #[test]
    fn test_reject_binary_path_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("bad.toml");
        std::fs::write(
            &manifest,
            r#"
suite = "bad"
version = "1.0"

[[cases]]
id = "evil"
path = "test.c"
binary_path = "../../etc/shadow"
expected_cwes = [22]
is_negative = false
language = "c"
"#,
        )
        .unwrap();

        let result = GroundTruth::load(&manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("binary_path"));
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

    #[test]
    fn test_stratified_sample_proportional() {
        // Create 100 CWE-114, 50 CWE-121, 50 CWE-190 cases.
        let mut cases = Vec::new();
        for i in 0..100 {
            cases.push(TestCase {
                id: format!("cwe114_{i}"),
                path: "t.c".into(),
                binary_path: None,
                expected_cwes: vec![114],
                is_negative: false,
                language: "c".into(),
            });
        }
        for i in 0..50 {
            cases.push(TestCase {
                id: format!("cwe121_{i}"),
                path: "t.c".into(),
                binary_path: None,
                expected_cwes: vec![121],
                is_negative: false,
                language: "c".into(),
            });
        }
        for i in 0..50 {
            cases.push(TestCase {
                id: format!("cwe190_{i}"),
                path: "t.c".into(),
                binary_path: None,
                expected_cwes: vec![190],
                is_negative: false,
                language: "c".into(),
            });
        }

        let refs: Vec<&TestCase> = cases.iter().collect();
        let result = stratified_sample(&refs, 20);

        assert_eq!(result.len(), 20);

        // Count CWEs in result — should be roughly proportional.
        let cwe114_count = result.iter().filter(|c| c.expected_cwes[0] == 114).count();
        let cwe121_count = result.iter().filter(|c| c.expected_cwes[0] == 121).count();
        let cwe190_count = result.iter().filter(|c| c.expected_cwes[0] == 190).count();

        // 100/200 = 50% → 10, 50/200 = 25% → 5, 50/200 = 25% → 5
        assert_eq!(cwe114_count, 10);
        assert_eq!(cwe121_count, 5);
        assert_eq!(cwe190_count, 5);
    }

    #[test]
    fn test_stratified_sample_no_truncation() {
        let cases = [
            TestCase {
                id: "a".into(),
                path: "t.c".into(),
                binary_path: None,
                expected_cwes: vec![78],
                is_negative: false,
                language: "c".into(),
            },
            TestCase {
                id: "b".into(),
                path: "t.c".into(),
                binary_path: None,
                expected_cwes: vec![121],
                is_negative: false,
                language: "c".into(),
            },
        ];
        let refs: Vec<&TestCase> = cases.iter().collect();
        let result = stratified_sample(&refs, 100);
        assert_eq!(result.len(), 2);
    }
}
