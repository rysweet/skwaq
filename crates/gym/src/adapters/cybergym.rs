//! CyberGym benchmark adapter.
//!
//! Integrates the UC Berkeley CyberGym evaluation framework (cybergym.io)
//! as a benchmark suite. CyberGym provides 1,507 real-world vulnerability
//! instances from OSS-Fuzz across 188 open-source projects.
//!
//! Each instance provides:
//! - `repo-vul.tar.gz`: pre-patch source code (positive case)
//! - `repo-fix.tar.gz`: post-patch source code (negative case, when available)
//! - `description.txt`: vulnerability description
//! - `patch.diff`: the fix
//!
//! Phase 1 integration is detection-only: can skwaq find the vulnerability
//! in pre-patch code? This is NOT PoC reproduction parity with CyberGym's
//! full evaluation (which requires generating working exploits).

use super::*;
use crate::agentic::AnalysisHints;
use crate::ground_truth::GroundTruth;
use std::path::{Path, PathBuf};

pub struct CyberGymAdapter {
    manifest_path: PathBuf,
}

impl CyberGymAdapter {
    pub fn new(manifest_path: PathBuf) -> Self {
        Self { manifest_path }
    }
}

#[async_trait(?Send)]
impl BenchmarkAdapter for CyberGymAdapter {
    fn name(&self) -> &str {
        "cybergym"
    }

    fn ground_truth(&self) -> anyhow::Result<GroundTruth> {
        GroundTruth::load(&self.manifest_path)
    }

    async fn setup(&self, config: &BenchmarkConfig) -> anyhow::Result<PathBuf> {
        let dest = config.cache_dir.join("cybergym");
        if dest.join(".ready").exists() {
            return Ok(dest);
        }

        // CyberGym data lives on HuggingFace (~130-240GB).
        // Require manual clone:
        //   git lfs install
        //   git clone https://huggingface.co/datasets/sunblaze-ucb/cybergym <dest>/dataset
        //
        // For the subset (10 cases):
        //   Download per instructions at https://github.com/sunblaze-ucb/cybergym
        let dataset_dir = dest.join("dataset");
        if !dataset_dir.exists() {
            anyhow::bail!(
                "CyberGym dataset not found at {}.\n\
                 Clone from HuggingFace:\n  \
                 git lfs install\n  \
                 git clone https://huggingface.co/datasets/sunblaze-ucb/cybergym {}\n\
                 Or for a small subset, see https://github.com/sunblaze-ucb/cybergym",
                dataset_dir.display(),
                dataset_dir.display()
            );
        }

        // Extract repo-vul archives for each case in the manifest
        let gt = self.ground_truth()?;
        let cases_dir = dest.join("cases");
        std::fs::create_dir_all(&cases_dir)?;

        for case in &gt.cases {
            let safe_id = sanitize_case_id(&case.id);
            let case_dir = cases_dir.join(&safe_id);
            if case_dir.exists() {
                continue;
            }

            // Determine archive path from task ID (arvo:NNN or oss-fuzz:NNN)
            let archive = archive_path_for_case(&dataset_dir, &case.id, case.is_negative);
            if !archive.exists() {
                tracing::warn!(
                    "CyberGym archive not found for case {}: {}",
                    case.id,
                    archive.display()
                );
                continue;
            }

            std::fs::create_dir_all(&case_dir)?;
            if let Err(e) = extract_tar_gz(&archive, &case_dir) {
                tracing::warn!(
                    "CyberGym: skipping case {} — extraction failed: {}",
                    case.id,
                    e
                );
                // Remove partial extraction
                let _ = std::fs::remove_dir_all(&case_dir);
                continue;
            }
        }

        std::fs::write(dest.join(".ready"), "")?;
        Ok(dest)
    }

    fn is_ready(&self, config: &BenchmarkConfig) -> bool {
        config.cache_dir.join("cybergym").join(".ready").exists()
    }

    async fn compile(&self, _data_dir: &Path, _config: &BenchmarkConfig) -> anyhow::Result<()> {
        // CyberGym cases are analyzed as source code in Phase 1.
        // Binary compilation requires Docker (Phase 2 future work).
        Ok(())
    }

    async fn run_case(
        &self,
        case: &TestCase,
        data_dir: &Path,
        config: &BenchmarkConfig,
    ) -> anyhow::Result<Vec<DetectedFinding>> {
        let case_dir = data_dir.join("cases").join(sanitize_case_id(&case.id));
        if !case_dir.exists() {
            // Case not extracted — return empty findings (scores as FN for
            // positive cases, TN for negative). This is honest: we can't
            // analyze what we don't have.
            tracing::debug!(
                "CyberGym case {} not extracted, returning no findings",
                case.id
            );
            return Ok(vec![]);
        }

        // Use patch.diff to identify only the vulnerable files instead of
        // walking the entire repo tree (which can be 900MB+ for projects
        // like FFmpeg or Wireshark).
        let source_files = patch_affected_files(&case_dir, data_dir, &case.id)
            .unwrap_or_else(|| collect_source_files_limited(&case_dir, 10));

        // Filter out header-only files with no executable code (issue #394).
        // Some benchmarks attribute project-level CVEs to all files including
        // headers that only contain preprocessor directives.
        let source_files: Vec<_> = source_files
            .into_iter()
            .filter(|f| !is_header_only(f))
            .collect();

        if source_files.is_empty() {
            tracing::warn!("No C/C++ source files found in {}", case_dir.display());
            return Ok(vec![]);
        }

        // In quick mode, use multi-file shared-graph analysis for cross-file
        // relationship detection.
        if config.quick_mode {
            return crate::agentic::run_multi_file_pattern_analysis(&source_files);
        }

        // Load optional context hints (description.txt, patch.diff) for
        // hint-augmented agentic analysis.
        let hints = load_case_hints(data_dir, &case.id);

        let mut all_findings = Vec::new();
        for path in &source_files {
            let findings = if config.llm_only {
                crate::agentic::run_llm_only_source_analysis(path, config.timeout_secs).await
            } else {
                crate::agentic::run_agentic_source_analysis_with_hints(
                    path,
                    config.timeout_secs,
                    &hints,
                )
                .await
            };
            match findings {
                Ok(f) => all_findings.extend(f),
                Err(e) => tracing::debug!("CyberGym file {} failed: {}", path.display(), e),
            }
        }

        Ok(all_findings)
    }

    fn map_finding_to_cwes(&self, finding: &DetectedFinding) -> Vec<u32> {
        crate::adapters::default_map_finding_to_cwes(finding)
    }
}

/// Load optional context hints for a CyberGym case.
///
/// Looks for description.txt and patch.diff in the dataset directory
/// alongside the case archives. These are injected into the agentic
/// analysis as "prior intelligence" and "known fix" context.
fn load_case_hints(data_dir: &Path, case_id: &str) -> AnalysisHints {
    let mut hints = AnalysisHints::default();

    // Strip "-fix" suffix from negative case IDs
    let base_id = case_id.strip_suffix("-fix").unwrap_or(case_id);

    if let Some((source, id)) = base_id.split_once(':') {
        let case_data_dir = data_dir.join("dataset").join("data").join(source).join(id);

        let desc_path = case_data_dir.join("description.txt");
        if desc_path.exists() {
            if let Ok(desc) = std::fs::read_to_string(&desc_path) {
                hints.vuln_description = Some(desc);
            }
        }

        let error_path = case_data_dir.join("error.txt");
        if error_path.exists() {
            if let Ok(error) = std::fs::read_to_string(&error_path) {
                hints.error_output = Some(error);
            }
        }

        let diff_path = case_data_dir.join("patch.diff");
        if diff_path.exists() {
            if let Ok(diff) = std::fs::read_to_string(&diff_path) {
                hints.patch_diff = Some(diff);
            }
        }
    }

    hints
}

/// Sanitize a CyberGym case ID for use as a filesystem path component.
/// Replaces colons with underscores (colons are invalid on Windows/macOS).
fn sanitize_case_id(case_id: &str) -> String {
    case_id.replace(':', "_")
}

/// Map a CyberGym task ID to its archive path within the dataset.
///
/// Task IDs are formatted as `arvo:NNN` or `oss-fuzz:NNN`.
/// Archives live at `data/{source}/{id}/repo-vul.tar.gz` (positive)
/// or `data/{source}/{id}/repo-fix.tar.gz` (negative/post-patch).
fn archive_path_for_case(dataset_dir: &Path, case_id: &str, is_negative: bool) -> PathBuf {
    let archive_name = if is_negative {
        "repo-fix.tar.gz"
    } else {
        "repo-vul.tar.gz"
    };

    // Strip "-fix" suffix from negative case IDs to get the base task ID.
    // e.g. "arvo:1065-fix" → "arvo:1065"
    let base_id = case_id.strip_suffix("-fix").unwrap_or(case_id);

    // Parse "arvo:NNN" or "oss-fuzz:NNN" format
    if let Some((source, id)) = base_id.split_once(':') {
        dataset_dir
            .join("data")
            .join(source)
            .join(id)
            .join(archive_name)
    } else {
        dataset_dir.join("data").join(base_id).join(archive_name)
    }
}

/// Collect source files with a cap to avoid walking massive repo trees.
fn collect_source_files_limited(dir: &Path, limit: usize) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_source_files_recursive_limited(dir, &mut files, 0, limit);
    files.sort();
    files
}

fn collect_source_files_recursive_limited(
    dir: &Path,
    files: &mut Vec<PathBuf>,
    depth: u32,
    limit: usize,
) {
    if depth > 3 || files.len() >= limit {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if files.len() >= limit {
            return;
        }
        let path = entry.path();
        if path.is_symlink() {
            continue;
        }
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(
                name,
                ".git" | "build" | "test" | "tests" | "doc" | "docs" | "third_party" | "vendor"
            ) {
                continue;
            }
            collect_source_files_recursive_limited(&path, files, depth + 1, limit);
        } else if is_c_source(&path) {
            files.push(path);
        }
    }
}

/// Extract affected file paths from patch.diff and resolve them in the case directory.
fn patch_affected_files(case_dir: &Path, data_dir: &Path, case_id: &str) -> Option<Vec<PathBuf>> {
    let base_id = case_id.strip_suffix("-fix").unwrap_or(case_id);
    let (source, id) = base_id.split_once(':')?;
    let patch_path = data_dir
        .join("dataset")
        .join("data")
        .join(source)
        .join(id)
        .join("patch.diff");

    let patch_content = std::fs::read_to_string(&patch_path).ok()?;

    let mut affected = Vec::new();
    for line in patch_content.lines() {
        // Parse "diff --git a/path/to/file.c b/path/to/file.c" or
        // "--- a/path/to/file.c"
        let rel_path = if line.starts_with("diff --git a/") {
            line.strip_prefix("diff --git a/")
                .and_then(|s| s.split_once(" b/"))
                .map(|(a, _)| a)
        } else if line.starts_with("--- a/") {
            line.strip_prefix("--- a/")
        } else {
            None
        };

        if let Some(rel) = rel_path {
            if is_source_extension(rel) {
                // Look in the extracted case dir (under src-vul/ or directly)
                let candidates = [case_dir.join("src-vul").join(rel), case_dir.join(rel)];
                for candidate in &candidates {
                    if candidate.exists() {
                        affected.push(candidate.clone());
                        break;
                    }
                }
            }
        }
    }

    affected.dedup();
    if affected.is_empty() {
        None
    } else {
        Some(affected)
    }
}

/// Returns true if a file is a header that contains only preprocessor directives
/// and no executable code (functions, assignments, expressions).
fn is_header_only(path: &Path) -> bool {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if ext != "h" && ext != "hpp" {
        return false; // Only filter .h/.hpp files
    }
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return false, // Can't read — don't filter
    };
    // A header has executable code if any non-preprocessor, non-comment,
    // non-blank line exists that looks like a statement or declaration.
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with("//")
            || trimmed.starts_with('*')
            || trimmed.starts_with("/*")
            || trimmed == "*/"
        {
            continue;
        }
        // Any other non-empty line suggests actual code
        return false;
    }
    true
}

fn is_source_extension(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.ends_with(".c")
        || lower.ends_with(".cc")
        || lower.ends_with(".cpp")
        || lower.ends_with(".cxx")
        || lower.ends_with(".h")
        || lower.ends_with(".hpp")
}

fn is_c_source(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("c" | "h" | "cc" | "cpp" | "cxx" | "hpp")
    )
}

/// Extract a .tar.gz archive into a destination directory.
fn extract_tar_gz(archive: &Path, dest: &Path) -> anyhow::Result<()> {
    use flate2::read::GzDecoder;
    use tar::Archive;

    let file = std::fs::File::open(archive)?;
    let gz = GzDecoder::new(file);
    let mut archive = Archive::new(gz);
    archive.unpack(dest)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_name() {
        let adapter = CyberGymAdapter::new(PathBuf::from("/nonexistent"));
        assert_eq!(adapter.name(), "cybergym");
    }

    #[test]
    fn test_archive_path_arvo() {
        let dataset = PathBuf::from("/data/cybergym/dataset");
        let path = archive_path_for_case(&dataset, "arvo:1065", false);
        assert_eq!(
            path,
            PathBuf::from("/data/cybergym/dataset/data/arvo/1065/repo-vul.tar.gz")
        );
    }

    #[test]
    fn test_archive_path_ossfuzz() {
        let dataset = PathBuf::from("/data/cybergym/dataset");
        let path = archive_path_for_case(&dataset, "oss-fuzz:42535201", false);
        assert_eq!(
            path,
            PathBuf::from("/data/cybergym/dataset/data/oss-fuzz/42535201/repo-vul.tar.gz")
        );
    }

    #[test]
    fn test_archive_path_negative_case() {
        let dataset = PathBuf::from("/data/cybergym/dataset");
        let path = archive_path_for_case(&dataset, "arvo:1065", true);
        assert_eq!(
            path,
            PathBuf::from("/data/cybergym/dataset/data/arvo/1065/repo-fix.tar.gz")
        );
    }

    #[test]
    fn test_archive_path_negative_case_with_fix_suffix() {
        let dataset = PathBuf::from("/data/cybergym/dataset");
        // Negative case IDs have "-fix" suffix that must be stripped
        let path = archive_path_for_case(&dataset, "arvo:1065-fix", true);
        assert_eq!(
            path,
            PathBuf::from("/data/cybergym/dataset/data/arvo/1065/repo-fix.tar.gz")
        );
    }

    #[test]
    fn test_is_c_source() {
        assert!(is_c_source(Path::new("foo.c")));
        assert!(is_c_source(Path::new("bar.cpp")));
        assert!(is_c_source(Path::new("baz.h")));
        assert!(is_c_source(Path::new("qux.cc")));
        assert!(!is_c_source(Path::new("readme.md")));
        assert!(!is_c_source(Path::new("Makefile")));
        assert!(!is_c_source(Path::new("data.json")));
    }

    #[test]
    fn test_collect_source_files_empty_dir() {
        let dir = std::env::temp_dir().join("cybergym_test_empty");
        let _ = std::fs::create_dir_all(&dir);
        let files = collect_source_files_limited(&dir, 50);
        assert!(files.is_empty());
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_sanitize_case_id() {
        assert_eq!(sanitize_case_id("arvo:1065"), "arvo_1065");
        assert_eq!(sanitize_case_id("oss-fuzz:42535201"), "oss-fuzz_42535201");
        assert_eq!(sanitize_case_id("arvo:1065-fix"), "arvo_1065-fix");
        assert_eq!(sanitize_case_id("simple_id"), "simple_id");
    }
}
