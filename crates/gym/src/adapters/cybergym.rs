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
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const FALLBACK_SOURCE_SCAN_MAX_DEPTH: u32 = 5;
const CASE_READY_MARKER: &str = ".extracted";

/// Directory names that signal "we are already at the project root" — descending
/// into them would land inside the project's own source tree, not inside a
/// packaging wrapper.
const SOURCE_LAYOUT_DIRS: &[&str] = &[
    "src", "lib", "include", "source", "Sources", "core", "main", "libs", "includes",
];

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
            let case_dir = case_dir_for_id(&dest, &case.id);
            if case_is_ready(&case_dir) {
                continue;
            }
            if case_dir.exists() {
                tracing::warn!(
                    "CyberGym case {} has a stale partial extraction at {}; re-extracting",
                    case.id,
                    case_dir.display()
                );
                reset_case_dir(&case_dir)?;
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
                let _ = reset_case_dir(&case_dir);
                continue;
            }
            write_case_ready_marker(&case_dir)?;
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
        let case_dir = match ensure_case_extracted(data_dir, &case.id, case.is_negative) {
            Ok(case_dir) => case_dir,
            Err(err) => {
                tracing::warn!("CyberGym case {} unavailable: {}", case.id, err);
                return Ok(vec![]);
            }
        };

        // Use patch.diff to identify only the vulnerable files instead of
        // walking the entire repo tree (which can be 900MB+ for projects
        // like FFmpeg or Wireshark).
        let source_files = patch_affected_files(&case_dir, data_dir, &case.id)
            .or_else(|| paired_case_affected_files(case, data_dir, &case_dir))
            .unwrap_or_else(|| {
                tracing::warn!(
                    "CyberGym case {}: patch path resolution failed, \
                     falling back to shallow source scan (≤25 files from {})",
                    case.id,
                    case_dir.display()
                );
                collect_source_files_limited(&case_dir, 25)
            });

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
        hints.vuln_description = read_text_ignoring_lfs_pointer(&desc_path);

        let error_path = case_data_dir.join("error.txt");
        hints.error_output = read_text_ignoring_lfs_pointer(&error_path);

        let diff_path = case_data_dir.join("patch.diff");
        hints.patch_diff = read_text_ignoring_lfs_pointer(&diff_path);
    }

    hints
}

/// Sanitize a CyberGym case ID for use as a filesystem path component.
/// Replaces colons with underscores (colons are invalid on Windows/macOS).
fn sanitize_case_id(case_id: &str) -> String {
    case_id.replace(':', "_")
}

fn case_dir_for_id(data_dir: &Path, case_id: &str) -> PathBuf {
    data_dir.join("cases").join(sanitize_case_id(case_id))
}

fn case_ready_marker_path(case_dir: &Path) -> PathBuf {
    case_dir.join(CASE_READY_MARKER)
}

fn case_is_ready(case_dir: &Path) -> bool {
    case_dir.is_dir() && case_ready_marker_path(case_dir).is_file()
}

fn write_case_ready_marker(case_dir: &Path) -> anyhow::Result<()> {
    std::fs::write(case_ready_marker_path(case_dir), "")?;
    Ok(())
}

fn reset_case_dir(case_dir: &Path) -> anyhow::Result<()> {
    if !case_dir.exists() {
        return Ok(());
    }

    let metadata = std::fs::symlink_metadata(case_dir)?;
    if metadata.is_dir() {
        std::fs::remove_dir_all(case_dir)?;
    } else {
        std::fs::remove_file(case_dir)?;
    }
    Ok(())
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

fn ensure_case_extracted(
    data_dir: &Path,
    case_id: &str,
    is_negative: bool,
) -> anyhow::Result<PathBuf> {
    let case_dir = case_dir_for_id(data_dir, case_id);
    if case_is_ready(&case_dir) {
        return Ok(case_dir);
    }
    if case_dir.exists() {
        tracing::warn!(
            "CyberGym case {} has a stale partial extraction at {}; re-extracting",
            case_id,
            case_dir.display()
        );
        reset_case_dir(&case_dir)?;
    }

    let archive = archive_path_for_case(&data_dir.join("dataset"), case_id, is_negative);
    if !archive.exists() {
        anyhow::bail!(
            "archive missing for case {} at {}",
            case_id,
            archive.display()
        );
    }

    std::fs::create_dir_all(&case_dir)?;
    if let Err(err) = extract_tar_gz(&archive, &case_dir) {
        let _ = reset_case_dir(&case_dir);
        return Err(err);
    }
    write_case_ready_marker(&case_dir)?;

    tracing::info!("CyberGym extracted case {} on demand", case_id);
    Ok(case_dir)
}

/// Collect source files with a cap to avoid walking massive repo trees.
fn collect_source_files_limited(dir: &Path, limit: usize) -> Vec<PathBuf> {
    let root = source_tree_root(dir);
    let mut files = Vec::new();
    collect_source_files_recursive_limited(&root, &mut files, 0, limit);
    files.sort();
    files
}

fn collect_source_files_recursive_limited(
    dir: &Path,
    files: &mut Vec<PathBuf>,
    depth: u32,
    limit: usize,
) {
    if depth > FALLBACK_SOURCE_SCAN_MAX_DEPTH || files.len() >= limit {
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

    let patch_content = read_text_ignoring_lfs_pointer(&patch_path)?;

    let mut affected = Vec::new();
    let source_root = source_tree_root(case_dir);
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
                let candidates = [
                    source_root.join(rel),
                    case_dir.join("src-vul").join(rel),
                    case_dir.join("src-fix").join(rel),
                    case_dir.join(rel),
                ];
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

fn paired_case_affected_files(
    case: &TestCase,
    data_dir: &Path,
    case_dir: &Path,
) -> Option<Vec<PathBuf>> {
    let counterpart_id = if case.is_negative {
        case.id.strip_suffix("-fix")?.to_string()
    } else {
        format!("{}-fix", case.id)
    };
    let counterpart_dir =
        ensure_case_extracted(data_dir, &counterpart_id, !case.is_negative).ok()?;
    let current_root = source_tree_root(case_dir);
    let counterpart_root = source_tree_root(&counterpart_dir);

    let mut affected = Vec::new();
    for rel_path in changed_source_rel_paths(&current_root, &counterpart_root) {
        let candidate = current_root.join(rel_path);
        if candidate.exists() {
            affected.push(candidate);
        }
    }

    if affected.is_empty() {
        None
    } else {
        Some(affected)
    }
}

fn changed_source_rel_paths(left_root: &Path, right_root: &Path) -> Vec<PathBuf> {
    let left = collect_source_map(left_root);
    let right = collect_source_map(right_root);
    let mut changed = Vec::new();

    for (rel_path, left_path) in &left {
        match right.get(rel_path) {
            Some(right_path) if files_equal(left_path, right_path) => {}
            _ => changed.push(rel_path.clone()),
        }
    }

    changed.sort();
    changed.dedup();
    changed
}

fn collect_source_map(root: &Path) -> BTreeMap<PathBuf, PathBuf> {
    let mut files = BTreeMap::new();
    collect_source_map_recursive(root, root, &mut files);
    files
}

fn collect_source_map_recursive(root: &Path, dir: &Path, files: &mut BTreeMap<PathBuf, PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
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
            collect_source_map_recursive(root, &path, files);
        } else if is_c_source(&path) {
            if let Ok(rel_path) = path.strip_prefix(root) {
                files.insert(rel_path.to_path_buf(), path);
            }
        }
    }
}

fn files_equal(left: &Path, right: &Path) -> bool {
    let Ok(left_meta) = std::fs::metadata(left) else {
        return false;
    };
    let Ok(right_meta) = std::fs::metadata(right) else {
        return false;
    };
    if left_meta.len() != right_meta.len() {
        return false;
    }
    std::fs::read(left).ok() == std::fs::read(right).ok()
}

fn source_tree_root(case_dir: &Path) -> PathBuf {
    let mut root = if case_dir.join("src-vul").is_dir() {
        case_dir.join("src-vul")
    } else if case_dir.join("src-fix").is_dir() {
        case_dir.join("src-fix")
    } else {
        case_dir.to_path_buf()
    };

    for _ in 0..2 {
        let Some(next_root) = single_child_dir_without_sources(&root) else {
            break;
        };
        root = next_root;
    }

    root
}

fn single_child_dir_without_sources(root: &Path) -> Option<PathBuf> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return None;
    };

    let mut dirs = Vec::new();
    let mut has_source_files = false;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_symlink() {
            continue;
        }
        if path.is_dir() {
            dirs.push(path);
        } else if is_c_source(&path) {
            has_source_files = true;
        }
    }

    if has_source_files || dirs.len() != 1 {
        None
    } else {
        let child = dirs.into_iter().next()?;
        let child_name = child.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // If the single child is a conventional source-layout directory, we are
        // already at the project root. Descending further would land inside the
        // project's own source tree, breaking patch-relative path resolution.
        if SOURCE_LAYOUT_DIRS.contains(&child_name) {
            return None;
        }
        Some(child)
    }
}

fn read_text_ignoring_lfs_pointer(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    if is_git_lfs_pointer(&text) {
        tracing::debug!("Ignoring Git LFS pointer sidecar at {}", path.display());
        None
    } else {
        Some(text)
    }
}

fn is_git_lfs_pointer(text: &str) -> bool {
    text.lines()
        .next()
        .is_some_and(|line| line.trim() == "version https://git-lfs.github.com/spec/v1")
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
    use crate::ground_truth::TestCase;
    use flate2::{write::GzEncoder, Compression};
    use tar::Builder;

    fn write_manifest(path: &Path) {
        std::fs::write(
            path,
            r#"suite = "cybergym"
version = "test"
download_url = ""
download_sha256 = ""

[[cases]]
id = "arvo:1065"
path = "cases/arvo:1065"
expected_cwes = [457]
is_negative = false
language = "cpp"
"#,
        )
        .unwrap();
    }

    fn test_config(cache_dir: PathBuf) -> BenchmarkConfig {
        BenchmarkConfig {
            cache_dir,
            cwe_filter: None,
            max_cases: None,
            quick_mode: true,
            llm_only: false,
            binary_mode: false,
            parallelism: 1,
            skip: 0,
            concurrency: 1,
            timeout_secs: 30,
            holdout_fraction: 0.0,
            max_improvements_per_cycle: 0,
        }
    }

    fn write_test_archive(archive: &Path, entries: &[(&str, &str)]) {
        let file = std::fs::File::create(archive).unwrap();
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = Builder::new(encoder);

        for (path, contents) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(contents.len() as u64);
            header.set_cksum();
            builder
                .append_data(&mut header, *path, contents.as_bytes())
                .unwrap();
        }

        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();
    }

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
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let files = collect_source_files_limited(dir, 50);
        assert!(files.is_empty());
    }

    #[test]
    fn test_sanitize_case_id() {
        assert_eq!(sanitize_case_id("arvo:1065"), "arvo_1065");
        assert_eq!(sanitize_case_id("oss-fuzz:42535201"), "oss-fuzz_42535201");
        assert_eq!(sanitize_case_id("arvo:1065-fix"), "arvo_1065-fix");
        assert_eq!(sanitize_case_id("simple_id"), "simple_id");
    }

    #[test]
    fn test_collect_source_files_limited_descends_into_src_tree() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp
            .path()
            .join("src-vul")
            .join("h2o")
            .join("lib")
            .join("http1")
            .join("parser.c");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "int parser(void) { return 0; }\n").unwrap();

        let files = collect_source_files_limited(temp.path(), 10);
        assert_eq!(files, vec![file]);
    }

    #[test]
    fn test_load_case_hints_ignores_git_lfs_pointer_sidecars() {
        let temp = tempfile::tempdir().unwrap();
        let case_data_dir = temp
            .path()
            .join("dataset")
            .join("data")
            .join("arvo")
            .join("1065");
        std::fs::create_dir_all(&case_data_dir).unwrap();
        let pointer = "version https://git-lfs.github.com/spec/v1\noid sha256:deadbeef\nsize 123\n";
        std::fs::write(case_data_dir.join("description.txt"), pointer).unwrap();
        std::fs::write(case_data_dir.join("error.txt"), pointer).unwrap();
        std::fs::write(case_data_dir.join("patch.diff"), pointer).unwrap();

        let hints = load_case_hints(temp.path(), "arvo:1065");
        assert!(hints.vuln_description.is_none());
        assert!(hints.error_output.is_none());
        assert!(hints.patch_diff.is_none());
    }

    #[test]
    fn test_paired_case_affected_files_uses_changed_sources() {
        let temp = tempfile::tempdir().unwrap();
        let vul_file = temp
            .path()
            .join("cases")
            .join("arvo_1065")
            .join("src-vul")
            .join("project")
            .join("src")
            .join("parser.c");
        let fix_file = temp
            .path()
            .join("cases")
            .join("arvo_1065-fix")
            .join("src-fix")
            .join("project")
            .join("src")
            .join("parser.c");
        let shared_vul = temp
            .path()
            .join("cases")
            .join("arvo_1065")
            .join("src-vul")
            .join("project")
            .join("src")
            .join("shared.c");
        let shared_fix = temp
            .path()
            .join("cases")
            .join("arvo_1065-fix")
            .join("src-fix")
            .join("project")
            .join("src")
            .join("shared.c");
        std::fs::create_dir_all(vul_file.parent().unwrap()).unwrap();
        std::fs::create_dir_all(fix_file.parent().unwrap()).unwrap();
        std::fs::write(&vul_file, "int parser(void) { return 1; }\n").unwrap();
        std::fs::write(&fix_file, "int parser(void) { return 0; }\n").unwrap();
        std::fs::write(&shared_vul, "int shared(void) { return 7; }\n").unwrap();
        std::fs::write(&shared_fix, "int shared(void) { return 7; }\n").unwrap();
        // Write the ready marker so ensure_case_extracted treats the fix dir as already extracted.
        let fix_case_dir = temp.path().join("cases").join("arvo_1065-fix");
        std::fs::write(fix_case_dir.join(CASE_READY_MARKER), "").unwrap();
        let vul_case_dir = temp.path().join("cases").join("arvo_1065");
        std::fs::write(vul_case_dir.join(CASE_READY_MARKER), "").unwrap();

        let case = TestCase {
            id: "arvo:1065".to_string(),
            path: String::new(),
            binary_path: None,
            expected_cwes: vec![121],
            is_negative: false,
            language: "c".to_string(),
        };
        let case_dir = temp.path().join("cases").join("arvo_1065");

        let affected = paired_case_affected_files(&case, temp.path(), &case_dir).unwrap();
        assert_eq!(affected, vec![vul_file]);
    }

    #[test]
    fn test_ensure_case_extracted_reextracts_partial_case_without_ready_marker() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path();
        let archive = data_dir
            .join("dataset")
            .join("data")
            .join("arvo")
            .join("1065")
            .join("repo-vul.tar.gz");
        std::fs::create_dir_all(archive.parent().unwrap()).unwrap();
        write_test_archive(
            &archive,
            &[(
                "src-vul/project/parser.c",
                "int parser(void) { return 0; }\n",
            )],
        );

        let case_dir = data_dir.join("cases").join("arvo_1065");
        std::fs::create_dir_all(&case_dir).unwrap();
        std::fs::write(case_dir.join("stale.txt"), "stale").unwrap();

        let extracted = ensure_case_extracted(data_dir, "arvo:1065", false).unwrap();
        assert_eq!(extracted, case_dir);
        assert!(extracted.join(CASE_READY_MARKER).is_file());
        assert!(extracted.join("src-vul/project/parser.c").is_file());
        assert!(!extracted.join("stale.txt").exists());
    }

    #[tokio::test]
    async fn test_setup_reextracts_partial_case_without_ready_marker() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = temp.path().join("cybergym.toml");
        write_manifest(&manifest);

        let cache_dir = temp.path().join("cache");
        let archive = cache_dir
            .join("cybergym")
            .join("dataset")
            .join("data")
            .join("arvo")
            .join("1065")
            .join("repo-vul.tar.gz");
        std::fs::create_dir_all(archive.parent().unwrap()).unwrap();
        write_test_archive(
            &archive,
            &[(
                "src-vul/project/parser.c",
                "int parser(void) { return 0; }\n",
            )],
        );

        let case_dir = cache_dir.join("cybergym").join("cases").join("arvo_1065");
        std::fs::create_dir_all(&case_dir).unwrap();
        std::fs::write(case_dir.join("stale.txt"), "stale").unwrap();

        let adapter = CyberGymAdapter::new(manifest);
        let extracted_root = adapter
            .setup(&test_config(cache_dir.clone()))
            .await
            .unwrap();

        assert_eq!(extracted_root, cache_dir.join("cybergym"));
        assert!(cache_dir.join("cybergym").join(".ready").is_file());
        assert!(case_dir.join(CASE_READY_MARKER).is_file());
        assert!(case_dir.join("src-vul/project/parser.c").is_file());
        assert!(!case_dir.join("stale.txt").exists());
    }

    #[test]
    fn test_source_tree_root_stops_at_project_root_not_src() {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path();
        let vuln_file = case_dir.join("project-1.2.3").join("src").join("vuln.c");
        std::fs::create_dir_all(vuln_file.parent().unwrap()).unwrap();
        std::fs::write(&vuln_file, "void vuln(char *s) { strcpy(buf, s); }\n").unwrap();

        let root = source_tree_root(case_dir);
        assert_eq!(
            root,
            case_dir.join("project-1.2.3"),
            "source_tree_root must stop at the project root, not descend into src/"
        );
    }

    #[test]
    fn test_source_tree_root_stops_at_conventional_lib() {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path();
        let src_file = case_dir.join("myproject").join("lib").join("util.c");
        std::fs::create_dir_all(src_file.parent().unwrap()).unwrap();
        std::fs::write(&src_file, "int util(void) { return 0; }\n").unwrap();

        let root = source_tree_root(case_dir);
        assert_eq!(
            root,
            case_dir.join("myproject"),
            "source_tree_root must not descend into lib/"
        );
    }

    #[test]
    fn test_patch_affected_files_resolves_src_relative_paths() {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path().join("cases").join("arvo_2000");
        let data_dir = temp.path();

        let src_file = case_dir.join("project-2.0").join("src").join("parser.c");
        std::fs::create_dir_all(src_file.parent().unwrap()).unwrap();
        std::fs::write(&src_file, "int parser(void) { return 1; }\n").unwrap();

        let patch_dir = data_dir
            .join("dataset")
            .join("data")
            .join("arvo")
            .join("2000");
        std::fs::create_dir_all(&patch_dir).unwrap();
        std::fs::write(
            patch_dir.join("patch.diff"),
            "diff --git a/src/parser.c b/src/parser.c\n\
             --- a/src/parser.c\n\
             +++ b/src/parser.c\n\
             @@ -1 +1 @@\n\
             -int parser(void) { return 1; }\n\
             +int parser(void) { return 0; }\n",
        )
        .unwrap();

        let affected = patch_affected_files(&case_dir, data_dir, "arvo:2000")
            .expect("patch_affected_files must find parser.c");
        assert_eq!(
            affected,
            vec![src_file],
            "patch path src/parser.c must resolve to project-2.0/src/parser.c"
        );
    }
}
