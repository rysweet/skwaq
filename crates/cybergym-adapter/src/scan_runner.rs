//! Orchestrates the analysis pipeline for scan operations.
//!
//! Runs skwaq's vulnerability detection against a validated target path,
//! with timeout enforcement and finding cap. Collects partial results
//! when individual analysis stages fail.

use crate::types::{AdapterError, Finding, ScanResult, ScanStatus};
use skwaq_gym::adapters;
use std::path::Path;

/// Maximum findings per scan (enforced centrally, not per-agent).
const MAX_FINDINGS: usize = 10_000;

/// Default timeout in seconds (30 minutes).
const DEFAULT_TIMEOUT_SECS: u64 = 1800;

/// Run a scan against the given target path.
///
/// The target must already be validated by `input_validator::validate_target`.
/// This function:
/// 1. Runs pattern detection (fast, no LLM)
/// 2. If not quick-only, runs agentic analysis (LLM-based)
/// 3. Merges findings, enforces the 10K cap
/// 4. Returns a `ScanResult` with appropriate status
pub async fn run_scan(
    target: &Path,
    timeout_secs: Option<u64>,
    quick_only: bool,
) -> Result<ScanResult, AdapterError> {
    let run_id = uuid::Uuid::new_v4().to_string();
    let started_at = chrono::Utc::now();
    let timeout = timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
    let target_str = target.to_string_lossy().to_string();

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(timeout),
        run_scan_inner(target, quick_only),
    )
    .await;

    let finished_at = chrono::Utc::now();

    match result {
        Ok(Ok((findings, partial))) => {
            let (capped_findings, truncated) = enforce_finding_cap(findings);
            let status = if partial || truncated > 0 {
                ScanStatus::Partial
            } else {
                ScanStatus::Complete
            };
            Ok(ScanResult {
                run_id,
                target: target_str,
                status,
                findings: capped_findings,
                started_at,
                finished_at,
                truncated_count: truncated,
            })
        }
        Ok(Err(e)) => {
            tracing::debug!("scan failed for {}: {}", target.display(), e);
            Err(AdapterError::ScanFailed {
                message: "scan analysis failed".to_string(),
            })
        }
        Err(_) => Err(AdapterError::Timeout { seconds: timeout }),
    }
}

/// Inner scan logic — runs pattern detection and optionally agentic analysis.
/// Returns (findings, was_partial).
async fn run_scan_inner(target: &Path, quick_only: bool) -> anyhow::Result<(Vec<Finding>, bool)> {
    let mut all_findings = Vec::new();
    let mut partial = false;

    // Layer 1: Pattern detection (always runs)
    match run_pattern_detection(target) {
        Ok(findings) => all_findings.extend(findings),
        Err(e) => {
            tracing::warn!("pattern detection failed: {}", e);
            partial = true;
        }
    }

    // Layer 2: Agentic analysis (LLM-based, unless quick_only)
    if !quick_only {
        match run_agentic_analysis(target).await {
            Ok(findings) => all_findings.extend(findings),
            Err(e) => {
                tracing::warn!("agentic analysis failed: {}", e);
                partial = true;
                // Partial results from pattern detection are still returned
            }
        }
    }

    Ok((all_findings, partial))
}

/// Run pattern-based detection on a target.
fn run_pattern_detection(target: &Path) -> anyhow::Result<Vec<Finding>> {
    let is_dir = target.is_dir();

    if is_dir {
        // Scan all supported source files in directory
        let mut findings = Vec::new();
        scan_directory(target, &mut findings)?;
        Ok(findings)
    } else {
        // Single file
        let raw = adapters::run_source_pattern_detection(target)?;
        Ok(convert_findings(&raw))
    }
}

/// Recursively scan a directory for source files.
fn scan_directory(dir: &Path, findings: &mut Vec<Finding>) -> anyhow::Result<()> {
    let entries = std::fs::read_dir(dir)?;
    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(e) => {
                tracing::debug!("skipping {}: {}", path.display(), e);
                continue;
            }
        };

        if file_type.is_symlink() {
            tracing::debug!("skipping symlink entry {}", path.display());
            continue;
        }

        if file_type.is_dir() {
            scan_directory(&path, findings)?;
        } else if file_type.is_file() && is_supported_source(&path) {
            match adapters::run_source_pattern_detection(&path) {
                Ok(raw) => findings.extend(convert_findings(&raw)),
                Err(e) => {
                    tracing::debug!("skipping {}: {}", path.display(), e);
                }
            }
        }
    }
    Ok(())
}

/// Check if a file has a supported source extension.
fn is_supported_source(path: &Path) -> bool {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    matches!(
        ext,
        "c" | "h" | "cpp" | "cxx" | "cc" | "hpp" | "py" | "js" | "ts" | "java"
    )
}

/// Run agentic (LLM-based) analysis on a target.
async fn run_agentic_analysis(target: &Path) -> anyhow::Result<Vec<Finding>> {
    let raw = if target.is_dir() {
        // For directories, find the first source file and analyze it
        // Full directory analysis would require investigation pipeline
        let mut source_file = None;
        if let Ok(entries) = std::fs::read_dir(target) {
            for entry in entries.flatten() {
                let path = entry.path();
                let file_type = match entry.file_type() {
                    Ok(file_type) => file_type,
                    Err(e) => {
                        tracing::debug!("skipping {}: {}", path.display(), e);
                        continue;
                    }
                };
                if file_type.is_symlink() {
                    tracing::debug!("skipping symlink entry {}", path.display());
                    continue;
                }
                if file_type.is_file() && is_supported_source(&path) {
                    source_file = Some(path);
                    break;
                }
            }
        }
        match source_file {
            Some(file) => skwaq_gym::agentic::run_agentic_source_analysis(&file, 1800).await?,
            None => return Ok(vec![]),
        }
    } else {
        skwaq_gym::agentic::run_agentic_source_analysis(target, 1800).await?
    };

    Ok(convert_findings(&raw))
}

/// Convert gym DetectedFindings to adapter Findings with source tagging.
fn convert_findings(raw: &[adapters::DetectedFinding]) -> Vec<Finding> {
    raw.iter()
        .map(|f| {
            Finding::new(
                f.id.clone(),
                f.cwes.clone(),
                f.severity.clone(),
                f.title.clone(),
                f.file.clone(),
                f.function.clone(),
                f.line,
                f.category.clone(),
            )
        })
        .collect()
}

/// Enforce the 10K finding cap. Returns (capped_findings, truncated_count).
fn enforce_finding_cap(mut findings: Vec<Finding>) -> (Vec<Finding>, usize) {
    if findings.len() <= MAX_FINDINGS {
        (findings, 0)
    } else {
        let truncated = findings.len() - MAX_FINDINGS;
        findings.truncate(MAX_FINDINGS);
        (findings, truncated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforce_cap_no_truncation() {
        let findings: Vec<Finding> = (0..100)
            .map(|i| {
                Finding::new(
                    format!("f{}", i),
                    vec![],
                    "low".into(),
                    "test".into(),
                    "f.c".into(),
                    "fn".into(),
                    None,
                    "test".into(),
                )
            })
            .collect();
        let (result, truncated) = enforce_finding_cap(findings);
        assert_eq!(result.len(), 100);
        assert_eq!(truncated, 0);
    }

    #[test]
    fn enforce_cap_truncates_excess() {
        let findings: Vec<Finding> = (0..10_005)
            .map(|i| {
                Finding::new(
                    format!("f{}", i),
                    vec![],
                    "low".into(),
                    "test".into(),
                    "f.c".into(),
                    "fn".into(),
                    None,
                    "test".into(),
                )
            })
            .collect();
        let (result, truncated) = enforce_finding_cap(findings);
        assert_eq!(result.len(), MAX_FINDINGS);
        assert_eq!(truncated, 5);
    }

    #[test]
    fn is_supported_source_checks_extensions() {
        assert!(is_supported_source(Path::new("main.c")));
        assert!(is_supported_source(Path::new("lib.py")));
        assert!(is_supported_source(Path::new("App.java")));
        assert!(!is_supported_source(Path::new("Cargo.toml")));
        assert!(!is_supported_source(Path::new("readme.md")));
    }

    #[test]
    fn convert_findings_preserves_source_tag() {
        let raw = vec![adapters::DetectedFinding {
            id: "d1".to_string(),
            category: "memory".to_string(),
            severity: "high".to_string(),
            cwes: vec![119],
            file: "test.c".to_string(),
            function: "gets".to_string(),
            line: Some(10),
            title: "Dangerous API: gets".to_string(),
        }];
        let converted = convert_findings(&raw);
        assert_eq!(converted.len(), 1);
        assert_eq!(converted[0].source(), "cybergym-adapter");
        assert_eq!(converted[0].cwes, vec![119]);
    }

    #[cfg(unix)]
    #[test]
    fn scan_directory_skips_symlinked_subdirectories() {
        let temp = tempfile::tempdir().unwrap();
        let real_dir = temp.path().join("real");
        let nested_dir = real_dir.join("nested");
        std::fs::create_dir_all(&nested_dir).unwrap();
        std::fs::write(
            nested_dir.join("danger.c"),
            "void vulnerable(char *x) { char buf[8]; gets(buf); }",
        )
        .unwrap();

        let scan_root = temp.path().join("scan-root");
        std::fs::create_dir_all(&scan_root).unwrap();
        std::os::unix::fs::symlink(&real_dir, scan_root.join("linked-dir")).unwrap();

        let mut findings = Vec::new();
        scan_directory(&scan_root, &mut findings).unwrap();
        assert!(findings.is_empty(), "symlinked directories must be skipped");
    }
}
