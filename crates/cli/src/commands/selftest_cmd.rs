//! `skwaq self-test` - run skwaq's analysis on its own source code.
//!
//! Ingests the `crates/` directory, runs quick analysis, and reports
//! whether any confirmed critical/high findings exist. Returns exit
//! code 0 if clean, 1 if confirmed issues found.

use skwaq_core::analysis::{AnalysisOrchestrator, FindingStatus};
use skwaq_core::graph::GraphDb;
use skwaq_core::source::is_source_file;

/// Run the self-test: ingest our own crates/, run quick analysis, report results.
pub fn run() -> anyhow::Result<()> {
    println!("=== Skwaq Self-Test ===\n");

    // Find the crates/ directory relative to the current directory or executable.
    let crates_dir = find_crates_dir()?;
    println!("[self-test] Source directory: {}", crates_dir.display());

    // Use a temporary database so we don't pollute the user's real DB.
    let temp_dir = tempfile::tempdir()?;
    let db_path = temp_dir.path().join("selftest.db");
    let db = GraphDb::open(&db_path)?;

    // 1. Ingest source files.
    let source_files = collect_source_files(&crates_dir)?;
    println!("[self-test] Found {} source file(s)", source_files.len());

    if source_files.is_empty() {
        anyhow::bail!(
            "No source files found in {}. Run from the skwaq project root.",
            crates_dir.display()
        );
    }

    let inv_id = format!("selftest-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let now = chrono::Utc::now().to_rfc3339();

    db.execute(
        "INSERT INTO investigations (id, name, target, status, created_at, updated_at) \
         VALUES (?1, ?2, ?3, 'active', ?4, ?5)",
        &[
            &inv_id.as_str(),
            &"self-test",
            &crates_dir.display().to_string().as_str(),
            &now.as_str(),
            &now.as_str(),
        ],
    )?;

    // Parse and ingest source files.
    let mut parsed_files = Vec::new();
    let mut parse_errors = 0;
    for file_path in &source_files {
        match skwaq_core::source::parse_file(file_path) {
            Ok(parsed) => parsed_files.push(parsed),
            Err(_) => parse_errors += 1,
        }
    }
    println!(
        "[self-test] Parsed {} file(s) ({} errors)",
        parsed_files.len(),
        parse_errors
    );

    let builder = skwaq_core::graph::builder::GraphBuilder::new(&db);
    let counts = builder.build_from_source(&parsed_files, &inv_id)?;
    println!(
        "[self-test] Graph: {} files, {} functions, {} calls",
        counts.files, counts.functions, counts.calls,
    );

    // Run dangerous pattern detection.
    let detector = skwaq_core::analysis::DangerousApiDetector::new();
    let mut total_hits = 0;
    for parsed in &parsed_files {
        if let Ok(hits) =
            detector.detect_in_source(std::path::Path::new(&parsed.path), &parsed.language)
        {
            for hit in &hits {
                let finding_id = uuid::Uuid::new_v4().to_string();
                let _ = db.execute(
                    "INSERT INTO findings (id, title, evidence, agent, timestamp, investigation_id) \
                     VALUES (?1, ?2, ?3, 'source-pattern-detector', ?4, ?5)",
                    &[
                        &finding_id.as_str(),
                        &format!(
                            "Dangerous pattern: {} ({}:{})",
                            hit.function_name, hit.file, hit.line
                        )
                        .as_str(),
                        &format!(
                            "category={}, severity={}, reason={}",
                            hit.danger_category, hit.severity, hit.reason
                        )
                        .as_str(),
                        &now.as_str(),
                        &inv_id.as_str(),
                    ],
                );
                total_hits += 1;
            }
        }
    }

    if total_hits > 0 {
        println!("[self-test] Detected {} dangerous pattern(s)", total_hits);
    }

    // 2. Run quick multi-cycle analysis.
    let max_cycles = 5;
    let orchestrator = AnalysisOrchestrator::new(&db, max_cycles);
    let cycles = orchestrator.run_quick_analysis(&inv_id)?;

    let total_cycles = cycles.len();
    println!(
        "[self-test] Analysis converged after {} cycle(s)",
        total_cycles
    );

    // 3. Count confirmed critical/high findings.
    let mut confirmed_critical = 0;
    let mut total_findings = 0;
    if let Some(last) = cycles.last() {
        total_findings = last.findings.len();
        for finding in &last.findings {
            let is_critical = finding.severity == "critical" || finding.severity == "high";
            let is_confirmed =
                finding.status == FindingStatus::Confirmed || finding.status == FindingStatus::New;
            if is_critical && is_confirmed {
                confirmed_critical += 1;
            }
        }

        // Display summary.
        let confirmed = last
            .findings
            .iter()
            .filter(|f| f.status == FindingStatus::Confirmed)
            .count();
        let invalidated = last
            .findings
            .iter()
            .filter(|f| f.status == FindingStatus::Invalidated)
            .count();
        let challenged = last
            .findings
            .iter()
            .filter(|f| f.status == FindingStatus::Challenged)
            .count();

        println!(
            "[self-test] {} total findings: {} confirmed, {} challenged, {} invalidated",
            total_findings, confirmed, challenged, invalidated,
        );
    }

    println!();
    if confirmed_critical > 0 {
        println!(
            "FAIL: {} confirmed critical/high finding(s) in own code.",
            confirmed_critical
        );
        std::process::exit(1);
    } else {
        println!(
            "PASS: No confirmed critical/high findings. ({} total findings checked)",
            total_findings
        );
    }

    Ok(())
}

/// Find the crates/ directory, searching from cwd upward and next to the executable.
fn find_crates_dir() -> anyhow::Result<std::path::PathBuf> {
    // Check cwd first
    let cwd = std::env::current_dir()?;
    let candidate = cwd.join("crates");
    if candidate.is_dir() {
        return Ok(candidate);
    }

    // Check next to executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            // target/debug/skwaq -> project_root/crates
            for ancestor in parent.ancestors().take(5) {
                let candidate = ancestor.join("crates");
                if candidate.is_dir() {
                    return Ok(candidate);
                }
            }
        }
    }

    anyhow::bail!("Cannot find crates/ directory. Run `skwaq self-test` from the project root.")
}

/// Collect source files recursively, applying the same limits as ingest.
fn collect_source_files(path: &std::path::Path) -> anyhow::Result<Vec<std::path::PathBuf>> {
    let skip_dirs: std::collections::HashSet<&str> = [
        "target",
        "node_modules",
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "vendor",
        "dist",
        "build",
    ]
    .iter()
    .copied()
    .collect();

    let mut files = Vec::new();
    walk_dir(path, &skip_dirs, &mut files)?;

    // Enforce max file count limit (same as ingest).
    const MAX_SOURCE_FILES: usize = 10_000;
    if files.len() > MAX_SOURCE_FILES {
        anyhow::bail!(
            "Source tree contains {} files, exceeding the {} file limit. \
             Narrow the scope or increase the limit.",
            files.len(),
            MAX_SOURCE_FILES,
        );
    }

    Ok(files)
}

fn walk_dir(
    dir: &std::path::Path,
    skip_dirs: &std::collections::HashSet<&str>,
    files: &mut Vec<std::path::PathBuf>,
) -> anyhow::Result<()> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| anyhow::anyhow!("Cannot read directory {}: {}", dir.display(), e))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if skip_dirs.contains(name) || name.starts_with('.') {
                    continue;
                }
            }
            walk_dir(&path, skip_dirs, files)?;
        } else if is_source_file(&path) {
            files.push(path);
        }
    }

    Ok(())
}
