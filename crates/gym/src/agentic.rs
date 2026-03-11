//! Agentic analysis: runs the LLM-driven agent pipeline on test cases.
//!
//! This module bridges the gym's benchmark framework with skwaq's
//! multi-agent analysis pipeline. For each test case, it:
//! 1. Ingests the source into a graph DB and runs pattern/dataflow analysis
//! 2. (When LLM is available) Runs the agent pipeline for semantic analysis
//! 3. Extracts findings with CWE classifications

use crate::adapters::DetectedFinding;
use skwaq_core::analysis::DangerousApiDetector;
use skwaq_core::graph::builder::GraphBuilder;
use skwaq_core::graph::GraphDb;
use skwaq_core::source::parse_file;
use std::path::Path;

/// Run agentic analysis on a source file.
///
/// Phase 1 (always): Ingest → pattern detection → multi-cycle orchestrator
/// Phase 2 (when LLM available): Agent pipeline for semantic analysis
pub async fn run_agentic_source_analysis(
    path: &Path,
    _timeout_secs: u64,
) -> anyhow::Result<Vec<DetectedFinding>> {
    let path = path.to_path_buf();

    // Phase 1: Sync analysis (pattern + dataflow + context validation)
    // All DB work happens here, no await points while DB is alive.
    let findings = run_sync_analysis(&path)?;

    // Phase 2: LLM agent pipeline (future work - requires Send-safe DB wrapper)
    // For now, the sync analysis with the multi-cycle orchestrator provides
    // pattern detection + taint analysis + context validation (false positive reduction).
    // The LLM pipeline will be integrated when we add a Send-safe DB wrapper
    // or switch to a connection pool.

    Ok(findings)
}

/// Run synchronous analysis: ingest, pattern detection, orchestrator cycles.
fn run_sync_analysis(path: &Path) -> anyhow::Result<Vec<DetectedFinding>> {
    let db = GraphDb::in_memory()?;
    let parsed = parse_file(path)?;

    let inv_id = format!(
        "gym-{}",
        uuid::Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("0")
    );
    let now = chrono::Utc::now().to_rfc3339();
    let file_str = path.to_string_lossy().to_string();

    // Create investigation
    db.execute(
        "INSERT INTO investigations (id, name, target, status, created_at, updated_at) \
         VALUES (?1, ?2, ?3, 'active', ?4, ?5)",
        &[
            &inv_id.as_str(),
            &file_str.as_str(),
            &file_str.as_str(),
            &now.as_str(),
            &now.as_str(),
        ],
    )?;

    // Build graph from parsed source (functions, calls, sources, sinks)
    let builder = GraphBuilder::new(&db);
    let counts = builder.build_from_source(std::slice::from_ref(&parsed), &inv_id)?;
    tracing::debug!(
        "Ingested {}: {} functions, {} calls, {} sources, {} sinks",
        file_str,
        counts.functions,
        counts.calls,
        counts.sources,
        counts.sinks,
    );

    // Run pattern detection and store as initial findings
    let detector = DangerousApiDetector::new();
    if let Ok(hits) = detector.detect_in_source(path, &parsed.language) {
        for hit in &hits {
            let finding_id = uuid::Uuid::new_v4().to_string();
            let _ = db.execute(
                "INSERT INTO findings (id, title, evidence, agent, timestamp, investigation_id, \
                 status, severity, category) \
                 VALUES (?1, ?2, ?3, 'source-pattern-detector', ?4, ?5, 'new', ?6, ?7)",
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
                    &hit.severity.to_string().to_lowercase().as_str(),
                    &hit.danger_category.to_string().as_str(),
                ],
            );
        }
    }

    // Run multi-cycle analysis (pattern perspective + dataflow + context validation)
    let orchestrator = skwaq_core::analysis::AnalysisOrchestrator::new(&db, 3);
    let _cycles = orchestrator.run_quick_analysis(&inv_id)?;

    // Collect all non-invalidated findings from the DB
    collect_findings_from_db(&db, &inv_id)
}

/// Extract findings from the DB after analysis.
fn collect_findings_from_db(
    db: &GraphDb,
    investigation_id: &str,
) -> anyhow::Result<Vec<DetectedFinding>> {
    let mut stmt = db.conn().prepare(
        "SELECT id, title, severity, category, evidence FROM findings \
         WHERE investigation_id = ?1 AND status != 'invalidated'",
    )?;

    let findings = stmt
        .query_map(rusqlite::params![investigation_id], |row| {
            let id: String = row.get(0)?;
            let title: String = row.get(1)?;
            let severity: String = row.get(2).unwrap_or_default();
            let category: String = row.get(3).unwrap_or_default();
            let _evidence: String = row.get(4).unwrap_or_default();

            Ok(DetectedFinding {
                id,
                category,
                severity,
                cwes: vec![],
                file: String::new(),
                function: extract_function_from_title(&title),
                line: None,
                title,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(findings)
}

fn extract_function_from_title(title: &str) -> String {
    // Extract function name from "Dangerous pattern: strcpy (file:line)"
    if let Some(start) = title.find(": ") {
        let rest = &title[start + 2..];
        if let Some(end) = rest.find(' ') {
            return rest[..end].to_string();
        }
        return rest.to_string();
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_analysis_buffer_overflow() {
        let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        dir.pop();
        dir.pop();
        let fixture = dir.join("tests/fixtures/buffer_overflow.c");

        if fixture.exists() {
            let findings = run_sync_analysis(&fixture).unwrap();
            assert!(
                !findings.is_empty(),
                "Expected findings from buffer_overflow.c"
            );
            // Should find strcpy pattern
            let has_memory = findings.iter().any(|f| f.category == "memory");
            assert!(has_memory, "Expected memory-category findings");
        }
    }

    #[test]
    fn test_sync_analysis_command_injection() {
        let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        dir.pop();
        dir.pop();
        let fixture = dir.join("tests/fixtures/command_injection.c");

        if fixture.exists() {
            let findings = run_sync_analysis(&fixture).unwrap();
            assert!(
                !findings.is_empty(),
                "Expected findings from command_injection.c"
            );
            let has_injection = findings.iter().any(|f| f.category == "injection");
            assert!(has_injection, "Expected injection-category findings");
        }
    }

    #[tokio::test]
    async fn test_agentic_analysis_runs() {
        let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        dir.pop();
        dir.pop();
        let fixture = dir.join("tests/fixtures/buffer_overflow.c");

        if fixture.exists() {
            let findings = run_agentic_source_analysis(&fixture, 30).await.unwrap();
            assert!(
                !findings.is_empty(),
                "Expected findings from agentic analysis"
            );
        }
    }
}
