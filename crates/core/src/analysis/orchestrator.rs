//! Multi-cycle analysis orchestrator.
//!
//! Runs analysis in recursive cycles where each cycle builds on the
//! previous one. Findings are confirmed, challenged, or invalidated
//! across cycles, and analysis stops when convergence is reached
//! (no new findings and no invalidations in the latest cycle).

use crate::analysis::findings::{Finding, FindingStatus, FindingUpdate};
use crate::analysis::perspectives;
use crate::graph::GraphDb;

/// Result of a single analysis cycle.
#[derive(Debug)]
pub struct AnalysisCycle {
    /// Which cycle this is (1-indexed).
    pub cycle_number: u32,
    /// All findings known at the end of this cycle.
    pub findings: Vec<Finding>,
    /// Number of findings discovered for the first time in this cycle.
    pub new_findings: usize,
    /// Number of findings from previous cycles that were invalidated.
    pub challenged: usize,
}

/// Orchestrator that runs multi-cycle analysis on an investigation.
pub struct AnalysisOrchestrator<'a> {
    db: &'a GraphDb,
    max_cycles: u32,
}

impl<'a> AnalysisOrchestrator<'a> {
    /// Create a new orchestrator.
    ///
    /// `max_cycles` caps the number of analysis passes to prevent
    /// runaway iteration. In practice, convergence happens in 2-4 cycles.
    pub fn new(db: &'a GraphDb, max_cycles: u32) -> Self {
        Self { db, max_cycles }
    }

    /// Run a quick multi-cycle analysis on the given investigation.
    ///
    /// Returns the history of all cycles run. The final cycle's findings
    /// list contains the definitive results with statuses reflecting
    /// the full analysis.
    pub fn run_quick_analysis(
        &self,
        investigation_id: &str,
    ) -> anyhow::Result<Vec<AnalysisCycle>> {
        let mut cycles = Vec::new();
        let mut all_findings: Vec<Finding> = Vec::new();

        for cycle_num in 1..=self.max_cycles {
            let (new_count, challenged_count) =
                self.run_cycle(cycle_num, investigation_id, &mut all_findings);

            cycles.push(AnalysisCycle {
                cycle_number: cycle_num,
                findings: all_findings.clone(),
                new_findings: new_count,
                challenged: challenged_count,
            });

            // Convergence: no new findings and no status changes
            if new_count == 0 && challenged_count == 0 && cycle_num > 1 {
                break;
            }
        }

        // Store final findings in the database
        self.store_findings(investigation_id, &all_findings)?;

        Ok(cycles)
    }

    /// Run a single analysis cycle, mutating the findings list in place.
    /// Returns (new_findings_count, invalidated_count).
    fn run_cycle(
        &self,
        cycle_num: u32,
        investigation_id: &str,
        all_findings: &mut Vec<Finding>,
    ) -> (usize, usize) {
        match cycle_num {
            1 => {
                // Cycle 1: Pattern detection + taint analysis + source/sink ID
                let pattern_findings =
                    perspectives::pattern_perspective(self.db, investigation_id, cycle_num);
                let dataflow_findings =
                    perspectives::dataflow_perspective(self.db, investigation_id, cycle_num);

                let new_count = pattern_findings.len() + dataflow_findings.len();
                all_findings.extend(pattern_findings);
                all_findings.extend(dataflow_findings);

                (new_count, 0)
            }
            2 => {
                // Cycle 2: Context validation - check for false positives
                let (updates, new_findings) = perspectives::context_perspective(
                    self.db,
                    investigation_id,
                    all_findings,
                    cycle_num,
                );

                let challenged_count = apply_updates(all_findings, &updates, cycle_num);
                let new_count = new_findings.len();
                all_findings.extend(new_findings);

                (new_count, challenged_count)
            }
            _ => {
                // Cycle 3+: Deeper analysis - look for patterns missed earlier
                // Re-run context perspective on any remaining New or Challenged findings
                let active_findings: Vec<Finding> = all_findings
                    .iter()
                    .filter(|f| {
                        f.status == FindingStatus::New || f.status == FindingStatus::Challenged
                    })
                    .cloned()
                    .collect();

                if active_findings.is_empty() {
                    return (0, 0);
                }

                let (updates, new_findings) = perspectives::context_perspective(
                    self.db,
                    investigation_id,
                    &active_findings,
                    cycle_num,
                );

                let challenged_count = apply_updates(all_findings, &updates, cycle_num);

                // Deduplicate new findings against existing
                let existing_titles: std::collections::HashSet<String> =
                    all_findings.iter().map(|f| f.title.clone()).collect();
                let truly_new: Vec<Finding> = new_findings
                    .into_iter()
                    .filter(|f| !existing_titles.contains(&f.title))
                    .collect();
                let new_count = truly_new.len();
                all_findings.extend(truly_new);

                (new_count, challenged_count)
            }
        }
    }

    /// Persist final findings to the database.
    fn store_findings(
        &self,
        investigation_id: &str,
        findings: &[Finding],
    ) -> anyhow::Result<()> {
        let now = chrono::Utc::now().to_rfc3339();

        for finding in findings {
            // Skip invalidated findings from storage
            if finding.status == FindingStatus::Invalidated {
                continue;
            }

            let agent = match finding.category.as_str() {
                "taint" => "taint-analyzer",
                "indirect" => "context-validator",
                _ => "pattern-detector",
            };

            self.db.execute(
                "INSERT OR REPLACE INTO findings (id, title, evidence, agent, timestamp, investigation_id, \
                 status, cycle_discovered, cycle_last_updated, severity, category) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                &[
                    &finding.id.as_str(),
                    &finding.title.as_str(),
                    &finding.evidence.join("; ").as_str(),
                    &agent,
                    &now.as_str(),
                    &investigation_id,
                    &finding.status.to_string().as_str(),
                    &finding.cycle_discovered.to_string().as_str(),
                    &finding.cycle_last_updated.to_string().as_str(),
                    &finding.severity.as_str(),
                    &finding.category.as_str(),
                ],
            )?;
        }

        Ok(())
    }
}

/// Apply a set of finding updates, returning the count of findings that changed status.
fn apply_updates(findings: &mut [Finding], updates: &[FindingUpdate], cycle: u32) -> usize {
    let mut changed = 0;
    for update in updates {
        if let Some(finding) = findings.iter_mut().find(|f| f.id == update.finding_id) {
            if finding.status != update.new_status {
                finding.status = update.new_status.clone();
                finding.cycle_last_updated = cycle;
                // Append the reason to evidence
                finding.evidence.push(format!(
                    "Cycle {}: {} — {}",
                    cycle, update.new_status, update.reason
                ));
                changed += 1;
            }
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_db_produces_no_findings() {
        let db = GraphDb::in_memory().unwrap();
        db.execute(
            "INSERT INTO investigations (id, name, target, status, created_at) \
             VALUES ('inv1', 'Test', '/test', 'active', '2026-03-10')",
            &[],
        )
        .unwrap();

        let orch = AnalysisOrchestrator::new(&db, 5);
        let cycles = orch.run_quick_analysis("inv1").unwrap();
        // Should run 2 cycles (cycle 1 finds nothing, cycle 2 finds nothing => convergence)
        assert!(cycles.len() >= 1);
        assert_eq!(cycles[0].new_findings, 0);
    }

    #[test]
    fn test_finds_dangerous_apis() {
        let db = GraphDb::in_memory().unwrap();
        db.execute(
            "INSERT INTO investigations (id, name) VALUES ('inv1', 'Test')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO functions (id, name) VALUES ('f1', 'strcpy')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO functions (id, name) VALUES ('f2', 'system')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO functions (id, name) VALUES ('f3', 'main')",
            &[],
        )
        .unwrap();

        let orch = AnalysisOrchestrator::new(&db, 5);
        let cycles = orch.run_quick_analysis("inv1").unwrap();

        assert!(!cycles.is_empty());
        let first = &cycles[0];
        assert!(first.new_findings >= 2); // strcpy and system
    }

    #[test]
    fn test_multi_cycle_convergence() {
        let db = GraphDb::in_memory().unwrap();
        db.execute(
            "INSERT INTO investigations (id, name) VALUES ('inv1', 'Test')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO functions (id, name) VALUES ('f1', 'recv')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO functions (id, name) VALUES ('f2', 'process')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO functions (id, name) VALUES ('f3', 'strcpy')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO calls (caller_id, callee_id) VALUES ('f1', 'f2')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO calls (caller_id, callee_id) VALUES ('f2', 'f3')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO data_sources (id, name, source_type) VALUES ('src1', 'recv', 'network')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO data_sinks (id, name, sink_type, danger_level) VALUES ('sink1', 'strcpy', 'memory', 'critical')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO taint_flows (source_id, sink_id, path, sanitized) VALUES ('src1', 'sink1', 'recv -> process -> strcpy', 0)",
            &[],
        )
        .unwrap();

        let orch = AnalysisOrchestrator::new(&db, 5);
        let cycles = orch.run_quick_analysis("inv1").unwrap();

        // Should converge within max_cycles
        assert!(cycles.len() <= 5);
        assert!(cycles.len() >= 2);

        // Cycle 1 should find pattern + taint findings
        assert!(cycles[0].new_findings > 0);

        // Final cycle should show convergence (or near it)
        let last = cycles.last().unwrap();
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

        // At least some findings should be confirmed or invalidated
        assert!(
            confirmed > 0 || invalidated > 0 || last.findings.iter().any(|f| f.status == FindingStatus::Challenged),
            "Cycle 2+ should have processed findings"
        );
    }

    #[test]
    fn test_findings_stored_in_db() {
        let db = GraphDb::in_memory().unwrap();
        db.execute(
            "INSERT INTO investigations (id, name) VALUES ('inv1', 'Test')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO functions (id, name) VALUES ('f1', 'strcpy')",
            &[],
        )
        .unwrap();

        let orch = AnalysisOrchestrator::new(&db, 3);
        let _cycles = orch.run_quick_analysis("inv1").unwrap();

        // Check that findings were stored
        let count: i64 = db
            .conn()
            .query_row("SELECT count(*) FROM findings", [], |row| row.get(0))
            .unwrap();
        assert!(count > 0, "Findings should be stored in the database");
    }

    #[test]
    fn test_apply_updates() {
        use crate::analysis::findings::{FindingLocation, FindingStatus, FindingUpdate};

        let mut findings = vec![Finding {
            id: "f1".to_string(),
            title: "Test".to_string(),
            description: String::new(),
            severity: "high".to_string(),
            category: "memory".to_string(),
            location: FindingLocation {
                file: String::new(),
                function: "strcpy".to_string(),
                line: None,
                address: None,
            },
            evidence: vec![],
            status: FindingStatus::New,
            cycle_discovered: 1,
            cycle_last_updated: 1,
        }];

        let updates = vec![FindingUpdate {
            finding_id: "f1".to_string(),
            new_status: FindingStatus::Confirmed,
            reason: "Verified by context analysis".to_string(),
        }];

        let changed = apply_updates(&mut findings, &updates, 2);
        assert_eq!(changed, 1);
        assert_eq!(findings[0].status, FindingStatus::Confirmed);
        assert_eq!(findings[0].cycle_last_updated, 2);
    }

    #[test]
    fn test_invalidated_findings_not_stored() {
        let db = GraphDb::in_memory().unwrap();
        db.execute(
            "INSERT INTO investigations (id, name) VALUES ('inv1', 'Test')",
            &[],
        )
        .unwrap();

        // Set up a scenario where a finding will be invalidated:
        // strcpy exists but also strlcpy exists (safe variant)
        db.execute(
            "INSERT INTO functions (id, name) VALUES ('f1', 'strcpy')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO functions (id, name) VALUES ('f2', 'strlcpy')",
            &[],
        )
        .unwrap();

        let orch = AnalysisOrchestrator::new(&db, 3);
        let cycles = orch.run_quick_analysis("inv1").unwrap();

        // The orchestrator should have found strcpy, then potentially invalidated it
        // because strlcpy (safe variant) exists
        assert!(!cycles.is_empty());

        // Check that invalidated findings are not in the DB
        let mut stmt = db
            .conn()
            .prepare("SELECT status FROM findings")
            .unwrap();
        let statuses: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .flatten()
            .collect();

        for status in &statuses {
            assert_ne!(status, "invalidated", "Invalidated findings should not be stored");
        }
    }
}
