//! Analysis pipeline: composable multi-agent workflow.
//!
//! A pipeline runs a sequence of agents, passing context forward.
//! Each stage can build its input from the graph database and previous results.
//! Relevant skill content is automatically injected into agent system prompts.
//!
//! The deep pipeline runs exploit-analyst and defense-analyst in parallel,
//! then feeds both perspectives into a debate stage before final synthesis.

use std::collections::{BTreeMap, BTreeSet};

use crate::graph::GraphDb;
use crate::llm::{Client, TokenBudget};
use crate::memory::MemoryStore;
use crate::skills::discovery::load_skill;

use super::definition::load_agent;
use super::output_schema::{
    DefenseAnalystAssessment, DefenseAnalystStructuredOutput, DefenseAnalystVerdict,
    ExploitAnalystAssessment, ExploitAnalystStructuredOutput, ExploitAnalystVerdict,
    ParsedAgentOutput,
};
use super::runner::{build_analysis_context, AgentContextFrame, AgentResult, AgentRunner};

/// Maximum characters for accumulated previous-results context passed between
/// pipeline stages.  Keeps subsequent agent prompts within LLM token limits.
const MAX_PIPELINE_CONTEXT_CHARS: usize = 8000;
const HIGH_CONFIDENCE_CONFIRM_THRESHOLD: i32 = 140;
const HIGH_CONFIDENCE_REJECT_THRESHOLD: i32 = -80;

/// A composable analysis pipeline of agent stages.
pub struct AnalysisPipeline {
    pub stages: Vec<PipelineStage>,
}

/// A single stage in the pipeline.
pub struct PipelineStage {
    /// Agent name to load (must match a `.md` file).
    pub agent_name: String,
    /// How to build the user prompt for this stage.
    pub context_mode: ContextMode,
}

/// How to build the initial context/user-prompt for an agent stage.
pub enum ContextMode {
    /// Build context from the graph database (attack surface, functions, taint flows).
    FromGraph,
    /// Use the output of previous stages as context, plus a preamble.
    FromPreviousResults { preamble: String },
}

/// A parallel debate group: two agents run on the same context, then
/// their outputs are compared and fed into the next stage.
pub struct DebateGroup {
    /// First agent in the debate (e.g., exploit-analyst).
    pub agent_a: String,
    /// Preamble for agent A's context.
    pub preamble_a: String,
    /// Second agent in the debate (e.g., defense-analyst).
    pub agent_b: String,
    /// Preamble for agent B's context.
    pub preamble_b: String,
}

impl AnalysisPipeline {
    /// Run the pipeline against an investigation.
    ///
    /// Returns results from each stage in order.
    pub async fn run(
        &self,
        target: &str,
        investigation_id: &str,
        db: &GraphDb,
        llm: Client,
        budget: &mut TokenBudget,
    ) -> anyhow::Result<Vec<AgentResult>> {
        let runner = AgentRunner::new(llm);
        let mut results: Vec<AgentResult> = Vec::new();

        for stage in &self.stages {
            if budget.exhausted() {
                tracing::warn!(
                    "Token budget exhausted before stage '{}', stopping pipeline",
                    stage.agent_name
                );
                break;
            }

            let mut agent = load_agent(&stage.agent_name)?;

            // Inject relevant skill content into the agent's system prompt.
            // This gives agents access to research-backed techniques and
            // best practices from skills like llm-binary-vuln-guide.
            inject_role_context(&mut agent);
            inject_skill_context(&mut agent);

            let context = match &stage.context_mode {
                ContextMode::FromGraph => build_analysis_context(target, investigation_id, db),
                ContextMode::FromPreviousResults { preamble } => {
                    build_previous_results_context(preamble, &results)
                }
            };

            eprintln!("  Running agent: {} ({})", agent.name, agent.description);

            let result = runner
                .run_agent_with_db(&agent, investigation_id, &context, db, budget)
                .await?;

            eprintln!(
                "  Agent {} completed ({} tokens used)",
                result.agent_name, result.tokens_used
            );

            results.push(result);
        }

        Ok(results)
    }

    /// Run the pipeline with durable agent memory enabled.
    ///
    /// Same as `run()` but agents can use `store_memory` and `recall_memory`
    /// tools to persist and recall experiences across runs.
    pub async fn run_with_memory(
        &self,
        target: &str,
        investigation_id: &str,
        db: &GraphDb,
        llm: Client,
        budget: &mut TokenBudget,
        memory: &MemoryStore,
    ) -> anyhow::Result<Vec<AgentResult>> {
        let runner = AgentRunner::new(llm);
        let mut results: Vec<AgentResult> = Vec::new();

        // Apply confidence decay at the start of each pipeline run
        if let Err(e) = memory.apply_decay() {
            tracing::warn!("Failed to apply memory decay: {e}");
        }

        for stage in &self.stages {
            if budget.exhausted() {
                tracing::warn!(
                    "Token budget exhausted before stage '{}', stopping pipeline",
                    stage.agent_name
                );
                break;
            }

            let mut agent = load_agent(&stage.agent_name)?;
            inject_role_context(&mut agent);
            inject_skill_context(&mut agent);

            let context = match &stage.context_mode {
                ContextMode::FromGraph => build_analysis_context(target, investigation_id, db),
                ContextMode::FromPreviousResults { preamble } => {
                    build_previous_results_context(preamble, &results)
                }
            };

            eprintln!("  Running agent: {} ({})", agent.name, agent.description);

            let result = runner
                .run_agent_with_db_and_memory(
                    &agent,
                    investigation_id,
                    &context,
                    db,
                    memory,
                    budget,
                )
                .await?;

            eprintln!(
                "  Agent {} completed ({} tokens used)",
                result.agent_name, result.tokens_used
            );

            results.push(result);
        }

        // Detect patterns after the pipeline completes
        let detector = crate::memory::PatternDetector::new(memory);
        for stage in &self.stages {
            if let Ok(new_patterns) = detector.detect_patterns(&stage.agent_name) {
                if new_patterns > 0 {
                    tracing::info!(
                        "Detected {} new patterns for agent '{}'",
                        new_patterns,
                        stage.agent_name
                    );
                }
            }
        }

        Ok(results)
    }

    /// Run the pipeline with a debate group that executes two agents independently.
    ///
    /// Stages before the debate run sequentially. Then both debate agents run
    /// on the same accumulated context. Their outputs are compared in a debate
    /// summary, and subsequent stages receive all results including the debate.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_with_debate(
        &self,
        target: &str,
        investigation_id: &str,
        db: &GraphDb,
        llm: Client,
        budget: &mut TokenBudget,
        debate: &DebateGroup,
        debate_after_stage: usize,
    ) -> anyhow::Result<Vec<AgentResult>> {
        let runner = AgentRunner::new(llm);
        let mut results: Vec<AgentResult> = Vec::new();

        // Run stages before the debate point.
        for (i, stage) in self.stages.iter().enumerate() {
            if i >= debate_after_stage {
                break;
            }
            if budget.exhausted() {
                tracing::warn!(
                    "Token budget exhausted before stage '{}', stopping pipeline",
                    stage.agent_name
                );
                return Ok(results);
            }

            let mut agent = load_agent(&stage.agent_name)?;
            inject_role_context(&mut agent);
            inject_skill_context(&mut agent);

            let context = match &stage.context_mode {
                ContextMode::FromGraph => build_analysis_context(target, investigation_id, db),
                ContextMode::FromPreviousResults { preamble } => {
                    build_previous_results_context(preamble, &results)
                }
            };

            eprintln!("  Running agent: {} ({})", agent.name, agent.description);
            let result = runner
                .run_agent_with_db(&agent, investigation_id, &context, db, budget)
                .await?;
            eprintln!(
                "  Agent {} completed ({} tokens used)",
                result.agent_name, result.tokens_used
            );
            results.push(result);
        }

        // Run the debate: both agents get the same context, execute sequentially
        // (since GraphDb is not Send, true parallel with tokio::spawn is not possible,
        // but they independently analyze the same findings without seeing each other).
        if !budget.exhausted() {
            let debate_context_a = build_previous_results_context(&debate.preamble_a, &results);
            let debate_context_b = build_previous_results_context(&debate.preamble_b, &results);

            // Agent A
            let mut agent_a = load_agent(&debate.agent_a)?;
            inject_role_context(&mut agent_a);
            inject_skill_context(&mut agent_a);
            eprintln!(
                "  Running debate agent A: {} ({})",
                agent_a.name, agent_a.description
            );
            let result_a = runner
                .run_agent_with_db(&agent_a, investigation_id, &debate_context_a, db, budget)
                .await?;
            eprintln!(
                "  Debate agent {} completed ({} tokens used)",
                result_a.agent_name, result_a.tokens_used
            );

            // Agent B (independent — does NOT see Agent A's output)
            let mut agent_b = load_agent(&debate.agent_b)?;
            inject_role_context(&mut agent_b);
            inject_skill_context(&mut agent_b);
            eprintln!(
                "  Running debate agent B: {} ({})",
                agent_b.name, agent_b.description
            );
            let result_b = runner
                .run_agent_with_db(&agent_b, investigation_id, &debate_context_b, db, budget)
                .await?;
            eprintln!(
                "  Debate agent {} completed ({} tokens used)",
                result_b.agent_name, result_b.tokens_used
            );

            // Create a debate summary that highlights agreements and disagreements.
            let debate_summary = build_debate_summary(&result_a, &result_b);
            let mut debate_frame = AgentContextFrame::synthetic(
                "debate-summary",
                "Pipeline-generated summary of offense/defense agreements and disagreements",
                None,
                &debate_summary,
            );
            let debate_context_summary = build_debate_context_summary(&debate_summary);
            debate_frame.structured_summary = Some(debate_context_summary.clone());
            debate_frame.key_points = extract_debate_context_key_points(&debate_context_summary);
            results.push(result_a);
            results.push(result_b);
            results.push(AgentResult {
                agent_name: "debate-summary".into(),
                output: debate_summary,
                tokens_used: 0,
                context_frame: debate_frame,
                parsed_output: None,
                parsed_output_error: None,
            });
        }

        // Run remaining stages (e.g., verdict-synthesizer) with debate results.
        for stage in self.stages.iter().skip(debate_after_stage) {
            if budget.exhausted() {
                tracing::warn!(
                    "Token budget exhausted before stage '{}', stopping pipeline",
                    stage.agent_name
                );
                break;
            }

            let mut agent = load_agent(&stage.agent_name)?;
            inject_role_context(&mut agent);
            inject_skill_context(&mut agent);

            let context = match &stage.context_mode {
                ContextMode::FromGraph => build_analysis_context(target, investigation_id, db),
                ContextMode::FromPreviousResults { preamble } => {
                    build_previous_results_context(preamble, &results)
                }
            };

            eprintln!("  Running agent: {} ({})", agent.name, agent.description);
            let result = runner
                .run_agent_with_db(&agent, investigation_id, &context, db, budget)
                .await?;
            eprintln!(
                "  Agent {} completed ({} tokens used)",
                result.agent_name, result.tokens_used
            );
            results.push(result);
        }

        Ok(results)
    }
}

/// Build context from previous agent results, with truncation.
fn build_previous_results_context(preamble: &str, results: &[AgentResult]) -> String {
    const OLDER_CONTEXT_OMITTED_NOTICE: &str =
        "\n...[truncated older context to preserve newest debate evidence]";
    const TRUNCATED_PREAMBLE_NOTICE: &str = "\n...[truncated]";

    let mut sections = Vec::with_capacity(results.len());
    for prev in results {
        sections.push(render_previous_result_context(prev));
    }

    let mut kept_sections: Vec<String> = Vec::new();
    let mut total_len = preamble.len();
    let mut omitted_any = false;

    for section in sections.iter().rev() {
        if total_len + section.len() <= MAX_PIPELINE_CONTEXT_CHARS {
            kept_sections.push(section.clone());
            total_len += section.len();
        } else if kept_sections.is_empty() {
            let available = MAX_PIPELINE_CONTEXT_CHARS
                .saturating_sub(total_len)
                .saturating_sub(OLDER_CONTEXT_OMITTED_NOTICE.len());
            let truncated = truncate_section_middle(section, available);
            if !truncated.is_empty() {
                total_len += truncated.len();
                kept_sections.push(truncated);
            }
            omitted_any = true;
        } else {
            omitted_any = true;
        }
    }

    kept_sections.reverse();

    if omitted_any {
        while total_len + OLDER_CONTEXT_OMITTED_NOTICE.len() > MAX_PIPELINE_CONTEXT_CHARS
            && !kept_sections.is_empty()
        {
            let removed = kept_sections.remove(0);
            total_len = total_len.saturating_sub(removed.len());
        }
    }

    let mut suffix = String::new();
    if omitted_any {
        suffix.push_str(OLDER_CONTEXT_OMITTED_NOTICE);
    }
    for section in &kept_sections {
        suffix.push_str(section);
    }

    let mut ctx = preamble.to_string();
    ctx.push_str(&suffix);

    if ctx.len() > MAX_PIPELINE_CONTEXT_CHARS {
        let preamble_budget = MAX_PIPELINE_CONTEXT_CHARS
            .saturating_sub(suffix.len())
            .saturating_sub(TRUNCATED_PREAMBLE_NOTICE.len());
        let mut trimmed = truncate_to_char_boundary(preamble, preamble_budget);
        if trimmed.len() < preamble.len() {
            trimmed.push_str(TRUNCATED_PREAMBLE_NOTICE);
        }
        trimmed.push_str(&suffix);
        return trimmed;
    }

    ctx
}

fn truncate_to_char_boundary(text: &str, max_len: usize) -> String {
    let mut boundary = max_len.min(text.len());
    while boundary > 0 && !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    text[..boundary].to_string()
}

fn truncate_from_end_to_char_boundary(text: &str, max_len: usize) -> String {
    if max_len >= text.len() {
        return text.to_string();
    }

    let mut start = text.len().saturating_sub(max_len);
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    text[start..].to_string()
}

fn truncate_section_middle(section: &str, max_len: usize) -> String {
    const TRUNCATED_SECTION_NOTICE: &str = "\n...[truncated newest context]...\n";

    if section.len() <= max_len {
        return section.to_string();
    }
    if max_len <= TRUNCATED_SECTION_NOTICE.len() {
        return truncate_to_char_boundary(section, max_len);
    }

    let remaining = max_len - TRUNCATED_SECTION_NOTICE.len();
    let head_len = remaining / 2;
    let tail_len = remaining - head_len;
    let head = truncate_to_char_boundary(section, head_len);
    let tail = truncate_from_end_to_char_boundary(section, tail_len);
    format!("{head}{TRUNCATED_SECTION_NOTICE}{tail}")
}

fn render_previous_result_context(prev: &AgentResult) -> String {
    let mut rendered = format!(
        "\n\n--- Context frame from {} ---\n{}",
        prev.agent_name,
        format_context_frame(&prev.context_frame)
    );
    if prev.context_frame.structured_summary.is_none() {
        rendered.push_str(&format!(
            "\n\n--- Condensed output from {} ---\n{}",
            prev.agent_name,
            format_output_excerpt(&prev.output)
        ));
    }
    rendered
}

fn build_debate_context_summary(summary: &str) -> String {
    let mut compact = String::from("Weighted debate threshold summary:\n");
    let mut current_finding: Option<String> = None;
    let mut in_summary_statistics = false;

    for line in summary.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed == "Weighted finding comparisons:" {
            continue;
        }

        if trimmed == "Summary statistics:" {
            in_summary_statistics = true;
            compact.push_str("\nSummary statistics:\n");
            continue;
        }

        if trimmed.starts_with("CONFIDENCE THRESHOLD NOTE:") && trimmed.contains("unavailable") {
            compact.push_str(trimmed);
            compact.push('\n');
            continue;
        }

        if in_summary_statistics {
            if trimmed.starts_with("- ")
                || trimmed.starts_with("WEIGHTED DISAGREEMENTS DETECTED:")
                || trimmed.starts_with("DISAGREEMENTS DETECTED:")
                || trimmed.starts_with("CONFIDENCE THRESHOLD NOTE:")
            {
                compact.push_str(trimmed);
                compact.push('\n');
            }
            continue;
        }

        if trimmed.starts_with("- ") {
            current_finding = Some(trimmed.to_string());
            continue;
        }

        if trimmed.starts_with("threshold_hint:") {
            if let Some(finding) = current_finding.take() {
                compact.push_str(&finding);
                compact.push('\n');
            }
            compact.push_str("  ");
            compact.push_str(trimmed);
            compact.push('\n');
            continue;
        }

        if trimmed.starts_with("offense_evidence:") || trimmed.starts_with("defense_evidence:") {
            compact.push_str("  ");
            compact.push_str(trimmed);
            compact.push('\n');
        }
    }

    if compact.trim() == "Weighted debate threshold summary:" {
        summary.to_string()
    } else {
        compact.trim_end().to_string()
    }
}

fn extract_debate_context_key_points(summary: &str) -> Vec<String> {
    const MAX_KEY_POINTS: usize = 10;

    summary
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.starts_with("- ")
                || line.starts_with("threshold_hint:")
                || line.starts_with("CONFIDENCE THRESHOLD NOTE:")
                || line.starts_with("WEIGHTED DISAGREEMENTS DETECTED:")
                || line.starts_with("DISAGREEMENTS DETECTED:")
        })
        .take(MAX_KEY_POINTS)
        .map(ToOwned::to_owned)
        .collect()
}

fn format_context_frame(frame: &AgentContextFrame) -> String {
    let mut rendered = format!(
        "agent: {}\ndescription: {}",
        frame.agent_name, frame.description
    );

    if let Some(role) = &frame.role {
        if !role.title.is_empty() {
            rendered.push_str(&format!("\nrole_title: {}", role.title));
        }
        append_role_list(&mut rendered, "expertise", &role.expertise);
        append_role_list(&mut rendered, "focus", &role.focus);
        append_role_list(&mut rendered, "skepticism", &role.skepticism);
        append_role_list(
            &mut rendered,
            "evidence_preferences",
            &role.evidence_preferences,
        );
    }

    if let Some(schema_name) = &frame.output_schema {
        rendered.push_str(&format!("\noutput_schema: {}", schema_name));
    }

    if let Some(summary) = &frame.structured_summary {
        rendered.push_str(&format!("\nstructured_summary:\n{}", summary));
    }

    if let Some(parse_error) = &frame.structured_output_error {
        rendered.push_str(&format!("\nstructured_output_error: {}", parse_error));
    }

    if !frame.key_points.is_empty() {
        rendered.push_str("\nkey_points:");
        for point in &frame.key_points {
            rendered.push_str(&format!("\n- {}", point));
        }
    }

    rendered
}

fn format_output_excerpt(output: &str) -> String {
    const MAX_EXCERPT_LINES: usize = 12;
    const MAX_EXCERPT_CHARS: usize = 1200;
    const EXCERPT_HEAD_LINES: usize = 6;
    const EXCERPT_TAIL_LINES: usize = 6;

    let lines: Vec<&str> = output.lines().collect();
    let line_based_excerpt = if lines.len() > MAX_EXCERPT_LINES {
        let mut excerpt_lines = lines
            .iter()
            .take(EXCERPT_HEAD_LINES)
            .copied()
            .collect::<Vec<_>>();
        excerpt_lines.push("...[middle lines omitted]...");
        excerpt_lines.extend(lines.iter().rev().take(EXCERPT_TAIL_LINES).copied().rev());
        excerpt_lines.join("\n")
    } else {
        lines.join("\n")
    };

    let mut excerpt = line_based_excerpt;
    let needs_line_truncation = lines.len() > MAX_EXCERPT_LINES;
    let needs_char_truncation = excerpt.len() > MAX_EXCERPT_CHARS;
    let needs_truncation = needs_line_truncation || needs_char_truncation;
    if needs_char_truncation {
        let mut boundary = MAX_EXCERPT_CHARS;
        while boundary > 0 && !excerpt.is_char_boundary(boundary) {
            boundary -= 1;
        }
        excerpt.truncate(boundary);
    }

    if needs_truncation && !excerpt.ends_with("\n...[truncated excerpt]") {
        excerpt.push_str("\n...[truncated excerpt]");
    }

    excerpt
}

fn append_role_list(rendered: &mut String, label: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }

    rendered.push_str(&format!("\n{}:", label));
    for value in values {
        rendered.push_str(&format!("\n- {}", value));
    }
}

/// Build a debate summary comparing two agent outputs.
///
/// Extracts per-finding verdicts from both agents and identifies:
/// - Agreements (both say exploitable or both say safe)
/// - Disagreements (one says exploitable, other says safe)
fn build_debate_summary(agent_a: &AgentResult, agent_b: &AgentResult) -> String {
    if let (Some(exploit), Some(defense)) = (
        agent_a
            .parsed_output
            .as_ref()
            .and_then(ParsedAgentOutput::as_exploit_analyst_v1),
        agent_b
            .parsed_output
            .as_ref()
            .and_then(ParsedAgentOutput::as_defense_analyst_v1),
    ) {
        return build_weighted_debate_summary(
            agent_a.agent_name.as_str(),
            exploit,
            agent_b.agent_name.as_str(),
            defense,
        );
    }

    if let (Some(exploit), Some(defense)) = (
        agent_b
            .parsed_output
            .as_ref()
            .and_then(ParsedAgentOutput::as_exploit_analyst_v1),
        agent_a
            .parsed_output
            .as_ref()
            .and_then(ParsedAgentOutput::as_defense_analyst_v1),
    ) {
        return build_weighted_debate_summary(
            agent_b.agent_name.as_str(),
            exploit,
            agent_a.agent_name.as_str(),
            defense,
        );
    }

    let mut summary = String::from("=== DEBATE SUMMARY ===\n\n");
    summary.push_str(&format!(
        "Two independent analysts reviewed the findings:\n\
         - {} (offense perspective): evaluated exploitability\n\
         - {} (defense perspective): evaluated mitigations\n\n",
        agent_a.agent_name, agent_b.agent_name
    ));
    if let Some(threshold_hint_unavailable) =
        build_threshold_hint_unavailable_note(agent_a, agent_b)
    {
        summary.push_str(&threshold_hint_unavailable);
        summary.push('\n');
    }

    // Extract verdicts from agent A (CONFIRMED/DOWNGRADED/REJECTED)
    let a_verdicts: Vec<&str> = agent_a
        .output
        .lines()
        .filter(|line| line_has_any_verdict_token(line, &["CONFIRMED", "REJECTED", "DOWNGRADED"]))
        .collect();

    // Extract verdicts from agent B (VULNERABLE/MITIGATED/SAFE)
    let b_verdicts: Vec<&str> = agent_b
        .output
        .lines()
        .filter(|line| line_has_any_verdict_token(line, &["VULNERABLE", "MITIGATED", "SAFE"]))
        .collect();

    summary.push_str("Offense analyst verdicts:\n");
    for v in &a_verdicts {
        summary.push_str(&format!("  {}\n", v.trim()));
    }

    summary.push_str("\nDefense analyst verdicts:\n");
    for v in &b_verdicts {
        summary.push_str(&format!("  {}\n", v.trim()));
    }

    // Identify agreements and disagreements.
    let a_positive = a_verdicts
        .iter()
        .filter(|l| line_has_any_verdict_token(l, &["CONFIRMED", "DOWNGRADED"]))
        .count();
    let a_rejects = a_verdicts
        .iter()
        .filter(|l| line_has_verdict_token(l, "REJECTED"))
        .count();
    let b_positive = b_verdicts
        .iter()
        .filter(|l| line_has_any_verdict_token(l, &["VULNERABLE", "MITIGATED"]))
        .count();
    let b_safe = b_verdicts
        .iter()
        .filter(|l| line_has_verdict_token(l, "SAFE"))
        .count();

    summary.push_str(&format!(
        "\nSummary statistics:\n\
         - Offense: {} positive, {} rejected\n\
         - Defense: {} positive, {} safe\n",
        a_positive, a_rejects, b_positive, b_safe
    ));

    if (a_positive > 0 && b_safe > 0) || (a_rejects > 0 && b_positive > 0) {
        summary.push_str(
            "\nDISAGREEMENTS DETECTED: Offense and Defense reached opposing conclusions in the fallback debate summary.\n\
             The verdict-synthesizer should carefully examine these conflicts and read the code \
             before making a final decision.\n",
        );
    }

    summary
}

fn build_threshold_hint_unavailable_note(
    agent_a: &AgentResult,
    agent_b: &AgentResult,
) -> Option<String> {
    let parse_failures = [agent_a, agent_b]
        .into_iter()
        .filter_map(|agent| {
            agent
                .parsed_output_error
                .as_ref()
                .map(|error| format!("{}: {}", agent.agent_name, error))
        })
        .collect::<Vec<_>>();

    if parse_failures.is_empty() {
        None
    } else {
        Some(format!(
            "CONFIDENCE THRESHOLD NOTE: unavailable because structured debate parsing failed ({}). Do not auto-confirm or auto-reject from thresholds; read the code directly.",
            parse_failures.join(" | ")
        ))
    }
}

fn build_weighted_debate_summary(
    offense_name: &str,
    exploit: &ExploitAnalystStructuredOutput,
    defense_name: &str,
    defense: &DefenseAnalystStructuredOutput,
) -> String {
    let mut summary = String::from("=== WEIGHTED DEBATE SUMMARY ===\n\n");
    summary.push_str(&format!(
        "Two independent analysts reviewed the findings with structured confidence:\n\
         - {} (offense perspective): exploitability confidence\n\
         - {} (defense perspective): mitigation confidence\n\n",
        offense_name, defense_name
    ));
    summary.push_str(&format!(
        "Offense summary: {}\nDefense summary: {}\n",
        exploit.summary, defense.summary
    ));

    let exploit_by_title = group_exploit_assessments(&exploit.assessments);
    let defense_by_title = group_defense_assessments(&defense.assessments);

    let mut disagreement_count = 0usize;
    let mut high_confidence_confirm_count = 0usize;
    let mut high_confidence_reject_count = 0usize;
    let mut review_required_count = 0usize;
    let all_titles: BTreeSet<String> = exploit_by_title
        .keys()
        .cloned()
        .chain(defense_by_title.keys().cloned())
        .collect();
    summary.push_str("\nWeighted finding comparisons:\n");
    for title_key in all_titles {
        let offense_assessments = exploit_by_title
            .get(&title_key)
            .cloned()
            .unwrap_or_default();
        let defense_assessments = defense_by_title
            .get(&title_key)
            .cloned()
            .unwrap_or_default();
        let display_title = display_title_for_group(&offense_assessments, &defense_assessments);
        let offense_aggregate = aggregate_exploit_group_score(&offense_assessments);
        let defense_aggregate = aggregate_defense_group_score(&defense_assessments);
        let offense_score = offense_aggregate.score;
        let defense_score = defense_aggregate.score;
        let net_score = offense_score + defense_score;

        let has_disagreement = offense_aggregate.has_internal_conflict
            || defense_aggregate.has_internal_conflict
            || (!offense_assessments.is_empty()
                && !defense_assessments.is_empty()
                && offense_score.signum() != 0
                && defense_score.signum() != 0
                && offense_score.signum() != defense_score.signum());
        if has_disagreement {
            disagreement_count += 1;
        }
        let (threshold_hint, threshold_reason) = classify_confidence_threshold(
            offense_score,
            defense_score,
            has_disagreement,
            !offense_assessments.is_empty(),
            !defense_assessments.is_empty(),
        );
        match threshold_hint {
            ConfidenceThresholdHint::HighConfidenceConfirm => high_confidence_confirm_count += 1,
            ConfidenceThresholdHint::HighConfidenceReject => high_confidence_reject_count += 1,
            ConfidenceThresholdHint::ReviewRequired => review_required_count += 1,
        }

        summary.push_str(&format!(
            "- {}: offense={}, defense={}",
            display_title,
            format_exploit_assessments(&offense_assessments),
            format_defense_assessments(&defense_assessments),
        ));
        if !offense_assessments.is_empty() && !defense_assessments.is_empty() {
            summary.push_str(&format!(", net_weight={}", net_score));
        }
        summary.push('\n');
        summary.push_str(&format!(
            "    threshold_hint: {} ({})\n",
            threshold_hint.as_str(),
            threshold_reason
        ));

        let offense_evidence = collect_exploit_evidence(&offense_assessments);
        if !offense_evidence.is_empty() {
            summary.push_str(&format!(
                "    offense_evidence: {}\n",
                offense_evidence.join(" | ")
            ));
        }
        let defense_evidence = collect_defense_evidence(&defense_assessments);
        if !defense_evidence.is_empty() {
            summary.push_str(&format!(
                "    defense_evidence: {}\n",
                defense_evidence.join(" | ")
            ));
        }
    }

    summary.push_str(&format!(
        "\nSummary statistics:\n- offense_assessments: {}\n- defense_assessments: {}\n- weighted_disagreements: {}\n- high_confidence_confirm: {}\n- high_confidence_reject: {}\n- review_required: {}\n",
        exploit.assessments.len(),
        defense.assessments.len(),
        disagreement_count,
        high_confidence_confirm_count,
        high_confidence_reject_count,
        review_required_count
    ));

    if disagreement_count > 0 {
        summary.push_str(
            "\nWEIGHTED DISAGREEMENTS DETECTED: Use the net_weight values, concrete evidence, and direct code reading to resolve conflicts.\n",
        );
    }
    if review_required_count > 0 {
        summary.push_str(
            "CONFIDENCE THRESHOLD NOTE: Only auto-confirm findings labelled HIGH_CONFIDENCE_CONFIRM. For REVIEW_REQUIRED findings, verify with direct code evidence before confirming.\n",
        );
    }

    summary
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConfidenceThresholdHint {
    HighConfidenceConfirm,
    HighConfidenceReject,
    ReviewRequired,
}

impl ConfidenceThresholdHint {
    fn as_str(self) -> &'static str {
        match self {
            Self::HighConfidenceConfirm => "HIGH_CONFIDENCE_CONFIRM",
            Self::HighConfidenceReject => "HIGH_CONFIDENCE_REJECT",
            Self::ReviewRequired => "REVIEW_REQUIRED",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AggregatedGroupScore {
    score: i32,
    has_internal_conflict: bool,
}

fn exploit_verdict_score(verdict: &ExploitAnalystVerdict) -> i32 {
    match verdict {
        ExploitAnalystVerdict::Confirmed => 1,
        ExploitAnalystVerdict::Downgraded => 1,
        ExploitAnalystVerdict::Rejected => -1,
    }
}

fn aggregate_group_scores(scores: impl Iterator<Item = i32>) -> AggregatedGroupScore {
    let mut best_score = 0;
    let mut best_abs = 0;
    let mut saw_positive = false;
    let mut saw_negative = false;

    for score in scores {
        if score > 0 {
            saw_positive = true;
        } else if score < 0 {
            saw_negative = true;
        }

        let abs = score.abs();
        if abs > best_abs {
            best_abs = abs;
            best_score = score;
        }
    }

    if saw_positive && saw_negative {
        AggregatedGroupScore {
            score: 0,
            has_internal_conflict: true,
        }
    } else {
        AggregatedGroupScore {
            score: best_score,
            has_internal_conflict: false,
        }
    }
}

fn aggregate_exploit_group_score(
    assessments: &[&ExploitAnalystAssessment],
) -> AggregatedGroupScore {
    aggregate_group_scores(assessments.iter().map(|assessment| {
        exploit_verdict_score(&assessment.verdict) * i32::from(assessment.confidence_percent)
    }))
}

fn defense_verdict_score(verdict: &DefenseAnalystVerdict) -> i32 {
    match verdict {
        DefenseAnalystVerdict::Vulnerable => 1,
        DefenseAnalystVerdict::Mitigated => 1,
        DefenseAnalystVerdict::Safe => -1,
    }
}

fn aggregate_defense_group_score(
    assessments: &[&DefenseAnalystAssessment],
) -> AggregatedGroupScore {
    aggregate_group_scores(assessments.iter().map(|assessment| {
        defense_verdict_score(&assessment.verdict) * i32::from(assessment.confidence_percent)
    }))
}

fn classify_confidence_threshold(
    offense_score: i32,
    defense_score: i32,
    has_disagreement: bool,
    has_offense_signal: bool,
    has_defense_signal: bool,
) -> (ConfidenceThresholdHint, &'static str) {
    if has_disagreement {
        return (ConfidenceThresholdHint::ReviewRequired, "disagreement");
    }

    let net_score = offense_score + defense_score;
    if has_offense_signal
        && has_defense_signal
        && offense_score >= 80
        && defense_score > 0
        && net_score >= HIGH_CONFIDENCE_CONFIRM_THRESHOLD
    {
        return (
            ConfidenceThresholdHint::HighConfidenceConfirm,
            "strong_consensus",
        );
    }

    if net_score <= HIGH_CONFIDENCE_REJECT_THRESHOLD
        && has_offense_signal
        && has_defense_signal
        && (defense_score <= -70 || offense_score <= -70)
    {
        return (
            ConfidenceThresholdHint::HighConfidenceReject,
            "strong_negative_signal",
        );
    }

    if has_offense_signal ^ has_defense_signal {
        return (
            ConfidenceThresholdHint::ReviewRequired,
            "missing_counterparty_signal",
        );
    }

    (
        ConfidenceThresholdHint::ReviewRequired,
        "insufficient_consensus",
    )
}

fn line_has_any_verdict_token(line: &str, tokens: &[&str]) -> bool {
    tokens
        .iter()
        .any(|token| line_has_verdict_token(line, token))
}

fn line_has_verdict_token(line: &str, token: &str) -> bool {
    line.to_uppercase()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|part| part == token)
}

fn normalize_finding_title(title: &str) -> String {
    let normalized = title
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(|part| part.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    if normalized.is_empty() {
        title.trim().to_ascii_lowercase()
    } else {
        normalized
    }
}

fn group_exploit_assessments(
    assessments: &[ExploitAnalystAssessment],
) -> BTreeMap<String, Vec<&ExploitAnalystAssessment>> {
    let mut grouped = BTreeMap::new();
    for assessment in assessments {
        grouped
            .entry(normalize_finding_title(&assessment.finding_title))
            .or_insert_with(Vec::new)
            .push(assessment);
    }
    grouped
}

fn group_defense_assessments(
    assessments: &[DefenseAnalystAssessment],
) -> BTreeMap<String, Vec<&DefenseAnalystAssessment>> {
    let mut grouped = BTreeMap::new();
    for assessment in assessments {
        grouped
            .entry(normalize_finding_title(&assessment.finding_title))
            .or_insert_with(Vec::new)
            .push(assessment);
    }
    grouped
}

fn display_title_for_group(
    offense_assessments: &[&ExploitAnalystAssessment],
    defense_assessments: &[&DefenseAnalystAssessment],
) -> String {
    offense_assessments
        .first()
        .map(|assessment| assessment.finding_title.clone())
        .or_else(|| {
            defense_assessments
                .first()
                .map(|assessment| assessment.finding_title.clone())
        })
        .unwrap_or_else(|| "(unknown finding)".into())
}

fn format_exploit_assessments(assessments: &[&ExploitAnalystAssessment]) -> String {
    if assessments.is_empty() {
        return "missing".into();
    }
    assessments
        .iter()
        .map(|assessment| {
            format!(
                "{} @ {}%",
                assessment.verdict, assessment.confidence_percent
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_defense_assessments(assessments: &[&DefenseAnalystAssessment]) -> String {
    if assessments.is_empty() {
        return "missing".into();
    }
    assessments
        .iter()
        .map(|assessment| {
            format!(
                "{} @ {}%",
                assessment.verdict, assessment.confidence_percent
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn collect_exploit_evidence(assessments: &[&ExploitAnalystAssessment]) -> Vec<String> {
    let mut evidence = BTreeSet::new();
    for assessment in assessments {
        for item in &assessment.evidence {
            let trimmed = item.trim();
            if !trimmed.is_empty() {
                evidence.insert(trimmed.to_string());
            }
        }
    }
    evidence.into_iter().collect()
}

fn collect_defense_evidence(assessments: &[&DefenseAnalystAssessment]) -> Vec<String> {
    let mut evidence = BTreeSet::new();
    for assessment in assessments {
        for item in &assessment.evidence {
            let trimmed = item.trim();
            if !trimmed.is_empty() {
                evidence.insert(trimmed.to_string());
            }
        }
    }
    evidence.into_iter().collect()
}

fn vuln_hunter_stage(agent_name: String, include_create_finding_preamble: bool) -> PipelineStage {
    let preamble = if include_create_finding_preamble {
        "The attack surface analysis is complete. Now perform deep \
         vulnerability analysis based on the attack surface findings below. \
         Focus on the highest-risk areas identified. \
         For each vulnerability found, use create_finding to record it."
    } else {
        "The attack surface analysis is complete. Now perform deep \
         vulnerability analysis based on the attack surface findings below. \
         Focus on the highest-risk areas identified."
    };

    PipelineStage {
        agent_name,
        context_mode: ContextMode::FromPreviousResults {
            preamble: preamble.into(),
        },
    }
}

/// Build the default analysis pipeline: decompile-renamer -> attack-surface -> vuln-hunter -> critic.
pub fn default_pipeline() -> AnalysisPipeline {
    default_pipeline_for_target("")
}

/// Build the default analysis pipeline with language-aware vuln-hunter selection.
pub fn default_pipeline_for_target(target: &str) -> AnalysisPipeline {
    let hunter = select_vuln_hunter(target);
    AnalysisPipeline {
        stages: vec![
            // Pre-processing: improve decompiled code readability
            PipelineStage {
                agent_name: "decompile-renamer".into(),
                context_mode: ContextMode::FromGraph,
            },
            PipelineStage {
                agent_name: "attack-surface".into(),
                context_mode: ContextMode::FromGraph,
            },
            vuln_hunter_stage(hunter, false),
            PipelineStage {
                agent_name: "critic".into(),
                context_mode: ContextMode::FromPreviousResults {
                    preamble: "Review the following vulnerability findings and validate each one. \
                               For each finding, determine if it is a true positive or false \
                               positive, and adjust severity if needed."
                        .into(),
                },
            },
        ],
    }
}

/// Build a deep analysis pipeline with parallel debate between exploit-analyst
/// and defense-analyst.
///
/// Discovery: attack-surface -> vuln-hunter (find everything)
/// Debate: exploit-analyst + defense-analyst run independently on the same findings,
///         then their perspectives are compared in a debate summary.
/// Synthesis: verdict-synthesizer weighs all perspectives including the debate.
///
/// This pipeline trades speed for precision. The debate step surfaces
/// disagreements between offense and defense perspectives before final synthesis.
pub fn deep_pipeline() -> AnalysisPipeline {
    deep_pipeline_for_target("")
}

/// Build a deep analysis pipeline with language-aware vuln-hunter selection.
pub fn deep_pipeline_for_target(target: &str) -> AnalysisPipeline {
    let hunter = select_vuln_hunter(target);
    AnalysisPipeline {
        stages: vec![
            // Pre-processing: improve decompiled code readability
            PipelineStage {
                agent_name: "decompile-renamer".into(),
                context_mode: ContextMode::FromGraph,
            },
            // Discovery phase
            PipelineStage {
                agent_name: "attack-surface".into(),
                context_mode: ContextMode::FromGraph,
            },
            vuln_hunter_stage(hunter, true),
            // NOTE: exploit-analyst and defense-analyst are NOT listed here.
            // They run via the debate group in deep_pipeline_with_debate().
            // Synthesis: final verdict based on all validation perspectives
            PipelineStage {
                agent_name: "verdict-synthesizer".into(),
                context_mode: ContextMode::FromPreviousResults {
                    preamble: "You have received the complete output from all agents in the pipeline: \
                               attack-surface mapping, vulnerability hunting, exploit analysis, and \
                               defense analysis. A DEBATE SUMMARY highlights agreements and \
                               disagreements between the offense and defense analysts. \
                               Pay special attention to DISAGREEMENTS — read the code yourself to \
                               break ties. \
                               For each finding that is genuinely exploitable (confirmed by exploit-analyst \
                               AND not fully mitigated per defense-analyst), use create_finding to record \
                               the confirmed vulnerability. Reject false positives and explain why. \
                               Be decisive — false positives damage credibility more than false negatives."
                        .into(),
                },
            },
        ],
    }
}

/// Build the debate group for the deep pipeline.
///
/// Both agents independently review the same vuln-hunter findings.
pub fn deep_pipeline_debate() -> DebateGroup {
    DebateGroup {
        agent_a: "exploit-analyst".into(),
        preamble_a: "Review each vulnerability finding below. For each one, evaluate \
                      whether it can actually be triggered by an attacker. Check reachability \
                      from external inputs, controllability of parameters, and real impact. \
                      Respond with CONFIRMED, DOWNGRADED, or REJECTED for each finding."
            .into(),
        agent_b: "defense-analyst".into(),
        preamble_b: "Review each vulnerability finding below. For each one, check whether \
                      defensive controls (input validation, sanitization, safe wrappers, \
                      architectural mitigations) make it non-exploitable. \
                      Respond with VULNERABLE, MITIGATED, or SAFE for each finding."
            .into(),
    }
}

/// Convenience: run the deep pipeline with the debate stage.
///
/// This is the recommended entry point for deep analysis. It runs:
/// 1. decompile-renamer, attack-surface, vuln-hunter (sequentially)
/// 2. exploit-analyst + defense-analyst (debate — independent parallel analysis)
/// 3. verdict-synthesizer (with debate summary)
pub async fn run_deep_pipeline_with_debate(
    target: &str,
    investigation_id: &str,
    db: &GraphDb,
    llm: Client,
    budget: &mut TokenBudget,
) -> anyhow::Result<Vec<AgentResult>> {
    let pipeline = deep_pipeline_for_target(target);
    let debate = deep_pipeline_debate();
    // Debate runs after stage index 3 (after vuln-hunter, which is stages[2]),
    // before verdict-synthesizer (stages[3]).
    pipeline
        .run_with_debate(target, investigation_id, db, llm, budget, &debate, 3)
        .await
}

/// Select the best vuln-hunter agent for the given target file.
///
/// Returns a language-specialized agent name if one exists for the file's
/// language, otherwise falls back to the generic `vuln-hunter`.
pub fn select_vuln_hunter(target: &str) -> String {
    let ext = target.rsplit('.').next().unwrap_or("").to_lowercase();

    let agent_name = match ext.as_str() {
        "py" | "pyw" => "vuln-hunter-python",
        "java" | "kt" | "scala" => "vuln-hunter-java",
        _ => "vuln-hunter",
    };

    // Verify the specialized agent actually exists; fall back to generic if not.
    match load_agent(agent_name) {
        Ok(_) => agent_name.to_string(),
        Err(_) => {
            if agent_name != "vuln-hunter" {
                tracing::debug!(
                    "Specialized agent '{}' not found for {}, using generic vuln-hunter",
                    agent_name,
                    target
                );
            }
            "vuln-hunter".to_string()
        }
    }
}

/// Build a pipeline from a list of agent names.
///
/// The first agent gets graph context, subsequent agents get previous results.
pub fn pipeline_from_names(names: &[String]) -> AnalysisPipeline {
    let stages = names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let context_mode = if i == 0 {
                ContextMode::FromGraph
            } else {
                ContextMode::FromPreviousResults {
                    preamble: format!(
                        "Continue the analysis based on the results from previous agents. \
                         You are the {} agent in the pipeline.",
                        ordinal(i + 1)
                    ),
                }
            };
            PipelineStage {
                agent_name: name.clone(),
                context_mode,
            }
        })
        .collect();

    AnalysisPipeline { stages }
}

fn ordinal(n: usize) -> String {
    match n {
        1 => "1st".into(),
        2 => "2nd".into(),
        3 => "3rd".into(),
        _ => format!("{n}th"),
    }
}

/// Mapping from agent names to skills that enhance their analysis.
const AGENT_SKILL_MAP: &[(&str, &str)] = &[
    ("vuln-hunter", "llm-binary-vuln-guide"),
    ("vuln-hunter-python", "llm-binary-vuln-guide"),
    ("vuln-hunter-java", "llm-binary-vuln-guide"),
    ("decompile-analyst", "llm-binary-vuln-guide"),
    ("decompile-renamer", "llm-binary-vuln-guide"),
    ("taint-tracer", "llm-binary-vuln-guide"),
    ("exploit-analyst", "llm-binary-vuln-guide"),
    ("attack-surface", "llm-binary-vuln-guide"),
];

/// Inject relevant skill content into an agent's system prompt.
///
/// Looks up skills mapped to this agent and appends their content
/// as a reference section at the end of the system prompt.
fn inject_skill_context(agent: &mut super::definition::AgentDefinition) {
    let relevant_skills: Vec<&str> = AGENT_SKILL_MAP
        .iter()
        .filter(|(agent_name, _)| *agent_name == agent.name)
        .map(|(_, skill_name)| *skill_name)
        .collect();

    for skill_name in relevant_skills {
        match load_skill(skill_name) {
            Ok(skill) if !skill.content.is_empty() => {
                agent.system_prompt.push_str(&format!(
                    "\n\n--- Reference: {} ---\n{}",
                    skill.name, skill.content
                ));
            }
            _ => {
                // Skill not found or empty — not an error, just skip.
                tracing::debug!("Skill '{}' not available for injection", skill_name);
            }
        }
    }
}

fn inject_role_context(agent: &mut super::definition::AgentDefinition) {
    let Some(role) = &agent.role else {
        return;
    };

    let mut role_card = String::from("\n\n--- Role Card ---");
    if !role.title.is_empty() {
        role_card.push_str(&format!("\nTitle: {}", role.title));
    }
    append_prompt_list(&mut role_card, "Expertise", &role.expertise);
    append_prompt_list(&mut role_card, "Focus", &role.focus);
    append_prompt_list(&mut role_card, "Skepticism checklist", &role.skepticism);
    append_prompt_list(
        &mut role_card,
        "Preferred evidence",
        &role.evidence_preferences,
    );
    agent.system_prompt.push_str(&role_card);
}

fn append_prompt_list(rendered: &mut String, label: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }

    rendered.push_str(&format!("\n{}:", label));
    for value in values {
        rendered.push_str(&format!("\n- {}", value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_vuln_hunter_python() {
        let agent = select_vuln_hunter("app.py");
        // Will be "vuln-hunter-python" if agent file exists, "vuln-hunter" otherwise.
        assert!(
            agent == "vuln-hunter-python" || agent == "vuln-hunter",
            "Expected vuln-hunter-python or vuln-hunter, got: {}",
            agent
        );
    }

    #[test]
    fn test_select_vuln_hunter_java() {
        let agent = select_vuln_hunter("Main.java");
        assert!(
            agent == "vuln-hunter-java" || agent == "vuln-hunter",
            "Expected vuln-hunter-java or vuln-hunter, got: {}",
            agent
        );
    }

    #[test]
    fn test_select_vuln_hunter_c_falls_back() {
        let agent = select_vuln_hunter("buffer_overflow.c");
        assert_eq!(agent, "vuln-hunter");
    }

    #[test]
    fn test_select_vuln_hunter_no_extension() {
        let agent = select_vuln_hunter("binary_with_no_ext");
        assert_eq!(agent, "vuln-hunter");
    }

    #[test]
    fn test_build_debate_summary_structure() {
        let result_a = AgentResult {
            agent_name: "exploit-analyst".into(),
            output: "Finding 1: **CONFIRMED [high]**: Buffer overflow is exploitable.\n\
                     Finding 2: **REJECTED**: Dead code, never called."
                .into(),
            tokens_used: 100,
            context_frame: AgentContextFrame::synthetic(
                "exploit-analyst",
                "Validates exploitability of vulnerability findings",
                None,
                "Finding 1: **CONFIRMED [high]**: Buffer overflow is exploitable.\n\
                 Finding 2: **REJECTED**: Dead code, never called.",
            ),
            parsed_output: None,
            parsed_output_error: None,
        };
        let result_b = AgentResult {
            agent_name: "defense-analyst".into(),
            output: "Finding 1: **VULNERABLE**: No bounds checking found.\n\
                     Finding 2: **SAFE**: Function is never reachable."
                .into(),
            tokens_used: 100,
            context_frame: AgentContextFrame::synthetic(
                "defense-analyst",
                "Identifies mitigations and defensive controls",
                None,
                "Finding 1: **VULNERABLE**: No bounds checking found.\n\
                 Finding 2: **SAFE**: Function is never reachable.",
            ),
            parsed_output: None,
            parsed_output_error: None,
        };

        let summary = build_debate_summary(&result_a, &result_b);
        assert!(summary.contains("DEBATE SUMMARY"));
        assert!(summary.contains("exploit-analyst"));
        assert!(summary.contains("defense-analyst"));
        assert!(summary.contains("Offense analyst verdicts"));
        assert!(summary.contains("Defense analyst verdicts"));
    }

    #[test]
    fn test_build_debate_summary_disagreement() {
        let result_a = AgentResult {
            agent_name: "exploit-analyst".into(),
            output: "**CONFIRMED [critical]**: RCE via command injection".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "exploit-analyst",
                "Validates exploitability of vulnerability findings",
                None,
                "**CONFIRMED [critical]**: RCE via command injection",
            ),
            parsed_output: None,
            parsed_output_error: None,
        };
        let result_b = AgentResult {
            agent_name: "defense-analyst".into(),
            output: "**SAFE**: Input is validated by allowlist".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "defense-analyst",
                "Identifies mitigations and defensive controls",
                None,
                "**SAFE**: Input is validated by allowlist",
            ),
            parsed_output: None,
            parsed_output_error: None,
        };

        let summary = build_debate_summary(&result_a, &result_b);
        assert!(
            summary.contains("DISAGREEMENTS DETECTED"),
            "Should flag disagreement when offense confirms but defense says safe"
        );
    }

    #[test]
    fn test_build_debate_summary_does_not_treat_unsafe_as_safe() {
        let result_a = AgentResult {
            agent_name: "exploit-analyst".into(),
            output: "**CONFIRMED [high]**: strcpy call is exploitable".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "exploit-analyst",
                "Validates exploitability of vulnerability findings",
                None,
                "**CONFIRMED [high]**: strcpy call is exploitable",
            ),
            parsed_output: None,
            parsed_output_error: None,
        };
        let result_b = AgentResult {
            agent_name: "defense-analyst".into(),
            output: "This code is UNSAFE because strcpy lacks bounds checks".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "defense-analyst",
                "Identifies mitigations and defensive controls",
                None,
                "This code is UNSAFE because strcpy lacks bounds checks",
            ),
            parsed_output: None,
            parsed_output_error: None,
        };

        let summary = build_debate_summary(&result_a, &result_b);
        assert!(!summary.contains("DISAGREEMENTS DETECTED"));
        assert!(summary.contains("Defense: 0 positive, 0 safe"));
    }

    #[test]
    fn test_build_debate_summary_prefers_weighted_structured_outputs() {
        let result_a = AgentResult {
            agent_name: "exploit-analyst".into(),
            output: "free-form exploit review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "exploit-analyst",
                "Validates exploitability of vulnerability findings",
                None,
                "free-form exploit review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::ExploitAnalystV1(
                    super::super::output_schema::ExploitAnalystStructuredOutput {
                        summary: "Exploit confidence favors one finding".into(),
                        assessments: vec![super::super::output_schema::ExploitAnalystAssessment {
                            finding_title: "Buffer overflow in parse_header".into(),
                            verdict: super::super::output_schema::ExploitAnalystVerdict::Confirmed,
                            confidence_percent: 88,
                            evidence: vec!["Attacker controls packet length".into()],
                        }],
                    },
                ),
            ),
            parsed_output_error: None,
        };
        let result_b = AgentResult {
            agent_name: "defense-analyst".into(),
            output: "free-form defense review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "defense-analyst",
                "Identifies mitigations and defensive controls",
                None,
                "free-form defense review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::DefenseAnalystV1(
                    super::super::output_schema::DefenseAnalystStructuredOutput {
                        summary: "Mitigation confidence is weaker".into(),
                        assessments: vec![super::super::output_schema::DefenseAnalystAssessment {
                            finding_title: "Buffer overflow in parse_header".into(),
                            verdict: super::super::output_schema::DefenseAnalystVerdict::Safe,
                            confidence_percent: 35,
                            evidence: vec!["Caller normally caps input".into()],
                        }],
                    },
                ),
            ),
            parsed_output_error: None,
        };

        let summary = build_debate_summary(&result_a, &result_b);
        assert!(summary.contains("WEIGHTED DEBATE SUMMARY"));
        assert!(summary.contains("net_weight=53"));
        assert!(summary.contains("weighted_disagreements: 1"));
        assert!(summary.contains("threshold_hint: REVIEW_REQUIRED (disagreement)"));
        assert!(summary.contains("offense_evidence: Attacker controls packet length"));
        assert!(summary.contains("defense_evidence: Caller normally caps input"));
    }

    #[test]
    fn test_build_debate_summary_flags_downgraded_vs_safe_disagreement() {
        let result_a = AgentResult {
            agent_name: "exploit-analyst".into(),
            output: "free-form exploit review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "exploit-analyst",
                "Validates exploitability of vulnerability findings",
                None,
                "free-form exploit review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::ExploitAnalystV1(
                    super::super::output_schema::ExploitAnalystStructuredOutput {
                        summary: "Exploit review".into(),
                        assessments: vec![super::super::output_schema::ExploitAnalystAssessment {
                            finding_title: "Buffer overflow in parse_header".into(),
                            verdict: super::super::output_schema::ExploitAnalystVerdict::Downgraded,
                            confidence_percent: 60,
                            evidence: vec!["Attacker controls packet length".into()],
                        }],
                    },
                ),
            ),
            parsed_output_error: None,
        };
        let result_b = AgentResult {
            agent_name: "defense-analyst".into(),
            output: "free-form defense review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "defense-analyst",
                "Identifies mitigations and defensive controls",
                None,
                "free-form defense review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::DefenseAnalystV1(
                    super::super::output_schema::DefenseAnalystStructuredOutput {
                        summary: "Defense review".into(),
                        assessments: vec![super::super::output_schema::DefenseAnalystAssessment {
                            finding_title: "Buffer overflow in parse_header".into(),
                            verdict: super::super::output_schema::DefenseAnalystVerdict::Safe,
                            confidence_percent: 90,
                            evidence: vec!["Runtime guard makes path unreachable".into()],
                        }],
                    },
                ),
            ),
            parsed_output_error: None,
        };

        let summary = build_debate_summary(&result_a, &result_b);
        assert!(summary.contains("WEIGHTED DISAGREEMENTS DETECTED"));
        assert!(summary.contains("net_weight=-30"));
        assert!(summary.contains("threshold_hint: REVIEW_REQUIRED (disagreement)"));
    }

    #[test]
    fn test_build_debate_summary_marks_high_confidence_confirm_for_vulnerable_consensus() {
        let result_a = AgentResult {
            agent_name: "exploit-analyst".into(),
            output: "free-form exploit review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "exploit-analyst",
                "Validates exploitability of vulnerability findings",
                None,
                "free-form exploit review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::ExploitAnalystV1(
                    super::super::output_schema::ExploitAnalystStructuredOutput {
                        summary: "Exploit review".into(),
                        assessments: vec![super::super::output_schema::ExploitAnalystAssessment {
                            finding_title: "Heap overflow in parse_header".into(),
                            verdict: super::super::output_schema::ExploitAnalystVerdict::Confirmed,
                            confidence_percent: 90,
                            evidence: vec!["Attacker fully controls copy length".into()],
                        }],
                    },
                ),
            ),
            parsed_output_error: None,
        };
        let result_b = AgentResult {
            agent_name: "defense-analyst".into(),
            output: "free-form defense review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "defense-analyst",
                "Identifies mitigations and defensive controls",
                None,
                "free-form defense review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::DefenseAnalystV1(
                    super::super::output_schema::DefenseAnalystStructuredOutput {
                        summary: "Defense review".into(),
                        assessments: vec![super::super::output_schema::DefenseAnalystAssessment {
                            finding_title: "Heap overflow in parse_header".into(),
                            verdict: super::super::output_schema::DefenseAnalystVerdict::Vulnerable,
                            confidence_percent: 70,
                            evidence: vec!["No bounds check before memcpy".into()],
                        }],
                    },
                ),
            ),
            parsed_output_error: None,
        };

        let summary = build_debate_summary(&result_a, &result_b);
        assert!(summary.contains("net_weight=160"));
        assert!(summary.contains("threshold_hint: HIGH_CONFIDENCE_CONFIRM (strong_consensus)"));
        assert!(summary.contains("high_confidence_confirm: 1"));
    }

    #[test]
    fn test_build_debate_summary_marks_high_confidence_reject() {
        let result_a = AgentResult {
            agent_name: "exploit-analyst".into(),
            output: "free-form exploit review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "exploit-analyst",
                "Validates exploitability of vulnerability findings",
                None,
                "free-form exploit review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::ExploitAnalystV1(
                    super::super::output_schema::ExploitAnalystStructuredOutput {
                        summary: "Exploit review".into(),
                        assessments: vec![super::super::output_schema::ExploitAnalystAssessment {
                            finding_title: "Stack overflow in parse_header".into(),
                            verdict: super::super::output_schema::ExploitAnalystVerdict::Rejected,
                            confidence_percent: 85,
                            evidence: vec!["Length is clamped before copy".into()],
                        }],
                    },
                ),
            ),
            parsed_output_error: None,
        };
        let result_b = AgentResult {
            agent_name: "defense-analyst".into(),
            output: "free-form defense review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "defense-analyst",
                "Identifies mitigations and defensive controls",
                None,
                "free-form defense review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::DefenseAnalystV1(
                    super::super::output_schema::DefenseAnalystStructuredOutput {
                        summary: "Defense review".into(),
                        assessments: vec![super::super::output_schema::DefenseAnalystAssessment {
                            finding_title: "Stack overflow in parse_header".into(),
                            verdict: super::super::output_schema::DefenseAnalystVerdict::Safe,
                            confidence_percent: 90,
                            evidence: vec!["Bounds guard rejects oversized packets".into()],
                        }],
                    },
                ),
            ),
            parsed_output_error: None,
        };

        let summary = build_debate_summary(&result_a, &result_b);
        assert!(summary.contains("net_weight=-175"));
        assert!(summary.contains("threshold_hint: HIGH_CONFIDENCE_REJECT (strong_negative_signal)"));
        assert!(summary.contains("high_confidence_reject: 1"));
    }

    #[test]
    fn test_build_debate_summary_marks_high_confidence_confirm_for_mitigated_consensus() {
        let result_a = AgentResult {
            agent_name: "exploit-analyst".into(),
            output: "free-form exploit review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "exploit-analyst",
                "Validates exploitability of vulnerability findings",
                None,
                "free-form exploit review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::ExploitAnalystV1(
                    super::super::output_schema::ExploitAnalystStructuredOutput {
                        summary: "Exploit review".into(),
                        assessments: vec![super::super::output_schema::ExploitAnalystAssessment {
                            finding_title: "Heap overflow in parse_header".into(),
                            verdict: super::super::output_schema::ExploitAnalystVerdict::Confirmed,
                            confidence_percent: 95,
                            evidence: vec!["Attacker fully controls copy length".into()],
                        }],
                    },
                ),
            ),
            parsed_output_error: None,
        };
        let result_b = AgentResult {
            agent_name: "defense-analyst".into(),
            output: "free-form defense review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "defense-analyst",
                "Identifies mitigations and defensive controls",
                None,
                "free-form defense review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::DefenseAnalystV1(
                    super::super::output_schema::DefenseAnalystStructuredOutput {
                        summary: "Defense review".into(),
                        assessments: vec![super::super::output_schema::DefenseAnalystAssessment {
                            finding_title: "Heap overflow in parse_header".into(),
                            verdict: super::super::output_schema::DefenseAnalystVerdict::Mitigated,
                            confidence_percent: 90,
                            evidence: vec!["Exploit path is partially constrained".into()],
                        }],
                    },
                ),
            ),
            parsed_output_error: None,
        };

        let summary = build_debate_summary(&result_a, &result_b);
        assert!(summary.contains("defense=MITIGATED @ 90%"));
        assert!(summary.contains("net_weight=185"));
        assert!(summary.contains("threshold_hint: HIGH_CONFIDENCE_CONFIRM (strong_consensus)"));
        assert!(summary.contains("high_confidence_confirm: 1"));
    }

    #[test]
    fn test_build_debate_summary_requires_review_for_offense_only_signal() {
        let result_a = AgentResult {
            agent_name: "exploit-analyst".into(),
            output: "free-form exploit review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "exploit-analyst",
                "Validates exploitability of vulnerability findings",
                None,
                "free-form exploit review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::ExploitAnalystV1(
                    super::super::output_schema::ExploitAnalystStructuredOutput {
                        summary: "Exploit review".into(),
                        assessments: vec![super::super::output_schema::ExploitAnalystAssessment {
                            finding_title: "Heap overflow in parse_header".into(),
                            verdict: super::super::output_schema::ExploitAnalystVerdict::Confirmed,
                            confidence_percent: 95,
                            evidence: vec!["Attacker fully controls copy length".into()],
                        }],
                    },
                ),
            ),
            parsed_output_error: None,
        };
        let result_b = AgentResult {
            agent_name: "defense-analyst".into(),
            output: "free-form defense review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "defense-analyst",
                "Identifies mitigations and defensive controls",
                None,
                "free-form defense review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::DefenseAnalystV1(
                    super::super::output_schema::DefenseAnalystStructuredOutput {
                        summary: "Defense review".into(),
                        assessments: vec![],
                    },
                ),
            ),
            parsed_output_error: None,
        };

        let summary = build_debate_summary(&result_a, &result_b);
        assert!(summary.contains("threshold_hint: REVIEW_REQUIRED (missing_counterparty_signal)"));
    }

    #[test]
    fn test_build_debate_summary_requires_review_for_defense_only_signal() {
        let result_a = AgentResult {
            agent_name: "exploit-analyst".into(),
            output: "free-form exploit review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "exploit-analyst",
                "Validates exploitability of vulnerability findings",
                None,
                "free-form exploit review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::ExploitAnalystV1(
                    super::super::output_schema::ExploitAnalystStructuredOutput {
                        summary: "Exploit review".into(),
                        assessments: vec![],
                    },
                ),
            ),
            parsed_output_error: None,
        };
        let result_b = AgentResult {
            agent_name: "defense-analyst".into(),
            output: "free-form defense review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "defense-analyst",
                "Identifies mitigations and defensive controls",
                None,
                "free-form defense review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::DefenseAnalystV1(
                    super::super::output_schema::DefenseAnalystStructuredOutput {
                        summary: "Defense review".into(),
                        assessments: vec![super::super::output_schema::DefenseAnalystAssessment {
                            finding_title: "Heap overflow in parse_header".into(),
                            verdict: super::super::output_schema::DefenseAnalystVerdict::Safe,
                            confidence_percent: 90,
                            evidence: vec!["Bounds guard rejects oversized packets".into()],
                        }],
                    },
                ),
            ),
            parsed_output_error: None,
        };

        let summary = build_debate_summary(&result_a, &result_b);
        assert!(summary.contains("threshold_hint: REVIEW_REQUIRED (missing_counterparty_signal)"));
    }

    #[test]
    fn test_build_debate_summary_requires_review_for_weak_consensus() {
        let result_a = AgentResult {
            agent_name: "exploit-analyst".into(),
            output: "free-form exploit review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "exploit-analyst",
                "Validates exploitability of vulnerability findings",
                None,
                "free-form exploit review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::ExploitAnalystV1(
                    super::super::output_schema::ExploitAnalystStructuredOutput {
                        summary: "Exploit review".into(),
                        assessments: vec![super::super::output_schema::ExploitAnalystAssessment {
                            finding_title: "Heap overflow in parse_header".into(),
                            verdict: super::super::output_schema::ExploitAnalystVerdict::Confirmed,
                            confidence_percent: 50,
                            evidence: vec!["Attacker influences copy length".into()],
                        }],
                    },
                ),
            ),
            parsed_output_error: None,
        };
        let result_b = AgentResult {
            agent_name: "defense-analyst".into(),
            output: "free-form defense review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "defense-analyst",
                "Identifies mitigations and defensive controls",
                None,
                "free-form defense review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::DefenseAnalystV1(
                    super::super::output_schema::DefenseAnalystStructuredOutput {
                        summary: "Defense review".into(),
                        assessments: vec![super::super::output_schema::DefenseAnalystAssessment {
                            finding_title: "Heap overflow in parse_header".into(),
                            verdict: super::super::output_schema::DefenseAnalystVerdict::Vulnerable,
                            confidence_percent: 30,
                            evidence: vec!["No complete sanitizer found".into()],
                        }],
                    },
                ),
            ),
            parsed_output_error: None,
        };

        let summary = build_debate_summary(&result_a, &result_b);
        assert!(summary.contains("net_weight=80"));
        assert!(summary.contains("threshold_hint: REVIEW_REQUIRED (insufficient_consensus)"));
    }

    #[test]
    fn test_build_debate_summary_requires_strong_offense_signal_for_auto_confirm() {
        let result_a = AgentResult {
            agent_name: "exploit-analyst".into(),
            output: "free-form exploit review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "exploit-analyst",
                "Validates exploitability of vulnerability findings",
                None,
                "free-form exploit review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::ExploitAnalystV1(
                    super::super::output_schema::ExploitAnalystStructuredOutput {
                        summary: "Exploit review".into(),
                        assessments: vec![super::super::output_schema::ExploitAnalystAssessment {
                            finding_title: "Heap overflow in parse_header".into(),
                            verdict: super::super::output_schema::ExploitAnalystVerdict::Confirmed,
                            confidence_percent: 70,
                            evidence: vec!["Attacker controls copy length".into()],
                        }],
                    },
                ),
            ),
            parsed_output_error: None,
        };
        let result_b = AgentResult {
            agent_name: "defense-analyst".into(),
            output: "free-form defense review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "defense-analyst",
                "Identifies mitigations and defensive controls",
                None,
                "free-form defense review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::DefenseAnalystV1(
                    super::super::output_schema::DefenseAnalystStructuredOutput {
                        summary: "Defense review".into(),
                        assessments: vec![super::super::output_schema::DefenseAnalystAssessment {
                            finding_title: "Heap overflow in parse_header".into(),
                            verdict: super::super::output_schema::DefenseAnalystVerdict::Vulnerable,
                            confidence_percent: 70,
                            evidence: vec!["No complete bounds check found".into()],
                        }],
                    },
                ),
            ),
            parsed_output_error: None,
        };

        let summary = build_debate_summary(&result_a, &result_b);
        assert!(summary.contains("net_weight=140"));
        assert!(summary.contains("threshold_hint: REVIEW_REQUIRED (insufficient_consensus)"));
    }

    #[test]
    fn test_build_debate_summary_does_not_inflate_duplicate_title_scores() {
        let result_a = AgentResult {
            agent_name: "exploit-analyst".into(),
            output: "free-form exploit review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "exploit-analyst",
                "Validates exploitability of vulnerability findings",
                None,
                "free-form exploit review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::ExploitAnalystV1(
                    super::super::output_schema::ExploitAnalystStructuredOutput {
                        summary: "Exploit review".into(),
                        assessments: vec![super::super::output_schema::ExploitAnalystAssessment {
                            finding_title: "Heap overflow in parse_header".into(),
                            verdict: super::super::output_schema::ExploitAnalystVerdict::Confirmed,
                            confidence_percent: 85,
                            evidence: vec!["Attacker controls copy length".into()],
                        }],
                    },
                ),
            ),
            parsed_output_error: None,
        };
        let result_b = AgentResult {
            agent_name: "defense-analyst".into(),
            output: "free-form defense review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "defense-analyst",
                "Identifies mitigations and defensive controls",
                None,
                "free-form defense review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::DefenseAnalystV1(
                    super::super::output_schema::DefenseAnalystStructuredOutput {
                        summary: "Defense review".into(),
                        assessments: vec![
                            super::super::output_schema::DefenseAnalystAssessment {
                                finding_title: "Heap overflow in parse_header".into(),
                                verdict:
                                    super::super::output_schema::DefenseAnalystVerdict::Vulnerable,
                                confidence_percent: 30,
                                evidence: vec!["No complete bounds check found".into()],
                            },
                            super::super::output_schema::DefenseAnalystAssessment {
                                finding_title: "heap overflow in parse-header".into(),
                                verdict:
                                    super::super::output_schema::DefenseAnalystVerdict::Vulnerable,
                                confidence_percent: 30,
                                evidence: vec!["Repeated summary of the same issue".into()],
                            },
                        ],
                    },
                ),
            ),
            parsed_output_error: None,
        };

        let summary = build_debate_summary(&result_a, &result_b);
        assert!(summary.contains("net_weight=115"));
        assert!(summary.contains("threshold_hint: REVIEW_REQUIRED (insufficient_consensus)"));
    }

    #[test]
    fn test_build_debate_summary_reviews_conflicting_duplicate_titles_regardless_of_order() {
        for exploit_assessments in [
            vec![
                super::super::output_schema::ExploitAnalystAssessment {
                    finding_title: "Heap overflow in parse_header".into(),
                    verdict: super::super::output_schema::ExploitAnalystVerdict::Confirmed,
                    confidence_percent: 90,
                    evidence: vec!["Attacker controls copy length".into()],
                },
                super::super::output_schema::ExploitAnalystAssessment {
                    finding_title: "heap overflow in parse-header".into(),
                    verdict: super::super::output_schema::ExploitAnalystVerdict::Rejected,
                    confidence_percent: 90,
                    evidence: vec!["Alternate path blocks the sink".into()],
                },
            ],
            vec![
                super::super::output_schema::ExploitAnalystAssessment {
                    finding_title: "heap overflow in parse-header".into(),
                    verdict: super::super::output_schema::ExploitAnalystVerdict::Rejected,
                    confidence_percent: 90,
                    evidence: vec!["Alternate path blocks the sink".into()],
                },
                super::super::output_schema::ExploitAnalystAssessment {
                    finding_title: "Heap overflow in parse_header".into(),
                    verdict: super::super::output_schema::ExploitAnalystVerdict::Confirmed,
                    confidence_percent: 90,
                    evidence: vec!["Attacker controls copy length".into()],
                },
            ],
        ] {
            let result_a = AgentResult {
                agent_name: "exploit-analyst".into(),
                output: "free-form exploit review".into(),
                tokens_used: 50,
                context_frame: AgentContextFrame::synthetic(
                    "exploit-analyst",
                    "Validates exploitability of vulnerability findings",
                    None,
                    "free-form exploit review",
                ),
                parsed_output: Some(
                    super::super::output_schema::ParsedAgentOutput::ExploitAnalystV1(
                        super::super::output_schema::ExploitAnalystStructuredOutput {
                            summary: "Exploit review".into(),
                            assessments: exploit_assessments,
                        },
                    ),
                ),
                parsed_output_error: None,
            };
            let result_b = AgentResult {
                agent_name: "defense-analyst".into(),
                output: "free-form defense review".into(),
                tokens_used: 50,
                context_frame: AgentContextFrame::synthetic(
                    "defense-analyst",
                    "Identifies mitigations and defensive controls",
                    None,
                    "free-form defense review",
                ),
                parsed_output: Some(
                    super::super::output_schema::ParsedAgentOutput::DefenseAnalystV1(
                        super::super::output_schema::DefenseAnalystStructuredOutput {
                            summary: "Defense review".into(),
                            assessments:
                                vec![super::super::output_schema::DefenseAnalystAssessment {
                                finding_title: "Heap overflow in parse_header".into(),
                                verdict:
                                    super::super::output_schema::DefenseAnalystVerdict::Vulnerable,
                                confidence_percent: 70,
                                evidence: vec!["No complete bounds check found".into()],
                            }],
                        },
                    ),
                ),
                parsed_output_error: None,
            };

            let summary = build_debate_summary(&result_a, &result_b);
            assert!(summary.contains("net_weight=70"));
            assert!(summary.contains("threshold_hint: REVIEW_REQUIRED (disagreement)"));
        }
    }

    #[test]
    fn test_build_debate_summary_normalizes_titles_and_reports_missing_branches() {
        let result_a = AgentResult {
            agent_name: "exploit-analyst".into(),
            output: "free-form exploit review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "exploit-analyst",
                "Validates exploitability of vulnerability findings",
                None,
                "free-form exploit review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::ExploitAnalystV1(
                    super::super::output_schema::ExploitAnalystStructuredOutput {
                        summary: "Exploit review".into(),
                        assessments: vec![
                            super::super::output_schema::ExploitAnalystAssessment {
                                finding_title: "Buffer Overflow in parse_header".into(),
                                verdict:
                                    super::super::output_schema::ExploitAnalystVerdict::Confirmed,
                                confidence_percent: 80,
                                evidence: vec!["Attacker controls packet length".into()],
                            },
                            super::super::output_schema::ExploitAnalystAssessment {
                                finding_title: "Use-after-free in cleanup".into(),
                                verdict:
                                    super::super::output_schema::ExploitAnalystVerdict::Rejected,
                                confidence_percent: 40,
                                evidence: vec!["Refcount is released before use".into()],
                            },
                        ],
                    },
                ),
            ),
            parsed_output_error: None,
        };
        let result_b = AgentResult {
            agent_name: "defense-analyst".into(),
            output: "free-form defense review".into(),
            tokens_used: 50,
            context_frame: AgentContextFrame::synthetic(
                "defense-analyst",
                "Identifies mitigations and defensive controls",
                None,
                "free-form defense review",
            ),
            parsed_output: Some(
                super::super::output_schema::ParsedAgentOutput::DefenseAnalystV1(
                    super::super::output_schema::DefenseAnalystStructuredOutput {
                        summary: "Defense review".into(),
                        assessments: vec![
                            super::super::output_schema::DefenseAnalystAssessment {
                                finding_title: "buffer overflow in parse-header".into(),
                                verdict: super::super::output_schema::DefenseAnalystVerdict::Safe,
                                confidence_percent: 35,
                                evidence: vec!["Caller normally caps input".into()],
                            },
                            super::super::output_schema::DefenseAnalystAssessment {
                                finding_title: "Integer overflow in length parse".into(),
                                verdict:
                                    super::super::output_schema::DefenseAnalystVerdict::Vulnerable,
                                confidence_percent: 72,
                                evidence: vec!["Length arithmetic is unchecked".into()],
                            },
                        ],
                    },
                ),
            ),
            parsed_output_error: None,
        };

        let summary = build_debate_summary(&result_a, &result_b);
        assert!(summary.contains("Buffer Overflow in parse_header"));
        assert!(summary.contains("net_weight=45"));
        assert!(
            summary.contains("Use-after-free in cleanup: offense=REJECTED @ 40%, defense=missing")
        );
        assert!(summary.contains(
            "Integer overflow in length parse: offense=missing, defense=VULNERABLE @ 72%"
        ));
    }

    #[test]
    fn test_build_previous_results_context_truncation() {
        let results = vec![AgentResult {
            agent_name: "test".into(),
            output: "x".repeat(MAX_PIPELINE_CONTEXT_CHARS + 1000),
            tokens_used: 0,
            context_frame: AgentContextFrame::synthetic("test", "Test agent", None, "x"),
            parsed_output: None,
            parsed_output_error: None,
        }];
        let ctx = build_previous_results_context(
            &"p".repeat(MAX_PIPELINE_CONTEXT_CHARS + 1000),
            &results,
        );
        assert!(ctx.len() <= MAX_PIPELINE_CONTEXT_CHARS + 20); // +20 for truncation marker
        assert!(ctx.contains("[truncated]"));
    }

    #[test]
    fn test_build_previous_results_context_includes_structured_frame() {
        let results = vec![AgentResult {
            agent_name: "exploit-analyst".into(),
            output: "**CONFIRMED [high]**: Concrete attack path".into(),
            tokens_used: 0,
            context_frame: AgentContextFrame::synthetic(
                "exploit-analyst",
                "Validates exploitability of vulnerability findings",
                Some(super::super::definition::AgentRoleMetadata {
                    title: "Exploitability specialist".into(),
                    expertise: vec!["reachability".into()],
                    focus: vec!["attacker control".into()],
                    skepticism: vec!["reject theoretical findings".into()],
                    evidence_preferences: vec!["concrete trigger paths".into()],
                }),
                "**CONFIRMED [high]**: Concrete attack path",
            ),
            parsed_output: None,
            parsed_output_error: None,
        }];

        let ctx = build_previous_results_context("preamble", &results);
        assert!(ctx.contains("Context frame from exploit-analyst"));
        assert!(ctx.contains("role_title: Exploitability specialist"));
        assert!(ctx.contains("key_points:"));
        assert!(ctx.contains("Concrete attack path"));
        assert!(ctx.contains("Condensed output from exploit-analyst"));
    }

    #[test]
    fn test_build_previous_results_context_prefers_structured_summary_over_raw_excerpt() {
        let mut frame =
            AgentContextFrame::synthetic("vuln-hunter", "Primary discovery agent", None, "raw");
        frame.output_schema = Some("vuln-hunter-v1".into());
        frame.structured_summary = Some("summary: one parsed finding".into());
        frame.key_points = vec!["summary: one parsed finding".into()];

        let results = vec![AgentResult {
            agent_name: "vuln-hunter".into(),
            output: "raw output with duplicated details".into(),
            tokens_used: 0,
            context_frame: frame,
            parsed_output: None,
            parsed_output_error: None,
        }];

        let ctx = build_previous_results_context("preamble", &results);
        assert!(ctx.contains("structured_summary:"));
        assert!(!ctx.contains("Condensed output from vuln-hunter"));
    }

    #[test]
    fn test_build_previous_results_context_preserves_newest_debate_summary_when_truncated() {
        let mut results = Vec::new();
        for idx in 0..20 {
            let repeated = "x".repeat(700);
            results.push(AgentResult {
                agent_name: format!("older-agent-{idx}"),
                output: repeated.clone(),
                tokens_used: 0,
                context_frame: AgentContextFrame::synthetic(
                    format!("older-agent-{idx}"),
                    "Older context",
                    None,
                    &repeated,
                ),
                parsed_output: None,
                parsed_output_error: None,
            });
        }

        let mut debate_frame = AgentContextFrame::synthetic(
            "debate-summary",
            "Pipeline-generated summary of offense/defense agreements and disagreements",
            None,
            "raw debate summary",
        );
        debate_frame.structured_summary = Some(
            "Weighted debate threshold summary:\n- Final finding: offense=CONFIRMED @ 95%, defense=VULNERABLE @ 90%, net_weight=185\n  threshold_hint: HIGH_CONFIDENCE_CONFIRM (strong_consensus)"
                .into(),
        );
        debate_frame.key_points =
            vec!["threshold_hint: HIGH_CONFIDENCE_CONFIRM (strong_consensus)".into()];
        results.push(AgentResult {
            agent_name: "debate-summary".into(),
            output: "raw debate summary".into(),
            tokens_used: 0,
            context_frame: debate_frame,
            parsed_output: None,
            parsed_output_error: None,
        });

        let ctx = build_previous_results_context("preamble", &results);
        assert!(ctx.contains("[truncated older context to preserve newest debate evidence]"));
        assert!(ctx.contains("Context frame from debate-summary"));
        assert!(ctx.contains("threshold_hint: HIGH_CONFIDENCE_CONFIRM (strong_consensus)"));
        assert!(!ctx.contains("older-agent-0"));
    }

    #[test]
    fn test_build_previous_results_context_keeps_exact_fit_without_omission_notice() {
        let preamble = "p".repeat(100);
        let mut frame_a =
            AgentContextFrame::synthetic("older-a", "Older context", None, "raw output");
        frame_a.structured_summary = Some(String::new());
        let mut frame_b =
            AgentContextFrame::synthetic("older-b", "Older context", None, "raw output");
        frame_b.structured_summary = Some(String::new());

        let mut result_a = AgentResult {
            agent_name: "older-a".into(),
            output: "raw output".into(),
            tokens_used: 0,
            context_frame: frame_a,
            parsed_output: None,
            parsed_output_error: None,
        };
        let mut result_b = AgentResult {
            agent_name: "older-b".into(),
            output: "raw output".into(),
            tokens_used: 0,
            context_frame: frame_b,
            parsed_output: None,
            parsed_output_error: None,
        };

        let base_len_a = render_previous_result_context(&result_a).len();
        let base_len_b = render_previous_result_context(&result_b).len();
        let remaining = MAX_PIPELINE_CONTEXT_CHARS
            .saturating_sub(preamble.len())
            .saturating_sub(base_len_a)
            .saturating_sub(base_len_b);
        let extra_a = remaining / 2;
        let extra_b = remaining - extra_a;
        result_a.context_frame.structured_summary = Some("a".repeat(extra_a));
        result_b.context_frame.structured_summary = Some("b".repeat(extra_b));

        let ctx = build_previous_results_context(&preamble, &[result_a, result_b]);
        assert!(ctx.len() <= MAX_PIPELINE_CONTEXT_CHARS);
        assert!(ctx.contains("Context frame from older-a"));
        assert!(ctx.contains("Context frame from older-b"));
        assert!(!ctx.contains("[truncated older context to preserve newest debate evidence]"));
    }

    #[test]
    fn test_build_previous_results_context_keeps_truncated_newest_section_when_oversized() {
        let older = AgentResult {
            agent_name: "older".into(),
            output: "older output".into(),
            tokens_used: 0,
            context_frame: AgentContextFrame::synthetic("older", "Older context", None, "older"),
            parsed_output: None,
            parsed_output_error: None,
        };

        let mut debate_frame = AgentContextFrame::synthetic(
            "debate-summary",
            "Pipeline-generated summary of offense/defense agreements and disagreements",
            None,
            "raw debate summary",
        );
        debate_frame.structured_summary = Some(
            "Weighted debate threshold summary:\n".to_string()
                + &"x".repeat(MAX_PIPELINE_CONTEXT_CHARS + 500),
        );
        let newest = AgentResult {
            agent_name: "debate-summary".into(),
            output: "raw debate summary".into(),
            tokens_used: 0,
            context_frame: debate_frame,
            parsed_output: None,
            parsed_output_error: None,
        };

        let ctx = build_previous_results_context("preamble", &[older, newest]);
        assert!(ctx.contains("Context frame from debate-summary"));
        assert!(ctx.contains("[truncated newest context]"));
    }

    #[test]
    fn test_build_debate_context_summary_preserves_threshold_hints() {
        let summary = "Weighted finding comparisons:\n- Finding A: offense=CONFIRMED @ 95%, defense=VULNERABLE @ 90%, net_weight=185\n    threshold_hint: HIGH_CONFIDENCE_CONFIRM (strong_consensus)\n    offense_evidence: attacker controls length\n- Finding B: offense=CONFIRMED @ 60%, defense=MITIGATED @ 55%, net_weight=115\n    threshold_hint: REVIEW_REQUIRED (insufficient_consensus)\n    defense_evidence: partial bounds check\n\nSummary statistics:\n- offense_assessments: 2\n- defense_assessments: 2\n- weighted_disagreements: 0\n- high_confidence_confirm: 1\n- high_confidence_reject: 0\n- review_required: 1\nCONFIDENCE THRESHOLD NOTE: Only auto-confirm findings labelled HIGH_CONFIDENCE_CONFIRM. For REVIEW_REQUIRED findings, verify with direct code evidence before confirming.\n";

        let compact = build_debate_context_summary(summary);
        assert!(compact.contains("Weighted debate threshold summary:"));
        assert!(compact.contains(
            "- Finding A: offense=CONFIRMED @ 95%, defense=VULNERABLE @ 90%, net_weight=185"
        ));
        assert!(compact.contains("threshold_hint: HIGH_CONFIDENCE_CONFIRM (strong_consensus)"));
        assert!(compact.contains("offense_evidence: attacker controls length"));
        assert!(compact.contains(
            "- Finding B: offense=CONFIRMED @ 60%, defense=MITIGATED @ 55%, net_weight=115"
        ));
        assert!(compact.contains("threshold_hint: REVIEW_REQUIRED (insufficient_consensus)"));
        assert!(compact.contains("defense_evidence: partial bounds check"));
        assert!(compact.contains("Summary statistics:"));
        assert!(compact.contains("- review_required: 1"));
        assert!(compact.contains("CONFIDENCE THRESHOLD NOTE:"));
    }

    #[test]
    fn test_build_debate_summary_marks_threshold_hints_unavailable_on_parse_failure() {
        let result_a = AgentResult {
            agent_name: "exploit-analyst".into(),
            output: "CONFIRMED finding from fallback text".into(),
            tokens_used: 0,
            context_frame: AgentContextFrame::synthetic(
                "exploit-analyst",
                "Validates exploitability of vulnerability findings",
                None,
                "CONFIRMED finding from fallback text",
            ),
            parsed_output: None,
            parsed_output_error: Some("failed to parse exploit-analyst-v1".into()),
        };
        let result_b = AgentResult {
            agent_name: "defense-analyst".into(),
            output: "SAFE finding from fallback text".into(),
            tokens_used: 0,
            context_frame: AgentContextFrame::synthetic(
                "defense-analyst",
                "Identifies mitigations and defensive controls",
                None,
                "SAFE finding from fallback text",
            ),
            parsed_output: None,
            parsed_output_error: Some("failed to parse defense-analyst-v1".into()),
        };

        let summary = build_debate_summary(&result_a, &result_b);
        assert!(summary.contains(
            "CONFIDENCE THRESHOLD NOTE: unavailable because structured debate parsing failed"
        ));
        assert!(summary.contains("exploit-analyst: failed to parse exploit-analyst-v1"));
        assert!(summary.contains("defense-analyst: failed to parse defense-analyst-v1"));
        assert!(summary.contains("Do not auto-confirm or auto-reject from thresholds"));
    }

    #[test]
    fn test_build_debate_summary_flags_rejected_vs_vulnerable_fallback_disagreement() {
        let result_a = AgentResult {
            agent_name: "exploit-analyst".into(),
            output: "REJECTED: attacker cannot reach sink".into(),
            tokens_used: 0,
            context_frame: AgentContextFrame::synthetic(
                "exploit-analyst",
                "Validates exploitability of vulnerability findings",
                None,
                "REJECTED: attacker cannot reach sink",
            ),
            parsed_output: None,
            parsed_output_error: Some("failed to parse exploit-analyst-v1".into()),
        };
        let result_b = AgentResult {
            agent_name: "defense-analyst".into(),
            output: "VULNERABLE: guard is incomplete".into(),
            tokens_used: 0,
            context_frame: AgentContextFrame::synthetic(
                "defense-analyst",
                "Identifies mitigations and defensive controls",
                None,
                "VULNERABLE: guard is incomplete",
            ),
            parsed_output: None,
            parsed_output_error: Some("failed to parse defense-analyst-v1".into()),
        };

        let summary = build_debate_summary(&result_a, &result_b);
        assert!(summary.contains(
            "Summary statistics:\n- Offense: 0 positive, 1 rejected\n- Defense: 1 positive, 0 safe"
        ));
        assert!(summary.contains("DISAGREEMENTS DETECTED"));
    }

    #[test]
    fn test_build_debate_context_summary_preserves_unavailable_note_on_fallback_summary() {
        let result_a = AgentResult {
            agent_name: "exploit-analyst".into(),
            output: "CONFIRMED finding from fallback text".into(),
            tokens_used: 0,
            context_frame: AgentContextFrame::synthetic(
                "exploit-analyst",
                "Validates exploitability of vulnerability findings",
                None,
                "CONFIRMED finding from fallback text",
            ),
            parsed_output: None,
            parsed_output_error: Some("failed to parse exploit-analyst-v1".into()),
        };
        let result_b = AgentResult {
            agent_name: "defense-analyst".into(),
            output: "SAFE finding from fallback text".into(),
            tokens_used: 0,
            context_frame: AgentContextFrame::synthetic(
                "defense-analyst",
                "Identifies mitigations and defensive controls",
                None,
                "SAFE finding from fallback text",
            ),
            parsed_output: None,
            parsed_output_error: Some("failed to parse defense-analyst-v1".into()),
        };

        let summary = build_debate_summary(&result_a, &result_b);
        let context_summary = build_debate_context_summary(&summary);
        assert!(context_summary.contains(
            "CONFIDENCE THRESHOLD NOTE: unavailable because structured debate parsing failed"
        ));
        assert!(context_summary.contains("Do not auto-confirm or auto-reject from thresholds"));
    }

    #[test]
    fn test_build_debate_context_summary_preserves_fallback_disagreement_warning() {
        let result_a = AgentResult {
            agent_name: "exploit-analyst".into(),
            output: "REJECTED: attacker cannot reach sink".into(),
            tokens_used: 0,
            context_frame: AgentContextFrame::synthetic(
                "exploit-analyst",
                "Validates exploitability of vulnerability findings",
                None,
                "REJECTED: attacker cannot reach sink",
            ),
            parsed_output: None,
            parsed_output_error: Some("failed to parse exploit-analyst-v1".into()),
        };
        let result_b = AgentResult {
            agent_name: "defense-analyst".into(),
            output: "VULNERABLE: guard is incomplete".into(),
            tokens_used: 0,
            context_frame: AgentContextFrame::synthetic(
                "defense-analyst",
                "Identifies mitigations and defensive controls",
                None,
                "VULNERABLE: guard is incomplete",
            ),
            parsed_output: None,
            parsed_output_error: Some("failed to parse defense-analyst-v1".into()),
        };

        let summary = build_debate_summary(&result_a, &result_b);
        let context_summary = build_debate_context_summary(&summary);
        let key_points = extract_debate_context_key_points(&context_summary);
        assert!(context_summary.contains("DISAGREEMENTS DETECTED:"));
        assert!(key_points
            .iter()
            .any(|point| point.contains("DISAGREEMENTS DETECTED:")));
    }

    #[test]
    fn format_context_frame_includes_structured_summary() {
        let mut frame =
            AgentContextFrame::synthetic("vuln-hunter", "Primary discovery agent", None, "raw");
        frame.output_schema = Some("vuln-hunter-v1".into());
        frame.structured_summary =
            Some("summary: Confirmed one issue\nfinding: [high] Overflow".into());

        let rendered = format_context_frame(&frame);
        assert!(rendered.contains("output_schema: vuln-hunter-v1"));
        assert!(rendered.contains("structured_summary:"));
        assert!(rendered.contains("Overflow"));
    }

    #[test]
    fn test_output_excerpt_truncates_long_multiline_output() {
        let output =
            "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\nline11\nline12\nline13";
        let excerpt = format_output_excerpt(output);
        assert!(excerpt.contains("line1"));
        assert!(excerpt.contains("line6"));
        assert!(excerpt.contains("line13"));
        assert!(excerpt.contains("[middle lines omitted]"));
        assert!(excerpt.contains("[truncated excerpt]"));
        assert!(!excerpt.contains("line7\nline8\nline9\nline10"));
    }

    #[test]
    fn test_inject_role_context_appends_role_card() {
        let mut agent = super::super::definition::AgentDefinition {
            name: "role-aware".into(),
            description: "Role-aware agent".into(),
            model: "claude-opus-4.6".into(),
            tools: vec![],
            max_turns: 5,
            role: Some(super::super::definition::AgentRoleMetadata {
                title: "Exploitability specialist".into(),
                expertise: vec!["reachability tracing".into()],
                focus: vec!["attacker control".into()],
                skepticism: vec!["reject dead code".into()],
                evidence_preferences: vec!["line-level citations".into()],
            }),
            output_schema: None,
            system_prompt: "Base prompt".into(),
            source_path: None,
        };

        inject_role_context(&mut agent);

        assert!(agent.system_prompt.contains("--- Role Card ---"));
        assert!(agent
            .system_prompt
            .contains("Title: Exploitability specialist"));
        assert!(agent.system_prompt.contains("Expertise:"));
        assert!(agent.system_prompt.contains("Preferred evidence:"));
    }

    #[test]
    fn test_deep_pipeline_has_verdict_synthesizer() {
        let pipeline = deep_pipeline();
        assert!(
            pipeline
                .stages
                .iter()
                .any(|s| s.agent_name == "verdict-synthesizer"),
            "Deep pipeline must include verdict-synthesizer"
        );
    }

    #[test]
    fn test_deep_pipeline_for_target_python() {
        let pipeline = deep_pipeline_for_target("app.py");
        let hunter_stage = pipeline
            .stages
            .iter()
            .find(|s| s.agent_name.starts_with("vuln-hunter"));
        assert!(
            hunter_stage.is_some(),
            "Pipeline must include a vuln-hunter variant"
        );
    }

    #[test]
    fn test_default_pipeline_for_target_python() {
        let pipeline = default_pipeline_for_target("app.py");
        let hunter_stage = pipeline
            .stages
            .iter()
            .find(|s| s.agent_name.starts_with("vuln-hunter"));
        assert!(
            hunter_stage.is_some(),
            "Default pipeline must include a vuln-hunter variant"
        );
    }

    #[test]
    fn test_memory_enabled_agents_expose_memory_tools() {
        let agents = [
            "decompile-renamer",
            "attack-surface",
            "vuln-hunter",
            "vuln-hunter-python",
            "vuln-hunter-java",
            "critic",
            "exploit-analyst",
            "defense-analyst",
            "verdict-synthesizer",
            "failure-analyst",
        ];

        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..");

        for name in agents {
            let path = repo_root.join("agents").join(format!("{name}.md"));
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
            assert!(
                content.contains(
                    "
  - store_memory
"
                ),
                "{name} should expose store_memory"
            );
            assert!(
                content.contains(
                    "
  - recall_memory
"
                ),
                "{name} should expose recall_memory"
            );
        }
    }
}
