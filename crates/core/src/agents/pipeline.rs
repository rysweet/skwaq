//! Analysis pipeline: composable multi-agent workflow.
//!
//! A pipeline runs a sequence of agents, passing context forward.
//! Each stage can build its input from the graph database and previous results.
//! Relevant skill content is automatically injected into agent system prompts.
//!
//! The deep pipeline runs exploit-analyst and defense-analyst in parallel,
//! then feeds both perspectives into a debate stage before final synthesis.

use crate::graph::GraphDb;
use crate::llm::{Client, TokenBudget};
use crate::memory::MemoryStore;
use crate::skills::discovery::load_skill;

use super::definition::load_agent;
use super::runner::{build_analysis_context, AgentContextFrame, AgentResult, AgentRunner};

/// Maximum characters for accumulated previous-results context passed between
/// pipeline stages.  Keeps subsequent agent prompts within LLM token limits.
const MAX_PIPELINE_CONTEXT_CHARS: usize = 8000;

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
            let debate_frame = AgentContextFrame::synthetic(
                "debate-summary",
                "Pipeline-generated summary of offense/defense agreements and disagreements",
                None,
                &debate_summary,
            );
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
    let mut ctx = preamble.to_string();
    for prev in results {
        ctx.push_str(&format!(
            "\n\n--- Context frame from {} ---\n{}",
            prev.agent_name,
            format_context_frame(&prev.context_frame)
        ));
        if prev.context_frame.structured_summary.is_none() {
            ctx.push_str(&format!(
                "\n\n--- Condensed output from {} ---\n{}",
                prev.agent_name,
                format_output_excerpt(&prev.output)
            ));
        }
    }
    // Truncate accumulated context to stay within LLM limits.
    if ctx.len() > MAX_PIPELINE_CONTEXT_CHARS {
        // Find nearest char boundary at or before the limit.
        let mut boundary = MAX_PIPELINE_CONTEXT_CHARS;
        while boundary > 0 && !ctx.is_char_boundary(boundary) {
            boundary -= 1;
        }
        ctx.truncate(boundary);
        ctx.push_str("\n...[truncated]");
    }
    ctx
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
    let mut summary = String::from("=== DEBATE SUMMARY ===\n\n");
    summary.push_str(&format!(
        "Two independent analysts reviewed the findings:\n\
         - {} (offense perspective): evaluated exploitability\n\
         - {} (defense perspective): evaluated mitigations\n\n",
        agent_a.agent_name, agent_b.agent_name
    ));

    // Extract verdicts from agent A (CONFIRMED/DOWNGRADED/REJECTED)
    let a_verdicts: Vec<&str> = agent_a
        .output
        .lines()
        .filter(|line| {
            let upper = line.to_uppercase();
            upper.contains("CONFIRMED")
                || upper.contains("REJECTED")
                || upper.contains("DOWNGRADED")
        })
        .collect();

    // Extract verdicts from agent B (VULNERABLE/MITIGATED/SAFE)
    let b_verdicts: Vec<&str> = agent_b
        .output
        .lines()
        .filter(|line| {
            let upper = line.to_uppercase();
            upper.contains("VULNERABLE") || upper.contains("MITIGATED") || upper.contains("SAFE")
        })
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
    let a_confirms = a_verdicts
        .iter()
        .filter(|l| l.to_uppercase().contains("CONFIRMED"))
        .count();
    let a_rejects = a_verdicts
        .iter()
        .filter(|l| l.to_uppercase().contains("REJECTED"))
        .count();
    let b_vulnerable = b_verdicts
        .iter()
        .filter(|l| l.to_uppercase().contains("VULNERABLE"))
        .count();
    let b_safe = b_verdicts
        .iter()
        .filter(|l| l.to_uppercase().contains("SAFE"))
        .count();

    summary.push_str(&format!(
        "\nSummary statistics:\n\
         - Offense: {} confirmed, {} rejected\n\
         - Defense: {} vulnerable, {} safe\n",
        a_confirms, a_rejects, b_vulnerable, b_safe
    ));

    if a_confirms > 0 && b_safe > 0 {
        summary.push_str(
            "\nDISAGREEMENTS DETECTED: Offense confirmed findings that Defense considers safe.\n\
             The verdict-synthesizer should carefully examine these conflicts and read the code \
             before making a final decision.\n",
        );
    }

    summary
}

/// Build the default analysis pipeline: decompile-renamer -> attack-surface -> vuln-hunter -> critic.
pub fn default_pipeline() -> AnalysisPipeline {
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
            PipelineStage {
                agent_name: "vuln-hunter".into(),
                context_mode: ContextMode::FromPreviousResults {
                    preamble: "The attack surface analysis is complete. Now perform deep \
                               vulnerability analysis based on the attack surface findings below. \
                               Focus on the highest-risk areas identified."
                        .into(),
                },
            },
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
            PipelineStage {
                agent_name: "vuln-hunter".into(),
                context_mode: ContextMode::FromPreviousResults {
                    preamble: "The attack surface analysis is complete. Now perform deep \
                               vulnerability analysis based on the attack surface findings below. \
                               Focus on the highest-risk areas identified. \
                               For each vulnerability found, use create_finding to record it."
                        .into(),
                },
            },
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
    let pipeline = deep_pipeline();
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

/// Build a deep pipeline with language-aware vuln-hunter selection.
///
/// Uses the file extension of `target` to pick a specialized vuln-hunter
/// (e.g., vuln-hunter-python for .py files) and runs the debate flow.
pub fn deep_pipeline_for_target(target: &str) -> AnalysisPipeline {
    let hunter = select_vuln_hunter(target);
    AnalysisPipeline {
        stages: vec![
            PipelineStage {
                agent_name: "decompile-renamer".into(),
                context_mode: ContextMode::FromGraph,
            },
            PipelineStage {
                agent_name: "attack-surface".into(),
                context_mode: ContextMode::FromGraph,
            },
            PipelineStage {
                agent_name: hunter,
                context_mode: ContextMode::FromPreviousResults {
                    preamble: "The attack surface analysis is complete. Now perform deep \
                               vulnerability analysis based on the attack surface findings below. \
                               Focus on the highest-risk areas identified. \
                               For each vulnerability found, use create_finding to record it."
                        .into(),
                },
            },
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
                content.contains("\n  - store_memory\n"),
                "{name} should expose store_memory"
            );
            assert!(
                content.contains("\n  - recall_memory\n"),
                "{name} should expose recall_memory"
            );
        }
    }
}
