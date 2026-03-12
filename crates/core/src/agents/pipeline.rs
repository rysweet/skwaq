//! Analysis pipeline: composable multi-agent workflow.
//!
//! A pipeline runs a sequence of agents, passing context forward.
//! Each stage can build its input from the graph database and previous results.
//! Relevant skill content is automatically injected into agent system prompts.

use crate::graph::GraphDb;
use crate::llm::{Client, TokenBudget};
use crate::skills::discovery::load_skill;

use super::definition::load_agent;
use super::runner::{build_analysis_context, AgentResult, AgentRunner};

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
            inject_skill_context(&mut agent);

            let context = match &stage.context_mode {
                ContextMode::FromGraph => build_analysis_context(target, investigation_id, db),
                ContextMode::FromPreviousResults { preamble } => {
                    let mut ctx = preamble.clone();
                    for prev in &results {
                        ctx.push_str(&format!(
                            "\n\n--- Output from {} ---\n{}",
                            prev.agent_name, prev.output
                        ));
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

/// Build a deep analysis pipeline with multi-agent validation panel.
///
/// Discovery: attack-surface → vuln-hunter (find everything)
/// Validation: exploit-analyst + defense-analyst + cwe-classifier (validate, reduce FPs)
///
/// This pipeline trades speed for precision. Each finding is validated by
/// three specialist agents, and only findings confirmed by 2/3 survive.
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
            // Validation phase - multi-agent panel
            PipelineStage {
                agent_name: "exploit-analyst".into(),
                context_mode: ContextMode::FromPreviousResults {
                    preamble: "Review each vulnerability finding below. For each one, evaluate \
                               whether it can actually be triggered by an attacker. Check reachability \
                               from external inputs, controllability of parameters, and real impact. \
                               Respond with CONFIRMED, DOWNGRADED, or REJECTED for each finding."
                        .into(),
                },
            },
            PipelineStage {
                agent_name: "defense-analyst".into(),
                context_mode: ContextMode::FromPreviousResults {
                    preamble: "Review each vulnerability finding below. For each one, check whether \
                               defensive controls (input validation, sanitization, safe wrappers, \
                               architectural mitigations) make it non-exploitable. \
                               Respond with VULNERABLE, MITIGATED, or SAFE for each finding."
                        .into(),
                },
            },
            // Synthesis: final verdict based on all validation perspectives
            PipelineStage {
                agent_name: "verdict-synthesizer".into(),
                context_mode: ContextMode::FromPreviousResults {
                    preamble: "You have received the complete output from all agents in the pipeline: \
                               attack-surface mapping, vulnerability hunting, exploit analysis, and \
                               defense analysis. Synthesize ALL perspectives into final verdicts. \
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
