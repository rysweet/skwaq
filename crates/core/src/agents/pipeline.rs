//! Analysis pipeline: composable multi-agent workflow.
//!
//! A pipeline runs a sequence of agents, passing context forward.
//! Each stage can build its input from the graph database and previous results.

use std::sync::Arc;

use crate::graph::GraphDb;
use crate::llm::{LlmClient, TokenBudget};

use super::definition::load_agent;
use super::runner::{build_analysis_context, AgentResult, AgentRunner};

/// Maximum characters for accumulated previous-results context passed between
/// pipeline stages.  Keeps subsequent agent prompts within LLM token limits.
const MAX_PIPELINE_CONTEXT_CHARS: usize = 3000;

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
    FromPreviousResults {
        preamble: String,
    },
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
        llm: Arc<dyn LlmClient>,
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

            let agent = load_agent(&stage.agent_name)?;

            let context = match &stage.context_mode {
                ContextMode::FromGraph => {
                    build_analysis_context(target, investigation_id, db)
                }
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
                        ctx.truncate(MAX_PIPELINE_CONTEXT_CHARS);
                        ctx.push_str("\n...[truncated]");
                    }
                    ctx
                }
            };

            eprintln!(
                "  Running agent: {} ({})",
                agent.name, agent.description
            );

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

/// Build the default analysis pipeline: attack-surface -> vuln-hunter -> critic.
pub fn default_pipeline() -> AnalysisPipeline {
    AnalysisPipeline {
        stages: vec![
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
