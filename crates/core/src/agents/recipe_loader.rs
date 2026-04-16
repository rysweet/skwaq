//! Recipe loader: parse YAML recipe definitions into pipeline structures.
//!
//! Recipes are embedded at compile time via `include_str!` and parsed into
//! `AnalysisPipeline` and optional `DebateGroup` structs.  The `vuln-hunter*`
//! placeholder in a recipe is resolved per-call via `select_vuln_hunter()`.

use std::sync::OnceLock;

use serde::Deserialize;

use super::pipeline::{AnalysisPipeline, ClientRole, ContextMode, DebateGroup, PipelineStage};

// ---------------------------------------------------------------------------
// Embedded recipe YAML (compile-time)
// ---------------------------------------------------------------------------

const STANDARD_YAML: &str = include_str!("../../../../recipes/analysis/standard.yaml");
const DEEP_YAML: &str = include_str!("../../../../recipes/analysis/deep.yaml");
const SOURCE_YAML: &str = include_str!("../../../../recipes/analysis/source.yaml");
const SOURCE_DEEP_YAML: &str = include_str!("../../../../recipes/analysis/source_deep.yaml");

// ---------------------------------------------------------------------------
// Parsed recipe cache (parse once, resolve vuln-hunter* per call)
// ---------------------------------------------------------------------------

static STANDARD_RECIPE: OnceLock<RecipeYaml> = OnceLock::new();
static DEEP_RECIPE: OnceLock<RecipeYaml> = OnceLock::new();
static SOURCE_RECIPE: OnceLock<RecipeYaml> = OnceLock::new();
static SOURCE_DEEP_RECIPE: OnceLock<RecipeYaml> = OnceLock::new();

fn standard_recipe() -> &'static RecipeYaml {
    STANDARD_RECIPE.get_or_init(|| parse_recipe(STANDARD_YAML).expect("invalid standard.yaml"))
}

fn deep_recipe() -> &'static RecipeYaml {
    DEEP_RECIPE.get_or_init(|| parse_recipe(DEEP_YAML).expect("invalid deep.yaml"))
}

fn source_recipe() -> &'static RecipeYaml {
    SOURCE_RECIPE.get_or_init(|| parse_recipe(SOURCE_YAML).expect("invalid source.yaml"))
}

fn source_deep_recipe() -> &'static RecipeYaml {
    SOURCE_DEEP_RECIPE
        .get_or_init(|| parse_recipe(SOURCE_DEEP_YAML).expect("invalid source_deep.yaml"))
}

// ---------------------------------------------------------------------------
// YAML schema (serde)
// ---------------------------------------------------------------------------

/// Top-level recipe file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecipeYaml {
    pub stages: Vec<StageYaml>,
    #[serde(default)]
    pub debate: Option<DebateYaml>,
}

/// One pipeline stage.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StageYaml {
    pub agent: String,
    pub context: ContextModeYaml,
    pub client_role: ClientRoleYaml,
    /// Required when `context` is `from_previous_results`.
    #[serde(default)]
    pub preamble: Option<String>,
}

/// Debate configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DebateYaml {
    pub after_stage: usize,
    pub agent_a: DebateAgentYaml,
    pub agent_b: DebateAgentYaml,
}

/// A single debate participant.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DebateAgentYaml {
    pub name: String,
    pub preamble: String,
}

/// Context mode enum for YAML.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ContextModeYaml {
    FromGraph,
    FromPreviousResults,
}

/// Client role enum for YAML.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ClientRoleYaml {
    Reasoning,
    Decompilation,
}

// ---------------------------------------------------------------------------
// Public(crate) API: load pipelines from cached recipes
// ---------------------------------------------------------------------------

/// Result of loading a recipe: a pipeline plus optional debate config.
pub(crate) struct LoadedRecipe {
    pub pipeline: AnalysisPipeline,
    pub debate: Option<LoadedDebate>,
}

/// Debate configuration extracted from a recipe.
pub(crate) struct LoadedDebate {
    pub group: DebateGroup,
    pub after_stage: usize,
}

/// Load the standard (binary) pipeline recipe.
pub(crate) fn load_standard_recipe(target: &str) -> LoadedRecipe {
    build_loaded_recipe(standard_recipe(), target)
}

/// Load the deep (binary) pipeline recipe.
pub(crate) fn load_deep_recipe(target: &str) -> LoadedRecipe {
    build_loaded_recipe(deep_recipe(), target)
}

/// Load the source pipeline recipe.
pub(crate) fn load_source_recipe(target: &str) -> LoadedRecipe {
    build_loaded_recipe(source_recipe(), target)
}

/// Load the deep source pipeline recipe.
pub(crate) fn load_source_deep_recipe(target: &str) -> LoadedRecipe {
    build_loaded_recipe(source_deep_recipe(), target)
}

// ---------------------------------------------------------------------------
// Internal: build pipeline structs from parsed recipe
// ---------------------------------------------------------------------------

fn build_loaded_recipe(recipe: &RecipeYaml, target: &str) -> LoadedRecipe {
    let vuln_hunter = super::pipeline::select_vuln_hunter(target);

    let stages = recipe
        .stages
        .iter()
        .map(|stage| {
            let agent_name = if stage.agent == "vuln-hunter*" {
                vuln_hunter.clone()
            } else {
                stage.agent.clone()
            };

            let context_mode = match stage.context {
                ContextModeYaml::FromGraph => ContextMode::FromGraph,
                ContextModeYaml::FromPreviousResults => ContextMode::FromPreviousResults {
                    preamble: stage
                        .preamble
                        .clone()
                        .expect("preamble required for from_previous_results"),
                },
            };

            let client_role = match stage.client_role {
                ClientRoleYaml::Reasoning => ClientRole::Reasoning,
                ClientRoleYaml::Decompilation => ClientRole::Decompilation,
            };

            PipelineStage {
                agent_name,
                context_mode,
                client_role,
            }
        })
        .collect();

    let debate = recipe.debate.as_ref().map(|d| LoadedDebate {
        after_stage: d.after_stage,
        group: DebateGroup {
            agent_a: d.agent_a.name.clone(),
            preamble_a: d.agent_a.preamble.clone(),
            agent_b: d.agent_b.name.clone(),
            preamble_b: d.agent_b.preamble.clone(),
        },
    });

    LoadedRecipe {
        pipeline: AnalysisPipeline { stages },
        debate,
    }
}

// ---------------------------------------------------------------------------
// Parsing + validation
// ---------------------------------------------------------------------------

fn parse_recipe(yaml: &str) -> anyhow::Result<RecipeYaml> {
    let recipe: RecipeYaml = serde_yaml_ng::from_str(yaml)?;
    validate_recipe(&recipe)?;
    Ok(recipe)
}

fn validate_recipe(recipe: &RecipeYaml) -> anyhow::Result<()> {
    if recipe.stages.is_empty() {
        anyhow::bail!("recipe must have at least one stage");
    }

    for (i, stage) in recipe.stages.iter().enumerate() {
        if stage.agent.is_empty() {
            anyhow::bail!("stage {i}: agent name must not be empty");
        }
        if stage.context == ContextModeYaml::FromPreviousResults && stage.preamble.is_none() {
            anyhow::bail!(
                "stage {i} ({}): preamble is required when context is from_previous_results",
                stage.agent
            );
        }
        if stage.context == ContextModeYaml::FromGraph && stage.preamble.is_some() {
            anyhow::bail!(
                "stage {i} ({}): preamble must not be set when context is from_graph",
                stage.agent
            );
        }
    }

    if let Some(debate) = &recipe.debate {
        if debate.after_stage > recipe.stages.len() {
            anyhow::bail!(
                "debate.after_stage ({}) exceeds number of stages ({})",
                debate.after_stage,
                recipe.stages.len()
            );
        }
        if debate.agent_a.name.is_empty() || debate.agent_b.name.is_empty() {
            anyhow::bail!("debate agent names must not be empty");
        }
        if debate.agent_a.preamble.is_empty() || debate.agent_b.preamble.is_empty() {
            anyhow::bail!("debate agent preambles must not be empty");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_all_bundled_recipes() {
        // Ensures all embedded YAML is syntactically valid and passes validation.
        let _ = standard_recipe();
        let _ = deep_recipe();
        let _ = source_recipe();
        let _ = source_deep_recipe();
    }

    #[test]
    fn test_standard_recipe_stages() {
        let loaded = load_standard_recipe("test.c");
        assert_eq!(loaded.pipeline.stages.len(), 4);
        assert_eq!(loaded.pipeline.stages[0].agent_name, "decompile-renamer");
        assert_eq!(loaded.pipeline.stages[1].agent_name, "attack-surface");
        assert_eq!(loaded.pipeline.stages[2].agent_name, "vuln-hunter");
        assert_eq!(loaded.pipeline.stages[3].agent_name, "critic");
        assert!(loaded.debate.is_none());
    }

    #[test]
    fn test_standard_recipe_context_modes() {
        let loaded = load_standard_recipe("");
        assert!(matches!(
            loaded.pipeline.stages[0].context_mode,
            ContextMode::FromGraph
        ));
        assert!(matches!(
            loaded.pipeline.stages[1].context_mode,
            ContextMode::FromGraph
        ));
        assert!(matches!(
            loaded.pipeline.stages[2].context_mode,
            ContextMode::FromGraph
        ));
        assert!(matches!(
            loaded.pipeline.stages[3].context_mode,
            ContextMode::FromPreviousResults { .. }
        ));
    }

    #[test]
    fn test_standard_recipe_client_roles() {
        let loaded = load_standard_recipe("");
        assert_eq!(
            loaded.pipeline.stages[0].client_role,
            ClientRole::Decompilation
        );
        assert_eq!(loaded.pipeline.stages[1].client_role, ClientRole::Reasoning);
        assert_eq!(loaded.pipeline.stages[2].client_role, ClientRole::Reasoning);
        assert_eq!(loaded.pipeline.stages[3].client_role, ClientRole::Reasoning);
    }

    #[test]
    fn test_deep_recipe_has_debate() {
        let loaded = load_deep_recipe("");
        assert_eq!(loaded.pipeline.stages.len(), 4);
        let debate = loaded.debate.expect("deep recipe must have debate");
        assert_eq!(debate.after_stage, 3);
        assert_eq!(debate.group.agent_a, "exploit-analyst");
        assert_eq!(debate.group.agent_b, "defense-analyst");
    }

    #[test]
    fn test_source_recipe_has_taint_tracer() {
        let loaded = load_source_recipe("app.py");
        assert_eq!(loaded.pipeline.stages.len(), 4);
        assert_eq!(loaded.pipeline.stages[0].agent_name, "attack-surface");
        assert_eq!(loaded.pipeline.stages[1].agent_name, "taint-tracer");
        // vuln-hunter* resolved for .py
        assert!(
            loaded.pipeline.stages[2].agent_name == "vuln-hunter-python"
                || loaded.pipeline.stages[2].agent_name == "vuln-hunter"
        );
        assert_eq!(loaded.pipeline.stages[3].agent_name, "critic");
        assert!(loaded.debate.is_none());
    }

    #[test]
    fn test_source_deep_recipe_full_pipeline() {
        let loaded = load_source_deep_recipe("Main.java");
        assert_eq!(loaded.pipeline.stages.len(), 5);
        assert_eq!(loaded.pipeline.stages[0].agent_name, "attack-surface");
        assert_eq!(loaded.pipeline.stages[1].agent_name, "taint-tracer");
        // vuln-hunter* resolved for .java
        assert!(
            loaded.pipeline.stages[2].agent_name == "vuln-hunter-java"
                || loaded.pipeline.stages[2].agent_name == "vuln-hunter"
        );
        assert_eq!(loaded.pipeline.stages[3].agent_name, "verdict-synthesizer");
        assert_eq!(loaded.pipeline.stages[4].agent_name, "cwe-classifier");
        let debate = loaded.debate.expect("source_deep must have debate");
        assert_eq!(debate.after_stage, 3);
    }

    #[test]
    fn test_vuln_hunter_resolution_per_target() {
        // C files -> generic vuln-hunter
        let c_loaded = load_standard_recipe("overflow.c");
        assert_eq!(c_loaded.pipeline.stages[2].agent_name, "vuln-hunter");

        // No extension -> generic vuln-hunter
        let no_ext = load_standard_recipe("binary_blob");
        assert_eq!(no_ext.pipeline.stages[2].agent_name, "vuln-hunter");
    }

    #[test]
    fn test_validation_rejects_empty_stages() {
        let yaml = "stages: []";
        assert!(parse_recipe(yaml).is_err());
    }

    #[test]
    fn test_validation_rejects_missing_preamble() {
        let yaml = r#"
stages:
  - agent: critic
    context: from_previous_results
    client_role: reasoning
"#;
        let err = parse_recipe(yaml).unwrap_err();
        assert!(err.to_string().contains("preamble is required"));
    }

    #[test]
    fn test_validation_rejects_preamble_on_from_graph() {
        let yaml = r#"
stages:
  - agent: attack-surface
    context: from_graph
    client_role: reasoning
    preamble: "should not be here"
"#;
        let err = parse_recipe(yaml).unwrap_err();
        assert!(err.to_string().contains("preamble must not be set"));
    }

    #[test]
    fn test_validation_rejects_invalid_debate_after_stage() {
        let yaml = r#"
stages:
  - agent: attack-surface
    context: from_graph
    client_role: reasoning
debate:
  after_stage: 5
  agent_a:
    name: exploit-analyst
    preamble: "test"
  agent_b:
    name: defense-analyst
    preamble: "test"
"#;
        let err = parse_recipe(yaml).unwrap_err();
        assert!(err.to_string().contains("exceeds number of stages"));
    }

    #[test]
    fn test_serde_rejects_unknown_fields() {
        let yaml = r#"
stages:
  - agent: attack-surface
    context: from_graph
    client_role: reasoning
    unknown_field: true
"#;
        assert!(parse_recipe(yaml).is_err());
    }

    #[test]
    fn test_serde_rejects_invalid_context_mode() {
        let yaml = r#"
stages:
  - agent: attack-surface
    context: from_memory
    client_role: reasoning
"#;
        assert!(parse_recipe(yaml).is_err());
    }

    #[test]
    fn test_serde_rejects_invalid_client_role() {
        let yaml = r#"
stages:
  - agent: attack-surface
    context: from_graph
    client_role: turbo
"#;
        assert!(parse_recipe(yaml).is_err());
    }

    // Parity tests: verify recipe-loaded pipelines match the old hardcoded constructors
    // in stage count, agent names, context modes, and client roles.

    fn normalize_ws(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn preamble_of(stage: &PipelineStage) -> Option<String> {
        match &stage.context_mode {
            ContextMode::FromPreviousResults { preamble } => Some(preamble.clone()),
            ContextMode::FromGraph => None,
        }
    }

    #[test]
    fn test_parity_standard_pipeline() {
        let old = super::super::pipeline::default_pipeline_for_target("");
        let new = load_standard_recipe("");

        assert_eq!(old.stages.len(), new.pipeline.stages.len());
        for (i, (o, n)) in old
            .stages
            .iter()
            .zip(new.pipeline.stages.iter())
            .enumerate()
        {
            assert_eq!(o.agent_name, n.agent_name, "stage {i} agent mismatch");
            assert_eq!(
                o.client_role, n.client_role,
                "stage {i} client_role mismatch"
            );
            let old_p = preamble_of(o).map(|s| normalize_ws(&s));
            let new_p = preamble_of(n).map(|s| normalize_ws(&s));
            assert_eq!(old_p, new_p, "stage {i} preamble mismatch");
        }
    }

    #[test]
    fn test_parity_deep_pipeline() {
        let old = super::super::pipeline::deep_pipeline_for_target("");
        let new = load_deep_recipe("");
        let old_debate = super::super::pipeline::deep_pipeline_debate();

        assert_eq!(old.stages.len(), new.pipeline.stages.len());
        for (i, (o, n)) in old
            .stages
            .iter()
            .zip(new.pipeline.stages.iter())
            .enumerate()
        {
            assert_eq!(o.agent_name, n.agent_name, "stage {i} agent mismatch");
            assert_eq!(
                o.client_role, n.client_role,
                "stage {i} client_role mismatch"
            );
            let old_p = preamble_of(o).map(|s| normalize_ws(&s));
            let new_p = preamble_of(n).map(|s| normalize_ws(&s));
            assert_eq!(old_p, new_p, "stage {i} preamble mismatch");
        }

        let debate = new.debate.expect("deep recipe must have debate");
        assert_eq!(debate.after_stage, 3);
        assert_eq!(debate.group.agent_a, old_debate.agent_a);
        assert_eq!(debate.group.agent_b, old_debate.agent_b);
        assert_eq!(
            normalize_ws(&debate.group.preamble_a),
            normalize_ws(&old_debate.preamble_a)
        );
        assert_eq!(
            normalize_ws(&debate.group.preamble_b),
            normalize_ws(&old_debate.preamble_b)
        );
    }

    #[test]
    fn test_parity_source_pipeline() {
        let old = super::super::pipeline::source_pipeline_for_target("");
        let new = load_source_recipe("");

        assert_eq!(old.stages.len(), new.pipeline.stages.len());
        for (i, (o, n)) in old
            .stages
            .iter()
            .zip(new.pipeline.stages.iter())
            .enumerate()
        {
            assert_eq!(o.agent_name, n.agent_name, "stage {i} agent mismatch");
            assert_eq!(
                o.client_role, n.client_role,
                "stage {i} client_role mismatch"
            );
            let old_p = preamble_of(o).map(|s| normalize_ws(&s));
            let new_p = preamble_of(n).map(|s| normalize_ws(&s));
            assert_eq!(old_p, new_p, "stage {i} preamble mismatch");
        }
    }

    #[test]
    fn test_parity_source_deep_pipeline() {
        let old = super::super::pipeline::source_deep_pipeline_for_target("");
        let new = load_source_deep_recipe("");

        assert_eq!(old.stages.len(), new.pipeline.stages.len());
        for (i, (o, n)) in old
            .stages
            .iter()
            .zip(new.pipeline.stages.iter())
            .enumerate()
        {
            assert_eq!(o.agent_name, n.agent_name, "stage {i} agent mismatch");
            assert_eq!(
                o.client_role, n.client_role,
                "stage {i} client_role mismatch"
            );
            let old_p = preamble_of(o).map(|s| normalize_ws(&s));
            let new_p = preamble_of(n).map(|s| normalize_ws(&s));
            assert_eq!(old_p, new_p, "stage {i} preamble mismatch");
        }

        let debate = new.debate.expect("source_deep recipe must have debate");
        assert_eq!(debate.after_stage, 3);
        assert_eq!(debate.group.agent_a, "exploit-analyst");
        assert_eq!(debate.group.agent_b, "defense-analyst");
    }

    #[test]
    fn test_parity_vuln_hunter_language_routing() {
        // Python target
        let py_old = super::super::pipeline::default_pipeline_for_target("exploit.py");
        let py_new = load_standard_recipe("exploit.py");
        assert_eq!(
            py_old.stages[2].agent_name, py_new.pipeline.stages[2].agent_name,
            "Python vuln-hunter mismatch"
        );

        // Java target
        let java_old = super::super::pipeline::default_pipeline_for_target("App.java");
        let java_new = load_standard_recipe("App.java");
        assert_eq!(
            java_old.stages[2].agent_name, java_new.pipeline.stages[2].agent_name,
            "Java vuln-hunter mismatch"
        );

        // C target (generic)
        let c_old = super::super::pipeline::default_pipeline_for_target("buf.c");
        let c_new = load_standard_recipe("buf.c");
        assert_eq!(
            c_old.stages[2].agent_name, c_new.pipeline.stages[2].agent_name,
            "C vuln-hunter mismatch"
        );
    }
}
