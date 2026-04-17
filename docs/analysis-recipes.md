# Analysis Pipeline Recipes

Skwaq analysis pipelines are defined as declarative YAML recipe files in
`recipes/analysis/`. Each recipe specifies the sequence of agents, their
context modes, LLM client roles, and optional debate configuration.

## Overview

Pipeline stage sequences are defined in YAML recipes and embedded at compile
time via `include_str!`. The `recipe_loader` module parses these once (using
`OnceLock`) and resolves the `vuln-hunter*` placeholder per constructor call
based on the target file's language.

```
recipes/analysis/
├── standard.yaml       # Binary: decompile-renamer → attack-surface → vuln-hunter* → critic
├── deep.yaml           # Binary deep: + exploit/defense debate → verdict-synthesizer
├── source.yaml         # Source: attack-surface → taint-tracer → vuln-hunter* → critic
└── source_deep.yaml    # Source deep: + debate → verdict-synthesizer → cwe-classifier
```

## Recipe Format

### Stages

```yaml
stages:
  - agent: attack-surface
    context: from_graph          # from_graph | from_previous_results
    client_role: reasoning       # reasoning | decompilation

  - agent: critic
    context: from_previous_results
    client_role: reasoning
    preamble: >-                 # required when context is from_previous_results
      Review the following vulnerability findings...
```

Use `vuln-hunter*` as the agent name to enable language-aware routing
(resolves to `vuln-hunter-python`, `vuln-hunter-java`, or generic
`vuln-hunter` based on file extension).

### Debate

```yaml
debate:
  after_stage: 3                 # 0-based index; debate runs after this stage
  agent_a:
    name: exploit-analyst
    preamble: >-
      Evaluate exploitability...
  agent_b:
    name: defense-analyst
    preamble: >-
      Check defensive controls...
```

## API

All existing public pipeline functions are preserved unchanged:

- `default_pipeline()` / `default_pipeline_for_target(target)` → `standard.yaml`
- `deep_pipeline()` / `deep_pipeline_for_target(target)` → `deep.yaml`
- `source_pipeline_for_target(target)` → `source.yaml`
- `source_deep_pipeline_for_target(target)` → `source_deep.yaml`
- `deep_pipeline_debate()` → debate section of `deep.yaml`
- `run_deep_pipeline_with_debate()` → pipeline + debate from `deep.yaml`

The `recipe_loader` module is `pub(crate)` — not exported to downstream
consumers.

## Validation

Recipes are validated on first parse:
- At least one stage required
- `preamble` required when `context: from_previous_results`
- `preamble` forbidden when `context: from_graph`
- `debate.after_stage` must not exceed stage count
- Unknown YAML fields are rejected (`#[serde(deny_unknown_fields)]`)

## Gym Self-Improvement Integration

The gym improvement loop can propose modifications to recipe files via
`RecipeChange` proposals. This enables the self-improvement system to evolve
pipeline structure — not just agent prompts and patterns.

### How It Works

When the failure-analyst identifies that missed vulnerabilities are due to
pipeline coverage gaps (e.g., no dedicated path-traversal specialist), it
generates a `RECIPE_CHANGE` proposal. The heuristic analyzer also emits
`RecipeChange` proposals when ≥3 false negatives share a CWE family.

```
False Negatives → Failure Analysis → RecipeChange Proposal → Overfitting Review → Schema Validation → Apply
```

### Validation Gate

Before any recipe file is modified, the proposed YAML is parsed against the
`RecipeDefinition` schema using `validate_recipe_yaml()`. This enforces:

- At least one stage is present
- `preamble` is required for `from_previous_results` context, forbidden for
  `from_graph`
- `debate.after_stage` is within bounds
- No unknown fields (`deny_unknown_fields`)

Invalid YAML is rejected — malformed proposals never reach disk.

### Path Security

`RecipeChange` targets are restricted to `recipes/analysis/*.yaml`. The
apply logic rejects:

- Paths outside `recipes/analysis/` (e.g., `agents/vuln-hunter.md`)
- Path traversal via `..` components (e.g., `recipes/analysis/../../Cargo.toml`)
- Non-YAML files (e.g., `recipes/analysis/exploit.rs`)

### Example Proposals

**Heuristic: Add specialist stage** (triggered by ≥3 FN for CWE-22):

```yaml
# Appended before debate: section (or at end) of standard.yaml
  - agent: path-traversal-specialist
    context: from_graph
    client_role: reasoning
```

**LLM: Modify debate threshold** (analyst identifies debate misconfiguration):

```
Kind: RECIPE_CHANGE
Target: recipes/analysis/deep.yaml
Find: "after_stage: 3"
Replace: "after_stage: 2"
Reason: Debate should run earlier to catch false positives before synthesis
```

**LLM: Add taint-tracer to binary pipeline** (missing dataflow analysis):

```
Kind: RECIPE_CHANGE
Target: recipes/analysis/standard.yaml
Find: |
  - agent: "vuln-hunter*"
    context: from_graph
    client_role: reasoning
Replace: |
  - agent: taint-tracer
    context: from_graph
    client_role: reasoning

  - agent: "vuln-hunter*"
    context: from_graph
    client_role: reasoning
```

### Public API

```rust
/// Validates a YAML string against the RecipeDefinition schema.
/// Returns Ok(()) if valid, Err with a descriptive message if not.
pub fn validate_recipe_yaml(yaml: &str) -> anyhow::Result<()>;
```

This function is re-exported from `skwaq_core::agents` and can be used by
any crate that needs to validate recipe YAML before applying changes.
