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
