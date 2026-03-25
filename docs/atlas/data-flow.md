# Layer 4 — Data Flow

## What this layer shows

The 5-layer detection pipeline that is the heart of Skwaq's vulnerability analysis system. This pipeline is assembled in `gym::agentic` and orchestrated by `analysis::orchestrator`.

## Pipeline overview

```
Source/Binary → Pre-process → L1 Pattern → L2 Dataflow → L3 Context → L4 Agents → L5 Synthesis → Findings
                                                                                                      ↓
                                                                                                   Scoring
                                                                                                      ↓
                                                                                                   History
                                                                                                      ↓
                                                                                            Improvement Cycle
                                                                                                      ↓
                                                                                              (back to L4)
```

## Pre-processing

| Step | Module | What it does |
|------|--------|-------------|
| Source parse | `source::parser` | Tree-sitter AST extraction, language detection |
| Binary parse | `binary::native` | ELF/PE header, sections, symbols via `goblin` |
| Decompile | `binary::ghidra` | Ghidra headless decompilation to pseudo-C |
| Graph build | `graph::builder` | Populate code property graph (nodes + edges) |
| Graph store | `graph::db` | SQLite-backed graph database |

## Layer 1 — Pattern Detection

Entry point: `analysis::perspective_pattern`

| Component | Module | What it detects |
|-----------|--------|----------------|
| Source patterns | `analysis::patterns_source` | Regex + tree-sitter pattern matching for dangerous APIs |
| Binary patterns | `analysis::patterns_binary` | Binary signature pattern matching |
| Semgrep | `analysis::semgrep` | External semgrep rule execution |
| Attack surface | `analysis::surface` | Entry points, source/sink identification |
| Semantic classifier | `analysis::semantic_classifier` | Classifies findings into semantic categories |

## Layer 2 — Dataflow Analysis

Entry point: `analysis::perspective_dataflow`

| Component | Module | What it traces |
|-----------|--------|---------------|
| Taint analysis | `analysis::taint` | Source → sink taint paths, stack buffer write chains |
| AST flow | `source::tree_sitter_flow` | AST-level data flow tracking |

## Layer 3 — Context Validation

Entry point: `analysis::perspective_context`

| Component | Module | What it validates |
|-----------|--------|------------------|
| Variant analysis | `analysis::variant` | Cross-reference with known vulnerability variants |
| Hardening checks | `analysis::hardening` | Binary security mitigations (RELRO, stack canaries, etc.) |
| Severity scoring | `analysis::severity` | Computes finding severity based on context |

## Layer 4 — LLM Agent Pipeline

Entry point: `analysis::orchestrator::AnalysisOrchestrator`

### Default pipeline

```
decompile-renamer → attack-surface → vuln-hunter → critic
```

### Deep pipeline (with debate)

```
decompile-renamer → attack-surface → vuln-hunter → [exploit-analyst ↔ defense-analyst] → verdict-synthesizer
```

### Agent tools available at runtime

All agents access graph queries, function reading, CWE lookup, knowledge search, and memory via `agents::tool_executor`.

### Specialist agents (invoked on demand)

| Agent | Role |
|-------|------|
| `taint-tracer` | Focused taint path analysis |
| `crash-analyst` | Crash/fuzzer finding analysis |
| `cwe-classifier` | CWE classification refinement |
| `decompile-analyst` | Decompilation quality assessment |
| `patch-diff-analyst` | Patch/diff vulnerability analysis |
| `results-skeptic` | Validation policy (non-executable) |

### Improvement agents (gym cycle)

| Agent | Role |
|-------|------|
| `failure-analyst` | Analyse false negatives, propose improvements |
| `overfitting-reviewer` | Review proposals for overfitting risk |

## Layer 5 — Synthesis

Entry point: `gym::agentic` (synthesis routing)

Four synthesis strategies, tried in order:

1. **Consensus early-exit** — If agents agree, skip further synthesis
2. **Semantic-confidence fast path** — High-confidence semantic match
3. **Expert-routed domain prompts** — Domain-specific synthesis
4. **Full LLM synthesis** — Complete synthesis via LLM

## Output and feedback loop

| Component | Module | What it produces |
|-----------|--------|-----------------|
| Findings | `analysis::findings` | Structured `Finding` objects |
| Scoring | `gym::scoring` | CWE accuracy, semantic class scores, regression detection |
| Reports | `reporting::*` | JSON, Markdown, SARIF output |
| History | `gym::history` | SQLite-backed run comparison |
| Improvement | `gym::improve` | Self-improvement cycle: failure analysis → proposal → review → patch |

The improvement cycle feeds back into Layer 4 by updating knowledge patterns and agent behaviour.

## Diagram files

- [data-flow.mmd](data-flow.mmd) — Mermaid source
- [data-flow.dot](data-flow.dot) — Graphviz source
