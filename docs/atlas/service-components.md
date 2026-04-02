# Layer 3 — Service Components

## What this layer shows

The internal module structure of each workspace crate, showing how functionality is organised into modules and sub-modules.

## skwaq-core (68 source files, 13 top-level modules)

| Module | Sub-modules | Role |
|--------|-------------|------|
| `agents` | definition, discovery, mcp_client, output_schema, pipeline, runner, tool_definitions, tool_executor, tool_translate | LLM agent system — load role-cards, define tools, run multi-agent pipelines |
| `analysis` | findings, hardening, orchestrator, patterns, patterns_binary, patterns_source, perspective_context, perspective_dataflow, perspective_pattern, semantic_classifier, semgrep, severity, surface, surface_binary, surface_source, taint, variant | Core detection engine — multi-cycle analysis orchestrator with three perspectives |
| `binary` | cache, ghidra, native, subprocess, types | Binary analysis — ELF parsing (goblin), Ghidra integration, analysis caching |
| `graph` | builder, builder_binary, builder_ghidra, builder_source, db, queries, types | Code property graph — SQLite-backed graph DB with typed nodes and relationships |
| `investigation` | annotations, hypotheses, manager | Investigation management — annotation and hypothesis tracking |
| `knowledge` | cwe, patterns, search | Knowledge base — CWE catalog (947 entries from MITRE CWE v4.19.1 with parent hierarchy), vulnerability patterns, search |
| `llm` | traits | LLM client abstraction — wraps RustyClawd for Claude API access |
| `memory` | experience, pattern, store | Agent memory — experience store, pattern detector |
| `reporting` | json, markdown, sarif | Report generation — JSON, Markdown, SARIF output formats |
| `skills` | discovery | Skill system — discover and run SKILL.md prompt packages |
| `source` | parser, tree_sitter_flow | Source code parsing — tree-sitter based, language detection |
| `config` | *(standalone)* | Configuration loading and defaults |
| `error` | *(standalone)* | Error types |

## skwaq-gym (23 source files, 10 top-level modules)

| Module | Sub-modules | Role |
|--------|-------------|------|
| `adapters` | binmetric, binpool, cgc, cybergym, cyberseceval, fixtures, juliet, owasp, realworld | Benchmark suite adapters — each implements `BenchmarkAdapter` |
| `agentic` | *(standalone)* | 5-layer detection pipeline assembly for gym runs |
| `dashboard` | *(standalone)* | Chart and table generation for eval results |
| `download` | *(standalone)* | Benchmark suite download and caching |
| `ground_truth` | *(standalone)* | Ground truth manifest loading and matching |
| `history` | *(standalone)* | SQLite-backed run history and comparison |
| `improve` | *(standalone)* | Self-improvement cycle — failure analysis, proposal, review, patching |
| `scoring` | *(standalone)* | CWE/semantic scoring, regression detection, aggregation |
| `reporting` | json_report, markdown_report, terminal | Gym-specific report generation |
| `throttle` | *(standalone)* | Rate limiting for LLM API calls |

## skwaq — CLI (29 source files, 26 command modules)

| Module | Role |
|--------|------|
| `agents_cmd` | List/run agents |
| `analyze` | Run analysis on ingested code |
| `annotate_cmd` | Add investigation annotations |
| `checksec_cmd` | Binary security hardening checks |
| `common` | Shared CLI helpers |
| `config_cmd` | View/set configuration |
| `diff_analyze` | Analyze git diffs |
| `doctor` | Environment diagnostics |
| `fuzz_cmd` | Fuzzing integration |
| `gym_cmd` | Benchmark evaluation |
| `hypothesize_cmd` | Investigation hypotheses |
| `ingest` | Ingest source/binary for analysis |
| `investigate` | Source investigation workflow |
| `investigate_binary` | Binary investigation workflow |
| `kb_cmd` | Knowledge base queries |
| `memory_cmd` | Agent memory operations |
| `report` | Generate reports |
| `selftest_cmd` | Self-test runner |
| `skills_cmd` | Skill management |
| `strings_cmd` | Binary string extraction |
| `surface_cmd` | Attack surface analysis |
| `symbols_cmd` | Symbol listing |
| `taint_cmd` | Taint analysis |
| `version_cmd` | Version info |
| `viz_cmd` | Graph visualisation |
| `xrefs_cmd` | Cross-reference queries |

## Diagram files

- [service-components.mmd](service-components.mmd) — Mermaid source
- [service-components.dot](service-components.dot) — Graphviz source
