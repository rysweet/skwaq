# Layer 1 — Repo Surface

## What this layer shows

Top-level directory structure, Cargo workspace organisation, and build system layout.

## Key facts

| Item | Detail |
|------|--------|
| Language | Rust (edition 2021) |
| Build | Cargo workspace, 3 member crates |
| Version | 0.4.0 |
| License | MIT OR Apache-2.0 |
| CI | GitHub Actions (`.github/workflows/`) |

## Workspace crates

| Crate | Path | Role |
|-------|------|------|
| `skwaq-core` | `crates/core/` | Core analysis engine — agents, graph DB, taint analysis, pattern detection |
| `skwaq-gym` | `crates/gym/` | Benchmark harness — eval, scoring, adapters, self-improvement loop |
| `skwaq` (bin) | `crates/cli/` | CLI entry point — command dispatch |

## Non-Rust content

| Directory | Contents |
|-----------|----------|
| `agents/` | 17 Markdown role-card files defining LLM agent personas and tools |
| `skills/` | 8 skill packages (prompt-based analysis tasks) |
| `data/knowledge/` | 6 knowledge-base documents (CWE families, vuln patterns, etc.) |
| `data/gym/ground_truth/` | 8 TOML benchmark suite manifests |
| `data/gym/realworld/` | Real-world CVE code samples (curl) |
| `tests/fixtures/` | 90+ C/JS/Python source files and pre-compiled binaries |
| `tests/gadugi/` | Integration test YAML scenarios |
| `tests/qa/` | QA scenario YAML definitions and shell runners |
| `scripts/` | 8 shell/Python helper scripts for gym evaluation |
| `ghidra-scripts/` | Ghidra headless analysis extraction script |
| `Specifications/` | 7 design and implementation spec documents |
| `docs/` | 11 Markdown user/developer guides |

## Diagram files

- [repo-surface.mmd](repo-surface.mmd) — Mermaid source
- [repo-surface.dot](repo-surface.dot) — Graphviz source
