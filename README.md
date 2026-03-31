# Skwaq

**A self-improving, multi-agent vulnerability analyzer.**

**[Website](https://rysweet.github.io/skwaq/)** | **[Benchmark Progress](https://github.com/rysweet/skwaq/issues/28)** | **[Specification](Specifications/SKWAQ_V2_SPEC.md)** | **[Code Atlas](docs/atlas/README.md)**

Skwaq uses a team of 18 specialized AI agents to investigate source code and binaries for security vulnerabilities. It builds a code property graph in [LadybugDB](https://github.com/LadybugDB/ladybug), traces how untrusted user input propagates through code (taint analysis), and uses multi-agent debate to reason about exploitability. The agents are powered by [RustyClawd](https://github.com/rysweet/RustyClawd), a Rust-based agentic LLM framework.

What makes it unique: **skwaq improves itself**. A built-in benchmark harness (Skwaq Gym) measures detection accuracy against 6 industry benchmarks, and a self-improvement loop uses AI agents to analyze their own failures and propose better investigation strategies — with an overfitting-reviewer agent that rejects ~66% of proposals to prevent building to the benchmark.

The name comes from the Lushootseed word for Raven — the trickster who reveals hidden truths.

## Quick Start

```bash
# Analyze a binary
skwaq ingest binary /usr/bin/target
skwaq analyze --quick
skwaq report --sarif

# Check binary hardening
skwaq checksec /usr/bin/target

# View findings
skwaq viz findings
skwaq report --json
```

## Install

### From Source

```bash
git clone https://github.com/rysweet/skwaq
cd skwaq
cargo build --release
# Binary at ./target/release/skwaq
```

### Prerequisites

- **Rust 1.70+** (for building)
- **Ghidra** (optional, for decompilation) - set `GHIDRA_INSTALL_DIR`
- **Python 3.10+** (optional, for angr symbolic execution)
- **Semgrep** (optional, for pattern matching) - `pip install semgrep`

Run `skwaq doctor` to check what's available.

## Commands

### Ingestion
```bash
skwaq ingest binary <path>     # Ingest ELF/PE binary
skwaq ingest source <path>     # Ingest source code (coming soon)
```

### Binary Inspection
```bash
skwaq checksec <binary>        # Binary hardening assessment
skwaq strings <binary>         # Extract printable strings
skwaq symbols <binary>         # List symbols and imports
skwaq surface                  # Show attack surface
skwaq xrefs <function>         # Cross-references
```

### Analysis
```bash
skwaq analyze --quick          # Pattern detection + taint analysis
skwaq analyze --investigation <id>  # Analyze specific investigation
skwaq agents list              # List installed agents and their role cards
```

`skwaq analyze --quick` now prints a `SEMANTIC` column for discovered and final
findings. This surfaces stable vulnerability classes such as
`buffer_overflow`, `format_string`, and `command_injection`, even when later
cycles challenge the initial coarse finding.

`skwaq agents list` now includes each agent's structured role title and any
declared output schema, which is useful for verifying which specialization
cards and schema-backed contracts are active in the current checkout, including
debate-stage schemas such as `exploit-analyst-v1` and `defense-analyst-v1`.

When structured exploit/defense outputs parse successfully, the deep debate
pipeline emits confidence-threshold hints in its weighted summary so the final
synthesizer can bias ambiguous findings toward rejection unless direct code
evidence is strong. If structured parsing fails, the debate summary now marks
those hints unavailable and falls back to direct code review.
`HIGH_CONFIDENCE_CONFIRM` is intentionally exploitability-led: it requires a
strong exploit-side signal plus supporting defense agreement, rather than any
net-positive score automatically promoting to confirm.
When a `threshold_hint` is present, it is the auto-confirm/auto-reject gate:
`REVIEW_REQUIRED` means the synthesizer should not auto-confirm from raw
category pairs alone, even if the debate text includes `CONFIRMED`,
`VULNERABLE`, `MITIGATED`, or `DOWNGRADED`.

### Investigation
```bash
skwaq investigate list         # List investigations
skwaq annotate <addr> "note"   # Add annotation
skwaq hypothesize "theory"     # Record hypothesis
```

### Reporting
```bash
skwaq report                   # Markdown report (default)
skwaq report --sarif           # SARIF for CI/CD
skwaq report --json            # JSON output
```

### Visualization
```bash
skwaq viz findings             # Findings table
skwaq viz callgraph            # Call graph tree
```

### Knowledge Base
```bash
skwaq kb init                  # Seed the CWE catalog and validate knowledge packs
skwaq kb search "buffer"       # Search initialized CWE + knowledge-pack entries
skwaq kb search "cwe-119 buffer overflow" --json
```

Run `skwaq kb init` once per workspace before searching. `kb search` uses the same
shared backend as agent knowledge lookup and can return mixed CWE and knowledge-pack
results; use `--json` for automation.

### System
```bash
skwaq doctor                   # Check prerequisites
skwaq config show              # Show configuration
skwaq gym preflight           # Verify Copilot benchmark readiness
skwaq version                  # Show version
```

### Gym Self-Improvement
```bash
skwaq gym run fixtures --quick        # Baseline benchmark
skwaq gym improve fixtures            # Run improvement cycle
skwaq gym run fixtures --quick        # Verify improvement
skwaq gym compare                     # Show score delta
skwaq gym case-diff                   # Per-case outcome changes
```

The `gym improve` command analyzes detection failures, proposes targeted fixes
(new patterns, CWE mappings, taint rules), reviews them for overfitting via an
LLM reviewer agent, and applies accepted patches. See
[docs/gym-self-improvement.md](docs/gym-self-improvement.md) for the full guide.
See [docs/detection-coverage.md](docs/detection-coverage.md) for how semantic
classification, CWE family mapping, and scoring interact.

### Model Comparison with Profiles
```bash
skwaq gym profile create opus --backend copilot --model claude-opus-4.6
skwaq gym run fixtures --quick --profile opus
skwaq gym dashboard --tui --profile opus
skwaq gym profiles                       # List all profiles
```

Profiles provide isolated state (results DB, memory graph, telemetry) for
reproducible multi-model evaluation. See
[docs/gym-profiles.md](docs/gym-profiles.md) for the full reference.

## Architecture

Three Rust crates:

- **skwaq-core**: Binary parsing (goblin), graph database (LadybugDB/SQLite), analysis engine, 18 agent definitions, LLM client via RustyClawd, durable agent memory
- **skwaq-gym**: Benchmark harness, 6 industry adapters, self-improvement loop with failure-analyst and overfitting-reviewer agents
- **skwaq** (cli): clap-based CLI with 20+ commands

```
CLI (clap) -> Analysis Engine -> Graph DB (LadybugDB)
                |                    |
          18 LLM Agents        Binary Parser
        (via RustyClawd)         (goblin)
```

See the [website](https://rysweet.github.io/skwaq/) for the full multi-agent pipeline diagram and benchmark results.

## Configuration

Create `skwaq.toml` in your project directory:

```toml
[llm]
reasoning = "copilot"       # default; or "anthropic" (requires ANTHROPIC_API_KEY)
decompilation = "copilot"   # backend for decompile-* stages; no hidden fallback

[llm.copilot]
model = "claude-opus-4.6"   # default model for Copilot backend

[llm.ollama]
host = "http://localhost:11434"
model = "llama3.1"

[binary]
ghidra_path = "/opt/ghidra"
```

### LLM Backend

Skwaq supports three LLM backends:

| Backend | Config | Auth |
|---------|--------|------|
| **GitHub Copilot** | `reasoning = "copilot"` | `gh auth login` (needs copilot scope) |
| **Azure AI Foundry** | `reasoning = "azure"` | `az login` or `AZURE_OPENAI_API_KEY` |
| **Anthropic** | `reasoning = "anthropic"` | `ANTHROPIC_API_KEY` |

```toml
# Azure AI Foundry (GPT-5.4)
[llm]
reasoning = "azure"
[llm.azure]
endpoint = "https://your-resource.cognitiveservices.azure.com/"
deployment = "gpt-54-skwaq"
api_version = "2024-10-21"

# GitHub Copilot (Claude Opus)
[llm]
reasoning = "copilot"
[llm.copilot]
model = "claude-opus-4.6"
```

Use `skwaq gym preflight` to verify your LLM configuration before benchmark runs.

### Dashboard & Telemetry

```bash
skwaq gym dashboard --live     # Real-time TUI with active jobs, ETA, agent stats
skwaq gym dashboard --tui      # Static snapshot
skwaq gym telemetry query      # Query OTEL spans
```

The dashboard shows per-suite F1/precision/recall, which model produced results, active jobs with progress and ETA, agent call stats, and API health. OTEL spans are exported to `~/.skwaq/telemetry/spans.jsonl`.

### Running from Any Directory

Set `SKWAQ_ROOT` to use the installed binary from anywhere:

```bash
export SKWAQ_ROOT=/path/to/skwaq
skwaq gym dashboard --live
```

### Infrastructure Setup

Deploy Azure AI Foundry models (idempotent):

```bash
bash infra/azure/setup.sh
```

### BinPool Benchmark

The BinPool suite requires manual download from [Zenodo](https://github.com/SimaArasteh/binpool).
After downloading, extract to `~/.local/share/skwaq/gym/cache/binpool/binpool_artifact/` and run `skwaq gym setup`.

## Latest Benchmark Results (GPT-5.4 via Azure AI Foundry)

| Suite | F1% | Precision% | Recall% | TP | FP | FN |
|-------|-----|-----------|--------|----|----|-----|
| CGC | 94.3 | 100.0 | 89.2 | 497 | 0 | 60 |
| CyberGym | 94.7 | 100.0 | 89.8 | 531 | 0 | 60 |
| CyberSecEval | 93.9 | 100.0 | 88.6 | 441 | 0 | 57 |
| Fixtures | 94.1 | 100.0 | 88.9 | 160 | 0 | 20 |
| OWASP | 90.2 | 100.0 | 82.1 | 533 | 0 | 116 |
| Juliet | 59.0 | 100.0 | 41.8 | 341 | 0 | 474 |

100% precision across all suites (zero false positives).

### Pattern-Only Detection (Latest, 2026-03-31)

| Suite | Cases | F1% | P% | R% |
|-------|-------|-----|----|----|
| Fixtures | 99 | 93.7 | 98.1 | 89.3 |
| OWASP | 500 | 93.8 | 100.0 | 88.3 |
| CyberSecEval | 578 | 91.8 | 100.0 | 84.8 |
| CGC | 226 | 89.8 | 100.0 | 81.5 |
| Juliet | 1,000 | 88.8 | 100.0 | 79.9 |

### Hybrid Agent Detection (Claude Opus via Anthropic API)

| Suite | Cases | F1% | P% | R% |
|-------|-------|-----|----|----|
| Juliet | 20 | 97.3 | 100.0 | 94.7 |
| OWASP | 20 | 95.2 | 100.0 | 90.9 |
| Fixtures | 99 | 92.6 | 100.0 | 86.2 |
| CyberSecEval | 20 | 90.9 | 100.0 | 83.3 |

## License

MIT OR Apache-2.0
