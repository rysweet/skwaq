# Skwaq

AI-powered vulnerability discovery CLI for binaries and source code.

Skwaq builds a Code Property Graph from binary analysis, detects dangerous API usage patterns, traces taint flows, and uses AI agents to reason about vulnerabilities. It complements tools like Ghidra and IDA Pro - it's the reasoning layer on top.

The name comes from the Lushootseed word for Raven - the trickster who reveals hidden truths.

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

## Architecture

Three Rust crates:

- **skwaq-core**: Binary parsing (goblin), graph database (SQLite), analysis engine, LLM client traits, reporting
- **skwaq-agents**: VulnHunter + Critic AI agents with tool-loop pattern
- **skwaq** (cli): clap-based CLI with 20+ commands

```
CLI (clap) -> Analysis Engine -> Graph DB (SQLite)
                |                    |
          LLM Agents          Binary Parser
        (Copilot/Ollama)        (goblin)
```

## Configuration

Create `skwaq.toml` in your project directory:

```toml
[llm]
reasoning = "copilot"       # default; or "anthropic" (requires ANTHROPIC_API_KEY)
decompilation = "copilot"   # explicit no-fallback benchmark config

[llm.copilot]
model = "claude-opus-4.6"   # default model for Copilot backend

[llm.ollama]
host = "http://localhost:11434"
model = "llama3.1"

[binary]
ghidra_path = "/opt/ghidra"
```

### LLM Backend

The default backend is **GitHub Copilot** (`reasoning = "copilot"`), which uses Claude models via the GitHub Copilot LM Models API. Authentication uses your GitHub token (`gh auth login`).

To use Anthropic directly, set `reasoning = "anthropic"` and provide `ANTHROPIC_API_KEY`.

See [docs/investigation-copilot-lm-api.md](docs/investigation-copilot-lm-api.md) for details on model availability and the Copilot integration architecture.

### Benchmark preflight and eval artifacts

Hybrid benchmark runs now require an explicit Copilot configuration with no hidden downgrade path. Before running a non-quick benchmark, run:

```bash
skwaq gym preflight
```

Use an explicit benchmark config like:

```toml
[llm]
reasoning = "copilot"
decompilation = "copilot"

[llm.copilot]
model = "claude-opus-4.6"
```

Binary benchmark paths now require Ghidra enrichment to come from either a live
Ghidra installation or a seeded cache entry. Cached analyses are reused by
binary content hash. If neither is available, `skwaq gym run` fails loudly
instead of silently falling back to a symbol-only binary graph.

`skwaq gym preflight` verifies:

- `[llm] reasoning = "copilot"` for benchmark runs
- explicit no-fallback config shape for reasoning and decompilation
- an Opus-class Copilot model such as `claude-opus-4.6`
- active GitHub authentication and Copilot client creation

For full eval runs, `skwaq gym eval` now writes reproducibility metadata alongside the usual reports:

- `metadata.json`
- `summary.json`
- `summary.md`
- `dashboard.md`

Gym reports also include semantic detection summaries derived from the same
semantic classifier used by synthesis and `skwaq analyze --quick`. JSON and
Markdown outputs surface per-semantic detection rates for classes such as
`buffer_overflow`, `format_string`, `path_traversal`, `race_condition`, and
`use_after_free`.

The manual GitHub workflows under `.github/workflows/gym-eval.yml` and `.github/workflows/gym-full.yml` call the same preflight step before hybrid runs.

### BinPool benchmark setup

The repository now includes a generated `data/gym/ground_truth/binpool.toml` manifest, so `binpool` shows up as a first-class gym suite instead of staying hidden behind a missing manifest.

The manifest is generated from the upstream public metadata index:

```bash
python3 scripts/generate_binpool_manifest.py
```

It currently selects one representative vulnerable binary per CVE for every upstream `binpool_info.json` entry that publishes both:

- at least one vulnerable binary path
- at least one usable CWE

`skwaq` does **not** auto-download BinPool. Upstream distributes the dataset via the Zenodo link referenced from <https://github.com/SimaArasteh/binpool>. After downloading it, extract the artifact so this directory exists:

```text
~/.local/share/skwaq/gym/cache/binpool/binpool_artifact/
```

Then run:

```bash
skwaq gym setup
skwaq gym run binpool --quick --max-cases 5
```

If you request an unknown suite, the CLI now lists the actually registered suites instead of a stale hardcoded `fixtures` fallback.

## License

MIT OR Apache-2.0
