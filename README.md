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
```

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

The manual GitHub workflows under `.github/workflows/gym-eval.yml` and `.github/workflows/gym-full.yml` call the same preflight step before hybrid runs.

## License

MIT OR Apache-2.0
