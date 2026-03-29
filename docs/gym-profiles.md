# Gym Model Profiles

Run side-by-side model comparisons with fully isolated state. Each profile
gets its own results database, memory graph, and telemetry — no environment
variable hacks required.

## Quick Start

```bash
# Create a profile for Claude Opus
skwaq gym profile create opus --backend copilot --model claude-opus-4.6

# Create a profile for GPT (fill in your Azure endpoint)
skwaq gym profile create gpt54 --backend azure \
  --endpoint https://YOUR.openai.azure.com \
  --deployment gpt-54-turbo

# Run the same benchmark on both
skwaq gym run fixtures --max-cases 20 --profile opus
skwaq gym run fixtures --max-cases 20 --profile gpt54

# View results per profile
skwaq gym dashboard --tui --profile opus
skwaq gym dashboard --tui --profile gpt54
```

## Concepts

A **profile** is a named directory under `~/.skwaq/profiles/<name>/` that
isolates LLM configuration and all mutable state produced by gym runs:

| Per-profile (isolated) | Shared (from SKWAQ_ROOT) |
|------------------------|--------------------------|
| `config.toml` (LLM overrides) | Binary (`target/release/skwaq`) |
| `results.db` (run history) | Agent prompts (`agents/*.md`) |
| `memory_graph/` (LadybugDB) | Ground truth (`data/gym/ground_truth/`) |
| `telemetry/` (OpenTelemetry spans) | Benchmark cache (`~/.local/share/skwaq/gym/cache/`) |
| `active_runs.jsonl` | Pattern source code |

When `--profile` is omitted, all commands behave exactly as before — results
go to the default locations. Profiles are purely additive.

## Profile Directory Layout

```
~/.skwaq/profiles/
├── opus/
│   ├── config.toml          # LLM backend overrides
│   ├── results.db           # SQLite history database
│   ├── memory_graph/        # LadybugDB instance
│   ├── telemetry/           # OTel span storage
│   └── active_runs.jsonl    # In-progress run tracking
└── gpt54/
    ├── config.toml
    ├── results.db
    ├── memory_graph/
    ├── telemetry/
    └── active_runs.jsonl
```

## CLI Reference

### `skwaq gym profile create`

Create a new profile with LLM backend configuration.

```
skwaq gym profile create <NAME> --backend <BACKEND> [OPTIONS]
```

| Argument | Required | Description |
|----------|----------|-------------|
| `NAME` | Yes | Profile name (`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`, max 64 chars) |
| `--backend` | Yes | LLM backend: `copilot`, `azure`, or `anthropic` |
| `--model` | No | Model identifier (e.g., `claude-opus-4.6`) |
| `--endpoint` | No | Azure OpenAI endpoint URL |
| `--deployment` | No | Azure OpenAI deployment name |

```bash
# Copilot backend with specific model
skwaq gym profile create opus --backend copilot --model claude-opus-4.6

# Azure backend (endpoint and deployment required)
skwaq gym profile create gpt54 --backend azure \
  --endpoint https://myorg.openai.azure.com \
  --deployment gpt-54-turbo

# Anthropic backend (requires ANTHROPIC_API_KEY env var)
skwaq gym profile create sonnet --backend anthropic --model claude-sonnet-4.6
```

### `skwaq gym profiles`

List all available profiles with their configuration summary.

```bash
$ skwaq gym profiles
NAME      BACKEND    MODEL               RUNS
opus      copilot    claude-opus-4.6     12
gpt54     azure      gpt-54-turbo         8
sonnet    anthropic  claude-sonnet-4.6    0
```

### `--profile` flag

Available on `run`, `eval`, `improve`, and `dashboard` subcommands.

```bash
skwaq gym run fixtures --max-cases 20 --profile opus
skwaq gym eval --suites fixtures,juliet --profile opus
skwaq gym improve fixtures --profile opus
skwaq gym dashboard --tui --profile opus
```

**Auto-creation behavior:**
- `run`, `eval`, `improve`: If the named profile directory does not exist, it
  is created automatically with default configuration (inheriting the current
  base `skwaq.toml` LLM settings). This enables frictionless first use.
- `dashboard`: Errors if the profile does not exist (there is nothing to show).

## Profile Configuration

Each profile's `config.toml` contains only `[llm]` section overrides. During
loading, the profile's `[llm]` section **replaces** the base `skwaq.toml`
`[llm]` section entirely. All other configuration sections come from the base
config.

### Example: `~/.skwaq/profiles/opus/config.toml`

```toml
[llm]
reasoning = "copilot"
decompilation = "copilot"

[llm.copilot]
model = "claude-opus-4.6"
```

### Example: `~/.skwaq/profiles/gpt54/config.toml`

```toml
[llm]
reasoning = "azure"
decompilation = "azure"

[llm.azure]
endpoint = "https://myorg.openai.azure.com"
deployment = "gpt-54-turbo"
api_version = "2025-01-01-preview"
```

### Config Merge Rules

1. Load base `skwaq.toml` as normal
2. If `--profile` is set, load `~/.skwaq/profiles/<name>/config.toml`
3. Replace `config.llm` entirely with the profile's `[llm]` section
4. All other sections (`[analysis]`, `[graph]`, etc.) are unchanged

The profile `config.toml` is a full `Config`-compatible TOML file, but only
the `[llm]` section is used during merge. Other sections, if present, are
silently ignored.

## Profile Name Rules

Profile names must match `^[a-zA-Z0-9][a-zA-Z0-9_-]*$`:

| Rule | Example | Valid? |
|------|---------|--------|
| Alphanumeric start | `opus` | Yes |
| Hyphens allowed | `gpt-4o` | Yes |
| Underscores allowed | `my_model` | Yes |
| Leading dot | `.hidden` | No |
| Path traversal | `../escape` | No |
| Spaces | `my model` | No |
| Empty | `` | No |
| Over 64 characters | `a` × 65 | No |

Invalid names are rejected at CLI parse time with an explanatory error message.

## Run Metadata

When a profile is active, the profile name is stored in `EvalRunMetadata`:

```json
{
  "run_id": "2026-03-29T10:30:00Z",
  "suite": "fixtures",
  "profile": "opus",
  "config": { ... }
}
```

This enables filtering and grouping results by profile in reports and the
dashboard.

## Default Profile Templates

Two templates are available via `skwaq gym profile create`:

### `opus`

```bash
skwaq gym profile create opus --backend copilot --model claude-opus-4.6
```

Generates:

```toml
[llm]
reasoning = "copilot"
decompilation = "copilot"

[llm.copilot]
model = "claude-opus-4.6"
```

### `gpt54`

```bash
skwaq gym profile create gpt54 --backend azure \
  --endpoint https://YOUR.openai.azure.com \
  --deployment YOUR_DEPLOYMENT
```

Azure profiles require you to fill in your own endpoint and deployment name.

## Workflow: Model Comparison

A typical model comparison workflow:

```bash
# 1. Create profiles
skwaq gym profile create opus --backend copilot --model claude-opus-4.6
skwaq gym profile create sonnet --backend copilot --model claude-sonnet-4.6

# 2. Run identical benchmarks
skwaq gym eval --suites fixtures --profile opus
skwaq gym eval --suites fixtures --profile sonnet

# 3. Check results independently
skwaq gym report --profile opus
skwaq gym report --profile sonnet

# 4. Run improvement cycles per model
skwaq gym improve fixtures --max-cases 20 --profile opus
skwaq gym improve fixtures --max-cases 20 --profile sonnet

# 5. Compare improvement deltas
skwaq gym history --profile opus
skwaq gym history --profile sonnet
```

Each profile's improvement cycle operates on its own memory graph and history
database, so improvements discovered by one model do not leak into another
model's evaluation.

## Troubleshooting

### Profile not found (dashboard)

```
Error: profile "typo-name" does not exist
Hint: run `skwaq gym profiles` to list available profiles
```

`dashboard` requires an existing profile with data. Use `skwaq gym profiles`
to see what is available.

### Profile auto-created on run

```
Info: created profile "new-model" with default LLM config from skwaq.toml
```

When `--profile` references a name that does not exist during `run`, `eval`,
or `improve`, the profile directory is created automatically using the base
config's LLM settings. Edit `~/.skwaq/profiles/new-model/config.toml` to
customize.

### Stale profile config

If you update `skwaq.toml` LLM settings and want profiles to match, you must
update each profile's `config.toml` independently. Profiles intentionally do
not inherit base config changes — that is the point of isolation.

## Security

- Profile directories are created with `0o700` permissions on Unix
- Symlinks in profile paths are rejected to prevent path traversal
- API keys and tokens are **never** stored in profile `config.toml` —
  credential resolution uses the existing chain (environment variables,
  Copilot token broker)
- Profile names are validated before any filesystem operation

## Related Documentation

- [Gym Configuration Reference](gym-configuration.md) — base config options
- [Gym Tutorial](gym-tutorial.md) — step-by-step improvement cycle walkthrough
- [Gym API Reference](gym-api-reference.md) — internal Rust API
- [Gym Self-Improvement](gym-self-improvement.md) — improvement loop mechanics
