# Investigation: GitHub Copilot LM Models API via RustyClawd

**Date**: 2026-03-12
**Status**: Complete
**Scope**: Assess changes required to use GitHub Copilot LM Models API instead of Anthropic direct API

## Summary

RustyClawd already has a production-ready Copilot backend. Only skwaqr-side configuration and model name changes are needed. No upstream RustyClawd code changes are required for the primary Copilot endpoint, but the GitHub Models secondary endpoint has a model prefix bug for non-OpenAI models.

## Architecture: Current State

```
Skwaqr Agents → skwaq_core::llm::create_client() → RustyClawd Client
                                                        ├── Backend::Anthropic → api.anthropic.com (default)
                                                        └── Backend::Copilot   → api.githubcopilot.com (primary)
                                                                               → models.github.ai (secondary)
```

RustyClawd's Copilot backend (`copilot.rs`, ~1120 lines) translates between Anthropic Messages API and OpenAI Chat Completions API format. The translation covers:

### Features Fully Translated
- System prompts → system role message
- Tool definitions → OpenAI functions format
- Tool use/results → full round-trip with tool_call_id
- Streaming → SSE chunk parsing and event translation
- Usage tracking → prompt_tokens ↔ input_tokens
- Stop reasons → stop/tool_calls/length mapped correctly
- Error signaling in tool results → "Error: " prefix workaround

### Features Lost in Translation (none impact skwaqr)
| Feature | Status | Used by Skwaqr? |
|---------|--------|-----------------|
| Thinking blocks | Silently dropped | No |
| Speed/fast mode | Not forwarded | No |
| top_k, stop_sequences | Dropped | No |
| tool_choice | Not translated | No |
| Image/vision content | Not supported | No |

## Model Catalog (Verified 2026-03-12)

Live query against `api.githubcopilot.com/models` confirmed these Anthropic models:

| Copilot Model ID | Family | Max Context | Max Output | Supports |
|-----------------|--------|-------------|------------|----------|
| `claude-opus-4.6` | claude-opus-4.6 | 200K | 128K | tool_calls, streaming, vision, adaptive_thinking |
| `claude-sonnet-4.6` | claude-sonnet-4.6 | 200K | 64K | tool_calls, streaming, vision, adaptive_thinking |
| `claude-opus-4.5` | claude-opus-4.5 | 160K | 32K | tool_calls, streaming, vision, thinking |
| `claude-sonnet-4.5` | claude-sonnet-4.5 | 200K | 64K | tool_calls, streaming, vision, thinking |
| `claude-sonnet-4` | claude-sonnet-4 | 216K | 16K | tool_calls, streaming, vision, thinking |
| `claude-haiku-4.5` | claude-haiku-4.5 | 200K | 64K | tool_calls, streaming, vision, thinking |

All Claude models support both `/v1/messages` AND `/chat/completions` endpoints.

### Model Name Format: DOTS not HYPHENS

**Critical**: Copilot uses dots in model IDs (e.g., `claude-opus-4.6`) while skwaqr agents currently use hyphens (`claude-opus-4-6`). The mapping is:
- `claude-opus-4-6` → `claude-opus-4.6`
- `claude-haiku-4-5-20251001` → `claude-haiku-4.5`

### qualify_model() prefix logic

RustyClawd's `CopilotAuth::qualify_model()` method:
- **Copilot endpoint** (`api.githubcopilot.com`): Model names pass through as-is — works correctly
- **GitHub Models endpoint** (`models.github.ai`): Hardcodes `openai/` prefix for non-namespaced models

This means `claude-opus-4.6` would incorrectly become `openai/claude-opus-4.6` on the secondary endpoint. It should be `anthropic/claude-opus-4.6`.

**Mitigation**: The primary Copilot endpoint is tried first. Since Claude models are confirmed in the Copilot catalog, the secondary endpoint should rarely be reached.

## Required Changes

### 1. Config defaults — `crates/core/src/config.rs` (REQUIRED)
- `default_llm_backend()`: `"anthropic"` → `"copilot"`
- `default_model()`: Update to valid Copilot model name

### 2. Agent model names — `agents/*.md` (13 files) (REQUIRED)
| Agent | Current Model | New Model |
|-------|--------------|-----------|
| attack-surface | claude-opus-4-6 | claude-opus-4.6 |
| critic | claude-opus-4-6 | claude-opus-4.6 |
| crash-analyst | claude-opus-4-6 | claude-opus-4.6 |
| cwe-classifier | claude-opus-4-6 | claude-opus-4.6 |
| decompile-analyst | claude-opus-4-6 | claude-opus-4.6 |
| decompile-renamer | claude-haiku-4-5-20251001 | claude-haiku-4.5 |
| defense-analyst | claude-opus-4-6 | claude-opus-4.6 |
| exploit-analyst | claude-opus-4-6 | claude-opus-4.6 |
| failure-analyst | claude-opus-4-6 | claude-opus-4.6 |
| patch-diff-analyst | claude-opus-4-6 | claude-opus-4.6 |
| taint-tracer | claude-opus-4-6 | claude-opus-4.6 |
| verdict-synthesizer | claude-opus-4-6 | claude-opus-4.6 |
| vuln-hunter | claude-opus-4-6 | claude-opus-4.6 |

### 3. Agent definition default — `crates/core/src/agents/definition.rs` (OPTIONAL)
- `default_model()`: `"openai/gpt-4o-mini"` → desired Copilot default
- Update associated test assertions

### 4. Auto-detect logic — `crates/core/src/llm/mod.rs` (OPTIONAL)
- Consider flipping endpoint priority (Copilot first, Anthropic second)

## Authentication Migration

| Aspect | Anthropic | Copilot |
|--------|-----------|---------|
| Credential | `ANTHROPIC_API_KEY` env var | GitHub token |
| Sources | Env var only | `GITHUB_TOKEN` env, `gh auth token`, config files |
| Setup | Get key from console.anthropic.com | `gh auth login` + `gh auth refresh --scopes copilot` |
| Validation | `sk-ant-*` prefix check | Token validated against models endpoint |

## No Upstream RustyClawd Changes Needed

For the primary Copilot endpoint, RustyClawd works as-is. The `qualify_model()` prefix issue only affects the GitHub Models secondary endpoint and could be addressed separately if needed.

## Implementation Status

- [x] Model catalog verified via live API query (2026-03-12)
- [x] Investigation findings documented
- [x] Config defaults updated — `config.rs`: backend → `"copilot"`, model → `"claude-opus-4.6"`
- [x] Agent definitions updated — 12 files → `claude-opus-4.6`, 1 file → `claude-haiku-4.5`
- [x] Definition.rs default model updated → `claude-opus-4.6` + tests updated
- [x] Tests passing — 40/40 across all 3 crates, clean compile
- [ ] End-to-end validation with `skwaq analyze --quick` (requires binary target)
- [ ] Optional: upstream RustyClawd issue for `qualify_model()` prefix logic
