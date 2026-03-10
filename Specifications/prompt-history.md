# Skwaq Prompt History

## Prompt 1 (2026-03-10)

**Prompt**: Implement Phase 8 of the Skwaq project - the remaining CLI commands and simple TUI views (annotate, hypothesize, surface, viz findings, viz callgraph, config show, and update remaining stubs).

**Response**:
- Implemented `skwaq annotate <target> "<text>"` command that inserts annotation nodes linked to the most recent investigation
- Implemented `skwaq hypothesize "<description>"` command that inserts hypothesis nodes with pending status
- Implemented `skwaq surface` command that queries data_sources and data_sinks tables and displays formatted tables
- Implemented `skwaq viz findings` command that displays findings in a formatted table with ID, TITLE, AGENT, EVIDENCE columns
- Implemented `skwaq viz callgraph` command that builds an adjacency list from the calls table and displays as an indented tree with [!] markers for dangerous functions (depth limit 5)
- Implemented `skwaq config show` command that displays all configuration sections from skwaq.toml or defaults
- Implemented `skwaq xrefs <function>` to query callers and callees from the call graph
- Implemented `skwaq taint` to display taint_flows from the database with source/sink filtering
- Implemented `skwaq kb init` (populates 15 CWE entries) and `skwaq kb search` (keyword search against CWE data)
- Updated decompile/disassemble stubs to show Ghidra requirement messages
- Updated find-similar stub to show LLM configuration requirement
- All 32 existing tests pass, cargo build clean

## Prompt 2 (2026-03-10)

**Prompt**: Implement Phases 6 and 7 of the Skwaq project - LLM Integration (Ollama backend, GitHub Copilot backend, LLM factory, agent prompts, VulnHunter wiring) and SARIF Reporting (SARIF output, Markdown report, report command updates).

**Response**:
- Created `crates/core/src/llm/ollama.rs`: OllamaClient implementing LlmClient trait, calls `/api/chat` with tool-calling support, parses tool_calls from response, handles token usage
- Created `crates/core/src/llm/copilot.rs`: CopilotClient implementing LlmClient trait, GitHub token exchange via `gh auth token` or GITHUB_TOKEN env var, calls OpenAI-compatible `chat/completions` endpoint with Copilot session token caching
- Updated `crates/core/src/llm/mod.rs`: re-exports both backends, added `create_llm_client(config)` factory function
- Created `prompts/vuln_hunter.md` and `prompts/critic.md` with agent system prompts
- Rewrote `crates/agents/src/vuln_hunter.rs`: loads prompts from disk, builds analysis context from graph DB (functions, taint flows, dangerous API calls), drives `execute_with_tools` loop with tool executor
- Rewrote `crates/agents/src/critic.rs`: validates findings via LLM tool loop with re-examination tools
- Implemented `crates/core/src/reporting/sarif.rs`: full SARIF v2.1.0 JSON generation with rules, results, locations, severity-to-level mapping, and `generate_sarif_for_investigation()` from DB
- Implemented `crates/core/src/reporting/markdown.rs`: full Markdown report with investigation summary, hardening info, findings table sorted by severity, detailed evidence sections, CWE links
- Updated `crates/cli/src/commands/report.rs` to support `--sarif`, `--markdown` (default), and `--json` format flags
- Added `--markdown` flag to CLI command definitions in `commands/mod.rs`
- All 43 tests passing (11 new tests for LLM backends, SARIF, and Markdown), 0 failures
