# Skwaq v2 Implementation Plan

## Phase 1: Scaffold + Core Types (compiles, no functionality)
- Cargo workspace with 3 crates (core, agents, cli)
- Error types, config types, binary analysis types
- LlmClient trait + TokenBudget
- SubprocessTool trait
- CLI skeleton with clap (all commands defined, most return "not yet implemented")
- `skwaq version` and `skwaq doctor` work

## Phase 2: Binary Parsing + Checksec (first useful output)
- goblin-based ELF/PE parsing (in-process, no subprocess)
- checksec integration
- `skwaq checksec <binary>` works
- `skwaq strings <binary>` works
- `skwaq symbols <binary>` works

## Phase 3: LadybugDB Graph Layer
- Database open/create with schema
- Graph builder (insert functions, calls, strings, symbols)
- Basic Cypher queries
- Investigation management (create, list, resume)

## Phase 4: Ghidra Integration
- SubprocessTool implementation for Ghidra
- Python post-scripts for function/CFG/decompile extraction
- Content-addressed cache
- `skwaq ingest binary` works end-to-end
- `skwaq decompile` shows Ghidra output

## Phase 5: Analysis Engine
- Dangerous API pattern detection
- Attack surface enumeration
- Taint analysis (Cypher path queries)
- `skwaq analyze --quick` works

## Phase 6: LLM Integration + Agents
- LlmClient implementations (Copilot, Ollama)
- VulnHunter agent with tool loop
- Critic agent
- `skwaq analyze` with AI reasoning works

## Phase 7: Variant Analysis + Reporting
- Vector embedding sidecar (usearch)
- `skwaq find-similar` works
- SARIF output
- Markdown report generation

## Phase 8: TUI + Polish
- Ratatui views (findings, decompile, callgraph)
- Investigation annotations/hypotheses
- User corrections
