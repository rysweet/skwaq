# Skwaq v2: AI-Powered Vulnerability Discovery CLI

## Executive Summary

Skwaq v2 is a Rust CLI that helps security researchers find vulnerabilities in binaries and source code faster. It builds a Code Property Graph from Ghidra's analysis, uses LLM agents to reason about the code, and surfaces the 10 functions most worth investigating - with evidence for why.

It is not a replacement for Ghidra, IDA, or Binary Ninja. It is the layer on top: the reasoning engine that turns hours of manual triage into minutes of directed analysis.

The name "Skwaq" comes from the Lushootseed word for Raven - the trickster who reveals hidden truths.

---

## What Makes This Different

The security tool landscape is crowded. Here's what Skwaq does that existing tools don't:

| Existing Tool | What It Does Well | What Skwaq Adds |
|---|---|---|
| **Ghidra** | Disassembly, decompilation, manual analysis | AI reasoning over the full CPG, automated triage, variant analysis |
| **IDA Pro** | Best decompiler, FLIRT signatures | Free alternative with LLM-enhanced naming, graph-based queries |
| **Joern** | Source-level CPG, Scala queries | Binary-first CPG, natural language queries via LLM, embedded DB |
| **CodeQL** | Powerful pattern queries | AI finds patterns you haven't written queries for |
| **Semgrep** | Fast source pattern matching | Binary analysis, cross-function reasoning |
| **angr** | Symbolic execution | Orchestration layer that combines symbolic results with AI reasoning |

**The unique value**: You describe a vulnerability pattern in natural language. Skwaq translates it to graph queries, finds all structural variants across the codebase, and ranks them by exploitability. No other tool does this.

---

## Design Principles

1. **Complement, don't replace**: Works alongside Ghidra/IDA. Imports their projects. Exports findings back.
2. **Hypothesis-driven**: Security research isn't a pipeline. It's hypothesis → investigate → refine. The tool supports bookmarks, annotations, and "find more like this."
3. **Honest about confidence**: Every finding includes evidence and confidence. No unexplained "this is vulnerable." False positive rate target: <15%.
4. **Fast feedback, deep analysis on demand**: Ghidra output shown immediately. LLM enhancement is async. Symbolic execution is opt-in.
5. **Works offline**: Local LLM support via Ollama. No mandatory cloud dependency.
6. **Single binary + external tools**: Skwaq itself is one binary. Ghidra/angr/Semgrep are external dependencies with explicit health checks.

---

## Core Capabilities

### 1. Binary Ingestion & Hardening Assessment

On ingestion, Skwaq immediately provides:

```
$ skwaq ingest binary ./target_firmware

[checksec] PIE: No | NX: Yes | Canary: No | RELRO: Partial | Fortify: No
[binary]  Format: ELF x86_64 | Stripped: Yes | Sections: 28
[ghidra]  Functions: 1,247 | Strings: 3,891 | Imports: 156
[surface] Network listeners: 3 | File parsers: 7 | IPC handlers: 2
[graph]   Nodes: 48,219 | Edges: 127,844 | Stored in .skwaq/graph/

Ready. Run: skwaq analyze --investigation inv_001
```

Binary hardening assessment (via `checksec.rs` crate) runs on every ingestion:
- PIE, NX, Stack Canary, RELRO, Fortify Source
- ASLR assessment
- Compiler identification
- This is table stakes that every researcher expects.

### 2. Source Ingestion

```
$ skwaq ingest source ./my-project
$ skwaq ingest source https://github.com/org/repo
```

AST parsing via tree-sitter (Rust-native). Supports C, C++, Python, JavaScript, Go, Rust, Java. Builds source-level CPG nodes alongside binary nodes when both are available.

### 3. AI-Enhanced Decompilation

Multi-stage, with each stage independently useful:

**Stage 1 - Ghidra decompilation** (always runs, fast): Raw C pseudocode. Shown immediately.

**Stage 2 - LLM naming & typing** (async, optional): Meaningful function/variable names, type recovery. Implemented via the `decompile-*` agent lane, which uses the explicit `[llm].decompilation` backend instead of borrowing the general reasoning lane. Results appear when ready and failures surface explicitly instead of silently downgrading.

**Stage 3 - Structural verification** (optional, `--verify`): Checks basic block count matches, call graph consistency, all paths accounted for. NOT recompilation (that's unreliable for real-world binaries).

**Confidence scoring** based on structural metrics, not recompilation success:
- Function boundary confidence (Ghidra's analysis quality)
- Decompiler coverage (% of instructions accounted for)
- Name recovery confidence (how much context was available)
- Overall 0.0-1.0 score per function

### 4. The Code Property Graph

Stored in **LadybugDB** - an embedded columnar graph database with full openCypher/GQL support.

**Why LadybugDB**:
- **Embedded**: No server. Database is a directory on disk. Runs in-process.
- **Cypher/GQL compatible**: Full openCypher query language. Queries transferable to/from Neo4j. GQL standards-track.
- **Columnar + vectorized**: Compressed sparse row storage with vectorized execution, optimized for graph traversals and analytical queries.
- **Zero dependencies**: No JVM, no Docker. Single library linked into the Skwaq binary.
- **Portable**: Database is a directory. Copy it, share it, version-control it.
- **Active**: v0.15.1 released March 2026. Successor to KuzuDB with continued development and enterprise support.
- **Consistency with other projects**: We use LadybugDB elsewhere, so graph schemas and tooling are reusable.

**Vector search**: LadybugDB does not have native vector indexes. We handle semantic search with a lightweight sidecar HNSW index (Rust `usearch` crate) that maps embeddings to LadybugDB node IDs. This is a simple key-value mapping, not a complex sync layer.

**Trade-off vs Neo4j**: No APOC graph algorithms (PageRank, betweenness centrality). No concurrent multi-writer. These are acceptable for a single-user CLI tool. If we outgrow it, Cypher compatibility means migration to Neo4j is straightforward.

#### Node Types

**Code Structure**: Function, BasicBlock, Variable, Type, File, Module
**Binary**: Section, Symbol, StringLiteral, Import, CrossReference
**Data Flow**: DataSource, DataSink, TaintPath
**Findings**: Vulnerability, Finding, ExploitPath
**Knowledge**: CWE, CVE, AttackPattern
**Workflow**: Investigation, AgentAction, Annotation, Hypothesis

#### Key: Annotation & Hypothesis Nodes

These support the hypothesis-driven workflow:

```
$ skwaq annotate 0x401234 "Suspicious: reads user length with no bounds check"
$ skwaq hypothesize "parse_tlv has heap overflow via unchecked length field"
$ skwaq investigate validate hyp_001   # Agent tries to confirm/refute
```

Annotations and hypotheses are first-class graph nodes linked to code elements. They persist across sessions and can be exported.

### 5. Variant Analysis (Killer Feature)

The feature that makes researchers switch:

```
$ skwaq find-similar --function parse_tlv
# Finds all functions with structurally similar patterns:
# - reads a length field from input
# - allocates based on that length
# - copies without bounds check

Found 4 variants:
  parse_option    (0x4023a8)  confidence: 0.91  [NOT PATCHED]
  parse_extension (0x404c12)  confidence: 0.87  [NOT PATCHED]
  parse_header    (0x401890)  confidence: 0.72  [PATCHED - has bounds check]
  parse_trailer   (0x405210)  confidence: 0.65  [UNCLEAR - needs review]
```

How it works:
1. User identifies one vulnerable function (or describes a pattern in natural language)
2. Skwaq extracts structural features: call patterns, data flow shape, API usage
3. Vector similarity search + graph pattern matching finds candidates
4. LLM agent validates each candidate and explains why it matches or doesn't
5. Results ranked by similarity and exploitability

Also works for **patch gap analysis**:
```
$ skwaq diff v1.0.bin v1.1.bin --find-unpatched
# Shows what was fixed and finds variants that were missed
```

### 6. Vulnerability Discovery Engine

Three layers, each independently useful:

#### Layer 1: Pattern Detection (seconds)
- Binary hardening gaps (checksec)
- Dangerous API usage (strcpy, sprintf, gets, system)
- Known vulnerable patterns via Semgrep rules (on reconstructed source)
- Custom Cypher queries against the CPG

#### Layer 2: Data Flow Analysis (minutes)
- Taint tracking from attack surface to dangerous sinks
- Cross-function data flow through the CPG
- Sanitization gap detection
- Prioritized by: attack surface exposure × sink danger × path complexity

#### Layer 3: AI Reasoning (minutes to hours, opt-in)
Two agents, not seven:

**VulnHunter**: Given the CPG, taint paths, and decompiled code, reasons about:
- Logic vulnerabilities (auth bypasses, access control failures)
- Cryptographic weaknesses
- Race conditions, TOCTOU
- State machine bugs in protocol implementations
- Anything that doesn't fit a pattern rule

**Critic**: Reviews VulnHunter's findings and:
- Validates evidence (does the code actually do what the finding claims?)
- Checks reachability (can an attacker actually reach this code?)
- Assesses exploitability
- Assigns severity (CVSS-like scoring)
- Filters false positives (target: <15% FP rate)

Every finding includes:
- Specific code location (function + offset/line)
- Evidence trail (which decompiled lines, which data flow path)
- CWE mapping
- Exploitability assessment
- Confidence score

### 7. AI Agent Design

Agents use a simple tool-loop pattern (LLM requests tool calls, Skwaq executes them, results fed back):

**Tools available to agents**:
- `query_graph(cypher)` - Run a Cypher query against the CPG
- `read_function(name_or_addr)` - Read decompiled source for a function
- `get_callers(func)` / `get_callees(func)` - Call graph traversal
- `get_taint_paths(source, sink)` - Taint flow queries
- `lookup_cwe(query)` - Search CWE database
- `check_hardening(binary)` - Get checksec results
- `create_finding(...)` - Record a vulnerability finding
- `search_similar(func, pattern)` - Vector similarity search

**Token budget management**: Agents receive a configurable token budget. Large binaries are analyzed in chunks, prioritized by attack surface proximity. The orchestrator tracks spend and stops when budget is exhausted.

**Prompts loaded from disk** (not compiled in): `~/.skwaq/prompts/vuln_hunter.md`. Editable without recompilation. Bundled defaults as fallback.

### 8. LLM Provider Flexibility

| Provider | Use Case | Config |
|---|---|---|
| **GitHub Copilot API** | Default, free with GitHub sub | `gh auth token` |
| **Azure OpenAI** | Enterprise, higher limits | API key or Entra ID |
| **Ollama (local)** | Air-gapped, privacy-sensitive | `ollama serve` on localhost |
| **OpenAI API** | Direct access | API key |

Configurable per-operation:
```toml
[llm]
reasoning = "copilot"        # For vulnerability analysis
decompilation = "ollama"     # Keep binaries local
embeddings = "ollama"        # For vector search
```

### 9. CLI Interface

```bash
# === Ingestion ===
skwaq ingest binary <path>                 # Ingest binary (runs checksec + Ghidra)
skwaq ingest source <path-or-url>          # Ingest source repository
skwaq ingest sarif <path>                  # Import existing SARIF findings

# === Binary Inspection ===
skwaq decompile <binary> [--function <name>] [--output <dir>]
skwaq disassemble <binary> [--function <addr>]
skwaq strings <binary>                     # Extract and classify strings
skwaq symbols <binary>                     # List symbols and imports
skwaq checksec <binary>                    # Binary hardening assessment
skwaq xrefs <binary> --target <addr>       # Cross-references
skwaq surface <binary>                     # Attack surface enumeration

# === Analysis ===
skwaq analyze <target>                     # Full analysis (patterns + taint + AI)
skwaq analyze <target> --quick             # Patterns + taint only (no AI)
skwaq analyze <target> --budget <tokens>   # Limit AI token spend
skwaq taint --source <func> --sink <func>  # Specific taint trace
skwaq find-similar --function <func>       # Variant analysis
skwaq diff <old> <new> [--find-unpatched]  # Patch gap analysis

# === Investigation (hypothesis-driven) ===
skwaq investigate new <target>             # Start investigation
skwaq investigate resume <id>              # Resume
skwaq investigate list                     # List all
skwaq annotate <addr> "<note>"             # Add annotation
skwaq hypothesize "<description>"          # Record hypothesis
skwaq investigate validate <hyp-id>        # Agent validates hypothesis

# === Reporting ===
skwaq report <investigation-id>            # Markdown report
skwaq report <investigation-id> --sarif    # SARIF for CI/CD
skwaq report <investigation-id> --json     # JSON output

# === Visualization (TUI) ===
skwaq viz callgraph <target>               # Interactive call graph
skwaq viz taint <finding-id>               # Taint flow visualization
skwaq viz decompile --function <name>      # Side-by-side asm/source
skwaq viz findings                         # Finding table (sortable, filterable)

# === Knowledge Base ===
skwaq kb init                              # Initialize CWE/CAPEC knowledge
skwaq kb search <query>                    # Search knowledge

# === System ===
skwaq config show | set <key> <value>
skwaq update [--check | --rollback]
skwaq doctor                               # Check all prerequisites
skwaq version
```

#### The `doctor` Command

Checks all external dependencies with actionable messages:
```
$ skwaq doctor
[ok] Ghidra 11.3 at /opt/ghidra
[ok] Python 3.11 at /usr/bin/python3
[!!] angr not installed. Install: pip install angr
[ok] Semgrep 1.56 at /usr/bin/semgrep
[ok] GitHub token valid (Copilot access confirmed)
[ok] Ollama running at localhost:11434
[ok] LadybugDB database at .skwaq/graph/ (48,219 nodes)
```

### 10. User Corrections

Researchers can correct AI output and corrections propagate:

```
$ skwaq rename-function FUN_00401234 verify_certificate
$ skwaq set-type param_1 "X509_CERT*"
$ skwaq correct-finding finding_003 --false-positive "This path is unreachable because..."
```

Corrections are stored in the graph. The LLM learns from corrections within the session (included in context for subsequent queries). Corrections persist across sessions.

---

## Architecture

```
+------------------------------------------------------------------+
|                    CLI (clap) + TUI (ratatui)                     |
+------------------------------------------------------------------+
|                    Command Router (clap derive)                    |
+------------------------------------------------------------------+
         |              |              |              |
    +--------+    +--------+    +--------+    +--------+
    | Ingest |    | Analyze|    | Report |    | System |
    +--------+    +--------+    +--------+    +--------+
         |              |              |              |
+------------------------------------------------------------------+
|       Agent Tool Loop (RustyClawd core + LlmClient trait)         |
|     LLM calls tools → Skwaq executes → results back → loop       |
+------------------------------------------------------------------+
    |                    |                    |
+----------+      +----------+        +----------+
| VulnHunter|     | Critic   |        | (future  |
| Agent     |     | Agent    |        |  agents) |
+----------+      +----------+        +----------+
         |              |              |
+------------------------------------------------------------------+
|              Analysis Engine (SubprocessTool trait)                |
+------------------------------------------------------------------+
| Ghidra     | angr      | Semgrep   | checksec.rs | tree-sitter  |
| (subprocess)|(subprocess)|(subprocess)| (in-process)| (in-process)|
+------------------------------------------------------------------+
         |                                           |
+------------------------------------------------------------------+
|              LadybugDB (embedded graph DB, Cypher/GQL)             |
|  [Code Nodes] [Binary Nodes] [Flow Edges] [Findings] [Knowledge]|
|  [Annotations] [Hypotheses] [Agent Actions]                      |
+------------------------------------------------------------------+
     |                                               |
+------------------+                   +------------------+
| usearch HNSW     |                   | LLM Client       |
| (vector search)  |                   | (RustyClawd core  |
+------------------+                   |  + LlmClient trait)|
+------------------------------------------------------------------+
| GitHub Copilot | Azure OpenAI | Ollama (local) | OpenAI Direct   |
+------------------------------------------------------------------+
```

### Technology Stack

| Component | Technology | Why |
|---|---|---|
| **Language** | Rust | Single binary, performance, safety |
| **CLI** | clap (derive) | Rust standard, composable |
| **TUI** | ratatui + crossterm | Proven, fast rendering |
| **Graph Database** | LadybugDB (embedded) | Cypher/GQL, columnar, no server, portable |
| **Vector Search** | `usearch` crate (HNSW sidecar) | Fast ANN search, maps to graph node IDs |
| **Binary parsing** | goblin + checksec.rs | Rust-native ELF/PE/Mach-O + hardening checks |
| **Source parsing** | tree-sitter (Rust crate) | Multi-language, fast |
| **Disassembly** | Ghidra headless (subprocess) | Industry standard, free, multi-arch |
| **Symbolic exec** | angr (Python subprocess) | Best-in-class, no Rust equivalent |
| **Pattern matching** | Semgrep (subprocess) | Fast, rule-based, community rules |
| **LLM (cloud)** | GitHub Copilot API / Azure OpenAI | Multi-model, auth via gh CLI |
| **LLM (local)** | Ollama via ollama-rs | Air-gapped support, privacy |
| **Self-update** | Custom (GitHub Releases) | Download, backup, replace, verify |
| **Async** | tokio | Rust standard async runtime |

### Key Design Decisions

1. **Build on RustyClawd's agent infrastructure**: RustyClawd is a proven Rust agent framework with an advanced tool loop, Copilot API client, TUI framework, self-update system, and plugin architecture. Rather than rewriting all of this, Skwaq depends on RustyClawd crates and extends them with security-domain capabilities. We add an `LlmClient` trait abstraction on top to support multiple backends (Copilot, Azure OpenAI, Ollama, OpenAI).

2. **LadybugDB over Neo4j**: Embedded = zero-ops, single binary distribution. Full openCypher/GQL compatibility means queries transfer to/from Neo4j. We already use LadybugDB elsewhere so schemas and tooling are reusable. v0.15.1 (March 2026) is actively maintained. Vector search handled by a lightweight `usearch` HNSW sidecar.

3. **Two agents, not seven**: Start with VulnHunter + Critic. These are the minimum viable agent set. Add specialized agents only when there's evidence they find things the two-agent system misses. Orchestrator logic lives in Rust code, not in an LLM.

4. **SubprocessTool trait**: Every external tool (Ghidra, angr, Semgrep) implements a trait with mandatory: health_check(), version_check(), timeout handling, output validation, resource cleanup. Failures are isolated and retryable.

5. **Complement Ghidra**: Position as a layer on top, not a replacement. Support importing Ghidra project files. Export findings as Ghidra bookmarks.

6. **Async LLM enrichment**: Ghidra decompiler output is shown immediately. LLM-enhanced names/types appear asynchronously. Researchers never wait for AI to do basic work.

7. **Pin RustyClawd to a release tag**: Use a specific version tag (not `main` branch) to avoid breaking changes. Vendor if needed for stability.

---

## Scope: v0.1 vs Future

### v0.1 (What we build first)

- Binary ingestion (ELF + PE) with checksec
- Source ingestion (C, C++, Python, Go)
- Ghidra headless integration with caching
- LLM-enhanced decompilation (naming, typing)
- LadybugDB Code Property Graph
- Taint analysis (Cypher path queries)
- Pattern detection (dangerous APIs, Semgrep)
- VulnHunter + Critic agents
- Variant analysis ("find similar")
- Investigation management with annotations/hypotheses
- SARIF output
- TUI visualizations (callgraph, findings table, decompile view)
- Copilot + Ollama LLM backends
- `skwaq doctor` prerequisite checker
- Content-addressed caching for Ghidra output

### v0.2 (Proven need)

- Mach-O support
- angr symbolic execution integration
- Patch gap analysis (diff --find-unpatched)
- Azure OpenAI backend
- Ghidra project import/export
- Additional tree-sitter languages

### v0.3+ (Future)

- Container image analysis
- Firmware image extraction + recursive analysis
- Cross-binary correlation (shared libraries, IPC)
- SBOM generation
- Binary SCA
- Protocol state machine analysis
- Self-update mechanism
- Plugin/extension system
- Team collaboration (investigation sharing/merging)

---

## Success Criteria

1. **Useful in 30 minutes**: Researcher ingests a binary, gets checksec + attack surface + top-10 suspicious functions with evidence.
2. **Variant analysis works**: Given one vulnerability, finds structural variants with >70% precision.
3. **False positive rate <15%**: Critic agent filters findings effectively.
4. **Faster than manual**: Reduces initial triage from hours to minutes for a typical 1MB binary.
5. **Works offline**: Full functionality with Ollama, no cloud required.
6. **Single binary**: `skwaq` is one file. External tools (Ghidra, etc.) are documented prerequisites.
7. **Researchers keep using it**: The hypothesis/annotation workflow makes it a daily tool, not a one-time scan.

---

## Non-Goals (Explicit)

- **Not a Ghidra replacement**: No GUI, no interactive disassembly. Use Ghidra for that.
- **Not a full SAST tool**: Use CodeQL/Semgrep for comprehensive source scanning.
- **Not a fuzzer**: Use AFL/libFuzzer. Skwaq may integrate fuzzer results in the future.
- **Not a runtime analyzer**: No debugging, no dynamic analysis. Static analysis only (angr is static symbolic execution).
- **Not a vulnerability scanner**: Doesn't scan networks or running services. Analyzes artifacts.
- **Not Windows-native**: Linux and macOS only. Windows users use WSL2.

---

## References

- [LadybugDB](https://ladybugdb.com/) - Embedded columnar graph database (Cypher/GQL)
- [checksec.rs](https://github.com/etke/checksec.rs) - Binary hardening checks in Rust
- [goblin](https://crates.io/crates/goblin) - Rust binary format parser
- [ollama-rs](https://lib.rs/crates/ollama-rs) - Rust Ollama client
- [Ghidra](https://ghidra-sre.org/) - NSA reverse engineering framework
- [angr](https://angr.io/) - Binary analysis and symbolic execution
- [Joern](https://joern.io/) - Code Property Graph (closest competitor)
- [LLM4Decompile](https://github.com/albertan017/LLM4Decompile) - Neural binary decompilation
- [GitHub Copilot Models API](https://docs.github.com/en/rest/models/inference) - LLM inference
- [GitHub Security Lab Taskflow](https://github.blog/security/how-to-scan-for-vulnerabilities-with-github-security-labs-open-source-ai-powered-framework/) - AI variant analysis
- [OpenAI Aardvark](https://openai.com/index/introducing-aardvark/) - AI security agent reference
- [SK2Decompile](https://arxiv.org/pdf/2509.22114) - Two-phase LLM decompilation research
