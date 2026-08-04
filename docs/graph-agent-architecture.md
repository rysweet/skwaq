# Graph-Agent-Driven Vulnerability Detection

Skwaq uses a graph-first agent architecture where LLM agents query the Code
Property Graph (CPG) directly to discover vulnerabilities. Agents traverse
taint flows, cross-file call chains, and data source/sink relationships as
their primary detection method. Regex pattern hits serve as hints that direct
agent attention, not as conclusions.

## Architecture Overview

```
Source Code → CPG Builder → LadybugDB Property Graph
                                    │
                           ┌────────┴────────┐
                           │  Enriched        │
                           │  Analysis        │
                           │  Context         │
                           │  ┌─────────────┐ │
                           │  │ Functions    │ │
                           │  │ Imports      │ │
                           │  │ Data Sources │ │
                           │  │ Call Graph   │ │
                           │  │ String Refs  │ │
                           │  │ Source Code  │ │
                           │  └─────────────┘ │
                           └────────┬─────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
              vuln-hunter    attack-surface    taint-tracer
              (graph-first)  (graph-first)    (graph-first)
                    │               │               │
                    └───────────────┼───────────────┘
                                    ▼
                           Agent Tool Calls
                    ┌──────────────────────────┐
                    │ get_taint_paths          │
                    │ get_cross_file_calls     │
                    │ get_data_sources         │
                    │ get_imports              │
                    │ query_graph (Cypher)     │
                    │ read_function            │
                    └──────────────────────────┘
                                    │
                                    ▼
                        Synthesis & Verdict
```

## Analysis Context

When an agent runs, `build_analysis_context()` assembles a structured context
from the CPG. The context has six sections, each with a character budget to
stay within the 100K total limit:

| Section | Budget | Content |
|---------|--------|---------|
| **Functions** | 10K | Function names, addresses, signatures |
| **Imports & Symbols** | 5K | `SELECT name, symbol_type FROM symbols` (LIMIT 50) |
| **Data Sources** | 3K | `SELECT name, source_type, location FROM data_sources` (LIMIT 30) |
| **Cross-File Call Graph** | 8K | 2-hop call chains across file boundaries (LIMIT 40 paths) |
| **String References** | 4K | String literals referenced by functions (LIMIT 30) |
| **Source Code** | 30K | Raw source with line numbers |

### Imports & Symbols

Lists all imported symbols for the investigation, giving agents visibility
into which libraries and APIs the code uses:

```
## Imports & Symbols

| Name | Type |
|------|------|
| stdio.h | import |
| malloc | function |
| free | function |
| sprintf | function |
| getenv | function |
```

Agents use this to quickly identify dangerous API usage (e.g., `sprintf`
without bounds) without scanning raw source.

### Data Sources

Lists all identified data sources — external inputs that could carry
untrusted data:

```
## Data Sources

| Name | Type | Location |
|------|------|----------|
| getenv | environment | main.c:15 |
| argv | command_line | main.c:8 |
| fread | file_input | parser.c:42 |
```

Agents use data sources as starting points for taint analysis. If a function
handles user input but has no data source entry, the agent knows the graph
is incomplete and can flag it.

### Cross-File Call Graph

Shows 2-hop call chains that cross file boundaries. This reveals how
untrusted data flows between compilation units:

```
## Cross-File Call Graph (2-hop)

| Caller (hop 1) | Callee (hop 2) |
|-----------------|----------------|
| parse_input (parser.c) | format_output (formatter.c) |
| read_config (config.c) | execute_query (db.c) |
| handle_request (server.c) | write_log (logger.c) |
```

The file prefix is extracted from each function's `address` field. Only
chains where the two hops span different files are included, since
cross-file flows are the most likely to escape single-file analysis.

### String References

Shows string literals referenced by functions in the investigation:

```
## String References

| Value |
|-------|
| SELECT * FROM users WHERE id = '%s' |
| /bin/sh |
| Content-Type: text/html |
| /tmp/%s |
```

String references are high-signal for vulnerability detection. A function
referencing `"/bin/sh"` or an SQL template with `%s` interpolation is
immediately suspicious.

## Agent Tools

Agents have four graph-query tools in addition to the existing `query_graph`
and `read_function` tools. Each tool accepts a function name (string) or
investigation ID from context.

### `get_taint_paths`

Returns taint flow paths involving a specified function — from data sources
through the function to data sinks.

**Arguments:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `function` | string | yes | Function name to trace (max 256 chars) |

**Returns:** Table of taint paths:

```
| Source | Sink | Path |
|--------|------|------|
| getenv | sprintf | getenv → parse_input → sprintf |
| argv | system | argv → build_cmd → system |
```

**Example agent usage:**

```
I'll check if this function is on any taint paths.
[calls get_taint_paths with function="parse_input"]

The function parse_input sits on a taint path from getenv() to sprintf().
This means untrusted environment data flows through parse_input into an
unbounded format string — confirming the CWE-134 format string vulnerability.
```

### `get_cross_file_calls`

Returns callers and callees of a function that reside in different files.

**Arguments:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `function` | string | yes | Function name to query (max 256 chars) |

**Returns:** Table of cross-file relationships:

```
| Direction | Function | File |
|-----------|----------|------|
| caller | handle_request | server.c |
| callee | execute_query | db.c |
```

**Example agent usage:**

```
Let me check who calls this function from other files.
[calls get_cross_file_calls with function="execute_query"]

execute_query is called from handle_request in server.c. This means
user-facing request data can reach the database query layer. I need to
check whether handle_request sanitizes its input before passing it through.
```

### `get_data_sources`

Returns all data sources for the current investigation.

**Arguments:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `investigation` | string | yes | Investigation ID |

**Returns:** Table of data sources:

```
| Name | Type | Location |
|------|------|----------|
| recv | network | socket.c:31 |
| fgets | stdin | main.c:12 |
| getenv | environment | config.c:8 |
```

### `get_imports`

Returns all imported symbols for the current investigation.

**Arguments:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `investigation` | string | yes | Investigation ID |

**Returns:** Table of imports:

```
| Name | Type |
|------|------|
| stdlib.h | import |
| string.h | import |
| unistd.h | import |
```

## Cypher Query Pipeline in `query_graph`

The `query_graph` tool accepts Cypher queries and executes them against
LadybugDB. The pipeline has two steps:

1. **Raw Cypher** — If the LLM emits valid Cypher, execute it directly
   via `db.cypher_query()`.
2. **Translated Cypher** — If raw execution fails, `translate_to_cypher()`
   pattern-matches the query and emits a safe Cypher string with
   `investigation_id` filtering and `LIMIT` clauses.

If both steps fail, an error is returned to the agent.

### Security Controls

| Control | Description |
|---------|-------------|
| String escaping | All interpolated values pass through `esc()` |
| Investigation scoping | Every generated Cypher includes `WHERE ... investigation_id = '{inv}'` |
| Result limits | Every `RETURN` includes `LIMIT` (20–50 depending on query type) |
| ID validation | `validate_investigation_id()` rejects injection characters |
| No passthrough | Unrecognized patterns are rejected, not executed |

### Error Handling

Cypher errors are returned to the agent as structured messages. Raw
database error strings are sanitized to prevent information leakage
about the graph schema.

See [Tool Translate: Cypher Migration](tool-translate-cypher-migration.md)
for the complete API reference and safety rules.

## Agent Methodology: Graph-First Detection

### vuln-hunter

The vuln-hunter agent uses graph traversal as its primary detection method:

1. **Survey graph context** — Review imports, data sources, and cross-file
   call graph provided in the analysis context
2. **Trace taint paths** — Use `get_taint_paths` for functions that handle
   external data
3. **Follow cross-file calls** — Use `get_cross_file_calls` to trace data
   flow across compilation units
4. **Read suspicious code** — Use `read_function` to examine functions on
   taint paths
5. **Verify with source** — Confirm the vulnerability exists in the actual
   code, not just the graph abstraction
6. **Create finding** — Record confirmed vulnerabilities with evidence chain
   (findings are attributed to the calling agent; see
   [Agent Finding Attribution](agent-finding-attribution.md))

Regex pattern hits from the pattern detector appear in the context as hints.
The agent uses them to direct attention but never treats a pattern match
alone as a confirmed vulnerability. Every finding must have a graph-backed
evidence chain: a concrete path from untrusted input to dangerous operation.

### attack-surface

The attack-surface agent maps entry points using graph structure:

1. **Identify entry points** — Functions with no callers (graph roots) or
   functions referenced by data sources
2. **Map external interfaces** — Use `get_imports` to identify network,
   file, and environment APIs
3. **Trace inbound data** — Use `get_taint_paths` and `get_cross_file_calls`
   to map how external data reaches internal functions
4. **Assess exposure** — Rate each entry point by the number of taint paths
   it feeds and the sensitivity of reachable sinks

## Improvement Loop: Graph-Aware Proposals

The self-improvement loop now generates graph-aware proposals in addition to
regex patterns. The failure-analyst agent prioritizes proposals in this order:

1. **AgentPrompt** — Modify agent instructions to improve graph traversal
   strategy
2. **TaintRule** — Add missing data sources or sinks to expand taint coverage
3. **CweMapping** — Fix CWE family mappings in the scoring engine
4. **NewPattern** — Add regex patterns only when graph-based detection is
   insufficient (e.g., purely syntactic patterns like `gets()` usage)

### AgentPrompt Proposals

Modify an agent's Markdown role card to improve its detection behavior.

```json
{
  "kind": "AgentPrompt",
  "description": "Add TOCTOU awareness to vuln-hunter",
  "target_cwes": [367],
  "target_file": "agents/vuln-hunter.md",
  "patch": {
    "find": "",
    "replace": "## TOCTOU Detection\n\nWhen you see access() or stat() calls..."
  },
  "source_case": "race_condition_toctou",
  "priority": "High"
}
```

When `patch.find` is empty, the new content is appended after the last `##`
heading in the file (or at EOF if no headings exist). When `patch.find`
contains `FIND:` / `REPLACE:` markers, a find/replace operation is performed
instead.

The file path is canonicalized and verified to fall within the `agents/`
directory to prevent directory traversal.

### TaintRule Proposals

Add data sources or sinks to the CPG via database insertion.

```json
{
  "kind": "TaintRule",
  "description": "Add mktemp() as taint source for temp file CWE",
  "target_cwes": [377],
  "patch": {
    "find": "",
    "replace": "mktemp|function|libc_tempfile"
  },
  "source_case": "insecure_tmpfile",
  "priority": "Medium"
}
```

The `patch.replace` field uses pipe-delimited format: `name|source_type|location`.
All three fields are required. Field length limits: name (256), type (64),
location (512). The database ID is generated server-side (`uuid::Uuid::new_v4()`).

The handler executes `INSERT OR IGNORE INTO data_sources` using parameterized
queries — the pipe-delimited format is parsed and validated before any SQL
execution.

### CweMapping Proposals

Modify CWE family mappings via find/replace patching on `scoring.rs`.

```json
{
  "kind": "CweMapping",
  "description": "Map CWE-367 to CWE-362 race condition family",
  "target_cwes": [367],
  "target_file": "crates/gym/src/scoring.rs",
  "patch": {
    "find": "// END CWE FAMILIES",
    "replace": "367 => 362, // TOCTOU → Race Condition\n            // END CWE FAMILIES"
  },
  "source_case": "race_condition_toctou",
  "priority": "High"
}
```

The target file is canonicalized and verified to fall within `crates/gym/src/`.
After patching, `cargo build` must succeed before the change is accepted.

### Heuristic Gap Detection

The heuristic failure analyzer checks for graph context gaps before falling
back to regex-based analysis:

| Gap Type | Detection | Proposal |
|----------|-----------|----------|
| Missing taint flows | Function handles external data but no `taint_flows` rows exist | `TaintRule` — add missing source/sink |
| Sparse call graph | Function has < 2 callers/callees in a multi-file project | `AgentPrompt` — improve cross-file tracing |
| No data sources | Investigation has zero `data_sources` entries | `TaintRule` — add data source entries |
| Unmapped CWE family | Expected CWE has no `cwe_family()` mapping | `CweMapping` — add family mapping |
| Missing regex (default) | No pattern matches and graph analysis is complete | `NewPattern` — add detection pattern |

## Context Budget Management

The total analysis context is capped at 100K characters. Each section
truncates independently at its budget limit with a `[truncated]` marker:

```
## Source Code [30K budget]
... source code with line numbers ...

## Functions [10K budget]
... function table ...

## Imports & Symbols [5K budget]
... symbol table ...
[truncated — 50 row limit reached]

## Data Sources [3K budget]
... data source table ...

## Cross-File Call Graph [8K budget]
... 2-hop call chains ...

## String References [4K budget]
... string literal values ...
```

If a section returns no rows (e.g., no data sources found), it is omitted
entirely — no empty section headers are emitted.

## Configuration

No additional configuration is required. The graph tools use the LadybugDB
property graph that the CPG builder populates during analysis. SQLite is
retained only for the `lookup_cwe` tool (static reference table). The context
budget allocations are compile-time constants.

### Token Budget Impact

The enriched context adds approximately 20K characters in the typical case.
This is offset by reducing the source code section from 40K to 30K characters.
The per-case token budget (50K target, 100K max) remains unchanged.

## Security Model

| Control | Description |
|---------|-------------|
| Cypher escaping | All interpolated values pass through `esc()` — no raw string embedding |
| Investigation scoping | Every Cypher query filters by `investigation_id` — no cross-investigation leakage |
| Sanitized error messages | Database errors are never exposed to agents |
| Path traversal prevention | AgentPrompt/CweMapping file paths are canonicalized and directory-checked |
| TaintRule validation | Pipe-delimited format strictly validated (3 parts, length limits) |
| Server-side UUIDs | TaintRule inserts use `uuid::Uuid::new_v4()`, never agent-provided IDs |
| Function name length cap | Tool arguments capped at 256 characters |
| Per-section truncation | Each context section enforces its own character and row limits |

For the complete security model, see [Gym Safety Hardening](gym-safety-hardening.md).

For a step-by-step guide to running improvement cycles that exercise the
graph-aware proposal pipeline, see [Graph-Agent Gym Cycle](graph-agent-gym-cycle.md).
