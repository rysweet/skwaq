# Tool Execution: Cypher-Native Query Layer

> **Status:** Complete (legacy SQL paths removed)
> **Relates to:** [Graph Migration Plan](graph-migration-plan.md), [Graph Agent Architecture](graph-agent-architecture.md)
> **Files:** `crates/core/src/agents/tool_translate.rs`, `crates/core/src/agents/tool_executor.rs`

## Overview

The agent tool execution layer runs all graph queries as native Cypher against
LadybugDB. The legacy SQL paths that existed during the migration window have
been removed. SQLite is retained **only** for the `lookup_cwe` tool, which
queries a static reference table (`cwes`) that has no graph equivalent.

---

## Architecture

### Query Execution Pipeline

`tool_executor.rs` implements a 2-step pipeline for `query_graph` tool calls:

```
LLM query string
       │
       ▼
┌─────────────────────┐
│ 1. Raw Cypher       │  If the LLM emits valid Cypher, run it directly
│    db.cypher_query() │  via LadybugDB.
└──────────┬──────────┘
           │ error
           ▼
┌─────────────────────┐
│ 2. Translated Cypher│  translate_to_cypher() pattern-matches the query
│    db.cypher_query() │  and emits a safe Cypher string.
└─────────────────────┘
```

Both steps use `db.cypher_query()` which routes through LadybugDB's C++ FFI
bridge. There is no SQL retry path — if both steps fail, the tool returns an
error to the agent.

### Backend Routing

All tool handlers route to a single backend:

| Tool | Backend | Notes |
|------|---------|-------|
| `query_graph` | Cypher (2-step pipeline) | — |
| `read_function` | Cypher | `esc()` escaping, `read_function_from_rows()` materializer |
| `rename_function` | Cypher | Two-phase check+execute pattern |
| `get_taint_paths` | Cypher | TAINT_FLOW relationship traversal |
| `get_cross_file_calls` | Cypher | CALLS traversal with file prefix filtering |
| `get_callers` / `get_callees` | Cypher | `investigation_id`-scoped call graph |
| `get_data_sources` / `get_imports` | Cypher | `investigation_id`-scoped |
| `create_finding` | Cypher | Single-write (no dual-write) |
| `search_similar` | Cypher | Single-read (no SQL retry) |
| `lookup_cwe` | **SQLite** | Static reference table, parameterized queries |
| `store_memory` / `recall_memory` | LadybugDB (via MemoryStore) | — |

---

## Module-Internal API

> **Note:** The functions below are `pub(super)` — visible within the `agents`
> module but not part of the external public API. They are documented here for
> contributors working on the translation layer.

### `tool_translate.rs`

#### `translate_to_cypher(query: &str, investigation_id: &str) -> Result<(String, Vec<String>)>`

Translates a natural-language or Cypher-like query into a safe, bounded Cypher
statement. Returns `(cypher_string, column_names)`.

**Pattern matching:** The function recognizes ~12 predefined query patterns
(schema discovery, function lookup, taint analysis, call graph traversal, etc.)
and emits the corresponding Cypher. Unrecognized queries return `Err` — they
are **not** passed through.

**All generated Cypher:**
- Filters by `investigation_id` (no cross-investigation leakage)
- Includes `LIMIT` clauses (default 20–50 depending on query type)
- Uses `esc()` on every interpolated string value

```rust
let (cypher, columns) = translate_to_cypher(
    "MATCH (f:Function) WHERE f.name CONTAINS 'main' RETURN f.name",
    "inv-abc-123",
)?;
// cypher:  "MATCH (f:Function) WHERE f.investigation_id = 'inv-abc-123'
//           AND f.name CONTAINS 'main' RETURN f.name, f.address, ... LIMIT 20"
// columns: ["name", "address", "decompiled", "language"]
```

#### `execute_cypher_read_query(db: &GraphDb, cypher: &str, columns: &[String]) -> Result<Vec<Value>>`

Executes a Cypher query via `db.cypher_query()` and returns the result as a
`Vec<serde_json::Value>` — one JSON object per row, keyed by the column names.

**Critical safety invariant:** Results are materialized into `Vec<Vec<Value>>`
by the `lbug` crate's `.collect()` before any LadybugDB connection is dropped.
This prevents use-after-free in the C++ FFI layer.

```rust
let json = execute_cypher_read_query(&db, &cypher, &columns)?;
// json: [{"name": "main", "address": "0x401000", ...}, ...]
```

#### `execute_create_finding(db: &GraphDb, investigation_id: &str, args: &Value) -> Result<Value>`

Creates a `Finding` node in LadybugDB with properties extracted from the JSON
args. Returns `{"status": "created", "id": "<uuid>"}`.

**Required fields:** `title`
**Optional fields:** `evidence`, `severity`, `category`
**Auto-populated:** `id` (UUID), `agent` (from context), `timestamp` (ISO 8601),
`investigation_id`, `status` ("open"), `cycle_discovered` (0)

#### `execute_search_similar(db: &GraphDb, investigation_id: &str, args: &Value) -> Result<Value>`

Searches for nodes whose `name`, `title`, or `description` fields contain the
search term. Uses `CONTAINS` in Cypher (case-sensitive). Returns a JSON array
of matching nodes across all label types.

**Required fields:** `query` (the search term)
**Optional fields:** `limit` (default 10)

#### `esc(s: &str) -> String`

Escapes a string for safe interpolation into Cypher string literals. Shared
between `tool_translate.rs` (defined, `pub(super)`) and `tool_executor.rs`
(imported). Identical to the implementation in `memory/store.rs`:

```rust
pub(super) fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}
```

**When to use:** Every `format!()` call that interpolates a user-supplied or
LLM-supplied string into a Cypher query MUST pass it through `esc()`. Numeric
values and enum variants may be interpolated directly.

#### `validate_investigation_id(id: &str) -> Result<()>`

Validates that an investigation ID contains only `[a-zA-Z0-9_-]` characters.
Returns `Err` with a descriptive message if validation fails. Called at the
entry point of every public function that accepts an investigation ID.

#### `extract_name_filter(query: &str) -> Option<String>`

Parses patterns like `n.name = 'foo'` or `name CONTAINS 'bar'` from a query
string and returns the filter value.

#### `extract_file_filter(query: &str) -> Option<String>`

Parses patterns like `file CONTAINS 'baz'` or `f.file_path = 'qux'` from a
query string and returns the filter value.

---

### `tool_executor.rs`

#### `execute_tool_with_memory(db, investigation_id, name, args, memory, agent_name) -> Result<Value>`

Main entry point. Dispatches to the appropriate handler based on `name`:

| Tool name | Handler | Backend |
|-----------|---------|---------|
| `query_graph` | `execute_query_graph()` | 2-step Cypher pipeline |
| `read_function` | `execute_read_function()` | Cypher |
| `rename_function` | `execute_rename_function()` | Cypher (check+execute) |
| `get_taint_paths` | `execute_get_taint_paths()` | Cypher |
| `get_cross_file_calls` | `execute_get_cross_file_calls()` | Cypher |
| `get_callers` / `get_callees` | `execute_get_callers/callees()` | Cypher |
| `get_data_sources` / `get_imports` | `execute_get_data_sources/imports()` | Cypher |
| `create_finding` | `execute_create_finding()` | Cypher |
| `search_similar` | `execute_search_similar()` | Cypher |
| `lookup_cwe` | `execute_lookup_cwe()` | SQLite (parameterized) |

#### `read_function_from_rows(rows: &[Vec<lbug::Value>]) -> Vec<Value>`

Helper that materializes LadybugDB row data into owned `serde_json::Value`
objects. All `LadybugGraphDb::as_str()` results are `.to_string()`'d
immediately — this is critical for FFI safety (see Safety Rules below).

```rust
fn read_function_from_rows(rows: &[Vec<lbug::Value>]) -> Vec<Value> {
    rows.iter()
        .filter_map(|row| {
            let name = LadybugGraphDb::as_str(row.get(0)?)?.to_string();
            let addr = LadybugGraphDb::as_str(row.get(1)?)?.to_string();
            // ... materialize all fields to owned Strings
            Some(json!({"name": name, "address": addr, ...}))
        })
        .collect()
}
```

---

## Cypher Query Patterns

### Schema Discovery

```cypher
MATCH (f:Function) WHERE f.investigation_id = '{inv}'
RETURN 'Function' AS table_name, count(f) AS count
UNION ALL
MATCH (d:DataSource) WHERE d.investigation_id = '{inv}'
RETURN 'DataSource' AS table_name, count(d) AS count
UNION ALL ...
```

### Function Lookup

```cypher
MATCH (f:Function)
WHERE f.investigation_id = '{inv}' AND f.name CONTAINS '{name}'
RETURN f.name, f.address, f.decompiled, f.language
LIMIT 20
```

### Function Rename (Two-Phase)

```cypher
-- Phase 1: Check existence
MATCH (f:Function)
WHERE f.investigation_id = '{inv}' AND f.name = '{old_name}'
RETURN f.name
LIMIT 1

-- Phase 2: Execute update (only if phase 1 returned a row)
MATCH (f:Function)
WHERE f.investigation_id = '{inv}' AND f.name = '{old_name}'
SET f.name = '{new_name}'
```

The two-phase pattern avoids holding read references across a mutation
boundary, which would risk use-after-free in the FFI layer.

### Taint Flow Analysis

```cypher
MATCH (s:DataSource)-[t:TAINT_FLOW]->(k:DataSink)
WHERE s.investigation_id = '{inv}'
RETURN s.name, k.name, t.path, t.sanitized
LIMIT 50
```

### Cross-File Calls

```cypher
MATCH (caller:Function)-[:CALLS]->(callee:Function)
WHERE caller.investigation_id = '{inv}'
  AND caller.file_path STARTS WITH '{prefix}'
  AND NOT callee.file_path STARTS WITH '{prefix}'
RETURN caller.name, caller.file_path, callee.name, callee.file_path
LIMIT 50
```

### Callers / Callees

```cypher
-- get_callers
MATCH (caller:Function)-[:CALLS]->(f:Function)
WHERE f.investigation_id = '{inv}' AND f.name = '{name}'
RETURN caller.name, caller.address
LIMIT 20

-- get_callees
MATCH (f:Function)-[:CALLS]->(callee:Function)
WHERE f.investigation_id = '{inv}' AND f.name = '{name}'
RETURN callee.name, callee.address
LIMIT 20
```

### Call Graph Traversal

```cypher
MATCH (caller:Function)-[:CALLS]->(callee:Function)
WHERE caller.investigation_id = '{inv}'
RETURN caller.name, callee.name
LIMIT 100
```

### Finding Creation

```cypher
CREATE (f:Finding {
  id: '{id}', title: '{title}', evidence: '{evidence}',
  agent: '{agent}', timestamp: '{ts}',
  investigation_id: '{inv}', status: 'open',
  cycle_discovered: 0, severity: '{sev}', category: '{cat}'
})
```

### Similarity Search

```cypher
MATCH (n)
WHERE n.investigation_id = '{inv}'
  AND (n.name CONTAINS '{term}' OR n.title CONTAINS '{term}'
       OR n.description CONTAINS '{term}')
RETURN labels(n) AS type, n.name, n.id
LIMIT {limit}
```

---

## Safety Rules

These invariants prevent the memory corruption that caused the revert of commit
`e2b04d22`:

### 1. Immediate Materialization of FFI Values

`LadybugGraphDb::as_str()` returns `&str` that borrows from `lbug::Value`,
which in turn borrows from C++ FFI buffers. **All `as_str()` results must be
`.to_string()`'d immediately** before the row or result set is dropped.

```rust
// CORRECT — owned String before any drop
let name = LadybugGraphDb::as_str(row.get(0)?)?.to_string();

// WRONG — &str may dangle if row is dropped
let name = LadybugGraphDb::as_str(row.get(0)?)?;
do_something_else(); // row could be dropped here
use_name(name); // ← use-after-free
```

The `read_function_from_rows()` helper enforces this pattern for all function
lookups.

### 2. Connection Scoping

LadybugDB connections (`lbug::Connection<'_>`) borrow from the database handle.
Query results reference connection-internal buffers. **All results must be
`.collect()`-ed into owned `Vec` before the connection is dropped.**

```rust
// CORRECT — results materialized before conn drops
pub fn query(&self, cypher: &str) -> Result<Vec<Vec<lbug::Value>>> {
    let conn = self.conn()?;
    let result = conn.query(cypher)?;
    Ok(result.collect())  // materializes into Vec
}

// WRONG — returning an iterator that borrows conn
pub fn query(&self, cypher: &str) -> Result<impl Iterator<Item = Vec<lbug::Value>>> {
    let conn = self.conn()?;
    Ok(conn.query(cypher)?)  // conn dropped, iterator dangles
}
```

### 3. Two-Phase Check+Execute for Writes

Write operations that need to validate state before mutating must use two
separate queries: a read query to check, then an execute query to mutate.
**Never hold read references across a mutation boundary.**

```rust
// CORRECT — two separate operations
let exists = db.cypher_query(&check_cypher)?;
if !exists.is_empty() {
    db.cypher_execute(&update_cypher)?;
}

// WRONG — read ref held during mutation (possible UAF in C++ layer)
let row = db.cypher_query(&check_cypher)?;
if row[0].get(0).is_some() {
    db.cypher_execute(&update_cypher)?;  // C++ state mutated while row refs alive
}
use_row(&row);  // ← dangling
```

### 4. No `unsafe` in tool_translate.rs or tool_executor.rs

All FFI interaction with LadybugDB's C++ core is confined to
`graph/ladybug_db.rs`. The translation and execution layers call
`db.cypher_query()` and `db.cypher_execute()` — never `lbug::` types directly.

### 5. No `.unwrap()` on Row Data

Row values from LadybugDB may be `Null` for optional properties. All extraction
uses `filter_map` with `Option` chaining:

```rust
let rows: Vec<Value> = results
    .iter()
    .filter_map(|row| {
        let name = LadybugGraphDb::as_str(row.get(0)?)?.to_string();
        Some(json!({"name": name}))
    })
    .collect();
```

### 6. String Escaping

Every string interpolated into a Cypher query MUST pass through `esc()`. No
exceptions. This prevents Cypher injection from LLM-generated content.

### 7. Investigation ID Validation

`validate_investigation_id()` is called before any query construction. This
rejects IDs containing quotes, semicolons, or other characters that could
break out of a Cypher string literal even with escaping.

---

## Configuration

No new configuration is required. The migration is transparent to users and
agents.

| Setting | Location | Effect |
|---------|----------|--------|
| `SKWAQ_ROOT` | Environment | Base directory for database files |
| `~/.skwaq/<investigation>/` | Filesystem | LadybugDB WAL storage for investigation graphs |
| `~/.skwaq/memory_graph/` | Filesystem | LadybugDB WAL storage for memory store |

### Corrupted WAL Recovery

If a LadybugDB WAL becomes corrupted (e.g., after a crash during write), the
symptom is `free(): invalid pointer` or `Fatal glibc error: malloc.c` on
startup. Investigation graphs and the memory store use **separate** WAL
directories:

```bash
# Recovery for a specific investigation graph:
rm -rf ~/.skwaq/<investigation>/
# The investigation graph will be recreated on next run.

# Recovery for the memory store:
rm -rf ~/.skwaq/memory_graph/
# The memory store will be recreated on next run.
```

---

## Testing

### Unit Tests

Inline tests in `tool_translate.rs` (`#[cfg(test)]` module) cover:

- **Pattern matching:** Each predefined query pattern produces the expected
  Cypher output
- **Escaping:** `esc()` handles backslashes, single quotes, empty strings,
  and Unicode correctly
- **Validation:** `validate_investigation_id()` accepts valid IDs and rejects
  injection attempts
- **Column extraction:** `extract_name_filter()` and `extract_file_filter()`
  parse filter values from various query formats
- **Translation output:** `translate_to_cypher()` returns correct column lists

### Integration Tests

```bash
cargo test --release -p skwaq-core -- --test-threads=1
```

All 451 tests pass. Use `--test-threads=1` to avoid mmap exhaustion from
concurrent LadybugDB instances (a pre-existing resource limitation, not a bug).

### Lint

```bash
cargo clippy --quiet --release -p skwaq-core -- -D warnings
```

### Runtime Validation

These commands exercise the full agentic pipeline (LLM -> tool call ->
translate -> execute -> LadybugDB FFI -> result marshalling):

```bash
# CGC benchmark — exercises binary analysis + taint flow queries
SKWAQ_ROOT=. ./target/release/skwaq gym run cgc --max-cases 1

# Fixtures benchmark — exercises source analysis + finding creation
SKWAQ_ROOT=. ./target/release/skwaq gym run fixtures --max-cases 2
```

Both must complete without crash. The CGC test is particularly important because
it generates high-volume graph queries through the agentic path that exposed
the original memory corruption in commit `e2b04d22`.

---

## Contributor Checklist

For contributors extending the query translation or execution layer:

- [ ] New Cypher patterns added to `translate_to_cypher()` match block
- [ ] All interpolated strings pass through `esc()`
- [ ] Investigation ID filter included in every `WHERE` clause
- [ ] `LIMIT` clause present on every `RETURN`
- [ ] `as_str()` results `.to_string()`'d immediately (never held as `&str`)
- [ ] Write operations use two-phase check+execute pattern
- [ ] No `unsafe` blocks in tool_translate.rs or tool_executor.rs
- [ ] No `.unwrap()` on row data extraction
- [ ] Unit test added for new pattern
- [ ] `cargo clippy --quiet --release -p skwaq-core -- -D warnings` passes
- [ ] Runtime validation passes (gym run cgc + fixtures)
