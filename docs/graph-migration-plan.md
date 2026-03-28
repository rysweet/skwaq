# Code Property Graph Migration: SQLite → Kuzu

> **Status:** Complete — tool execution layer fully migrated to Cypher (see [tool-translate-cypher-migration.md](tool-translate-cypher-migration.md))
> **Issue:** #331
> **Date:** 2025-07-17

## Motivation

The skwaq code property graph (CPG) is stored in SQLite with a schema that
models nodes and edges as relational tables. Graph traversals—call-chain
reachability, taint-path discovery, cross-file dataflow—require recursive CTEs
that are verbose, hard to optimise, and limited to a single recursion pattern
at a time. Kuzu is an embeddable graph database that supports Cypher natively,
handles concurrent readers/writers better than SQLite-WAL, and is purpose-built
for the traversal-heavy workloads that dominate our analysis pipelines.

The module header in `crates/core/src/graph/mod.rs` already reads *"Graph
database layer backed by Kùzu"* and `db.rs` notes the SQLite backend is
intended to be *"swappable to LadybugDB/Kuzu when native linking issues are
resolved."* This plan makes that swap concrete.

---

## 1  Current SQLite Schema

All tables live in `skwaq.db`, created by `ensure_schema()` in
`crates/core/src/graph/db.rs` (lines 63–234).

### 1.1  Node Tables (13)

| Table | Primary Key | Notable Columns |
|-------|------------|-----------------|
| `functions` | `id TEXT` | `name`, `address`, `decompiled`, `confidence REAL`, `language`, `is_reconstructed INT`, `investigation_id`, `parameter_count INT` |
| `basic_blocks` | `id TEXT` | `address`, `size INT`, `function_id` (FK → functions) |
| `data_sources` | `id TEXT` | `name`, `source_type`, `location`, `investigation_id` |
| `data_sinks` | `id TEXT` | `name`, `sink_type`, `danger_level`, `location`, `investigation_id` |
| `vulnerabilities` | `id TEXT` | `title`, `description`, `severity`, `cvss REAL`, `cwe_id`, `function_id`, `evidence`, `confidence REAL`, `investigation_id` |
| `findings` | `id TEXT` | `title`, `evidence`, `agent`, `timestamp`, `investigation_id`, `status`, `cycle_discovered INT`, `cycle_last_updated INT`, `severity`, `category` |
| `cwes` | `id TEXT` | `cwe_id`, `name`, `description` |
| `investigations` | `id TEXT` | `name`, `target`, `status`, `created_at`, `updated_at` |
| `annotations` | `id TEXT` | `target_address`, `text`, `author`, `timestamp`, `investigation_id` |
| `hypotheses` | `id TEXT` | `description`, `status`, `evidence`, `confidence REAL`, `timestamp`, `investigation_id` |
| `agent_actions` | `id TEXT` | `agent`, `action`, `reasoning`, `timestamp`, `investigation_id` |
| `symbols` | `id TEXT` | `name`, `address`, `symbol_type`, `binding`, `investigation_id` |
| `string_literals` | `id TEXT` | `value`, `offset`, `investigation_id` |

### 1.2  Relationship Tables (5 edge-like)

| Table | Columns | Semantics |
|-------|---------|-----------|
| `calls` | `caller_id`, `callee_id` (PK, FKs → functions) | Call-graph edge |
| `contains_block` | `function_id`, `block_id` (PK) | Function → BasicBlock |
| `flows_to` | `from_block`, `to_block` (PK) | Control-flow edge between blocks |
| `taint_flows` | `source_id`, `sink_id` (PK), `path TEXT`, `sanitized INT` | Taint edge Source→Sink |
| `func_references_string` | `function_id`, `string_id` (PK) | Function → StringLiteral |

### 1.3  Indexes

```sql
CREATE INDEX idx_functions_investigation ON functions(investigation_id);
CREATE INDEX idx_functions_name          ON functions(name);
CREATE INDEX idx_calls_caller            ON calls(caller_id);
CREATE INDEX idx_calls_callee            ON calls(callee_id);
CREATE INDEX idx_taint_source            ON taint_flows(source_id);
CREATE INDEX idx_taint_sink              ON taint_flows(sink_id);
CREATE INDEX idx_vulns_investigation     ON vulnerabilities(investigation_id);
```

### 1.4  Write Paths (Graph Builders)

| Builder | File | Tables Written |
|---------|------|---------------|
| Source builder | `builder_source.rs` | `functions`, `calls`, `string_literals`, `symbols`, `data_sources`, `data_sinks`, `flows_to`, `taint_flows` |
| Binary builder | `builder_binary.rs` | `functions`, `symbols`, `data_sources`, `data_sinks`, `string_literals` |
| Ghidra builder | `builder_ghidra.rs` | `functions` (UPDATE `decompiled`), `calls` |
| Shared helpers | `builder.rs` | `functions`, `calls`, `data_sources`, `data_sinks`, `taint_flows` |

All builders use `INSERT OR IGNORE` within transactions.

---

## 2  Current Kuzu Usage

**None.** The `kuzu` crate is not in `Cargo.toml`. No Rust source imports or
references Kuzu beyond comments:

| File | Comment |
|------|---------|
| `Cargo.toml:43` | *"LadybugDB (lbug crate) and kuzu both have CXX-bridge linking issues"* |
| `crates/core/src/graph/db.rs:4-5` | *"Designed to be swappable to LadybugDB/Kuzu when native linking issues are resolved"* |
| `crates/core/src/graph/mod.rs:1` | *"Graph database layer backed by Kùzu."* (aspirational) |

The linking issues noted in these comments were specific to earlier Kuzu
releases. The `kuzu` Rust crate (≥ 0.4) now ships pre-built static libraries
and no longer requires a system-level CXX bridge, making integration feasible.

---

## 3  Queries to Migrate

### 3.1  Recursive CTEs — Taint Path Discovery

Found in two files with identical logic:

- `crates/core/src/analysis/taint.rs:120` — `discover_paths_via_call_graph()`
- `crates/core/src/analysis/perspective_dataflow.rs:112`

```sql
-- Current SQLite recursive CTE
WITH RECURSIVE call_chain(func_id, func_name, path, depth) AS (
    SELECT f.id, f.name, f.name, 0
    FROM functions f WHERE f.id = ?1
  UNION ALL
    SELECT f2.id, f2.name, cc.path || ' -> ' || f2.name, cc.depth + 1
    FROM calls c
    JOIN call_chain cc ON c.caller_id = cc.func_id
    JOIN functions f2  ON c.callee_id = f2.id
    WHERE cc.depth < ?2
)
SELECT func_name, path FROM call_chain WHERE depth > 0
```

The outer loop iterates over every data-source function and checks if any
reachable function name matches a data-sink name.

### 3.2  Cypher → SQL Translator

`crates/core/src/agents/tool_translate.rs` is a pattern-matching translator,
not a parser. It recognises ~12 Cypher-ish patterns (e.g., `MATCH`,
`.name CONTAINS`, `LABELS`, node/relationship keywords) and emits one of ~12
hard-coded SQL templates. Unrecognised `SELECT` statements are passed through
after safety checks (read-only, no comments, table whitelist of 18 tables).

Key templates:

| Pattern trigger | SQL template |
|----------------|--------------|
| Schema / `LABELS` | `UNION ALL` of `SELECT 'tablename', COUNT(*) …` for 6 tables |
| `.name = 'X'` / `.name CONTAINS 'X'` | `SELECT … FROM functions WHERE name LIKE …` |
| `file CONTAINS 'X'` | `SELECT … FROM functions WHERE address LIKE …` |
| Finding / vulnerability keywords | `SELECT … FROM findings ORDER BY severity …` |
| Source keywords | `SELECT … FROM data_sources …` |
| Sink keywords | `SELECT … FROM data_sinks …` |
| Call / relationship keywords | `SELECT f1.name, f2.name FROM calls JOIN functions …` |
| Taint keywords | `SELECT … FROM taint_flows JOIN data_sources JOIN data_sinks …` |
| `SELECT …` passthrough | Whitelist + read-only check, then execute |

### 3.3  Tool Executor Graph Queries

`crates/core/src/agents/tool_executor.rs` dispatches these graph tools:

| Tool | SQL Summary |
|------|-------------|
| `query_graph` | Delegates to `translate_to_sql()` → `execute_read_query()` |
| `read_function` | `SELECT … FROM functions WHERE name = ?` (fallback by address) |
| `get_callers` | `JOIN calls → functions` filtering by callee name |
| `get_callees` | `JOIN calls → functions` filtering by caller name |
| `get_taint_paths` | `JOIN taint_flows → data_sources → data_sinks`, optional location prefix filter |
| `get_cross_file_calls` | Callers + callees filtered to different file prefixes (Rust post-filter) |
| `get_data_sources` | `SELECT … FROM data_sources` |
| `get_imports` | `SELECT … FROM symbols WHERE symbol_type = 'import'` |

### 3.4  Reusable Query Helpers

`crates/core/src/graph/queries.rs` provides read helpers used by CLI commands:
`get_functions`, `get_call_graph`, `get_taint_paths`, `get_vulnerabilities`,
`get_investigations`, `get_dangerous_calls` — all straightforward `SELECT`
queries over the same schema.

---

## 4  Kuzu Schema Design

### 4.1  Node Tables

```cypher
CREATE NODE TABLE Function (
    id STRING,
    name STRING,
    address STRING DEFAULT '',
    decompiled STRING DEFAULT '',
    confidence DOUBLE DEFAULT 0.0,
    language STRING DEFAULT 'unknown',
    is_reconstructed BOOL DEFAULT FALSE,
    investigation_id STRING DEFAULT '',
    parameter_count INT64 DEFAULT 0,
    PRIMARY KEY (id)
);

CREATE NODE TABLE BasicBlock (
    id STRING,
    address STRING,
    size INT64 DEFAULT 0,
    PRIMARY KEY (id)
);

CREATE NODE TABLE DataSource (
    id STRING,
    name STRING,
    source_type STRING DEFAULT '',
    location STRING DEFAULT '',
    investigation_id STRING DEFAULT '',
    PRIMARY KEY (id)
);

CREATE NODE TABLE DataSink (
    id STRING,
    name STRING,
    sink_type STRING DEFAULT '',
    danger_level STRING DEFAULT 'medium',
    location STRING DEFAULT '',
    investigation_id STRING DEFAULT '',
    PRIMARY KEY (id)
);

CREATE NODE TABLE Vulnerability (
    id STRING,
    title STRING,
    description STRING DEFAULT '',
    severity STRING DEFAULT 'medium',
    cvss DOUBLE DEFAULT 0.0,
    cwe_id STRING DEFAULT '',
    evidence STRING DEFAULT '',
    confidence DOUBLE DEFAULT 0.0,
    investigation_id STRING DEFAULT '',
    PRIMARY KEY (id)
);

CREATE NODE TABLE Finding (
    id STRING,
    title STRING,
    evidence STRING DEFAULT '',
    agent STRING DEFAULT '',
    timestamp STRING DEFAULT '',
    investigation_id STRING DEFAULT '',
    status STRING DEFAULT 'new',
    cycle_discovered INT64 DEFAULT 1,
    cycle_last_updated INT64 DEFAULT 1,
    severity STRING DEFAULT '',
    category STRING DEFAULT '',
    PRIMARY KEY (id)
);

CREATE NODE TABLE CWE (
    id STRING,
    cwe_id STRING DEFAULT '',
    name STRING,
    description STRING DEFAULT '',
    PRIMARY KEY (id)
);

CREATE NODE TABLE Investigation (
    id STRING,
    name STRING,
    target STRING DEFAULT '',
    status STRING DEFAULT 'active',
    created_at STRING DEFAULT '',
    updated_at STRING DEFAULT '',
    PRIMARY KEY (id)
);

CREATE NODE TABLE Annotation (
    id STRING,
    target_address STRING DEFAULT '',
    text STRING DEFAULT '',
    author STRING DEFAULT 'user',
    timestamp STRING DEFAULT '',
    investigation_id STRING DEFAULT '',
    PRIMARY KEY (id)
);

CREATE NODE TABLE Hypothesis (
    id STRING,
    description STRING DEFAULT '',
    status STRING DEFAULT 'pending',
    evidence STRING DEFAULT '',
    confidence DOUBLE DEFAULT 0.0,
    timestamp STRING DEFAULT '',
    investigation_id STRING DEFAULT '',
    PRIMARY KEY (id)
);

CREATE NODE TABLE AgentAction (
    id STRING,
    agent STRING DEFAULT '',
    action STRING DEFAULT '',
    reasoning STRING DEFAULT '',
    timestamp STRING DEFAULT '',
    investigation_id STRING DEFAULT '',
    PRIMARY KEY (id)
);

CREATE NODE TABLE Symbol (
    id STRING,
    name STRING,
    address STRING DEFAULT '',
    symbol_type STRING DEFAULT '',
    binding STRING DEFAULT '',
    investigation_id STRING DEFAULT '',
    PRIMARY KEY (id)
);

CREATE NODE TABLE StringLiteral (
    id STRING,
    value STRING,
    offset STRING DEFAULT '',
    investigation_id STRING DEFAULT '',
    PRIMARY KEY (id)
);
```

### 4.2  Relationship Tables

```cypher
-- Call-graph edge
CREATE REL TABLE CALLS (
    FROM Function TO Function
);

-- Control-flow edge between basic blocks
CREATE REL TABLE FLOWS_TO (
    FROM BasicBlock TO BasicBlock
);

-- Function contains basic block
CREATE REL TABLE CONTAINS_BLOCK (
    FROM Function TO BasicBlock
);

-- Taint-flow edge with metadata
CREATE REL TABLE TAINT_FLOW (
    FROM DataSource TO DataSink,
    path STRING DEFAULT '',
    sanitized BOOL DEFAULT FALSE
);

-- Function references a string literal
CREATE REL TABLE REFERENCES_STRING (
    FROM Function TO StringLiteral
);

-- Vulnerability is associated with a function
CREATE REL TABLE HAS_VULNERABILITY (
    FROM Function TO Vulnerability
);
```

### 4.3  Schema Design Notes

- **`investigation_id` stays on nodes** rather than becoming a separate
  `Investigation` → node relationship, because every query filters by it.
  Kuzu node-property filtering is fast enough; adding a rel hop would slow
  every query.
- **`FLOWS_TO`** is between `BasicBlock` nodes (intra-procedural CFG), not
  between functions. The SQLite `flows_to` table stores block-level edges.
- **`TAINT_FLOW`** carries `path` and `sanitized` as relationship properties,
  preserving the SQLite schema's edge metadata.
- **Many-to-many** relationships that were composite-PK tables in SQLite
  (`calls`, `contains_block`, `func_references_string`) become natural Kuzu
  relationship tables.
- **`HAS_VULNERABILITY`** is new — the SQLite schema stores `function_id` as a
  column on `vulnerabilities`. In Kuzu this becomes a first-class relationship
  enabling traversals like "find all functions with critical vulnerabilities."

### 4.4  Type Mapping

| SQLite | Kuzu | Affected Columns |
|--------|------|-----------------|
| `INTEGER` (0/1 booleans) | `BOOL` | `is_reconstructed`, `sanitized` |
| `REAL` | `DOUBLE` | `confidence`, `cvss` |
| `TEXT` | `STRING` | All text columns |
| `INSERT OR IGNORE` | `MERGE` or check-then-insert | Idempotent inserts |
| Foreign keys via columns | Implicit in `REL TABLE` direction | Structural enforcement |

---

## 5  Query Migration Examples

### 5.1  Taint Path Discovery (Recursive CTE → Cypher)

**Before — SQLite recursive CTE** (`taint.rs:120`, `perspective_dataflow.rs:112`):

```sql
WITH RECURSIVE call_chain(func_id, func_name, path, depth) AS (
    SELECT f.id, f.name, f.name, 0
    FROM functions f WHERE f.id = ?1
  UNION ALL
    SELECT f2.id, f2.name,
           cc.path || ' -> ' || f2.name, cc.depth + 1
    FROM calls c
    JOIN call_chain cc ON c.caller_id = cc.func_id
    JOIN functions f2  ON c.callee_id = f2.id
    WHERE cc.depth < ?2
)
SELECT func_name, path
FROM call_chain WHERE depth > 0;
```

**After — Kuzu Cypher:**

```cypher
MATCH p = (start:Function)-[:CALLS*1..10]->(reached:Function)
WHERE start.id = $source_id
RETURN reached.name AS func_name,
       [n IN nodes(p) | n.name] AS path
```

The variable-length path `[:CALLS*1..10]` replaces the recursive CTE entirely.
Depth is controlled by the upper bound (parameterised). The `nodes(p)` list
comprehension replaces the string-concatenated `path` column.

To find taint paths specifically (source function reaches a sink function):

```cypher
MATCH (src:DataSource), (snk:DataSink),
      (srcFn:Function), (snkFn:Function)
WHERE src.name = srcFn.name AND snk.name = snkFn.name
      AND src.investigation_id = $inv_id
MATCH p = (srcFn)-[:CALLS*1..10]->(snkFn)
RETURN src.name AS source, snk.name AS sink,
       [n IN nodes(p) | n.name] AS call_chain
```

### 5.2  Cross-File Call Graph Traversal

**Before — SQLite** (two queries in `tool_executor.rs` + Rust post-filter):

```sql
-- callees
SELECT f2.name, f2.address FROM calls c
JOIN functions f1 ON c.caller_id = f1.id
JOIN functions f2 ON c.callee_id = f2.id
WHERE f1.investigation_id = ?1 AND f1.name = ?2 LIMIT 50;

-- callers (separate query)
SELECT f1.name, f1.address FROM calls c
JOIN functions f1 ON c.caller_id = f1.id
JOIN functions f2 ON c.callee_id = f2.id
WHERE f2.investigation_id = ?1 AND f2.name = ?2 LIMIT 50;
```

Then Rust filters to keep only rows where the address prefix (file) differs.

**After — Kuzu Cypher (single query, cross-file filter in Cypher):**

```cypher
MATCH (f:Function)-[:CALLS]-(other:Function)
WHERE f.name = $func_name
      AND f.investigation_id = $inv_id
      AND substring(f.address, 0, position(':' IN f.address))
       != substring(other.address, 0, position(':' IN other.address))
RETURN other.name, other.address,
       CASE WHEN (f)-[:CALLS]->(other) THEN 'callee' ELSE 'caller' END AS direction
LIMIT 50
```

### 5.3  Agent `query_graph` Tool — Schema Discovery

**Before — SQLite** (`tool_translate.rs` UNION):

```sql
SELECT 'functions' as label, COUNT(*) as count FROM functions
  WHERE investigation_id = ?1
UNION ALL
SELECT 'data_sources', COUNT(*) FROM data_sources
  WHERE investigation_id = ?1
UNION ALL ...
```

**After — Kuzu Cypher:**

```cypher
MATCH (n:Function) WHERE n.investigation_id = $inv_id
RETURN 'Function' AS label, count(n) AS count
UNION ALL
MATCH (n:DataSource) WHERE n.investigation_id = $inv_id
RETURN 'DataSource' AS label, count(n) AS count
UNION ALL
MATCH (n:DataSink) WHERE n.investigation_id = $inv_id
RETURN 'DataSink' AS label, count(n) AS count
```

### 5.4  Agent `query_graph` Tool — Direct Cypher Pass-Through

With Kuzu, the `tool_translate.rs` translator becomes largely unnecessary.
Agent-generated Cypher queries can be passed directly to Kuzu's query engine
with safety checks (read-only validation, parameterised `investigation_id`).
The 12 hard-coded SQL templates can be replaced by a thin Cypher whitelist or
removed entirely, since Kuzu speaks Cypher natively.

### 5.5  Simple Lookups

**Before — `read_function`** (`tool_executor.rs`):

```sql
SELECT id, name, address, decompiled, confidence FROM functions
WHERE name = ?1 AND investigation_id = ?2 LIMIT 1
```

**After:**

```cypher
MATCH (f:Function)
WHERE f.name = $name AND f.investigation_id = $inv_id
RETURN f.id, f.name, f.address, f.decompiled, f.confidence
LIMIT 1
```

### 5.6  Bulk Inserts (Builder Write Path)

**Before — SQLite** (`builder_source.rs`):

```sql
INSERT OR IGNORE INTO functions (id, name, address, language, investigation_id)
VALUES (?1, ?2, ?3, ?4, ?5);
INSERT OR IGNORE INTO calls (caller_id, callee_id) VALUES (?1, ?2);
```

**After — Kuzu:**

```cypher
MERGE (f:Function {id: $1})
ON CREATE SET f.name = $2, f.address = $3, f.language = $4,
              f.investigation_id = $5;

MATCH (a:Function {id: $caller}), (b:Function {id: $callee})
MERGE (a)-[:CALLS]->(b);
```

For bulk ingestion, Kuzu's `COPY FROM` with in-memory CSV buffers can replace
row-by-row inserts for better throughput.

---

## 6  Migration Order

### Phase 1 — Dual-Write  *(estimated: 2–3 PRs)*

**Goal:** Every graph write goes to both SQLite and Kuzu. All reads still come
from SQLite. No user-visible behaviour change.

1. Add `kuzu` crate dependency to `Cargo.toml`. Verify CXX-bridge linking
   succeeds in CI on all target platforms.
2. Create `crates/core/src/graph/db_kuzu.rs` with:
   - `open()` — create/open a Kuzu database directory alongside `skwaq.db`.
   - `ensure_schema()` — execute the `CREATE NODE TABLE` / `CREATE REL TABLE`
     statements from §4.
3. Extend `GraphDb` (or introduce a `DualGraphDb` wrapper) to hold both a
   `rusqlite::Connection` and a `kuzu::Database` + `kuzu::Connection`.
4. Update the write paths in `builder.rs`, `builder_source.rs`,
   `builder_binary.rs`, `builder_ghidra.rs` to call both backends inside
   the existing transaction boundary.
5. All reads remain SQLite — no read-path changes.
6. **Tests:** All 856 existing `#[test]` annotations must pass. Add
   integration tests that verify Kuzu contains the same data as SQLite after
   a build.

### Phase 2 — Read from Kuzu  *(estimated: 3–4 PRs)*

**Goal:** All read queries switch to Kuzu Cypher. SQLite writes continue as a
safety net.

1. Rewrite `taint.rs` and `perspective_dataflow.rs` recursive CTEs as Cypher
   variable-length path queries (§5.1).
2. Rewrite `tool_executor.rs` graph tools (`get_callers`, `get_callees`,
   `get_taint_paths`, `get_cross_file_calls`, etc.) to query Kuzu.
3. Replace or simplify `tool_translate.rs`:
   - Agent Cypher queries can be forwarded to Kuzu directly after safety
     validation.
   - Remove the 12 hard-coded SQL templates.
   - Keep the read-only and injection-prevention checks.
4. Rewrite `queries.rs` helper functions to use Cypher.
5. **Tests:** All existing tests pass. Add Cypher-specific query tests.
   Optionally add a feature flag `--features sqlite-fallback` to toggle the
   read backend during the transition.

### Phase 3 — Remove SQLite  *(estimated: 1–2 PRs)*

**Goal:** SQLite dependency is fully removed from the graph layer.

1. Remove dual-write logic; `builder_*.rs` write only to Kuzu.
2. Remove `db.rs` SQLite schema, `rusqlite` dependency from graph module.
3. Update `GraphDb` to wrap only Kuzu.
4. Remove the feature flag if one was added.
5. Update `Cargo.toml` — remove `rusqlite` if no other module uses it.
   (`crates/gym/src/history.rs` uses its own SQLite DB and is out of scope.)
6. Add a one-time migration utility (`skwaq migrate-graph`) that reads an
   existing `skwaq.db` and populates a Kuzu database directory, for users
   with existing investigation data.
7. **Tests:** All tests pass with Kuzu-only backend.

### Phase Summary

| Phase | Writes | Reads | SQLite? | Kuzu? |
|-------|--------|-------|---------|-------|
| 1 — Dual-Write | SQLite + Kuzu | SQLite | ✅ | ✅ (write-only) |
| 2 — Read from Kuzu | SQLite + Kuzu | Kuzu | ✅ (write-only) | ✅ |
| 3 — Remove SQLite | Kuzu | Kuzu | ❌ | ✅ |

---

## 7  Risks and Mitigations

### 7.1  CXX-Bridge / Native Linking

**Risk:** Earlier Kuzu Rust bindings required a working C++ toolchain and
CXX-bridge, which caused build failures (the exact issue noted in
`Cargo.toml:43`).

**Mitigation:** The `kuzu` crate ≥ 0.4 ships pre-built static libraries for
Linux x86_64 and aarch64. Verify in CI that `cargo build` succeeds on the
project's target platforms before merging Phase 1. If linking fails on a
required platform, evaluate the `kuzu-client` crate (connects over IPC
instead of embedding).

### 7.2  Concurrent Access

**Risk:** SQLite-WAL allows one writer at a time; concurrent writes from
multiple agents or parallel builds can cause `SQLITE_BUSY`.

**Kuzu improvement:** Kuzu supports concurrent read transactions and
serialisable writes with MVCC. Multiple analysis agents can read the graph
simultaneously without blocking. This is a net improvement.

### 7.3  Performance Characteristics

**Risk:** Kuzu's write throughput for bulk node/edge creation may differ from
SQLite `INSERT OR IGNORE` inside a transaction.

**Mitigation:** Kuzu supports `COPY FROM` for bulk ingestion and batched
`CREATE` statements. During Phase 1 dual-write, benchmark both backends. If
Kuzu writes are slower, use `COPY FROM` with in-memory CSV buffers for bulk
builder operations.

**Reads** are expected to be faster for graph traversals (variable-length
paths avoid the recursive CTE overhead) and comparable for simple lookups.

### 7.4  Transaction Semantics

**Risk:** SQLite's `INSERT OR IGNORE` has no direct Kuzu equivalent.

**Mitigation:** Use `MERGE` (create-if-not-exists) for idempotent inserts.
If the Kuzu version does not support `MERGE`, implement a check-then-insert
pattern. Wrap bulk operations in Kuzu transactions.

### 7.5  Backward Compatibility / Data Migration

**Risk:** Users with existing `skwaq.db` files cannot use them after Phase 3.

**Mitigation:** The Phase 3 `skwaq migrate-graph` utility reads SQLite and
writes to Kuzu. During Phase 2, both backends coexist, so users can adopt
gradually. Document the migration path in release notes.

### 7.6  Database Size on Disk

**Risk:** Running two databases simultaneously in Phases 1–2 doubles disk
usage.

**Mitigation:** The CPG is typically small (tens of MB). The dual-write
period is temporary. Acceptable trade-off for safe migration.

### 7.7  Test Coverage

**Risk:** The 856 existing tests may not cover all graph query edge cases
that behave differently between SQLite and Kuzu (e.g., NULL handling,
string collation).

**Mitigation:** Phase 1 adds comparison tests that assert both backends
return identical results for a representative workload. Phase 2 runs the
full test suite against Kuzu reads. Any divergence is caught before Phase 3
removes the fallback.

### 7.8  Agent-Generated Cypher

**Risk:** The `tool_translate.rs` translator is pattern-based. Agents may
generate Cypher that the current translator doesn't handle. Switching to
native Cypher execution changes what agents can and cannot do.

**Mitigation:** In Phase 2, agents send Cypher directly to Kuzu with
safety validation (read-only check, parameterised `investigation_id`,
no mutation statements). This is strictly more capable than the current
12-template translator. Validate that the existing agent test fixtures
produce correct results with native Cypher execution.

### 7.9  Gym Benchmark History

**Risk:** The gym crate (`crates/gym/src/history.rs`) also uses SQLite.

**Mitigation:** Keep gym on SQLite — benchmark history is relational, not
graph data. This is a separate database file; no migration needed.

---

## Appendix A: Files to Modify

| File | Phase | Change |
|------|-------|--------|
| `Cargo.toml` | 1 | Add `kuzu` dependency |
| `crates/core/Cargo.toml` | 1 | Add `kuzu` dependency |
| `crates/core/src/graph/db.rs` | 1–3 | Add Kuzu backend, then remove SQLite |
| `crates/core/src/graph/db_kuzu.rs` | 1 | New file — Kuzu schema + connection |
| `crates/core/src/graph/mod.rs` | 1 | Export new module |
| `crates/core/src/graph/builder.rs` | 1 | Dual-write helpers |
| `crates/core/src/graph/builder_source.rs` | 1 | Dual-write |
| `crates/core/src/graph/builder_binary.rs` | 1 | Dual-write |
| `crates/core/src/graph/builder_ghidra.rs` | 1 | Dual-write |
| `crates/core/src/graph/queries.rs` | 2 | Rewrite to Cypher |
| `crates/core/src/analysis/taint.rs` | 2 | Replace recursive CTE with Cypher |
| `crates/core/src/analysis/perspective_dataflow.rs` | 2 | Replace recursive CTE with Cypher |
| `crates/core/src/agents/tool_translate.rs` | 2 | Replace SQL templates with Cypher pass-through |
| `crates/core/src/agents/tool_executor.rs` | 2 | Switch read queries to Kuzu |
| `crates/core/src/investigation/manager.rs` | 2 | Rewrite investigation CRUD as Cypher |
| `crates/cli/src/commands/taint_cmd.rs` | 3 | Update taint query |
| `crates/cli/src/commands/xrefs_cmd.rs` | 3 | Update cross-reference queries |
| `crates/cli/src/commands/surface_cmd.rs` | 3 | Update attack surface queries |
| `crates/cli/src/commands/ingest.rs` | 3 | Update graph creation path |
| `crates/cli/src/commands/analyze.rs` | 3 | Update finding queries |
