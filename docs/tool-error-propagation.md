# Tool Error Propagation

Agent tool functions in `tool_executor.rs` propagate database errors to callers
instead of swallowing them. When a graph query fails, the tool returns an
`Err(anyhow::Error)` that flows through the agent runner and surfaces as a
tool-use error in the LLM conversation. Agents receive an explicit failure
signal and can retry or adjust their strategy.

This applies to six tool entry points: `get_callers`, `get_callees`,
`get_taint_paths`, `get_data_sources`, `get_imports`, and `rename_function`.
`get_callers` and `get_callees` share the `execute_get_call_neighbors`
implementation, so five internal functions are modified.

## Why This Matters

Silent tool failures corrupt agent analysis. When `get_data_sources` returns
an empty list due to a query error, the agent concludes "no external inputs
exist" and skips taint analysis entirely. The vulnerability goes unreported —
not because the code is safe, but because the tool lied about it.

With error propagation, the agent sees a tool error and knows the data is
missing. It can retry, use alternative tools, or report that analysis was
incomplete.

## Error Behavior

Every tool function returns `anyhow::Result<serde_json::Value>`. On database
failure, the function:

1. Logs the error at `tracing::error!` level (not `debug!`)
2. Returns `Err(anyhow::anyhow!("descriptive message: {original_error}"))`

The caller chain handles the rest:

| Layer | File | Behavior |
|-------|------|----------|
| Tool executor | `tool_executor.rs` | Returns `Err` with context |
| Agent runner | `runner.rs` | Converts to tool-use error message in LLM conversation |
| Agent traits | `traits.rs` | Wraps as `ClientError::ToolExecution` |
| Gym agentic | `gym/agentic.rs` | Logs error, continues pipeline with reduced context |

Agents already handle tool errors in the LLM protocol — the tool-use error
appears as a message the agent can read and react to. No changes to agent
markdown definitions or runner logic are needed.

## Affected Tools

### get_callers / get_callees

Returns functions that call (or are called by) a target function.

**Before:** Cypher query failure logged at `debug!` level, returned empty list.
SQL prepare failure replaced with a dummy query that returned no rows.

**After:** Cypher query failure returns `Err` with the query error. SQL prepare
failure propagates via `anyhow::Context`. SQL row-read errors propagate instead
of being filtered out with `.filter_map(|r| r.ok())`.

```
// Agent sees this on success:
{"status": "ok", "callers": [{"name": "handle_request", "address": "server.c:42"}]}

// Agent sees this on failure:
Tool error: get_callers cypher query failed: LadybugDB: no such table: ladybug_nodes
```

### get_taint_paths

Returns taint flow paths (source → function → sink) for a target function.

**Before:** Query failure logged at `debug!`, returned empty path list.

**After:** Query failure returns `Err` with the original error message.

```
// Agent sees this on success:
{"status": "ok", "taint_paths": [{"source": "getenv", "sink": "sprintf", "path": "getenv → parse_input → sprintf"}]}

// Agent sees this on failure:
Tool error: get_taint_paths query failed: LadybugDB: connection closed
```

### get_data_sources

Returns all external data inputs (network, file, env, stdin) for the
investigation.

**Before:** Query failure logged at `debug!`, returned empty source list.

**After:** Query failure returns `Err`.

```
// Agent sees this on failure:
Tool error: get_data_sources query failed: LadybugDB: disk I/O error
```

### get_imports

Returns all imported symbols for the investigation.

**Before:** Query failure logged at `debug!`, returned empty import list.

**After:** Query failure returns `Err`.

```
// Agent sees this on failure:
Tool error: get_imports query failed: LadybugDB: table ladybug_edges does not exist
```

### rename_function

Updates a function's display name and decompiled code after variable renaming.

**Before:** Cypher existence checks used `.unwrap_or(false)`, collapsing errors
into "function not found." SQL UPDATE used `.unwrap_or(0)`, collapsing errors
into "0 rows updated."

**After:** All three database operations propagate errors. A failed existence
check returns `Err` instead of falling through to the "not found" branch. A
failed SQL UPDATE returns `Err` instead of reporting zero rows affected.

```
// Agent sees this on failure:
Tool error: rename_function existence check failed: LadybugDB: database is locked
```

## Error Logging

All database errors in the six tool entry points log at `tracing::error!` level.
This makes tool failures visible in production logs and monitoring dashboards.

Previous behavior logged at `tracing::debug!`, which was invisible in default
log configurations and made production diagnosis impossible.

## Testing

Direct unit tests for the `Err` path turned out to be impractical with the
current `GraphDb` design:

- LadybugDB does **not** return `Err` for "label has no nodes" — it returns
  an empty result set, which is the correct happy-path behavior already
  exercised by existing `_empty` and `_isolation` tests.
- Dropping the underlying SQLite tables (`ladybug_nodes`, `ladybug_edges`)
  does not corrupt the embedded LadybugDB store either — LadybugDB owns its
  own in-process state and does not rely on those SQLite tables for the
  tool query paths exercised here.
- Injecting a corrupted/closed DB handle would require refactoring `GraphDb`
  to support dependency injection of the underlying `LadybugGraphDb`, which
  is out of scope for a surgical correctness fix.

The change is therefore covered by:

1. **Existing happy-path unit tests** — verify no regression on `Ok` results
   (e.g., `test_execute_tool_get_callers_empty`, `test_callers_scoped_to_investigation`).
2. **Code review** of the `bail!` / `?` patterns at the five sites.
3. **Integration testing** via `cargo run -- gym run fixtures --quick` before
   the PR is merged, which exercises the full pipeline against real corpora.

A future refactor could parameterize `GraphDb` over its graph backend to
enable mock-based `Err`-path coverage without touching the production code.

## Compatibility

This change is backward-compatible at the agent level. The tool-use protocol
already defines error responses — agents have always been capable of receiving
tool errors. The only behavior change is that tools that previously returned
`{"status": "ok", "callers": []}` on failure now return an error. Agents that
assumed empty results meant "no data" continue to work correctly for the
genuine empty-data case, which still returns `{"status": "ok", ...}` with an
empty list.

The gym benchmark scores are unaffected because the graph database does not
fail during normal benchmark execution. The error paths only trigger on actual
database corruption or connection issues.

## Related Documentation

- [Graph-Agent Architecture](graph-agent-architecture.md) — Tool definitions
  and agent methodology
- [Tool Translate: Cypher Migration](tool-translate-cypher-migration.md) —
  Cypher query pipeline and error handling in `query_graph`
