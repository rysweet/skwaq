# Agent Finding Attribution

When an agent calls the `create_finding` tool during analysis, the resulting
Finding node in LadybugDB carries an `agent` field identifying which agent
produced it. This field is critical for two purposes:

1. **Inter-agent context passing** — Downstream pipeline stages query findings
   by agent name to assemble context. For example, `runner.rs` collects
   taint-tracer findings to inject into the vuln-hunter prompt.
2. **Audit trail** — Every finding traces back to the agent that created it,
   enabling per-agent accuracy analysis in the gym scoring engine.

## How It Works

### Agent Name Propagation

The agent pipeline runs each agent via one of two runner functions:

| Runner Function | Agent Name Source | Memory Support |
|-----------------|-------------------|----------------|
| `run_agent_with_db` | `agent.name` from the `AgentDefinition` | No |
| `run_agent_with_db_and_memory` | `agent.name` from the `AgentDefinition` | Yes |

Both functions clone the agent's name from its definition and pass it through
the tool execution closure as `Some(&name)`. When the agent calls
`create_finding`, the executor forwards this name to `execute_create_finding`,
which stores it as the `agent` property on the Finding node.

```
AgentDefinition.name ("taint-tracer")
       │
       ▼
run_agent_with_db / run_agent_with_db_and_memory
       │
       ├── clones name before closure
       │
       ▼
execute_tool_with_memory(db, inv, tool, args, memory, Some(&name))
       │
       ▼
execute_create_finding(db, inv, args, agent_name=Some("taint-tracer"))
       │
       ▼
Finding node: { agent: "taint-tracer", title: "...", ... }
```

### Fallback Behavior

If `agent_name` is `None` (e.g., when called from contexts outside the agent
pipeline such as skills or tests), `execute_create_finding` defaults to
`"vuln_hunter"`. This preserves backwards compatibility for callers that do not
have an agent identity.

```rust
// In tool_translate.rs — execute_create_finding
let agent = agent_name.unwrap_or("vuln_hunter");
```

This default exists as a safety net. All pipeline agents pass their real name.

### Downstream Queries

The runner collects findings from specific agents to build context for later
pipeline stages. For example, after the taint-tracer runs, its findings are
queried and injected into the vuln-hunter's prompt:

```rust
// runner.rs — after taint-tracer completes
let mut stmt = db.conn().prepare(
    "SELECT title, evidence, severity, category FROM findings \
     WHERE investigation_id = ?1 \
     AND agent IN ('taint-tracer', 'taint-analyzer', 'orchestrator') \
     AND status != 'invalidated' LIMIT 15",
)?;
```

Correct attribution ensures taint-tracer findings appear in this query. Without
it, taint-tracer findings would be invisible to vuln-hunter.

## Agent Names in the Pipeline

Each pipeline recipe specifies agents by the `name` field in their YAML
frontmatter. These names flow through the system unchanged:

| Recipe | Agent Name | Finding Attribution |
|--------|-----------|---------------------|
| `source.yaml` | `attack-surface` | `agent: "attack-surface"` |
| `source.yaml` | `taint-tracer` | `agent: "taint-tracer"` |
| `source.yaml` | `vuln-hunter` | `agent: "vuln-hunter"` |
| `source.yaml` | `critic` | `agent: "critic"` |
| `source_deep.yaml` | `exploit-analyst` | `agent: "exploit-analyst"` |
| `source_deep.yaml` | `defense-analyst` | `agent: "defense-analyst"` |
| `source_deep.yaml` | `verdict-synthesizer` | `agent: "verdict-synthesizer"` |
| `source_deep.yaml` | `cwe-classifier` | `agent: "cwe-classifier"` |

## Verifying Attribution

Query findings by agent to verify correct attribution:

```bash
# Query the SQLite database directly
sqlite3 skwaq.db "SELECT agent, count(*) AS count FROM findings \
  WHERE investigation_id = 'INV_ID' \
  GROUP BY agent ORDER BY count DESC"
```

Expected output for a source deep pipeline run:

```
vuln-hunter|5
taint-tracer|3
attack-surface|2
verdict-synthesizer|1
```

Every finding's `agent` field matches the agent name from `agents/*.md`.

## Configuration

No configuration is required. Agent names are defined in agent card YAML
frontmatter (`agents/*.md`) and propagated automatically through the pipeline.

## Related Documentation

- [Graph-Agent Architecture](graph-agent-architecture.md) — How agents use
  graph tools for vulnerability detection
- [Gym Agent Definitions](gym-agents.md) — Agent card format and tool reference
- [Analysis Pipeline Recipes](analysis-recipes.md) — Pipeline stage definitions
- [Tool Translate: Cypher Migration](tool-translate-cypher-migration.md) —
  `execute_create_finding` and `execute_tool_with_memory` API reference
