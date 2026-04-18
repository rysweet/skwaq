# Gym Agent Definitions

The improvement loop and analysis pipeline use LLM agents defined as Markdown
role cards in the `agents/` directory. Each agent has a YAML frontmatter
header and a prompt body.

## Agent Card Format

```yaml
---
name: agent-name
description: "What this agent does"
model: claude-opus-4.6
tools:
  - query_graph
  - read_function
  - lookup_knowledge
  - store_memory
  - recall_memory
  - create_finding
max_turns: 25
output_schema: optional-schema-name
role:
  title: "Human-readable role"
  expertise:
    - area1
    - area2
  focus:
    - aspect1
  skepticism:
    - be critical of X
  evidence_preferences:
    - prefer Y type evidence
---

## Agent Prompt

You are [Agent], a [specialist]. Your job is to [task].
...
```

### Frontmatter Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Agent identifier (used in code to load the card) |
| `description` | yes | One-line description |
| `model` | yes | LLM model (`claude-opus-4.6`, `claude-haiku-4.5`) |
| `tools` | yes | List of tools the agent can call |
| `max_turns` | yes | Maximum tool-call turns before termination |
| `output_schema` | no | Named schema for structured output validation |
| `role` | no | Structured role metadata for synthesis weighting |

### Available Tools

| Tool | Description |
|------|-------------|
| `query_graph` | Query the Code Property Graph (Cypher or SQL SELECT) |
| `read_function` | Get source/decompiled code by name or address |
| `get_taint_paths` | Trace taint flows through a function (source → sink paths) |
| `get_cross_file_calls` | Find callers/callees in different files |
| `get_data_sources` | List all data sources for an investigation |
| `get_imports` | List all imported symbols for an investigation |
| `get_callers` | Return all functions calling a specified function |
| `get_callees` | Return all functions called by a specified function |
| `lookup_cwe` | Look up CWE by ID with description and mitigations |
| `lookup_knowledge` | Search the CWE knowledge base and knowledge packs |
| `store_memory` | Persist findings/insights for other agents |
| `recall_memory` | Retrieve findings stored by other agents |
| `create_finding` | Register a vulnerability finding (attributed to the calling agent) |
| `search_similar` | Find code patterns similar to a snippet |

The graph-query tools (`get_taint_paths`, `get_cross_file_calls`,
`get_data_sources`, `get_imports`) are the primary discovery mechanism.
Agents should use these tools first, then use `query_graph` for
custom queries and `read_function` for source-level confirmation. See
[Graph-Agent Architecture](graph-agent-architecture.md) for details.

## Improvement Loop Agents

### failure-analyst

**Purpose:** Diagnoses why vulnerabilities were missed (false negatives).

**Model:** claude-opus-4.6 | **Max turns:** 25

**Input:** False negative cases with source code, expected CWEs, graph
context (imports, data sources, call graph, string references), and
knowledge base context.

**Output:** Structured JSON proposals, prioritized by type:

```json
[
  {
    "kind": "AgentPrompt",
    "description": "Add TOCTOU detection instructions to vuln-hunter",
    "target_cwes": [367],
    "target_file": "agents/vuln-hunter.md",
    "source_case": "race_condition_toctou",
    "priority": "High",
    "rationale": "vuln-hunter lacks instructions to trace access/open sequences"
  },
  {
    "kind": "TaintRule",
    "description": "Add mktemp as taint source",
    "target_cwes": [377],
    "source_case": "insecure_tmpfile",
    "priority": "Medium",
    "rationale": "mktemp return value is untrusted but not tracked as taint source"
  }
]
```

**Proposal priority order:**
1. `AgentPrompt` — improve agent graph traversal strategy
2. `TaintRule` — expand taint coverage with missing sources/sinks
3. `CweMapping` — fix CWE family mapping gaps
4. `NewPattern` — add regex patterns only when graph detection is insufficient

**Graph gap detection** (heuristic classification):
- Missing taint flows for functions handling external data → `TaintRule`
- Sparse cross-file call graph → `AgentPrompt`
- No data sources in investigation → `TaintRule`
- Unmapped CWE family → `CweMapping`
- No graph gap found → `NewPattern` (default)

**Anti-overfitting rules** (built into the prompt):
- Reject patterns that match benchmark-specific naming (e.g., `test_case_*`)
- Reject patterns that only match a single fixture
- Prefer patterns grounded in CWE documentation or real CVEs

### overfitting-reviewer

**Purpose:** Gates proposals to prevent benchmark overfitting.

**Model:** claude-opus-4.6 | **Max turns:** 20

**Input:** List of proposals from the failure analyst.

**Output:** Review decisions per proposal:

```json
{
  "verdict": "Accept",
  "reason": "TOCTOU via access() is well-documented (CWE-367)",
  "overfitting_risk": "Low",
  "real_world_applicability": "High",
  "suggested_modification": null
}
```

**Review criteria:**
- Does the pattern match real-world vulnerable code, not just test fixtures?
- Is the CWE mapping consistent with MITRE definitions?
- Could this increase false positives on typical codebases?
- Is the pattern too narrow (only catches the exact fixture)?

## Analysis Pipeline Agents

### vuln-hunter

Primary vulnerability discovery agent. Uses graph traversal as its primary
detection method:

1. Survey imports, data sources, and cross-file call graph from context
2. Trace taint paths with `get_taint_paths` for functions handling external data
3. Follow cross-file calls with `get_cross_file_calls` to trace data across files
4. Read suspicious code with `read_function` for source-level confirmation
5. Create findings only with graph-backed evidence chains

Regex pattern hits appear as hints in context but are never treated as
confirmed vulnerabilities. Every finding requires a concrete path from
untrusted input to dangerous operation.

**Tools:** `query_graph`, `read_function`, `get_taint_paths`,
`get_cross_file_calls`, `get_data_sources`, `get_imports`, `get_callers`,
`get_callees`, `lookup_cwe`, `lookup_knowledge`, `store_memory`,
`recall_memory`, `create_finding`, `search_similar`

### exploit-analyst

Evaluates whether detected findings are actually exploitable. Outputs
structured exploit scores with confidence levels.

### defense-analyst

Checks for mitigations that make findings safe (bounds checks, sanitization,
safe API wrappers). Cross-checks exploit-analyst findings.

### verdict-synthesizer

Final evidence-weighting synthesizer. Resolves disagreement between
exploit-analyst and defense-analyst. Handles confidence threshold hints:

| Hint | Meaning |
|------|---------|
| `HIGH_CONFIDENCE_CONFIRM` | Strong exploit signal + defense agreement |
| `REVIEW_REQUIRED` | Ambiguous — do not auto-confirm |
| `LIKELY_SAFE` | Defense evidence outweighs exploit evidence |

### cwe-classifier

Validates and corrects CWE classifications on findings. Ensures detected
CWEs match the actual vulnerability type.

### attack-surface

Maps entry points and external interfaces using graph structure:

1. Identify entry points — functions with no callers (graph roots) or
   functions referenced by data sources
2. Map external interfaces — use `get_imports` to find network, file, and
   environment APIs
3. Trace inbound data — use `get_taint_paths` and `get_cross_file_calls`
   to map how external data reaches internal functions
4. Assess exposure by taint path count and sink sensitivity

**Tools:** `query_graph`, `read_function`, `get_taint_paths`,
`get_cross_file_calls`, `get_data_sources`, `get_imports`, `get_callers`,
`get_callees`, `lookup_knowledge`, `store_memory`, `recall_memory`,
`create_finding`

### critic

Cross-checks findings from other agents. Challenges weak evidence and
identifies logical gaps in vulnerability chains.

## Specialized Agents

### decompile-renamer

Renames decompiler-generated variables (var_1, param_1) to meaningful names
before vulnerability analysis. Runs as the first pipeline stage for binary
analysis.

### decompile-analyst

Analyzes decompiled code quality, identifies compiler optimization artifacts,
and provides context for vulnerability assessment in binary targets.

### vuln-hunter-java

Java-specialized vulnerability hunter. Understands servlet APIs, JNDI,
deserialization, JDBC patterns. Used for OWASP Benchmark cases.

### vuln-hunter-python

Python-specialized vulnerability hunter. Handles pickle deserialization,
eval/exec, subprocess, SQL injection via string formatting.

### crash-analyst

Analyzes crash dumps and fuzzer output to identify exploitable conditions.
Used in CyberGym (OSS-Fuzz) and CGC (DARPA) benchmarks.

### taint-tracer

Traces data flow from untrusted sources to dangerous sinks across function
boundaries. Uses get_taint_paths and get_cross_file_calls tools. Findings
created by taint-tracer carry `agent: "taint-tracer"` in the database, enabling
downstream agents (vuln-hunter) to query and incorporate taint analysis results.
See [Agent Finding Attribution](agent-finding-attribution.md).

### patch-diff-analyst

Analyzes patch diffs to identify what was fixed and infer the vulnerability
type. Used in CyberGym where patch.diff is available.

### results-skeptic

Post-analysis agent that challenges findings for false positive reduction.
Questions whether each finding is truly exploitable.

## Adding a New Agent

1. Create a Markdown file in `agents/` with YAML frontmatter
2. Define the role, tools, and prompt
3. Reference the agent name in the relevant code path
4. Test with `skwaq agents list` to verify the card loads

```bash
skwaq agents list
# Shows all agent cards with role titles and output schemas
```

Keep agent prompts focused on a single responsibility. The synthesis layer
handles cross-agent coordination — individual agents should not try to
do everything.

## Related Documentation

- [Graph-Agent Gym Cycle](graph-agent-gym-cycle.md) — Running improvement
  cycles that generate AgentPrompt proposals to tune agent behavior
- [Agent Finding Attribution](agent-finding-attribution.md) — How findings
  are attributed to the agent that created them
- [Graph-Agent Architecture](graph-agent-architecture.md) — How agents use
  graph tools for vulnerability detection
