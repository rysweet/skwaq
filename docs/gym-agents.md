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
| `query_graph` | Query the Code Property Graph (functions, calls, data flows) |
| `read_function` | Read source/decompiled code for a specific function |
| `lookup_knowledge` | Search the CWE knowledge base |
| `store_memory` | Persist findings/insights for other agents |
| `recall_memory` | Retrieve findings stored by other agents |
| `create_finding` | Register a vulnerability finding |

## Improvement Loop Agents

### failure-analyst

**Purpose:** Diagnoses why vulnerabilities were missed (false negatives).

**Model:** claude-opus-4.6 | **Max turns:** 25

**Input:** False negative cases with source code, expected CWEs, and
knowledge base context.

**Output:** Structured JSON proposals:

```json
[
  {
    "kind": "NewPattern",
    "description": "Add TOCTOU race condition pattern",
    "target_cwes": [367],
    "regex": "\\baccess\\s*\\(",
    "source_case": "race_condition_toctou",
    "priority": "High",
    "rationale": "access() followed by open() is classic TOCTOU"
  }
]
```

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

Primary vulnerability discovery agent. Graph-first approach: queries taint
paths, reads code, traces callers. Rejects theoretical issues without a
concrete trigger path.

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

### critic

Cross-checks findings from other agents. Challenges weak evidence and
identifies logical gaps in vulnerability chains.

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
