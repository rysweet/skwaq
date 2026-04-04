# Amplihack Agents

<!-- AMPLIHACK_CONTEXT_START -->

## 🎯 USER PREFERENCES (MANDATORY - MUST FOLLOW)

## Amplihack Copilot Workflow Rules

A recipe-managed workflow is already active for this session.

Do NOT invoke `Skill(skill="dev-orchestrator")`, do NOT run `run_recipe_by_name("smart-orchestrator")`, and do NOT reinterpret the current prompt as a new top-level task.

Follow the current prompt exactly. Return only the requested output format. Use tools only when the prompt explicitly requires them.

## User Preferences

# User Preferences

**MANDATORY**: These preferences MUST be followed by all agents. Priority #2 (only explicit user requirements override).

## Autonomy

Work autonomously. Follow workflows without asking permission between steps. Only ask when truly blocked on critical missing information.

## Core Preferences

| Setting             | Value                      |
| ------------------- | -------------------------- |
| Verbosity           | balanced                   |
| Communication Style | (not set)                  |
| Update Frequency    | regular                    |
| Priority Type       | balanced                   |
| Collaboration Style | autonomous and independent |
| Auto Update         | ask                        |
| Neo4j Auto-Shutdown | ask                        |
| Preferred Languages | (not set)                  |
| Coding Standards    | (not set)                  |

## Workflow Configuration

**Selected**: DEFAULT_WORKFLOW (`@~/.amplihack/.claude/workflows/DEFAULT_WORKFLOW.md`)
**Consensus Depth**: balanced

Use CONSENSUS_WORKFLOW for: ambiguous requirements, architectural changes, critical/security code, public APIs.

## Behavioral Rules

- **No sycophancy**: Be direct, challenge wrong ideas, point out flaws. Never use "Great idea!", "Excellent point!", etc. See `@~/.amplihack/.claude/context/TRUST.md`.
- **Quality over speed**: Always prefer complete, high-quality work over fast delivery.

## Learned Patterns

<!-- User feedback and learned behaviors are added here by /amplihack:customize learn -->

## Managing Preferences

Use `/amplihack:customize` to view or modify (`set`, `show`, `reset`, `learn`).

<!-- AMPLIHACK_CONTEXT_END -->


