---
name: vuln-scan
description: Run a comprehensive vulnerability scan on the current investigation. Use when the user wants to find security vulnerabilities in ingested code or binaries. Combines pattern detection, data flow analysis, and AI reasoning.
allowed-tools: Bash(skwaq *)
disable-model-invocation: true
---

# Vulnerability Scan

Run a comprehensive multi-layer vulnerability analysis on $ARGUMENTS.

## Process
1. Check if an investigation exists, if not suggest `skwaq ingest`
2. Run quick analysis first: `skwaq analyze --quick`
3. Then run AI analysis: `skwaq analyze`
4. Review findings: `skwaq viz findings`
5. Generate report: `skwaq report --sarif`

Report results to the user with severity ratings and remediation advice.
