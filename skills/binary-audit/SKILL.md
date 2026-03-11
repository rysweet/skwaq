---
name: binary-audit
description: Comprehensive binary security assessment including hardening, attack surface, and vulnerability analysis. Use when analyzing an ELF or PE binary.
allowed-tools: Bash(skwaq *), Read, Grep, Glob
disable-model-invocation: true
---

# Binary Security Audit

Perform a comprehensive security audit of the binary at $ARGUMENTS.

## Steps
1. Run checksec: `skwaq checksec $0`
2. Ingest the binary: `skwaq ingest binary $0`
3. Initialize knowledge base: `skwaq kb init`
4. Map attack surface: `skwaq surface`
5. Run pattern analysis: `skwaq analyze --quick`
6. Run AI-powered analysis: `skwaq analyze`
7. Review findings: `skwaq viz findings`
8. Generate SARIF report: `skwaq report --sarif`

Summarize all findings with severity, CWE mapping, and remediation advice.
