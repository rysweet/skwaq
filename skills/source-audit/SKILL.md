---
name: source-audit
description: Multi-language source code security audit. Use when analyzing source code for vulnerabilities. Supports Python, JavaScript, Go, Rust, Java, C/C++.
allowed-tools: Bash(skwaq *), Read, Grep, Glob
disable-model-invocation: true
---

# Source Code Security Audit

Analyze source code at $ARGUMENTS for security vulnerabilities.

## Steps
1. Ingest the source: `skwaq ingest source $0`
2. Initialize knowledge base: `skwaq kb init`
3. Run pattern analysis: `skwaq analyze --quick`
4. Run AI analysis with full agent pipeline: `skwaq analyze`
5. Review findings: `skwaq viz findings`
6. For each critical finding, explain the vulnerability and how to fix it

Focus on: injection, deserialization, command execution, XSS, SSRF, path traversal, and authentication/authorization issues.
