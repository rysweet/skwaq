# Skwaq Gym Evaluation Summary

- Generated: 2026-04-13 00:47 UTC
- Cycle commits: `1c2c341b03ceb8823bf22e0108bd247d0208b235` -> `24ad851c97e63a42de7ca42f97f75634f3c0a248`
- Mode: mixed
- LLM backend: copilot
- LLM model: claude-opus-4.6
- Git dirty during runs: true
- Note: this directory contains the completed per-suite artifacts from one broader local gym cycle. The suite-specific logs/JSON files are the source of truth.

| Suite | Mode | Cases | Commit | F1 | Precision | Recall | TP | FP | FN | TN | Status | Note |
|-------|------|-------|--------|----|-----------|--------|----|----|----|----|--------|------|
| juliet | hybrid | 30 | `1c2c341b` | 92.0% | 100.0% | 85.2% | 23 | 0 | 4 | 1 | complete | Broad local validation that surfaced the `PUTENV`/`setenv` CWE-427 gap |
| owasp | hybrid | 30 | `24ad851c` | 100.0% | 100.0% | 100.0% | 16 | 0 | 0 | 14 | complete | Completed on Copilot backend |
| cyberseceval | hybrid | 30 | `24ad851c` | 87.5% | 100.0% | 77.8% | 21 | 0 | 6 | 0 | complete | Completed on Copilot backend |
| cgc | pattern-only | 10 | `24ad851c` | 94.7% | 100.0% | 90.0% | 18 | 0 | 2 | 0 | complete | Hybrid 30-case CGC path was throughput-bound; completed via pattern-only capped follow-up |
