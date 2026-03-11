---
name: compare-binaries
description: Compare two binaries for security differences. Use for patch analysis or regression testing.
allowed-tools: Bash(skwaq *), Read
disable-model-invocation: true
---

# Binary Comparison

Compare security posture of two binaries: $0 and $1.

## Steps
1. Run checksec on both binaries:
   - `skwaq checksec $0`
   - `skwaq checksec $1`
2. Compare hardening differences
3. Ingest both and compare function counts, imports, strings
4. Identify functions present in one but not the other (patch analysis)
5. Report security improvements and regressions
