---
name: explain-vuln
description: Explain a specific vulnerability finding in detail with remediation guidance. Use when the user wants to understand a finding or how to fix it.
user-invocable: true
---

# Vulnerability Explainer

Explain the vulnerability described by $ARGUMENTS in detail:

1. **What**: Describe the vulnerability type and CWE classification
2. **Where**: Show the exact code location and affected function
3. **How**: Explain how an attacker could exploit this
4. **Impact**: Describe the potential impact (confidentiality, integrity, availability)
5. **Fix**: Provide specific remediation code with before/after examples
6. **Verify**: Suggest how to verify the fix works

Use the investigation database to look up the finding details:
`skwaq report --json`
