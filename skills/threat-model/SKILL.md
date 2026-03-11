---
name: threat-model
description: Generate a threat model for the analyzed target. Use after ingesting a binary or source code to understand the threat landscape.
user-invocable: true
---

# Threat Model Generator

Generate a threat model for the current investigation.

## Process
1. Review the attack surface: `skwaq surface`
2. Review findings: `skwaq viz findings`
3. Identify threat actors (who would attack this?)
4. Map attack vectors (how could they attack?)
5. Assess risks using STRIDE methodology:
   - **S**poofing - can identity be faked?
   - **T**ampering - can data be modified?
   - **R**epudiation - can actions be denied?
   - **I**nformation Disclosure - can data leak?
   - **D**enial of Service - can it be crashed?
   - **E**levation of Privilege - can access be escalated?
6. Prioritize threats by likelihood and impact
7. Suggest mitigations for top threats
