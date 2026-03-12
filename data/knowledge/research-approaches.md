# Research Approaches to LLM-Assisted Vulnerability Detection

## IRIS (ICLR 2025) — LLM + CodeQL Hybrid
**Paper:** https://arxiv.org/abs/2405.17238

**Key insight:** LLMs alone have high false discovery rates (~85%). CodeQL alone
has low recall (~22%). Combining them yields 2x the detections of CodeQL with
better precision.

**Architecture:**
1. CodeQL generates candidate query results (initial findings)
2. LLM validates each candidate with semantic reasoning
3. LLM suggests new queries for patterns CodeQL missed
4. Iterative refinement between static analysis and LLM

**Results:** 55/120 vulns detected (vs 27 for CodeQL alone), F1=17.7%

**Lesson for Skwaq:** Our dual-judge (pattern ∩ LLM) is architecturally similar.
IRIS suggests we should also let the LLM suggest new patterns — close the loop.

## SafeGenBench — Dual-Judge Scoring
**Paper:** https://www.emergentmind.com/papers/2506.05692

**Key insight:** When evaluating LLM-generated code for vulnerabilities, using
two independent judges (pattern-based + LLM-based) and requiring agreement
dramatically reduces false positives.

**Lesson for Skwaq:** This is exactly our dual-judge approach. Validates the
architecture.

## VulnLLM-R — Specialized Reasoning Model
**Paper:** https://github.com/ucsb-mlsec/VulnLLM-R

**Key insight:** General-purpose LLMs underperform on vulnerability detection
because they lack specialized security reasoning. Fine-tuning on vulnerability
datasets improves performance.

**Lesson for Skwaq:** We can't fine-tune, but we CAN give agents specialized
knowledge through knowledge packs — achieving similar domain expertise
through retrieval rather than training.

## GitHub SecLab Taskflow
**Repo:** https://github.com/GitHubSecurityLab/seclab-taskflow-agent

**Key insight:** Structured workflows for security analysis (similar to our
agent pipeline). Uses task decomposition and specialized agents.

**Lesson for Skwaq:** Validates the multi-agent pipeline approach. Their
workflow is simpler (fewer agents) but less thorough.

## DARPA AI Cyber Challenge (AIxCC, 2025)
Winning systems discovered 77% of presented vulnerabilities, patched 61%.
Found 18 real zero-days (6 in C, 12 in Java).

**Key techniques used by winners:**
- Symbolic execution + LLM reasoning
- Fuzzing guided by LLM-generated seeds
- Automated patch generation and validation
- Multi-model ensemble approaches

**Lesson for Skwaq:** The frontier is approaching human-level automated vuln
detection. Our hybrid approach is on the right track. Fuzzing integration
would be the next major capability gap to close.

## Key Principles from Research

1. **Hybrid > Pure LLM**: Every successful system combines static analysis with LLM reasoning
2. **Dual-judge reduces FPs**: Independent agreement between methods is powerful
3. **Domain knowledge matters**: Specialized knowledge beats general reasoning
4. **Iterative refinement**: Let LLMs and static analysis inform each other
5. **Real-world validation**: Synthetic benchmarks overestimate performance; test on real code
