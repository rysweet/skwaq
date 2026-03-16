---
name: llm-binary-vuln-guide
description: Reference guide for LLM-based vulnerability detection in binary code. Provides best practices, techniques, and prompting strategies for using LLMs to find vulnerabilities in stripped binaries, firmware, and decompiled code. Use when analyzing binaries with AI, writing vulnerability analysis prompts, or optimizing detection pipelines.
user-invocable: false
---

# LLM-Based Binary Vulnerability Detection Guide

This skill provides research-backed techniques for using LLMs to detect
vulnerabilities in binary code. It is loaded automatically when skwaq agents
perform binary analysis to enhance their effectiveness.

## Core Principle: Decompilation First

LLMs cannot effectively reason about raw bytes or assembly. Always decompile to
pseudo-C before LLM analysis. Raw assembly has 98% cosine similarity across
different CWE types, making classification impossible without lifting.

**Pipeline**: Binary → Disassembly → Decompilation (Ghidra) → LLM Enhancement → Vulnerability Analysis

## Decompiled Code Optimization

Before sending decompiled output to an LLM, optimize it:

1. **Variable renaming**: Replace `var_1`, `param_1` with meaningful names inferred from usage context
2. **Type recovery**: Infer struct layouts, array sizes, and pointer types from access patterns
3. **Code restructuring**: Normalize control flow flattened by optimization
4. **Vulnerability annotation**: Mark dangerous API calls, unchecked arithmetic, and trust boundaries

This preprocessing step alone can improve detection accuracy by 20-40% (VulBinLLM, 2025).

## The Two-Prompt Strategy for Patch Diffing

For analyzing patches between binary versions (Bishop Fox, 2025):

**Prompt 1 (Characterization)**:
- Provide decompiled functions from both versions
- Ask the LLM to suggest function names, summarize purpose, and describe changes

**Prompt 2 (Ranking)**:
- Provide security advisory text plus Prompt 1 output
- Ask the LLM to rank functions by relevance to the advisory

This places vulnerable functions in the Top 5 results 100% of the time.

## Evidence-First Prompting

When analyzing decompiled code, require the LLM to:
- Back every claim with a quote from the code, including function name and offset
- Avoid cosmetic rewriting — verify findings against actual code
- Distinguish decompiler artifacts from real vulnerabilities
- Explicitly state confidence level per finding

## Function-Level Analysis with Memory Management

Large binaries exceed context windows. Use a function analysis queue:

1. **Prioritize**: Rank functions by attack surface exposure × sink danger
2. **Analyze individually**: One function per LLM call with relevant caller/callee context
3. **Archive summaries**: Store per-function summaries for cross-function reasoning
4. **Second pass**: Re-analyze high-risk functions with enriched cross-function context

## Hybrid Analysis: LLM + Traditional Tools

The highest-quality results combine LLMs with traditional analysis. Key combinations:

| LLM Strength | Traditional Tool | Combined Approach |
|---|---|---|
| Semantic reasoning | Fuzzing (AFL, libFuzzer) | Fuzzer finds crash sites, LLM reasons about root cause (FirmAgent: 91% precision) |
| Pattern recognition | Symbolic execution (angr) | LLM predicts vulnerable paths, symbex verifies reachability |
| Code understanding | Taint analysis | LLM generates taint propagation rules automatically (LATTE: 37 zero-days) |
| Natural language | SARIF/CodeQL | LLM enriches static analysis findings with exploitability assessment |

## Dangerous API Patterns in Decompiled Code

When reviewing decompiled code, look for these patterns that frequently indicate vulnerabilities:

### Memory Corruption
- `strcpy`/`strcat` with non-constant source (CWE-120)
- `sprintf` with `%s` and user-influenced argument (CWE-134)
- `memcpy` where size derives from attacker-controlled data (CWE-122)
- `malloc` with attacker-influenced size followed by unchecked copy (CWE-122)
- `realloc` to zero (implementation-defined free, CWE-131)

### Use-After-Free / Double-Free
- `free()` followed by access through aliased pointer (CWE-416)
- `free()` in error path, then again in cleanup (CWE-415)
- Pointer stored in global/struct, freed locally, accessed later (CWE-416)

### Integer Issues
- `atoi`/`strtol` result used as allocation size without range check (CWE-190)
- Signed/unsigned comparison in bounds checks (CWE-681)
- Integer truncation on 64→32 bit cast before allocation (CWE-197)

### Command / Code Injection
- `system()` with user-influenced argument (CWE-78)
- `exec*()` family with unsanitized path or arguments (CWE-78)
- `dlopen`/`LoadLibrary` with user-controlled path (CWE-427)

### Firmware / IoT Specific
- Hardcoded credentials in `.rodata` section (CWE-798)
- Default keys/IVs adjacent to crypto function calls (CWE-321)
- `recv`/`read` directly into stack buffer without length check (CWE-121 if stack, CWE-120/CWE-122 otherwise)
  - Verify the destination is actually stack-allocated and that the write can exceed its available size
  - Stack array or `alloca` existence alone is not a vulnerability; confirm the unsafe write path
- UART/serial handlers with no authentication (CWE-306)

## Compiler Optimization Awareness

Decompiled code from optimized binaries (-O2, -O3) exhibits patterns that can
confuse LLMs:

- **Inlined functions**: Dangerous calls may be inlined and harder to spot
- **Loop unrolling**: Bounds checks may be partially eliminated by the compiler
- **Dead store elimination**: Security-relevant memset/bzero of sensitive data may be optimized away (CWE-14)
- **Tail call optimization**: Function boundaries may not match source, affecting call graph analysis

## Prompting Tips for Binary Vulnerability Analysis

1. **Never label code as "malicious"** in the prompt — it introduces analytical bias
2. **Provide CWE definitions** in context for the CWE categories relevant to the binary type
3. **Use explicit iteration**: Force processing of all functions using count/offset — local models stop after ~12 functions otherwise
4. **Decompose for local models**: Cloud models handle comprehensive prompts; local models need smaller, focused tasks
5. **Include caller/callee context**: A function is only vulnerable if reachable from untrusted input — always provide call chain context
6. **Specify architecture**: ARM vs x86 vs MIPS decompilation has different artifacts and calling conventions

## Model Selection Guidance

| Use Case | Recommended | Notes |
|---|---|---|
| Deep vulnerability reasoning | Cloud (Claude Opus/Sonnet) | Best accuracy, $1-35/analysis |
| Function naming/typing | Specialized (LLM4Decompile, ReCopilot) | 13%+ improvement over general LLMs |
| Air-gapped/offline | Ollama (Qwen3:32b, Devstral 24b) | Free, slower, less thorough |
| Batch triage | Cloud (fast tier) | Balance cost and throughput |

Code-specific LLMs outperform general-purpose LLMs by 76.45% on binary analysis
tasks (BinMetric, IJCAI 2025).

## False Positive Management

LLMs generate more false positives than traditional static analyzers. Mitigate by:

1. **Three-Question Test**: Can attacker REACH it? CONTROL the input? Cause REAL HARM?
2. **Multi-agent validation**: VulnHunter finds → Critic validates → only concordant findings reported
3. **Evidence requirement**: Every finding must cite specific code, address, and data flow
4. **Confidence scoring**: Flag low-confidence findings separately for human triage
5. **Decompiler artifact filtering**: Distinguish real vulnerabilities from decompiler noise

## Key References

- VulBinLLM (2025): LLM framework for stripped binary vuln detection — https://arxiv.org/html/2505.22010
- LATTE (2025): LLM-powered static binary taint analysis, 37 zero-days — https://dl.acm.org/doi/10.1145/3711816
- FirmAgent (NDSS 2026): Fuzzing + LLM for IoT firmware, 91% precision — https://www.ndss-symposium.org/ndss-paper/firmagent-leveraging-fuzzing-to-assist-llm-agents-with-iot-firmware-vulnerability-discovery/
- ClearAgent (2025): Agentic binary analysis framework — https://dl.acm.org/doi/10.1145/3759425.3763397
- LLM4Decompile (2024-2025): Open-source decompilation models — https://github.com/albertan017/LLM4Decompile
- Bishop Fox (2025): LLM-powered patch diffing — https://bishopfox.com/blog/vulnerability-discovery-with-llm-powered-patch-diffing
- BinMetric (IJCAI 2025): Binary analysis benchmark — https://arxiv.org/html/2505.07360v1
- DeGPT (NDSS 2024): Decompiler output optimization — https://www.ndss-symposium.org/wp-content/uploads/2024-401-paper.pdf
- Cisco Talos (2025): LLMs as RE sidekick — https://blog.talosintelligence.com/using-llm-as-a-reverse-engineering-sidekick/
- Check Point (2025): Generative AI for RE — https://research.checkpoint.com/2025/generative-ai-for-reverse-engineering/
- NCC Group (2025): AI vs traditional static analysis — https://www.nccgroup.com/research-blog/comparing-ai-against-traditional-static-analysis-tools-to-highlight-buffer-overflows/
