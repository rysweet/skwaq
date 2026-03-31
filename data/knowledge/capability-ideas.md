# Capability Improvement Ideas — 2026-03-31

## Cross-Validation: No Overfitting Detected
- CyberGym (never used in improvement cycles): F1=71.9% — unchanged from baseline
- All improvements generalize: CyberSecEval +8.4%, CGC +7.3% without degrading other suites
- 100% precision maintained across ALL suites

## 5 Creative Approaches to Boost Detection

### 1. Wrapper-Aware Taint Resolution Agent
**Priority: HIGH (best effort-to-impact ratio)**
Pre-analysis pass that resolves thin wrapper functions to their underlying dangerous sinks.
Identifies functions with single call chains to printf/exec/SQL, rewrites conceptual call graph.
- Addresses: CWE-134 format string (70% → 85-90%), CWE-78 injection through wrappers
- Complexity: Low-Medium
- How to test: Count format_string FN cases where the sink is behind 1-2 wrapper layers

### 2. Trust-Boundary Propagation Pack (KG Enrichment)
**Priority: HIGH (highest ceiling)**
Pre-analysis graph enrichment that annotates nodes with trust domain labels.
Identifies servlet entry points, IPC endpoints, deserialization boundaries.
Propagates "taint-from-untrusted" labels forward through call graph.
- Addresses: CWE-501 trust boundary (0% → 40-60%), CWE-200/201 info exposure
- Complexity: Medium
- How to test: Run OWASP CWE-501 cases with trust annotations vs without

### 3. Sensitivity-Classifier + Information-Flow Agent (Two-Stage)
**Priority: MEDIUM**
Stage 1: LLM classifies variables as sensitive (passwords, keys, tokens, PII).
Stage 2: Traces whether classified sensitive data reaches output sinks.
Separates sensitivity detection from flow analysis.
- Addresses: CWE-200/201 information exposure (60% → 80-85%)
- Complexity: Medium
- How to test: Run CGC cases with CWE-200 ground truth, compare with/without sensitivity roster

### 4. Negative-Space Auditor Agent
**Priority: MEDIUM (high FP risk)**
Post-processing stage that detects absence of required security operations.
For each sensitive buffer, checks if clearing function called before free/return.
- Addresses: CWE-226 missing memory clearing (0% → 70%)
- Complexity: Medium
- How to test: Run Juliet CWE-226 cases, measure TP/FP ratio carefully

### 5. Type-Lineage Agent
**Priority: LOW (high complexity)**
Traces type information propagation across function boundaries.
Builds "type lineage map" tracking casts, pointer arithmetic, size calculations.
- Addresses: CWE-188 memory layout, CWE-196 type conversion
- Complexity: High
- How to test: Run Juliet CWE-196 cases with type annotations vs without
