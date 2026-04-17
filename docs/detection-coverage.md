# Detection Coverage: Semantic Classification & CWE Mapping

This document describes the detection coverage model used by skwaq's static
analysis engine — how source patterns are classified into semantic vulnerability
classes, how those classes map to CWE identifiers, and how scoring uses both
layers to evaluate detection accuracy.

## Architecture Overview

Detection flows through three layers:

```
Source Patterns → Semantic Classifier → CWE Scoring
(patterns_source.rs)   (semantic_classifier.rs)   (scoring.rs)
```

1. **Source patterns** fire regex matches against code, producing `DetectedFinding`
   values with a `DangerCategory` and optional function name.
2. **Semantic classification** maps each finding to one or more
   `SemanticPatternClass` values (e.g., `BufferOverflow`, `UnsafeApiUsage`)
   based on the category, title text, and matched function name.
3. **CWE scoring** infers CWE IDs from the semantic class and compares them
   against ground-truth CWEs using family normalization.

A finding is scored as a true positive when any of its inferred CWEs shares a
family with any ground-truth CWE for that test case.

## Semantic Pattern Classes

The `SemanticPatternClass` enum in `semantic_classifier.rs` defines 34
vulnerability classes (as of 2026-03-31). The source pattern engine has 298
patterns across 6 languages:

| Language | Patterns |
|----------|----------|
| C/C++ | 173 |
| Java | 43 |
| Python | 39 |
| JavaScript/TS | 15 |
| Go | 10 |
| Rust | 10 |

Each class has a dedicated recognition function that checks category,
title keywords, and function names.

### UnsafeApiUsage

Detects use of functions that are inherently dangerous regardless of context —
the "banned API" pattern from CWE-676.

**Recognition criteria:**

| Signal | Match |
|--------|-------|
| Category | `"unsafe_code"` |
| Function name | `transmute`, `setuid`, `setgid`, `gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf`, `mktemp`, `tmpnam`, `tempnam` |
| Title keywords | "dangerous function", "potentially dangerous", "unsafe api", "deprecated api", "banned function" |

The function-name list includes all C standard library functions that CERT C
and CWE-676 classify as banned:

- **`gets`** — unbounded read from stdin (CWE-120, CWE-676)
- **`strcpy`, `strcat`** — no bounds checking on destination buffer (CWE-120, CWE-676)
- **`sprintf`, `vsprintf`** — unbounded formatted output (CWE-120, CWE-676)
- **`mktemp`, `tmpnam`, `tempnam`** — predictable temporary file names (CWE-377, CWE-676)
- **`transmute`** — Rust unsafe type coercion
- **`setuid`, `setgid`** — privilege management functions

**CWE coverage:** UnsafeApiUsage maps to CWEs 222, 223, 242, 244, 247, 617, 676.

**Multi-class interaction:** A function like `mktemp` triggers both
`UnsafeApiUsage` and `InsecureTempFile`. The classifier collects all matching
classes and merges their CWE sets, so both CWE-676 and CWE-377 appear in the
inferred set.

### Adding New Banned Functions

To add a new function to the unsafe API list:

1. Edit `is_unsafe_api_usage()` in `semantic_classifier.rs`
2. Add the function name (without parentheses or arguments) to the
   `is_function()` call's array
3. Verify the function is genuinely banned per CERT C / CWE-676 — not merely
   discouraged or having a safer alternative
4. Run `cargo test` to ensure no regressions
5. Run `gym eval --suite fixtures` to measure detection impact

```rust
// Example: adding a new banned function
fn is_unsafe_api_usage(category: &str, title: &str, function_name: &str) -> bool {
    category == "unsafe_code"
        || is_function(function_name, &[
            "transmute", "setuid", "setgid",
            "gets", "strcpy", "strcat", "sprintf", "vsprintf",
            "mktemp", "tmpnam", "tempnam",
        ])
        || contains_any(title, &[
            "dangerous function", "potentially dangerous",
            "unsafe api", "deprecated api", "banned function",
        ])
}
```

**Important:** The `is_function()` helper matches against the normalized
function name extracted from findings. The pattern engine strips trailing
parentheses during `normalize_symbol`, so `gets(` in source becomes `gets` in
the function name field.

## CWE Family Mapping

The `cwe_family()` function in `scoring.rs` normalizes CWE IDs into canonical
families so that related CWEs match during scoring. For example, CWE-120
(Buffer Copy without Checking Size of Input) normalizes to CWE-119 (Improper
Restriction of Operations within the Bounds of a Memory Buffer).

### Key Family Mappings

| Family (canonical CWE) | Member CWEs |
|------------------------|-------------|
| Buffer Overflow (119) | 118, 120–127, 129, 131, 135, 170, 176, 188, 467, 562, 590, 785, 787, 788, 805, 806, 822–825, 839, 843 |
| Injection (74) | 15, 77, 78, 79, 80, 89, 90, 94–96, 114, 116, 501, 643, **918** |
| Integer Overflow (190) | 128, 189, 191–197, 680–682 |
| Unsafe API (676) | 222, 223, 242, 244, 247, 617 |
| Crypto Weakness (327) | 256, 259, 295, 310, 319, 321, 323, 325, 326, 328, 330, 338, 347, 780, 1240 |
| Path Traversal (22) | 23, 36, 426 |
| Race Condition (362) | 364, 366, 367, 832 |
| Use-After-Free (416) | 415, 561, 562, 761, 763 |
| Null Pointer (476) | 252, 253, 690 |
| Resource Leak (401) | 399, 400, 404, 459, 675, 770, 772, 773, 775, 789, 835 |

### SSRF Detection (CWE-918)

Server-Side Request Forgery (CWE-918) is mapped to the **Injection family
(CWE-74)** in `cwe_family()`. This reflects MITRE's classification of SSRF as a
subtype of injection — the attacker injects a crafted URL to make the server
issue requests to unintended destinations.

```rust
// In cwe_family():
918 => 74,  // SSRF → Injection family
```

This mapping enables scoring to count SSRF pattern hits as true positives when
the ground truth specifies CWE-918, because the scoring engine compares at the
family level. Patterns that detect `urlopen`, `urllib.request.urlopen`, or
`requests.get` with user-controlled URLs fire with `DangerCategory::Injection`,
which the semantic classifier maps to `CommandInjection` (CWE-74 family).

### Adding New CWE Mappings

To map a new CWE to an existing family:

1. Identify the correct family by checking MITRE's CWE hierarchy
2. Add the CWE ID to the appropriate match arm in `cwe_family()`
3. If the CWE also needs semantic class coverage, add it to
   `semantic_class_to_cwes()` for the relevant class
4. Run `cargo test` and `gym eval --suite fixtures` to verify

```rust
// Example: mapping CWE-918 (SSRF) to the injection family
pub fn cwe_family(cwe: u32) -> u32 {
    match cwe {
        // ...existing arms...
        // SSRF -> Injection family
        918 => 74,
        // Everything else maps to itself.
        other => other,
    }
}
```

## Scoring Pipeline

The scoring engine evaluates detection quality through these steps:

### 1. CWE Inference Cascade

For each detected finding, CWEs are inferred using a three-level cascade:

```
Explicit CWEs on finding  →  Semantic class CWEs  →  Category CWEs
     (highest priority)         (if no explicit)       (last resort)
```

This is implemented in `inferred_finding_cwes()`:

- If the finding has explicit CWE IDs, use those directly
- Otherwise, classify the finding into semantic classes and collect all
  associated CWEs via `semantic_class_to_cwes()`
- As a last resort, map the `DangerCategory` string to CWEs via
  `category_to_cwes()`

### 2. Family-Level Matching

A finding is a true positive when any inferred CWE shares a family with any
ground-truth CWE:

```
family(inferred_cwe) == family(ground_truth_cwe)  →  TP
```

This avoids requiring exact CWE matches. A `strcpy` pattern that infers
CWE-676 (via UnsafeApiUsage) matches a ground truth of CWE-120 only if both
normalize to the same family — and in this case they do, because CWE-676 maps
to itself (the unsafe API family) while CWE-120 maps to CWE-119 (buffer
overflow). The multi-class system resolves this: `strcpy` triggers both
`UnsafeApiUsage` (CWE-676) and `BufferOverflow` (which includes CWE-120),
ensuring a family match.

### 3. Metrics

| Metric | Formula |
|--------|---------|
| Precision | TP / (TP + FP) |
| Recall | TP / (TP + FN) |
| F1 | 2 × P × R / (P + R) |

The gym tracks these at three granularities: overall, per-CWE, and
per-semantic-class.

## Verifying Detection Changes

After modifying patterns, classifiers, or CWE mappings:

```bash
# 1. Run unit tests
cargo test

# 2. Check for lint issues
cargo clippy

# 3. Evaluate detection on the fixtures benchmark
skwaq gym eval --suite fixtures

# 4. Compare against the last saved baseline
skwaq gym compare
```

The `gym eval` output shows per-case results. Look for:

- **FN → TP transitions** — cases that were missed and are now detected
- **New FP introductions** — cases where a new pattern fires incorrectly
- **Metric changes** — F1, precision, recall deltas

### Regression Gates

The improvement loop enforces automatic regression gates:

| Gate | Threshold |
|------|-----------|
| F1 decrease | 0% (must not decrease) |
| Precision drop | ≤ 2% |
| Per-CWE rate regression | ≤ 2% per individual CWE |

Manual changes bypass the automated gate, so always run `gym eval` and review
results before merging.

## Common Detection Gaps and Fixes

This section documents detection gap categories and their resolution patterns,
based on false negative analysis of the fixtures benchmark.

### Unsafe C API Functions (CWE-676)

**Symptom:** Patterns in `patterns_source.rs` fire on `gets`, `strcpy`, etc.,
but the finding is not scored as a true positive for CWE-676.

**Root cause:** The semantic classifier's `is_unsafe_api_usage()` did not
recognize these function names, so the `UnsafeApiUsage` class (and its CWE-676
mapping) was never applied. The finding fell back to category-level CWE
inference, which may not include CWE-676.

**Fix:** Add the banned function names to the `is_function()` call in
`is_unsafe_api_usage()`.

### SSRF (CWE-918)

**Symptom:** Python SSRF patterns (`urlopen`, `urllib.request`) fire and
produce `DangerCategory::Injection` findings, but CWE-918 ground truths are
not matched.

**Root cause:** CWE-918 was not mapped in `cwe_family()`, so it normalized to
itself (918). Injection findings infer CWE-74 family, but `family(918) = 918 ≠
74`, causing a family mismatch.

**Fix:** Add `918 => 74` to `cwe_family()` to map SSRF into the injection
family.

### Multi-CWE Ground Truths

Some test cases have multiple ground-truth CWEs (e.g., CWE-120 *and* CWE-676).
A finding counts as TP if it matches *any* of them. The multi-class classifier
helps here: a `gets` finding classified as both `BufferOverflow` and
`UnsafeApiUsage` covers both CWE-120 (via buffer overflow family) and CWE-676
(via unsafe API family).
