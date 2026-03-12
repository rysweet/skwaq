# Next Agent Prompt: Skwaq Binary Analysis — Remaining Work

## Context

You are continuing work on skwaq, an AI-powered vulnerability discovery CLI for binaries and source code. The previous agent completed issue #86 (binary analysis capability expansion — all 5 phases), ran benchmark evaluations, and entered the self-improvement loop. Several critical issues were identified that need to be addressed.

**Repository:** `/home/azureuser/src/skwaqr`
**Branch:** Start from `main` (pull latest first)
**Issue tracking:** GitHub issue #28 is the master tracking issue for the gym benchmark harness
**Workflow:** You MUST use the default-workflow (`/dev`) for all non-trivial work. Classify every task.

## Current Benchmark Scores (eval-2026-03-12-v11)

| Benchmark | Cases | F1 | Precision | Recall |
|-----------|-------|-----|-----------|--------|
| Fixtures | 22 | 94.7% | 100% | 90.0% |
| Juliet | 500 | 81.0% | 100% | 68.0% |
| OWASP | 500 | 89.1% | 100% | 80.3% |
| CyberSecEval | 200 | 83.4% | 100% | 71.5% |
| CGC | 200 | 79.1% | 100% | 65.4% |

100% precision (zero false positives) is maintained across all benchmarks. The gap is in recall.

## Critical Issues to Address (Priority Order)

### 1. AUDIT ALL PATTERNS FOR BENCHMARK OVERFITTING (Highest Priority)

The previous agent was caught adding CGC-specific patterns (`cgc_strcat`, `cgc_strcpy`) which is overfitting to the benchmark. While these were replaced with generalized suffix patterns (`\w+_strcpy`, `\w+_strcat`), a comprehensive audit is needed.

**What to do:**
- Read every pattern in `crates/core/src/analysis/patterns_source.rs` (all ~1000 lines)
- Read every pattern in `crates/core/src/analysis/patterns.rs` (the DANGEROUS_APIS list)
- For EACH pattern, ask: "Would this pattern detect the vulnerability in a project I've never seen?"
- Flag any pattern that is specific to a particular benchmark, framework, or naming convention
- Patterns like `\bRuntime\b[^;]*\.exec\s*\(` are GOOD — they detect a class of Java command execution
- Patterns like `\bcgc_receive\s*\(` are BAD — they only match one project's naming convention
- The generalized suffix patterns (`\w+_strcpy`) are ACCEPTABLE — they catch a real class (prefixed wrappers)
- Document your findings in a table: pattern | file:line | verdict (GOOD/OVERFITTING/ACCEPTABLE) | reason

**Files to audit:**
- `crates/core/src/analysis/patterns_source.rs` — all language-specific patterns
- `crates/core/src/analysis/patterns.rs` — DANGEROUS_APIS binary import list
- `crates/gym/src/scoring.rs` — category_to_cwes() mapping (is the CWE mapping biased toward benchmarks?)
- `data/gym/ground_truth/fixtures.toml` — are our fixture CWEs representative of real-world distribution?

### 2. USE AGENTS FOR SEMANTIC PATTERN CLASSES (Strategic Priority)

The current detection is entirely regex-based pattern matching on function names and API calls. This fundamentally cannot detect:
- Logic vulnerabilities (null deref, integer overflow, off-by-one)
- Vulnerabilities in custom code that doesn't call known dangerous APIs
- Inter-procedural taint flow (data flows from input to dangerous operation across functions)
- Context-dependent vulnerabilities (is this strcpy reachable from user input?)

**What to do:**
- The LLM agent pipeline (attack-surface → vuln-hunter → critic in default mode, or the full deep pipeline with exploit-analyst + defense-analyst + verdict-synthesizer) already exists
- The gym currently runs pattern-only detection (`--quick`) for large benchmarks because agent analysis takes ~2 min/case
- Implement a **hybrid scoring mode** where pattern detection runs first (fast), then agent analysis runs on cases where patterns found something suspicious but couldn't confirm, or found nothing but the code looks complex
- The `agentic.rs` dual-judge approach (pattern ∩ LLM) exists but is only used for fixtures — extend it to work efficiently at scale
- Consider: can we run the agent pipeline on just the FALSE NEGATIVE cases from pattern detection? That would be the highest-value use of LLM tokens

**Key files:**
- `crates/gym/src/agentic.rs` — dual-judge pipeline (run_agentic_source_analysis, run_agentic_binary_analysis)
- `crates/core/src/agents/pipeline.rs` — agent pipeline definitions (default_pipeline, deep_pipeline)
- `crates/core/src/agents/runner.rs` — agent execution
- `agents/*.md` — agent definitions (vuln-hunter, attack-surface, critic, etc.)

**Architecture question:** The agents use `create_finding` tool to record findings in the graph DB. The gym's dual-judge intersects pattern findings with LLM findings. Should we change this to: (1) run patterns, (2) run agents ONLY on cases where patterns found 0 findings, (3) union the results? This would improve recall without sacrificing precision, and minimize LLM token spend.

### 3. CLONE AND RUN BINPOOL BENCHMARK (Concrete Task)

BinPool (FSE 2025) is the gold standard binary vulnerability benchmark: 603 real CVEs across 89 CWE classes, 162 Debian packages, 6144 binaries at 4 optimization levels.

**What to do:**
```bash
# Clone BinPool dataset
git clone https://github.com/SimaArasteh/binpool.git ~/.local/share/skwaq/gym/cache/binpool/
touch ~/.local/share/skwaq/gym/cache/binpool/.ready

# Generate ground truth manifest from BinPool metadata
# BinPool has its own metadata format — you'll need to parse it into our fixtures.toml format
# Look at their README and data structure to understand how CVEs map to binaries
```

- Create `data/gym/ground_truth/binpool.toml` manifest by parsing BinPool's metadata
- The adapter already exists at `crates/gym/src/adapters/binpool.rs`
- Run: `skwaq gym run binpool --quick --max-cases 100`
- Record results in eval tag and update issue #28
- Compare with published results from the BinPool paper

### 4. COMPLETE THE ISSUE #28 BODY UPDATE

The issue body was partially updated but still needs:
- The hybrid scores table needs updating (currently shows old F1 values for pattern mode)
- The Fixtures trajectory chart needs the new data points for v8-v11 (22-case expanded suite)
- The Juliet, OWASP, CyberSecEval trajectory charts need new data points
- The "How Does Skwaq Compare?" section needs binary analysis comparison data added
- Add BinPool/BinMetric/VulBinLLM/CveBinarySheet to the research references section
- The PR table needs entries for PRs #87-111

### 5. SELF-IMPROVEMENT LOOP — FOCUS ON RECALL WITHOUT OVERFITTING

The improvement loop should target recall improvements that are GENERALIZABLE, not benchmark-specific.

**Good improvement targets:**
- Integer overflow detection: currently 56% on CyberSecEval CWE-190. The patterns match `atoi`, `atol`, and casts, but miss custom parsing functions that convert strings to integers
- Path traversal: 50% on OWASP CWE-22. The patterns match `new File(getParameter)` but miss indirect flows where the path is stored in a variable first
- Null pointer: 0% across all benchmarks. This is a logic vulnerability — pattern matching cannot detect it. Agents CAN detect it by reasoning about code flow. This is the test case for item #2 above.

**Bad improvement targets (overfitting):**
- Adding patterns for specific function names seen in benchmark code
- Adding patterns that match specific variable names or coding conventions
- Tuning CWE family mappings to match benchmark expectations

**Process for each improvement:**
1. Identify the class of vulnerability being missed (not the specific benchmark case)
2. Design a detection approach that works on ANY code (not just the benchmark)
3. Implement and test on fixtures first
4. Run on the benchmark and measure improvement
5. If improvement is <2pp, the pattern is too narrow — reconsider
6. Commit with clear explanation of WHY this is generalizable

### 6. QUALITY ITEMS FROM PREVIOUS AUDIT

The code review (run by the reviewer agent) found several remaining issues:

**HIGH — Not yet fixed:**
- `compile_single` result silently ignored in Juliet parallel compilation (`juliet.rs:84`). Use AtomicUsize counter or collect failures.
- `collect_crashes` in fuzz_cmd.rs creates dummy crash info with hardcoded "unknown" and "SIGSEGV". Should actually run binary under debugger or at least label as "untriaged".

**MEDIUM — Not yet fixed:**
- `fuzz_cmd.rs` uses `which` command for fuzzer detection — not cross-platform. Use the `which` crate or try running the command.
- `store_crash_data` and `run_fuzz_analyze` use different databases (persistent vs in-memory). Data from standalone `fuzz` is invisible to `fuzz-analyze`.

**LOW — Addressed but worth verifying:**
- `annotations` insert failure in `rename_function` tool — check if this was fixed or if `let _ =` still exists somewhere.

### 7. MISSING TEST COVERAGE

The reviewer noted zero tests for several new modules:
- `crates/cli/src/commands/diff_analyze.rs` — no tests
- `crates/cli/src/commands/fuzz_cmd.rs` — no tests
- `crates/cli/src/commands/investigate_binary.rs` — no tests
- `crates/gym/src/adapters/binpool.rs` — only tests `name()`
- `crates/gym/src/adapters/binmetric.rs` — only tests `name()`

At minimum, add tests for:
- `compute_function_diff()` in diff_analyze.rs (pure function, easy to test)
- `collect_crashes()` in fuzz_cmd.rs (filesystem operation, testable with tempdir)
- `detect_fuzzer()` in fuzz_cmd.rs (should have a test that verifies error message)

### 8. EVAL PROCESS AUTOMATION

The `skwaq gym eval` command exists (merged from another PR) and handles multi-process parallel execution. But it doesn't:
- Run both source AND binary modes (it only runs the default mode)
- Create eval release tags automatically
- Update issue #28 automatically
- Compare with previous eval results

Consider adding a `--tag` flag to `gym eval` that creates a git tag with the results, or a post-eval script that does this.

## Key Architectural Decisions to Make

1. **Pattern matching vs agent analysis:** The current approach is pattern-first, agents-optional. Should it be agents-first with patterns as a fast pre-filter? The 100% precision comes from patterns — will agents maintain it?

2. **Binary vs source tradeoff:** Binary mode improves CGC (+6.4pp) but slightly hurts Fixtures (-1.8pp). Should binary be the default for all suites, or should it be per-suite?

3. **Generalized patterns vs specific patterns:** Where is the line? `\bstrcpy\s*\(` is clearly general. `\w+_strcpy\s*\(` catches wrappers. `\bcgc_strcpy\s*\(` is overfitting. Document the principle.

## Process Requirements

1. **ALWAYS use `/dev` (dev-orchestrator)** for non-trivial work. Classify into Q&A/Operations/Investigation/Development.
2. **Create branches from main** for each piece of work.
3. **Run `cargo test` and `cargo clippy`** before every commit. Pre-commit hooks are installed.
4. **Create PRs with clear descriptions** including test results.
5. **Wait for CI** (fmt + clippy + test + gym-smoke) before merging.
6. **Create eval release tags** after benchmark runs: `eval-YYYY-MM-DD-vN`
7. **Update issue #28** with results after each eval.
8. **Save benchmark results** in release tags in the repo.
9. **Do NOT add benchmark-specific patterns.** Every pattern must detect a CLASS of vulnerability.

## Files You'll Need

```
# Core detection
crates/core/src/analysis/patterns.rs          # DANGEROUS_APIS list (binary imports)
crates/core/src/analysis/patterns_source.rs   # Language-specific source patterns (~1000 lines)
crates/core/src/analysis/patterns_binary.rs   # Binary-level detection (DangerousApiDetector)

# Agent system
crates/core/src/agents/pipeline.rs            # Agent pipelines (default, deep)
crates/core/src/agents/runner.rs              # Agent execution + context building
crates/core/src/agents/tool_executor.rs       # Tool implementations
crates/core/src/agents/tool_definitions.rs    # Tool definitions
agents/*.md                                    # Agent definitions (12 agents)

# Gym/benchmarks
crates/gym/src/agentic.rs                     # Dual-judge analysis pipeline
crates/gym/src/adapters/*.rs                  # Benchmark adapters (7 suites)
crates/gym/src/scoring.rs                     # Scoring engine + CWE mappings
crates/gym/src/lib.rs                         # Gym orchestrator
data/gym/ground_truth/*.toml                  # Ground truth manifests

# CLI
crates/cli/src/commands/gym_cmd.rs            # Gym CLI commands
crates/cli/src/commands/diff_analyze.rs       # Binary diff analysis
crates/cli/src/commands/fuzz_cmd.rs           # Fuzzing commands
crates/cli/src/commands/investigate_binary.rs # Binary investigation
crates/cli/src/commands/doctor.rs             # Dependency checking

# Test fixtures
tests/fixtures/*.c                            # C vulnerability test cases (10 vuln + 5 safe)
tests/fixtures/cpp_vulns.cpp                  # C++ test case
tests/fixtures/multi_file/                    # Multi-file inter-procedural test
tests/fixtures/Makefile                       # Compilation (5 opt levels + stripped)
```

## Success Criteria

1. No benchmark-specific patterns remain in the codebase
2. Agent-based detection is integrated into the gym for at least one benchmark
3. BinPool benchmark is running and producing results
4. All quality issues from the audit are fixed
5. Test coverage added for untested modules
6. Issue #28 body is fully current with all trajectory charts updated
7. At least one eval release tag created with improved results
8. Zero regression in precision (must stay 100% FP=0)
