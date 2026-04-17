# Gym API Reference

Internal Rust API for the `skwaq-gym` crate. This documents the public types
and functions used by the improvement loop, scoring engine, and benchmark
adapters.

## Improvement Engine (`improve.rs`)

### `run_improvement_cycle`

```rust
pub async fn run_improvement_cycle(
    adapter: &dyn BenchmarkAdapter,
    config: &BenchmarkConfig,
    data_dir: &Path,
    runtime_config: &skwaq_core::config::Config,
    profile_name: Option<&str>,
) -> Result<ImprovementCycle>
```

Runs one full improvement cycle: benchmark, analyze false negatives, generate
proposals, review for overfitting, and return accepted proposals.

**Returns** an `ImprovementCycle` containing the baseline score, false
negative cases, and all proposals (both reviewed and accepted).

### `apply_accepted_proposals`

```rust
pub fn apply_accepted_proposals(
    cycle: &ImprovementCycle,
    db: Option<&GraphDb>,
) -> Result<ApplyReport>
```

Applies accepted proposals from a completed improvement cycle. Handles all
six proposal types:

| Kind | Strategy | Target |
|------|----------|--------|
| `NewPattern` | Source patch | `patterns_source.rs` |
| `AgentPrompt` | File patch (append or find/replace) | `agents/*.md` |
| `CweMapping` | Source patch | `scoring.rs` |
| `TaintRule` | Database INSERT | `data_sources` / `data_sinks` table |
| `RecipeChange` | YAML patch (append or find/replace) | `recipes/analysis/*.yaml` |
| `GroundTruthFix` | Source patch | `fixtures.toml` |

The `db` parameter is required for `TaintRule` proposals. Pass `None` if
no database is available — `TaintRule` proposals will be skipped with a
warning.

**Returns** the count of successfully applied proposals.

### Types

#### `ImprovementCycle`

```rust
pub struct ImprovementCycle {
    pub suite: String,
    pub baseline_score: AggregateScore,
    pub false_negatives: Vec<FalseNegativeCase>,
    pub reviewed_proposals: Vec<Improvement>,  // All proposals, including rejected
    pub proposals: Vec<Improvement>,           // Accepted proposals only
    pub holdout_case_count: usize,
    pub training_case_count: usize,
    pub cross_validation_pending: Vec<String>,
    pub run_metadata: Option<ImproveRunMetadata>,
}

pub struct ImproveRunMetadata {
    pub llm_backend: String,
    pub llm_model: String,
    pub run_mode: String,
    pub binary_mode: bool,
    pub profile: Option<String>,
    pub timestamp_utc: String,
}

pub struct ApplyReport {
    pub applied: usize,
    pub skipped: usize,
    pub blocked: usize,
    pub total: usize,
    pub blocked_reasons: Vec<String>,
}
```

#### `Improvement`

```rust
pub struct Improvement {
    pub kind: ImprovementKind,
    pub description: String,
    pub target_cwes: Vec<u32>,
    pub target_file: PathBuf,
    pub patch: Patch,
    pub source_case: String,
    pub priority: Priority,
    pub supporting_evidence: Vec<EvidenceRef>,
    pub review: Option<ReviewDecision>,
}
```

#### `ImprovementKind`

```rust
pub enum ImprovementKind {
    NewPattern,       // Regex pattern → patterns_source.rs
    AgentPrompt,      // Agent role card modification
    CweMapping,       // CWE family mapping → scoring.rs
    TaintRule,        // Taint source/sink → taint.rs
    RecipeChange,     // Pipeline recipe modification → recipes/analysis/*.yaml
    GroundTruthFix,   // Ground truth correction → fixtures.toml
}
```

#### `Patch`

```rust
pub struct Patch {
    pub find: String,     // Exact string to locate in target file
    pub replace: String,  // Replacement string
}
```

Patches use exact string matching. If `find` does not appear in the target
file, the patch is skipped with a warning.

#### `ReviewDecision`

```rust
pub struct ReviewDecision {
    pub verdict: ReviewVerdict,
    pub reason: String,
    pub overfitting_risk: ReviewRating,
    pub real_world_applicability: ReviewRating,
    pub suggested_modification: Option<String>,
    pub evidence_refs: Vec<EvidenceRef>,
}

pub enum ReviewVerdict { Accept, Reject, Modify }
pub enum ReviewRating { Low, Medium, High }
```

#### `Priority`

```rust
pub enum Priority { High, Medium, Low }
```

#### `FalseNegativeCase`

```rust
pub struct FalseNegativeCase {
    pub case_id: String,
    pub expected_cwes: Vec<u32>,
    pub detected_cwes: Vec<u32>,
    pub source_path: PathBuf,
    pub source_content: String,
}
```

#### `EvidenceRef`

```rust
pub struct EvidenceRef {
    pub source_type: EvidenceSourceType,  // Knowledge, Memory, Heuristic
    pub source: Option<String>,
    pub topic: Option<String>,
    pub title: Option<String>,
    pub memory_type: Option<String>,
    pub context: Option<String>,
    pub tags: Vec<String>,
    pub rationale: String,
}
```

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `FAILURE_ANALYST_MIN_CASES` | 5 | Minimum FN cases to trigger analysis |
| `FAILURE_ANALYST_MAX_CASES` | 20 | Maximum FN cases analyzed per cycle |
| `FAILURE_ANALYST_TARGET_BUDGET_PER_CASE` | 50,000 | Target token budget per case |
| `FAILURE_ANALYST_MAX_BUDGET_PER_CASE` | 100,000 | Hard cap per case |
| `IMPROVE_KB_MAX_CWE_QUERIES` | 6 | Knowledge base CWE queries per cycle |
| `IMPROVE_KB_HITS_PER_QUERY` | 2 | Results per KB query |

---

## Scoring Engine (`scoring.rs`)

### `score_case`

```rust
pub fn score_case(
    case: &TestCase,
    findings: &[DetectedFinding],
    finding_to_cwes_fn: impl Fn(&DetectedFinding) -> Vec<u32>,
) -> CaseOutcome
```

Scores a single test case against its detected findings.

**Positive cases** (`is_negative = false`): A finding matches if its CWE
family or exact CWE ID matches any expected CWE.

**Negative cases** (`is_negative = true`): Only findings with
`severity = "critical"` and CWEs matching the original vulnerability count as
false positives. This prevents pattern-matching noise from inflating FP
counts.

### `aggregate`

```rust
pub fn aggregate(outcomes: &[CaseOutcome]) -> AggregateScore
```

Aggregates per-case outcomes into suite-level metrics: precision, recall, F1,
per-CWE scores, per-semantic scores, and negative case calibration.

### `cwe_family`

```rust
pub fn cwe_family(cwe: u32) -> u32
```

Maps a specific CWE ID to its family root. Examples:

| Input CWE | Family CWE | Family Name |
|-----------|------------|-------------|
| CWE-121 | CWE-119 | Buffer Overflow |
| CWE-134 | CWE-134 | Format String |
| CWE-78 | CWE-74 | Injection |
| CWE-367 | CWE-362 | Race Condition |
| CWE-416 | CWE-119 | Use After Free |

Over 40 CWE mappings are defined. Unmapped CWEs return themselves.

### Types

#### `AggregateScore`

```rust
pub struct AggregateScore {
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub true_negatives: u32,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub per_cwe: HashMap<u32, CweScore>,
    pub per_semantic: HashMap<String, SemanticScore>,
    pub negative_calibration: NegativeCaseCalibration,
}
```

#### `CaseOutcome`

```rust
pub struct CaseOutcome {
    pub case_id: String,
    pub suite: String,
    pub expected_cwes: Vec<u32>,
    pub detected_cwes: Vec<u32>,
    pub matched_finding_ids: Vec<String>,
    pub unmatched_finding_ids: Vec<String>,
    pub cwe_hits: HashMap<u32, bool>,
}
```

#### `CweScore`

```rust
pub struct CweScore {
    pub cwe_id: u32,
    pub total_cases: u32,
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub detection_rate: f64,
    pub precision: f64,
}
```

#### `NegativeCaseCalibration`

```rust
pub struct NegativeCaseCalibration {
    pub total_negative_cases: u32,
    pub true_negatives: u32,
    pub false_positives: u32,
    pub false_positive_rate: f64,
    pub per_semantic_fps: HashMap<String, u32>,
}
```

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `CWE_REGRESSION_NOISE_MARGIN` | 0.02 | 2% tolerance for regression detection |

---

## Benchmark Adapter (`adapters/mod.rs`)

### `BenchmarkAdapter` Trait

```rust
#[async_trait(?Send)]
pub trait BenchmarkAdapter {
    fn name(&self) -> &str;
    fn ground_truth(&self) -> Result<GroundTruth>;
    async fn setup(&self, config: &BenchmarkConfig) -> Result<PathBuf>;
    fn is_ready(&self, config: &BenchmarkConfig) -> bool;
    fn validate_config(&self, config: &BenchmarkConfig) -> Result<()>;
    async fn compile(&self, data_dir: &Path, config: &BenchmarkConfig) -> Result<()>;
    async fn run_case(
        &self,
        case: &TestCase,
        data_dir: &Path,
        config: &BenchmarkConfig,
    ) -> Result<Vec<DetectedFinding>>;
    fn map_finding_to_cwes(&self, finding: &DetectedFinding) -> Vec<u32>;
}
```

Implement this trait to add a new benchmark suite.

### `BenchmarkConfig`

```rust
pub struct BenchmarkConfig {
    pub cache_dir: PathBuf,
    pub cwe_filter: Option<Vec<u32>>,
    pub max_cases: Option<usize>,
    pub quick_mode: bool,
    pub llm_only: bool,
    pub binary_mode: bool,
    pub parallelism: usize,
    pub skip: usize,
    pub concurrency: usize,
    pub timeout_secs: u64,
    pub holdout_fraction: f64,
    pub max_improvements_per_cycle: usize,
}
```

| Field | Default | Valid Range | Description |
|-------|---------|-------------|-------------|
| `quick_mode` | false | — | Pattern-only analysis (no LLM agents) |
| `llm_only` | false | — | LLM agents only (no pattern detection) |
| `holdout_fraction` | 0.2 | (0.0, 0.5] | Fraction of cases reserved for cross-validation |
| `max_improvements_per_cycle` | 5 | [1, 10] | Cap on accepted proposals per cycle |
| `max_cases` | 20 | [1, 50] | Maximum cases to evaluate per suite |
| `parallelism` | 5 | [1, 50] | Parallel processes per suite |
| `concurrency` | 2 | [1, 16] | In-process async concurrency |
| `timeout_secs` | 120 | [5, 600] | Per-case analysis timeout in seconds |

Range constraints are enforced at CLI parse time. Out-of-range values produce
an immediate error with the valid range displayed.

### Pattern Safety

LLM-proposed regex patterns are compiled with `RegexBuilder::size_limit(200_000)`
before acceptance. This prevents NFA memory exhaustion from pathological patterns.
The `regex` crate additionally guarantees linear-time matching (no backtracking).

Patterns are inserted into `patterns_source.rs` using typed `SourcePattern` struct
construction — LLM output is never interpolated via `format!()` into Rust source.

### `DetectedFinding`

```rust
pub struct DetectedFinding {
    pub id: String,
    pub category: String,
    pub severity: String,
    pub cwes: Vec<u32>,
    pub file: String,
    pub function: String,
    pub line: Option<u32>,
    pub title: String,
}
```

---

## Agent Tools (`tool_definitions.rs`, `tool_executor.rs`)

### Graph Query Tools

Four tools for querying the Code Property Graph. All accept function names
(strings, max 256 chars) or investigation IDs. Implemented as SQL queries
against the SQLite CPG database.

#### `get_taint_paths`

```json
{
  "name": "get_taint_paths",
  "parameters": {
    "function": { "type": "string", "description": "Function name to trace" }
  }
}
```

Returns taint flow paths involving the function: source name, sink name, and
path through the function. Joins `taint_flows`, `data_sources`, `data_sinks`,
and `functions` tables.

#### `get_cross_file_calls`

```json
{
  "name": "get_cross_file_calls",
  "parameters": {
    "function": { "type": "string", "description": "Function name to query" }
  }
}
```

Returns callers and callees in different files. Extracts file prefix from
`functions.address` and filters to cross-file relationships only.

#### `get_data_sources`

```json
{
  "name": "get_data_sources",
  "parameters": {
    "investigation": { "type": "string", "description": "Investigation ID" }
  }
}
```

Returns all `data_sources` rows (name, source_type, location) for the
investigation.

#### `get_imports`

```json
{
  "name": "get_imports",
  "parameters": {
    "investigation": { "type": "string", "description": "Investigation ID" }
  }
}
```

Returns all `symbols` rows where `symbol_type = 'import'` for the
investigation.

### SQL Passthrough (`tool_translate.rs`)

The `query_graph` tool accepts both Cypher and SQL queries. SQL `SELECT`
statements are validated through a three-layer defense:

1. **Keyword blocklist** — Rejects DML keywords, `LOAD_EXTENSION`, `PRAGMA`,
   comments (`--`, `/*`), and semicolons
2. **Table whitelist** — Only 18 CPG tables are allowed (functions, calls,
   data_sources, data_sinks, taint_flows, symbols, string_literals,
   func_references_string, investigations, findings, analysis_runs,
   function_analysis, finding_cwes, finding_evidence, agent_memory,
   investigation_files, knowledge_entries, analysis_hints)
3. **`stmt.readonly()` check** — SQLite's built-in read-only verification

Non-SQL input falls through to the existing Cypher-to-SQL translator.

---

## Agentic Analysis (`agentic.rs`)

### `run_agentic_source_analysis`

```rust
pub async fn run_agentic_source_analysis(
    path: &Path,
    timeout_secs: u64,
) -> Vec<DetectedFinding>
```

Full 5-layer analysis pipeline on a single source file.

### `run_agentic_source_analysis_with_hints`

```rust
pub async fn run_agentic_source_analysis_with_hints(
    path: &Path,
    timeout_secs: u64,
    hints: &AnalysisHints,
) -> Vec<DetectedFinding>
```

Analysis with optional context hints (vulnerability description, patch diff,
error output) for suites like CyberGym that provide metadata.

### `run_multi_file_pattern_analysis`

```rust
pub fn run_multi_file_pattern_analysis(
    paths: &[PathBuf],
) -> Vec<DetectedFinding>
```

Pattern-only analysis across multiple files sharing a Code Property Graph.
Enables cross-file relationship detection.

### Analysis Pipeline Layers

| Layer | Name | Description |
|-------|------|-------------|
| 1 | Ingest | Parse source into Code Property Graph |
| 2 | Pattern | Regex-based dangerous API detection |
| 3 | Dataflow | Taint tracking from sources to sinks |
| 4 | Agent | LLM agent reasoning about code semantics |
| 5 | Synthesis | LLM weighs all evidence for final verdict |

### Synthesis Decision Paths

The synthesis layer routes findings through one of six paths, tracked by
`SynthesisStats`:

| Path | Description |
|------|-------------|
| Pattern confidence early exit | Pattern detector has high confidence — accept |
| Semantic confidence fast-path | Semantic classifier confident — accept |
| Expert routed | Sent to specialized agent (exploit/defense) |
| LLM synthesis | Full multi-agent debate then synthesizer verdict |
| Consensus early exit | All agents agree — accept without synthesis |
| Fallback | Synthesis failed — keep all findings |

---

## Profiles (`profiles.rs`)

### `ProfileName`

```rust
pub struct ProfileName(String);

impl ProfileName {
    pub fn new(name: &str) -> Result<Self>;
    pub fn as_str(&self) -> &str;
}
```

Validated profile name. Must match `^[a-zA-Z0-9][a-zA-Z0-9_-]*$` with a
maximum length of 64 characters. Construction via `ProfileName::new()` rejects
invalid names with an explanatory error.

### `ProfilePaths`

```rust
pub struct ProfilePaths {
    pub root: PathBuf,
    pub config_toml: PathBuf,
    pub results_db: PathBuf,
    pub memory_graph: PathBuf,
    pub telemetry: PathBuf,
    pub active_runs: PathBuf,
}

impl ProfilePaths {
    pub fn resolve(name: &ProfileName) -> Self;
    pub fn ensure(&self) -> Result<()>;
    pub fn load_merged_config(&self) -> Result<Config>;
}
```

Resolves all profile paths under `~/.skwaq/profiles/<name>/`. `ensure()`
creates the directory tree with `0o700` permissions if it does not exist.
`load_merged_config()` loads the base `skwaq.toml`, then replaces the `[llm]`
section with the profile's `config.toml` overlay.

**Security:** `resolve()` rejects symlinks via `symlink_metadata()` before
constructing paths. Profile names are validated through `ProfileName::new()`
before any filesystem access.

### `list_profiles`

```rust
pub fn list_profiles() -> Result<Vec<ProfileSummary>>
```

Lists all profiles under `~/.skwaq/profiles/`, returning name, backend, model,
and run count for each.

```rust
pub struct ProfileSummary {
    pub name: ProfileName,
    pub backend: String,
    pub model: Option<String>,
    pub run_count: usize,
}
```

### `create_profile`

```rust
pub fn create_profile(
    name: &ProfileName,
    backend: &str,
    model: Option<&str>,
    endpoint: Option<&str>,
    deployment: Option<&str>,
) -> Result<ProfilePaths>
```

Creates a new profile directory and writes the `config.toml`. Returns the
resolved paths.

### `default_templates`

```rust
pub fn default_templates() -> Vec<(&'static str, &'static str)>
```

Returns `(name, toml_content)` pairs for the built-in profile templates
(`opus` and `gpt54`).

---

### `LlmConfig::merge_overlay` (`config.rs`)

```rust
impl LlmConfig {
    pub fn merge_overlay(&mut self, overlay: LlmConfig);
}
```

Replaces `self` entirely with `overlay`. Called during profile config loading
to swap the base LLM configuration with the profile's override. Infallible.

---

### `Gym` Profile Support (`lib.rs`)

```rust
impl Gym {
    pub fn with_profile(
        root: PathBuf,
        profile: &str,
    ) -> Result<Self>;
}
```

Constructs a `Gym` instance with profile-specific paths for `results_db`,
`memory_graph`, and `telemetry`. Calls `ProfilePaths::ensure()` to create
the directory if needed. The merged LLM config is stored in the `Gym` struct
and threaded through to `run_llm_pipeline()` and improvement functions.

Additional fields on `Gym`:

```rust
pub struct Gym {
    // ... existing fields ...
    pub profile_name: Option<String>,
    pub memory_store_path: Option<PathBuf>,
    pub telemetry_dir: Option<PathBuf>,
    pub llm_config: Option<Config>,
}
```

When `profile_name` is `None`, all paths resolve to their defaults (backward
compatible).

---

### `RunMetadata` Profile Field (`history.rs`)

```rust
pub struct RunMetadata {
    // ... existing fields ...
    #[serde(default)]
    pub profile: Option<String>,
}
```

The `profile` field is added with `#[serde(default)]` for backward
compatibility — existing history entries deserialize with `profile: None`.

---

## Report Formats

### JSON Report

```json
{
  "suite": "fixtures",
  "timestamp": "2026-03-21T10:30:00Z",
  "skwaq_commit": "b1ed70b7",
  "precision": 0.958,
  "recall": 0.784,
  "f1": 0.863,
  "true_positives": 91,
  "false_positives": 4,
  "false_negatives": 25,
  "true_negatives": 12,
  "per_cwe": [
    {
      "cwe_id": 119,
      "total_cases": 20,
      "true_positives": 18,
      "false_positives": 1,
      "false_negatives": 2,
      "detection_rate": 0.90,
      "precision": 0.947
    }
  ],
  "per_semantic": [
    {
      "class_name": "buffer_overflow",
      "total_cases": 15,
      "true_positives": 14,
      "detection_rate": 0.933,
      "precision": 1.0
    }
  ]
}
```

### Markdown Report

```
## Fixtures Benchmark Results

| Metric    | Value  |
|-----------|--------|
| Precision | 95.8%  |
| Recall    | 78.4%  |
| F1        | 86.3%  |
| TP        | 91     |
| FP        | 4      |
| FN        | 25     |
| TN        | 12     |

### Per-CWE Detection Rates

| CWE   | Cases | TP | FP | FN | Det% | Prec% |   |
|-------|-------|----|----|----|------|-------|---|
| 119   | 20    | 18 | 1  | 2  | 90%  | 95%   | + |
| 362   | 5     | 4  | 0  | 1  | 80%  | 100%  | + |

Legend: + >80%, ~ 50-80%, - <50%
```
