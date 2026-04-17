# Skwaq v2: Technical Design Document

## 1. Workspace Structure

Three crates. Split further only when compile times or dependency conflicts force it.

```
skwaq/
├── Cargo.toml                      # Workspace root
├── Cargo.lock
├── README.md
├── crates/
│   ├── core/                       # skwaq-core: everything except CLI and agents
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── config.rs           # Configuration (TOML, env vars, interactive)
│   │       ├── llm/                # LLM client abstraction
│   │       │   ├── mod.rs
│   │       │   ├── traits.rs       # LlmClient trait + ToolLoop
│   │       │   ├── copilot.rs      # GitHub Copilot API backend
│   │       │   ├── azure.rs        # Azure OpenAI backend
│   │       │   ├── ollama.rs       # Ollama local backend
│   │       │   └── openai.rs       # Direct OpenAI backend
│   │       ├── graph/              # LadybugDB graph layer (Cypher/GQL)
│   │       │   ├── mod.rs
│   │       │   ├── db.rs           # Database lifecycle + connection
│   │       │   ├── schema.rs       # Cypher schema definitions
│   │       │   ├── builder.rs      # Graph construction from analysis
│   │       │   ├── queries.rs      # Reusable Cypher query library
│   │       │   └── types.rs        # Node/edge type definitions
│   │       ├── binary/             # Binary analysis engine
│   │       │   ├── mod.rs
│   │       │   ├── subprocess.rs   # SubprocessTool trait + implementations
│   │       │   ├── ghidra.rs       # Ghidra headless runner
│   │       │   ├── radare2.rs      # r2 runner (optional)
│   │       │   ├── native.rs       # goblin + checksec (in-process)
│   │       │   ├── decompile.rs    # LLM-enhanced decompilation
│   │       │   ├── cache.rs        # Content-addressed analysis cache
│   │       │   └── types.rs        # Binary analysis types
│   │       ├── source/             # Source code analysis
│   │       │   ├── mod.rs
│   │       │   ├── parser.rs       # tree-sitter AST parsing
│   │       │   └── builder.rs      # Source -> graph
│   │       ├── analysis/           # Vulnerability analysis
│   │       │   ├── mod.rs
│   │       │   ├── taint.rs        # Cypher taint path queries
│   │       │   ├── patterns.rs     # Dangerous API detection
│   │       │   ├── semgrep.rs      # Semgrep subprocess wrapper
│   │       │   ├── variant.rs      # Variant analysis (find-similar)
│   │       │   ├── hardening.rs    # checksec assessment
│   │       │   ├── surface.rs      # Attack surface enumeration
│   │       │   └── severity.rs     # CVSS-like scoring
│   │       ├── knowledge/          # CWE/CVE knowledge base
│   │       │   ├── mod.rs
│   │       │   ├── cwe.rs          # CWE import and query
│   │       │   └── patterns.rs     # Vulnerability pattern library
│   │       ├── investigation/      # Investigation management
│   │       │   ├── mod.rs
│   │       │   ├── manager.rs      # Create, resume, list investigations
│   │       │   ├── annotations.rs  # User annotations and corrections
│   │       │   └── hypotheses.rs   # Hypothesis tracking
│   │       ├── reporting/          # Output generation
│   │       │   ├── mod.rs
│   │       │   ├── sarif.rs        # SARIF v2.1
│   │       │   ├── markdown.rs
│   │       │   └── json.rs
│   │       └── error.rs            # Error types
│   ├── agents/                     # skwaq-agents: LLM agent definitions
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── vuln_hunter.rs      # Primary vulnerability discovery agent
│   │       ├── critic.rs           # Finding validation + FP reduction
│   │       ├── tools.rs            # Tool definitions available to agents
│   │       └── budget.rs           # Token budget tracking + chunking
│   └── cli/                        # skwaq-cli: binary entry point
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs
│           ├── lib.rs
│           ├── commands/           # clap command definitions
│           │   ├── mod.rs
│           │   ├── ingest.rs
│           │   ├── analyze.rs
│           │   ├── decompile.rs
│           │   ├── binary_cmds.rs  # strings, symbols, checksec, xrefs, surface
│           │   ├── investigate.rs
│           │   ├── annotate.rs     # annotate, hypothesize, correct, rename
│           │   ├── find_similar.rs
│           │   ├── report.rs
│           │   ├── viz.rs
│           │   ├── kb.rs
│           │   ├── config.rs
│           │   └── doctor.rs       # Prerequisite checker
│           └── tui/
│               ├── mod.rs
│               ├── findings_view.rs
│               ├── decompile_view.rs
│               ├── callgraph_view.rs
│               └── taint_view.rs
├── prompts/                        # Agent prompts (loaded from disk, editable)
│   ├── vuln_hunter.md
│   └── critic.md
├── data/
│   ├── knowledge/                  # CWE XML, vulnerability patterns
│   └── rules/                      # Custom Semgrep rules
├── ghidra-scripts/                 # Python post-scripts for Ghidra headless
│   ├── extract_functions.py
│   ├── extract_cfg.py
│   └── decompile_function.py
├── tests/
│   ├── fixtures/                   # Vulnerable C programs + compiled binaries
│   │   ├── buffer_overflow.c
│   │   ├── format_string.c
│   │   ├── use_after_free.c
│   │   ├── Makefile              # Compile at O0-O3
│   │   └── binaries/             # Pre-compiled test binaries
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── scripts/
│   ├── setup-ghidra.sh
│   └── setup-angr.sh
└── .github/
    └── workflows/
        ├── ci.yml
        └── release.yml
```

## 2. Cargo Workspace

```toml
[workspace]
resolver = "2"
members = ["crates/core", "crates/agents", "crates/cli"]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT OR Apache-2.0"
repository = "https://github.com/rysweet/skwaq"

[workspace.dependencies]
# RustyClawd agent framework (pinned to release tag)
rustyclawd-core = { git = "https://github.com/rysweet/RustyClawd", tag = "v0.1.0" }
rustyclawd-tools = { git = "https://github.com/rysweet/RustyClawd", tag = "v0.1.0" }
rustyclawd-cli = { git = "https://github.com/rysweet/RustyClawd", tag = "v0.1.0" }

# Async
tokio = { version = "1.35", features = ["full"] }
futures = "0.3"
async-trait = "0.1"

# CLI + TUI
clap = { version = "4.4", features = ["derive", "cargo"] }
ratatui = "0.29"
crossterm = "0.29"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"

# Error handling
anyhow = "1.0"
thiserror = "2.0"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# HTTP
reqwest = { version = "0.13", features = ["json", "stream"] }

# Graph database (LadybugDB - embedded, Cypher/GQL compatible)
ladybug = "0.15"  # Or kuzu = "0.15" (API-compatible)

# Vector search sidecar
usearch = "2.13"

# Binary analysis
goblin = "0.9"
checksec = { version = "0.0.9", features = ["elf", "pe", "macho"] }

# Source parsing
tree-sitter = "0.24"
tree-sitter-c = "0.23"
tree-sitter-cpp = "0.23"
tree-sitter-python = "0.23"
tree-sitter-go = "0.23"
tree-sitter-rust = "0.23"
tree-sitter-javascript = "0.23"
tree-sitter-java = "0.23"

# LLM (local)
ollama-rs = "0.2"

# Utilities
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1.6", features = ["v4", "serde"] }
sha2 = "0.10"          # Content-addressed caching
tempfile = "3.8"
shellexpand = "3.1"

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true
```

## 3. Key Components

### 3.1 LLM Client Trait (RustyClawd Foundation + Abstraction Layer)

RustyClawd provides the proven Copilot API client and tool loop. We wrap it with an `LlmClient` trait to support additional backends (Azure OpenAI, Ollama, OpenAI direct).

```rust
// crates/core/src/llm/traits.rs
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,       // "system", "user", "assistant", "tool"
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,  // JSON Schema
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug)]
pub struct LlmResponse {
    pub content: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    pub usage: TokenUsage,
}

#[derive(Debug, Default)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[async_trait]
pub trait LlmClient: Send + Sync {
    async fn chat(
        &self,
        messages: &[Message],
        tools: &[ToolDefinition],
        model: &str,
    ) -> anyhow::Result<LlmResponse>;
}

/// The core agentic loop. ~50 lines.
pub async fn execute_with_tools<F, Fut>(
    client: &dyn LlmClient,
    model: &str,
    system_prompt: &str,
    user_prompt: &str,
    tools: &[ToolDefinition],
    tool_executor: F,
    budget: &mut TokenBudget,
) -> anyhow::Result<String>
where
    F: Fn(&str, &serde_json::Value) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<serde_json::Value>>,
{
    let mut messages = vec![
        Message { role: "system".into(), content: system_prompt.into(), tool_call_id: None },
        Message { role: "user".into(), content: user_prompt.into(), tool_call_id: None },
    ];

    loop {
        if budget.exhausted() {
            return Ok("Analysis stopped: token budget exhausted.".into());
        }

        let response = client.chat(&messages, tools, model).await?;
        budget.track(&response.usage);

        if response.tool_calls.is_empty() {
            return Ok(response.content.unwrap_or_default());
        }

        // Record assistant message with tool calls
        messages.push(Message {
            role: "assistant".into(),
            content: response.content.unwrap_or_default(),
            tool_call_id: None,
        });

        // Execute each tool call and feed results back
        for call in &response.tool_calls {
            let result = tool_executor(&call.name, &call.arguments).await?;
            messages.push(Message {
                role: "tool".into(),
                content: serde_json::to_string(&result)?,
                tool_call_id: Some(call.id.clone()),
            });
        }
    }
}

#[derive(Debug)]
pub struct TokenBudget {
    pub limit: u64,
    pub used: u64,
}

impl TokenBudget {
    pub fn new(limit: u64) -> Self { Self { limit, used: 0 } }
    pub fn unlimited() -> Self { Self { limit: u64::MAX, used: 0 } }
    pub fn exhausted(&self) -> bool { self.used >= self.limit }
    pub fn track(&mut self, usage: &TokenUsage) {
        self.used += usage.input_tokens + usage.output_tokens;
    }
}
```

### 3.2 SubprocessTool Trait

Every external tool must implement this. Handles the hard parts: health checks, timeouts, output validation, cleanup.

```rust
// crates/core/src/binary/subprocess.rs
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

#[async_trait]
pub trait SubprocessTool: Send + Sync {
    /// Human-readable name
    fn name(&self) -> &str;

    /// Check if the tool is installed and working
    async fn health_check(&self) -> ToolHealth;

    /// Minimum supported version (if applicable)
    fn min_version(&self) -> Option<&str> { None }

    /// Default timeout for this tool
    fn default_timeout(&self) -> Duration;
}

pub struct ToolHealth {
    pub available: bool,
    pub version: Option<String>,
    pub path: Option<String>,
    pub error: Option<String>,
    pub install_hint: String,
}

/// Run a subprocess with timeout, output capture, and cleanup
pub async fn run_tool(
    cmd: &mut Command,
    tool_name: &str,
    timeout_duration: Duration,
    temp_dir: Option<&Path>,
) -> anyhow::Result<ToolOutput> {
    let result = timeout(timeout_duration, cmd.output()).await;

    match result {
        Ok(Ok(output)) => {
            if output.status.success() {
                Ok(ToolOutput {
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                    success: true,
                })
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("{tool_name} failed (exit {}): {stderr}", output.status)
            }
        }
        Ok(Err(e)) => {
            anyhow::bail!("{tool_name} not found or failed to start: {e}")
        }
        Err(_) => {
            // Timeout: clean up temp directory if provided
            if let Some(dir) = temp_dir {
                let _ = tokio::fs::remove_dir_all(dir).await;
            }
            anyhow::bail!("{tool_name} timed out after {timeout_duration:?}")
        }
    }
}

pub struct ToolOutput {
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
}
```

### 3.3 Content-Addressed Cache

Ghidra analysis takes minutes. Never redo it for the same binary.

```rust
// crates/core/src/binary/cache.rs
use sha2::{Sha256, Digest};
use std::path::{Path, PathBuf};

pub struct AnalysisCache {
    cache_dir: PathBuf,  // .skwaq/cache/
}

impl AnalysisCache {
    /// Get cached analysis for a binary, or None if not cached
    pub fn get(&self, binary_path: &Path) -> Option<CachedAnalysis> {
        let hash = self.hash_file(binary_path)?;
        let cache_path = self.cache_dir.join(&hash).join("analysis.json");
        if cache_path.exists() {
            let data = std::fs::read_to_string(&cache_path).ok()?;
            serde_json::from_str(&data).ok()
        } else {
            None
        }
    }

    /// Store analysis results keyed by binary hash
    pub fn put(&self, binary_path: &Path, analysis: &CachedAnalysis) -> anyhow::Result<()> {
        let hash = self.hash_file(binary_path)
            .ok_or_else(|| anyhow::anyhow!("Cannot hash binary"))?;
        let dir = self.cache_dir.join(&hash);
        std::fs::create_dir_all(&dir)?;
        let data = serde_json::to_string_pretty(analysis)?;
        std::fs::write(dir.join("analysis.json"), data)?;
        Ok(())
    }

    fn hash_file(&self, path: &Path) -> Option<String> {
        let data = std::fs::read(path).ok()?;
        let hash = Sha256::digest(&data);
        Some(format!("{:x}", hash))
    }
}
```

### 3.4 LadybugDB Graph Layer (Cypher)

```rust
// crates/core/src/graph/db.rs
use ladybug::{Connection, Database, SystemConfig};
use std::path::Path;

pub struct GraphDb {
    db: Database,
}

impl GraphDb {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let db = Database::new(path, SystemConfig::default())?;
        let this = Self { db };
        this.ensure_schema()?;
        Ok(this)
    }

    pub fn connection(&self) -> anyhow::Result<Connection> {
        Ok(Connection::new(&self.db)?)
    }

    fn ensure_schema(&self) -> anyhow::Result<()> {
        let conn = self.connection()?;
        // LadybugDB Cypher DDL - same syntax as Neo4j
        let schema = [
            "CREATE NODE TABLE IF NOT EXISTS Function(
                id STRING PRIMARY KEY, name STRING, address STRING,
                decompiled STRING, confidence DOUBLE DEFAULT 0.0,
                language STRING DEFAULT 'unknown',
                is_reconstructed BOOLEAN DEFAULT false,
                investigation_id STRING
            )",
            "CREATE NODE TABLE IF NOT EXISTS BasicBlock(
                id STRING PRIMARY KEY, address STRING,
                size INT64, function_id STRING
            )",
            "CREATE NODE TABLE IF NOT EXISTS DataSource(
                id STRING PRIMARY KEY, name STRING,
                source_type STRING, location STRING, investigation_id STRING
            )",
            "CREATE NODE TABLE IF NOT EXISTS DataSink(
                id STRING PRIMARY KEY, name STRING,
                sink_type STRING, danger_level STRING,
                location STRING, investigation_id STRING
            )",
            "CREATE NODE TABLE IF NOT EXISTS Vulnerability(
                id STRING PRIMARY KEY, title STRING,
                description STRING DEFAULT '', severity STRING,
                cvss DOUBLE DEFAULT 0.0, cwe_id STRING DEFAULT '',
                function_id STRING, evidence STRING DEFAULT '',
                confidence DOUBLE DEFAULT 0.0, investigation_id STRING
            )",
            "CREATE NODE TABLE IF NOT EXISTS CWE(
                cwe_id STRING PRIMARY KEY, name STRING,
                description STRING DEFAULT ''
            )",
            "CREATE NODE TABLE IF NOT EXISTS Investigation(
                id STRING PRIMARY KEY, name STRING, target STRING,
                status STRING, created_at STRING, updated_at STRING
            )",
            "CREATE NODE TABLE IF NOT EXISTS Annotation(
                id STRING PRIMARY KEY, target_address STRING,
                text STRING, author STRING DEFAULT 'user',
                timestamp STRING, investigation_id STRING
            )",
            "CREATE NODE TABLE IF NOT EXISTS Hypothesis(
                id STRING PRIMARY KEY, description STRING,
                status STRING DEFAULT 'pending',
                evidence STRING DEFAULT '', timestamp STRING,
                investigation_id STRING
            )",
            // Relationships
            "CREATE REL TABLE IF NOT EXISTS CALLS(FROM Function TO Function)",
            "CREATE REL TABLE IF NOT EXISTS CONTAINS(FROM Function TO BasicBlock)",
            "CREATE REL TABLE IF NOT EXISTS FLOWS_TO(FROM BasicBlock TO BasicBlock)",
            "CREATE REL TABLE IF NOT EXISTS LOCATED_IN(FROM Vulnerability TO Function)",
            "CREATE REL TABLE IF NOT EXISTS MATCHES(FROM Vulnerability TO CWE)",
            "CREATE REL TABLE IF NOT EXISTS TAINT_FLOW(FROM DataSource TO DataSink,
                path STRING, sanitized BOOLEAN DEFAULT false)",
        ];

        for stmt in &schema {
            let _ = conn.query(stmt); // Ignore "already exists"
        }
        Ok(())
    }

    /// Run a Cypher read query
    pub fn query(&self, cypher: &str) -> anyhow::Result<serde_json::Value> {
        let conn = self.connection()?;
        let result = conn.query(cypher)?;
        Ok(self.result_to_json(&result))
    }

    /// Run a Cypher write query
    pub fn mutate(&self, cypher: &str) -> anyhow::Result<()> {
        let conn = self.connection()?;
        conn.query(cypher)?;
        Ok(())
    }
}
```

### 3.5 Taint Analysis (Cypher)

Variable-length path queries in Cypher handle taint tracking well:

```rust
// crates/core/src/analysis/taint.rs

impl TaintAnalyzer {
    /// Find all unsanitized paths from attack surface to dangerous sinks
    pub fn find_unsanitized_paths(&self, investigation_id: &str) -> anyhow::Result<Vec<TaintPath>> {
        // Cypher variable-length path query for taint tracking
        let query = format!(r#"
            MATCH (src:DataSource)-[:TAINT_FLOW]->(sink:DataSink)
            WHERE src.investigation_id = '{inv}'
              AND src.source_type <> 'internal'
              AND NOT EXISTS {{
                  MATCH (src)-[t:TAINT_FLOW]->(sink) WHERE t.sanitized = true
              }}
            MATCH (src_func:Function {{name: src.name, investigation_id: '{inv}'}})
            MATCH (sink_func:Function {{name: sink.name, investigation_id: '{inv}'}})
            MATCH path = (src_func)-[:CALLS*1..10]->(sink_func)
            RETURN src.name AS source_name,
                   sink.name AS sink_name,
                   sink.danger_level AS danger,
                   length(path) AS hops
            ORDER BY danger DESC, hops ASC
        "#, inv = investigation_id);

        let results = self.db.query(&query)?;
        self.parse_taint_results(&results)
    }
}
```

### 3.6 Variant Analysis

The killer feature. Combines structural graph queries with vector similarity:

```rust
// crates/core/src/analysis/variant.rs

pub struct VariantAnalyzer {
    db: GraphDb,
    llm: Box<dyn LlmClient>,
}

impl VariantAnalyzer {
    /// Find functions structurally similar to the given function
    pub async fn find_similar(
        &self,
        function_id: &str,
        investigation_id: &str,
    ) -> anyhow::Result<Vec<VariantMatch>> {
        // Step 1: Extract structural features of the target function
        let target = self.get_function_features(function_id)?;

        // Step 2: Vector similarity search for candidates
        let candidates = self.vector_search(&target.embedding, investigation_id, 50)?;

        // Step 3: Structural filtering (call pattern, data flow shape)
        let filtered = self.structural_filter(&target, &candidates)?;

        // Step 4: LLM validation of top candidates
        let mut results = Vec::new();
        for candidate in filtered.iter().take(20) {
            let validation = self.llm_validate(&target, candidate).await?;
            results.push(VariantMatch {
                function: candidate.clone(),
                similarity: validation.similarity,
                explanation: validation.explanation,
                is_patched: validation.has_mitigation,
            });
        }

        results.sort_by(|a, b| b.similarity.partial_cmp(&a.similarity).unwrap());
        Ok(results)
    }

    fn vector_search(
        &self,
        embedding: &[f32],
        investigation_id: &str,
        k: usize,
    ) -> anyhow::Result<Vec<FunctionFeatures>> {
        // usearch HNSW sidecar: find nearest embeddings, then fetch from LadybugDB
        let neighbor_ids = self.hnsw_index.search(embedding, k)?;

        // Fetch function details from graph via Cypher
        let id_list = neighbor_ids.iter()
            .map(|id| format!("'{}'", id))
            .collect::<Vec<_>>().join(", ");
        let query = format!(
            "MATCH (f:Function) WHERE f.id IN [{}] AND f.investigation_id = '{}' \
             RETURN f.id, f.name, f.address, f.decompiled, f.confidence",
            id_list, investigation_id
        );
        self.db.query(&query)
            .map(|results| self.parse_search_results(&results))
    }
}
```

### 3.7 VulnHunter Agent

```rust
// crates/agents/src/vuln_hunter.rs

pub struct VulnHunterAgent {
    llm: Box<dyn LlmClient>,
    db: GraphDb,
    model: String,
}

impl VulnHunterAgent {
    pub async fn analyze(
        &self,
        investigation_id: &str,
        budget: &mut TokenBudget,
    ) -> anyhow::Result<Vec<Finding>> {
        // Load prompt from disk (editable without recompile)
        let system_prompt = self.load_prompt("vuln_hunter.md")?;

        // Build context: top functions by attack surface proximity
        let context = self.build_analysis_context(investigation_id)?;

        // Chunk if too large for context window
        let chunks = self.chunk_by_budget(&context, budget);

        let mut all_findings = Vec::new();
        for chunk in chunks {
            let user_prompt = format!(
                "Investigation: {}\n\nBinary hardening:\n{}\n\nAttack surface functions:\n{}\n\n\
                 Taint paths:\n{}\n\nAnalyze for vulnerabilities.",
                investigation_id, chunk.hardening, chunk.functions, chunk.taint_paths,
            );

            let result = execute_with_tools(
                self.llm.as_ref(),
                &self.model,
                &system_prompt,
                &user_prompt,
                &self.tool_definitions(),
                |name, args| self.execute_tool(name, args, investigation_id),
                budget,
            ).await?;

            let findings = self.parse_findings(&result)?;
            all_findings.extend(findings);
        }

        Ok(all_findings)
    }

    async fn execute_tool(
        &self,
        name: &str,
        args: &serde_json::Value,
        investigation_id: &str,
    ) -> anyhow::Result<serde_json::Value> {
        match name {
            "query_graph" => {
                let cypher = args["query"].as_str().unwrap_or("");
                let results = self.db.query(cypher)?;
                Ok(results)
            }
            "read_function" => {
                let func_name = args["name"].as_str().unwrap_or("");
                let query = format!(
                    "MATCH (f:Function {{name: '{}', investigation_id: '{}'}}) \
                     RETURN f.name, f.decompiled, f.confidence",
                    func_name, investigation_id
                );
                self.db.query(&query)
            }
            "get_callers" => {
                let func = args["function"].as_str().unwrap_or("");
                let query = format!(
                    "MATCH (caller:Function)-[:CALLS]->(callee:Function {{name: '{}'}}) \
                     RETURN caller.name",
                    func
                );
                self.db.query(&query)
            }
            "lookup_cwe" => {
                let q = args["query"].as_str().unwrap_or("");
                let query = format!(
                    "MATCH (c:CWE) WHERE c.name CONTAINS '{}' \
                     RETURN c.cwe_id, c.name, c.description", q
                );
                self.db.query(&query)
            }
            "create_finding" => {
                let id = uuid::Uuid::new_v4().to_string();
                let title = args["title"].as_str().unwrap_or("");
                let severity = args["severity"].as_str().unwrap_or("medium");
                let evidence = args["evidence"].as_str().unwrap_or("");
                let function = args["function"].as_str().unwrap_or("");

                self.db.mutate(&format!(
                    "CREATE (f:Finding {{id: '{}', title: '{}', evidence: '{}', \
                     agent: 'vuln_hunter', timestamp: '{}', investigation_id: '{}'}})",
                    id, title, evidence, chrono::Utc::now().to_rfc3339(), investigation_id
                ))?;
                Ok(serde_json::json!({"finding_id": id, "status": "created"}))
            }
            "search_similar" => {
                let func = args["function"].as_str().unwrap_or("");
                // Delegate to variant analyzer
                Ok(serde_json::json!({"status": "variant search initiated", "function": func}))
            }
            _ => anyhow::bail!("Unknown tool: {name}"),
        }
    }

    fn load_prompt(&self, filename: &str) -> anyhow::Result<String> {
        // Try user-customized prompt, otherwise use the bundled default
        let user_path = dirs::home_dir()
            .unwrap_or_default()
            .join(".skwaq/prompts")
            .join(filename);

        if user_path.exists() {
            Ok(std::fs::read_to_string(user_path)?)
        } else {
            // Bundled default
            match filename {
                "vuln_hunter.md" => Ok(include_str!("../../prompts/vuln_hunter.md").to_string()),
                "critic.md" => Ok(include_str!("../../prompts/critic.md").to_string()),
                _ => anyhow::bail!("Unknown prompt: {filename}"),
            }
        }
    }
}
```

### 3.8 Doctor Command

```rust
// crates/cli/src/commands/doctor.rs

pub async fn run_doctor() -> anyhow::Result<()> {
    let checks: Vec<Box<dyn SubprocessTool>> = vec![
        Box::new(GhidraRunner::new_unchecked()),
        Box::new(SemgrepRunner::new_unchecked()),
        // angr is optional for v0.1
    ];

    println!("Skwaq v{} - System Check\n", env!("CARGO_PKG_VERSION"));

    for tool in &checks {
        let health = tool.health_check().await;
        if health.available {
            println!("[ok] {} {} at {}",
                tool.name(),
                health.version.as_deref().unwrap_or(""),
                health.path.as_deref().unwrap_or(""),
            );
        } else {
            println!("[!!] {} - {}",
                tool.name(),
                health.error.as_deref().unwrap_or("not found"),
            );
            println!("     Install: {}", health.install_hint);
        }
    }

    // Check LLM connectivity
    check_llm_backends().await;

    // Check LadybugDB
    check_database().await;

    Ok(())
}
```

## 4. Configuration

```toml
# skwaq.toml
[general]
database_path = ".skwaq/graph"
cache_path = ".skwaq/cache"
log_level = "info"

[llm]
# Backend: "copilot", "azure", "ollama", "openai"
reasoning = "copilot"
decompilation = "copilot"
embeddings = "ollama"      # Keep embeddings local

[llm.copilot]
# Auth via gh CLI or GITHUB_TOKEN env var
model = "gpt-4o"

[llm.ollama]
host = "http://localhost:11434"
model = "llama3.1"
embedding_model = "nomic-embed-text"

[llm.azure]
endpoint = ""              # Or AZURE_OPENAI_ENDPOINT env var
api_key = ""               # Or AZURE_OPENAI_API_KEY
model = "gpt-4o"

[binary]
ghidra_path = ""           # Auto-detected or GHIDRA_INSTALL_DIR
default_timeout = 600      # seconds
enable_cache = true

[analysis]
max_taint_depth = 15
false_positive_target = 0.15  # 15% FP rate target
default_token_budget = 100000

[output]
default_format = "tui"
```

## 5. Testing Strategy

| Layer | % | What to Test |
|---|---|---|
| **Unit** | 60% | Types, Cypher query construction, SARIF serialization, checksec interpretation, cache logic, confidence scoring |
| **Integration** | 30% | LadybugDB graph ops, Ghidra JSON parsing, taint queries, agent tool dispatch, variant search |
| **E2E** | 10% | Full: ingest fixture binary -> analyze -> report. Real LadybugDB + Ghidra, mocked LLM |

**Test fixtures**: 5 vulnerable C programs compiled at O0-O3 (buffer overflow, format string, use-after-free, integer overflow, command injection). Committed as both source and pre-compiled binaries.

## 6. CI/CD & Release

```yaml
# .github/workflows/release.yml
name: Release
on:
  push:
    tags: ["v*"]

jobs:
  build:
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
            asset: skwaq-linux-x86_64
          - os: macos-latest
            target: aarch64-apple-darwin
            asset: skwaq-macos-aarch64
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { targets: "${{ matrix.target }}" }
      - run: cargo build --release --target ${{ matrix.target }}
      - run: sha256sum target/${{ matrix.target }}/release/skwaq > checksums.txt
      - uses: softprops/action-gh-release@v2
        with:
          files: |
            target/${{ matrix.target }}/release/skwaq
            checksums.txt
          generate_release_notes: true
```

## 7. Error Handling

```rust
#[derive(Debug, thiserror::Error)]
pub enum SkwaqError {
    #[error("{tool} not found. {install_hint}")]
    ToolNotFound { tool: String, install_hint: String },

    #[error("{tool} timed out after {timeout:?}")]
    ToolTimeout { tool: String, timeout: Duration },

    #[error("{tool} failed: {message}")]
    ToolFailed { tool: String, message: String },

    #[error("LLM error ({provider}): {message}")]
    LlmError { provider: String, message: String },

    #[error("Token budget exhausted ({used}/{limit} tokens)")]
    BudgetExhausted { used: u64, limit: u64 },

    #[error("Graph error: {0}")]
    GraphError(String),

    #[error("Binary parse error: {0}")]
    BinaryError(String),

    #[error("Investigation not found: {0}")]
    InvestigationNotFound(String),
}
```

Every user-facing error includes what went wrong and what to do about it.
