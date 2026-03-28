//! Agent runner: execute any agent definition against the graph database.
//!
//! The runner loads the agent's system prompt, filters available tools,
//! builds context, and drives the LLM tool loop via RustyClawd's Client.

use crate::graph::GraphDb;
use crate::llm::{execute_with_tools, Client, TokenBudget};
use crate::memory::MemoryStore;

use super::definition::{AgentDefinition, AgentRoleMetadata};
use super::output_schema::{output_schema_contract, parse_structured_output, ParsedAgentOutput};
use super::tool_definitions::{agent_tools, filter_tools};
use super::tool_executor::{execute_tool, execute_tool_with_memory};

/// Lightweight structured summary passed between pipeline stages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentContextFrame {
    /// Agent that produced this frame.
    pub agent_name: String,
    /// Short human-facing description of the agent's role in the pipeline.
    pub description: String,
    /// Optional structured role metadata from the agent definition.
    pub role: Option<AgentRoleMetadata>,
    /// High-signal observations extracted from the final output.
    pub key_points: Vec<String>,
    /// Optional schema name advertised by the producing agent.
    pub output_schema: Option<String>,
    /// Structured summary derived from parsed agent output.
    pub structured_summary: Option<String>,
    /// Explicit parse failure message when a schema-backed output could not be parsed.
    pub structured_output_error: Option<String>,
}

impl AgentContextFrame {
    pub fn from_agent(
        agent: &AgentDefinition,
        output: &str,
        parsed_output: Option<&ParsedAgentOutput>,
        parsed_output_error: Option<&str>,
    ) -> Self {
        let key_points = parsed_output
            .map(ParsedAgentOutput::key_points)
            .unwrap_or_else(|| extract_key_points(output));

        Self {
            agent_name: agent.name.clone(),
            description: agent.description.clone(),
            role: agent.role.clone(),
            key_points,
            output_schema: agent.output_schema.clone(),
            structured_summary: parsed_output.map(ParsedAgentOutput::context_summary),
            structured_output_error: parsed_output_error.map(ToOwned::to_owned),
        }
    }

    pub fn synthetic(
        agent_name: impl Into<String>,
        description: impl Into<String>,
        role: Option<AgentRoleMetadata>,
        output: &str,
    ) -> Self {
        Self {
            agent_name: agent_name.into(),
            description: description.into(),
            role,
            key_points: extract_key_points(output),
            output_schema: None,
            structured_summary: None,
            structured_output_error: None,
        }
    }
}

/// Result from running an agent.
#[derive(Debug, Clone)]
pub struct AgentResult {
    /// The agent's name.
    pub agent_name: String,
    /// The final text output from the LLM.
    pub output: String,
    /// Tokens used during this agent's run.
    pub tokens_used: u64,
    /// Structured summary of the agent output for downstream stages.
    pub context_frame: AgentContextFrame,
    /// Parsed structured output when the agent advertises an output schema.
    pub parsed_output: Option<ParsedAgentOutput>,
    /// Explicit parse failure when a schema-backed output could not be parsed.
    pub parsed_output_error: Option<String>,
}

/// Runs any agent definition against the graph database.
pub struct AgentRunner {
    client: Client,
}

impl AgentRunner {
    /// Create a new runner with the given RustyClawd client.
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Run an agent with access to the graph database for tool execution.
    ///
    /// This is the primary entry point for running agents. The database
    /// reference is captured by the tool executor closure.
    pub async fn run_agent_with_db(
        &self,
        agent: &AgentDefinition,
        investigation_id: &str,
        context: &str,
        db: &GraphDb,
        budget: &mut TokenBudget,
    ) -> anyhow::Result<AgentResult> {
        let agent_span = tracing::info_span!(
            "gym.agent",
            agent_name = %agent.name,
            model = %agent.model,
            investigation_id = %investigation_id,
            tokens_out = tracing::field::Empty,
        )
        .entered();

        let all_tools = agent_tools();
        let tools = filter_tools(&all_tools, &agent.tools);
        let model = &agent.model;
        let system_prompt = build_system_prompt(agent);

        let tokens_before = budget.used;
        let inv_id = investigation_id.to_string();

        let output = execute_with_tools(
            &self.client,
            model,
            &system_prompt,
            context,
            &tools,
            |tool_name, args| {
                let inv = inv_id.clone();
                let result = execute_tool(db, &inv, &tool_name, &args);
                async move { result }
            },
            budget,
        )
        .await?;

        let tokens_used = budget.used - tokens_before;
        agent_span.record("tokens_out", tokens_used);
        let (parsed_output, parsed_output_error) =
            parse_structured_output_for_agent(agent, &output);
        let context_frame = AgentContextFrame::from_agent(
            agent,
            &output,
            parsed_output.as_ref(),
            parsed_output_error.as_deref(),
        );

        Ok(AgentResult {
            agent_name: agent.name.clone(),
            output,
            tokens_used,
            context_frame,
            parsed_output,
            parsed_output_error,
        })
    }

    /// Run an agent with access to both the graph database and durable memory.
    ///
    /// Agents can use `store_memory` and `recall_memory` tools to persist
    /// and recall experiences across runs.
    pub async fn run_agent_with_db_and_memory(
        &self,
        agent: &AgentDefinition,
        investigation_id: &str,
        context: &str,
        db: &GraphDb,
        memory: &MemoryStore,
        budget: &mut TokenBudget,
    ) -> anyhow::Result<AgentResult> {
        let agent_span = tracing::info_span!(
            "gym.agent",
            agent_name = %agent.name,
            model = %agent.model,
            investigation_id = %investigation_id,
            tokens_out = tracing::field::Empty,
        )
        .entered();

        let all_tools = agent_tools();
        let tools = filter_tools(&all_tools, &agent.tools);
        let model = &agent.model;
        let system_prompt = build_system_prompt(agent);

        let tokens_before = budget.used;
        let inv_id = investigation_id.to_string();
        let agent_name_str = agent.name.clone();

        let output = execute_with_tools(
            &self.client,
            model,
            &system_prompt,
            context,
            &tools,
            |tool_name, args| {
                let inv = inv_id.clone();
                let name = agent_name_str.clone();
                let result = execute_tool_with_memory(
                    db,
                    &inv,
                    &tool_name,
                    &args,
                    Some(memory),
                    Some(&name),
                );
                async move { result }
            },
            budget,
        )
        .await?;

        let tokens_used = budget.used - tokens_before;
        agent_span.record("tokens_out", tokens_used);
        let (parsed_output, parsed_output_error) =
            parse_structured_output_for_agent(agent, &output);
        let context_frame = AgentContextFrame::from_agent(
            agent,
            &output,
            parsed_output.as_ref(),
            parsed_output_error.as_deref(),
        );

        Ok(AgentResult {
            agent_name: agent.name.clone(),
            output,
            tokens_used,
            context_frame,
            parsed_output,
            parsed_output_error,
        })
    }
}

fn build_system_prompt(agent: &AgentDefinition) -> String {
    let mut system_prompt = agent.system_prompt.clone();
    if let Some(schema_name) = &agent.output_schema {
        if let Some(contract) = output_schema_contract(schema_name) {
            system_prompt.push_str(contract);
        }
    }
    system_prompt
}

fn parse_structured_output_for_agent(
    agent: &AgentDefinition,
    output: &str,
) -> (Option<ParsedAgentOutput>, Option<String>) {
    let Some(schema_name) = &agent.output_schema else {
        return (None, None);
    };

    match parse_structured_output(schema_name, output) {
        Ok(parsed) => (Some(parsed), None),
        Err(error) => {
            let message = error.to_string();
            tracing::warn!(
                "Failed to parse structured output for agent '{}' with schema '{}': {}",
                agent.name,
                schema_name,
                message
            );
            (None, Some(message))
        }
    }
}

fn extract_key_points(output: &str) -> Vec<String> {
    const MAX_KEY_POINTS: usize = 10;
    const VERDICT_MARKERS: [&str; 6] = [
        "CONFIRMED",
        "DOWNGRADED",
        "REJECTED",
        "VULNERABLE",
        "MITIGATED",
        "SAFE",
    ];

    let lines: Vec<String> = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect();

    let mut points: Vec<String> = lines
        .iter()
        .filter(|line| VERDICT_MARKERS.iter().any(|marker| line.contains(marker)))
        .take(MAX_KEY_POINTS)
        .cloned()
        .collect();

    if points.is_empty() {
        points = lines
            .iter()
            .filter(|line| {
                line.starts_with("- ")
                    || line.starts_with("* ")
                    || line.chars().next().is_some_and(|c| c.is_ascii_digit())
            })
            .take(MAX_KEY_POINTS)
            .cloned()
            .collect();
    }

    if points.is_empty() {
        points = lines.into_iter().take(MAX_KEY_POINTS).collect();
    }

    points
}

/// Maximum characters for the analysis context sent to the LLM.
///
/// With 128K output tokens and ~250K input token budgets, agents can handle
/// substantial context. We include source code, graph data, and prior
/// findings to give agents enough information for real tool-calling analysis.
const DEFAULT_MAX_CONTEXT_CHARS: usize = 100_000;

/// Build context for the analysis from the graph database.
///
/// This summarizes the investigation data to give the agent a starting
/// point for its analysis.  The total output is truncated to
/// `max_context_chars` to stay within LLM token limits.
pub fn build_analysis_context(target: &str, investigation_id: &str, db: &GraphDb) -> String {
    build_analysis_context_with_limit(target, investigation_id, db, DEFAULT_MAX_CONTEXT_CHARS)
}

/// Build context with an explicit character limit.
pub fn build_analysis_context_with_limit(
    target: &str,
    investigation_id: &str,
    db: &GraphDb,
    max_context_chars: usize,
) -> String {
    let mut parts = vec![format!("Analyze target: {target}\n\nGraph DB summary:\n")];

    // Include source code if available — agents need to SEE the code to analyze it.
    // Look up the target path from the investigation and read it.
    if let Ok(mut stmt) = db
        .conn()
        .prepare("SELECT target FROM investigations WHERE id = ?1")
    {
        if let Ok(file_path) = stmt.query_row([investigation_id], |row| row.get::<_, String>(0)) {
            let path = std::path::Path::new(&file_path);
            if path.exists() {
                if let Ok(source) = std::fs::read_to_string(path) {
                    let max_source = 30_000; // ~10K tokens of source code
                    let display = if source.len() > max_source {
                        format!(
                            "{}...[truncated at {} chars]",
                            &source[..max_source],
                            max_source
                        )
                    } else {
                        source
                    };
                    parts.push(format!(
                        "\n## SOURCE CODE ({})\n\
                         Analyze this code carefully for vulnerabilities.\n\
                         ```\n{}\n```\n",
                        path.file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| file_path.clone()),
                        display,
                    ));
                }
            }
        }
    }

    // Summarize functions with confidence indicators
    if let Ok(mut stmt) = db.conn().prepare(
        "SELECT name, address, confidence FROM functions WHERE investigation_id = ?1 ORDER BY name LIMIT 20",
    ) {
        if let Ok(rows) = stmt.query_map([investigation_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, f64>(2).unwrap_or(0.0),
            ))
        }) {
            let funcs: Vec<(String, String, f64)> =
                rows.collect::<Result<Vec<_>, _>>().unwrap_or_default();
            if !funcs.is_empty() {
                parts.push(format!("\n## Functions ({} shown):\n", funcs.len()));
                let mut low_confidence_count = 0;
                for (name, addr, confidence) in &funcs {
                    if *confidence > 0.0 && *confidence < 0.5 {
                        parts.push(format!(
                            "- {name} @ {addr} [WARNING: LOW CONFIDENCE {:.0}% — decompiled output may be unreliable]",
                            confidence * 100.0
                        ));
                        low_confidence_count += 1;
                    } else if *confidence > 0.0 {
                        parts.push(format!("- {name} @ {addr} [confidence: {:.0}%]", confidence * 100.0));
                    } else {
                        parts.push(format!("- {name} @ {addr}"));
                    }
                }
                if low_confidence_count > 0 {
                    parts.push(format!(
                        "\n⚠ {} function(s) have low decompilation confidence. \
                         Treat findings in these functions with extra skepticism.",
                        low_confidence_count
                    ));
                }
            }
        }
    }

    // Imports and symbols from the investigation
    if let Ok(mut stmt) = db.conn().prepare(
        "SELECT name, symbol_type FROM symbols WHERE investigation_id = ?1 ORDER BY name LIMIT 50",
    ) {
        if let Ok(rows) = stmt.query_map([investigation_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }) {
            let symbols: Vec<(String, String)> =
                rows.collect::<Result<Vec<_>, _>>().unwrap_or_default();
            if !symbols.is_empty() {
                parts.push(format!(
                    "\n## IMPORTS & SYMBOLS ({} shown):\n",
                    symbols.len()
                ));
                for (name, sym_type) in &symbols {
                    parts.push(format!("- {name} [{sym_type}]"));
                }
            }
        }
    }

    // Data sources for the investigation
    if let Ok(mut stmt) = db.conn().prepare(
        "SELECT name, source_type, location FROM data_sources WHERE investigation_id = ?1 LIMIT 30",
    ) {
        if let Ok(rows) = stmt.query_map([investigation_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        }) {
            let sources: Vec<(String, String, String)> =
                rows.collect::<Result<Vec<_>, _>>().unwrap_or_default();
            if !sources.is_empty() {
                parts.push(format!("\n## DATA SOURCES ({}):\n", sources.len()));
                for (name, src_type, location) in &sources {
                    parts.push(format!("- {name} ({src_type}) @ {location}"));
                }
            }
        }
    }

    // Cross-file call graph (2-hop chains)
    if let Ok(mut stmt) = db.conn().prepare(
        "SELECT f2.name, f3.name FROM calls c1 \
         JOIN functions f2 ON c1.callee_id = f2.id \
         JOIN calls c2 ON f2.id = c2.caller_id \
         JOIN functions f3 ON c2.callee_id = f3.id \
         WHERE f2.investigation_id = ?1 LIMIT 30",
    ) {
        if let Ok(rows) = stmt.query_map([investigation_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }) {
            let chains: Vec<(String, String)> =
                rows.collect::<Result<Vec<_>, _>>().unwrap_or_default();
            if !chains.is_empty() {
                parts.push("\n## CROSS-FILE CALL GRAPH (2-hop chains):\n".into());
                for (hop1, hop2) in &chains {
                    parts.push(format!("- {hop1} -> {hop2}"));
                }
            }
        }
    }

    // String literal references
    if let Ok(mut stmt) = db.conn().prepare(
        "SELECT f.name, sl.value FROM func_references_string frs \
         JOIN functions f ON frs.function_id = f.id \
         JOIN string_literals sl ON frs.string_id = sl.id \
         WHERE f.investigation_id = ?1 LIMIT 30",
    ) {
        if let Ok(rows) = stmt.query_map([investigation_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }) {
            let refs: Vec<(String, String)> =
                rows.collect::<Result<Vec<_>, _>>().unwrap_or_default();
            if !refs.is_empty() {
                parts.push("\n## STRING LITERAL REFERENCES:\n".into());
                for (func_name, value) in &refs {
                    parts.push(format!("- {func_name}: \"{value}\""));
                }
            }
        }
    }

    // Summarize taint flows
    if let Ok(mut stmt) = db.conn().prepare(
        "SELECT s.name, k.name, tf.path FROM taint_flows tf \
         JOIN data_sources s ON tf.source_id = s.id \
         JOIN data_sinks k ON tf.sink_id = k.id \
         WHERE tf.sanitized = 0 AND s.investigation_id = ?1 LIMIT 10",
    ) {
        if let Ok(rows) = stmt.query_map([investigation_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        }) {
            let flows: Vec<(String, String, String)> =
                rows.collect::<Result<Vec<_>, _>>().unwrap_or_default();
            if !flows.is_empty() {
                parts.push(format!("\n## Unsanitized taint flows ({}):\n", flows.len()));
                for (src, sink, path) in &flows {
                    parts.push(format!("- {src} -> {sink}: {path}"));
                }
            }
        }
    }

    // Summarize dangerous API calls
    let dangerous: Vec<&str> = vec![
        "strcpy", "strcat", "sprintf", "gets", "scanf", "system", "exec", "popen", "memcpy",
        "memmove", "recv", "read",
    ];
    let param_placeholders: String = (0..dangerous.len())
        .map(|i| format!("?{}", i + 1))
        .collect::<Vec<_>>()
        .join(", ");
    let inv_param = format!("?{}", dangerous.len() + 1);
    let sql = format!(
        "SELECT f1.name, f2.name FROM calls c \
         JOIN functions f1 ON c.caller_id = f1.id \
         JOIN functions f2 ON c.callee_id = f2.id \
         WHERE f2.name IN ({param_placeholders}) AND f1.investigation_id = {inv_param} LIMIT 15"
    );
    if let Ok(mut stmt) = db.conn().prepare(&sql) {
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = dangerous
            .iter()
            .map(|n| Box::new(n.to_string()) as Box<dyn rusqlite::types::ToSql>)
            .collect();
        params.push(Box::new(investigation_id.to_string()) as Box<dyn rusqlite::types::ToSql>);
        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();
        if let Ok(rows) = stmt.query_map(params_refs.as_slice(), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }) {
            let calls: Vec<(String, String)> =
                rows.collect::<Result<Vec<_>, _>>().unwrap_or_default();
            if !calls.is_empty() {
                parts.push(format!("\n## Dangerous API calls ({}):\n", calls.len()));
                for (caller, callee) in &calls {
                    parts.push(format!("- {caller} -> {callee}"));
                }
            }
        }
    }

    // Include data flow edges from tree-sitter analysis
    if let Ok(mut stmt) = db
        .conn()
        .prepare("SELECT from_block, to_block FROM flows_to LIMIT 30")
    {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }) {
            let flows: Vec<(String, String)> =
                rows.collect::<Result<Vec<_>, _>>().unwrap_or_default();
            if !flows.is_empty() {
                parts.push(format!(
                    "\n## Data flow edges ({} — from tree-sitter analysis):\n\
                     These trace variable assignments and usage within functions.\n\
                     Format: <source> -> <destination>\n",
                    flows.len()
                ));
                for (from, to) in &flows {
                    parts.push(format!("- {} -> {}", from, to));
                }
            }
        }
    }

    // Include findings from taint analyzer and orchestrator
    if let Ok(mut stmt) = db.conn().prepare(
        "SELECT title, evidence, severity, category FROM findings \
         WHERE investigation_id = ?1 AND agent IN ('taint-analyzer', 'orchestrator') \
         AND status != 'invalidated' LIMIT 15",
    ) {
        if let Ok(rows) = stmt.query_map([investigation_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1).unwrap_or_default(),
                row.get::<_, String>(2).unwrap_or_default(),
                row.get::<_, String>(3).unwrap_or_default(),
            ))
        }) {
            let findings: Vec<(String, String, String, String)> =
                rows.collect::<Result<Vec<_>, _>>().unwrap_or_default();
            if !findings.is_empty() {
                parts.push(format!(
                    "\n## Prior analysis findings ({} — from taint/pattern analysis):\n\
                     These are HIGH PRIORITY leads. Investigate each one.\n",
                    findings.len()
                ));
                for (title, evidence, severity, category) in &findings {
                    parts.push(format!(
                        "- [{}] {}: {} ({})",
                        severity, title, evidence, category
                    ));
                }
            }
        }
    }

    parts.push(
        "\n\nYou have access to durable memory (store_memory/recall_memory tools). \
         Use recall_memory to check for relevant past experiences before starting your analysis. \
         Use store_memory to record significant findings and lessons learned. \
         Keep stored memories generalized — avoid target-specific addresses or paths."
            .into(),
    );

    parts.push(
        "\n\nStart your analysis. Use the tools to dig deeper, then create findings for \
         each confirmed vulnerability."
            .into(),
    );

    let full = parts.join("\n");

    // Truncate to stay within LLM token limits (char-boundary safe).
    if full.len() > max_context_chars {
        let mut boundary = max_context_chars;
        while boundary > 0 && !full.is_char_boundary(boundary) {
            boundary -= 1;
        }
        let mut truncated = full[..boundary].to_string();
        truncated.push_str("\n...[truncated]");
        truncated
    } else {
        full
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_agent(output_schema: Option<&str>) -> AgentDefinition {
        AgentDefinition {
            name: "vuln-hunter".into(),
            description: "Primary vulnerability discovery agent".into(),
            model: "claude-opus-4.6".into(),
            tools: vec!["create_finding".into()],
            max_turns: 5,
            role: None,
            output_schema: output_schema.map(str::to_string),
            system_prompt: "Base prompt".into(),
            source_path: None,
        }
    }

    #[test]
    fn build_system_prompt_includes_schema_contract() {
        let prompt = build_system_prompt(&test_agent(Some("vuln-hunter-v1")));
        assert!(prompt.contains("Structured Output Contract"));
        assert!(prompt.contains("\"summary\""));
    }

    #[test]
    fn parse_structured_output_for_agent_preserves_error() {
        let (_parsed, error) =
            parse_structured_output_for_agent(&test_agent(Some("vuln-hunter-v1")), "plain text");
        assert!(error.is_some());
        assert!(error.unwrap().contains("Missing fenced JSON block"));
    }

    #[test]
    fn context_frame_uses_structured_output_when_available() {
        let parsed = parse_structured_output(
            "vuln-hunter-v1",
            r#"Some prose
```json
{"summary":"Confirmed one exploitable issue","findings":[{"title":"Overflow","severity":"high","cwe_id":"CWE-121","function":"parse_header"}]}
```"#,
        )
        .unwrap();
        let agent = test_agent(Some("vuln-hunter-v1"));
        let frame = AgentContextFrame::from_agent(&agent, "ignored", Some(&parsed), None);
        assert_eq!(frame.output_schema.as_deref(), Some("vuln-hunter-v1"));
        assert!(frame
            .structured_summary
            .as_deref()
            .unwrap()
            .contains("Overflow"));
        assert!(frame
            .key_points
            .iter()
            .any(|point| point.contains("Overflow")));
    }

    // ===== Task 1: ENRICH-CONTEXT TDD tests =====
    // These tests define the contract for the 4 new context sections.
    // They will FAIL until build_analysis_context is updated.

    #[test]
    fn context_includes_symbols_imports_section() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        // Set up investigation
        db.execute(
            "INSERT INTO investigations (id, name, target) VALUES (?1, ?2, ?3)",
            &[
                &inv_id as &dyn rusqlite::types::ToSql,
                &"test",
                &"/nonexistent",
            ],
        )
        .unwrap();

        // Insert symbols
        db.execute(
            "INSERT INTO symbols (id, name, symbol_type, investigation_id) VALUES (?1, ?2, ?3, ?4)",
            &[
                &"s1" as &dyn rusqlite::types::ToSql,
                &"malloc",
                &"import",
                &inv_id,
            ],
        )
        .unwrap();
        db.execute(
            "INSERT INTO symbols (id, name, symbol_type, investigation_id) VALUES (?1, ?2, ?3, ?4)",
            &[
                &"s2" as &dyn rusqlite::types::ToSql,
                &"free",
                &"import",
                &inv_id,
            ],
        )
        .unwrap();

        let ctx = build_analysis_context_with_limit("target.c", inv_id, &db, 100_000);

        assert!(
            ctx.contains("IMPORTS") || ctx.contains("SYMBOLS"),
            "Context must include an imports/symbols section"
        );
        assert!(ctx.contains("malloc"), "Context must list symbol 'malloc'");
        assert!(ctx.contains("free"), "Context must list symbol 'free'");
    }

    #[test]
    fn context_includes_data_sources_section() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        db.execute(
            "INSERT INTO investigations (id, name, target) VALUES (?1, ?2, ?3)",
            &[
                &inv_id as &dyn rusqlite::types::ToSql,
                &"test",
                &"/nonexistent",
            ],
        )
        .unwrap();

        db.execute(
            "INSERT INTO data_sources (id, name, source_type, location, investigation_id) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                &"ds1" as &dyn rusqlite::types::ToSql,
                &"user_input",
                &"stdin",
                &"main.c:42",
                &inv_id,
            ],
        )
        .unwrap();

        let ctx = build_analysis_context_with_limit("target.c", inv_id, &db, 100_000);

        assert!(
            ctx.contains("DATA SOURCES"),
            "Context must include a data sources section"
        );
        assert!(
            ctx.contains("user_input"),
            "Context must list the data source name"
        );
        assert!(ctx.contains("stdin"), "Context must list the source type");
    }

    #[test]
    fn context_includes_cross_file_call_graph() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        db.execute(
            "INSERT INTO investigations (id, name, target) VALUES (?1, ?2, ?3)",
            &[
                &inv_id as &dyn rusqlite::types::ToSql,
                &"test",
                &"/nonexistent",
            ],
        )
        .unwrap();

        // Create 3 functions for 2-hop call chain: f1 -> f2 -> f3
        for (id, name, addr) in &[
            ("f1", "main", "file_a.c:0x1000"),
            ("f2", "helper", "file_b.c:0x2000"),
            ("f3", "sink_func", "file_c.c:0x3000"),
        ] {
            db.execute(
                "INSERT INTO functions (id, name, address, investigation_id) \
                 VALUES (?1, ?2, ?3, ?4)",
                &[id as &dyn rusqlite::types::ToSql, name, addr, &inv_id],
            )
            .unwrap();
        }
        db.execute(
            "INSERT INTO calls (caller_id, callee_id) VALUES (?1, ?2)",
            &[&"f1" as &dyn rusqlite::types::ToSql, &"f2"],
        )
        .unwrap();
        db.execute(
            "INSERT INTO calls (caller_id, callee_id) VALUES (?1, ?2)",
            &[&"f2" as &dyn rusqlite::types::ToSql, &"f3"],
        )
        .unwrap();

        let ctx = build_analysis_context_with_limit("target.c", inv_id, &db, 100_000);

        assert!(
            ctx.contains("CROSS-FILE") || ctx.contains("CALL GRAPH"),
            "Context must include a cross-file call graph section"
        );
        // The 2-hop chain should show helper -> sink_func (from f2 -> f3)
        assert!(
            ctx.contains("helper") && ctx.contains("sink_func"),
            "Context must show the 2-hop call chain"
        );
    }

    #[test]
    fn context_includes_string_references() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        db.execute(
            "INSERT INTO investigations (id, name, target) VALUES (?1, ?2, ?3)",
            &[
                &inv_id as &dyn rusqlite::types::ToSql,
                &"test",
                &"/nonexistent",
            ],
        )
        .unwrap();

        // Insert a function, a string literal, and the reference
        db.execute(
            "INSERT INTO functions (id, name, address, investigation_id) VALUES (?1, ?2, ?3, ?4)",
            &[
                &"f1" as &dyn rusqlite::types::ToSql,
                &"parse_cmd",
                &"main.c:0x1000",
                &inv_id,
            ],
        )
        .unwrap();
        db.execute(
            "INSERT INTO string_literals (id, value, investigation_id) VALUES (?1, ?2, ?3)",
            &[&"sl1" as &dyn rusqlite::types::ToSql, &"/bin/sh", &inv_id],
        )
        .unwrap();
        db.execute(
            "INSERT INTO func_references_string (function_id, string_id) VALUES (?1, ?2)",
            &[&"f1" as &dyn rusqlite::types::ToSql, &"sl1"],
        )
        .unwrap();

        let ctx = build_analysis_context_with_limit("target.c", inv_id, &db, 100_000);

        assert!(
            ctx.contains("STRING") || ctx.contains("LITERAL"),
            "Context must include a string references section"
        );
        assert!(
            ctx.contains("/bin/sh"),
            "Context must show the referenced string literal"
        );
    }

    #[test]
    fn context_source_code_budget_reduced_to_30k() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        // Create a temp file with 35K of source code
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let big_source = "x".repeat(35_000);
        std::fs::write(tmp.path(), &big_source).unwrap();

        db.execute(
            "INSERT INTO investigations (id, name, target) VALUES (?1, ?2, ?3)",
            &[
                &inv_id as &dyn rusqlite::types::ToSql,
                &"test",
                &tmp.path().to_str().unwrap(),
            ],
        )
        .unwrap();

        let ctx = build_analysis_context_with_limit("target.c", inv_id, &db, 100_000);

        // With max_source=30K, 35K source should be truncated
        assert!(
            ctx.contains("truncated"),
            "35K source should be truncated at 30K limit"
        );
        // The context should NOT contain the full 35K
        let source_section_end = ctx.find("truncated").unwrap();
        let source_start = ctx.find("SOURCE CODE").unwrap_or(0);
        let source_section = &ctx[source_start..source_section_end + 20];
        // Verify truncation happened at ~30K, not 40K
        assert!(
            source_section.len() < 32_000,
            "Source section should be truncated around 30K, not 40K"
        );
    }

    #[test]
    fn context_symbols_section_respects_limit() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        db.execute(
            "INSERT INTO investigations (id, name, target) VALUES (?1, ?2, ?3)",
            &[
                &inv_id as &dyn rusqlite::types::ToSql,
                &"test",
                &"/nonexistent",
            ],
        )
        .unwrap();

        // Insert 60 symbols — should be capped at 50
        for i in 0..60 {
            db.execute(
                "INSERT INTO symbols (id, name, symbol_type, investigation_id) \
                 VALUES (?1, ?2, ?3, ?4)",
                &[
                    &format!("s{i}") as &dyn rusqlite::types::ToSql,
                    &format!("sym_{i}"),
                    &"import",
                    &inv_id,
                ],
            )
            .unwrap();
        }

        let ctx = build_analysis_context_with_limit("target.c", inv_id, &db, 100_000);

        // Should contain sym_0 (early entries)
        assert!(ctx.contains("sym_0"), "Should include early symbols");
        // Should NOT contain sym_59 (beyond the 50-row limit)
        assert!(
            !ctx.contains("sym_59"),
            "Should respect 50-row limit on symbols"
        );
    }
}
