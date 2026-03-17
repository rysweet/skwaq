//! Taint analysis via graph traversal and source-level chain detection.
//!
//! `TaintAnalyzer` queries the SQLite graph for data-flow paths from
//! sources to sinks that lack sanitisation, producing candidate
//! vulnerability findings.
//!
//! Two strategies are used:
//! 1. Pre-computed taint flows (from the `taint_flows` table populated
//!    during ingestion).
//! 2. On-the-fly call-chain traversal using a recursive CTE to discover
//!    paths from data sources to data sinks through the call graph.
//!
//! Additionally, `detect_stack_buffer_write_chains` performs source-level
//! detection of CWE-121 (stack-based buffer overflow) by tracing fixed-size
//! stack buffer declarations to downstream unbounded write operations within
//! the same function scope.

use crate::graph::GraphDb;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Performs taint analysis over the property graph.
pub struct TaintAnalyzer<'a> {
    db: &'a GraphDb,
    max_depth: u32,
}

impl<'a> TaintAnalyzer<'a> {
    pub fn new(db: &'a GraphDb, max_depth: u32) -> Self {
        Self { db, max_depth }
    }

    /// Find data-flow paths from sources to sinks where no sanitiser
    /// appears along the path.
    ///
    /// First checks pre-computed `taint_flows`, then uses a recursive CTE
    /// to discover additional paths through the call graph.
    pub fn find_unsanitized_paths(&self) -> anyhow::Result<Vec<TaintPath>> {
        let mut results = Vec::new();

        // Strategy 1: Pre-computed taint flows from ingestion
        results.extend(self.query_precomputed_flows()?);

        // Strategy 2: On-the-fly discovery via recursive CTE
        results.extend(self.discover_paths_via_call_graph()?);

        // Deduplicate by (source, sink) pair
        results.sort_by(|a, b| (&a.source, &a.sink).cmp(&(&b.source, &b.sink)));
        results.dedup_by(|a, b| a.source == b.source && a.sink == b.sink);

        Ok(results)
    }

    /// Query the pre-computed taint_flows table.
    fn query_precomputed_flows(&self) -> anyhow::Result<Vec<TaintPath>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT s.name, k.name, tf.path FROM taint_flows tf \
             JOIN data_sources s ON tf.source_id = s.id \
             JOIN data_sinks k ON tf.sink_id = k.id \
             WHERE tf.sanitized = 0",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(TaintPath {
                source: row.get::<_, String>(0)?,
                sink: row.get::<_, String>(1)?,
                hops: row
                    .get::<_, String>(2)?
                    .split("->")
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
                sanitized: false,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Use a recursive CTE to trace call chains from functions matching
    /// data source names to functions matching data sink names.
    fn discover_paths_via_call_graph(&self) -> anyhow::Result<Vec<TaintPath>> {
        let max_depth = self.max_depth;

        // Get all data source function names
        let mut src_stmt = self
            .db
            .conn()
            .prepare("SELECT DISTINCT name FROM data_sources")?;
        let sources: Vec<String> = src_stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;

        // Get all data sink function names
        let mut sink_stmt = self
            .db
            .conn()
            .prepare("SELECT DISTINCT name FROM data_sinks")?;
        let sinks: Vec<String> = sink_stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;

        if sources.is_empty() || sinks.is_empty() {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();

        // For each source, trace call chains and see if any reach a sink
        for source in &sources {
            // Find the function id(s) matching this source name
            let mut id_stmt = self
                .db
                .conn()
                .prepare("SELECT id FROM functions WHERE name = ?1")?;
            let source_ids: Vec<String> = id_stmt
                .query_map([source.as_str()], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;

            for source_id in &source_ids {
                // Recursive CTE to walk the call graph
                let sql = "WITH RECURSIVE call_chain(func_id, func_name, path, depth) AS ( \
                         SELECT f.id, f.name, f.name, 0 \
                         FROM functions f WHERE f.id = ?1 \
                         UNION ALL \
                         SELECT f2.id, f2.name, cc.path || ' -> ' || f2.name, cc.depth + 1 \
                         FROM calls c \
                         JOIN call_chain cc ON c.caller_id = cc.func_id \
                         JOIN functions f2 ON c.callee_id = f2.id \
                         WHERE cc.depth < ?2 \
                     ) \
                     SELECT func_name, path FROM call_chain WHERE depth > 0";

                let mut cte_stmt = self.db.conn().prepare(sql)?;
                let rows = cte_stmt
                    .query_map(rusqlite::params![source_id.as_str(), max_depth], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?;

                for row in rows {
                    let (func_name, path) = row?;
                    if sinks.contains(&func_name) {
                        results.push(TaintPath {
                            source: source.clone(),
                            sink: func_name,
                            hops: path.split(" -> ").map(|s| s.trim().to_string()).collect(),
                            sanitized: false,
                        });
                    }
                }
            }
        }

        Ok(results)
    }
}

/// A single unsanitized taint path from source to sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPath {
    pub source: String,
    pub sink: String,
    pub hops: Vec<String>,
    pub sanitized: bool,
}

/// A detected chain where a fixed-size stack buffer flows into an
/// unbounded write API within the same function scope (CWE-121).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackBufferWriteChain {
    /// The variable name of the stack buffer (e.g. "buf").
    pub buffer_var: String,
    /// The declared size of the buffer (e.g. 64 for `char buf[64]`).
    pub buffer_size: String,
    /// The dangerous write API called with this buffer (e.g. "strcpy").
    pub write_api: String,
    /// Line number of the buffer declaration.
    pub decl_line: usize,
    /// Line number of the dangerous write call.
    pub write_line: usize,
}

/// Dangerous write APIs that can overflow a fixed-size stack buffer when
/// called without explicit bounds checking.
const UNBOUNDED_WRITE_APIS: &[&str] = &[
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf", "sscanf", "fscanf", "wcscpy",
    "wcscat", "lstrcpyA", "lstrcpyW", "lstrcpy", "lstrcatA", "lstrcatW", "lstrcat", "memcpy",
    "memmove",
];

/// Detect CWE-121 stack-buffer-to-write chains in C/C++ source code.
///
/// Scans for fixed-size stack buffer declarations (`char buf[N]`, `int arr[N]`,
/// `alloca(N)`) and then checks whether an unbounded write API references that
/// same buffer variable within the same function body. Only produces a finding
/// when BOTH a stack allocation AND an unsafe write to it are present — bare
/// declarations without a downstream write are NOT flagged.
pub fn detect_stack_buffer_write_chains(content: &str) -> Vec<StackBufferWriteChain> {
    // Phase 1: split content into per-function bodies so we only match
    // buffer+write pairs that co-occur in the same function scope.
    let function_bodies = split_into_function_bodies(content);

    let mut chains = Vec::new();

    // Regex for fixed-size stack array: `type var[size]`
    // Captures: (var_name, array_size)
    let stack_array_re = Regex::new(
        r"(?m)\b(?:char|unsigned\s+char|int|unsigned\s+int|short|long|uint8_t|uint16_t|uint32_t|wchar_t|TCHAR|WCHAR|BYTE|CHAR)\s+(\w+)\s*\[\s*(\w+)\s*\]",
    ).unwrap();

    // Regex for alloca: `type *var = (type *)alloca(size)`
    let alloca_re =
        Regex::new(r"(?m)\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?alloca\s*\(\s*(\w+)\s*\)").unwrap();

    for (func_body, base_line) in &function_bodies {
        // Collect stack buffers declared in this function
        let mut buffers: Vec<(String, String, usize)> = Vec::new(); // (var, size, line)

        for cap in stack_array_re.captures_iter(func_body) {
            let var = cap[1].to_string();
            let size = cap[2].to_string();
            let byte_offset = cap.get(0).unwrap().start();
            let line = base_line + func_body[..byte_offset].matches('\n').count();
            buffers.push((var, size, line));
        }

        for cap in alloca_re.captures_iter(func_body) {
            let var = cap[1].to_string();
            let size = cap[2].to_string();
            let byte_offset = cap.get(0).unwrap().start();
            let line = base_line + func_body[..byte_offset].matches('\n').count();
            buffers.push((var, size, line));
        }

        // For each buffer, check if any unbounded write API uses it
        for (var, size, decl_line) in &buffers {
            for api in UNBOUNDED_WRITE_APIS {
                // Match: api(var, ...) or api(..., var, ...) — the buffer
                // appears as an argument to the dangerous API.
                let pattern = format!(
                    r"\b{api}\s*\([^)]*\b{var}\b",
                    api = regex::escape(api),
                    var = regex::escape(var),
                );
                if let Ok(re) = Regex::new(&pattern) {
                    for m in re.find_iter(func_body) {
                        let byte_offset = m.start();
                        let write_line = base_line + func_body[..byte_offset].matches('\n').count();
                        chains.push(StackBufferWriteChain {
                            buffer_var: var.clone(),
                            buffer_size: size.clone(),
                            write_api: api.to_string(),
                            decl_line: *decl_line,
                            write_line,
                        });
                    }
                }
            }
        }
    }

    // Deduplicate by (buffer_var, write_api, write_line)
    chains.sort_by(|a, b| {
        (&a.buffer_var, &a.write_api, a.write_line).cmp(&(
            &b.buffer_var,
            &b.write_api,
            b.write_line,
        ))
    });
    chains.dedup_by(|a, b| {
        a.buffer_var == b.buffer_var && a.write_api == b.write_api && a.write_line == b.write_line
    });

    chains
}

/// Split C/C++ source into approximate function bodies with their starting
/// line offsets. Uses a simple brace-counting heuristic — good enough for
/// the pattern-level analysis we need without a full parser.
fn split_into_function_bodies(content: &str) -> Vec<(String, usize)> {
    let mut bodies = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    // Look for function-like patterns: `type name(...)` followed by `{`
    let func_sig_re = Regex::new(r"^[a-zA-Z_][\w\s\*]*\b\w+\s*\([^)]*\)\s*\{?\s*$").unwrap();

    while i < lines.len() {
        let line = lines[i].trim();

        // Detect function start
        if func_sig_re.is_match(line)
            || (line.ends_with(')') && i + 1 < lines.len() && lines[i + 1].trim() == "{")
        {
            // Find the opening brace
            let mut brace_line = i;
            if !line.contains('{') {
                // Look ahead for opening brace
                for (j, lookahead) in lines.iter().enumerate().skip(i + 1).take(2) {
                    if lookahead.trim().starts_with('{') {
                        brace_line = j;
                        break;
                    }
                }
                if brace_line == i {
                    i += 1;
                    continue;
                }
            }

            // Count braces to find function end
            let func_start = i;
            let mut depth = 0;
            let mut func_end = brace_line;
            for (j, body_line) in lines.iter().enumerate().skip(brace_line) {
                for ch in body_line.chars() {
                    if ch == '{' {
                        depth += 1;
                    } else if ch == '}' {
                        depth -= 1;
                        if depth == 0 {
                            func_end = j;
                            break;
                        }
                    }
                }
                if depth == 0 && func_end > brace_line {
                    break;
                }
            }

            if func_end > func_start {
                let body = lines[func_start..=func_end].join("\n");
                // Line numbers are 1-based
                bodies.push((body, func_start + 1));
                i = func_end + 1;
                continue;
            }
        }
        i += 1;
    }

    // If we couldn't parse any functions, treat the entire content as one body
    // so we still detect chains in flat/unparseable code.
    if bodies.is_empty() && !content.is_empty() {
        bodies.push((content.to_string(), 1));
    }

    bodies
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_precomputed_flows() {
        let db = GraphDb::in_memory().unwrap();

        db.execute(
            "INSERT INTO data_sources (id, name, source_type) VALUES ('src1', 'recv', 'network')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO data_sinks (id, name, sink_type, danger_level) VALUES ('sink1', 'strcpy', 'memory', 'critical')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO taint_flows (source_id, sink_id, path, sanitized) VALUES ('src1', 'sink1', 'recv -> process -> strcpy', 0)",
            &[],
        )
        .unwrap();

        let analyzer = TaintAnalyzer::new(&db, 10);
        let paths = analyzer.find_unsanitized_paths().unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].source, "recv");
        assert_eq!(paths[0].sink, "strcpy");
        assert_eq!(paths[0].hops.len(), 3);
    }

    #[test]
    fn test_call_graph_discovery() {
        let db = GraphDb::in_memory().unwrap();

        // Set up a call chain: recv -> process -> strcpy
        db.execute(
            "INSERT INTO functions (id, name) VALUES ('f1', 'recv')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO functions (id, name) VALUES ('f2', 'process')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO functions (id, name) VALUES ('f3', 'strcpy')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO calls (caller_id, callee_id) VALUES ('f1', 'f2')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO calls (caller_id, callee_id) VALUES ('f2', 'f3')",
            &[],
        )
        .unwrap();

        // Register source and sink
        db.execute(
            "INSERT INTO data_sources (id, name, source_type) VALUES ('src1', 'recv', 'network')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO data_sinks (id, name, sink_type) VALUES ('sink1', 'strcpy', 'memory')",
            &[],
        )
        .unwrap();

        let analyzer = TaintAnalyzer::new(&db, 10);
        let paths = analyzer.find_unsanitized_paths().unwrap();
        assert!(!paths.is_empty());
        let path = &paths[0];
        assert_eq!(path.source, "recv");
        assert_eq!(path.sink, "strcpy");
    }

    #[test]
    fn test_no_paths_when_empty() {
        let db = GraphDb::in_memory().unwrap();
        let analyzer = TaintAnalyzer::new(&db, 10);
        let paths = analyzer.find_unsanitized_paths().unwrap();
        assert!(paths.is_empty());
    }

    #[test]
    fn test_sanitized_flows_excluded() {
        let db = GraphDb::in_memory().unwrap();

        db.execute(
            "INSERT INTO data_sources (id, name, source_type) VALUES ('src1', 'recv', 'network')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO data_sinks (id, name, sink_type) VALUES ('sink1', 'strcpy', 'memory')",
            &[],
        )
        .unwrap();
        // This flow IS sanitized — should be excluded
        db.execute(
            "INSERT INTO taint_flows (source_id, sink_id, path, sanitized) VALUES ('src1', 'sink1', 'recv -> validate -> strcpy', 1)",
            &[],
        )
        .unwrap();

        let analyzer = TaintAnalyzer::new(&db, 10);
        let paths = analyzer.find_unsanitized_paths().unwrap();
        assert!(paths.is_empty());
    }

    // --- Stack buffer write chain tests ---

    #[test]
    fn chain_detects_strcpy_into_stack_buffer() {
        let src = r#"
void vuln(char *input) {
    char buf[64];
    strcpy(buf, input);
}
"#;
        let chains = detect_stack_buffer_write_chains(src);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].buffer_var, "buf");
        assert_eq!(chains[0].buffer_size, "64");
        assert_eq!(chains[0].write_api, "strcpy");
    }

    #[test]
    fn chain_detects_sprintf_into_stack_buffer() {
        let src = r#"
void format_input(const char *user) {
    char output[128];
    sprintf(output, "Hello %s", user);
}
"#;
        let chains = detect_stack_buffer_write_chains(src);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].buffer_var, "output");
        assert_eq!(chains[0].write_api, "sprintf");
    }

    #[test]
    fn chain_detects_gets_into_stack_buffer() {
        let src = r#"
void read_line() {
    char line[256];
    gets(line);
}
"#;
        let chains = detect_stack_buffer_write_chains(src);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].write_api, "gets");
    }

    #[test]
    fn chain_detects_memcpy_into_stack_buffer() {
        let src = r#"
void copy_data(const void *src, size_t len) {
    unsigned char buf[512];
    memcpy(buf, src, len);
}
"#;
        let chains = detect_stack_buffer_write_chains(src);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].write_api, "memcpy");
    }

    #[test]
    fn chain_detects_alloca_to_write() {
        let src = r#"
void dynamic_stack(const char *input, size_t n) {
    char *tmp = (char *)alloca(n);
    strcpy(tmp, input);
}
"#;
        let chains = detect_stack_buffer_write_chains(src);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].buffer_var, "tmp");
        assert_eq!(chains[0].write_api, "strcpy");
    }

    #[test]
    fn chain_ignores_declaration_only() {
        // Just declaring a buffer with no dangerous write should NOT produce a chain
        let src = r#"
void safe_func() {
    char buf[64];
    buf[0] = 'a';
}
"#;
        let chains = detect_stack_buffer_write_chains(src);
        assert!(
            chains.is_empty(),
            "declaration-only should not trigger a chain"
        );
    }

    #[test]
    fn chain_ignores_heap_buffer() {
        // malloc'd buffer is NOT a stack buffer — should not trigger
        let src = r#"
void heap_func(const char *input) {
    char *buf = malloc(64);
    strcpy(buf, input);
    free(buf);
}
"#;
        let chains = detect_stack_buffer_write_chains(src);
        assert!(
            chains.is_empty(),
            "heap allocation should not trigger stack chain"
        );
    }

    #[test]
    fn chain_detects_multiple_writes_to_same_buffer() {
        let src = r#"
void multi_write(const char *a, const char *b) {
    char buf[64];
    strcpy(buf, a);
    strcat(buf, b);
}
"#;
        let chains = detect_stack_buffer_write_chains(src);
        assert_eq!(chains.len(), 2);
        let apis: Vec<&str> = chains.iter().map(|c| c.write_api.as_str()).collect();
        assert!(apis.contains(&"strcpy"));
        assert!(apis.contains(&"strcat"));
    }

    #[test]
    fn chain_detects_wide_char_buffer() {
        let src = r#"
void wide_vuln(const wchar_t *input) {
    wchar_t wbuf[128];
    wcscpy(wbuf, input);
}
"#;
        let chains = detect_stack_buffer_write_chains(src);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].write_api, "wcscpy");
    }

    #[test]
    fn chain_multiple_functions_isolated() {
        // Chains should be scoped to functions — a buffer in func A
        // should not match a write in func B.
        let src = r#"
void func_a() {
    char buf[64];
}

void func_b(const char *input) {
    char other[64];
    strcpy(other, input);
}
"#;
        let chains = detect_stack_buffer_write_chains(src);
        // Should find chain in func_b only (other + strcpy), not buf
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].buffer_var, "other");
    }
}
