//! Graph construction helpers for populating the SQLite database with
//! analysis artifacts such as functions, call edges, and extracted strings.

use super::db::GraphDb;
use crate::analysis::surface::{
    identify_source_sinks_in_content, SourceSinkKind, SINK_PATTERNS, SOURCE_PATTERNS,
};
use crate::binary::types::{BinaryInfo, GhidraAnalysis};
use crate::source::ParsedSource;
use serde::Serialize;

/// Counts of nodes inserted by `build_from_binary_info`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct InsertCounts {
    pub functions: usize,
    pub imports: usize,
    pub strings: usize,
    pub sources: usize,
    pub sinks: usize,
}

/// Fluent builder for inserting analysis data into the graph.
pub struct GraphBuilder<'a> {
    db: &'a GraphDb,
}

impl<'a> GraphBuilder<'a> {
    /// Create a new builder backed by `db`.
    pub fn new(db: &'a GraphDb) -> Self {
        Self { db }
    }

    /// Populate the graph from parsed binary info.
    ///
    /// Inserts function nodes (from symbols of type Func), import nodes,
    /// string literal nodes, and classifies imports as data sources or sinks.
    pub fn build_from_binary_info(
        &self,
        info: &BinaryInfo,
        investigation_id: &str,
    ) -> anyhow::Result<InsertCounts> {
        let mut counts = InsertCounts::default();

        // Wrap all inserts in a single transaction for performance.
        self.db.mutate("BEGIN TRANSACTION;")?;

        let result = self.build_from_binary_info_inner(info, investigation_id, &mut counts);

        if result.is_ok() {
            self.db.mutate("COMMIT;")?;
        } else {
            if let Err(e) = self.db.mutate("ROLLBACK;") {
                tracing::error!("Failed to rollback transaction: {e}");
            }
        }

        result?;
        Ok(counts)
    }

    fn build_from_binary_info_inner(
        &self,
        info: &BinaryInfo,
        investigation_id: &str,
        counts: &mut InsertCounts,
    ) -> anyhow::Result<()> {
        // Insert function nodes from symbols that look like functions.
        for sym in &info.symbols {
            // goblin st_type: STT_FUNC = 2. Debug format produces "2".
            if sym.symbol_type == "2" || sym.symbol_type.contains("Func") {
                let id = format!("func-{:x}-{}", sym.address, &sym.name);
                self.db.execute(
                    "INSERT OR IGNORE INTO functions (id, name, address, investigation_id) \
                     VALUES (?1, ?2, ?3, ?4)",
                    &[&id.as_str(), &sym.name.as_str(), &format!("0x{:x}", sym.address).as_str(), &investigation_id],
                )?;
                counts.functions += 1;
            }
        }

        // Insert import nodes as symbols.
        for imp in &info.imports {
            let id = format!("imp-{}", &imp.name);
            self.db.execute(
                "INSERT OR IGNORE INTO symbols (id, name, symbol_type, binding, investigation_id) \
                 VALUES (?1, ?2, 'import', 'dynamic', ?3)",
                &[&id.as_str(), &imp.name.as_str(), &investigation_id],
            )?;
            counts.imports += 1;

            // Classify as data source.
            let base = imp.name.split('@').next().unwrap_or(&imp.name);
            if SOURCE_PATTERNS.iter().any(|p| base == *p) {
                let src_id = format!("src-{}", &imp.name);
                let source_type = classify_source(base);
                self.db.execute(
                    "INSERT OR IGNORE INTO data_sources (id, name, source_type, investigation_id) \
                     VALUES (?1, ?2, ?3, ?4)",
                    &[&src_id.as_str(), &imp.name.as_str(), &source_type, &investigation_id],
                )?;
                counts.sources += 1;
            }

            // Classify as data sink.
            if SINK_PATTERNS.iter().any(|p| base == *p) {
                let sink_id = format!("sink-{}", &imp.name);
                let danger = classify_sink_danger(base);
                self.db.execute(
                    "INSERT OR IGNORE INTO data_sinks (id, name, sink_type, danger_level, investigation_id) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    &[&sink_id.as_str(), &imp.name.as_str(), &"dangerous_api", &danger, &investigation_id],
                )?;
                counts.sinks += 1;
            }
        }

        // Insert string literals (cap at 5000 to avoid huge DBs for large binaries).
        let max_strings = 5000;
        for s in info.strings.iter().take(max_strings) {
            let id = format!("str-{:x}", s.offset);
            self.db.execute(
                "INSERT OR IGNORE INTO string_literals (id, value, offset, investigation_id) \
                 VALUES (?1, ?2, ?3, ?4)",
                &[&id.as_str(), &s.value.as_str(), &format!("{}", s.offset).as_str(), &investigation_id],
            )?;
            counts.strings += 1;
        }

        Ok(())
    }

    /// Insert a function node into the graph.
    pub fn insert_function(
        &self,
        id: &str,
        name: &str,
        address: &str,
        _file: &str,
    ) -> anyhow::Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO functions (id, name, address, decompiled, confidence) \
             VALUES (?1, ?2, ?3, '', 0.0)",
            &[&id, &name, &address],
        )?;
        Ok(())
    }

    /// Insert a CALLS relationship between two functions.
    pub fn insert_call(&self, caller_id: &str, callee_id: &str) -> anyhow::Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO calls (caller_id, callee_id) VALUES (?1, ?2)",
            &[&caller_id, &callee_id],
        )?;
        Ok(())
    }

    /// Insert a DataSource node representing an extracted string or input.
    pub fn insert_string_source(
        &self,
        id: &str,
        name: &str,
        kind: &str,
    ) -> anyhow::Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO data_sources (id, name, source_type) VALUES (?1, ?2, ?3)",
            &[&id, &name, &kind],
        )?;
        Ok(())
    }

    /// Insert a DataSink node.
    pub fn insert_data_sink(
        &self,
        id: &str,
        name: &str,
        kind: &str,
    ) -> anyhow::Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO data_sinks (id, name, sink_type) VALUES (?1, ?2, ?3)",
            &[&id, &name, &kind],
        )?;
        Ok(())
    }

    /// Insert a taint flow relationship between a source and sink.
    pub fn insert_taint_flow(
        &self,
        source_id: &str,
        sink_id: &str,
        path: &str,
    ) -> anyhow::Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO taint_flows (source_id, sink_id, path, sanitized) \
             VALUES (?1, ?2, ?3, 0)",
            &[&source_id, &sink_id, &path],
        )?;
        Ok(())
    }
}

/// Counts of nodes updated/inserted by Ghidra analysis enrichment.
#[derive(Debug, Clone, Default, Serialize)]
pub struct GhidraInsertCounts {
    pub functions_updated: usize,
    pub functions_added: usize,
    pub calls_added: usize,
}

impl<'a> GraphBuilder<'a> {
    /// Enrich the graph with Ghidra decompilation results.
    ///
    /// Updates existing function nodes with decompiled code, adds new function
    /// nodes discovered by Ghidra (it finds more than goblin), and stores call
    /// relationships from Ghidra's call graph.
    pub fn build_from_ghidra_analysis(
        &self,
        analysis: &GhidraAnalysis,
        investigation_id: &str,
    ) -> anyhow::Result<GhidraInsertCounts> {
        let mut counts = GhidraInsertCounts::default();

        self.db.mutate("BEGIN TRANSACTION;")?;

        let result =
            self.build_from_ghidra_inner(analysis, investigation_id, &mut counts);

        if result.is_ok() {
            self.db.mutate("COMMIT;")?;
        } else {
            if let Err(e) = self.db.mutate("ROLLBACK;") {
                tracing::error!("Failed to rollback transaction: {e}");
            }
        }

        result?;
        Ok(counts)
    }

    fn build_from_ghidra_inner(
        &self,
        analysis: &GhidraAnalysis,
        investigation_id: &str,
        counts: &mut GhidraInsertCounts,
    ) -> anyhow::Result<()> {
        // Build lookups from existing functions so we can match Ghidra
        // functions to goblin functions. We need both address and name
        // matching because goblin uses file offsets (e.g. 0x10d0) while
        // Ghidra uses full virtual addresses (e.g. 00101000).
        let mut addr_to_id: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut name_to_id: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        {
            let mut stmt = self.db.conn().prepare(
                "SELECT id, name, address FROM functions WHERE investigation_id = ?1",
            )?;
            let rows = stmt.query_map([investigation_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            for row in rows {
                let (id, name, addr) = row?;
                addr_to_id.insert(addr.clone(), id.clone());
                // Also store without 0x prefix for matching
                if let Some(stripped) = addr.strip_prefix("0x") {
                    addr_to_id.insert(stripped.to_string(), id.clone());
                }
                // Store by name (strip @GLIBC suffixes for matching)
                let base_name = name.split('@').next().unwrap_or(&name).to_string();
                name_to_id.insert(base_name, id);
            }
        }

        // Build a map from Ghidra address to the DB function id we assign
        let mut ghidra_addr_to_db_id: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        for gfunc in &analysis.functions {
            // Try to find an existing function by address first, then by name.
            // Address matching: goblin stores "0x10d0", Ghidra stores "00101000".
            // These often differ due to PIE base address differences.
            let existing_id = addr_to_id.get(&gfunc.address)
                .or_else(|| {
                    let with_prefix = format!("0x{}", &gfunc.address);
                    addr_to_id.get(&with_prefix)
                })
                .or_else(|| {
                    // Try stripping leading zeros from Ghidra address
                    let stripped = gfunc.address.trim_start_matches('0');
                    if !stripped.is_empty() {
                        addr_to_id.get(stripped)
                            .or_else(|| addr_to_id.get(&format!("0x{}", stripped)))
                    } else {
                        None
                    }
                })
                .or_else(|| {
                    // Fall back to name matching - reliable for non-stripped binaries
                    let base_name = gfunc.name.split('@').next().unwrap_or(&gfunc.name);
                    // Skip generic Ghidra names like FUN_00101234
                    if !base_name.starts_with("FUN_") && !base_name.starts_with("DAT_") {
                        name_to_id.get(base_name)
                    } else {
                        None
                    }
                });

            if let Some(func_id) = existing_id {
                // Update existing function with decompiled code
                if let Some(ref decomp) = gfunc.decompiled {
                    self.db.execute(
                        "UPDATE functions SET decompiled = ?1, parameter_count = ?2 \
                         WHERE id = ?3",
                        &[
                            &decomp.as_str(),
                            &(gfunc.parameter_count as i64) as &dyn rusqlite::types::ToSql,
                            &func_id.as_str(),
                        ],
                    )?;
                    counts.functions_updated += 1;
                }
                ghidra_addr_to_db_id.insert(gfunc.address.clone(), func_id.clone());
            } else {
                // New function discovered by Ghidra - insert it
                let func_id = format!("ghidra-{}-{}", &gfunc.address, &gfunc.name);
                self.db.execute(
                    "INSERT OR IGNORE INTO functions \
                     (id, name, address, decompiled, parameter_count, investigation_id) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    &[
                        &func_id.as_str(),
                        &gfunc.name.as_str(),
                        &gfunc.address.as_str(),
                        &gfunc.decompiled.as_deref().unwrap_or(""),
                        &(gfunc.parameter_count as i64) as &dyn rusqlite::types::ToSql,
                        &investigation_id,
                    ],
                )?;
                counts.functions_added += 1;
                ghidra_addr_to_db_id.insert(gfunc.address.clone(), func_id);
            }
        }

        // Insert call relationships from Ghidra's call graph
        for gfunc in &analysis.functions {
            let caller_id = match ghidra_addr_to_db_id.get(&gfunc.address) {
                Some(id) => id.clone(),
                None => continue,
            };

            for call_addr in &gfunc.calls {
                let callee_id = match ghidra_addr_to_db_id.get(call_addr) {
                    Some(id) => id.clone(),
                    None => {
                        // Callee not in our map - it may be an external function.
                        // Create a stub entry for it.
                        let stub_id = format!("ghidra-ext-{}", call_addr);
                        self.db.execute(
                            "INSERT OR IGNORE INTO functions (id, name, address, investigation_id) \
                             VALUES (?1, ?2, ?3, ?4)",
                            &[
                                &stub_id.as_str(),
                                &format!("sub_{}", call_addr).as_str(),
                                &call_addr.as_str(),
                                &investigation_id,
                            ],
                        )?;
                        stub_id
                    }
                };

                self.db.execute(
                    "INSERT OR IGNORE INTO calls (caller_id, callee_id) VALUES (?1, ?2)",
                    &[&caller_id.as_str(), &callee_id.as_str()],
                )?;
                counts.calls_added += 1;
            }
        }

        Ok(())
    }
}

/// Counts of nodes inserted by `build_from_source`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SourceInsertCounts {
    pub files: usize,
    pub functions: usize,
    pub calls: usize,
    pub strings: usize,
    pub imports: usize,
    pub sources: usize,
    pub sinks: usize,
}

impl<'a> GraphBuilder<'a> {
    /// Populate the graph from parsed source files.
    ///
    /// Inserts function nodes, call edges, string literals, import records,
    /// and identifies data sources/sinks from the parsed source.
    pub fn build_from_source(
        &self,
        parsed_files: &[ParsedSource],
        investigation_id: &str,
    ) -> anyhow::Result<SourceInsertCounts> {
        let mut counts = SourceInsertCounts::default();

        self.db.mutate("BEGIN TRANSACTION;")?;

        let result =
            self.build_from_source_inner(parsed_files, investigation_id, &mut counts);

        if result.is_ok() {
            self.db.mutate("COMMIT;")?;
        } else {
            if let Err(e) = self.db.mutate("ROLLBACK;") {
                tracing::error!("Failed to rollback transaction: {e}");
            }
        }

        result?;
        Ok(counts)
    }

    fn build_from_source_inner(
        &self,
        parsed_files: &[ParsedSource],
        investigation_id: &str,
        counts: &mut SourceInsertCounts,
    ) -> anyhow::Result<()> {
        for parsed in parsed_files {
            counts.files += 1;
            let file_prefix = format!(
                "src-{}-{}",
                parsed.language,
                parsed.path.replace(['/', '\\', '.'], "_")
            );

            // Insert functions.
            for func in &parsed.functions {
                let id = format!("{}-fn-{}-L{}", file_prefix, func.name, func.line);
                self.db.execute(
                    "INSERT OR IGNORE INTO functions (id, name, address, language, investigation_id) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    &[
                        &id.as_str(),
                        &func.name.as_str(),
                        &format!("{}:{}", parsed.path, func.line).as_str(),
                        &parsed.language.as_str(),
                        &investigation_id,
                    ],
                )?;
                counts.functions += 1;
            }

            // Insert call edges.
            // We create callee function stubs if they don't already exist,
            // then link caller -> callee.
            for call in &parsed.calls {
                let callee_id = format!("{}-call-{}", file_prefix, call.name.replace('.', "_"));
                // Ensure callee node exists (may be external).
                self.db.execute(
                    "INSERT OR IGNORE INTO functions (id, name, language, investigation_id) \
                     VALUES (?1, ?2, ?3, ?4)",
                    &[
                        &callee_id.as_str(),
                        &call.name.as_str(),
                        &parsed.language.as_str(),
                        &investigation_id,
                    ],
                )?;

                // Find enclosing function (closest function with line <= call.line).
                let enclosing = parsed
                    .functions
                    .iter()
                    .filter(|f| f.line <= call.line)
                    .last();

                if let Some(enc) = enclosing {
                    let caller_id = format!("{}-fn-{}-L{}", file_prefix, enc.name, enc.line);
                    self.db.execute(
                        "INSERT OR IGNORE INTO calls (caller_id, callee_id) VALUES (?1, ?2)",
                        &[&caller_id.as_str(), &callee_id.as_str()],
                    )?;
                    counts.calls += 1;
                }
            }

            // Insert string literals (cap at 2000 per file).
            for s in parsed.string_literals.iter().take(2000) {
                let id = format!("{}-str-L{}", file_prefix, s.line);
                self.db.execute(
                    "INSERT OR IGNORE INTO string_literals (id, value, offset, investigation_id) \
                     VALUES (?1, ?2, ?3, ?4)",
                    &[
                        &id.as_str(),
                        &s.value.as_str(),
                        &format!("{}:{}", parsed.path, s.line).as_str(),
                        &investigation_id,
                    ],
                )?;
                counts.strings += 1;
            }

            // Insert imports as symbols.
            for imp in &parsed.imports {
                let id = format!("{}-imp-{}", file_prefix, imp.replace(['/', '.', ':'], "_"));
                self.db.execute(
                    "INSERT OR IGNORE INTO symbols (id, name, symbol_type, binding, investigation_id) \
                     VALUES (?1, ?2, 'import', 'source', ?3)",
                    &[&id.as_str(), &imp.as_str(), &investigation_id],
                )?;
                counts.imports += 1;
            }

            // Identify and store data sources and sinks.
            let source_content = parsed
                .functions
                .iter()
                .map(|_| "") // We need the original content for source/sink detection.
                .next();

            // Re-read file content for source/sink identification.
            // The parsed struct doesn't carry raw content, so we use the
            // path.  If the file can't be read (e.g. during tests with
            // synthetic data), skip this step gracefully.
            let raw_content = std::fs::read_to_string(&parsed.path).ok();
            if let Some(ref content) = raw_content {
                let _ = source_content; // suppress warning
                let ss_hits = identify_source_sinks_in_content(
                    content,
                    &parsed.language,
                    &parsed.path,
                )?;

                for hit in &ss_hits {
                    match hit.kind {
                        SourceSinkKind::Source => {
                            let src_id = format!(
                                "{}-source-{}-L{}",
                                file_prefix,
                                hit.category,
                                hit.line
                            );
                            self.db.execute(
                                "INSERT OR IGNORE INTO data_sources \
                                 (id, name, source_type, location, investigation_id) \
                                 VALUES (?1, ?2, ?3, ?4, ?5)",
                                &[
                                    &src_id.as_str(),
                                    &hit.name.as_str(),
                                    &hit.category.as_str(),
                                    &format!("{}:{}", parsed.path, hit.line).as_str(),
                                    &investigation_id,
                                ],
                            )?;
                            counts.sources += 1;
                        }
                        SourceSinkKind::Sink => {
                            let sink_id = format!(
                                "{}-sink-{}-L{}",
                                file_prefix,
                                hit.category,
                                hit.line
                            );
                            self.db.execute(
                                "INSERT OR IGNORE INTO data_sinks \
                                 (id, name, sink_type, danger_level, location, investigation_id) \
                                 VALUES (?1, ?2, ?3, 'high', ?4, ?5)",
                                &[
                                    &sink_id.as_str(),
                                    &hit.name.as_str(),
                                    &hit.category.as_str(),
                                    &format!("{}:{}", parsed.path, hit.line).as_str(),
                                    &investigation_id,
                                ],
                            )?;
                            counts.sinks += 1;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Classify a source import into a category string.
fn classify_source(name: &str) -> &'static str {
    match name {
        "recv" | "recvfrom" | "recvmsg" | "accept" => "network",
        "read" | "fread" | "fgets" | "fopen" | "open" => "file",
        "scanf" | "sscanf" | "fscanf" | "getchar" | "getline" | "readline" | "gets" => "input",
        "getenv" => "environment",
        _ => "other",
    }
}

/// Classify sink danger level.
fn classify_sink_danger(name: &str) -> &'static str {
    match name {
        "strcpy" | "gets" | "sprintf" | "system" | "exec" | "execve" | "execvp" | "popen" => {
            "critical"
        }
        "memcpy" | "memmove" | "strncpy" | "snprintf" | "strcat" | "strncat" => "high",
        "free" | "realloc" | "malloc" => "medium",
        _ => "low",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::types::*;

    #[test]
    fn test_build_from_binary_info_empty() {
        let db = GraphDb::in_memory().unwrap();
        let builder = GraphBuilder::new(&db);
        let info = BinaryInfo {
            format: BinaryFormat::Elf,
            architecture: "x86_64".into(),
            bits: 64,
            endianness: "little".into(),
            is_stripped: false,
            entry_point: 0,
            sections: vec![],
            symbols: vec![],
            imports: vec![],
            strings: vec![],
            hardening: HardeningInfo::default(),
        };
        let counts = builder.build_from_binary_info(&info, "inv-test").unwrap();
        assert_eq!(counts.functions, 0);
        assert_eq!(counts.imports, 0);
        assert_eq!(counts.strings, 0);
    }

    #[test]
    fn test_build_from_binary_info_with_data() {
        let db = GraphDb::in_memory().unwrap();
        let builder = GraphBuilder::new(&db);
        let info = BinaryInfo {
            format: BinaryFormat::Elf,
            architecture: "x86_64".into(),
            bits: 64,
            endianness: "little".into(),
            is_stripped: false,
            entry_point: 0x401000,
            sections: vec![],
            symbols: vec![
                SymbolInfo {
                    name: "main".into(),
                    address: 0x401000,
                    size: 100,
                    symbol_type: "2".into(), // STT_FUNC
                    binding: "Global".into(),
                },
                SymbolInfo {
                    name: "some_data".into(),
                    address: 0x600000,
                    size: 8,
                    symbol_type: "1".into(), // STT_OBJECT
                    binding: "Local".into(),
                },
            ],
            imports: vec![
                ImportInfo { name: "recv".into(), library: String::new() },
                ImportInfo { name: "strcpy".into(), library: String::new() },
                ImportInfo { name: "printf".into(), library: String::new() },
            ],
            strings: vec![
                ExtractedString {
                    value: "hello".into(),
                    offset: 100,
                    encoding: StringEncoding::Ascii,
                },
            ],
            hardening: HardeningInfo::default(),
        };

        let counts = builder.build_from_binary_info(&info, "inv-test").unwrap();
        assert_eq!(counts.functions, 1); // only "main" is Func
        assert_eq!(counts.imports, 3);
        assert_eq!(counts.strings, 1);
        assert_eq!(counts.sources, 1); // recv
        assert_eq!(counts.sinks, 1); // strcpy

        // Verify data in DB
        let func_count: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM functions WHERE investigation_id = 'inv-test'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(func_count, 1);

        let src_count: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM data_sources WHERE investigation_id = 'inv-test'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(src_count, 1);
    }

    #[test]
    fn test_build_from_ghidra_updates_existing_functions() {
        let db = GraphDb::in_memory().unwrap();
        let builder = GraphBuilder::new(&db);

        // First, insert a function via binary info (simulating goblin output).
        let info = BinaryInfo {
            format: BinaryFormat::Elf,
            architecture: "x86_64".into(),
            bits: 64,
            endianness: "little".into(),
            is_stripped: false,
            entry_point: 0x401000,
            sections: vec![],
            symbols: vec![SymbolInfo {
                name: "main".into(),
                address: 0x401000,
                size: 100,
                symbol_type: "2".into(),
                binding: "Global".into(),
            }],
            imports: vec![],
            strings: vec![],
            hardening: HardeningInfo::default(),
        };
        builder.build_from_binary_info(&info, "inv-ghidra").unwrap();

        // Now enrich with Ghidra analysis
        let ghidra = GhidraAnalysis {
            functions: vec![
                GhidraFunction {
                    name: "main".into(),
                    address: "401000".into(), // without 0x prefix (Ghidra style)
                    size: 100,
                    decompiled: Some("int main(int argc, char **argv) {\n  system(argv[1]);\n  return 0;\n}".into()),
                    calls: vec!["401100".into()],
                    called_by: vec![],
                    parameter_count: 2,
                },
                GhidraFunction {
                    name: "helper".into(),
                    address: "401100".into(),
                    size: 50,
                    decompiled: Some("void helper(void) { return; }".into()),
                    calls: vec![],
                    called_by: vec!["401000".into()],
                    parameter_count: 0,
                },
            ],
            strings: vec![],
            imports: vec![],
        };

        let gcounts = builder.build_from_ghidra_analysis(&ghidra, "inv-ghidra").unwrap();

        // main should be updated (address match via 0x prefix stripping)
        assert_eq!(gcounts.functions_updated, 1);
        // helper is new
        assert_eq!(gcounts.functions_added, 1);
        // main->helper call edge
        assert_eq!(gcounts.calls_added, 1);

        // Verify decompiled code was stored
        let decomp: String = db
            .conn()
            .query_row(
                "SELECT decompiled FROM functions WHERE name = 'main' AND investigation_id = 'inv-ghidra'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(decomp.contains("system(argv[1])"));

        // Verify helper function exists
        let helper_count: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM functions WHERE name = 'helper' AND investigation_id = 'inv-ghidra'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(helper_count, 1);

        // Verify call edge exists
        let call_count: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM calls",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(call_count, 1);
    }

    #[test]
    fn test_build_from_ghidra_empty_analysis() {
        let db = GraphDb::in_memory().unwrap();
        let builder = GraphBuilder::new(&db);

        let ghidra = GhidraAnalysis {
            functions: vec![],
            strings: vec![],
            imports: vec![],
        };

        let gcounts = builder.build_from_ghidra_analysis(&ghidra, "inv-empty").unwrap();
        assert_eq!(gcounts.functions_updated, 0);
        assert_eq!(gcounts.functions_added, 0);
        assert_eq!(gcounts.calls_added, 0);
    }
}
