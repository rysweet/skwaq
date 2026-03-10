//! Graph construction helpers for populating the SQLite database with
//! analysis artifacts such as functions, call edges, and extracted strings.

use super::db::GraphDb;
use crate::analysis::surface::{
    identify_source_sinks_in_content, SourceSinkKind, SINK_PATTERNS, SOURCE_PATTERNS,
};
use crate::binary::types::BinaryInfo;
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
            let _ = self.db.mutate("ROLLBACK;");
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
            let _ = self.db.mutate("ROLLBACK;");
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
}
