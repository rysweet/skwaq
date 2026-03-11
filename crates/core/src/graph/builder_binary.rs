//! Graph construction from parsed binary info (goblin output).

use super::builder::{GraphBuilder, InsertCounts};
use crate::analysis::surface::{SINK_PATTERNS, SOURCE_PATTERNS};
use crate::binary::types::BinaryInfo;

impl<'a> GraphBuilder<'a> {
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
        self.db().mutate("BEGIN TRANSACTION;")?;

        let result = self.build_from_binary_info_inner(info, investigation_id, &mut counts);

        if result.is_ok() {
            self.db().mutate("COMMIT;")?;
        } else if let Err(e) = self.db().mutate("ROLLBACK;") {
            tracing::error!("Failed to rollback transaction: {e}");
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
                self.db().execute(
                    "INSERT OR IGNORE INTO functions (id, name, address, investigation_id) \
                     VALUES (?1, ?2, ?3, ?4)",
                    &[
                        &id.as_str(),
                        &sym.name.as_str(),
                        &format!("0x{:x}", sym.address).as_str(),
                        &investigation_id,
                    ],
                )?;
                counts.functions += 1;
            }
        }

        // Insert import nodes as symbols.
        for imp in &info.imports {
            let id = format!("imp-{}", &imp.name);
            self.db().execute(
                "INSERT OR IGNORE INTO symbols (id, name, symbol_type, binding, investigation_id) \
                 VALUES (?1, ?2, 'import', 'dynamic', ?3)",
                &[&id.as_str(), &imp.name.as_str(), &investigation_id],
            )?;
            counts.imports += 1;

            // Classify as data source.
            let base = imp.name.split('@').next().unwrap_or(&imp.name);
            if SOURCE_PATTERNS.contains(&base) {
                let src_id = format!("src-{}", &imp.name);
                let source_type = classify_source(base);
                self.db().execute(
                    "INSERT OR IGNORE INTO data_sources (id, name, source_type, investigation_id) \
                     VALUES (?1, ?2, ?3, ?4)",
                    &[
                        &src_id.as_str(),
                        &imp.name.as_str(),
                        &source_type,
                        &investigation_id,
                    ],
                )?;
                counts.sources += 1;
            }

            // Classify as data sink.
            if SINK_PATTERNS.contains(&base) {
                let sink_id = format!("sink-{}", &imp.name);
                let danger = classify_sink_danger(base);
                self.db().execute(
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
            self.db().execute(
                "INSERT OR IGNORE INTO string_literals (id, value, offset, investigation_id) \
                 VALUES (?1, ?2, ?3, ?4)",
                &[
                    &id.as_str(),
                    &s.value.as_str(),
                    &format!("{}", s.offset).as_str(),
                    &investigation_id,
                ],
            )?;
            counts.strings += 1;
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
    use crate::graph::db::GraphDb;

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
                ImportInfo {
                    name: "recv".into(),
                    library: String::new(),
                },
                ImportInfo {
                    name: "strcpy".into(),
                    library: String::new(),
                },
                ImportInfo {
                    name: "printf".into(),
                    library: String::new(),
                },
            ],
            strings: vec![ExtractedString {
                value: "hello".into(),
                offset: 100,
                encoding: StringEncoding::Ascii,
            }],
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
                |row: &rusqlite::Row| row.get(0),
            )
            .unwrap();
        assert_eq!(func_count, 1);

        let src_count: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM data_sources WHERE investigation_id = 'inv-test'",
                [],
                |row: &rusqlite::Row| row.get(0),
            )
            .unwrap();
        assert_eq!(src_count, 1);
    }
}
