//! Graph construction from parsed source files.

use super::builder::{GraphBuilder, SourceInsertCounts};
use crate::analysis::surface::{identify_source_sinks_in_content, SourceSinkKind};
use crate::source::ParsedSource;

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

        self.db().mutate("BEGIN TRANSACTION;")?;

        let result = self.build_from_source_inner(parsed_files, investigation_id, &mut counts);

        if result.is_ok() {
            self.db().mutate("COMMIT;")?;
        } else if let Err(e) = self.db().mutate("ROLLBACK;") {
            tracing::error!("Failed to rollback transaction: {e}");
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
                self.db().execute(
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
                self.db().execute(
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
                let enclosing = parsed.functions.iter().rfind(|f| f.line <= call.line);

                if let Some(enc) = enclosing {
                    let caller_id = format!("{}-fn-{}-L{}", file_prefix, enc.name, enc.line);
                    self.db().execute(
                        "INSERT OR IGNORE INTO calls (caller_id, callee_id) VALUES (?1, ?2)",
                        &[&caller_id.as_str(), &callee_id.as_str()],
                    )?;
                    counts.calls += 1;
                }
            }

            // Insert string literals (cap at 2000 per file).
            for s in parsed.string_literals.iter().take(2000) {
                let id = format!("{}-str-L{}", file_prefix, s.line);
                self.db().execute(
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
                self.db().execute(
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
                let ss_hits =
                    identify_source_sinks_in_content(content, &parsed.language, &parsed.path)?;

                for hit in &ss_hits {
                    match hit.kind {
                        SourceSinkKind::Source => {
                            let src_id =
                                format!("{}-source-{}-L{}", file_prefix, hit.category, hit.line);
                            self.db().execute(
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
                            let sink_id =
                                format!("{}-sink-{}-L{}", file_prefix, hit.category, hit.line);
                            self.db().execute(
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
