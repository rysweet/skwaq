//! Graph enrichment from Ghidra decompilation results.

use super::builder::{GraphBuilder, GhidraInsertCounts};
use crate::binary::types::GhidraAnalysis;

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

        self.db().mutate("BEGIN TRANSACTION;")?;

        let result =
            self.build_from_ghidra_inner(analysis, investigation_id, &mut counts);

        if result.is_ok() {
            self.db().mutate("COMMIT;")?;
        } else {
            if let Err(e) = self.db().mutate("ROLLBACK;") {
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
            let mut stmt = self.db().conn().prepare(
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
                    self.db().execute(
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
                self.db().execute(
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
                        self.db().execute(
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

                self.db().execute(
                    "INSERT OR IGNORE INTO calls (caller_id, callee_id) VALUES (?1, ?2)",
                    &[&caller_id.as_str(), &callee_id.as_str()],
                )?;
                counts.calls_added += 1;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::types::*;
    use crate::graph::db::GraphDb;

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
