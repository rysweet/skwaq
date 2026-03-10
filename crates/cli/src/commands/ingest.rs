//! `skwaq ingest` - ingest binary, source, or SARIF data.

use super::IngestSub;
use skwaq_core::analysis::surface::identify_attack_surface;
use skwaq_core::binary::native::parse_binary;
use skwaq_core::graph::builder::GraphBuilder;
use skwaq_core::graph::db::GraphDb;
use std::path::PathBuf;

pub fn run(sub: &IngestSub) -> anyhow::Result<()> {
    match sub {
        IngestSub::Binary { path } => ingest_binary(path),
        IngestSub::Source { path } => {
            println!("skwaq ingest source: coming soon ({})", path.display());
            Ok(())
        }
        IngestSub::Sarif { path } => {
            println!("skwaq ingest sarif: coming soon ({})", path.display());
            Ok(())
        }
    }
}

fn ingest_binary(path: &PathBuf) -> anyhow::Result<()> {
    // 1. Parse the binary.
    let info = parse_binary(path)?;

    // 2. Display checksec hardening report.
    let h = &info.hardening;
    println!(
        "[checksec] PIE: {} | NX: {} | Canary: {} | RELRO: {} | Fortify: {}",
        h.pie, h.nx, h.canary, h.relro, h.fortify,
    );

    // 3. Display binary metadata.
    println!(
        "[binary]  Format: {} {} | Stripped: {} | Sections: {}",
        info.format,
        info.architecture,
        if info.is_stripped { "Yes" } else { "No" },
        info.sections.len(),
    );

    // 4. Generate investigation ID.
    let inv_id = format!("inv-{}", &uuid::Uuid::new_v4().to_string()[..8]);

    // 5. Open graph DB.
    let db_dir = graph_db_path()?;
    let db = GraphDb::open(&db_dir)?;

    // 6. Create investigation record.
    let now = chrono::Utc::now().to_rfc3339();
    let target_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string());
    db.execute(
        "INSERT INTO investigations (id, name, target, status, created_at, updated_at) \
         VALUES (?1, ?2, ?3, 'active', ?4, ?5)",
        &[
            &inv_id.as_str(),
            &target_name.as_str(),
            &path.display().to_string().as_str(),
            &now.as_str(),
            &now.as_str(),
        ],
    )?;

    // 7. Populate graph from binary info.
    let builder = GraphBuilder::new(&db);
    let counts = builder.build_from_binary_info(&info, &inv_id)?;

    println!(
        "[graph]   Functions: {} | Strings: {} | Imports: {}",
        counts.functions, counts.strings, counts.imports,
    );

    // 8. Attack surface analysis.
    let surface = identify_attack_surface(&info);
    println!(
        "[surface] Network: {} | File: {} | IPC: {} | Input: {}",
        surface.network.len(),
        surface.file.len(),
        surface.ipc.len(),
        surface.input.len(),
    );

    // 9. Print DB summary.
    println!(
        "[db]      Investigation {} stored in {}",
        inv_id,
        db_dir.display(),
    );

    println!();
    println!("Ready. Run: skwaq analyze --investigation {}", inv_id);

    Ok(())
}

/// Return the default graph DB directory: `.skwaq/graph/` under current dir.
fn graph_db_path() -> anyhow::Result<PathBuf> {
    let dir = std::env::current_dir()?.join(".skwaq").join("graph");
    Ok(dir)
}
