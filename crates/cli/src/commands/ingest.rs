//! `skwaq ingest` - ingest binary, source, or SARIF data.

use super::IngestSub;
use skwaq_core::analysis::patterns::DangerousApiDetector;
use skwaq_core::analysis::surface::identify_attack_surface;
use skwaq_core::binary::native::parse_binary;
use skwaq_core::config::Config;
use skwaq_core::graph::builder::GraphBuilder;
use skwaq_core::graph::db::GraphDb;
use skwaq_core::source::{detect_language, is_source_file, parse_file};
use std::path::PathBuf;

pub fn run(sub: &IngestSub) -> anyhow::Result<()> {
    match sub {
        IngestSub::Binary { path } => ingest_binary(path),
        IngestSub::Source { path } => ingest_source(path),
        IngestSub::Sarif { path } => {
            anyhow::bail!(
                "SARIF report ingestion not yet implemented. Path: {}",
                path.display()
            );
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

    // 5. Open graph DB via Config (creates directory if needed).
    let db_dir = Config::load()?.database_path();
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

fn ingest_source(path: &PathBuf) -> anyhow::Result<()> {
    println!("Ingesting source code from: {}", path.display());

    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", path.display());
    }

    // 1. Walk the directory tree and collect source files.
    let source_files = collect_source_files(path)?;
    if source_files.is_empty() {
        anyhow::bail!(
            "No recognized source files found in {}. Supported: .py, .js, .ts, .go, .rs, .java, .c, .cpp, .h",
            path.display()
        );
    }

    println!("[scan]    Found {} source file(s)", source_files.len());

    // Count files per language.
    let mut lang_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for f in &source_files {
        if let Some(lang) = detect_language(f.as_path()) {
            *lang_counts.entry(lang.to_string()).or_default() += 1;
        }
    }
    let lang_summary: Vec<String> = lang_counts
        .iter()
        .map(|(lang, count)| format!("{}: {}", lang, count))
        .collect();
    println!("[langs]   {}", lang_summary.join(" | "));

    // 2. Parse each source file.
    let mut parsed_files = Vec::new();
    let mut parse_errors = 0;

    for file_path in &source_files {
        match parse_file(file_path) {
            Ok(parsed) => parsed_files.push(parsed),
            Err(e) => {
                tracing::warn!("Failed to parse {}: {}", file_path.display(), e);
                parse_errors += 1;
            }
        }
    }

    println!(
        "[parse]   Parsed {} file(s) ({} errors)",
        parsed_files.len(),
        parse_errors
    );

    // 3. Generate investigation ID and open DB.
    let inv_id = format!("inv-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let db_dir = Config::load()?.database_path();
    let db = GraphDb::open(&db_dir)?;

    // 4. Create investigation record.
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
            &format!("source:{}", target_name).as_str(),
            &path.display().to_string().as_str(),
            &now.as_str(),
            &now.as_str(),
        ],
    )?;

    // 5. Populate graph from parsed source files.
    let builder = GraphBuilder::new(&db);
    let counts = builder.build_from_source(&parsed_files, &inv_id)?;

    println!(
        "[graph]   Files: {} | Functions: {} | Calls: {} | Strings: {} | Imports: {}",
        counts.files, counts.functions, counts.calls, counts.strings, counts.imports,
    );
    println!(
        "[surface] Sources: {} | Sinks: {}",
        counts.sources, counts.sinks,
    );

    // 6. Run initial dangerous pattern detection on all source files.
    let detector = DangerousApiDetector::new();
    let mut total_hits = 0;
    for parsed in &parsed_files {
        match detector.detect_in_source(
            std::path::Path::new(&parsed.path),
            &parsed.language,
        ) {
            Ok(hits) => {
                for hit in &hits {
                    let finding_id = uuid::Uuid::new_v4().to_string();
                    let _ = db.execute(
                        "INSERT INTO findings (id, title, evidence, agent, timestamp, investigation_id) \
                         VALUES (?1, ?2, ?3, 'source-pattern-detector', ?4, ?5)",
                        &[
                            &finding_id.as_str(),
                            &format!(
                                "Dangerous pattern: {} ({}:{})",
                                hit.function_name, hit.file, hit.line
                            )
                            .as_str(),
                            &format!(
                                "category={}, severity={}, reason={}",
                                hit.danger_category, hit.severity, hit.reason
                            )
                            .as_str(),
                            &now.as_str(),
                            &inv_id.as_str(),
                        ],
                    );
                    total_hits += 1;
                }
            }
            Err(e) => {
                tracing::warn!("Pattern detection failed for {}: {}", parsed.path, e);
            }
        }
    }

    if total_hits > 0 {
        println!(
            "[detect]  Found {} dangerous pattern(s) across source files",
            total_hits
        );
    }

    // 7. Print DB summary.
    println!(
        "[db]      Investigation {} stored in {}",
        inv_id,
        db_dir.display(),
    );

    println!();
    println!(
        "Ready. Run: skwaq analyze --quick --investigation {}",
        inv_id
    );

    Ok(())
}

/// Recursively collect source files from a path.
fn collect_source_files(path: &PathBuf) -> anyhow::Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    if path.is_file() {
        if is_source_file(path) {
            files.push(path.clone());
        }
        return Ok(files);
    }

    // Walk directory tree, skipping common non-source directories.
    let skip_dirs: std::collections::HashSet<&str> = [
        "target",
        "node_modules",
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "vendor",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
    ]
    .iter()
    .copied()
    .collect();

    walk_dir(path, &skip_dirs, &mut files)?;
    Ok(files)
}

fn walk_dir(
    dir: &PathBuf,
    skip_dirs: &std::collections::HashSet<&str>,
    files: &mut Vec<PathBuf>,
) -> anyhow::Result<()> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| anyhow::anyhow!("Cannot read directory {}: {}", dir.display(), e))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if skip_dirs.contains(name) || name.starts_with('.') {
                    continue;
                }
            }
            walk_dir(&path, skip_dirs, files)?;
        } else if is_source_file(&path) {
            files.push(path);
        }
    }

    Ok(())
}
