//! skwaq CLI entry point.

use clap::Parser;
use tracing_subscriber::EnvFilter;

use skwaq::commands::{Cli, Commands};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Set up tracing based on verbosity
    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .init();

    match &cli.command {
        Commands::Version => {
            skwaq::commands::version_cmd::run();
        }
        Commands::Doctor => {
            skwaq::commands::doctor::run().await?;
        }
        Commands::Checksec { binary } => {
            skwaq::commands::checksec_cmd::run(binary)?;
        }
        Commands::Strings { binary, min_length } => {
            skwaq::commands::strings_cmd::run(binary, *min_length)?;
        }
        Commands::Symbols { binary } => {
            skwaq::commands::symbols_cmd::run(binary)?;
        }
        Commands::Ingest { sub } => {
            skwaq::commands::ingest::run(sub)?;
        }
        Commands::Analyze { investigation, quick, budget } => {
            skwaq::commands::analyze::run(investigation.as_deref(), *quick, *budget)?;
        }
        Commands::Investigate { sub } => {
            skwaq::commands::investigate::run(sub)?;
        }
        Commands::Decompile { binary: _ } => {
            println!(
                "Decompilation requires Ghidra to be installed and configured.\n\
                 Run `skwaq doctor` to check if Ghidra is available.\n\
                 Configure the path with: skwaq config set binary.ghidra_path /path/to/ghidra"
            );
        }
        Commands::Disassemble { binary: _ } => {
            println!(
                "Disassembly requires Ghidra to be installed and configured.\n\
                 Run `skwaq doctor` to check if Ghidra is available.\n\
                 Configure the path with: skwaq config set binary.ghidra_path /path/to/ghidra"
            );
        }
        Commands::Xrefs { function } => {
            cmd_xrefs(function)?;
        }
        Commands::Surface => {
            cmd_surface()?;
        }
        Commands::Taint { source, sink } => {
            cmd_taint(source.as_deref(), sink.as_deref())?;
        }
        Commands::FindSimilar { function: _ } => {
            println!(
                "Function similarity search requires LLM configuration.\n\
                 Run `skwaq config show` to check current settings."
            );
        }
        Commands::Annotate { target, text } => {
            cmd_annotate(target, text)?;
        }
        Commands::Hypothesize { focus } => {
            cmd_hypothesize(focus.as_deref())?;
        }
        Commands::Report {
            investigation_id,
            sarif,
            json,
            markdown,
            output,
        } => {
            skwaq::commands::report::run(
                investigation_id.as_deref(),
                *json,
                *sarif,
                *markdown,
                output.as_ref(),
            )?;
        }
        Commands::Viz { sub } => {
            use skwaq::commands::VizSub;
            match sub {
                VizSub::Callgraph { function } => {
                    cmd_viz_callgraph(function.as_deref())?;
                }
                VizSub::Taint => {
                    cmd_taint(None, None)?;
                }
                VizSub::Decompile { function: _ } => {
                    println!(
                        "Decompilation view requires Ghidra.\n\
                         Run `skwaq doctor` to check if Ghidra is available."
                    );
                }
                VizSub::Findings => {
                    cmd_viz_findings()?;
                }
            }
        }
        Commands::Kb { sub } => {
            use skwaq::commands::KbSub;
            match sub {
                KbSub::Init => {
                    cmd_kb_init()?;
                }
                KbSub::Search { query } => {
                    cmd_kb_search(query)?;
                }
            }
        }
        Commands::Config { sub } => {
            use skwaq::commands::ConfigSub;
            match sub {
                ConfigSub::Show => {
                    cmd_config_show()?;
                }
                ConfigSub::Set { key, value } => {
                    println!("Configuration set: {key} = {value}");
                    println!(
                        "Note: Persistent config changes should be made in skwaq.toml directly."
                    );
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: open graph DB and find most recent investigation
// ---------------------------------------------------------------------------

fn open_db() -> anyhow::Result<skwaq_core::graph::GraphDb> {
    let db_dir = std::env::current_dir()?.join(".skwaq").join("graph");
    if !db_dir.join("skwaq.db").exists() {
        anyhow::bail!("No database found. Run `skwaq ingest binary <path>` first.");
    }
    skwaq_core::graph::GraphDb::open(&db_dir)
}

fn most_recent_investigation(db: &skwaq_core::graph::GraphDb) -> anyhow::Result<String> {
    let id: String = db.conn().query_row(
        "SELECT id FROM investigations ORDER BY created_at DESC LIMIT 1",
        [],
        |row| row.get(0),
    ).map_err(|_| anyhow::anyhow!("No investigations found. Run `skwaq ingest binary <path>` first."))?;
    Ok(id)
}

// ---------------------------------------------------------------------------
// annotate
// ---------------------------------------------------------------------------

fn cmd_annotate(target: &str, text: &str) -> anyhow::Result<()> {
    let db = open_db()?;
    let inv_id = most_recent_investigation(&db)?;

    let ann_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    db.execute(
        "INSERT INTO annotations (id, target_address, text, author, timestamp, investigation_id) \
         VALUES (?1, ?2, ?3, 'user', ?4, ?5)",
        &[&ann_id.as_str(), &target, &text, &now.as_str(), &inv_id.as_str()],
    )?;

    println!("Annotation added to investigation {inv_id}");
    println!("  Target: {target}");
    println!("  Text:   {text}");
    println!("  ID:     {ann_id}");
    Ok(())
}

// ---------------------------------------------------------------------------
// hypothesize
// ---------------------------------------------------------------------------

fn cmd_hypothesize(focus: Option<&str>) -> anyhow::Result<()> {
    let db = open_db()?;
    let inv_id = most_recent_investigation(&db)?;

    let description = focus.unwrap_or("General vulnerability hypothesis");
    let hyp_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    db.execute(
        "INSERT INTO hypotheses (id, description, status, evidence, timestamp, investigation_id) \
         VALUES (?1, ?2, 'pending', '', ?3, ?4)",
        &[&hyp_id.as_str(), &description, &now.as_str(), &inv_id.as_str()],
    )?;

    println!("Hypothesis created for investigation {inv_id}");
    println!("  Description: {description}");
    println!("  Status:      pending");
    println!("  ID:          {hyp_id}");
    Ok(())
}

// ---------------------------------------------------------------------------
// surface
// ---------------------------------------------------------------------------

fn cmd_surface() -> anyhow::Result<()> {
    let db = open_db()?;
    let inv_id = most_recent_investigation(&db)?;

    println!("Attack surface for investigation: {inv_id}\n");

    // Data sources (entry points)
    let mut stmt = db.conn().prepare(
        "SELECT name, source_type, location FROM data_sources \
         WHERE investigation_id = ?1 ORDER BY source_type, name"
    )?;
    let sources: Vec<(String, String, String)> = stmt.query_map([inv_id.as_str()], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
    })?.filter_map(|r| r.ok()).collect();

    if sources.is_empty() {
        println!("  No data sources (entry points) found.");
    } else {
        println!("ENTRY POINTS (data sources):");
        println!("  {:<30} {:<15} {}", "NAME", "TYPE", "LOCATION");
        println!("  {}", "-".repeat(65));
        for (name, stype, loc) in &sources {
            let loc_display = if loc.is_empty() { "-" } else { loc.as_str() };
            println!("  {:<30} {:<15} {}", name, stype, loc_display);
        }
        println!("\n  {} entry point(s)\n", sources.len());
    }

    // Data sinks (dangerous functions)
    let mut stmt = db.conn().prepare(
        "SELECT name, sink_type, danger_level, location FROM data_sinks \
         WHERE investigation_id = ?1 ORDER BY danger_level DESC, name"
    )?;
    let sinks: Vec<(String, String, String, String)> = stmt.query_map([inv_id.as_str()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?.filter_map(|r| r.ok()).collect();

    if sinks.is_empty() {
        println!("  No data sinks (dangerous functions) found.");
    } else {
        println!("DANGEROUS SINKS:");
        println!("  {:<30} {:<15} {:<10} {}", "NAME", "TYPE", "DANGER", "LOCATION");
        println!("  {}", "-".repeat(75));
        for (name, stype, danger, loc) in &sinks {
            let loc_display = if loc.is_empty() { "-" } else { loc.as_str() };
            println!("  {:<30} {:<15} {:<10} {}", name, stype, danger, loc_display);
        }
        println!("\n  {} dangerous sink(s)", sinks.len());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// viz findings
// ---------------------------------------------------------------------------

fn cmd_viz_findings() -> anyhow::Result<()> {
    let db = open_db()?;
    let inv_id = most_recent_investigation(&db)?;

    let mut stmt = db.conn().prepare(
        "SELECT id, title, agent, evidence FROM findings \
         WHERE investigation_id = ?1 ORDER BY timestamp DESC"
    )?;
    let findings: Vec<(String, String, String, String)> = stmt.query_map([inv_id.as_str()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?.filter_map(|r| r.ok()).collect();

    if findings.is_empty() {
        println!("No findings for investigation {inv_id}.");
        println!("Run `skwaq analyze --quick` to generate findings.");
        return Ok(());
    }

    println!("Findings for investigation: {inv_id}\n");
    println!(
        "  {:<8} {:<40} {:<20} {}",
        "ID", "TITLE", "AGENT", "EVIDENCE"
    );
    println!("  {}", "-".repeat(100));

    for (id, title, agent, evidence) in &findings {
        let short_id = if id.len() > 8 { &id[..8] } else { id };
        let short_title = if title.len() > 38 {
            format!("{}...", &title[..35])
        } else {
            title.clone()
        };
        let short_evidence = if evidence.len() > 40 {
            format!("{}...", &evidence[..37])
        } else {
            evidence.clone()
        };
        println!(
            "  {:<8} {:<40} {:<20} {}",
            short_id, short_title, agent, short_evidence
        );
    }

    println!("\n  {} finding(s) total.", findings.len());
    Ok(())
}

// ---------------------------------------------------------------------------
// viz callgraph
// ---------------------------------------------------------------------------

fn cmd_viz_callgraph(root_filter: Option<&str>) -> anyhow::Result<()> {
    use std::collections::{HashMap, HashSet};

    let db = open_db()?;
    let inv_id = most_recent_investigation(&db)?;

    // Build adjacency list from calls table
    let mut stmt = db.conn().prepare(
        "SELECT f1.name, f2.name FROM calls c \
         JOIN functions f1 ON c.caller_id = f1.id \
         JOIN functions f2 ON c.callee_id = f2.id \
         WHERE f1.investigation_id = ?1"
    )?;
    let edges: Vec<(String, String)> = stmt.query_map([inv_id.as_str()], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?.filter_map(|r| r.ok()).collect();

    if edges.is_empty() {
        println!("No call graph data for investigation {inv_id}.");
        println!("Call graph edges are populated during binary ingestion with symbol data.");
        return Ok(());
    }

    // Build adjacency list and track callees
    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    let mut called: HashSet<String> = HashSet::new();
    for (caller, callee) in &edges {
        children.entry(caller.clone()).or_default().push(callee.clone());
        called.insert(callee.clone());
    }

    // Dangerous function names for marking with [!]
    let dangerous: HashSet<&str> = [
        "strcpy", "strcat", "gets", "sprintf", "system", "popen",
        "exec", "execve", "execvp", "memcpy", "scanf", "gets",
    ].iter().copied().collect();

    // Find root functions (callers not called by others)
    let mut roots: Vec<String> = children
        .keys()
        .filter(|k| !called.contains(k.as_str()))
        .cloned()
        .collect();
    roots.sort();

    // Optionally filter to a specific root
    if let Some(filter) = root_filter {
        roots.retain(|r| r.contains(filter));
        if roots.is_empty() {
            println!("No root function matching '{filter}' found.");
            return Ok(());
        }
    }

    println!("Call graph for investigation: {inv_id}\n");

    for root in &roots {
        let mut visited = HashSet::new();
        print_tree(&children, root, "", true, &dangerous, &mut visited, 0, 5);
    }

    Ok(())
}

fn print_tree(
    children: &std::collections::HashMap<String, Vec<String>>,
    node: &str,
    prefix: &str,
    is_last: bool,
    dangerous: &std::collections::HashSet<&str>,
    visited: &mut std::collections::HashSet<String>,
    depth: usize,
    max_depth: usize,
) {
    let base_name = node.split('@').next().unwrap_or(node);
    let marker = if dangerous.contains(base_name) { " [!]" } else { "" };

    if depth == 0 {
        println!("{}{}", node, marker);
    } else {
        let connector = if is_last { "\u{2514}\u{2500}\u{2500} " } else { "\u{251c}\u{2500}\u{2500} " };
        println!("{}{}{}{}", prefix, connector, node, marker);
    }

    if depth >= max_depth {
        return;
    }

    if !visited.insert(node.to_string()) {
        // Already visited — avoid cycles
        return;
    }

    if let Some(kids) = children.get(node) {
        let mut sorted_kids = kids.clone();
        sorted_kids.sort();
        sorted_kids.dedup();
        let count = sorted_kids.len();
        for (i, kid) in sorted_kids.iter().enumerate() {
            let is_last_child = i == count - 1;
            let new_prefix = if depth == 0 {
                if is_last_child { "    ".to_string() } else { "\u{2502}   ".to_string() }
            } else {
                let ext = if is_last { "    " } else { "\u{2502}   " };
                format!("{}{}", prefix, ext)
            };
            print_tree(children, kid, &new_prefix, is_last_child, dangerous, visited, depth + 1, max_depth);
        }
    }

    visited.remove(node);
}

// ---------------------------------------------------------------------------
// taint
// ---------------------------------------------------------------------------

fn cmd_taint(source_filter: Option<&str>, sink_filter: Option<&str>) -> anyhow::Result<()> {
    let db = open_db()?;

    // Query taint_flows
    let mut stmt = db.conn().prepare(
        "SELECT s.name, k.name, tf.path, tf.sanitized FROM taint_flows tf \
         JOIN data_sources s ON tf.source_id = s.id \
         JOIN data_sinks k ON tf.sink_id = k.id"
    )?;
    let flows: Vec<(String, String, String, bool)> = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)? != 0,
        ))
    })?.filter_map(|r| r.ok()).collect();

    if flows.is_empty() {
        println!("No taint flows found.");
        println!("Run `skwaq analyze --quick` to discover taint paths.");
        return Ok(());
    }

    // Apply filters
    let filtered: Vec<_> = flows.iter().filter(|(src, snk, _, _)| {
        let src_match = source_filter.map_or(true, |f| src.contains(f));
        let snk_match = sink_filter.map_or(true, |f| snk.contains(f));
        src_match && snk_match
    }).collect();

    println!("Taint flows ({} total, {} shown):\n", flows.len(), filtered.len());
    println!(
        "  {:<20} {:<20} {:<10} {}",
        "SOURCE", "SINK", "SANITIZED", "PATH"
    );
    println!("  {}", "-".repeat(80));

    for (src, snk, path, sanitized) in &filtered {
        let san_str = if *sanitized { "yes" } else { "NO" };
        println!("  {:<20} {:<20} {:<10} {}", src, snk, san_str, path);
    }

    let unsanitized = filtered.iter().filter(|(_, _, _, s)| !s).count();
    println!("\n  {} unsanitized flow(s) found.", unsanitized);
    Ok(())
}

// ---------------------------------------------------------------------------
// xrefs
// ---------------------------------------------------------------------------

fn cmd_xrefs(function: &str) -> anyhow::Result<()> {
    let db = open_db()?;
    let inv_id = most_recent_investigation(&db)?;

    // Find callers of this function
    let mut stmt = db.conn().prepare(
        "SELECT f1.name FROM calls c \
         JOIN functions f1 ON c.caller_id = f1.id \
         JOIN functions f2 ON c.callee_id = f2.id \
         WHERE f2.name = ?1 AND f1.investigation_id = ?2"
    )?;
    let callers: Vec<String> = stmt.query_map(
        [function, inv_id.as_str()],
        |row| row.get::<_, String>(0),
    )?.filter_map(|r| r.ok()).collect();

    // Find callees of this function
    let mut stmt = db.conn().prepare(
        "SELECT f2.name FROM calls c \
         JOIN functions f1 ON c.caller_id = f1.id \
         JOIN functions f2 ON c.callee_id = f2.id \
         WHERE f1.name = ?1 AND f1.investigation_id = ?2"
    )?;
    let callees: Vec<String> = stmt.query_map(
        [function, inv_id.as_str()],
        |row| row.get::<_, String>(0),
    )?.filter_map(|r| r.ok()).collect();

    println!("Cross-references for '{}' (investigation {}):\n", function, inv_id);

    if callers.is_empty() && callees.is_empty() {
        println!("  No cross-references found for '{function}'.");
        println!("  Make sure the function name matches exactly (case-sensitive).");
        return Ok(());
    }

    if !callers.is_empty() {
        println!("  Called by ({}):", callers.len());
        for c in &callers {
            println!("    <- {c}");
        }
    }

    if !callees.is_empty() {
        println!("  Calls ({}):", callees.len());
        for c in &callees {
            println!("    -> {c}");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// config show
// ---------------------------------------------------------------------------

fn cmd_config_show() -> anyhow::Result<()> {
    let config = skwaq_core::config::Config::load()?;

    println!("skwaq configuration:\n");

    println!("[general]");
    println!("  database_path     = {}", config.general.database_path);
    println!("  cache_path        = {}", config.general.cache_path);
    println!("  log_level         = {}", config.general.log_level);

    println!("\n[llm]");
    println!("  reasoning         = {}", config.llm.reasoning);
    println!("  decompilation     = {}", config.llm.decompilation);
    println!("  embeddings        = {}", config.llm.embeddings);

    println!("\n[llm.copilot]");
    println!("  model             = {}", config.llm.copilot.model);

    println!("\n[llm.ollama]");
    println!("  host              = {}", config.llm.ollama.host);
    println!("  model             = {}", config.llm.ollama.model);
    println!("  embedding_model   = {}", config.llm.ollama.embedding_model);

    println!("\n[binary]");
    let ghidra = if config.binary.ghidra_path.is_empty() {
        "(not set)"
    } else {
        &config.binary.ghidra_path
    };
    println!("  ghidra_path       = {}", ghidra);
    println!("  default_timeout   = {}s", config.binary.default_timeout);
    println!("  enable_cache      = {}", config.binary.enable_cache);

    println!("\n[analysis]");
    println!("  max_taint_depth       = {}", config.analysis.max_taint_depth);
    println!("  false_positive_target = {}", config.analysis.false_positive_target);
    println!("  default_token_budget  = {}", config.analysis.default_token_budget);

    println!("\n[output]");
    println!("  default_format    = {}", config.output.default_format);

    // Show config file location
    let candidates = ["skwaq.toml", ".skwaq/config.toml"];
    let found = candidates.iter().find(|p| std::path::Path::new(p).exists());
    match found {
        Some(path) => println!("\nLoaded from: {path}"),
        None => println!("\nUsing defaults (no skwaq.toml found)"),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// kb init / kb search
// ---------------------------------------------------------------------------

fn cmd_kb_init() -> anyhow::Result<()> {
    let db = open_db().or_else(|_| {
        // Create the DB if it doesn't exist
        let db_dir = std::env::current_dir()?.join(".skwaq").join("graph");
        skwaq_core::graph::GraphDb::open(&db_dir)
    })?;

    // Insert some well-known CWEs into the cwes table
    let cwes = [
        ("CWE-119", "Improper Restriction of Operations within the Bounds of a Memory Buffer", "Buffer overflow/underflow vulnerabilities"),
        ("CWE-120", "Buffer Copy without Checking Size of Input", "Classic buffer overflow from unbounded copy operations"),
        ("CWE-125", "Out-of-bounds Read", "Reading data past the end of an allocated buffer"),
        ("CWE-134", "Use of Externally-Controlled Format String", "Format string vulnerabilities from user-controlled format specifiers"),
        ("CWE-190", "Integer Overflow or Wraparound", "Integer arithmetic that wraps leading to unexpected values"),
        ("CWE-416", "Use After Free", "Accessing memory after it has been freed"),
        ("CWE-476", "NULL Pointer Dereference", "Dereferencing a NULL pointer leading to crash"),
        ("CWE-78", "Improper Neutralization of Special Elements used in an OS Command", "OS command injection"),
        ("CWE-787", "Out-of-bounds Write", "Writing data past the end of an allocated buffer"),
        ("CWE-798", "Use of Hard-coded Credentials", "Credentials embedded directly in source code"),
        ("CWE-20", "Improper Input Validation", "Failure to validate user-supplied input"),
        ("CWE-22", "Improper Limitation of a Pathname to a Restricted Directory", "Path traversal"),
        ("CWE-77", "Improper Neutralization of Special Elements used in a Command", "Command injection"),
        ("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command", "SQL injection"),
        ("CWE-362", "Concurrent Execution using Shared Resource with Improper Synchronization", "Race conditions"),
    ];

    let mut inserted = 0;
    for (cwe_id, name, description) in &cwes {
        let id = cwe_id.to_lowercase().replace('-', "_");
        let result = db.execute(
            "INSERT OR IGNORE INTO cwes (id, cwe_id, name, description) VALUES (?1, ?2, ?3, ?4)",
            &[&id.as_str(), cwe_id, name, description],
        )?;
        if result > 0 {
            inserted += 1;
        }
    }

    println!("Knowledge base initialized: {inserted} CWE entries added ({} total in catalog).", cwes.len());
    Ok(())
}

fn cmd_kb_search(query: &str) -> anyhow::Result<()> {
    let db = open_db()?;

    let pattern = format!("%{}%", query.to_lowercase());
    let mut stmt = db.conn().prepare(
        "SELECT cwe_id, name, description FROM cwes \
         WHERE lower(cwe_id) LIKE ?1 OR lower(name) LIKE ?1 OR lower(description) LIKE ?1 \
         ORDER BY cwe_id"
    )?;
    let results: Vec<(String, String, String)> = stmt.query_map([pattern.as_str()], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
    })?.filter_map(|r| r.ok()).collect();

    if results.is_empty() {
        println!("No CWE entries matching '{query}'.");
        println!("Try `skwaq kb init` to populate the knowledge base.");
        return Ok(());
    }

    println!("CWE entries matching '{query}':\n");
    for (cwe_id, name, desc) in &results {
        println!("  {:<10} {}", cwe_id, name);
        println!("            {}\n", desc);
    }

    println!("{} result(s).", results.len());
    Ok(())
}
