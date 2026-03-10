//! `skwaq viz` - visualization sub-commands.

use std::collections::{HashMap, HashSet};

use super::common::{most_recent_investigation, open_db};

/// Display findings for the most recent investigation.
pub fn run_findings() -> anyhow::Result<()> {
    let db = open_db()?;
    let inv_id = most_recent_investigation(&db)?;

    let mut stmt = db.conn().prepare(
        "SELECT id, title, agent, evidence FROM findings \
         WHERE investigation_id = ?1 ORDER BY timestamp DESC",
    )?;
    let findings: Vec<(String, String, String, String)> = stmt
        .query_map([inv_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

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
        let short_title = if title.chars().count() > 38 {
            format!("{}...", title.chars().take(35).collect::<String>())
        } else {
            title.clone()
        };
        let short_evidence = if evidence.chars().count() > 40 {
            format!("{}...", evidence.chars().take(37).collect::<String>())
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

/// Display the call graph as an ASCII tree.
pub fn run_callgraph(root_filter: Option<&str>) -> anyhow::Result<()> {
    let db = open_db()?;
    let inv_id = most_recent_investigation(&db)?;

    // Build adjacency list from calls table
    let mut stmt = db.conn().prepare(
        "SELECT f1.name, f2.name FROM calls c \
         JOIN functions f1 ON c.caller_id = f1.id \
         JOIN functions f2 ON c.callee_id = f2.id \
         WHERE f1.investigation_id = ?1",
    )?;
    let edges: Vec<(String, String)> = stmt
        .query_map([inv_id.as_str()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    if edges.is_empty() {
        println!("No call graph data for investigation {inv_id}.");
        println!("Call graph edges are populated during binary ingestion with symbol data.");
        return Ok(());
    }

    // Build adjacency list and track callees
    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    let mut called: HashSet<String> = HashSet::new();
    for (caller, callee) in &edges {
        children
            .entry(caller.clone())
            .or_default()
            .push(callee.clone());
        called.insert(callee.clone());
    }

    // Dangerous function names for marking with [!]
    let dangerous: HashSet<&str> = [
        "strcpy", "strcat", "gets", "sprintf", "system", "popen", "exec", "execve", "execvp",
        "memcpy", "scanf",
    ]
    .iter()
    .copied()
    .collect();

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

/// Recursively print a tree node with box-drawing characters.
pub fn print_tree(
    children: &HashMap<String, Vec<String>>,
    node: &str,
    prefix: &str,
    is_last: bool,
    dangerous: &HashSet<&str>,
    visited: &mut HashSet<String>,
    depth: usize,
    max_depth: usize,
) {
    let base_name = node.split('@').next().unwrap_or(node);
    let marker = if dangerous.contains(base_name) {
        " [!]"
    } else {
        ""
    };

    if depth == 0 {
        println!("{}{}", node, marker);
    } else {
        let connector = if is_last {
            "\u{2514}\u{2500}\u{2500} "
        } else {
            "\u{251c}\u{2500}\u{2500} "
        };
        println!("{}{}{}{}", prefix, connector, node, marker);
    }

    if depth >= max_depth {
        return;
    }

    if !visited.insert(node.to_string()) {
        // Already visited -- avoid cycles
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
                if is_last_child {
                    "    ".to_string()
                } else {
                    "\u{2502}   ".to_string()
                }
            } else {
                let ext = if is_last { "    " } else { "\u{2502}   " };
                format!("{}{}", prefix, ext)
            };
            print_tree(
                children,
                kid,
                &new_prefix,
                is_last_child,
                dangerous,
                visited,
                depth + 1,
                max_depth,
            );
        }
    }

    visited.remove(node);
}
