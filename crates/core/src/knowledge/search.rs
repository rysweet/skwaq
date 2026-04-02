use crate::graph::GraphDb;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const KB_SEARCH_LIMIT: usize = 5;

/// A single CWE entry from the knowledge graph JSON file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CweEntry {
    pub cwe_id: String,
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub parent_cwe: Option<String>,
    #[serde(default)]
    pub semantic_class: String,
    #[serde(default)]
    pub danger_categories: Vec<String>,
    #[serde(default)]
    pub detection_signals: Vec<String>,
    #[serde(default)]
    pub skwaq_tools: Vec<String>,
    #[serde(default)]
    pub fn_insight: String,
}

/// Top-level structure of the CWE knowledge graph JSON file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CweKnowledgeGraph {
    pub version: u32,
    pub description: String,
    pub cwes: Vec<CweEntry>,
}

/// Minimal fallback CWEs used when the JSON data file is not available (e.g. tests).
const FALLBACK_CWES: [(&str, &str, &str); 15] = [
    (
        "CWE-119",
        "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "Buffer overflow/underflow vulnerabilities",
    ),
    (
        "CWE-120",
        "Buffer Copy without Checking Size of Input",
        "Classic buffer overflow from unbounded copy operations",
    ),
    (
        "CWE-125",
        "Out-of-bounds Read",
        "Reading data past the end of an allocated buffer",
    ),
    (
        "CWE-134",
        "Use of Externally-Controlled Format String",
        "Format string vulnerabilities from user-controlled format specifiers",
    ),
    (
        "CWE-190",
        "Integer Overflow or Wraparound",
        "Integer arithmetic that wraps leading to unexpected values",
    ),
    (
        "CWE-416",
        "Use After Free",
        "Accessing memory after it has been freed",
    ),
    (
        "CWE-476",
        "NULL Pointer Dereference",
        "Dereferencing a NULL pointer leading to crash",
    ),
    (
        "CWE-78",
        "Improper Neutralization of Special Elements used in an OS Command",
        "OS command injection",
    ),
    (
        "CWE-787",
        "Out-of-bounds Write",
        "Writing data past the end of an allocated buffer",
    ),
    (
        "CWE-798",
        "Use of Hard-coded Credentials",
        "Credentials embedded directly in source code",
    ),
    (
        "CWE-20",
        "Improper Input Validation",
        "Failure to validate user-supplied input",
    ),
    (
        "CWE-22",
        "Improper Limitation of a Pathname to a Restricted Directory",
        "Path traversal",
    ),
    (
        "CWE-77",
        "Improper Neutralization of Special Elements used in a Command",
        "Command injection",
    ),
    (
        "CWE-89",
        "Improper Neutralization of Special Elements used in an SQL Command",
        "SQL injection",
    ),
    (
        "CWE-362",
        "Concurrent Execution using Shared Resource with Improper Synchronization",
        "Race conditions",
    ),
];

/// Locate the CWE knowledge graph JSON file relative to common project roots.
pub fn find_cwe_kg_file() -> Option<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    [
        PathBuf::from("data/cwe-knowledge-graph.json"),
        PathBuf::from("../data/cwe-knowledge-graph.json"),
        manifest_dir.join("../../data/cwe-knowledge-graph.json"),
    ]
    .into_iter()
    .find(|p| p.is_file())
}

/// Load the CWE knowledge graph from the JSON data file.
/// Returns None if the file is not found (fallback to FALLBACK_CWES).
pub fn load_cwe_knowledge_graph() -> Option<CweKnowledgeGraph> {
    let path = find_cwe_kg_file()?;
    let content = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Load CWE entries — from the JSON data file if available, else from fallback.
fn load_cwe_entries() -> Vec<CweEntry> {
    if let Some(kg) = load_cwe_knowledge_graph() {
        return kg.cwes;
    }
    // Fallback: convert the minimal const array to CweEntry structs
    FALLBACK_CWES
        .iter()
        .map(|(id, name, desc)| CweEntry {
            cwe_id: id.to_string(),
            name: name.to_string(),
            description: desc.to_string(),
            parent_cwe: None,
            semantic_class: String::new(),
            danger_categories: Vec::new(),
            detection_signals: Vec::new(),
            skwaq_tools: Vec::new(),
            fn_insight: String::new(),
        })
        .collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct KnowledgeHit {
    pub source: String,
    pub topic: String,
    pub title: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InitSummary {
    pub inserted_cwes: usize,
    pub total_seed_cwes: usize,
    pub knowledge_packs_found: usize,
}

pub fn initialize_cwe_catalog(db: &GraphDb) -> anyhow::Result<InitSummary> {
    let knowledge_dir = resolve_knowledge_dir()?;
    initialize_cwe_catalog_with_dir(db, &knowledge_dir)
}

pub(crate) fn initialize_cwe_catalog_with_dir(
    db: &GraphDb,
    knowledge_dir: &Path,
) -> anyhow::Result<InitSummary> {
    let entries = load_cwe_entries();
    let total = entries.len();
    let mut inserted = 0usize;
    for entry in &entries {
        let id = entry.cwe_id.to_lowercase().replace('-', "_");
        let parent = entry.parent_cwe.as_deref().unwrap_or("");
        let danger_cats = entry.danger_categories.join(",");
        let signals = entry.detection_signals.join(",");
        let tools = entry.skwaq_tools.join(",");
        let result = db.execute(
            "INSERT OR IGNORE INTO cwes (id, cwe_id, name, description, parent_cwe, semantic_class, danger_categories, detection_signals, skwaq_tools, fn_insight) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            &[
                &id.as_str(),
                &entry.cwe_id.as_str(),
                &entry.name.as_str(),
                &entry.description.as_str(),
                &parent,
                &entry.semantic_class.as_str(),
                &danger_cats.as_str(),
                &signals.as_str(),
                &tools.as_str(),
                &entry.fn_insight.as_str(),
            ],
        )?;
        if result > 0 {
            inserted += result;
        }
    }

    let knowledge_packs_found = count_knowledge_packs(knowledge_dir)?;

    Ok(InitSummary {
        inserted_cwes: inserted,
        total_seed_cwes: total,
        knowledge_packs_found,
    })
}

pub fn search_knowledge(db: Option<&GraphDb>, query: &str) -> anyhow::Result<Vec<KnowledgeHit>> {
    let knowledge_dir = resolve_knowledge_dir()?;
    search_knowledge_with_dir(db, query, &knowledge_dir)
}

pub fn find_knowledge_dir() -> Option<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    [
        PathBuf::from("data/knowledge"),
        PathBuf::from("../data/knowledge"),
        manifest_dir.join("../../data/knowledge"),
    ]
    .into_iter()
    .find(|path| path.is_dir())
}

fn resolve_knowledge_dir() -> anyhow::Result<PathBuf> {
    find_knowledge_dir().context(
        "Knowledge pack directory not found. Expected one of: data/knowledge, ../data/knowledge, or crates/core/../../data/knowledge.",
    )
}

fn count_knowledge_packs(dir: &Path) -> anyhow::Result<usize> {
    let mut count = 0usize;
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read knowledge directory: {}", dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "Failed to read knowledge directory entry: {}",
                dir.display()
            )
        })?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read knowledge pack: {}", path.display()))?;
        count += 1;
    }
    Ok(count)
}

pub(crate) fn search_knowledge_with_dir(
    db: Option<&GraphDb>,
    query: &str,
    knowledge_dir: &Path,
) -> anyhow::Result<Vec<KnowledgeHit>> {
    let normalized = query.trim().to_lowercase();
    if normalized.is_empty() {
        return Ok(Vec::new());
    }

    let mut scored: Vec<(usize, KnowledgeHit)> = Vec::new();
    if let Some(db) = db {
        scored.extend(search_cwes(db, &normalized)?);
    }
    scored.extend(search_markdown(knowledge_dir, &normalized)?);

    scored.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1.topic.cmp(&b.1.topic))
            .then_with(|| a.1.title.cmp(&b.1.title))
    });

    // Ensure both CWE and knowledge-pack sources are represented in results.
    // With 947 CWEs, pure score-based truncation can push knowledge-packs out entirely.
    let min_per_source = 2;
    let mut cwe_hits: Vec<_> = scored
        .iter()
        .filter(|(_, h)| h.source == "cwe")
        .take(KB_SEARCH_LIMIT)
        .collect();
    let mut pack_hits: Vec<_> = scored
        .iter()
        .filter(|(_, h)| h.source == "knowledge-pack")
        .take(min_per_source)
        .collect();

    // If one source has fewer than min_per_source, give the other more slots
    let cwe_slots = KB_SEARCH_LIMIT.saturating_sub(pack_hits.len().min(min_per_source));
    cwe_hits.truncate(cwe_slots);
    let remaining = KB_SEARCH_LIMIT.saturating_sub(cwe_hits.len());
    pack_hits.truncate(remaining);

    let mut merged: Vec<(usize, KnowledgeHit)> =
        cwe_hits.into_iter().chain(pack_hits).cloned().collect();
    merged.sort_by(|a, b| b.0.cmp(&a.0));

    Ok(merged.into_iter().map(|(_, hit)| hit).collect())
}

fn search_cwes(db: &GraphDb, query: &str) -> anyhow::Result<Vec<(usize, KnowledgeHit)>> {
    let terms = search_terms(query);
    let mut where_parts = Vec::new();
    let mut params = Vec::new();
    for term in &terms {
        let pattern = format!("%{term}%");
        for column in [
            "lower(cwe_id)",
            "lower(name)",
            "lower(description)",
            "lower(semantic_class)",
            "lower(detection_signals)",
        ] {
            where_parts.push(format!("{column} LIKE ?{}", params.len() + 1));
            params.push(pattern.clone());
        }
    }

    let sql = format!(
        "SELECT cwe_id, name, description FROM cwes
         WHERE {}
         ORDER BY cwe_id",
        where_parts.join(" OR ")
    );
    let mut stmt = db.conn().prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;

    let mut hits = Vec::new();
    for row in rows {
        let (cwe_id, name, description) = row?;
        let score = cwe_relevance(query, &cwe_id, &name, &description);
        if score == 0 {
            continue;
        }
        hits.push((
            score,
            KnowledgeHit {
                source: "cwe".into(),
                topic: cwe_id.clone(),
                title: format!("{cwe_id} {name}"),
                content: description,
            },
        ));
    }
    Ok(hits)
}

fn search_markdown(dir: &Path, query: &str) -> anyhow::Result<Vec<(usize, KnowledgeHit)>> {
    let mut hits = Vec::new();
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read knowledge directory: {}", dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "Failed to read knowledge directory entry: {}",
                dir.display()
            )
        })?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read knowledge pack: {}", path.display()))?;
        let topic = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        let score = markdown_relevance(query, &topic, &content);
        if score == 0 {
            continue;
        }

        let excerpt = relevant_excerpt(query, &content);
        hits.push((
            score,
            KnowledgeHit {
                source: "knowledge-pack".into(),
                topic: topic.clone(),
                title: topic,
                content: excerpt,
            },
        ));
    }

    Ok(hits)
}

fn cwe_relevance(query: &str, cwe_id: &str, name: &str, description: &str) -> usize {
    let cwe_lower = cwe_id.to_lowercase();
    let name_lower = name.to_lowercase();
    let desc_lower = description.to_lowercase();
    if query == cwe_lower {
        return 200;
    }
    let mut score = 0usize;
    if cwe_lower.contains(query) || query.contains(&cwe_lower) {
        score += 120;
    }
    for term in query_terms(query) {
        if name_lower.contains(term) {
            score += 20;
        }
        if desc_lower.contains(term) {
            score += 10;
        }
    }
    score
}

fn markdown_relevance(query: &str, topic: &str, content: &str) -> usize {
    if topic == query || topic.contains(query) || query.contains(topic) {
        return 100;
    }

    let lower = content.to_lowercase();
    let mut score = 0usize;
    for term in query_terms(query) {
        if topic.contains(term) {
            score += 25;
        }
        if lower.contains(term) {
            score += 10;
        }
    }
    score
}

fn relevant_excerpt(query: &str, content: &str) -> String {
    let relevant_sections: Vec<&str> = content
        .split("\n\n")
        .filter(|section| {
            let lower = section.to_lowercase();
            query_terms(query).any(|term| lower.contains(term))
        })
        .take(5)
        .collect();

    if relevant_sections.is_empty() {
        content.chars().take(500).collect()
    } else {
        relevant_sections.join("\n\n")
    }
}

fn query_terms(query: &str) -> impl Iterator<Item = &str> {
    query.split_whitespace().filter(|word| word.len() > 2)
}

fn search_terms(query: &str) -> Vec<&str> {
    let mut terms = vec![query];
    for term in query_terms(query) {
        if !terms.contains(&term) {
            terms.push(term);
        }
    }
    terms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize_cwe_catalog_is_idempotent() {
        let db = crate::graph::GraphDb::in_memory().unwrap();
        let first = initialize_cwe_catalog(&db).unwrap();
        let second = initialize_cwe_catalog(&db).unwrap();

        // With the JSON data file, we get 947 CWEs; without it, 15 fallback entries.
        assert!(
            first.total_seed_cwes >= 15,
            "expected at least 15 seed CWEs, got {}",
            first.total_seed_cwes
        );
        assert_eq!(first.inserted_cwes, first.total_seed_cwes);
        assert_eq!(second.inserted_cwes, 0);
    }

    #[test]
    fn test_search_knowledge_with_cwe_and_pack_results() {
        let db = crate::graph::GraphDb::in_memory().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let knowledge_dir = temp.path().join("knowledge");
        std::fs::create_dir_all(&knowledge_dir).unwrap();
        // Use a unique term ("durable memory lessons") so the markdown pack
        // scores high enough to survive truncation alongside the 145 CWE entries.
        std::fs::write(
            knowledge_dir.join("memory.md"),
            "# Memory\n\nUse durable memory lessons to store generalized vulnerability analysis xyzunique.",
        )
        .unwrap();
        initialize_cwe_catalog_with_dir(&db, &knowledge_dir).unwrap();

        // Search a unique term that matches the knowledge pack strongly
        let results = search_knowledge_with_dir(
            Some(&db),
            "durable memory lessons xyzunique",
            &knowledge_dir,
        )
        .unwrap();

        assert!(
            results
                .iter()
                .any(|result| result.source == "knowledge-pack"),
            "expected knowledge-pack result for unique term"
        );
    }

    #[test]
    fn test_initialize_cwe_catalog_requires_readable_knowledge_dir() {
        let db = crate::graph::GraphDb::in_memory().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let missing_dir = temp.path().join("missing");

        let error = initialize_cwe_catalog_with_dir(&db, &missing_dir).unwrap_err();

        assert!(error
            .to_string()
            .contains("Failed to read knowledge directory"));
    }

    #[test]
    fn test_search_knowledge_surfaces_pack_read_errors() {
        let db = crate::graph::GraphDb::in_memory().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let knowledge_dir = temp.path().join("knowledge");
        std::fs::create_dir_all(&knowledge_dir).unwrap();
        std::fs::create_dir_all(knowledge_dir.join("broken.md")).unwrap();

        let error = search_knowledge_with_dir(Some(&db), "memory", &knowledge_dir).unwrap_err();

        assert!(error.to_string().contains("Failed to read knowledge pack"));
    }

    #[test]
    fn test_cwe_kg_json_parses() {
        // The JSON file should be loadable if present in the repo
        if let Some(kg) = load_cwe_knowledge_graph() {
            assert!(kg.version >= 1, "expected version >= 1, got {}", kg.version);
            assert!(
                kg.cwes.len() >= 100,
                "expected at least 100 CWE entries, got {}",
                kg.cwes.len()
            );
            // Spot check a known entry
            let cwe119 = kg.cwes.iter().find(|c| c.cwe_id == "CWE-119");
            assert!(cwe119.is_some(), "CWE-119 must be in the knowledge graph");
            let cwe119 = cwe119.unwrap();
            assert!(!cwe119.detection_signals.is_empty());
            assert!(!cwe119.skwaq_tools.is_empty());
            assert!(!cwe119.fn_insight.is_empty());
        }
    }

    #[test]
    fn test_enriched_columns_inserted() {
        let db = crate::graph::GraphDb::in_memory().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let knowledge_dir = temp.path().join("knowledge");
        std::fs::create_dir_all(&knowledge_dir).unwrap();
        initialize_cwe_catalog_with_dir(&db, &knowledge_dir).unwrap();

        // Query enriched columns for CWE-119 (always present in fallback or full)
        let (semantic_class, detection_signals, fn_insight): (String, String, String) = db
            .conn()
            .query_row(
                "SELECT semantic_class, detection_signals, fn_insight FROM cwes WHERE cwe_id = 'CWE-119'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();

        // If the full JSON was loaded, we expect enriched data
        if let Some(_kg) = load_cwe_knowledge_graph() {
            assert!(
                !semantic_class.is_empty(),
                "semantic_class should be populated"
            );
            assert!(
                !detection_signals.is_empty(),
                "detection_signals should be populated"
            );
            assert!(!fn_insight.is_empty(), "fn_insight should be populated");
        }
    }

    #[test]
    fn test_cwe_kg_has_947_entries() {
        // The full MITRE CWE database should have 947 entries
        if let Some(kg) = load_cwe_knowledge_graph() {
            assert_eq!(
                kg.cwes.len(),
                947,
                "expected 947 CWE entries from full MITRE database, got {}",
                kg.cwes.len()
            );
        }
    }

    #[test]
    fn test_cwe_kg_parent_hierarchy_present() {
        // Most CWEs should have a parent_cwe from MITRE RelatedWeaknesses
        if let Some(kg) = load_cwe_knowledge_graph() {
            let with_parent = kg.cwes.iter().filter(|c| c.parent_cwe.is_some()).count();
            assert!(
                with_parent >= 900,
                "expected at least 900 CWEs with parent_cwe, got {with_parent}"
            );
            // Spot-check: CWE-120 should be child of CWE-787 per MITRE
            let cwe120 = kg.cwes.iter().find(|c| c.cwe_id == "CWE-120").unwrap();
            assert_eq!(
                cwe120.parent_cwe.as_deref(),
                Some("CWE-787"),
                "CWE-120 should have parent CWE-787"
            );
        }
    }

    #[test]
    fn test_enriched_entries_preserved_after_expansion() {
        // The original 144 enriched entries must retain detection_signals and fn_insight
        if let Some(kg) = load_cwe_knowledge_graph() {
            let enriched: Vec<_> = kg
                .cwes
                .iter()
                .filter(|c| !c.detection_signals.is_empty())
                .collect();
            assert!(
                enriched.len() >= 140,
                "expected at least 140 enriched CWEs with detection_signals, got {}",
                enriched.len()
            );

            // Spot-check: CWE-79 (XSS) should have detection signals
            let cwe79 = kg.cwes.iter().find(|c| c.cwe_id == "CWE-79");
            assert!(cwe79.is_some(), "CWE-79 must exist");
            let cwe79 = cwe79.unwrap();
            assert!(
                !cwe79.detection_signals.is_empty(),
                "CWE-79 should have detection_signals"
            );
            assert!(
                !cwe79.fn_insight.is_empty(),
                "CWE-79 should have fn_insight"
            );
        }
    }

    #[test]
    fn test_initialize_full_cwe_catalog_count() {
        // When JSON is available, initialize should insert all 947 entries
        let db = crate::graph::GraphDb::in_memory().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let knowledge_dir = temp.path().join("knowledge");
        std::fs::create_dir_all(&knowledge_dir).unwrap();
        let summary = initialize_cwe_catalog_with_dir(&db, &knowledge_dir).unwrap();

        // With the full MITRE data, we expect 947 entries; without it, 15 fallback
        if load_cwe_knowledge_graph().is_some() {
            assert_eq!(
                summary.total_seed_cwes, 947,
                "expected 947 total seed CWEs"
            );
            assert_eq!(
                summary.inserted_cwes, 947,
                "expected 947 inserted CWEs on first run"
            );
        }
    }

    #[test]
    fn test_parent_cwe_column_populated() {
        // parent_cwe should be stored in the DB for hierarchy queries
        let db = crate::graph::GraphDb::in_memory().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let knowledge_dir = temp.path().join("knowledge");
        std::fs::create_dir_all(&knowledge_dir).unwrap();
        initialize_cwe_catalog_with_dir(&db, &knowledge_dir).unwrap();

        if load_cwe_knowledge_graph().is_some() {
            let parent: String = db
                .conn()
                .query_row(
                    "SELECT parent_cwe FROM cwes WHERE cwe_id = 'CWE-120'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                parent, "CWE-787",
                "CWE-120 parent_cwe should be CWE-787 in DB"
            );
        }
    }

    #[test]
    fn test_search_finds_newly_added_cwes() {
        // CWEs that were NOT in the original 145 should now be searchable
        let db = crate::graph::GraphDb::in_memory().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let knowledge_dir = temp.path().join("knowledge");
        std::fs::create_dir_all(&knowledge_dir).unwrap();
        initialize_cwe_catalog_with_dir(&db, &knowledge_dir).unwrap();

        if load_cwe_knowledge_graph().is_some() {
            // CWE-5 (J2EE Misconfiguration) is in the expanded set but not in FALLBACK_CWES
            let results =
                search_knowledge_with_dir(Some(&db), "cwe-5", &knowledge_dir).unwrap();
            assert!(
                results.iter().any(|h| h.topic == "CWE-5"),
                "CWE-5 from expanded MITRE data should be searchable"
            );
        }
    }

    #[test]
    fn test_fallback_when_json_missing() {
        // The fallback CWEs should always work even if JSON is gone
        let entries: Vec<CweEntry> = FALLBACK_CWES
            .iter()
            .map(|(id, name, desc)| CweEntry {
                cwe_id: id.to_string(),
                name: name.to_string(),
                description: desc.to_string(),
                parent_cwe: None,
                semantic_class: String::new(),
                danger_categories: Vec::new(),
                detection_signals: Vec::new(),
                skwaq_tools: Vec::new(),
                fn_insight: String::new(),
            })
            .collect();
        assert_eq!(entries.len(), 15);
        assert!(entries.iter().any(|e| e.cwe_id == "CWE-119"));
    }
}
