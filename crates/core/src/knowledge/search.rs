use crate::graph::GraphDb;
use anyhow::Context;
use serde::Serialize;
use std::path::{Path, PathBuf};

const KB_SEARCH_LIMIT: usize = 5;

const SEEDED_CWES: [(&str, &str, &str); 15] = [
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
    let mut inserted = 0usize;
    for (cwe_id, name, description) in SEEDED_CWES {
        let id = cwe_id.to_lowercase().replace('-', "_");
        let result = db.execute(
            "INSERT OR IGNORE INTO cwes (id, cwe_id, name, description) VALUES (?1, ?2, ?3, ?4)",
            &[&id.as_str(), &cwe_id, &name, &description],
        )?;
        if result > 0 {
            inserted += result;
        }
    }

    let knowledge_packs_found = count_knowledge_packs(knowledge_dir)?;

    Ok(InitSummary {
        inserted_cwes: inserted,
        total_seed_cwes: SEEDED_CWES.len(),
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
    scored.truncate(KB_SEARCH_LIMIT);

    Ok(scored.into_iter().map(|(_, hit)| hit).collect())
}

fn search_cwes(db: &GraphDb, query: &str) -> anyhow::Result<Vec<(usize, KnowledgeHit)>> {
    let terms = search_terms(query);
    let mut where_parts = Vec::new();
    let mut params = Vec::new();
    for term in &terms {
        let pattern = format!("%{term}%");
        for column in ["lower(cwe_id)", "lower(name)", "lower(description)"] {
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

        assert_eq!(first.total_seed_cwes, 15);
        assert_eq!(first.inserted_cwes, 15);
        assert_eq!(second.inserted_cwes, 0);
    }

    #[test]
    fn test_search_knowledge_with_cwe_and_pack_results() {
        let db = crate::graph::GraphDb::in_memory().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let knowledge_dir = temp.path().join("knowledge");
        std::fs::create_dir_all(&knowledge_dir).unwrap();
        std::fs::write(
            knowledge_dir.join("memory.md"),
            "# Memory\n\nUse durable memory to store generalized lessons about buffer overflows.",
        )
        .unwrap();
        initialize_cwe_catalog_with_dir(&db, &knowledge_dir).unwrap();

        let results =
            search_knowledge_with_dir(Some(&db), "cwe-119 buffer overflow", &knowledge_dir)
                .unwrap();

        assert!(
            results.iter().any(|result| result.source == "cwe"),
            "expected cwe result"
        );
        assert!(
            results
                .iter()
                .any(|result| result.source == "knowledge-pack"),
            "expected knowledge-pack result"
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
}
