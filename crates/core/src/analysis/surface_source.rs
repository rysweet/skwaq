//! Source-level data source/sink identification across multiple languages.

use regex::Regex;
use std::path::Path;

/// A source or sink found in source code.
#[derive(Debug, Clone)]
pub struct SourceSinkHit {
    pub name: String,
    pub kind: SourceSinkKind,
    pub category: String,
    pub file: String,
    pub line: usize,
}

/// Whether the hit is a data source or a data sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceSinkKind {
    Source,
    Sink,
}

impl std::fmt::Display for SourceSinkKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Source => write!(f, "source"),
            Self::Sink => write!(f, "sink"),
        }
    }
}

struct SourceSinkPattern {
    regex: &'static str,
    kind: SourceSinkKind,
    category: &'static str,
}

fn python_source_sinks() -> &'static [SourceSinkPattern] {
    &[
        SourceSinkPattern {
            regex: r#"request\.args"#,
            kind: SourceSinkKind::Source,
            category: "http_input",
        },
        SourceSinkPattern {
            regex: r#"request\.form"#,
            kind: SourceSinkKind::Source,
            category: "http_input",
        },
        SourceSinkPattern {
            regex: r#"request\.json"#,
            kind: SourceSinkKind::Source,
            category: "http_input",
        },
        SourceSinkPattern {
            regex: r#"request\.data"#,
            kind: SourceSinkKind::Source,
            category: "http_input",
        },
        SourceSinkPattern {
            regex: r#"\binput\s*\("#,
            kind: SourceSinkKind::Source,
            category: "user_input",
        },
        SourceSinkPattern {
            regex: r#"\bos\.environ"#,
            kind: SourceSinkKind::Source,
            category: "environment",
        },
        SourceSinkPattern {
            regex: r#"\bopen\s*\([^)]+\)\.read"#,
            kind: SourceSinkKind::Source,
            category: "file_read",
        },
        SourceSinkPattern {
            regex: r#"\bsys\.argv"#,
            kind: SourceSinkKind::Source,
            category: "command_line",
        },
        SourceSinkPattern {
            regex: r#"\bsys\.stdin"#,
            kind: SourceSinkKind::Source,
            category: "stdin",
        },
        SourceSinkPattern {
            regex: r#"\bcursor\.execute\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        SourceSinkPattern {
            regex: r#"\bos\.system\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\bsubprocess\.\w+\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\beval\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "code_exec",
        },
        SourceSinkPattern {
            regex: r#"\bexec\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "code_exec",
        },
        SourceSinkPattern {
            regex: r#"\bpickle\.loads?\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "deserialization",
        },
        SourceSinkPattern {
            regex: r#"\bopen\s*\([^)]+,\s*['"]w"#,
            kind: SourceSinkKind::Sink,
            category: "file_write",
        },
    ]
}

fn javascript_source_sinks() -> &'static [SourceSinkPattern] {
    &[
        SourceSinkPattern {
            regex: r#"req\.params"#,
            kind: SourceSinkKind::Source,
            category: "http_input",
        },
        SourceSinkPattern {
            regex: r#"req\.body"#,
            kind: SourceSinkKind::Source,
            category: "http_input",
        },
        SourceSinkPattern {
            regex: r#"req\.query"#,
            kind: SourceSinkKind::Source,
            category: "http_input",
        },
        SourceSinkPattern {
            regex: r#"process\.env"#,
            kind: SourceSinkKind::Source,
            category: "environment",
        },
        SourceSinkPattern {
            regex: r#"process\.argv"#,
            kind: SourceSinkKind::Source,
            category: "command_line",
        },
        SourceSinkPattern {
            regex: r#"process\.stdin"#,
            kind: SourceSinkKind::Source,
            category: "stdin",
        },
        SourceSinkPattern {
            regex: r#"window\.location"#,
            kind: SourceSinkKind::Source,
            category: "url_input",
        },
        SourceSinkPattern {
            regex: r#"document\.cookie"#,
            kind: SourceSinkKind::Source,
            category: "cookie",
        },
        SourceSinkPattern {
            regex: r#"\bdb\.query\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        SourceSinkPattern {
            regex: r#"\bchild_process\.exec\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\beval\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "code_exec",
        },
        SourceSinkPattern {
            regex: r#"\.innerHTML\s*="#,
            kind: SourceSinkKind::Sink,
            category: "xss",
        },
        SourceSinkPattern {
            regex: r#"\bdocument\.write\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "xss",
        },
        SourceSinkPattern {
            regex: r#"\bfs\.writeFile"#,
            kind: SourceSinkKind::Sink,
            category: "file_write",
        },
        SourceSinkPattern {
            regex: r#"\bres\.send\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "http_response",
        },
    ]
}

fn go_source_sinks() -> &'static [SourceSinkPattern] {
    &[
        SourceSinkPattern {
            regex: r#"r\.URL\.Query\s*\("#,
            kind: SourceSinkKind::Source,
            category: "http_input",
        },
        SourceSinkPattern {
            regex: r#"r\.FormValue\s*\("#,
            kind: SourceSinkKind::Source,
            category: "http_input",
        },
        SourceSinkPattern {
            regex: r#"\bos\.Getenv\s*\("#,
            kind: SourceSinkKind::Source,
            category: "environment",
        },
        SourceSinkPattern {
            regex: r#"\bbufio\.NewReader\s*\("#,
            kind: SourceSinkKind::Source,
            category: "reader",
        },
        SourceSinkPattern {
            regex: r#"\bos\.Args\b"#,
            kind: SourceSinkKind::Source,
            category: "command_line",
        },
        SourceSinkPattern {
            regex: r#"\bos\.Stdin\b"#,
            kind: SourceSinkKind::Source,
            category: "stdin",
        },
        SourceSinkPattern {
            regex: r#"\bdb\.Exec\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        SourceSinkPattern {
            regex: r#"\bdb\.Query\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        SourceSinkPattern {
            regex: r#"\bexec\.Command\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\btemplate\.HTML\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "xss",
        },
        SourceSinkPattern {
            regex: r#"\bfmt\.Fprintf\s*\(w,"#,
            kind: SourceSinkKind::Sink,
            category: "http_response",
        },
    ]
}

fn java_source_sinks() -> &'static [SourceSinkPattern] {
    &[
        SourceSinkPattern {
            regex: r#"request\.getParameter\s*\("#,
            kind: SourceSinkKind::Source,
            category: "http_input",
        },
        SourceSinkPattern {
            regex: r#"request\.getInputStream"#,
            kind: SourceSinkKind::Source,
            category: "http_input",
        },
        SourceSinkPattern {
            regex: r#"\bSystem\.getenv\s*\("#,
            kind: SourceSinkKind::Source,
            category: "environment",
        },
        SourceSinkPattern {
            regex: r#"\bSystem\.getProperty\s*\("#,
            kind: SourceSinkKind::Source,
            category: "environment",
        },
        SourceSinkPattern {
            regex: r#"\bScanner\s*\(\s*System\.in"#,
            kind: SourceSinkKind::Source,
            category: "stdin",
        },
        SourceSinkPattern {
            regex: r#"\bstatement\.execute\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        SourceSinkPattern {
            regex: r#"\bRuntime\.getRuntime\(\)\.exec\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\bProcessBuilder\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\bObjectInputStream\b"#,
            kind: SourceSinkKind::Sink,
            category: "deserialization",
        },
        SourceSinkPattern {
            regex: r#"\bresponse\.getWriter\(\)\.write\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "http_response",
        },
    ]
}

fn rust_source_sinks() -> &'static [SourceSinkPattern] {
    &[
        SourceSinkPattern {
            regex: r#"\bstd::env::args\s*\("#,
            kind: SourceSinkKind::Source,
            category: "command_line",
        },
        SourceSinkPattern {
            regex: r#"\bstd::env::var\s*\("#,
            kind: SourceSinkKind::Source,
            category: "environment",
        },
        SourceSinkPattern {
            regex: r#"\bstd::io::stdin\s*\("#,
            kind: SourceSinkKind::Source,
            category: "stdin",
        },
        SourceSinkPattern {
            regex: r#"\bstd::fs::read"#,
            kind: SourceSinkKind::Source,
            category: "file_read",
        },
        SourceSinkPattern {
            regex: r#"\bCommand::new\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\bconn\.execute\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        SourceSinkPattern {
            regex: r#"\bstd::fs::write\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "file_write",
        },
    ]
}

fn c_cpp_source_sinks() -> &'static [SourceSinkPattern] {
    &[
        SourceSinkPattern {
            regex: r#"\brecv\s*\("#,
            kind: SourceSinkKind::Source,
            category: "network",
        },
        SourceSinkPattern {
            regex: r#"\bfread\s*\("#,
            kind: SourceSinkKind::Source,
            category: "file_read",
        },
        SourceSinkPattern {
            regex: r#"\bfgets\s*\("#,
            kind: SourceSinkKind::Source,
            category: "file_read",
        },
        SourceSinkPattern {
            regex: r#"\bgets\s*\("#,
            kind: SourceSinkKind::Source,
            category: "stdin",
        },
        SourceSinkPattern {
            regex: r#"\bgetenv\s*\("#,
            kind: SourceSinkKind::Source,
            category: "environment",
        },
        SourceSinkPattern {
            regex: r#"\bscanf\s*\("#,
            kind: SourceSinkKind::Source,
            category: "stdin",
        },
        SourceSinkPattern {
            regex: r#"\bstrcpy\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "memory",
        },
        SourceSinkPattern {
            regex: r#"\bsprintf\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "memory",
        },
        SourceSinkPattern {
            regex: r#"\bsystem\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\bmemcpy\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "memory",
        },
    ]
}

fn get_source_sink_patterns(language: &str) -> &'static [SourceSinkPattern] {
    match language {
        "python" => python_source_sinks(),
        "javascript" | "typescript" => javascript_source_sinks(),
        "go" => go_source_sinks(),
        "rust" => rust_source_sinks(),
        "java" => java_source_sinks(),
        "c" | "cpp" => c_cpp_source_sinks(),
        _ => &[],
    }
}

/// Identify data sources and sinks in a source file.
pub fn identify_source_sinks(
    source_path: &Path,
    language: &str,
) -> anyhow::Result<Vec<SourceSinkHit>> {
    let content = std::fs::read_to_string(source_path)
        .map_err(|e| anyhow::anyhow!("Cannot read {}: {}", source_path.display(), e))?;

    identify_source_sinks_in_content(&content, language, &source_path.display().to_string())
}

/// Identify data sources and sinks in source content already in memory.
pub fn identify_source_sinks_in_content(
    content: &str,
    language: &str,
    file_path: &str,
) -> anyhow::Result<Vec<SourceSinkHit>> {
    let patterns = get_source_sink_patterns(language);
    let mut hits = Vec::new();

    for pat in patterns {
        let re = Regex::new(pat.regex)
            .map_err(|e| anyhow::anyhow!("Bad pattern {}: {}", pat.regex, e))?;

        for m in re.find_iter(content) {
            let byte_offset = m.start();
            let line = content[..byte_offset].matches('\n').count() + 1;
            let matched_text = m.as_str().trim().to_string();

            hits.push(SourceSinkHit {
                name: matched_text,
                kind: pat.kind.clone(),
                category: pat.category.to_string(),
                file: file_path.to_string(),
                line,
            });
        }
    }

    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_source_sinks() {
        let src = r#"
from flask import request
name = request.args.get("name")
user = input("Enter name: ")
os.environ["KEY"]
cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
os.system("echo " + name)
eval(name)
"#;
        let hits = identify_source_sinks_in_content(src, "python", "app.py").unwrap();
        let sources: Vec<_> = hits
            .iter()
            .filter(|h| h.kind == SourceSinkKind::Source)
            .collect();
        let sinks: Vec<_> = hits
            .iter()
            .filter(|h| h.kind == SourceSinkKind::Sink)
            .collect();
        assert!(!sources.is_empty(), "Should find data sources");
        assert!(!sinks.is_empty(), "Should find data sinks");
        assert!(sources.iter().any(|s| s.category == "http_input"));
        assert!(sinks.iter().any(|s| s.category == "command_exec"));
    }

    #[test]
    fn test_javascript_source_sinks() {
        let src = r#"
const id = req.params.id;
const key = process.env.API_KEY;
eval(id);
res.send(output);
db.query("SELECT * FROM x WHERE id = " + id);
"#;
        let hits = identify_source_sinks_in_content(src, "javascript", "app.js").unwrap();
        let sources: Vec<_> = hits
            .iter()
            .filter(|h| h.kind == SourceSinkKind::Source)
            .collect();
        let sinks: Vec<_> = hits
            .iter()
            .filter(|h| h.kind == SourceSinkKind::Sink)
            .collect();
        assert!(!sources.is_empty());
        assert!(!sinks.is_empty());
    }

    #[test]
    fn test_go_source_sinks() {
        let src = r#"
func handler(w http.ResponseWriter, r *http.Request) {
    input := r.URL.Query().Get("cmd")
    key := os.Getenv("SECRET")
    exec.Command(input).Run()
}
"#;
        let hits = identify_source_sinks_in_content(src, "go", "main.go").unwrap();
        assert!(hits.iter().any(|h| h.kind == SourceSinkKind::Source));
        assert!(hits.iter().any(|h| h.kind == SourceSinkKind::Sink));
    }

    #[test]
    fn test_rust_source_sinks() {
        let src = r#"
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let key = std::env::var("SECRET").unwrap();
    Command::new(&args[1]).output().unwrap();
}
"#;
        let hits = identify_source_sinks_in_content(src, "rust", "main.rs").unwrap();
        assert!(hits.iter().any(|h| h.kind == SourceSinkKind::Source));
        assert!(hits.iter().any(|h| h.kind == SourceSinkKind::Sink));
    }

    #[test]
    fn test_safe_source_no_hits() {
        let src = r#"
fn add(a: i32, b: i32) -> i32 {
    a + b
}
"#;
        let hits = identify_source_sinks_in_content(src, "rust", "safe.rs").unwrap();
        assert!(hits.is_empty());
    }
}
