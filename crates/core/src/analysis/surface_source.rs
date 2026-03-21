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
            regex: r#"\bsocket\..*\.recv\w*\s*\("#,
            kind: SourceSinkKind::Source,
            category: "network",
        },
        SourceSinkPattern {
            regex: r#"\burllib\.\w+\.urlopen\s*\("#,
            kind: SourceSinkKind::Source,
            category: "network",
        },
        SourceSinkPattern {
            regex: r#"\brequests\.\w+\s*\("#,
            kind: SourceSinkKind::Source,
            category: "network",
        },
        SourceSinkPattern {
            regex: r#"\bfileinput\.input\s*\("#,
            kind: SourceSinkKind::Source,
            category: "file_read",
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
        // Additional Python sinks
        SourceSinkPattern {
            regex: r#"\bos\.popen\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\bsubprocess\.run\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\brender_template_string\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "template_injection",
        },
        SourceSinkPattern {
            regex: r#"\bsqlalchemy\.\w+\.execute\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        // Deserialization sinks (CWE-502)
        SourceSinkPattern {
            regex: r#"\byaml\.load\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "deserialization",
        },
        SourceSinkPattern {
            regex: r#"\bjsonpickle\.decode\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "deserialization",
        },
        SourceSinkPattern {
            regex: r#"\bmarshal\.loads?\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "deserialization",
        },
        SourceSinkPattern {
            regex: r#"\bshelve\.open\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "deserialization",
        },
        // Additional SQL sinks
        SourceSinkPattern {
            regex: r#"\bpsycopg2\..*\.execute\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        SourceSinkPattern {
            regex: r#"\bmysql\.connector\..*\.execute\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        // Additional sources
        SourceSinkPattern {
            regex: r#"\bflask\.request\.cookies"#,
            kind: SourceSinkKind::Source,
            category: "http_input",
        },
        SourceSinkPattern {
            regex: r#"\bflask\.request\.headers"#,
            kind: SourceSinkKind::Source,
            category: "http_input",
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
        // Additional command exec sinks
        SourceSinkPattern {
            regex: r#"\bchild_process\.spawn\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\bchild_process\.execSync\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\bchild_process\.execFile\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        // SQL sinks
        SourceSinkPattern {
            regex: r#"\bmysql\.\w*\.?query\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        SourceSinkPattern {
            regex: r#"\bpg\.\w*\.?query\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        SourceSinkPattern {
            regex: r#"\bsequelize\.query\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        // Deserialization sinks
        SourceSinkPattern {
            regex: r#"\bJSON\.parse\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "deserialization",
        },
        SourceSinkPattern {
            regex: r#"\bserialize-javascript\b"#,
            kind: SourceSinkKind::Sink,
            category: "deserialization",
        },
        // Additional sources
        SourceSinkPattern {
            regex: r#"req\.headers"#,
            kind: SourceSinkKind::Source,
            category: "http_input",
        },
        SourceSinkPattern {
            regex: r#"req\.cookies"#,
            kind: SourceSinkKind::Source,
            category: "http_input",
        },
        SourceSinkPattern {
            regex: r#"\bfs\.readFileSync\s*\("#,
            kind: SourceSinkKind::Source,
            category: "file_read",
        },
        SourceSinkPattern {
            regex: r#"\bfs\.readFile\s*\("#,
            kind: SourceSinkKind::Source,
            category: "file_read",
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
        // Additional Go sources
        SourceSinkPattern {
            regex: r#"\bnet\.Conn\b.*\bRead\s*\("#,
            kind: SourceSinkKind::Source,
            category: "network",
        },
        SourceSinkPattern {
            regex: r#"\bhttp\.Request\b.*\bBody\b"#,
            kind: SourceSinkKind::Source,
            category: "http_input",
        },
        SourceSinkPattern {
            regex: r#"\bioutil\.ReadAll\s*\("#,
            kind: SourceSinkKind::Source,
            category: "reader",
        },
        SourceSinkPattern {
            regex: r#"\bio\.ReadAll\s*\("#,
            kind: SourceSinkKind::Source,
            category: "reader",
        },
        // Additional Go sinks
        SourceSinkPattern {
            regex: r#"\bdb\.QueryRow\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        SourceSinkPattern {
            regex: r#"\bos\.Create\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "file_write",
        },
        // Deserialization
        SourceSinkPattern {
            regex: r#"\bjson\.Unmarshal\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "deserialization",
        },
        SourceSinkPattern {
            regex: r#"\bgob\.NewDecoder\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "deserialization",
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
            regex: r#"request\.getHeader\s*\("#,
            kind: SourceSinkKind::Source,
            category: "http_input",
        },
        SourceSinkPattern {
            regex: r#"request\.getCookies\s*\("#,
            kind: SourceSinkKind::Source,
            category: "http_input",
        },
        SourceSinkPattern {
            regex: r#"request\.getQueryString\s*\("#,
            kind: SourceSinkKind::Source,
            category: "http_input",
        },
        SourceSinkPattern {
            regex: r#"\bBufferedReader\b[^;]*\.readLine\s*\("#,
            kind: SourceSinkKind::Source,
            category: "file_read",
        },
        SourceSinkPattern {
            regex: r#"\bProperties\b[^;]*\.getProperty\s*\("#,
            kind: SourceSinkKind::Source,
            category: "config_input",
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
        // Additional Java sinks
        SourceSinkPattern {
            regex: r#"\bPreparedStatement\.\w+\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        SourceSinkPattern {
            regex: r#"\bRuntime\.getRuntime\(\)\.exec\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\bScriptEngine\b.*\beval\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "code_exec",
        },
        SourceSinkPattern {
            regex: r#"\bObjectInputStream\b.*\breadObject\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "deserialization",
        },
        SourceSinkPattern {
            regex: r#"\.getWriter\(\)\.\w+\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "http_response",
        },
        // Additional Java deserialization sinks (CWE-502)
        SourceSinkPattern {
            regex: r#"\bXMLDecoder\b"#,
            kind: SourceSinkKind::Sink,
            category: "deserialization",
        },
        SourceSinkPattern {
            regex: r#"\bXStream\b.*\bfromXML\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "deserialization",
        },
        // Additional Java SQL sinks (CWE-89)
        SourceSinkPattern {
            regex: r#"\bStatement\b.*\.executeQuery\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        SourceSinkPattern {
            regex: r#"\bStatement\b.*\.executeUpdate\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        SourceSinkPattern {
            regex: r#"\bConnection\b.*\.prepareStatement\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        // Additional Java sources
        SourceSinkPattern {
            regex: r#"\bServletRequest\b.*\.getParameterValues\s*\("#,
            kind: SourceSinkKind::Source,
            category: "http_input",
        },
        SourceSinkPattern {
            regex: r#"\bServletRequest\b.*\.getAttribute\s*\("#,
            kind: SourceSinkKind::Source,
            category: "http_input",
        },
        SourceSinkPattern {
            regex: r#"\bResultSet\b.*\.getString\s*\("#,
            kind: SourceSinkKind::Source,
            category: "database_result",
        },
        // JNDI injection (CWE-074)
        SourceSinkPattern {
            regex: r#"\bInitialContext\b.*\.lookup\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "jndi_injection",
        },
        // LDAP injection
        SourceSinkPattern {
            regex: r#"\bDirContext\b.*\.search\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "ldap_injection",
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
        // Additional Rust sources
        SourceSinkPattern {
            regex: r#"\bTcpStream\b.*\.read\s*\("#,
            kind: SourceSinkKind::Source,
            category: "network",
        },
        SourceSinkPattern {
            regex: r#"\bhyper::body::to_bytes\s*\("#,
            kind: SourceSinkKind::Source,
            category: "http_input",
        },
        SourceSinkPattern {
            regex: r#"\bstd::fs::read_to_string\s*\("#,
            kind: SourceSinkKind::Source,
            category: "file_read",
        },
        // Additional Rust sinks
        SourceSinkPattern {
            regex: r#"\bsqlx::query\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        SourceSinkPattern {
            regex: r#"\bserde_json::from_str\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "deserialization",
        },
        SourceSinkPattern {
            regex: r#"\bunsafe\s*\{"#,
            kind: SourceSinkKind::Sink,
            category: "unsafe_block",
        },
    ]
}

fn c_cpp_source_sinks() -> &'static [SourceSinkPattern] {
    &[
        // --- Sources (where untrusted data enters) ---
        SourceSinkPattern {
            regex: r#"\brecv\s*\("#,
            kind: SourceSinkKind::Source,
            category: "network",
        },
        SourceSinkPattern {
            regex: r#"\bread\s*\(\s*\w+sock"#,
            kind: SourceSinkKind::Source,
            category: "network",
        },
        SourceSinkPattern {
            regex: r#"\brecvfrom\s*\("#,
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
            regex: r#"\bargv\b"#,
            kind: SourceSinkKind::Source,
            category: "command_line",
        },
        SourceSinkPattern {
            regex: r#"\brecvmsg\s*\("#,
            kind: SourceSinkKind::Source,
            category: "network",
        },
        SourceSinkPattern {
            regex: r#"\baccept\s*\("#,
            kind: SourceSinkKind::Source,
            category: "network",
        },
        SourceSinkPattern {
            regex: r#"\bread\s*\("#,
            kind: SourceSinkKind::Source,
            category: "file_read",
        },
        SourceSinkPattern {
            regex: r#"\bgetchar\s*\("#,
            kind: SourceSinkKind::Source,
            category: "stdin",
        },
        SourceSinkPattern {
            regex: r#"\bgetline\s*\("#,
            kind: SourceSinkKind::Source,
            category: "stdin",
        },
        SourceSinkPattern {
            regex: r#"\bfscanf\s*\("#,
            kind: SourceSinkKind::Source,
            category: "file_read",
        },
        SourceSinkPattern {
            regex: r#"\bsscanf\s*\("#,
            kind: SourceSinkKind::Source,
            category: "string_parse",
        },
        SourceSinkPattern {
            regex: r#"\bfgetc\s*\("#,
            kind: SourceSinkKind::Source,
            category: "file_read",
        },
        SourceSinkPattern {
            regex: r#"\bgetc\s*\("#,
            kind: SourceSinkKind::Source,
            category: "file_read",
        },
        SourceSinkPattern {
            regex: r#"\bpread\s*\("#,
            kind: SourceSinkKind::Source,
            category: "file_read",
        },
        SourceSinkPattern {
            regex: r#"\breaddir\s*\("#,
            kind: SourceSinkKind::Source,
            category: "file_read",
        },
        // --- Sinks (where data reaches dangerous operations) ---
        SourceSinkPattern {
            regex: r#"\bstrcpy\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "memory",
        },
        SourceSinkPattern {
            regex: r#"\bstrcat\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "memory",
        },
        SourceSinkPattern {
            regex: r#"\bsprintf\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "memory",
        },
        SourceSinkPattern {
            regex: r#"\bmemcpy\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "memory",
        },
        SourceSinkPattern {
            regex: r#"\bmemmove\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "memory",
        },
        SourceSinkPattern {
            regex: r#"\bsystem\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\bpopen\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\bexecl\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\bexecvp\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\bLoadLibrary[AW]?\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "process_control",
        },
        SourceSinkPattern {
            regex: r#"\bdlopen\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "process_control",
        },
        SourceSinkPattern {
            regex: r#"\bfree\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "memory_lifecycle",
        },
        SourceSinkPattern {
            regex: r#"\bprintf\s*\(\s*[a-zA-Z_]"#,
            kind: SourceSinkKind::Sink,
            category: "format_string",
        },
        SourceSinkPattern {
            regex: r#"\bfprintf\s*\([^,]+,\s*[a-zA-Z_]"#,
            kind: SourceSinkKind::Sink,
            category: "format_string",
        },
        // SQL query sinks (CWE-89)
        SourceSinkPattern {
            regex: r#"\bmysql_query\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        SourceSinkPattern {
            regex: r#"\bsqlite3_exec\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        SourceSinkPattern {
            regex: r#"\bPQexec\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        // File write sinks (CWE-73)
        SourceSinkPattern {
            regex: r#"\bfwrite\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "file_write",
        },
        SourceSinkPattern {
            regex: r#"\bfputs\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "file_write",
        },
        SourceSinkPattern {
            regex: r#"\bwrite\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "file_write",
        },
        // Additional exec sinks (CWE-78)
        SourceSinkPattern {
            regex: r#"\bexecve\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\bexeclp\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\bexecle\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\bexecv\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        // Format string sinks (CWE-134)
        SourceSinkPattern {
            regex: r#"\bsprintf\s*\(\s*[a-zA-Z_]"#,
            kind: SourceSinkKind::Sink,
            category: "format_string",
        },
        SourceSinkPattern {
            regex: r#"\bsnprintf\s*\([^,]+,\s*[^,]+,\s*[a-zA-Z_]"#,
            kind: SourceSinkKind::Sink,
            category: "format_string",
        },
        SourceSinkPattern {
            regex: r#"\bsyslog\s*\([^,]+,\s*[a-zA-Z_]"#,
            kind: SourceSinkKind::Sink,
            category: "format_string",
        },
        // Deserialization sinks
        SourceSinkPattern {
            regex: r#"\bunserialize\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "deserialization",
        },
        // Additional memory sinks (CWE-120, CWE-126)
        SourceSinkPattern {
            regex: r#"\bstrncpy\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "memory",
        },
        SourceSinkPattern {
            regex: r#"\bstrncat\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "memory",
        },
        SourceSinkPattern {
            regex: r#"\bwcscpy\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "memory",
        },
        SourceSinkPattern {
            regex: r#"\bwcscat\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "memory",
        },
        SourceSinkPattern {
            regex: r#"\brealloc\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "memory_lifecycle",
        },
        // Additional format string sinks (CWE-134)
        SourceSinkPattern {
            regex: r#"\bvprintf\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "format_string",
        },
        SourceSinkPattern {
            regex: r#"\bvfprintf\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "format_string",
        },
        SourceSinkPattern {
            regex: r#"\bvsprintf\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "format_string",
        },
        SourceSinkPattern {
            regex: r#"\bvsnprintf\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "format_string",
        },
        // Windows process creation (CWE-78)
        SourceSinkPattern {
            regex: r#"\bCreateProcess[AW]?\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\bShellExecute[AW]?\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\bWinExec\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        // Additional exec family
        SourceSinkPattern {
            regex: r#"\bexecvpe\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        SourceSinkPattern {
            regex: r#"\bfexecve\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "command_exec",
        },
        // Additional SQL sinks
        SourceSinkPattern {
            regex: r#"\bsqlite3_prepare\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        SourceSinkPattern {
            regex: r#"\bmysql_real_query\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        SourceSinkPattern {
            regex: r#"\bPQexecParams\s*\("#,
            kind: SourceSinkKind::Sink,
            category: "sql_query",
        },
        // Additional C/C++ sources
        SourceSinkPattern {
            regex: r#"\bmmap\s*\("#,
            kind: SourceSinkKind::Source,
            category: "memory_mapped",
        },
        SourceSinkPattern {
            regex: r#"\breadv\s*\("#,
            kind: SourceSinkKind::Source,
            category: "file_read",
        },
        SourceSinkPattern {
            regex: r#"\bgetaddrinfo\s*\("#,
            kind: SourceSinkKind::Source,
            category: "network",
        },
        // IPC sources
        SourceSinkPattern {
            regex: r#"\bshmget\s*\("#,
            kind: SourceSinkKind::Source,
            category: "ipc",
        },
        SourceSinkPattern {
            regex: r#"\bshmat\s*\("#,
            kind: SourceSinkKind::Source,
            category: "ipc",
        },
        SourceSinkPattern {
            regex: r#"\bmsgrcv\s*\("#,
            kind: SourceSinkKind::Source,
            category: "ipc",
        },
        SourceSinkPattern {
            regex: r#"\bpipe\s*\("#,
            kind: SourceSinkKind::Source,
            category: "ipc",
        },
        // Windows-specific sources
        SourceSinkPattern {
            regex: r#"\bReadFile\s*\("#,
            kind: SourceSinkKind::Source,
            category: "file_read",
        },
        SourceSinkPattern {
            regex: r#"\bRegQueryValueEx[AW]?\s*\("#,
            kind: SourceSinkKind::Source,
            category: "registry",
        },
        SourceSinkPattern {
            regex: r#"\bGetEnvironmentVariable[AW]?\s*\("#,
            kind: SourceSinkKind::Source,
            category: "environment",
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
