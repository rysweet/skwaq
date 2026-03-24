//! Binary-level attack surface analysis.
//!
//! Identifies externally-reachable entry points by categorizing imports
//! into network listeners, file parsers, IPC handlers, and user input.

use crate::binary::types::BinaryInfo;
use crate::graph::GraphDb;

/// Categorized attack surface counts.
#[derive(Debug, Clone, Default)]
pub struct AttackSurface {
    /// Functions related to network I/O (socket, bind, listen, accept, recv, recvfrom, send, connect).
    pub network: Vec<String>,
    /// Functions related to file I/O (fopen, fread, fgets, read, open, fclose, fwrite).
    pub file: Vec<String>,
    /// Functions related to IPC (pipe, shmget, msgget, mq_open, shmat, semget).
    pub ipc: Vec<String>,
    /// Functions related to user input (scanf, gets, getenv, getchar, fgets from stdin).
    pub input: Vec<String>,
}

const NETWORK_PATTERNS: &[&str] = &[
    "socket",
    "bind",
    "listen",
    "accept",
    "recv",
    "recvfrom",
    "recvmsg",
    "send",
    "sendto",
    "sendmsg",
    "connect",
    "getaddrinfo",
    "gethostbyname",
];

const FILE_PATTERNS: &[&str] = &[
    "fopen", "fread", "fgets", "read", "open", "openat", "pread", "readdir", "fclose", "fwrite",
    "fdopen",
];

const IPC_PATTERNS: &[&str] = &[
    "pipe",
    "shmget",
    "msgget",
    "mq_open",
    "shmat",
    "semget",
    "mkfifo",
    "socketpair",
];

const INPUT_PATTERNS: &[&str] = &[
    "scanf", "sscanf", "fscanf", "gets", "getenv", "getchar", "getline", "readline",
];

/// Source patterns: functions that read external data into the program.
pub const SOURCE_PATTERNS: &[&str] = &[
    "recv", "recvfrom", "recvmsg", "accept", "read", "fread", "fgets", "gets", "getenv", "scanf",
    "sscanf", "fscanf", "getchar", "getline", "readline", "fopen", "open", "pread", "fgetc",
    "getc", "readdir",
];

/// Sink patterns: dangerous functions that consume tainted data.
pub const SINK_PATTERNS: &[&str] = &[
    "strcpy",
    "strncpy",
    "sprintf",
    "snprintf",
    "strcat",
    "strncat",
    "system",
    "_wsystem",
    "exec",
    "execve",
    "execvp",
    "execlp",
    "execvpe",
    "popen",
    "_popen",
    "_wpopen",
    "memcpy",
    "memmove",
    "gets",
    "free",
    "realloc",
    "malloc",
    "printf",
    "fprintf",
    "vprintf",
    "vfprintf",
    "vsnprintf",
    "wprintf",
    "fwprintf",
    "write",
    "fwrite",
    "fputs",
    "send",
    "sendto",
    "sendmsg",
    "mysql_query",
    "sqlite3_exec",
    "PQexec",
    "execl",
    "execle",
    "execv",
    "syslog",
    "dlopen",
    // Spawn family (CWE-78)
    "_spawnl",
    "_spawnle",
    "_spawnlp",
    "_spawnlpe",
    "_spawnv",
    "_spawnve",
    "_spawnvp",
    "_spawnvpe",
    "posix_spawn",
    // Environment modification (CWE-427)
    "putenv",
    "_putenv",
];

/// Analyze the attack surface of a binary by categorizing its imports.
pub fn identify_attack_surface(info: &BinaryInfo) -> AttackSurface {
    let mut surface = AttackSurface::default();

    for imp in &info.imports {
        let name = imp.name.as_str();
        // Strip optional "@" version suffix (e.g. "recv@@GLIBC_2.2.5")
        let base = name.split('@').next().unwrap_or(name);

        if NETWORK_PATTERNS.contains(&base) {
            surface.network.push(name.to_string());
        }
        if FILE_PATTERNS.contains(&base) {
            surface.file.push(name.to_string());
        }
        if IPC_PATTERNS.contains(&base) {
            surface.ipc.push(name.to_string());
        }
        if INPUT_PATTERNS.contains(&base) {
            surface.input.push(name.to_string());
        }
    }

    surface
}

/// Identifies and scores attack surface entry points from the graph DB.
pub struct AttackSurfaceAnalyzer<'a> {
    db: &'a GraphDb,
}

impl<'a> AttackSurfaceAnalyzer<'a> {
    pub fn new(db: &'a GraphDb) -> Self {
        Self { db }
    }

    /// Enumerate externally-reachable functions and score exposure risk.
    pub fn analyze(&self) -> anyhow::Result<Vec<SurfaceEntry>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT f.name FROM functions f \
             WHERE f.id NOT IN (SELECT callee_id FROM calls)",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(SurfaceEntry {
                function_name: row.get::<_, String>(0)?,
                entry_type: "uncalled".to_string(),
                risk_score: 0.5,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}

/// A single entry point on the attack surface.
#[derive(Debug, Clone)]
pub struct SurfaceEntry {
    pub function_name: String,
    pub entry_type: String,
    pub risk_score: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::types::*;

    fn make_imports(names: &[&str]) -> Vec<ImportInfo> {
        names
            .iter()
            .map(|n| ImportInfo {
                name: n.to_string(),
                library: String::new(),
            })
            .collect()
    }

    #[test]
    fn test_identify_network() {
        let info = BinaryInfo {
            format: BinaryFormat::Elf,
            architecture: "x86_64".into(),
            bits: 64,
            endianness: "little".into(),
            is_stripped: false,
            entry_point: 0,
            sections: vec![],
            symbols: vec![],
            imports: make_imports(&["socket", "bind", "listen", "accept", "printf"]),
            strings: vec![],
            hardening: HardeningInfo::default(),
        };
        let surface = identify_attack_surface(&info);
        assert_eq!(surface.network.len(), 4);
        assert!(surface.file.is_empty());
    }

    #[test]
    fn test_identify_file() {
        let info = BinaryInfo {
            format: BinaryFormat::Elf,
            architecture: "x86_64".into(),
            bits: 64,
            endianness: "little".into(),
            is_stripped: false,
            entry_point: 0,
            sections: vec![],
            symbols: vec![],
            imports: make_imports(&["fopen", "fread", "fclose"]),
            strings: vec![],
            hardening: HardeningInfo::default(),
        };
        let surface = identify_attack_surface(&info);
        assert_eq!(surface.file.len(), 3);
    }

    #[test]
    fn test_identify_ipc() {
        let info = BinaryInfo {
            format: BinaryFormat::Elf,
            architecture: "x86_64".into(),
            bits: 64,
            endianness: "little".into(),
            is_stripped: false,
            entry_point: 0,
            sections: vec![],
            symbols: vec![],
            imports: make_imports(&["pipe", "shmget"]),
            strings: vec![],
            hardening: HardeningInfo::default(),
        };
        let surface = identify_attack_surface(&info);
        assert_eq!(surface.ipc.len(), 2);
    }

    #[test]
    fn test_identify_input() {
        let info = BinaryInfo {
            format: BinaryFormat::Elf,
            architecture: "x86_64".into(),
            bits: 64,
            endianness: "little".into(),
            is_stripped: false,
            entry_point: 0,
            sections: vec![],
            symbols: vec![],
            imports: make_imports(&["scanf", "getenv", "malloc"]),
            strings: vec![],
            hardening: HardeningInfo::default(),
        };
        let surface = identify_attack_surface(&info);
        assert_eq!(surface.input.len(), 2);
    }

    #[test]
    fn test_empty_imports() {
        let info = BinaryInfo {
            format: BinaryFormat::Elf,
            architecture: "x86_64".into(),
            bits: 64,
            endianness: "little".into(),
            is_stripped: false,
            entry_point: 0,
            sections: vec![],
            symbols: vec![],
            imports: vec![],
            strings: vec![],
            hardening: HardeningInfo::default(),
        };
        let surface = identify_attack_surface(&info);
        assert!(surface.network.is_empty());
        assert!(surface.file.is_empty());
        assert!(surface.ipc.is_empty());
        assert!(surface.input.is_empty());
    }
}
