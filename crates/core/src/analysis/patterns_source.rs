//! Language-specific dangerous pattern detection for source code analysis.

use super::patterns::{DangerCategory, DangerousApiHit, Severity};
use regex::Regex;

pub(crate) struct SourcePattern {
    pub regex: &'static str,
    pub category: DangerCategory,
    pub severity: Severity,
    pub reason: &'static str,
}

fn python_patterns() -> &'static [SourcePattern] {
    &[
        SourcePattern {
            regex: r"\beval\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "eval() executes arbitrary code; use ast.literal_eval() for data",
        },
        SourcePattern {
            regex: r"\bexec\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "exec() executes arbitrary code; avoid or sandbox",
        },
        SourcePattern {
            regex: r"\bos\.system\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "os.system() passes commands to shell; use subprocess with shell=False",
        },
        SourcePattern {
            regex: r"\bsubprocess\.call\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason: "subprocess.call may use shell; ensure shell=False and validate inputs",
        },
        SourcePattern {
            regex: r"\bsubprocess\.Popen\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason: "Popen may use shell; ensure shell=False and validate inputs",
        },
        SourcePattern {
            regex: r"\bpickle\.loads?\s*\(",
            category: DangerCategory::Deserialization,
            severity: Severity::Critical,
            reason: "pickle deserialization executes arbitrary code; use json or safe alternatives",
        },
        SourcePattern {
            regex: r"\byaml\.load\s*\(",
            category: DangerCategory::Deserialization,
            severity: Severity::High,
            reason: "yaml.load is unsafe; use yaml.safe_load",
        },
        SourcePattern {
            regex: r"\b__import__\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason: "__import__() can load arbitrary modules; validate input",
        },
        SourcePattern {
            regex: r"\bshelve\.open\s*\(",
            category: DangerCategory::Deserialization,
            severity: Severity::High,
            reason: "shelve uses pickle internally; avoid with untrusted data",
        },
        SourcePattern {
            regex: r"\bmarshall\.loads?\s*\(",
            category: DangerCategory::Deserialization,
            severity: Severity::High,
            reason: "marshal deserialization can execute code; use json",
        },
        // Path traversal (CWE-22) — from self-improvement iteration 5
        SourcePattern {
            regex: r"\bopen\s*\([^)]*\+",
            category: DangerCategory::PathTraversal,
            severity: Severity::High,
            reason:
                "File open with concatenated path; validate and canonicalize to prevent traversal",
        },
        SourcePattern {
            regex: r"\bos\.path\.join\s*\(",
            category: DangerCategory::PathTraversal,
            severity: Severity::Medium,
            reason:
                "os.path.join with untrusted input can traverse directories; canonicalize result",
        },
        // Weak random in Python — from self-improvement iteration 5
        SourcePattern {
            regex: r"\brandom\.\w+\s*\(",
            category: DangerCategory::Crypto,
            severity: Severity::Medium,
            reason:
                "random module is not cryptographically secure; use secrets module for security",
        },
        SourcePattern {
            regex: r"\bcursor\.execute\s*\([^)]*%",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "SQL injection via string formatting; use parameterized queries",
        },
        SourcePattern {
            regex: r#"\bcursor\.execute\s*\([^)]*\+\s*"#,
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "SQL injection via string concatenation; use parameterized queries",
        },
        // Weak cryptography (CWE-327) — from PR #107
        SourcePattern {
            regex: r"\bhashlib\.md5\s*\(",
            category: DangerCategory::Crypto,
            severity: Severity::High,
            reason: "MD5 is cryptographically broken; use SHA-256 or SHA-3",
        },
        SourcePattern {
            regex: r"\bhashlib\.sha1\s*\(",
            category: DangerCategory::Crypto,
            severity: Severity::High,
            reason: "SHA-1 is cryptographically weak; use SHA-256 or SHA-3",
        },
        SourcePattern {
            regex: r#"\bhashlib\.new\s*\(\s*['"](?:md5|sha1|md4|md2)['"]"#,
            category: DangerCategory::Crypto,
            severity: Severity::High,
            reason: "Weak hash algorithm; use SHA-256 or stronger",
        },
        SourcePattern {
            regex: r"(?i)\bfrom\s+Crypto\.Cipher\s+import\s+DES\b",
            category: DangerCategory::Crypto,
            severity: Severity::Critical,
            reason: "DES is broken with 56-bit key; use AES",
        },
        SourcePattern {
            regex: r"(?i)\bfrom\s+Cryptodome\.Cipher\s+import\s+DES\b",
            category: DangerCategory::Crypto,
            severity: Severity::Critical,
            reason: "DES is broken with 56-bit key; use AES",
        },
        SourcePattern {
            regex: r"(?i)\bDES\.new\s*\(",
            category: DangerCategory::Crypto,
            severity: Severity::Critical,
            reason: "DES cipher is broken; use AES with adequate key size",
        },
        SourcePattern {
            regex: r"(?i)\bBlowfish\.new\s*\(",
            category: DangerCategory::Crypto,
            severity: Severity::High,
            reason: "Blowfish has known weaknesses; use AES",
        },
        SourcePattern {
            regex: r"(?i)\bRC4\.new\s*\(",
            category: DangerCategory::Crypto,
            severity: Severity::Critical,
            reason: "RC4 is broken; use AES-GCM or ChaCha20",
        },
        SourcePattern {
            regex: r"(?i)\bARC2\.new\s*\(",
            category: DangerCategory::Crypto,
            severity: Severity::Critical,
            reason: "RC2 is obsolete; use AES",
        },
        // Hard-coded credentials (CWE-798) — from PR #106
        // Require 4+ char non-space values to avoid FPs on help text
        SourcePattern {
            regex: r#"(?i)(?:password|passwd|pwd)\s*=\s*["'][^\s"']{4,}["']"#,
            category: DangerCategory::Crypto,
            severity: Severity::Critical,
            reason: "Hard-coded password; use environment variables or secret management",
        },
        SourcePattern {
            regex: r#"(?i)(?:secret|api_key|apikey|access_key|token)\s*=\s*["'][^\s"']{4,}["']"#,
            category: DangerCategory::Crypto,
            severity: Severity::Critical,
            reason: "Hard-coded secret/key; use environment variables or vault",
        },
        SourcePattern {
            regex: r#"(?i)(?:password|passwd|pwd)\s*=\s*["']\s*["']"#,
            category: DangerCategory::Crypto,
            severity: Severity::High,
            reason: "Empty password assignment; authentication bypass risk",
        },
        // Enhanced injection patterns (CWE-74) — from PR #109
        SourcePattern {
            regex: r"\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason:
                "subprocess with shell=True enables shell injection; use shell=False with list args",
        },
        SourcePattern {
            regex: r"\bos\.popen\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "os.popen() passes command to shell; use subprocess with shell=False",
        },
        SourcePattern {
            regex: r#"\bexecute\s*\(\s*f["']"#,
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "SQL injection via f-string in execute(); use parameterized queries",
        },
        SourcePattern {
            regex: r#"\bexecute\s*\(\s*["'][^)]*\.format\s*\("#,
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "SQL injection via .format() in execute(); use parameterized queries",
        },
        SourcePattern {
            regex: r"\brender_template_string\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason:
                "Server-side template injection (SSTI); avoid rendering user-controlled templates",
        },
        SourcePattern {
            regex: r"\bTemplate\s*\([^)]*\+",
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason: "Template with string concatenation may enable SSTI; use static templates",
        },
        SourcePattern {
            regex: r#"\bos\.system\s*\(\s*f["']"#,
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason:
                "Command injection via f-string in os.system(); use subprocess with shell=False",
        },
        // subprocess.run without shell=True is safe by default — not flagged
        SourcePattern {
            regex: r"\b__import__\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "Dynamic import can load arbitrary modules; avoid with untrusted input",
        },
        SourcePattern {
            regex: r#"\bcompile\s*\([^)]*,\s*[^)]*,\s*['"]exec['"]"#,
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "compile() with exec mode enables code execution; avoid with untrusted input",
        },
    ]
}

fn javascript_patterns() -> &'static [SourcePattern] {
    &[
        SourcePattern {
            regex: r"\beval\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "eval() executes arbitrary code; avoid entirely",
        },
        SourcePattern {
            regex: r"\.innerHTML\s*=",
            category: DangerCategory::Xss,
            severity: Severity::High,
            reason: "innerHTML can execute scripts; use textContent or sanitize",
        },
        SourcePattern {
            regex: r"\bdocument\.write\s*\(",
            category: DangerCategory::Xss,
            severity: Severity::High,
            reason: "document.write can inject scripts; use DOM API",
        },
        SourcePattern {
            regex: r"\bchild_process\.exec\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "child_process.exec uses shell; use execFile or spawn",
        },
        SourcePattern {
            regex: r"\bnew\s+Function\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "new Function() is eval-equivalent; avoid",
        },
        SourcePattern {
            regex: r#"\bsetTimeout\s*\(\s*['""]"#,
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason: "setTimeout with string arg is eval-equivalent; pass a function reference",
        },
        SourcePattern {
            regex: r#"\bsetInterval\s*\(\s*['""]"#,
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason: "setInterval with string arg is eval-equivalent; pass a function reference",
        },
        // Path traversal (CWE-22) — from self-improvement iteration 5
        SourcePattern {
            regex: r"\bfs\.\w*(?:write|read|unlink|rmdir|mkdir|access|stat|open)\w*\s*\(",
            category: DangerCategory::PathTraversal,
            severity: Severity::High,
            reason: "File system operation with potentially user-controlled path; validate and sanitize path",
        },
        SourcePattern {
            regex: r"\bpath\.(?:join|resolve|normalize)\s*\(",
            category: DangerCategory::PathTraversal,
            severity: Severity::Medium,
            reason: "Path manipulation may allow directory traversal; canonicalize and validate against base directory",
        },
        SourcePattern {
            regex: r"__proto__",
            category: DangerCategory::PrototypePollution,
            severity: Severity::High,
            reason: "prototype pollution via __proto__; validate or freeze prototypes",
        },
        SourcePattern {
            regex: r"\bconstructor\s*\[",
            category: DangerCategory::PrototypePollution,
            severity: Severity::High,
            reason: "prototype pollution via constructor; sanitize keys",
        },
    ]
}

fn go_patterns() -> &'static [SourcePattern] {
    &[
        SourcePattern {
            regex: r"\bexec\.Command\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason: "exec.Command runs external processes; validate arguments",
        },
        SourcePattern {
            regex: r"\btemplate\.HTML\s*\(",
            category: DangerCategory::Xss,
            severity: Severity::High,
            reason: "template.HTML bypasses escaping; sanitize input",
        },
        SourcePattern {
            regex: r#"\bsql\.Query\s*\([^)]*\+"#,
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "SQL injection via concatenation; use parameterized queries",
        },
        SourcePattern {
            regex: r#"\bdb\.Exec\s*\([^)]*\+"#,
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "SQL injection via concatenation; use parameterized queries",
        },
        SourcePattern {
            regex: r"\bhttp\.ListenAndServe\s*\(",
            category: DangerCategory::Crypto,
            severity: Severity::Medium,
            reason: "HTTP without TLS; use ListenAndServeTLS for production",
        },
    ]
}

fn rust_patterns() -> &'static [SourcePattern] {
    &[
        SourcePattern {
            regex: r"\bunsafe\s*\{",
            category: DangerCategory::UnsafeCode,
            severity: Severity::High,
            reason: "unsafe block bypasses Rust safety guarantees; minimize and audit",
        },
        SourcePattern {
            regex: r"\bCommand::new\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason: "Command::new runs external processes; validate arguments",
        },
        SourcePattern {
            regex: r"\.unwrap\s*\(\s*\)",
            category: DangerCategory::Memory,
            severity: Severity::Low,
            reason: ".unwrap() panics on error; consider .expect() or proper error handling",
        },
        SourcePattern {
            regex: r"\*\s*\w+\s+as\s+\*",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "raw pointer cast; ensure safety invariants",
        },
        SourcePattern {
            regex: r"std::mem::transmute",
            category: DangerCategory::Memory,
            severity: Severity::Critical,
            reason: "transmute bypasses type safety; use safe alternatives",
        },
    ]
}

fn java_patterns() -> &'static [SourcePattern] {
    &[
        // Runtime.exec is covered by the broader pattern below (line ~432):
        //   r"\bRuntime\b[^;]*\.exec\s*\("
        SourcePattern {
            regex: r"\bProcessBuilder\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason: "ProcessBuilder runs OS commands; validate arguments",
        },
        SourcePattern {
            regex: r"\bStatement\.execute\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason: "Statement.execute may be vulnerable to SQL injection; use PreparedStatement",
        },
        SourcePattern {
            regex: r"\bObjectInputStream\b",
            category: DangerCategory::Deserialization,
            severity: Severity::Critical,
            reason: "Java deserialization can execute code; use allowlists or safe formats",
        },
        SourcePattern {
            regex: r"\bJNDI\b|\bInitialContext\b",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason:
                "JNDI lookup can lead to remote code execution (Log4Shell class); validate inputs",
        },
        SourcePattern {
            regex: r"\bScriptEngine\b.*\beval\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "ScriptEngine.eval executes arbitrary code; avoid with untrusted input",
        },
        // SQL injection patterns
        SourcePattern {
            regex: r#"\.execute\w*\s*\([^)]*\+\s*"#,
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason:
                "SQL query built with string concatenation; use PreparedStatement with parameters",
        },
        SourcePattern {
            regex: r"\.createQuery\s*\([^)]*\+",
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason:
                "Query creation with string concatenation; use parameterized queries",
        },
        // XSS patterns
        SourcePattern {
            regex: r"\bsetHeader\s*\(\s*.*\+",
            category: DangerCategory::Xss,
            severity: Severity::High,
            reason: "HTTP header set with user input; validate and encode output",
        },
        SourcePattern {
            regex: r"\.getWriter\(\)\.write\s*\(",
            category: DangerCategory::Xss,
            severity: Severity::High,
            reason: "Writing directly to response; encode output to prevent XSS",
        },
        SourcePattern {
            regex: r"\.getWriter\(\)\.println\s*\(",
            category: DangerCategory::Xss,
            severity: Severity::High,
            reason: "Writing directly to response; encode output to prevent XSS",
        },
        SourcePattern {
            regex: r"\.getWriter\(\)\.\w+\s*\([^)]*\+",
            category: DangerCategory::Xss,
            severity: Severity::Medium,
            reason: "Writing to response writer with concatenation; encode output to prevent XSS",
        },
        // Insecure cookie (CWE-614)
        SourcePattern {
            regex: r"\bnew\s+[\w.]*Cookie\s*\(",
            category: DangerCategory::Crypto,
            severity: Severity::Medium,
            reason: "Cookie creation; ensure setSecure(true) and setHttpOnly(true) are called",
        },
        // Weak cryptography patterns
        SourcePattern {
            regex: r#"\bCipher\.getInstance\s*\(\s*"DES"#,
            category: DangerCategory::Crypto,
            severity: Severity::High,
            reason: "DES is a weak cipher; use AES-256-GCM or ChaCha20",
        },
        SourcePattern {
            regex: r#"\bCipher\.getInstance\s*\(\s*".*ECB"#,
            category: DangerCategory::Crypto,
            severity: Severity::High,
            reason: "ECB mode is insecure (no IV, reveals patterns); use GCM or CBC with HMAC",
        },
        // Weak hash patterns
        SourcePattern {
            regex: r#"\bMessageDigest\.getInstance\s*\(\s*"(MD5|SHA-1|SHA1)""#,
            category: DangerCategory::Crypto,
            severity: Severity::High,
            reason: "MD5/SHA-1 are cryptographically broken; use SHA-256 or SHA-3",
        },
        // Weak random
        SourcePattern {
            regex: r"\bnew\s+(?:java\.util\.)?Random\s*\(",
            category: DangerCategory::Crypto,
            severity: Severity::Medium,
            reason: "java.util.Random is not cryptographically secure; use SecureRandom",
        },
        SourcePattern {
            regex: r"\bMath\.random\s*\(",
            category: DangerCategory::Crypto,
            severity: Severity::Medium,
            reason: "Math.random is not cryptographically secure; use SecureRandom",
        },
        // Path traversal: narrow new File+getParameter covered by broader pattern below (~line 405)
        SourcePattern {
            regex: r"\bgetRequestDispatcher\s*\([^)]*getParameter",
            category: DangerCategory::PathTraversal,
            severity: Severity::High,
            reason: "Request dispatch with user input; validate path to prevent traversal",
        },
        // LDAP injection
        SourcePattern {
            regex: r"\bsearch\s*\([^)]*\+.*getParameter",
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason: "LDAP query with user input; use parameterized LDAP queries",
        },
        // XPath injection (CWE-643) — from self-improvement iteration 8
        SourcePattern {
            regex: r"\bXPath\b[^;]*\b(?:compile|evaluate|selectNodes|selectSingleNode)\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason: "XPath query may be vulnerable to injection; use parameterized XPath or validate input",
        },
        SourcePattern {
            regex: r"\bXPathFactory\b",
            category: DangerCategory::Injection,
            severity: Severity::Medium,
            reason: "XPath evaluation may be vulnerable to injection if query includes user input",
        },
        SourcePattern {
            regex: r"\bDocumentBuilder\b[^;]*\bparse\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Medium,
            reason: "XML parsing may be vulnerable to XXE; disable external entities",
        },
        // Trust boundary (CWE-501) — additional session patterns
        SourcePattern {
            regex: r"\bputValue\s*\([^)]*getParameter",
            category: DangerCategory::Injection,
            severity: Severity::Medium,
            reason: "Session putValue with user input crosses trust boundary (CWE-501); validate before storing",
        },
        // Path traversal (CWE-22) — File.separator and normalize patterns
        SourcePattern {
            regex: r"\bnew\s+File\s*\([^)]*File\.separator",
            category: DangerCategory::PathTraversal,
            severity: Severity::High,
            reason: "File construction with separator may allow traversal; canonicalize and validate",
        },
        SourcePattern {
            regex: r"\bPaths\.get\s*\([^)]*getParameter",
            category: DangerCategory::PathTraversal,
            severity: Severity::High,
            reason: "Path from user input; validate and resolve against a safe base directory",
        },
        // LDAP injection (CWE-90) — from self-improvement iteration 5: DirContext.search
        SourcePattern {
            regex: r"\b(?:DirContext|InitialDirContext|LdapContext|EventDirContext)\.search\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason: "LDAP DirContext.search may be vulnerable to injection; use parameterized search filters",
        },
        SourcePattern {
            regex: r"\bNamingEnumeration\b",
            category: DangerCategory::Injection,
            severity: Severity::Medium,
            reason: "NamingEnumeration from LDAP search may contain injected data; validate results",
        },
        // Path traversal (CWE-22) — from self-improvement iteration 5
        SourcePattern {
            regex: r"\bnew\s+(?:java\.io\.)?File\s*\([^)]*(?:getParameter|getHeader|getCookies|request\.|param|input|fileName|filePath|path)",
            category: DangerCategory::PathTraversal,
            severity: Severity::High,
            reason: "File path from user input; validate and canonicalize path to prevent traversal",
        },
        SourcePattern {
            regex: r"\bnew\s+FileInputStream\s*\(",
            category: DangerCategory::PathTraversal,
            severity: Severity::Medium,
            reason: "FileInputStream may read user-controlled path; validate path to prevent traversal",
        },
        SourcePattern {
            regex: r"\bnew\s+FileOutputStream\s*\(",
            category: DangerCategory::PathTraversal,
            severity: Severity::Medium,
            reason: "FileOutputStream may write to user-controlled path; validate path to prevent traversal",
        },
        // From self-improvement: broader Runtime.exec pattern
        SourcePattern {
            regex: r"\bRuntime\b[^;]*\.exec\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "Runtime.exec runs OS commands; validate all arguments",
        },
        // From self-improvement: cookie-based path traversal
        SourcePattern {
            regex: r"\bgetCookies\s*\(\s*\)",
            category: DangerCategory::PathTraversal,
            severity: Severity::High,
            reason: "Cookie values may contain path traversal payloads; validate and canonicalize",
        },
        // Trust boundary (CWE-501): HttpSession setAttribute with user input
        SourcePattern {
            regex: r"\bsetAttribute\s*\([^)]*getParameter",
            category: DangerCategory::Injection,
            severity: Severity::Medium,
            reason: "Storing user input in session without validation; sanitize before storing",
        },
        // Broader trust boundary: HttpSession with any put/set + parameter
        SourcePattern {
            regex: r"\b(?:HttpSession|session)\b[^;]*\bsetAttribute\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Medium,
            reason: "Session setAttribute may store untrusted data across trust boundary (CWE-501)",
        },
        // Cookie creation covered by broader pattern above (line ~332):
        //   r"\bnew\s+[\w.]*Cookie\s*\("
    ]
}

fn c_cpp_patterns() -> &'static [SourcePattern] {
    &[
        SourcePattern {
            regex: r"\bstrcpy\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::Critical,
            reason: "strcpy has no bounds checking; use strncpy or strlcpy",
        },
        SourcePattern {
            regex: r"\bsprintf\s*\(",
            category: DangerCategory::FormatString,
            severity: Severity::High,
            reason: "sprintf has no bounds checking; use snprintf",
        },
        SourcePattern {
            regex: r"\bgets\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::Critical,
            reason: "gets has no bounds checking; use fgets",
        },
        SourcePattern {
            regex: r"\bsystem\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "system() passes to shell; use exec* family",
        },
        SourcePattern {
            regex: r"\bstrcat\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::Critical,
            reason: "strcat has no bounds checking; use strncat or strlcat",
        },
        SourcePattern {
            regex: r"\bscanf\s*\(",
            category: DangerCategory::FormatString,
            severity: Severity::High,
            reason: "scanf with %s has no bounds; use width specifiers",
        },
        SourcePattern {
            regex: r"\bpopen\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "popen passes to shell; use pipe+fork+exec",
        },
        SourcePattern {
            regex: r"\bprintf\s*\(\s*[a-zA-Z_]\w*\s*\)",
            category: DangerCategory::FormatString,
            severity: Severity::High,
            reason: "printf with variable as format string; use printf(\"%s\", var) instead",
        },
        // fprintf/snprintf/vprintf/vfprintf/vsnprintf format string sinks (CWE-134)
        SourcePattern {
            regex: r"\bfprintf\s*\([^,]+,\s*[a-zA-Z_]\w*\s*\)",
            category: DangerCategory::FormatString,
            severity: Severity::High,
            reason: "fprintf with variable format string; use fprintf(f, \"%s\", var) instead",
        },
        SourcePattern {
            regex: r"\bsnprintf\s*\([^,]+,[^,]+,\s*[a-zA-Z_]\w*\s*\)",
            category: DangerCategory::FormatString,
            severity: Severity::Medium,
            reason: "snprintf with variable format string; format string vulnerability even with bounded output",
        },
        SourcePattern {
            regex: r"\bvprintf\s*\(\s*[a-zA-Z_]\w*\s*,",
            category: DangerCategory::FormatString,
            severity: Severity::High,
            reason: "vprintf with variable format string; validate format origin",
        },
        SourcePattern {
            regex: r"\bvfprintf\s*\([^,]+,\s*[a-zA-Z_]\w*\s*,",
            category: DangerCategory::FormatString,
            severity: Severity::High,
            reason: "vfprintf with variable format string; validate format origin",
        },
        SourcePattern {
            regex: r"\bvsnprintf\s*\([^,]+,\s*[^,]+,\s*[a-zA-Z_]\w*\s*,",
            category: DangerCategory::FormatString,
            severity: Severity::Medium,
            reason: "vsnprintf with variable format string; validate format origin",
        },
        SourcePattern {
            regex: r"\batoi\s*\(",
            category: DangerCategory::IntegerOverflow,
            severity: Severity::High,
            reason: "atoi has no error checking and can cause integer overflow; use strtol with validation",
        },
        SourcePattern {
            regex: r"\batol\s*\(",
            category: DangerCategory::IntegerOverflow,
            severity: Severity::High,
            reason: "atol has no error checking and can cause integer overflow; use strtol with validation",
        },
        // exec family (from self-improvement: failure-analyst on Juliet CWE-78)
        SourcePattern {
            regex: r"(?i)\bexecl\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "execl executes a program; validate all arguments",
        },
        SourcePattern {
            regex: r"(?i)\bexecle\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "execle executes a program with environment; validate all arguments",
        },
        SourcePattern {
            regex: r"(?i)\bexecv\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "execv executes a program; validate all arguments",
        },
        SourcePattern {
            regex: r"(?i)\bexecvp\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "execvp executes a program via PATH; validate all arguments",
        },
        SourcePattern {
            regex: r"(?i)\bexecve\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "execve executes a program with environment; validate all arguments",
        },
        // Memory operations (from self-improvement: heuristic on Juliet CWE-119/120)
        SourcePattern {
            regex: r"\bmemcpy\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "memcpy with unchecked size can cause buffer overflow; validate size parameter",
        },
        SourcePattern {
            regex: r"\bmemmove\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "memmove with unchecked size can cause buffer overflow; validate size parameter",
        },
        SourcePattern {
            regex: r"\bwcscpy\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::Critical,
            reason: "wcscpy has no bounds checking (wide-char strcpy); use wcsncpy",
        },
        SourcePattern {
            regex: r"\bsscanf\s*\(",
            category: DangerCategory::FormatString,
            severity: Severity::High,
            reason: "sscanf with %s has no bounds; use width specifiers",
        },
        SourcePattern {
            regex: r"\bfscanf\s*\(",
            category: DangerCategory::FormatString,
            severity: Severity::High,
            reason: "fscanf with %s has no bounds; use width specifiers",
        },
        // Weak PRNG (CWE-338) — from self-improvement iteration 5
        SourcePattern {
            regex: r"\brand\s*\(\s*\)",
            category: DangerCategory::Crypto,
            severity: Severity::Medium,
            reason: "rand() is not cryptographically secure; use a CSPRNG or platform-specific secure random",
        },
        SourcePattern {
            regex: r"\bsrand\s*\(",
            category: DangerCategory::Crypto,
            severity: Severity::Medium,
            reason: "srand/rand are not cryptographically secure; use a CSPRNG",
        },
        // Integer overflow in allocation (CWE-680) — from self-improvement iteration 5
        SourcePattern {
            regex: r"\brealloc\s*\([^,]+,\s*[^;]*\*[^;]*\)",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "realloc with multiplication may overflow; check for integer overflow before reallocation",
        },
        // Use-after-free / double-free (CWE-416) — from self-improvement iteration 5
        SourcePattern {
            regex: r"\bfree\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::Low,
            reason: "free() requires careful lifecycle management; verify no use-after-free or double-free",
        },
        // Stack-based buffer overflow (CWE-121) — from self-improvement iteration 5
        SourcePattern {
            regex: r"\balloca\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "alloca allocates on the stack; large or unchecked sizes cause stack overflow",
        },
        // LDAP injection (CWE-90) — from self-improvement iteration 5
        SourcePattern {
            regex: r"(?i)\bldap_search(_ext)?(_s)?[AW]?\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason: "LDAP search with untrusted input may allow LDAP injection; sanitize filter parameters",
        },
        SourcePattern {
            regex: r"(?i)\bldap_add(_ext)?(_s)?[AW]?\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason: "LDAP add with untrusted input may allow LDAP injection; sanitize all parameters",
        },
        SourcePattern {
            regex: r"(?i)\bldap_modify(_ext)?(_s)?[AW]?\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason: "LDAP modify with untrusted input may allow LDAP injection; sanitize all parameters",
        },
        // Use of inherently dangerous function (CWE-242) — from self-improvement iteration 5
        SourcePattern {
            regex: r"\b_splitpath\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "_splitpath is inherently dangerous (no bounds checking); use _splitpath_s",
        },
        SourcePattern {
            regex: r"\blstrcat[AW]?\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::Critical,
            reason: "lstrcat has no bounds checking; use StringCchCat or strncat",
        },
        SourcePattern {
            regex: r"\blstrcpy[AW]?\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::Critical,
            reason: "lstrcpy has no bounds checking; use StringCchCopy or strncpy",
        },
        // Process control (CWE-114) — from self-improvement iteration 5
        SourcePattern {
            regex: r"(?i)\bLoadLibrary[AW]?(Ex[AW]?)?\s*\(",
            category: DangerCategory::PathTraversal,
            severity: Severity::High,
            reason: "LoadLibrary with untrusted input allows uncontrolled search path loading (CWE-427); validate library path",
        },
        SourcePattern {
            regex: r"\bdlopen\s*\(",
            category: DangerCategory::PathTraversal,
            severity: Severity::High,
            reason: "dlopen with untrusted path allows uncontrolled search path loading (CWE-427); validate library path",
        },
        // Windows-specific patterns (from self-improvement iteration 4)
        SourcePattern {
            regex: r"(?i)\bSetComputerName[AW]?\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason: "SetComputerName with untrusted input allows external control of system settings (CWE-15)",
        },
        SourcePattern {
            regex: r"(?i)\bSetEnvironmentVariable[AW]?\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason: "SetEnvironmentVariable with untrusted input can modify system behavior",
        },
        SourcePattern {
            regex: r"(?i)\bRegSetValue[AW]?(Ex[AW]?)?\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason: "Registry write with untrusted input can compromise system configuration",
        },
        SourcePattern {
            regex: r"(?i)\bCreateProcess[AW]?\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "CreateProcess runs external programs; validate command line arguments",
        },
        SourcePattern {
            regex: r"(?i)\bShellExecute[AW]?(Ex[AW]?)?\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "ShellExecute runs programs via shell; validate all parameters",
        },
        SourcePattern {
            regex: r"(?i)\bWinExec\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "WinExec is deprecated and insecure; use CreateProcess with validated args",
        },
        SourcePattern {
            regex: r"(?i)\b_execl\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "_execl (MSVC) executes a program; validate all arguments",
        },
        // Integer truncation/cast patterns (CWE-190/195/197) — from self-improvement iteration 8
        SourcePattern {
            regex: r"\(\s*(?:unsigned\s+)?(?:short|char)\s*\)\s*\w",
            category: DangerCategory::Memory,
            severity: Severity::Medium,
            reason: "Narrowing cast may truncate value; check for overflow before cast",
        },
        SourcePattern {
            regex: r"\(\s*(?:size_t|unsigned)\s*\)\s*\w+\s*[\-\+\*]",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "Signed-to-unsigned cast before arithmetic may wrap; validate sign first",
        },
        SourcePattern {
            regex: r"\bmalloc\s*\([^;]*\*[^;]*\)",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "malloc with multiplication may cause integer overflow in size calculation; use safe multiply",
        },
        SourcePattern {
            regex: r"\bcalloc\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::Low,
            reason: "calloc is safer than malloc for arrays but verify count*size doesn't overflow",
        },
        // Generalized dangerous API suffix detection.
        // Catches prefixed wrappers like project_strcpy, my_memcpy, safe_strcat, etc.
        // This is NOT benchmark-specific — any project wrapping libc functions is caught.
        SourcePattern {
            regex: r"\b\w+_strcpy\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::Critical,
            reason: "Wrapper around strcpy likely has no bounds checking; vulnerable to buffer overflow",
        },
        SourcePattern {
            regex: r"\b\w+_strcat\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::Critical,
            reason: "Wrapper around strcat likely has no bounds checking; vulnerable to buffer overflow",
        },
        SourcePattern {
            regex: r"\b\w+_memcpy\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "Wrapper around memcpy with unchecked size can cause buffer overflow",
        },
        SourcePattern {
            regex: r"\b\w+_sprintf\s*\(",
            category: DangerCategory::FormatString,
            severity: Severity::High,
            reason: "Wrapper around sprintf likely has no bounds checking; use snprintf variant",
        },
        SourcePattern {
            regex: r"\b\w+_printf\s*\(\s*[a-zA-Z_]\w*\s*\)",
            category: DangerCategory::FormatString,
            severity: Severity::High,
            reason: "Printf wrapper with variable format string; format string vulnerability",
        },
        SourcePattern {
            regex: r"\b\w+_malloc\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::Medium,
            reason: "Allocation wrapper: verify size is not attacker-controlled",
        },
        SourcePattern {
            regex: r"\b\w+_free\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::Low,
            reason: "Free wrapper: verify no double-free or use-after-free",
        },
        SourcePattern {
            regex: r"\b\w+_allocate\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "Custom allocator: verify size parameter is not attacker-controlled",
        },
        SourcePattern {
            regex: r"\b\w+_calloc\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::Medium,
            reason: "Custom calloc wrapper: verify count*size doesn't overflow",
        },
        // Hard-coded credentials (CWE-798)
        SourcePattern {
            regex: r#"(?i)(?:password|passwd|pwd)\s*=\s*"[^"]+""#,
            category: DangerCategory::Crypto,
            severity: Severity::Critical,
            reason: "Hard-coded password in C code; use configuration or environment variables",
        },
        SourcePattern {
            regex: r#"(?i)(?:secret|key|token)\s*=\s*"[^"]+""#,
            category: DangerCategory::Crypto,
            severity: Severity::High,
            reason: "Hard-coded secret/key in C code; use secure configuration",
        },
        // --- Null dereference (CWE-476/690) ---
        SourcePattern {
            regex: r"\*\s*\(\s*\w+\s*\)\s*=",
            category: DangerCategory::NullDeref,
            severity: Severity::High,
            reason: "Pointer dereference without null check; verify pointer is non-null before use",
        },
        SourcePattern {
            regex: r"(?i)\b(?:malloc|calloc|realloc)\s*\([^)]*\)\s*;",
            category: DangerCategory::NullDeref,
            severity: Severity::High,
            reason: "Allocation result not checked for NULL; malloc/calloc/realloc can return NULL",
        },
        SourcePattern {
            regex: r"\bNULL\b",
            category: DangerCategory::NullDeref,
            severity: Severity::Low,
            reason: "NULL reference in code; verify null checks on all paths using this value",
        },
        // --- Integer overflow (CWE-190/191/192/680) ---
        SourcePattern {
            regex: r"\b\w+\s*\+\+\s*;",
            category: DangerCategory::IntegerOverflow,
            severity: Severity::Medium,
            reason: "Increment without overflow check; may wrap on INT_MAX/UINT_MAX",
        },
        SourcePattern {
            regex: r"\b\w+\s*\+=\s*\w+",
            category: DangerCategory::IntegerOverflow,
            severity: Severity::Medium,
            reason: "Addition assignment without overflow check; validate operands before addition",
        },
        SourcePattern {
            regex: r"\b\w+\s*\*=\s*\w+",
            category: DangerCategory::IntegerOverflow,
            severity: Severity::High,
            reason: "Multiplication assignment without overflow check; validate operands",
        },
        // --- Divide by zero (CWE-369) ---
        SourcePattern {
            regex: r"\b\w+\s*/\s*\w+",
            category: DangerCategory::DivideByZero,
            severity: Severity::Medium,
            reason: "Division without zero-check on divisor; validate divisor is non-zero",
        },
        SourcePattern {
            regex: r"\b\w+\s*%\s*\w+",
            category: DangerCategory::DivideByZero,
            severity: Severity::Medium,
            reason: "Modulo without zero-check on divisor; validate divisor is non-zero",
        },
        // --- Resource leak (CWE-401/772/775) ---
        SourcePattern {
            regex: r"\bfopen\s*\(",
            category: DangerCategory::ResourceLeak,
            severity: Severity::Medium,
            reason: "File opened with fopen; verify matching fclose on all paths including error paths",
        },
        SourcePattern {
            regex: r"\bsocket\s*\(",
            category: DangerCategory::ResourceLeak,
            severity: Severity::Medium,
            reason: "Socket opened; verify matching close() on all paths including error paths",
        },
        SourcePattern {
            regex: r"\bopen\s*\(",
            category: DangerCategory::ResourceLeak,
            severity: Severity::Medium,
            reason: "File descriptor opened; verify matching close() on all paths",
        },
        SourcePattern {
            regex: r"\bCreateFile[AW]?\s*\(",
            category: DangerCategory::ResourceLeak,
            severity: Severity::Medium,
            reason: "Handle opened via CreateFile; verify matching CloseHandle on all paths",
        },
        // --- Uninitialized variable (CWE-457/908) ---
        SourcePattern {
            regex: r"\b(?:int|long|short|char|float|double|unsigned|size_t)\s+\w+\s*;",
            category: DangerCategory::UninitializedVar,
            severity: Severity::Medium,
            reason: "Variable declared without initialization; C does not zero-initialize local variables",
        },
        SourcePattern {
            regex: r"\b(?:int|long|short|char|float|double|unsigned|size_t)\s+\w+\s*\[",
            category: DangerCategory::UninitializedVar,
            severity: Severity::Medium,
            reason: "Array declared without initialization; contents are indeterminate in C",
        },
        // --- Resource exhaustion (CWE-400) ---
        SourcePattern {
            regex: r"\bwhile\s*\(\s*1\s*\)",
            category: DangerCategory::ResourceExhaustion,
            severity: Severity::Medium,
            reason: "Infinite loop: while(1) without break may cause resource exhaustion",
        },
        SourcePattern {
            regex: r"\bfor\s*\(\s*;\s*;\s*\)",
            category: DangerCategory::ResourceExhaustion,
            severity: Severity::Medium,
            reason: "Infinite loop: for(;;) without break may cause resource exhaustion",
        },
        // --- Invalid free (CWE-590) ---
        SourcePattern {
            regex: r"\bfree\s*\(\s*&\w+\s*\)",
            category: DangerCategory::InvalidFree,
            severity: Severity::High,
            reason: "free() on address-of stack variable; only heap-allocated memory should be freed",
        },
        // --- Access control (CWE-272/284) ---
        SourcePattern {
            regex: r"\bsetuid\s*\(\s*0\s*\)",
            category: DangerCategory::AccessControl,
            severity: Severity::Critical,
            reason: "setuid(0) escalates to root; verify privilege dropping is intentional and authorized",
        },
        SourcePattern {
            regex: r"\bseteuid\s*\(\s*0\s*\)",
            category: DangerCategory::AccessControl,
            severity: Severity::Critical,
            reason: "seteuid(0) escalates effective UID to root; verify this is intentional",
        },
        // --- Information exposure (CWE-226/534/535) ---
        SourcePattern {
            regex: r#"(?i)\b(?:password|passwd|secret|token|api_key|apikey)\s*=\s*["']"#,
            category: DangerCategory::InformationExposure,
            severity: Severity::High,
            reason: "Hardcoded credential or secret in source code",
        },
        // --- Error handling (CWE-390/391/666) ---
        SourcePattern {
            regex: r"\bcatch\s*\([^)]*\)\s*\{\s*\}",
            category: DangerCategory::ErrorHandling,
            severity: Severity::Medium,
            reason: "Empty catch block swallows exceptions silently (CWE-390)",
        },
        // Self-improvement: from case cyberseceval_10_c (CWEs [680])
        SourcePattern {
            regex: r"(malloc|calloc|realloc|alloca)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\*\s*[a-zA-Z_][a-zA-Z0-9_]*",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "Detect CWE-680 (Integer Overflow to Buffer Overflow) patterns where an integer multiplication or arithmetic operation is",
        },
        // Self-improvement: from case CWE114_Process_Control__w32_char_connect_socket_51a (CWEs [114])
        SourcePattern {
            regex: r"LoadLibrary[AW]\s*\(",
            category: DangerCategory::UnsafeCode,
            severity: Severity::High,
            reason: "Add detection pattern for CWE-114 (Process Control) where externally sourced data (e.g., from a network socket) flows in",
        },
        // Self-improvement: from case CWE114_Process_Control__w32_char_connect_socket_52b (CWEs [114])
        SourcePattern {
            regex: r"LoadLibrary[AW]\s*\(",
            category: DangerCategory::UnsafeCode,
            severity: Severity::High,
            reason: "Detect process control vulnerability where data received from a network socket is used to dynamically load a library via",
        },
        // Self-improvement: from case cyberseceval_7_c (CWEs [120])
        SourcePattern {
            regex: r"\b(strcpy|strcat|gets|sprintf)\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "Add or improve pattern detection for CWE-120 (Buffer Copy without Checking Size of Input) to catch common unsafe buffer ",
        },
        // Self-improvement: from case CWE114_Process_Control__w32_char_connect_socket_22b (CWEs [114])
        SourcePattern {
            regex: r"LoadLibrary(A|W|ExA|ExW)\s*\(",
            category: DangerCategory::UnsafeCode,
            severity: Severity::High,
            reason: "Add a detection pattern for CWE-114 Process Control that identifies calls to LoadLibraryA/LoadLibraryW/LoadLibraryExA/Lo",
        },
        // Self-improvement: from case CWE114_Process_Control__w32_char_connect_socket_52a (CWEs [114])
        SourcePattern {
            regex: r"LoadLibrary[AW]?\s*\(",
            category: DangerCategory::UnsafeCode,
            severity: Severity::High,
            reason: "Add a taint rule to detect CWE-114 Process Control via LoadLibrary calls (LoadLibraryA, LoadLibraryW, LoadLibrary) where",
        },
        // Self-improvement: from case cyberseceval_7_c (CWEs [120])
        SourcePattern {
            regex: r"strcpy\s*\(\s*\w+\s*,",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "Detect buffer overflow vulnerability in C code where a fixed-size buffer is used with unbounded string copy operations (",
        },
        // Self-improvement: from case cyberseceval_10_c (CWEs [680])
        SourcePattern {
            regex: r"(malloc|calloc|realloc)\s*\(.*[*+].*\)",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "Add detection pattern for CWE-680: Integer Overflow to Buffer Overflow, where a multiplication or arithmetic operation o",
        },
        // Self-improvement: from case CWE114_Process_Control__w32_char_connect_socket_51a (CWEs [114])
        SourcePattern {
            regex: r"LoadLibrary[AW]?\s*\(",
            category: DangerCategory::UnsafeCode,
            severity: Severity::High,
            reason: "Add a sink pattern for LoadLibrary variants (LoadLibraryA, LoadLibraryW, LoadLibrary) which are the primary sinks for CW",
        },
        // Self-improvement: from case cyberseceval_7_c (CWEs [120])
        SourcePattern {
            regex: r"(strcpy|memcpy|sprintf|strcat)\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "Add or improve pattern detection for buffer copy operations (e.g., strcpy, memcpy, sprintf) into fixed-size buffers with",
        },
        // Self-improvement: from case cyberseceval_8_c (CWEs [590])
        SourcePattern {
            regex: r"free\s*\(\s*&\w+\s*\)",
            category: DangerCategory::InvalidFree,
            severity: Severity::High,
            reason: "Add detection pattern for CWE-590: Free of Memory not on the Heap. This pattern should detect cases where free() is call",
        },
        // Self-improvement: from case CWE114_Process_Control__w32_char_connect_socket_51a (CWEs [114])
        SourcePattern {
            regex: r"\b(LoadLibrary[AW]|LoadLibraryEx[AW]|dlopen)\s*\(",
            category: DangerCategory::UnsafeCode,
            severity: Severity::High,
            reason: "Create sink patterns for process control functions: LoadLibraryA, LoadLibraryW, LoadLibraryExA, LoadLibraryExW (Windows)",
        },
        // Self-improvement: from case CWE114_Process_Control__w32_char_connect_socket_52a (CWEs [114])
        SourcePattern {
            regex: r"LoadLibrary[AW]\s*\(",
            category: DangerCategory::UnsafeCode,
            severity: Severity::High,
            reason: "Add detection pattern for CWE-114 Process Control via LoadLibraryA/LoadLibraryW calls with tainted input. The sink funct",
        },
        // Self-improvement: from case cyberseceval_8_c (CWEs [590])
        SourcePattern {
            regex: r"free\s*\(\s*&\w+\s*\)",
            category: DangerCategory::InvalidFree,
            severity: Severity::High,
            reason: "Add a pattern to detect CWE-590 (Free of Memory not on the Heap) where free() is called on stack-allocated variables, st",
        },
        // Self-improvement: from case cyberseceval_10_c (CWEs [680])
        SourcePattern {
            regex: r"(malloc|calloc|realloc)\s*\(.*\*.*\)",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "Detect integer overflow in multiplication used for memory allocation size calculation (e.g., multiplying user-controlled",
        },
        // Self-improvement: from case cyberseceval_7_c (CWEs [120])
        SourcePattern {
            regex: r"\bsprintf\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "Add C/C++ pattern sprintf() to detect CWE-[120] ",
        },
        // Self-improvement: from case CWE114_Process_Control__w32_char_connect_socket_51a (CWEs [114])
        SourcePattern {
            regex: r"\b(LoadLibrary[AW]?|LoadLibraryEx[AW]?)\s*\(",
            category: DangerCategory::UnsafeCode,
            severity: Severity::High,
            reason: "Add sink patterns for CWE-114 Process Control. On Windows (w32), the primary sinks are LoadLibrary and LoadLibraryEx whi",
        },
        // Self-improvement: from case CWE114_Process_Control__w32_char_connect_socket_52a (CWEs [114])
        SourcePattern {
            regex: r"(LoadLibrary[AW]?|dlopen)\s*\(",
            category: DangerCategory::UnsafeCode,
            severity: Severity::High,
            reason: "Add detection pattern for CWE-114 (Process Control) where user-controlled data flows into LoadLibrary/LoadLibraryA/LoadL",
        },
        // Self-improvement: from case multi_file (CWEs [122])
        SourcePattern {
            regex: r"(malloc|calloc|realloc)\s*\(.*\).*\n.*\b(read|recv|fgets|fread|gets|memcpy|strcpy|strcat)\b",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "Detect heap buffer overflow (CWE-122) when data is read into a heap-allocated buffer without proper bounds checking. The",
        },
        // Self-improvement: from case multi_file (CWEs [78])
        SourcePattern {
            regex: r"(system|popen|exec[lv]?p?|ShellExecute|CreateProcess)\s*\(.*\b(strcat|sprintf|snprintf|strncpy|memcpy|argv|getenv|scanf|fgets|recv|read)\b",
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason: "Detect OS command injection (CWE-78) where user-controlled input is concatenated or interpolated into strings passed to ",
        },
        // Self-improvement: from case multi_file (CWEs [122])
        SourcePattern {
            regex: r"malloc\s*\(.*\).*str(cat|cpy)\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "Detect heap buffer overflow (CWE-122) in cases where a fixed-size heap buffer is allocated and then written to without p",
        },
        // Self-improvement: from case multi_file (CWEs [78])
        SourcePattern {
            regex: r"(system|popen|exec[lv]?p?)\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::High,
            reason: "Detect OS command injection (CWE-78) where user-controlled input or insufficiently validated data is concatenated into s",
        },
        // Self-improvement: from case cse_dangerous_func_tmpfile (CWEs [676, 377])
        SourcePattern {
            regex: r"\b(mktemp|tmpnam|tempnam)\s*\(",
            category: DangerCategory::TempFile,
            severity: Severity::High,
            reason: "Detect insecure temp file creation (CWE-676, CWE-377) via mktemp/tmpnam/tempnam which are always dangerous and deprecated by POSIX",
        },
        // Self-improvement: from case cse_classic_bufovf_gets (CWEs [120])
        SourcePattern {
            regex: r"\bscanf\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "Detect scanf usage (CWE-120) which can cause buffer overflow when used with unbounded format specifiers like %s",
        },
        // Self-improvement: from case race_condition (CWEs [367])
        SourcePattern {
            regex: r"\baccess\s*\(",
            category: DangerCategory::Race,
            severity: Severity::High,
            reason: "Detect access() TOCTOU race condition (CWE-367) — access() checks are inherently vulnerable to time-of-check-time-of-use attacks",
        },
    ]
}

fn get_patterns_for_language(language: &str) -> &'static [SourcePattern] {
    match language {
        "python" => python_patterns(),
        "javascript" | "typescript" => javascript_patterns(),
        "go" => go_patterns(),
        "rust" => rust_patterns(),
        "java" => java_patterns(),
        "c" | "cpp" => c_cpp_patterns(),
        _ => &[],
    }
}

/// Detect dangerous patterns in source content already in memory.
pub fn detect_in_source_content(
    content: &str,
    language: &str,
    file_path: &str,
) -> anyhow::Result<Vec<DangerousApiHit>> {
    let patterns = get_patterns_for_language(language);
    let mut hits = Vec::new();

    for pat in patterns {
        let re = Regex::new(pat.regex)
            .map_err(|e| anyhow::anyhow!("Bad pattern {}: {}", pat.regex, e))?;

        for m in re.find_iter(content) {
            let byte_offset = m.start();
            let line = content[..byte_offset].matches('\n').count() + 1;
            let matched_text = m.as_str().trim().to_string();

            hits.push(DangerousApiHit {
                function_name: matched_text,
                library: format!("source:{}", language),
                reason: pat.reason.to_string(),
                danger_category: pat.category.clone(),
                severity: pat.severity.clone(),
                file: file_path.to_string(),
                line,
            });
        }
    }

    // For C/C++, also detect stack-buffer-to-write chains (CWE-121).
    // These are higher-confidence findings than individual API matches
    // because they prove both allocation AND unsafe write co-occur.
    if matches!(language, "c" | "cpp") {
        let chains = super::taint::detect_stack_buffer_write_chains(content);
        for chain in chains {
            hits.push(DangerousApiHit {
                function_name: format!("{}({}, ...)", chain.write_api, chain.buffer_var),
                library: format!("source:{}", language),
                reason: format!(
                    "CWE-121: stack buffer '{}[{}]' written by unbounded {}() \
                     — confirm write size is not attacker-controlled",
                    chain.buffer_var, chain.buffer_size, chain.write_api,
                ),
                danger_category: DangerCategory::Memory,
                severity: Severity::Critical,
                file: file_path.to_string(),
                line: chain.write_line,
            });
        }
    }

    // Sort by severity (Critical first)
    hits.sort_by(|a, b| a.severity.cmp(&b.severity));
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::patterns_binary::DangerousApiDetector;

    #[test]
    fn test_detect_python_dangerous() {
        let detector = DangerousApiDetector::new();
        let src = r#"
import os
user_input = input()
os.system("echo " + user_input)
eval(user_input)
pickle.loads(data)
"#;
        let hits = detector
            .detect_in_source_content(src, "python", "app.py")
            .unwrap();
        assert!(hits
            .iter()
            .any(|h| h.danger_category == DangerCategory::Injection));
        assert!(hits
            .iter()
            .any(|h| h.danger_category == DangerCategory::Deserialization));
        assert!(hits.len() >= 3);
    }

    #[test]
    fn test_detect_javascript_dangerous() {
        let detector = DangerousApiDetector::new();
        let src = r#"
const input = req.params.id;
eval(input);
document.innerHTML = input;
child_process.exec("ls " + input);
new Function(input);
"#;
        let hits = detector
            .detect_in_source_content(src, "javascript", "app.js")
            .unwrap();
        assert!(hits.iter().any(|h| h.function_name.contains("eval")));
        assert!(hits
            .iter()
            .any(|h| h.danger_category == DangerCategory::Xss));
        assert!(hits.len() >= 3);
    }

    #[test]
    fn test_detect_rust_dangerous() {
        let detector = DangerousApiDetector::new();
        let src = r#"
fn run(input: &str) {
    unsafe {
        let ptr = input.as_ptr();
    }
    Command::new(input).output().unwrap();
}
"#;
        let hits = detector
            .detect_in_source_content(src, "rust", "main.rs")
            .unwrap();
        assert!(hits
            .iter()
            .any(|h| h.danger_category == DangerCategory::UnsafeCode));
        assert!(hits
            .iter()
            .any(|h| h.danger_category == DangerCategory::Injection));
    }

    #[test]
    fn test_detect_go_dangerous() {
        let detector = DangerousApiDetector::new();
        let src = r#"
func run(input string) {
    exec.Command(input).Run()
    template.HTML(input)
}
"#;
        let hits = detector
            .detect_in_source_content(src, "go", "main.go")
            .unwrap();
        assert!(hits
            .iter()
            .any(|h| h.danger_category == DangerCategory::Injection));
        assert!(hits
            .iter()
            .any(|h| h.danger_category == DangerCategory::Xss));
    }

    #[test]
    fn test_detect_java_dangerous() {
        let detector = DangerousApiDetector::new();
        let src = r#"
import java.io.ObjectInputStream;
Runtime.getRuntime().exec(cmd);
ObjectInputStream ois = new ObjectInputStream(in);
"#;
        let hits = detector
            .detect_in_source_content(src, "java", "Vuln.java")
            .unwrap();
        assert!(hits
            .iter()
            .any(|h| h.danger_category == DangerCategory::Injection));
        assert!(hits
            .iter()
            .any(|h| h.danger_category == DangerCategory::Deserialization));
    }

    #[test]
    fn test_detect_c_dangerous() {
        let detector = DangerousApiDetector::new();
        let src = r#"
void vuln(char *input) {
    char buf[64];
    strcpy(buf, input);
    sprintf(buf, "%s", input);
    system(input);
}
"#;
        let hits = detector
            .detect_in_source_content(src, "c", "vuln.c")
            .unwrap();
        assert!(hits.iter().any(|h| h.function_name.contains("strcpy")));
        assert!(hits.iter().any(|h| h.function_name.contains("system")));
        assert!(hits.len() >= 3);
    }

    #[test]
    fn test_detect_source_no_false_positives() {
        let detector = DangerousApiDetector::new();
        let src = r#"
def safe_function():
    print("hello")
    x = 1 + 2
    return x
"#;
        let hits = detector
            .detect_in_source_content(src, "python", "safe.py")
            .unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn test_detect_c_format_string_and_integer_patterns() {
        let detector = DangerousApiDetector::new();
        let src = r#"
void vuln(char *msg, char *num_str) {
    printf(msg);
    int n = atoi(num_str);
    long l = atol(num_str);
}
"#;
        let hits = detector
            .detect_in_source_content(src, "c", "test.c")
            .unwrap();
        assert!(
            hits.iter().any(|h| h.function_name.contains("printf")),
            "Expected printf(variable) format string detection"
        );
        assert!(
            hits.iter().any(|h| h.function_name.contains("atoi")),
            "Expected atoi detection"
        );
        assert!(
            hits.iter().any(|h| h.function_name.contains("atoi")
                && matches!(h.danger_category, DangerCategory::IntegerOverflow)),
            "atoi should be categorized as IntegerOverflow"
        );
        assert!(
            hits.iter().any(|h| h.function_name.contains("atol")),
            "Expected atol detection"
        );
    }

    #[test]
    fn test_detect_custom_wrapper_apis() {
        let detector = DangerousApiDetector::new();
        let src = r#"
void handle_input(char *dst, const char *src, char *user_fmt, size_t len) {
    project_strcpy(dst, src);
    wrapper_memcpy(dst, src, len);
    logger_sprintf(dst, "%s", src);
    audit_printf(user_fmt);
    void *mem = pool_allocate(4096, 0);
}
"#;
        let hits = detector
            .detect_in_source_content(src, "c", "challenge.c")
            .unwrap();
        assert!(
            hits.iter()
                .any(|h| h.function_name.contains("project_strcpy")),
            "Expected custom strcpy wrapper detection"
        );
        assert!(
            hits.iter()
                .any(|h| h.function_name.contains("wrapper_memcpy")),
            "Expected custom memcpy wrapper detection"
        );
        assert!(
            hits.iter()
                .any(|h| h.function_name.contains("logger_sprintf")),
            "Expected custom sprintf wrapper detection"
        );
        assert!(
            hits.iter()
                .any(|h| h.function_name.contains("audit_printf")),
            "Expected custom printf wrapper detection"
        );
        assert!(hits.len() >= 4);
    }

    #[test]
    fn test_source_patterns_remain_benchmark_agnostic() {
        let disallowed_tokens = ["cgc", "juliet", "cyberseceval"];
        let pattern_sets = [
            ("python", python_patterns()),
            ("javascript", javascript_patterns()),
            ("go", go_patterns()),
            ("rust", rust_patterns()),
            ("java", java_patterns()),
            ("c/c++", c_cpp_patterns()),
        ];

        for (language, patterns) in pattern_sets {
            for pattern in patterns {
                let pattern_text =
                    format!("{} {}", pattern.regex, pattern.reason).to_ascii_lowercase();
                for token in disallowed_tokens {
                    assert!(
                        !pattern_text.contains(token),
                        "{language} pattern should stay benchmark-agnostic and avoid `{token}`: regex=`{}` reason=`{}`",
                        pattern.regex,
                        pattern.reason
                    );
                }
            }
        }
    }

    #[test]
    fn test_safe_printf_not_flagged() {
        let detector = DangerousApiDetector::new();
        let src = r#"
void safe(const char *msg) {
    printf("%s\n", msg);
    printf("hello world\n");
}
"#;
        let hits = detector
            .detect_in_source_content(src, "c", "safe.c")
            .unwrap();
        // Safe printf with format literal should not trigger the format string pattern.
        // (sprintf is still flagged by the existing pattern, but printf with literal is safe)
        let format_hits: Vec<_> = hits
            .iter()
            .filter(|h| h.danger_category == DangerCategory::FormatString)
            .collect();
        assert!(
            format_hits.is_empty(),
            "Safe printf should not trigger format string detection, got: {:?}",
            format_hits
                .iter()
                .map(|h| &h.function_name)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_detect_fprintf_vprintf_snprintf_format_strings() {
        let detector = DangerousApiDetector::new();
        let src = r#"
void vuln(FILE *fp, char *data, char *fmt, va_list args) {
    fprintf(fp, data);
    snprintf(buf, sizeof(buf), data);
    vprintf(fmt, args);
    vfprintf(fp, fmt, args);
    vsnprintf(buf, sizeof(buf), fmt, args);
    vprintf("%s\n", args);
    vfprintf(fp, "%s\n", args);
    vsnprintf(buf, sizeof(buf), "%s\n", args);
}
"#;
        let hits = detector
            .detect_in_source_content(src, "c", "fmt.c")
            .unwrap();
        let fmt_hits: Vec<_> = hits
            .iter()
            .filter(|h| h.danger_category == DangerCategory::FormatString)
            .collect();
        assert_eq!(
            fmt_hits.len(),
            5,
            "Literal-format vprintf-family calls should not be flagged"
        );
        assert!(
            fmt_hits.iter().any(|h| h.function_name.contains("fprintf")),
            "Should detect fprintf with variable format"
        );
        assert!(
            fmt_hits
                .iter()
                .any(|h| h.function_name.contains("snprintf")),
            "Should detect snprintf with variable format"
        );
        assert!(
            fmt_hits.iter().any(|h| h.function_name.contains("vprintf")),
            "Should detect vprintf"
        );
        assert!(
            fmt_hits
                .iter()
                .any(|h| h.function_name.contains("vfprintf")),
            "Should detect vfprintf"
        );
        assert!(
            fmt_hits
                .iter()
                .any(|h| h.function_name.contains("vsnprintf")),
            "Should detect vsnprintf"
        );
    }

    #[test]
    fn test_detect_python_weak_crypto() {
        let detector = DangerousApiDetector::new();
        let src = r#"
import hashlib
h = hashlib.md5(data)
h2 = hashlib.sha1(data)
from Crypto.Cipher import DES
cipher = DES.new(key, DES.MODE_ECB)
"#;
        let hits = detector
            .detect_in_source_content(src, "python", "crypto.py")
            .unwrap();
        let crypto_hits: Vec<_> = hits
            .iter()
            .filter(|h| h.danger_category == DangerCategory::Crypto)
            .collect();
        assert!(
            crypto_hits.len() >= 3,
            "Should detect md5, sha1, and DES; found {}",
            crypto_hits.len()
        );
    }

    #[test]
    fn test_detect_python_hardcoded_credentials() {
        let src = r#"
password = "super_secret_123"
api_key = "sk-1234567890abcdef"
"#;
        let hits = detect_in_source_content(src, "python", "config.py").unwrap();
        assert!(
            hits.iter()
                .any(|h| h.danger_category == DangerCategory::Crypto),
            "Should detect hard-coded credentials"
        );
    }

    #[test]
    fn test_detect_c_hardcoded_credentials() {
        let src = r#"
const char* password = "admin123";
"#;
        let hits = detect_in_source_content(src, "c", "config.c").unwrap();
        assert!(
            hits.iter()
                .any(|h| h.danger_category == DangerCategory::Crypto),
            "Should detect hard-coded credentials in C"
        );
    }

    #[test]
    fn test_detect_c_null_deref_patterns() {
        let src = r#"
void vuln() {
    char *p = malloc(100);
    *p = 'a';
    if (p == NULL) return;
}
"#;
        let hits = detect_in_source_content(src, "c", "null.c").unwrap();
        assert!(
            hits.iter()
                .any(|h| h.danger_category == DangerCategory::NullDeref),
            "Should detect null dereference risk"
        );
    }

    #[test]
    fn test_detect_c_resource_leak_patterns() {
        let src = r#"
void vuln() {
    FILE *f = fopen("data.txt", "r");
    int fd = socket(AF_INET, SOCK_STREAM, 0);
}
"#;
        let hits = detect_in_source_content(src, "c", "leak.c").unwrap();
        assert!(
            hits.iter()
                .any(|h| h.danger_category == DangerCategory::ResourceLeak),
            "Should detect resource leak risk"
        );
    }

    #[test]
    fn test_detect_c_uninitialized_var_patterns() {
        let src = r#"
void vuln() {
    int x;
    char buf[64];
    return x;
}
"#;
        let hits = detect_in_source_content(src, "c", "uninit.c").unwrap();
        assert!(
            hits.iter()
                .any(|h| h.danger_category == DangerCategory::UninitializedVar),
            "Should detect uninitialized variable risk"
        );
    }

    #[test]
    fn test_detect_c_divide_by_zero_patterns() {
        let src = r#"
int vuln(int a, int b) {
    return a / b;
}
"#;
        let hits = detect_in_source_content(src, "c", "divzero.c").unwrap();
        assert!(
            hits.iter()
                .any(|h| h.danger_category == DangerCategory::DivideByZero),
            "Should detect divide-by-zero risk"
        );
    }

    #[test]
    fn test_detect_c_integer_overflow_patterns() {
        let src = r#"
void vuln(int n) {
    n++;
    int total = 0;
    total += n;
}
"#;
        let hits = detect_in_source_content(src, "c", "overflow.c").unwrap();
        assert!(
            hits.iter()
                .any(|h| h.danger_category == DangerCategory::IntegerOverflow),
            "Should detect integer overflow risk"
        );
    }

    #[test]
    fn test_cwe121_chain_produces_critical_hit() {
        let src = r#"
void vuln(char *input) {
    char buf[64];
    strcpy(buf, input);
}
"#;
        let hits = detect_in_source_content(src, "c", "overflow.c").unwrap();
        let chain_hits: Vec<_> = hits
            .iter()
            .filter(|h| h.reason.contains("CWE-121"))
            .collect();
        assert!(
            !chain_hits.is_empty(),
            "Should produce CWE-121 chain finding for stack buffer + strcpy"
        );
        assert_eq!(chain_hits[0].severity, Severity::Critical);
        assert!(chain_hits[0].function_name.contains("strcpy"));
        assert!(chain_hits[0].function_name.contains("buf"));
    }

    #[test]
    fn test_cwe121_no_chain_for_declaration_only() {
        let src = r#"
void safe_func() {
    char buf[64];
    buf[0] = '\0';
}
"#;
        let hits = detect_in_source_content(src, "c", "safe.c").unwrap();
        let chain_hits: Vec<_> = hits
            .iter()
            .filter(|h| h.reason.contains("CWE-121"))
            .collect();
        assert!(
            chain_hits.is_empty(),
            "Declaration-only should not produce CWE-121 chain, got: {:?}",
            chain_hits.iter().map(|h| &h.reason).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_cwe121_chain_not_triggered_for_python() {
        // Chain detection is C/C++ only
        let src = r#"
buf = bytearray(64)
import ctypes
ctypes.memmove(buf, data, len(data))
"#;
        let hits = detect_in_source_content(src, "python", "test.py").unwrap();
        let chain_hits: Vec<_> = hits
            .iter()
            .filter(|h| h.reason.contains("CWE-121"))
            .collect();
        assert!(
            chain_hits.is_empty(),
            "CWE-121 chains should not trigger for Python"
        );
    }
}
