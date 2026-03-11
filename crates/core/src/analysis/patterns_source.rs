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
        SourcePattern {
            regex: r"\bRuntime\.getRuntime\(\)\.exec\s*\(",
            category: DangerCategory::Injection,
            severity: Severity::Critical,
            reason: "Runtime.exec runs OS commands; validate all arguments",
        },
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
}
