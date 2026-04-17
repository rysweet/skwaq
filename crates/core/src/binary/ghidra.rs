//! Ghidra headless analyzer integration via subprocess.

use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::binary::cache::AnalysisCache;
use crate::binary::subprocess::*;
use crate::binary::types::*;

pub struct GhidraRunner {
    ghidra_path: Option<PathBuf>,
}

/// Result of attempting to load Ghidra analysis for a binary.
///
/// The loader prefers a validated cached analysis when available, otherwise it
/// triggers a fresh Ghidra run if Ghidra is installed.
#[derive(Debug)]
pub enum GhidraLoadOutcome {
    NotAvailable,
    Cached(GhidraAnalysis),
    Fresh(GhidraAnalysis),
    Failed(String),
}

impl GhidraRunner {
    pub fn new(ghidra_path: Option<PathBuf>) -> Self {
        Self { ghidra_path }
    }

    /// Find Ghidra installation directory.
    pub fn find_ghidra() -> Option<PathBuf> {
        // Check env var first
        if let Ok(path) = std::env::var("GHIDRA_INSTALL_DIR") {
            let p = PathBuf::from(&path);
            if p.join("support/analyzeHeadless").exists() {
                return Some(p);
            }
        }

        // Check common locations
        let candidates = ["/opt/ghidra", "/usr/local/ghidra", "/usr/share/ghidra"];
        for candidate in candidates {
            let p = PathBuf::from(candidate);
            if p.join("support/analyzeHeadless").exists() {
                return Some(p);
            }
        }

        // Check home directory
        if let Some(home) = dirs::home_dir() {
            let p = home.join("ghidra");
            if p.join("support/analyzeHeadless").exists() {
                return Some(p);
            }
        }

        None
    }

    /// Find the ghidra-scripts/ directory containing extract_analysis.py.
    fn find_scripts_dir() -> Option<PathBuf> {
        // 1. SKWAQ_SCRIPTS_DIR env var
        if let Ok(path) = std::env::var("SKWAQ_SCRIPTS_DIR") {
            let p = PathBuf::from(&path);
            if p.join("extract_analysis.py").exists() {
                return Some(p);
            }
        }

        // 2. Current directory / ghidra-scripts
        let cwd = std::env::current_dir().ok()?;
        let p = cwd.join("ghidra-scripts");
        if p.join("extract_analysis.py").exists() {
            return Some(p);
        }

        // 3. Next to the binary
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                let p = parent.join("ghidra-scripts");
                if p.join("extract_analysis.py").exists() {
                    return Some(p);
                }
                // Also check one level up (e.g. target/debug/../ghidra-scripts)
                if let Some(grandparent) = parent.parent() {
                    let p = grandparent.join("ghidra-scripts");
                    if p.join("extract_analysis.py").exists() {
                        return Some(p);
                    }
                    // And two levels up (target/debug/../../ghidra-scripts)
                    if let Some(ggp) = grandparent.parent() {
                        let p = ggp.join("ghidra-scripts");
                        if p.join("extract_analysis.py").exists() {
                            return Some(p);
                        }
                    }
                }
            }
        }

        None
    }

    fn headless_path(&self) -> Option<PathBuf> {
        let base = self.ghidra_path.as_ref()?;
        let path = base.join("support/analyzeHeadless");
        if path.exists() {
            Some(path)
        } else {
            None
        }
    }

    /// Run Ghidra headless analysis on a binary.
    /// Returns parsed analysis output with decompiled functions.
    pub async fn analyze(
        &self,
        binary_path: &Path,
        timeout_secs: u64,
    ) -> anyhow::Result<GhidraAnalysis> {
        let headless = self
            .headless_path()
            .ok_or_else(|| anyhow::anyhow!("Ghidra not found. Set GHIDRA_INSTALL_DIR"))?;

        let scripts_dir = Self::find_scripts_dir().ok_or_else(|| {
            anyhow::anyhow!(
                "ghidra-scripts/extract_analysis.py not found. \
                 Set SKWAQ_SCRIPTS_DIR or run from the skwaq project root."
            )
        })?;

        let project_dir = tempfile::tempdir()?;
        let output_file = project_dir.path().join("ghidra_output.json");

        let binary_abs = std::fs::canonicalize(binary_path).map_err(|e| {
            anyhow::anyhow!(
                "Cannot resolve binary path {}: {}",
                binary_path.display(),
                e
            )
        })?;

        let mut cmd = tokio::process::Command::new(&headless);
        cmd.args([
            project_dir
                .path()
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF-8 path"))?,
            "SkwaqProject",
            "-import",
            binary_abs
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF-8 binary path"))?,
            "-postScript",
            "extract_analysis.py",
            output_file
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF-8 output path"))?,
            "-scriptPath",
            scripts_dir
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF-8 scripts path"))?,
            "-analysisTimeoutPerFile",
            &timeout_secs.to_string(),
            "-deleteProject", // Clean up Ghidra project files automatically
        ]);

        let _output = run_tool(
            &mut cmd,
            "Ghidra",
            Duration::from_secs(timeout_secs + 60), // Extra buffer beyond analysis timeout
            Some(project_dir.path()),
        )
        .await?;

        // Parse the JSON output from the post-script
        if output_file.exists() {
            let data = tokio::fs::read_to_string(&output_file).await?;
            let raw: serde_json::Value = serde_json::from_str(&data)?;
            let analysis = parse_ghidra_json(&raw)?;
            Ok(analysis)
        } else {
            anyhow::bail!(
                "Ghidra analysis completed but no output file was produced. \
                 Check that extract_analysis.py ran correctly."
            )
        }
    }
}

fn default_cache_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".skwaq")
        .join("cache")
        .join("ghidra")
}

fn ghidra_cache_locks() -> &'static Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_for_cache_key(cache_key: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = ghidra_cache_locks()
        .lock()
        .expect("ghidra cache lock registry poisoned");
    locks
        .entry(cache_key.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// Load validated Ghidra analysis for a binary, preferring cached results.
///
/// Returns a cached analysis when a bounded, validated cache entry exists for
/// the current binary contents. Otherwise, if Ghidra is installed, runs a fresh
/// Ghidra analysis with the provided timeout and caches the result.
pub async fn load_cached_or_analyze(binary_path: &Path, timeout_secs: u64) -> GhidraLoadOutcome {
    let cache = AnalysisCache::new(default_cache_dir());
    load_cached_or_analyze_with_cache(binary_path, &cache, timeout_secs).await
}

async fn load_cached_or_analyze_with_cache(
    binary_path: &Path,
    cache: &AnalysisCache,
    timeout_secs: u64,
) -> GhidraLoadOutcome {
    if let Some(cached_json) = cache.get_json(binary_path, MAX_GHIDRA_CACHE_BYTES) {
        match parse_ghidra_json(&cached_json) {
            Ok(cached) => return GhidraLoadOutcome::Cached(cached),
            Err(e) => {
                tracing::warn!(
                    "Ignoring invalid cached Ghidra analysis for {}: {}",
                    binary_path.display(),
                    e
                );
            }
        }
    }

    let Some(cache_key) = cache.cache_key(binary_path) else {
        return GhidraLoadOutcome::Failed("Cannot hash binary".to_string());
    };
    let cache_lock = lock_for_cache_key(&cache_key);
    let _guard = cache_lock.lock().await;

    if let Some(cached_json) = cache.get_json(binary_path, MAX_GHIDRA_CACHE_BYTES) {
        match parse_ghidra_json(&cached_json) {
            Ok(cached) => return GhidraLoadOutcome::Cached(cached),
            Err(e) => {
                tracing::warn!(
                    "Ignoring invalid cached Ghidra analysis for {} after lock acquisition: {}",
                    binary_path.display(),
                    e
                );
            }
        }
    }

    let Some(ghidra_path) = GhidraRunner::find_ghidra() else {
        return GhidraLoadOutcome::NotAvailable;
    };

    let runner = GhidraRunner::new(Some(ghidra_path));
    match runner.analyze(binary_path, timeout_secs).await {
        Ok(analysis) => {
            if let Err(e) = cache.put(binary_path, &analysis) {
                tracing::warn!("Failed to cache Ghidra results: {}", e);
            }
            GhidraLoadOutcome::Fresh(analysis)
        }
        Err(e) => GhidraLoadOutcome::Failed(e.to_string()),
    }
}

/// Maximum number of functions to parse from Ghidra output to prevent
/// resource exhaustion from maliciously crafted binaries.
const MAX_GHIDRA_FUNCTIONS: usize = 50_000;
const MAX_GHIDRA_STRINGS: usize = 200_000;
const MAX_GHIDRA_IMPORTS: usize = 50_000;
const MAX_GHIDRA_CACHE_BYTES: u64 = 128 * 1024 * 1024;

/// Parse raw Ghidra JSON output into typed GhidraAnalysis.
///
/// The Python script may produce string offsets (e.g. "00401234") instead of
/// numeric offsets. This function handles both formats.
///
/// Enforces a limit of [`MAX_GHIDRA_FUNCTIONS`] to prevent resource exhaustion.
fn parse_ghidra_json(raw: &serde_json::Value) -> anyhow::Result<GhidraAnalysis> {
    let raw_functions = raw.get("functions").and_then(|v| v.as_array());
    if let Some(arr) = raw_functions {
        if arr.len() > MAX_GHIDRA_FUNCTIONS {
            anyhow::bail!(
                "Ghidra output contains {} functions, exceeding the {} limit. \
                 This may indicate a maliciously crafted binary.",
                arr.len(),
                MAX_GHIDRA_FUNCTIONS,
            );
        }
    }
    if let Some(arr) = raw.get("strings").and_then(|v| v.as_array()) {
        if arr.len() > MAX_GHIDRA_STRINGS {
            anyhow::bail!(
                "Ghidra output contains {} strings, exceeding the {} limit. \
                 This may indicate a maliciously crafted binary.",
                arr.len(),
                MAX_GHIDRA_STRINGS,
            );
        }
    }
    if let Some(arr) = raw.get("imports").and_then(|v| v.as_array()) {
        if arr.len() > MAX_GHIDRA_IMPORTS {
            anyhow::bail!(
                "Ghidra output contains {} imports, exceeding the {} limit. \
                 This may indicate a maliciously crafted binary.",
                arr.len(),
                MAX_GHIDRA_IMPORTS,
            );
        }
    }

    let functions: Vec<GhidraFunction> = raw
        .get("functions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|f| {
                    Some(GhidraFunction {
                        name: f.get("name")?.as_str()?.to_string(),
                        address: f.get("address")?.as_str()?.to_string(),
                        size: f.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
                        decompiled: f
                            .get("decompiled")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        calls: f
                            .get("calls")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        called_by: f
                            .get("called_by")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        parameter_count: f
                            .get("parameter_count")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as u32,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let strings: Vec<ExtractedString> = raw
        .get("strings")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| {
                    let value = s.get("value")?.as_str()?.to_string();
                    // offset may be a hex string (from Ghidra addresses) or a number
                    let offset = s
                        .get("offset")
                        .map(|v| {
                            if let Some(n) = v.as_u64() {
                                n
                            } else if let Some(s) = v.as_str() {
                                // Parse hex address like "00401234"
                                u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0)
                            } else {
                                0
                            }
                        })
                        .unwrap_or(0);
                    let encoding = s
                        .get("encoding")
                        .and_then(|v| v.as_str())
                        .map(|e| match e {
                            "utf16le" | "utf16" => StringEncoding::Utf16Le,
                            "ascii" => StringEncoding::Ascii,
                            _ => StringEncoding::Utf8,
                        })
                        .unwrap_or(StringEncoding::Utf8);
                    Some(ExtractedString {
                        value,
                        offset,
                        encoding,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let imports: Vec<ImportInfo> = raw
        .get("imports")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|i| {
                    Some(ImportInfo {
                        name: i.get("name")?.as_str()?.to_string(),
                        library: i
                            .get("library")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let analysis = GhidraAnalysis {
        functions,
        strings,
        imports,
    };
    validate_ghidra_analysis(&analysis)?;
    Ok(analysis)
}

fn validate_ghidra_analysis(analysis: &GhidraAnalysis) -> anyhow::Result<()> {
    if analysis.functions.len() > MAX_GHIDRA_FUNCTIONS {
        anyhow::bail!(
            "Ghidra analysis contains {} functions, exceeding the {} limit. \
             This may indicate a malicious or corrupted analysis payload.",
            analysis.functions.len(),
            MAX_GHIDRA_FUNCTIONS,
        );
    }
    if analysis.strings.len() > MAX_GHIDRA_STRINGS {
        anyhow::bail!(
            "Ghidra analysis contains {} strings, exceeding the {} limit. \
             This may indicate a malicious or corrupted analysis payload.",
            analysis.strings.len(),
            MAX_GHIDRA_STRINGS,
        );
    }
    if analysis.imports.len() > MAX_GHIDRA_IMPORTS {
        anyhow::bail!(
            "Ghidra analysis contains {} imports, exceeding the {} limit. \
             This may indicate a malicious or corrupted analysis payload.",
            analysis.imports.len(),
            MAX_GHIDRA_IMPORTS,
        );
    }
    Ok(())
}

#[async_trait]
impl SubprocessTool for GhidraRunner {
    fn name(&self) -> &str {
        "Ghidra"
    }

    async fn health_check(&self) -> ToolHealth {
        match Self::find_ghidra() {
            Some(path) => {
                let headless_str = path.join("support/analyzeHeadless");
                let version = get_version(headless_str.to_str().unwrap_or(""), &[]).await;
                ToolHealth {
                    available: true,
                    version,
                    path: Some(path.to_string_lossy().to_string()),
                    error: None,
                }
            }
            None => ToolHealth {
                available: false,
                version: None,
                path: None,
                error: Some("Ghidra not found".into()),
            },
        }
    }

    fn default_timeout(&self) -> Duration {
        Duration::from_secs(600)
    }

    fn install_hint(&self) -> &str {
        "Download from https://ghidra-sre.org/ and set GHIDRA_INSTALL_DIR"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::tempdir;

    #[test]
    fn test_find_ghidra_respects_env() {
        // If GHIDRA_INSTALL_DIR is set to a valid path, find_ghidra should return it
        let existing = std::env::var("GHIDRA_INSTALL_DIR").ok();
        // Test with invalid path - should not find it via env
        std::env::set_var("GHIDRA_INSTALL_DIR", "/nonexistent/ghidra");
        // find_ghidra may still find it at /opt/ghidra etc, so we just ensure it doesn't crash
        let _ = GhidraRunner::find_ghidra();
        // Restore
        if let Some(val) = existing {
            std::env::set_var("GHIDRA_INSTALL_DIR", val);
        } else {
            std::env::remove_var("GHIDRA_INSTALL_DIR");
        }
    }

    #[test]
    fn test_parse_ghidra_json_minimal() {
        let json = serde_json::json!({
            "functions": [
                {
                    "name": "main",
                    "address": "00401000",
                    "size": 42,
                    "decompiled": "int main(int argc, char **argv) { return 0; }",
                    "calls": ["00401100"],
                    "called_by": [],
                    "parameter_count": 2
                }
            ],
            "strings": [
                {
                    "value": "/bin/sh",
                    "offset": "00402000",
                    "encoding": "ascii"
                }
            ],
            "imports": [
                {
                    "name": "system",
                    "library": "libc.so.6"
                }
            ]
        });

        let analysis = parse_ghidra_json(&json).unwrap();
        assert_eq!(analysis.functions.len(), 1);
        assert_eq!(analysis.functions[0].name, "main");
        assert_eq!(
            analysis.functions[0].decompiled.as_deref(),
            Some("int main(int argc, char **argv) { return 0; }")
        );
        assert_eq!(analysis.functions[0].calls.len(), 1);
        assert_eq!(analysis.strings.len(), 1);
        assert_eq!(analysis.strings[0].value, "/bin/sh");
        assert_eq!(analysis.imports.len(), 1);
        assert_eq!(analysis.imports[0].name, "system");
    }

    #[test]
    fn test_parse_ghidra_json_empty() {
        let json = serde_json::json!({
            "functions": [],
            "strings": [],
            "imports": []
        });
        let analysis = parse_ghidra_json(&json).unwrap();
        assert!(analysis.functions.is_empty());
        assert!(analysis.strings.is_empty());
        assert!(analysis.imports.is_empty());
    }

    #[test]
    fn test_parse_ghidra_json_numeric_offset() {
        let json = serde_json::json!({
            "functions": [],
            "strings": [{"value": "hello", "offset": 12345, "encoding": "utf8"}],
            "imports": []
        });
        let analysis = parse_ghidra_json(&json).unwrap();
        assert_eq!(analysis.strings[0].offset, 12345);
    }

    #[test]
    fn test_parse_ghidra_json_rejects_excessive_functions() {
        // Build a JSON payload with more than MAX_GHIDRA_FUNCTIONS entries.
        let count = MAX_GHIDRA_FUNCTIONS + 1;
        let functions: Vec<serde_json::Value> = (0..count)
            .map(|i| {
                serde_json::json!({
                    "name": format!("func_{}", i),
                    "address": format!("{:08x}", i),
                    "size": 10,
                })
            })
            .collect();
        let json = serde_json::json!({
            "functions": functions,
            "strings": [],
            "imports": []
        });
        let result = parse_ghidra_json(&json);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("exceeding"),
            "Error should mention exceeding limit: {err_msg}"
        );
    }

    #[test]
    fn test_validate_ghidra_analysis_rejects_excessive_cached_functions() {
        let analysis = GhidraAnalysis {
            functions: (0..=MAX_GHIDRA_FUNCTIONS)
                .map(|i| GhidraFunction {
                    name: format!("func_{i}"),
                    address: format!("{i:08x}"),
                    size: 1,
                    decompiled: None,
                    calls: vec![],
                    called_by: vec![],
                    parameter_count: 0,
                })
                .collect(),
            strings: vec![],
            imports: vec![],
        };

        let err = validate_ghidra_analysis(&analysis).unwrap_err().to_string();
        assert!(
            err.contains("exceeding"),
            "Error should mention exceeding limit: {err}"
        );
    }

    #[tokio::test]
    async fn test_load_cached_or_analyze_prefers_cache() {
        let temp = tempdir().unwrap();
        let binary_path = temp.path().join("sample.bin");
        std::fs::write(&binary_path, b"not-a-real-binary").unwrap();

        let cache = AnalysisCache::new(temp.path().join("cache"));
        let analysis = GhidraAnalysis {
            functions: vec![GhidraFunction {
                name: "main".into(),
                address: "00401000".into(),
                size: 16,
                decompiled: Some("int main(void) { return 0; }".into()),
                calls: vec![],
                called_by: vec![],
                parameter_count: 0,
            }],
            strings: vec![],
            imports: vec![],
        };
        cache.put(&binary_path, &analysis).unwrap();

        let outcome = load_cached_or_analyze_with_cache(&binary_path, &cache, 1).await;
        match outcome {
            GhidraLoadOutcome::Cached(cached) => {
                assert_eq!(cached.functions.len(), 1);
                assert_eq!(cached.functions[0].name, "main");
            }
            other => panic!("expected cached analysis, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_load_cached_or_analyze_misses_cache_after_binary_change() {
        let temp = tempdir().unwrap();
        let binary_path = temp.path().join("sample.bin");
        std::fs::write(&binary_path, b"version-1").unwrap();

        let cache = AnalysisCache::new(temp.path().join("cache"));
        let analysis = GhidraAnalysis {
            functions: vec![GhidraFunction {
                name: "main".into(),
                address: "00401000".into(),
                size: 16,
                decompiled: Some("int main(void) { return 0; }".into()),
                calls: vec![],
                called_by: vec![],
                parameter_count: 0,
            }],
            strings: vec![],
            imports: vec![],
        };
        cache.put(&binary_path, &analysis).unwrap();

        std::fs::write(&binary_path, b"version-2").unwrap();

        let outcome = load_cached_or_analyze_with_cache(&binary_path, &cache, 1).await;
        assert!(
            !matches!(outcome, GhidraLoadOutcome::Cached(_)),
            "binary content changed, so the content-addressed cache should miss"
        );
    }

    #[tokio::test]
    async fn test_cache_lock_serializes_same_binary_work() {
        let temp = tempdir().unwrap();
        let binary_path = temp.path().join("sample.bin");
        std::fs::write(&binary_path, b"binary").unwrap();
        let cache = AnalysisCache::new(temp.path().join("cache"));

        let cache_key = cache.cache_key(&binary_path).unwrap();
        let lock = lock_for_cache_key(&cache_key);
        let guard = lock.lock().await;

        let acquired = Arc::new(AtomicUsize::new(0));
        let acquired_clone = Arc::clone(&acquired);
        let lock_clone = Arc::clone(&lock);
        let waiter = tokio::spawn(async move {
            let _guard = lock_clone.lock().await;
            acquired_clone.fetch_add(1, Ordering::SeqCst);
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(acquired.load(Ordering::SeqCst), 0);
        drop(guard);
        waiter.await.unwrap();
        assert_eq!(acquired.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_load_cached_or_analyze_ignores_invalid_cache_payload() {
        let temp = tempdir().unwrap();
        let binary_path = temp.path().join("sample.bin");
        std::fs::write(&binary_path, b"version-1").unwrap();

        let cache = AnalysisCache::new(temp.path().join("cache"));
        let data = std::fs::read(&binary_path).unwrap();
        let hash = format!("{:x}", Sha256::digest(&data));
        let dir = temp.path().join("cache").join(hash);
        std::fs::create_dir_all(&dir).unwrap();

        let functions: Vec<serde_json::Value> = (0..=MAX_GHIDRA_FUNCTIONS)
            .map(|i| {
                serde_json::json!({
                    "name": format!("func_{}", i),
                    "address": format!("{:08x}", i),
                    "size": 1,
                    "decompiled": null,
                    "calls": [],
                    "called_by": [],
                    "parameter_count": 0
                })
            })
            .collect();
        std::fs::write(
            dir.join("analysis.json"),
            serde_json::json!({
                "functions": functions,
                "strings": [],
                "imports": []
            })
            .to_string(),
        )
        .unwrap();

        let outcome = load_cached_or_analyze_with_cache(&binary_path, &cache, 1).await;
        assert!(
            !matches!(outcome, GhidraLoadOutcome::Cached(_)),
            "invalid cached analysis should not be trusted"
        );
    }
}
