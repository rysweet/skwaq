//! `skwaq fuzz` — run a fuzzer on a binary and analyze crash sites.
//!
//! Supports AFL++ (afl-fuzz) and libFuzzer. Collects crashes, extracts
//! crash sites with stack traces, and stores results in the graph DB
//! for AI-powered root cause analysis.

use std::path::{Path, PathBuf};

/// Run a fuzzer on the target binary.
pub async fn run_fuzz(
    binary: &Path,
    duration_secs: u64,
    corpus_dir: Option<&Path>,
    output_dir: Option<&Path>,
) -> anyhow::Result<()> {
    println!("Fuzzing binary: {}", binary.display());
    println!("  Duration: {}s", duration_secs);

    // Verify binary exists
    if !binary.exists() {
        anyhow::bail!("Binary not found: {}", binary.display());
    }

    // Set up directories
    let output = match output_dir {
        Some(d) => d.to_path_buf(),
        None => {
            let dir = PathBuf::from(".skwaq/fuzz").join(
                binary
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "target".to_string()),
            );
            std::fs::create_dir_all(&dir)?;
            dir
        }
    };

    let corpus = match corpus_dir {
        Some(d) => d.to_path_buf(),
        None => {
            let dir = output.join("corpus");
            std::fs::create_dir_all(&dir)?;
            // Create a seed if corpus is empty
            if std::fs::read_dir(&dir)?.count() == 0 {
                std::fs::write(dir.join("seed"), b"AAAA")?;
            }
            dir
        }
    };

    let crashes_dir = output.join("crashes");
    std::fs::create_dir_all(&crashes_dir)?;

    // Try AFL++ first, then libFuzzer
    let fuzzer = detect_fuzzer().await?;
    println!("  Fuzzer: {}", fuzzer);

    let crash_count = match fuzzer.as_str() {
        "afl-fuzz" => run_afl(binary, &corpus, &output, duration_secs).await?,
        "libfuzzer" => run_libfuzzer(binary, &corpus, &crashes_dir, duration_secs).await?,
        _ => anyhow::bail!("No supported fuzzer found"),
    };

    println!("\n  Fuzzing complete: {} crashes found", crash_count);

    if crash_count > 0 {
        // Collect and deduplicate crash info
        let crashes = collect_crashes(&crashes_dir)?;
        println!("  Unique crash sites: {}", crashes.len());

        // Store crash data in investigation
        store_crash_data(binary, &crashes).await?;

        println!("\n  Run `skwaq analyze` on the investigation to analyze crashes with AI.");
        println!(
            "  Or run `skwaq fuzz-analyze {}` for end-to-end analysis.",
            binary.display()
        );
    }

    Ok(())
}

/// Run end-to-end: fuzz → collect crashes → AI analysis.
pub async fn run_fuzz_analyze(binary: &Path, duration_secs: u64) -> anyhow::Result<()> {
    println!(
        "Fuzz-analyze: {} ({}s fuzz, then AI analysis)",
        binary.display(),
        duration_secs
    );

    // Step 1: Fuzz
    let output_dir = PathBuf::from(".skwaq/fuzz").join(
        binary
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "target".to_string()),
    );
    std::fs::create_dir_all(&output_dir)?;

    run_fuzz(binary, duration_secs, None, Some(&output_dir)).await?;

    // Step 2: Collect crashes
    let crashes_dir = output_dir.join("crashes");
    let crashes = collect_crashes(&crashes_dir)?;

    if crashes.is_empty() {
        println!("\nNo crashes found — binary appears robust for this duration.");
        return Ok(());
    }

    // Step 3: AI analysis of each crash
    println!(
        "\nAnalyzing {} crash sites with AI agents...",
        crashes.len()
    );

    let db = skwaq_core::graph::GraphDb::in_memory()?;
    let inv_id = format!("fuzz-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let now = chrono::Utc::now().to_rfc3339();

    db.execute(
        "INSERT INTO investigations (id, name, target, status, created_at, updated_at) \
         VALUES (?1, ?2, ?3, 'active', ?4, ?5)",
        &[
            &inv_id.as_str(),
            &format!("fuzz: {}", binary.display()).as_str(),
            &binary.to_string_lossy().to_string().as_str(),
            &now.as_str(),
            &now.as_str(),
        ],
    )?;

    // Ingest binary into graph
    let binary_info = skwaq_core::binary::native::parse_binary(binary)?;
    let builder = skwaq_core::graph::builder::GraphBuilder::new(&db);
    builder.build_from_binary_info(&binary_info, &inv_id)?;

    // Store crash findings as annotations for the crash-analyst agent
    for crash in &crashes {
        let ann_id = uuid::Uuid::new_v4().to_string();
        let content = format!(
            "CRASH: address={}, signal={}, input_file={}\nStack trace:\n{}",
            crash.address, crash.signal, crash.input_file, crash.stack_trace
        );
        let _ = db.execute(
            "INSERT INTO annotations (id, content, agent, timestamp, investigation_id) \
             VALUES (?1, ?2, 'fuzzer', ?3, ?4)",
            &[
                &ann_id.as_str(),
                &content.as_str(),
                &now.as_str(),
                &inv_id.as_str(),
            ],
        );
    }

    // Run crash-analyst agent
    let config = match skwaq_core::config::Config::load() {
        Ok(c) => c,
        Err(_) => {
            println!("  LLM not configured. Crash data stored but not analyzed.");
            return Ok(());
        }
    };

    let llm_client = match skwaq_core::llm::create_client(&config.llm).await {
        Ok(c) => c,
        Err(e) => {
            println!(
                "  LLM not available ({}). Crash data stored but not analyzed.",
                e
            );
            return Ok(());
        }
    };

    let agent = skwaq_core::agents::definition::load_agent("crash-analyst")?;
    let mut budget =
        skwaq_core::llm::TokenBudget::new(config.analysis.default_token_budget.min(100_000));
    let runner = skwaq_core::agents::runner::AgentRunner::new(llm_client);

    // Build context with crash data
    let mut context = format!(
        "# Fuzzer Crash Analysis for {}\n\n## Crashes Found: {}\n\n",
        binary.display(),
        crashes.len()
    );
    for (i, crash) in crashes.iter().enumerate() {
        context.push_str(&format!(
            "### Crash {} — address: {}, signal: {}\n```\n{}\n```\n\n",
            i + 1,
            crash.address,
            crash.signal,
            crash.stack_trace
        ));
    }
    context.push_str(
        "Analyze each crash site. Use read_function to examine the code at each crash address. \
         Determine the root cause, exploitability, and CWE. Use create_finding for each vulnerability.\n",
    );

    match runner
        .run_agent_with_db(&agent, &inv_id, &context, &db, &mut budget)
        .await
    {
        Ok(result) => {
            println!("\n{}", result.output);
            println!("({} tokens used)", result.tokens_used);
        }
        Err(e) => {
            println!("  Crash analysis failed: {}", e);
        }
    }

    // Print findings
    let mut stmt = db
        .conn()
        .prepare("SELECT title, severity, category FROM findings WHERE investigation_id = ?1")?;
    let findings: Vec<(String, String, String)> = stmt
        .query_map([&inv_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1).unwrap_or_default(),
                row.get::<_, String>(2).unwrap_or_default(),
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    if !findings.is_empty() {
        println!("\n## Vulnerability Findings from Crash Analysis\n");
        for (i, (title, severity, category)) in findings.iter().enumerate() {
            println!(
                "  {}. [{}] {} ({})",
                i + 1,
                severity.to_uppercase(),
                title,
                category
            );
        }
    }

    Ok(())
}

/// Detect which fuzzer is available.
async fn detect_fuzzer() -> anyhow::Result<String> {
    if which_exists("afl-fuzz") {
        return Ok("afl-fuzz".to_string());
    }
    // libFuzzer is typically compiled into the binary, not a separate tool
    // Check for afl-clang-fast as an indicator
    if which_exists("afl-clang-fast") {
        return Ok("afl-fuzz".to_string());
    }
    anyhow::bail!(
        "No fuzzer found. Install AFL++:\n  \
         Ubuntu: sudo apt install afl++\n  \
         Cargo: cargo install afl\n  \
         Or compile your binary with libFuzzer (-fsanitize=fuzzer)"
    )
}

fn which_exists(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run AFL++ fuzzer.
async fn run_afl(
    binary: &Path,
    corpus: &Path,
    output: &Path,
    duration_secs: u64,
) -> anyhow::Result<usize> {
    println!("  Starting AFL++ (timeout: {}s)...", duration_secs);

    let status = tokio::process::Command::new("timeout")
        .args([
            &duration_secs.to_string(),
            "afl-fuzz",
            "-i",
            &corpus.to_string_lossy(),
            "-o",
            &output.to_string_lossy(),
            "-V",
            &duration_secs.to_string(),
            "--",
            &binary.to_string_lossy(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .status()
        .await?;

    // AFL returns non-zero on timeout (expected)
    let _ = status;

    // Count crashes
    let crashes_dir = output.join("default").join("crashes");
    if crashes_dir.exists() {
        let count = std::fs::read_dir(&crashes_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
            .count();
        // Copy crashes to the standard location
        let dest = output.join("crashes");
        std::fs::create_dir_all(&dest)?;
        for entry in std::fs::read_dir(&crashes_dir)? {
            let entry = entry?;
            if !entry.file_name().to_string_lossy().starts_with('.') {
                let _ = std::fs::copy(entry.path(), dest.join(entry.file_name()));
            }
        }
        Ok(count)
    } else {
        Ok(0)
    }
}

/// Run libFuzzer (binary must be compiled with -fsanitize=fuzzer).
async fn run_libfuzzer(
    binary: &Path,
    corpus: &Path,
    crashes_dir: &Path,
    duration_secs: u64,
) -> anyhow::Result<usize> {
    println!("  Starting libFuzzer (timeout: {}s)...", duration_secs);

    let status = tokio::process::Command::new(binary)
        .args([
            &corpus.to_string_lossy().to_string(),
            &format!("-artifact_prefix={}/", crashes_dir.display()),
            &format!("-max_total_time={}", duration_secs),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .status()
        .await?;

    let _ = status;

    let count = std::fs::read_dir(crashes_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("crash-"))
        .count();

    Ok(count)
}

/// A crash site discovered by the fuzzer.
#[derive(Debug, Clone)]
pub struct CrashInfo {
    pub address: String,
    pub signal: String,
    pub stack_trace: String,
    pub input_file: String,
}

/// Collect and deduplicate crashes from the output directory.
fn collect_crashes(crashes_dir: &Path) -> anyhow::Result<Vec<CrashInfo>> {
    let mut crashes = Vec::new();

    if !crashes_dir.exists() {
        return Ok(crashes);
    }

    for entry in std::fs::read_dir(crashes_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && !entry.file_name().to_string_lossy().starts_with('.') {
            crashes.push(CrashInfo {
                address: "unknown".to_string(),
                signal: "SIGSEGV".to_string(),
                stack_trace: format!("Crash input: {}", path.display()),
                input_file: path.to_string_lossy().to_string(),
            });
        }
    }

    Ok(crashes)
}

/// Store crash data in graph DB for later analysis.
async fn store_crash_data(binary: &Path, crashes: &[CrashInfo]) -> anyhow::Result<()> {
    let db = skwaq_core::graph::GraphDb::in_memory()?;
    let inv_id = format!("fuzz-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let now = chrono::Utc::now().to_rfc3339();

    db.execute(
        "INSERT INTO investigations (id, name, target, status, created_at, updated_at) \
         VALUES (?1, ?2, ?3, 'active', ?4, ?5)",
        &[
            &inv_id.as_str(),
            &format!("fuzz: {}", binary.display()).as_str(),
            &binary.to_string_lossy().to_string().as_str(),
            &now.as_str(),
            &now.as_str(),
        ],
    )?;

    for crash in crashes {
        let ann_id = uuid::Uuid::new_v4().to_string();
        let content = format!(
            "CRASH: address={}, signal={}\n{}",
            crash.address, crash.signal, crash.stack_trace
        );
        db.execute(
            "INSERT INTO annotations (id, content, agent, timestamp, investigation_id) \
             VALUES (?1, ?2, 'fuzzer', ?3, ?4)",
            &[
                &ann_id.as_str(),
                &content.as_str(),
                &now.as_str(),
                &inv_id.as_str(),
            ],
        )?;
    }

    Ok(())
}
