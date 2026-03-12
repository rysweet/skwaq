//! `skwaq doctor` - check system dependencies and connectivity.
//!
//! All dependencies are required. Missing tools cause errors, not warnings.

use skwaq_core::binary::subprocess::{command_exists, get_version};
use skwaq_core::config::Config;

/// Run all health checks and print a summary.
/// Returns error if any dependency is missing.
pub async fn run() -> anyhow::Result<()> {
    println!("skwaq doctor — checking system dependencies\n");

    let config = Config::load().unwrap_or_default();
    let mut all_ok = true;

    all_ok &= check_ghidra(&config).await;
    all_ok &= check_python().await;
    all_ok &= check_semgrep().await;
    all_ok &= check_gcc().await;
    all_ok &= check_afl().await;
    all_ok &= check_ghidra_mcp().await;
    all_ok &= check_database(&config);
    all_ok &= check_llm(&config).await;

    println!();
    if all_ok {
        println!("All checks passed.");
    } else {
        anyhow::bail!("Missing required dependencies. Install them and run `skwaq doctor` again.");
    }

    Ok(())
}

/// Check required dependencies at startup.
/// Returns Ok(()) if all required tools are present, Err with details otherwise.
pub async fn check_required_deps() -> anyhow::Result<()> {
    let mut missing = Vec::new();

    if !gcc_available().await {
        missing.push("gcc (sudo apt install gcc)");
    }

    if !llm_available().await {
        missing.push("LLM (set ANTHROPIC_API_KEY or GITHUB_TOKEN)");
    }

    if !missing.is_empty() {
        anyhow::bail!(
            "Missing required dependencies:\n{}",
            missing
                .iter()
                .map(|m| format!("  - {}", m))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    Ok(())
}

async fn gcc_available() -> bool {
    get_version("gcc", &["--version"]).await.is_some()
}

async fn llm_available() -> bool {
    std::env::var("ANTHROPIC_API_KEY").is_ok()
        || std::env::var("GITHUB_TOKEN").is_ok()
        || std::env::var("GH_TOKEN").is_ok()
}

async fn check_ghidra(config: &Config) -> bool {
    print!("  Ghidra .............. ");
    if !config.binary.ghidra_path.is_empty() {
        let analyze = std::path::Path::new(&config.binary.ghidra_path).join("analyzeHeadless");
        if analyze.exists() {
            println!("OK ({})", config.binary.ghidra_path);
            return true;
        }
    }
    if let Some(path) = command_exists("analyzeHeadless").await {
        println!("OK ({path})");
        true
    } else {
        println!("MISSING");
        println!("    Install: https://ghidra-sre.org/");
        println!("    Or set binary.ghidra_path in skwaq.toml");
        false
    }
}

async fn check_python() -> bool {
    print!("  Python 3 ........... ");
    if let Some(version) = get_version("python3", &["--version"]).await {
        println!("OK ({version})");
        true
    } else if let Some(version) = get_version("python", &["--version"]).await {
        if version.contains('3') {
            println!("OK ({version})");
            true
        } else {
            println!("WRONG VERSION ({version}, need 3.x)");
            false
        }
    } else {
        println!("MISSING");
        println!("    Install: https://www.python.org/downloads/");
        false
    }
}

async fn check_semgrep() -> bool {
    print!("  Semgrep ............. ");
    if let Some(version) = get_version("semgrep", &["--version"]).await {
        println!("OK ({version})");
        true
    } else {
        println!("MISSING");
        println!("    Install: pip install semgrep");
        false
    }
}

async fn check_gcc() -> bool {
    print!("  GCC ................. ");
    if let Some(version) = get_version("gcc", &["--version"]).await {
        let first_line = version.lines().next().unwrap_or(&version);
        println!("OK ({})", first_line);
        true
    } else {
        println!("MISSING");
        println!("    Install: sudo apt install gcc (Ubuntu) or brew install gcc (macOS)");
        false
    }
}

async fn check_afl() -> bool {
    print!("  AFL++ (fuzzing) ..... ");
    if let Some(version) = get_version("afl-fuzz", &["--version"]).await {
        let first_line = version.lines().next().unwrap_or(&version);
        println!("OK ({})", first_line);
        true
    } else {
        println!("MISSING");
        println!("    Install: sudo apt install afl++ (Ubuntu)");
        println!("    Or: cargo install afl");
        false
    }
}

async fn check_ghidra_mcp() -> bool {
    print!("  GhidraMCP server .... ");
    if command_exists("ghidra-mcp-server").await.is_some() {
        println!("OK");
        true
    } else {
        println!("MISSING");
        println!("    Install: https://github.com/cyberkaida/reverse-engineering-assistant");
        false
    }
}

async fn check_llm(_config: &Config) -> bool {
    print!("  LLM configuration ... ");
    if std::env::var("ANTHROPIC_API_KEY").is_ok() {
        println!("OK (Anthropic API key found)");
        return true;
    }
    if std::env::var("GITHUB_TOKEN").is_ok() || std::env::var("GH_TOKEN").is_ok() {
        println!("OK (GitHub token found for Copilot Models)");
        return true;
    }
    println!("MISSING");
    println!("    Set ANTHROPIC_API_KEY or GITHUB_TOKEN environment variable");
    false
}

fn check_database(config: &Config) -> bool {
    print!("  Database path ....... ");
    let db_path = config.database_path();
    if db_path.exists() {
        println!("OK ({db_path:?})");
    } else {
        println!("OK (will create at {db_path:?})");
    }
    true
}
