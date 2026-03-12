//! `skwaq doctor` - check system dependencies and connectivity.

use skwaq_core::binary::subprocess::{command_exists, get_version};
use skwaq_core::config::Config;

/// Run all health checks and print a summary.
pub async fn run() -> anyhow::Result<()> {
    println!("skwaq doctor — checking system dependencies\n");

    let config = Config::load().unwrap_or_default();
    let mut all_ok = true;

    // Ghidra
    let ghidra_ok = check_ghidra(&config).await;
    all_ok &= ghidra_ok;

    // Python
    let python_ok = check_python().await;
    all_ok &= python_ok;

    // Semgrep
    let semgrep_ok = check_semgrep().await;
    all_ok &= semgrep_ok;

    // GCC/compilation tools
    let gcc_ok = check_gcc().await;
    all_ok &= gcc_ok;

    // AFL++ (fuzzing)
    let afl_ok = check_afl().await;
    // AFL is optional, don't fail overall
    let _ = afl_ok;

    // GhidraMCP server
    let mcp_ok = check_ghidra_mcp().await;
    let _ = mcp_ok; // Optional

    // Database directory
    let db_ok = check_database(&config);
    all_ok &= db_ok;

    // LLM configuration
    let llm_ok = check_llm(&config).await;
    let _ = llm_ok; // Optional but recommended

    println!();
    if all_ok {
        println!("All required checks passed.");
    } else {
        println!("Some required checks failed. See above for details.");
    }

    Ok(())
}

async fn check_ghidra(config: &Config) -> bool {
    print!("  Ghidra .............. ");

    // Check configured path first, then PATH
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
        println!("NOT FOUND");
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
        println!("NOT FOUND");
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
        println!("NOT FOUND");
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
        println!("NOT FOUND");
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
        println!("NOT FOUND (optional — needed for `skwaq fuzz`)");
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
        println!("NOT FOUND (optional — needed for MCP-based investigation)");
        println!("    Install: https://github.com/cyberkaida/reverse-engineering-assistant");
        false
    }
}

async fn check_llm(config: &Config) -> bool {
    print!("  LLM configuration ... ");
    if std::env::var("ANTHROPIC_API_KEY").is_ok() {
        println!("OK (Anthropic API key found)");
        return true;
    }
    if std::env::var("GITHUB_TOKEN").is_ok() || std::env::var("GH_TOKEN").is_ok() {
        println!("OK (GitHub token found for Copilot Models)");
        return true;
    }
    if !config.llm.reasoning.is_empty() && config.llm.reasoning != "auto" {
        println!("OK (configured: {})", config.llm.reasoning);
        return true;
    }
    println!("NOT CONFIGURED (optional — needed for AI agent analysis)");
    println!("    Set ANTHROPIC_API_KEY or GITHUB_TOKEN environment variable");
    false
}

fn check_database(config: &Config) -> bool {
    print!("  Database path ....... ");
    let db_path = config.database_path();
    if db_path.exists() {
        println!("OK ({db_path:?})");
        true
    } else {
        println!("OK (will create at {db_path:?})");
        // Not an error - will be created on first use
        true
    }
}
