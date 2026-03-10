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

    // Database directory
    let db_ok = check_database(&config);
    all_ok &= db_ok;

    println!();
    if all_ok {
        println!("All checks passed.");
    } else {
        println!("Some checks failed. See above for details.");
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
