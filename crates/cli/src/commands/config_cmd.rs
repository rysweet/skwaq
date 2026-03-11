//! `skwaq config` - configuration management.

pub fn run_show() -> anyhow::Result<()> {
    let config = skwaq_core::config::Config::load()?;

    println!("skwaq configuration:\n");

    println!("[general]");
    println!("  database_path     = {}", config.general.database_path);
    println!("  cache_path        = {}", config.general.cache_path);
    println!("  log_level         = {}", config.general.log_level);

    println!("\n[llm]");
    println!("  reasoning         = {}", config.llm.reasoning);
    println!("  decompilation     = {}", config.llm.decompilation);
    println!("  embeddings        = {}", config.llm.embeddings);

    println!("\n[llm.copilot]");
    println!("  model             = {}", config.llm.copilot.model);

    println!("\n[llm.ollama]");
    println!("  host              = {}", config.llm.ollama.host);
    println!("  model             = {}", config.llm.ollama.model);
    println!(
        "  embedding_model   = {}",
        config.llm.ollama.embedding_model
    );

    println!("\n[binary]");
    let ghidra = if config.binary.ghidra_path.is_empty() {
        "(not set)"
    } else {
        &config.binary.ghidra_path
    };
    println!("  ghidra_path       = {}", ghidra);
    println!("  default_timeout   = {}s", config.binary.default_timeout);
    println!("  enable_cache      = {}", config.binary.enable_cache);

    println!("\n[analysis]");
    println!(
        "  max_taint_depth       = {}",
        config.analysis.max_taint_depth
    );
    println!(
        "  false_positive_target = {}",
        config.analysis.false_positive_target
    );
    println!(
        "  default_token_budget  = {}",
        config.analysis.default_token_budget
    );

    println!("\n[output]");
    println!("  default_format    = {}", config.output.default_format);

    // Show config file location
    let candidates = ["skwaq.toml", ".skwaq/config.toml"];
    let found = candidates.iter().find(|p| std::path::Path::new(p).exists());
    match found {
        Some(path) => println!("\nLoaded from: {path}"),
        None => println!("\nUsing defaults (no skwaq.toml found)"),
    }

    Ok(())
}
