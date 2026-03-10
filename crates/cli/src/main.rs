//! skwaq CLI entry point.

use clap::Parser;
use tracing_subscriber::EnvFilter;

use skwaq::commands::{Cli, Commands};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Set up tracing based on verbosity
    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .init();

    match &cli.command {
        Commands::Version => {
            skwaq::commands::version_cmd::run();
        }
        Commands::Doctor => {
            skwaq::commands::doctor::run().await?;
        }
        Commands::Checksec { binary } => {
            skwaq::commands::checksec_cmd::run(binary)?;
        }
        Commands::Strings { binary, min_length } => {
            skwaq::commands::strings_cmd::run(binary, *min_length)?;
        }
        Commands::Symbols { binary } => {
            skwaq::commands::symbols_cmd::run(binary)?;
        }
        Commands::Ingest { sub } => {
            skwaq::commands::ingest::run(sub)?;
        }
        Commands::Analyze { investigation, quick, budget } => {
            skwaq::commands::analyze::run(investigation.as_deref(), *quick, *budget)?;
        }
        Commands::Investigate { sub } => {
            skwaq::commands::investigate::run(sub)?;
        }
        // Stubs for remaining commands
        Commands::Decompile { binary } => {
            println!("skwaq decompile: coming soon ({})", binary.display());
        }
        Commands::Disassemble { binary } => {
            println!("skwaq disassemble: coming soon ({})", binary.display());
        }
        Commands::Xrefs { function } => {
            println!("skwaq xrefs: coming soon ({function})");
        }
        Commands::Surface => {
            println!("skwaq surface: coming soon");
        }
        Commands::Taint { source, sink } => {
            println!(
                "skwaq taint: coming soon (source={}, sink={})",
                source.as_deref().unwrap_or("auto"),
                sink.as_deref().unwrap_or("auto")
            );
        }
        Commands::FindSimilar { function } => {
            println!("skwaq find-similar: coming soon ({function})");
        }
        Commands::Annotate { target, text } => {
            println!("skwaq annotate: coming soon ({target}: {text})");
        }
        Commands::Hypothesize { focus } => {
            println!(
                "skwaq hypothesize: coming soon ({})",
                focus.as_deref().unwrap_or("all")
            );
        }
        Commands::Report {
            investigation_id,
            sarif,
            json,
            output,
        } => {
            skwaq::commands::report::run(
                investigation_id.as_deref(),
                *json,
                *sarif,
                output.as_ref(),
            )?;
        }
        Commands::Viz { sub } => {
            use skwaq::commands::VizSub;
            match sub {
                VizSub::Callgraph { function } => {
                    println!(
                        "skwaq viz callgraph: coming soon ({})",
                        function.as_deref().unwrap_or("all")
                    );
                }
                VizSub::Taint => println!("skwaq viz taint: coming soon"),
                VizSub::Decompile { function } => {
                    println!("skwaq viz decompile: coming soon ({function})");
                }
                VizSub::Findings => println!("skwaq viz findings: coming soon"),
            }
        }
        Commands::Kb { sub } => {
            use skwaq::commands::KbSub;
            match sub {
                KbSub::Init => println!("skwaq kb init: coming soon"),
                KbSub::Search { query } => {
                    println!("skwaq kb search: coming soon ({query})");
                }
            }
        }
        Commands::Config { sub } => {
            use skwaq::commands::ConfigSub;
            match sub {
                ConfigSub::Show => println!("skwaq config show: coming soon"),
                ConfigSub::Set { key, value } => {
                    println!("skwaq config set: coming soon ({key}={value})");
                }
            }
        }
    }

    Ok(())
}
