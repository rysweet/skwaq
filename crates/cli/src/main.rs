//! skwaq CLI entry point.

use clap::Parser;
use opentelemetry::trace::TracerProvider as _;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer as _;

use skwaq::commands::{Cli, Commands};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Set up tracing based on verbosity
    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    // Initialize OTEL tracer provider for span export (Tier 1: file exporter)
    let telemetry_dir = skwaq_gym::telemetry::default_telemetry_dir();
    let otel_provider = skwaq_gym::telemetry::init_tracer_provider(&telemetry_dir, None).ok();

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter));

    if let Some(provider) = otel_provider {
        // With OTEL: fmt layer (respects verbosity) + OTEL layer (always captures info+ spans)
        let otel_layer = tracing_opentelemetry::layer().with_tracer(provider.tracer("skwaq"));
        let otel_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_filter(env_filter))
            .with(otel_layer.with_filter(otel_filter))
            .init();
    } else {
        // Without OTEL: fmt only (graceful degradation if telemetry dir fails)
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }

    match &cli.command {
        Commands::Gym { sub } => {
            skwaq::commands::gym_cmd::run(sub).await?;
        }
        Commands::Memory { sub } => {
            skwaq::commands::memory_cmd::run(sub)?;
        }
        Commands::Version => {
            skwaq::commands::version_cmd::run();
        }
        Commands::InvestigateBinary { binary } => {
            skwaq::commands::investigate_binary::run(binary).await?;
        }
        Commands::Fuzz {
            binary,
            duration,
            corpus,
            output,
        } => {
            skwaq::commands::fuzz_cmd::run_fuzz(
                binary,
                *duration,
                corpus.as_deref(),
                output.as_deref(),
            )
            .await?;
        }
        Commands::FuzzAnalyze { binary, duration } => {
            skwaq::commands::fuzz_cmd::run_fuzz_analyze(binary, *duration).await?;
        }
        Commands::DiffAnalyze { v1, v2, advisory } => {
            skwaq::commands::diff_analyze::run(v1, v2, advisory.as_deref()).await?;
        }
        Commands::Doctor => {
            skwaq::commands::doctor::run().await?;
        }
        Commands::SelfTest => {
            skwaq::commands::selftest_cmd::run()?;
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
            skwaq::commands::ingest::run(sub).await?;
        }
        Commands::Analyze {
            investigation,
            quick,
            budget,
            agents,
            agent,
        } => {
            skwaq::commands::analyze::run(
                investigation.as_deref(),
                *quick,
                *budget,
                agents.as_deref(),
                agent.as_deref(),
            )
            .await?;
        }
        Commands::Agents { sub } => {
            use skwaq::commands::AgentsSub;
            match sub {
                AgentsSub::List => {
                    skwaq::commands::agents_cmd::run_list();
                }
            }
        }
        Commands::Skills { sub } => {
            use skwaq::commands::SkillsSub;
            match sub {
                SkillsSub::List => {
                    skwaq::commands::skills_cmd::run_list();
                }
                SkillsSub::Run { name, args } => {
                    skwaq::commands::skills_cmd::run_run(name, args.clone()).await?;
                }
            }
        }
        Commands::Investigate { sub } => {
            skwaq::commands::investigate::run(sub)?;
        }
        Commands::Decompile { binary: _ } => {
            anyhow::bail!(
                "Decompilation requires Ghidra to be installed and configured.\n\
                 Run `skwaq doctor` to check if Ghidra is available.\n\
                 Configure the path with: skwaq config set binary.ghidra_path /path/to/ghidra"
            );
        }
        Commands::Disassemble { binary: _ } => {
            anyhow::bail!(
                "Disassembly requires Ghidra to be installed and configured.\n\
                 Run `skwaq doctor` to check if Ghidra is available.\n\
                 Configure the path with: skwaq config set binary.ghidra_path /path/to/ghidra"
            );
        }
        Commands::Xrefs { function } => {
            skwaq::commands::xrefs_cmd::run(function)?;
        }
        Commands::Surface => {
            skwaq::commands::surface_cmd::run()?;
        }
        Commands::Taint { source, sink } => {
            skwaq::commands::taint_cmd::run(source.as_deref(), sink.as_deref())?;
        }
        Commands::FindSimilar { function: _ } => {
            anyhow::bail!(
                "Function similarity search requires LLM configuration.\n\
                 Run `skwaq config show` to check current settings."
            );
        }
        Commands::Annotate { target, text } => {
            skwaq::commands::annotate_cmd::run(target, text)?;
        }
        Commands::Hypothesize { focus } => {
            skwaq::commands::hypothesize_cmd::run(focus.as_deref())?;
        }
        Commands::Report {
            investigation_id,
            sarif,
            json,
            markdown,
            output,
        } => {
            skwaq::commands::report::run(
                investigation_id.as_deref(),
                *json,
                *sarif,
                *markdown,
                output.as_ref(),
            )?;
        }
        Commands::Viz { sub } => {
            use skwaq::commands::VizSub;
            match sub {
                VizSub::Callgraph { function } => {
                    skwaq::commands::viz_cmd::run_callgraph(function.as_deref())?;
                }
                VizSub::Taint => {
                    skwaq::commands::taint_cmd::run(None, None)?;
                }
                VizSub::Decompile { function: _ } => {
                    anyhow::bail!(
                        "Decompilation view requires Ghidra.\n\
                         Run `skwaq doctor` to check if Ghidra is available."
                    );
                }
                VizSub::Findings => {
                    skwaq::commands::viz_cmd::run_findings()?;
                }
            }
        }
        Commands::Kb { sub } => {
            use skwaq::commands::KbSub;
            match sub {
                KbSub::Init => {
                    skwaq::commands::kb_cmd::run_init()?;
                }
                KbSub::Search { query, json } => {
                    skwaq::commands::kb_cmd::run_search(query, *json)?;
                }
            }
        }
        Commands::Config { sub } => {
            use skwaq::commands::ConfigSub;
            match sub {
                ConfigSub::Show => {
                    skwaq::commands::config_cmd::run_show()?;
                }
                ConfigSub::Set { key: _, value: _ } => {
                    anyhow::bail!("Config writing not implemented. Edit skwaq.toml directly.");
                }
            }
        }
    }

    Ok(())
}
