//! CLI commands for managing durable agent memory.

use clap::Subcommand;
use skwaq_core::memory::{ExperienceType, MemoryStore};

#[derive(Subcommand)]
pub enum MemorySub {
    /// Show memory statistics for all agents or a specific agent
    Stats {
        /// Agent name (shows all agents if omitted)
        #[arg(long)]
        agent: Option<String>,
    },
    /// List recent memories for an agent
    List {
        /// Agent name
        agent: String,
        /// Maximum number of memories to show
        #[arg(long, default_value = "20")]
        limit: usize,
        /// Filter by type (success, failure, pattern, insight)
        #[arg(long)]
        r#type: Option<String>,
    },
    /// Search memories by keyword
    Search {
        /// Agent name
        agent: String,
        /// Search query
        query: String,
        /// Maximum number of results
        #[arg(long, default_value = "10")]
        limit: usize,
    },
    /// Apply confidence decay and prune expired memories
    Decay,
    /// Clear all memories for an agent
    Clear {
        /// Agent name
        agent: String,
    },
    /// Detect and promote patterns from agent experiences
    DetectPatterns {
        /// Agent name
        agent: String,
    },
}

pub fn run(sub: &MemorySub) -> anyhow::Result<()> {
    let store = MemoryStore::open_default()?;

    match sub {
        MemorySub::Stats { agent } => match agent {
            Some(name) => {
                let stats = store.statistics(name)?;
                println!("Memory statistics for agent '{name}':");
                println!("  Total:      {}", stats.total_experiences);
                println!("  Successes:  {}", stats.successes);
                println!("  Failures:   {}", stats.failures);
                println!("  Patterns:   {}", stats.patterns);
                println!("  Insights:   {}", stats.insights);
                println!("  Avg conf:   {:.2}", stats.avg_confidence);
            }
            None => {
                let stats = store.global_statistics()?;
                println!("Global memory statistics:");
                println!("  Total:      {}", stats.total_experiences);
                println!("  Successes:  {}", stats.successes);
                println!("  Failures:   {}", stats.failures);
                println!("  Patterns:   {}", stats.patterns);
                println!("  Insights:   {}", stats.insights);
                println!("  Avg conf:   {:.2}", stats.avg_confidence);
            }
        },
        MemorySub::List {
            agent,
            limit,
            r#type,
        } => {
            let exp_type = r#type.as_deref().and_then(ExperienceType::from_str);

            let experiences = store.recall_recent(agent, *limit, exp_type)?;

            if experiences.is_empty() {
                println!("No memories found for agent '{agent}'.");
                return Ok(());
            }

            println!(
                "Memories for agent '{}' ({} found):\n",
                agent,
                experiences.len()
            );
            for exp in &experiences {
                println!("  [{:>8}] {}", exp.experience_type.as_str(), exp.id);
                println!("    Context:    {}", truncate(&exp.context, 80));
                println!("    Outcome:    {}", truncate(&exp.outcome, 80));
                println!(
                    "    Confidence: {:.2}  Recalled: {}  Tags: {:?}",
                    exp.confidence, exp.recall_count, exp.tags
                );
                println!();
            }
        }
        MemorySub::Search {
            agent,
            query,
            limit,
        } => {
            let results = store.recall(agent, query, *limit, 0.0)?;

            if results.is_empty() {
                println!("No matching memories found for agent '{agent}' with query '{query}'.");
                return Ok(());
            }

            println!(
                "Search results for agent '{}', query '{}' ({} found):\n",
                agent,
                query,
                results.len()
            );
            for exp in &results {
                println!("  [{:>8}] {}", exp.experience_type.as_str(), exp.id);
                println!("    Context:    {}", truncate(&exp.context, 80));
                println!("    Outcome:    {}", truncate(&exp.outcome, 80));
                println!(
                    "    Confidence: {:.2}  Tags: {:?}",
                    exp.confidence, exp.tags
                );
                println!();
            }
        }
        MemorySub::Decay => {
            let pruned = store.apply_decay()?;
            println!("Applied confidence decay. Pruned {pruned} expired memories.");
        }
        MemorySub::Clear { agent } => {
            let stats_before = store.statistics(agent)?;
            println!(
                "Clearing {} memories for agent '{agent}'...",
                stats_before.total_experiences
            );
            store.clear_agent(agent)?;
            println!("Done.");
        }
        MemorySub::DetectPatterns { agent } => {
            let detector = skwaq_core::memory::PatternDetector::new(&store);
            let new_patterns = detector.detect_patterns(agent)?;
            println!("Detected {new_patterns} new patterns for agent '{agent}'.");
        }
    }

    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}
