//! `skwaq analyze` - AI-driven vulnerability analysis (stub).

pub fn run(quick: bool, budget: Option<u64>) -> anyhow::Result<()> {
    let mode = if quick { "quick" } else { "full" };
    let budget_str = budget
        .map(|b| format!(" (budget: {b} tokens)"))
        .unwrap_or_default();
    println!("skwaq analyze ({mode}{budget_str}): coming soon");
    Ok(())
}
