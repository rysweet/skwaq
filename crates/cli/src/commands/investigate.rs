//! `skwaq investigate` - investigation management (stub).

use super::InvestigateSub;

pub fn run(sub: &InvestigateSub) -> anyhow::Result<()> {
    match sub {
        InvestigateSub::New { name } => {
            println!("skwaq investigate new: coming soon ({name})");
        }
        InvestigateSub::Resume { id } => {
            println!("skwaq investigate resume: coming soon ({id})");
        }
        InvestigateSub::List => {
            println!("skwaq investigate list: coming soon");
        }
        InvestigateSub::Export { id, output } => {
            let out = output
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "stdout".into());
            println!("skwaq investigate export: coming soon ({id} -> {out})");
        }
    }
    Ok(())
}
