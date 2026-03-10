//! `skwaq ingest` - ingest binary, source, or SARIF data (stub).

use super::IngestSub;

pub fn run(sub: &IngestSub) -> anyhow::Result<()> {
    match sub {
        IngestSub::Binary { path } => {
            println!("skwaq ingest binary: coming soon ({})", path.display());
        }
        IngestSub::Source { path } => {
            println!("skwaq ingest source: coming soon ({})", path.display());
        }
        IngestSub::Sarif { path } => {
            println!("skwaq ingest sarif: coming soon ({})", path.display());
        }
    }
    Ok(())
}
