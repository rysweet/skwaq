//! `skwaq strings` - extract printable strings from a binary.

use std::path::Path;

use skwaq_core::binary::native::parse_binary;

/// Run the strings command on the given binary.
pub fn run(binary: &Path, min_length: usize) -> anyhow::Result<()> {
    let info = parse_binary(binary)?;

    let strings: Vec<_> = info
        .strings
        .iter()
        .filter(|s| s.value.len() >= min_length)
        .collect();

    println!(
        "{} strings (>= {} chars) in {}",
        strings.len(),
        min_length,
        binary.display()
    );
    println!();

    for s in &strings {
        println!("  {:#010x}  {}", s.offset, s.value);
    }

    Ok(())
}
