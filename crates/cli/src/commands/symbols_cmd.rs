//! `skwaq symbols` - list symbols from a binary.

use std::path::Path;

use skwaq_core::binary::native::parse_binary;

/// Run the symbols command on the given binary.
pub fn run(binary: &Path) -> anyhow::Result<()> {
    let info = parse_binary(binary)?;

    if info.symbols.is_empty() && info.imports.is_empty() {
        println!(
            "No symbols found in {} (binary may be stripped)",
            binary.display()
        );
        return Ok(());
    }

    if !info.symbols.is_empty() {
        println!("Symbols ({}):", info.symbols.len());
        println!(
            "  {:<18} {:<8} {:<10} {:<10} Name",
            "Address", "Size", "Type", "Bind"
        );
        println!("  {}", "-".repeat(70));
        for sym in &info.symbols {
            println!(
                "  {:#018x} {:<8} {:<10} {:<10} {}",
                sym.address, sym.size, sym.symbol_type, sym.binding, sym.name
            );
        }
    }

    if !info.imports.is_empty() {
        println!();
        println!("Imports ({}):", info.imports.len());
        for imp in &info.imports {
            if imp.library.is_empty() {
                println!("  {}", imp.name);
            } else {
                println!("  {} ({})", imp.name, imp.library);
            }
        }
    }

    Ok(())
}
