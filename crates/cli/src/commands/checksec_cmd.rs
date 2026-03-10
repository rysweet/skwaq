//! `skwaq checksec` - show binary hardening information.

use std::path::Path;

use skwaq_core::analysis::format_hardening;
use skwaq_core::binary::native::parse_binary;

/// Run the checksec command on the given binary.
pub fn run(binary: &Path) -> anyhow::Result<()> {
    let info = parse_binary(binary)?;

    println!("File: {}", binary.display());
    println!("Format: {} ({}-bit, {})", info.format, info.bits, info.endianness);
    println!("Architecture: {}", info.architecture);
    println!();
    println!("{}", format_hardening(&info.hardening));

    Ok(())
}
