//! Binary hardening report formatting.
//!
//! Takes a [`HardeningInfo`] from native binary analysis and produces
//! a human-readable summary string.

use crate::binary::types::HardeningInfo;

/// Format a `HardeningInfo` struct into a readable multi-line report.
pub fn format_hardening(info: &HardeningInfo) -> String {
    format!(
        "Binary Hardening Report\n\
         -----------------------\n\
         PIE (Position Independent): {pie}\n\
         NX (Non-Executable Stack):  {nx}\n\
         Stack Canary:               {canary}\n\
         RELRO:                      {relro}\n\
         Fortify Source:             {fortify}",
        pie = info.pie,
        nx = info.nx,
        canary = info.canary,
        relro = info.relro,
        fortify = info.fortify,
    )
}
