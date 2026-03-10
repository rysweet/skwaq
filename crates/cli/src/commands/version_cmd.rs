//! `skwaq version` - show version information.

/// Print version information.
pub fn run() {
    let version = env!("CARGO_PKG_VERSION");
    println!("skwaq {version}");
}
