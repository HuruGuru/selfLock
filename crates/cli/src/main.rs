//! `selflock-cli` — thin binary wrapper around the shared CLI logic.
//!
//! The same logic is embedded in the GUI executable (invoked with `--cli`), so
//! most users never need this separate binary; it is kept for headless use.

fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(selflock_cli::run_from_env())
}
