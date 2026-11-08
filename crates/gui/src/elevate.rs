//! Best-effort elevation helpers.
//!
//! The GUI itself is not privileged, so when a firewall/hosts operation needs
//! administrator rights we re-run the CLI in an elevated process.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Path to this executable. The GUI re-invokes itself in CLI mode (`--cli`) to
/// perform privileged work and to register the auto-clear task, so no separate
/// CLI binary needs to ship alongside it.
pub fn self_exe() -> Option<PathBuf> {
    std::env::current_exe().ok()
}

/// Run `program args...` with elevated privileges and wait for it to finish.
///
/// Returns the exit code of the (elevated) child on success, or an error string
/// when elevation itself could not be performed (e.g. the UAC prompt was
/// dismissed).
pub fn run_elevated(program: &Path, args: &[String]) -> Result<i32, String> {
    use std::os::windows::process::CommandExt;

    log::info!(
        "elevate: requesting elevation for {} {}",
        program.display(),
        args.join(" ")
    );

    // Don't flash a console window for our (invisible) helper PowerShell.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let exe = program.display().to_string();
    // Pre-quote the whole argument list with Windows command-line rules and pass
    // it as ONE string. `Start-Process -ArgumentList @(...)` joins array elements
    // with spaces without quoting, which silently breaks any path containing a
    // space (e.g. `C:\Users\John Smith\...`).
    let arg_string = args
        .iter()
        .map(|a| windows_quote(a))
        .collect::<Vec<_>>()
        .join(" ");
    let script = format!(
        "$ErrorActionPreference='Stop'; \
         $p = Start-Process -FilePath '{exe}' -Verb RunAs -ArgumentList '{arg_str}' -Wait -PassThru; \
         exit $p.ExitCode",
        exe = exe.replace('\'', "''"),
        arg_str = arg_string.replace('\'', "''")
    );
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("failed to launch powershell: {e}"))?;
    let code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    log::info!("elevate: powershell exit code {code}");
    if !stdout.trim().is_empty() {
        log::info!("elevate: stdout: {}", stdout.trim());
    }
    if !stderr.trim().is_empty() {
        log::warn!("elevate: stderr: {}", stderr.trim());
    }
    // Code 1 (or a hidden error) generally means the UAC prompt was declined.
    if !output.status.success() && code == 1 {
        return Err("elevation was cancelled or the UAC prompt was declined".into());
    }
    Ok(code)
}

/// Whether we appear to already be running elevated.
pub fn is_elevated() -> bool {
    selflock_core::elevation::is_elevated()
}

/// Quote a single argument for the Windows command line per the `CommandLineToArgvW`
/// rules: wrap in double quotes and escape embedded quotes / trailing backslashes.
fn windows_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => {
                backslashes += 1;
                out.push('\\');
            }
            '"' => {
                // Backslashes before a quote must be doubled, the quote escaped.
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push('\\');
                out.push('"');
            }
            _ => {
                backslashes = 0;
                out.push(c);
            }
        }
    }
    // Backslashes before the closing quote must be doubled.
    for _ in 0..backslashes {
        out.push('\\');
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::windows_quote;

    #[test]
    fn quotes_plain_argument() {
        assert_eq!(windows_quote("--cli"), "\"--cli\"");
    }

    #[test]
    fn keeps_spaces_inside_quotes() {
        assert_eq!(
            windows_quote(r"C:\Users\John Smith\file"),
            "\"C:\\Users\\John Smith\\file\""
        );
    }

    #[test]
    fn escapes_trailing_backslash() {
        assert_eq!(windows_quote("C:\\dir\\"), "\"C:\\dir\\\\\"");
    }

    #[test]
    fn escapes_embedded_quote() {
        assert_eq!(windows_quote("a\"b"), "\"a\\\"b\"");
    }
}
