//! Child-process helpers.
//!
//! The single shipped binary is a GUI-subsystem executable, so it has no console
//! of its own. Any console program it launches (e.g. `netsh`, `ipconfig`,
//! `powershell`) would otherwise pop up its own console window. `hidden_command`
//! creates such processes without a visible window while still allowing their
//! stdout/stderr to be captured.

use std::os::windows::process::CommandExt;
use std::process::Command;

/// Create a `Command` that never shows a console window.
///
/// The child still gets a hidden console, so captured output works; nothing is
/// shown to the user.
pub fn hidden_command(program: &str) -> Command {
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut command = Command::new(program);
    command.creation_flags(CREATE_NO_WINDOW);
    command
}
