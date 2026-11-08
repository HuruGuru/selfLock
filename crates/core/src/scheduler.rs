//! Automatic block clearing at the block's end time.
//!
//! The original macOS app ships a privileged daemon that keeps running (and
//! clears the block) even when the GUI is closed. This port has no daemon, so it
//! registers a scheduled task that runs the program in removal mode
//! (`remove --force`) as the current user at the block's end time. This clears the
//! block without the app being open, and also after a reboot.

use crate::error::Result;
use chrono::{DateTime, Utc};
use std::path::Path;

/// Name of the scheduled task / marker used for the auto-clear.
pub const TASK_NAME: &str = "SelfLock-ClearBlock";

/// Register (or replace) the automatic clear for `end`, running `program args...`.
pub fn schedule_clear(program: &Path, args: &[String], end: DateTime<Utc>) -> Result<()> {
    windows::schedule(program, args, end)
}

/// Remove the automatic clear (called when a block is cleared early or normally).
pub fn cancel_clear() -> Result<()> {
    windows::cancel()
}

mod windows {
    use super::*;
    use crate::process::hidden_command;

    fn run_powershell(script: &str) -> std::result::Result<(), String> {
        log::info!(
            "scheduler: powershell -Command {}",
            script.replace('\n', " ")
        );
        let output = hidden_command("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .map_err(|e| format!("failed to launch powershell: {e}"))?;
        let code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
            log::info!("scheduler: {line}");
        }
        for line in stderr.lines().filter(|l| !l.trim().is_empty()) {
            log::warn!("scheduler: {line}");
        }
        if output.status.success() {
            Ok(())
        } else {
            Err(format!("powershell exited {code}: {}", stderr.trim()))
        }
    }

    /// How often the task re-checks an expired block once its trigger time has
    /// passed. This is the safety net for a missed trigger: if the machine was
    /// asleep (or the clock jumped) at the end time, the next tick clears the block
    /// shortly after the system is usable again.
    const RETRY_INTERVAL_MINUTES: i64 = 1;

    /// How long the repetition stays armed. Long enough for any block length, and
    /// the task is removed as soon as the block is cleared anyway.
    const RETRY_WINDOW_DAYS: i64 = 30;

    /// Build the `Register-ScheduledTask` script.
    ///
    /// Three things matter here:
    /// * a one-shot trigger at the exact end time (the normal, prompt-free path),
    /// * a repetition, so a trigger missed during sleep/hibernate is retried,
    /// * a logon trigger, so a block that expired while the machine was off is
    ///   cleared on the next logon even if the repetition also missed.
    fn registration_script(exe_q: &str, argument_q: &str, end_local: &str) -> String {
        format!(
            "$end = [datetimeoffset]::Parse('{end_local}'); \
             $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name; \
             $action = New-ScheduledTaskAction -Execute '{exe_q}' -Argument '{argument_q}'; \
             $trigger = New-ScheduledTaskTrigger -Once -At $end.LocalDateTime \
                 -RepetitionInterval (New-TimeSpan -Minutes {RETRY_INTERVAL_MINUTES}) \
                 -RepetitionDuration (New-TimeSpan -Days {RETRY_WINDOW_DAYS}); \
             $logon = New-ScheduledTaskTrigger -AtLogOn -User $me; \
             $principal = New-ScheduledTaskPrincipal -UserId $me -LogonType Interactive -RunLevel Highest; \
             $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1); \
             Register-ScheduledTask -TaskName '{TASK_NAME}' \
                 -Action $action -Trigger @($trigger, $logon) -Principal $principal \
                 -Settings $settings -Force | Out-Null; \
             Write-Output 'scheduled'"
        )
    }

    /// Task Scheduler stores whole seconds: a start boundary with a fractional part
    /// is truncated, which made the task fire up to a second **before** the block
    /// ended (and `--if-expired` then, correctly, refused to clear it). Round up so
    /// the trigger is never earlier than the real end time.
    fn trigger_time(end: DateTime<Utc>) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(end.timestamp() + 1, 0).unwrap_or(end)
    }

    pub fn schedule(program: &Path, args: &[String], end: DateTime<Utc>) -> Result<()> {
        let end_local = trigger_time(end).with_timezone(&chrono::Local).to_rfc3339();
        let exe_q = program.display().to_string().replace('\'', "''");
        // Windows paths never contain `"`, so the only quoting that matters is
        // surrounding each argument (some contain spaces).
        let argument = args
            .iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(" ");
        // Escape for the enclosing PowerShell single-quoted string.
        let argument_q = argument.replace('\'', "''");

        // Run as the current (interactive) user with highest privileges. We avoid
        // SYSTEM: `netsh` hangs when run from SYSTEM in session 0, which would leave
        // the block half-cleared. The task only runs while this user is logged on.
        let script = registration_script(&exe_q, &argument_q, &end_local);
        match run_powershell(&script) {
            Ok(()) => {
                log::info!("scheduler: registered '{TASK_NAME}' to clear the block at {end_local}");
                Ok(())
            }
            Err(e) => {
                log::warn!("scheduler: could not register auto-clear: {e}");
                Err(crate::error::Error::other(format!(
                    "could not register auto-clear scheduled task: {e}"
                )))
            }
        }
    }

    pub fn cancel() -> Result<()> {
        let script = format!(
            "Unregister-ScheduledTask -TaskName '{TASK_NAME}' -Confirm:$false -ErrorAction SilentlyContinue; Write-Output 'cancelled'"
        );
        match run_powershell(&script) {
            Ok(()) => {
                log::info!("scheduler: removed '{TASK_NAME}'");
                Ok(())
            }
            Err(e) => {
                log::warn!("scheduler: could not remove auto-clear task: {e}");
                Ok(())
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn script_arms_end_repetition_and_logon_triggers() {
            let script = registration_script(
                "C:\\app\\selflock.exe",
                "\"--cli\" \"remove\" \"--force\" \"--if-expired\"",
                "2026-11-08T15:22:09.744831+05:00",
            );
            assert!(script.contains("New-ScheduledTaskTrigger -Once -At $end.LocalDateTime"));
            assert!(script.contains("-RepetitionInterval (New-TimeSpan -Minutes 1)"));
            assert!(script.contains("-RepetitionDuration (New-TimeSpan -Days 30)"));
            assert!(script.contains("New-ScheduledTaskTrigger -AtLogOn -User $me"));
            assert!(script.contains("-Trigger @($trigger, $logon)"));
            assert!(script.contains("-StartWhenAvailable"));
            assert!(script.contains("Register-ScheduledTask -TaskName 'SelfLock-ClearBlock'"));
            // `run_powershell` passes this to `powershell -Command`, and the Rust
            // line continuations must collapse it into a single line.
            assert!(!script.contains('\n'));
            assert!(script.trim_end().ends_with("Write-Output 'scheduled'"));
        }

        #[test]
        fn trigger_is_rounded_up_to_the_next_whole_second() {
            // The real end can carry sub-second precision; the task boundary cannot.
            let end = DateTime::<Utc>::from_timestamp(1_762_620_670, 516_330_000).unwrap();
            let trigger = trigger_time(end);
            assert!(
                trigger > end,
                "trigger {trigger} must not be before end {end}"
            );
            assert_eq!(trigger.timestamp_subsec_nanos(), 0);
            assert_eq!(trigger.timestamp(), end.timestamp() + 1);

            // A whole-second end also moves to the next second (at most 1 s late).
            let exact = DateTime::<Utc>::from_timestamp(1_762_620_670, 0).unwrap();
            assert_eq!(trigger_time(exact).timestamp(), exact.timestamp() + 1);
        }
    }
}
