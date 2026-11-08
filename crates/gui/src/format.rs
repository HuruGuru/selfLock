//! Small formatting helpers shared by the GUI.

/// Format a number of seconds as `MM:SS` (or `HH:MM:SS` when over an hour).
pub fn format_duration(seconds: i64) -> String {
    let s = seconds.max(0);
    let hours = s / 3600;
    let minutes = (s % 3600) / 60;
    let secs = s % 60;
    if hours > 0 {
        format!("{hours:02}:{minutes:02}:{secs:02}")
    } else {
        format!("{minutes:02}:{secs:02}")
    }
}

/// Format a number of minutes as a human-readable duration (`1h 30m`, `1d`).
pub fn format_minutes(minutes: u32) -> String {
    let d = minutes / (24 * 60);
    let h = (minutes % (24 * 60)) / 60;
    let m = minutes % 60;
    match (d, h, m) {
        (0, 0, m) => format!("{m}m"),
        (0, h, 0) => format!("{h}h"),
        (0, h, m) => format!("{h}h {m}m"),
        (d, 0, 0) => format!("{d}d"),
        (d, 0, m) => format!("{d}d {m}m"),
        (d, h, 0) => format!("{d}d {h}h"),
        (d, h, m) => format!("{d}d {h}h {m}m"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_short() {
        assert_eq!(format_duration(59), "00:59");
        assert_eq!(format_duration(125), "02:05");
    }

    #[test]
    fn formats_long() {
        assert_eq!(format_duration(3725), "01:02:05");
    }

    #[test]
    fn formats_minutes() {
        assert_eq!(format_minutes(90), "1h 30m");
        assert_eq!(format_minutes(45), "45m");
        assert_eq!(format_minutes(120), "2h");
        assert_eq!(format_minutes(240), "4h");
        assert_eq!(format_minutes(480), "8h");
        assert_eq!(format_minutes(720), "12h");
        assert_eq!(format_minutes(1440), "1d");
    }

    #[test]
    fn formats_every_preset_label() {
        // Keep in sync with the preset row in `app.rs`.
        for (minutes, label) in [
            (5u32, "5m"),
            (15, "15m"),
            (30, "30m"),
            (60, "1h"),
            (120, "2h"),
            (240, "4h"),
            (480, "8h"),
            (720, "12h"),
            (1440, "1d"),
            (4320, "3d"),
            (7200, "5d"),
            (8640, "6d"),
        ] {
            assert_eq!(format_minutes(minutes), label, "preset {minutes}");
        }
    }
}
