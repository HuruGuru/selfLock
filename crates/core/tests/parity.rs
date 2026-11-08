//! Parity tests ported from the original project's `SCUtilityTests.m`.

use chrono::{Duration, Utc};
use selflock_core::cleaner::clean_blocklist_entry;
use selflock_core::settings::Settings;

/// Port of `-testCleanBlocklistEntries`.
#[test]
fn clean_blocklist_entries_matches_original() {
    // Ignores weird invalid entries.
    assert!(clean_blocklist_entry("").is_empty());
    assert!(clean_blocklist_entry("      ").is_empty());
    assert!(clean_blocklist_entry("  \n\n   \n***!@#$%^*()+=<>,/?| ").is_empty());
    assert!(clean_blocklist_entry("://}**").is_empty());

    let one = |s: &str| {
        let v = clean_blocklist_entry(s);
        assert_eq!(v.len(), 1, "expected 1 entry for {s:?}, got {v:?}");
        v.into_iter().next().unwrap()
    };

    assert_eq!(one("selflockapp.com"), "selflockapp.com");
    assert_eq!(one("selFlockApp.com"), "selflockapp.com");
    assert_eq!(one("www.selFlockApp.com"), "www.selflockapp.com");
    assert_eq!(one("http://www.selFlockApp.com"), "www.selflockapp.com");
    assert_eq!(one("https://www.selFlockApp.com"), "www.selflockapp.com");
    assert_eq!(one("ftp://www.selFlockApp.com"), "www.selflockapp.com");
    assert_eq!(
        one("https://www.selFlockApp.com:73"),
        "www.selflockapp.com:73"
    );
    assert_eq!(one("http://charlie:mypass@cnn.com:54"), "cnn.com:54");
    assert_eq!(
        one("http://mysite.com/my/path/is/very/long.php?querystring=ydfjkl&otherquerystring=%40%80%20#cool"),
        "mysite.com"
    );
    assert_eq!(one("127.0.0.1/20"), "127.0.0.1/20");

    let cleaned = clean_blocklist_entry(
        "http://charlie:mypass@cnn.com:54\nhttps://selfLockAPP.com\n192.168.1.1/24\ntest.com\n{}*&\nhttps://reader.google.com/mypath/is/great.php",
    );
    assert_eq!(cleaned.len(), 5);
    assert_eq!(cleaned[0], "cnn.com:54");
    assert_eq!(cleaned[1], "selflockapp.com");
    assert_eq!(cleaned[2], "192.168.1.1/24");
    assert_eq!(cleaned[3], "test.com");
    assert_eq!(cleaned[4], "reader.google.com");
}

/// Port of `-testModernBlockDetection`.
#[test]
fn modern_block_detection_matches_original() {
    let mut s = Settings::default();

    assert!(!s.any_block_is_running());
    assert!(s.current_block_is_expired());

    // A block that should have expired 5 minutes ago.
    s.block_is_running = true;
    s.active_blocklist = vec!["facebook.com".into(), "reddit.com".into()];
    s.active_block_as_whitelist = false;
    s.block_end_date = Some(Utc::now() - Duration::minutes(5));

    assert!(s.any_block_is_running());
    assert!(s.current_block_is_expired());

    // A block that should still be running.
    s.block_end_date = Some(Utc::now() + Duration::minutes(5));
    assert!(s.any_block_is_running());
    assert!(!s.current_block_is_expired());

    // Removing a block.
    s.remove_block_from_settings();
    assert!(!s.any_block_is_running());
    assert!(s.current_block_is_expired());
}
