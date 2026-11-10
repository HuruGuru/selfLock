Change Log

v1.4.1 (2026-11-10)
Fixed
- Prevented hosts-file rules from becoming permanent when an unrelated footer appears before the block.
- Refused to overwrite an unreadable or non-UTF-8 hosts file, preventing loss of user entries.
- Serialized settings read-modify-write operations and made block start/clear state changes transactional.
- Kept block state and the auto-clear task when start or clear only partially succeeds.
- Added `--if-expired` to GUI-scheduled auto-clear tasks so an old task cannot remove a newer live block.
- Validated firewall state entries, preserved state on failed rule deletion, and restored firewall policy only after rules are removed.
- Rejected allowlist blocks in release builds instead of silently converting them to blocklist blocks.
- Stopped stale settings snapshots from overwriting options changed by another process.
- Moved GUI block-state persistence off the UI thread.
- Added Unicode path handling tests for Cyrillic installation paths.
