//! Port of `SCBlockFileReaderWriter` — reading/writing the `.selflock` blocklist
//! file format (a property list with `HostBlacklist` + `BlockAsWhitelist` keys).

use crate::error::{Error, Result};
use plist::{Dictionary, Value};
use std::path::Path;

/// In-memory representation of a saved blocklist file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlocklistFile {
    pub blocklist: Vec<String>,
    pub block_as_whitelist: bool,
}

impl BlocklistFile {
    pub fn new(blocklist: Vec<String>, block_as_whitelist: bool) -> Self {
        BlocklistFile {
            blocklist,
            block_as_whitelist,
        }
    }
}

/// Port of `+[SCBlockFileReaderWriter readBlocklistFromFile:]`.
pub fn read_from_path(path: impl AsRef<Path>) -> Result<BlocklistFile> {
    let path = path.as_ref();
    let value = Value::from_file(path)
        .map_err(|e| Error::BlocklistRead(format!("{}: {e}", path.display())))?;

    let dict = value
        .as_dictionary()
        .ok_or_else(|| Error::BlocklistRead("not a dictionary".into()))?;

    let hosts = dict
        .get("HostBlacklist")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::BlocklistRead("missing HostBlacklist".into()))?;

    let blocklist: Vec<String> = hosts
        .iter()
        .filter_map(|v| v.as_string().map(str::to_string))
        .collect();

    let block_as_whitelist = dict
        .get("BlockAsWhitelist")
        .and_then(Value::as_boolean)
        .ok_or_else(|| Error::BlocklistRead("missing BlockAsWhitelist".into()))?;

    Ok(BlocklistFile {
        blocklist,
        block_as_whitelist,
    })
}

/// Port of `+[SCBlockFileReaderWriter writeBlocklistToFileURL:...]`.
///
/// Writes an XML property list (portable across platforms, unlike the original
/// binary format, but readable by the same `plist` tooling).
pub fn write_to_path(path: impl AsRef<Path>, file: &BlocklistFile) -> Result<()> {
    let mut dict = Dictionary::new();
    dict.insert(
        "HostBlacklist".to_string(),
        Value::Array(
            file.blocklist
                .iter()
                .map(|s| Value::String(s.clone()))
                .collect(),
        ),
    );
    dict.insert(
        "BlockAsWhitelist".to_string(),
        Value::Boolean(file.block_as_whitelist),
    );

    Value::Dictionary(dict)
        .to_file_xml(path.as_ref())
        .map_err(|e| Error::other(format!("failed to write blocklist file: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("sl-blocklist-test-{}.selflock", std::process::id()));
        let original = BlocklistFile::new(vec!["example.com".into(), "foo.com:80".into()], true);
        write_to_path(&path, &original).unwrap();
        let read = read_from_path(&path).unwrap();
        assert_eq!(original, read);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_missing_keys() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("sl-badblocklist-{}.selflock", std::process::id()));
        Value::Dictionary(Dictionary::new())
            .to_file_xml(&path)
            .unwrap();
        assert!(read_from_path(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
