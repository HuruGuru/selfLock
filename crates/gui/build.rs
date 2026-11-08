//! Embed a Windows VERSIONINFO resource, icon, and manifest into the GUI binary.
//!
//! The manifest is the default `asInvoker` plus DPI/long-path awareness; the app
//! elevates itself on demand at runtime rather than requesting admin up front.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../assets/lock.ico");
    windows_resource();
}

fn windows_resource() {
    use winresource::WindowsResource;

    // The icon lives at the workspace root; resolve it against this crate's dir.
    let icon = format!("{}/../../assets/lock.ico", env!("CARGO_MANIFEST_DIR"));

    let mut res = WindowsResource::new();
    res.set_icon(&icon);
    res.set("FileDescription", "SelfLock");
    res.set("ProductName", "SelfLock");
    res.set("OriginalFilename", "selflock.exe");
    res.set("LegalCopyright", "GPL-3.0-or-later");
    res.set("Comments", "SelfLock for Windows");

    // "1.0.0" -> FILEVERSION / PRODUCTVERSION packed as 4 x u16.
    let mut version = [0u16; 4];
    for (i, part) in env!("CARGO_PKG_VERSION").split('.').take(4).enumerate() {
        version[i] = part.parse().unwrap_or(0);
    }
    let packed = ((version[0] as u64) << 48)
        | ((version[1] as u64) << 32)
        | ((version[2] as u64) << 16)
        | (version[3] as u64);
    res.set_version_info(winresource::VersionInfo::FILEVERSION, packed);
    res.set_version_info(winresource::VersionInfo::PRODUCTVERSION, packed);
    let text = format!(
        "{}.{}.{}.{}",
        version[0], version[1], version[2], version[3]
    );
    res.set("FileVersion", &text);
    res.set("ProductVersion", &text);

    res.set_manifest(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">permonitorv2,permonitor</dpiAwareness>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
</assembly>
"#,
    );

    if let Err(e) = res.compile() {
        panic!("failed to embed Windows resources: {e}");
    }
}
