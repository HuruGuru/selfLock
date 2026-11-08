//! Small Windows platform helpers shared by the CLI and GUI, so both use a single
//! FFI style (via `windows-sys`) instead of ad-hoc `extern` blocks.

/// Show a native informational message box.
pub fn message_box(title: &str, text: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONINFORMATION, MB_OK};
    let text: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let title: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        );
    }
}

/// Hide the console window when it belongs to this process alone.
///
/// The single shipped binary is a GUI-subsystem program, but the standalone CLI is
/// a console program; when Windows allocates a fresh console for an elevated run we
/// hide it. A console shared with the user's terminal is left untouched.
pub fn hide_private_console() {
    use windows_sys::Win32::System::Console::{GetConsoleProcessList, GetConsoleWindow};
    use windows_sys::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE};
    unsafe {
        let mut pids = [0u32; 8];
        let count = GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32);
        if count == 1 {
            let hwnd = GetConsoleWindow();
            if !hwnd.is_null() {
                ShowWindow(hwnd, SW_HIDE);
            }
        }
    }
}
