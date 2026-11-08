//! Single-instance guard for the GUI.
//!
//! Prevents a second GUI instance from opening (for example when the app is
//! launched again while a block is running). The guard is process-wide and
//! released automatically when the returned value is dropped.

/// Held for the lifetime of the process; dropping it releases the lock.
pub struct SingleInstance {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

impl SingleInstance {
    /// Try to become the single running instance identified by `name`.
    ///
    /// Returns `None` if another instance already holds the lock.
    pub fn try_acquire(name: &str) -> Option<Self> {
        use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS};
        use windows_sys::Win32::System::Threading::CreateMutexW;
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, wide.as_ptr()) };
        if handle.is_null() {
            return None;
        }
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            unsafe { CloseHandle(handle) };
            return None;
        }
        Some(SingleInstance { handle })
    }
}

impl Drop for SingleInstance {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) };
    }
}
