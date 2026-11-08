//! Hiding a folder where a leading dot does not: on Windows, the hidden
//! attribute, for the private folder an archive read once is written into
//! before it moves into place (`extract`'s `Destination::staging`). On Unix
//! the folder's name, starting with a dot, hides it already.
//!
//! On Windows the calls to the system take `unsafe` code: they are given a
//! path as the system takes it, NUL-terminated UTF-16 that lives for both
//! calls, and read nothing else. See `docs/unsafe.md`.

#![allow(unsafe_code)]

use std::path::Path;

/// Gives the folder at `path` the hidden attribute, keeping its others:
/// whether it has it. Always on Unix, where its name hides it.
#[cfg(windows)]
pub(crate) fn hide(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_HIDDEN, GetFileAttributesW, INVALID_FILE_ATTRIBUTES, SetFileAttributesW,
    };
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: `wide` is a NUL-terminated UTF-16 path that outlives the call,
    // which reads it and nothing else.
    let attributes = unsafe { GetFileAttributesW(wide.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        return false;
    }
    // SAFETY: as above; the attributes are the folder's own, and one more.
    unsafe { SetFileAttributesW(wide.as_ptr(), attributes | FILE_ATTRIBUTE_HIDDEN) != 0 }
}

/// Gives the folder at `path` the hidden attribute, keeping its others:
/// whether it has it. Always on Unix, where its name hides it.
#[cfg(not(windows))]
pub(crate) fn hide(_: &Path) -> bool {
    true
}
