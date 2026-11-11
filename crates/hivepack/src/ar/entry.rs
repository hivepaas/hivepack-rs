//! An entry's header, as libarchive's `archive_entry` holds what the ar
//! reader sets in it (`archive_entry.c`).

/// `AE_IFMT`: the file type bits of a mode.
pub const AE_IFMT: u32 = 0o170000;
/// `AE_IFREG`: a regular file, which every ar entry is.
pub const AE_IFREG: u32 = 0o100000;

/// An entry's header: what libarchive's ar reader sets in its
/// `archive_entry`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Header {
    /// The name: the header's, its spaces and a GNU name's `/` taken off, a
    /// GNU long name from the filename table, or a BSD long name from
    /// before the data. Up to its first NUL, and possibly empty.
    pub path: Vec<u8>,
    /// The mode in the header, in octal, as `mode_t` holds it, its file
    /// type set to a regular file ([`AE_IFREG`]) whatever it said.
    pub mode: u32,
    /// The owner's user id, as `uid_t` holds the header's decimal number.
    pub uid: u32,
    /// The owner's group id, as `gid_t` holds it.
    pub gid: u32,
    /// The data's size: the header's, less a BSD long name's length.
    pub size: u64,
    /// The modification time, in seconds since 1970, as `time_t` holds the
    /// header's decimal number.
    pub mod_time: i64,
}

/// The bytes of `bytes` up to its first NUL, as C reads a string.
pub(crate) fn c_string(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b == 0) {
        Some(n) => &bytes[..n],
        None => bytes,
    }
}
