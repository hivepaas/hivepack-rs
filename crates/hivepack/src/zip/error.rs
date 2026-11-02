//! Errors: port of `zip_error.c`, `zip_error_strerror.c`, and the tables of
//! `zip_err_str.c`, which libzip's build generates from the comments in
//! `zip.h` and `zipint.h`.

use std::fmt;

/// `ZIP_ER_*`: what went wrong. [`Error::code`] gives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ErrorCode {
    /// `ZIP_ER_OK`: no error.
    Ok = 0,
    /// `ZIP_ER_MULTIDISK`: multi-disk zip archives not supported.
    MultiDisk = 1,
    /// `ZIP_ER_RENAME`: renaming temporary file failed.
    Rename = 2,
    /// `ZIP_ER_CLOSE`: closing zip archive failed.
    Close = 3,
    /// `ZIP_ER_SEEK`: seek error.
    Seek = 4,
    /// `ZIP_ER_READ`: read error.
    Read = 5,
    /// `ZIP_ER_WRITE`: write error.
    Write = 6,
    /// `ZIP_ER_CRC`: CRC error.
    Crc = 7,
    /// `ZIP_ER_ZIPCLOSED`: containing zip archive was closed.
    ZipClosed = 8,
    /// `ZIP_ER_NOENT`: no such file.
    NoEntry = 9,
    /// `ZIP_ER_EXISTS`: file already exists.
    Exists = 10,
    /// `ZIP_ER_OPEN`: can't open file.
    Open = 11,
    /// `ZIP_ER_TMPOPEN`: failure to create temporary file.
    TmpOpen = 12,
    /// `ZIP_ER_ZLIB`: zlib error.
    Zlib = 13,
    /// `ZIP_ER_MEMORY`: malloc failure.
    Memory = 14,
    /// `ZIP_ER_CHANGED`: entry has been changed.
    Changed = 15,
    /// `ZIP_ER_COMPNOTSUPP`: compression method not supported.
    CompNotSupp = 16,
    /// `ZIP_ER_EOF`: premature end of file.
    Eof = 17,
    /// `ZIP_ER_INVAL`: invalid argument.
    Inval = 18,
    /// `ZIP_ER_NOZIP`: not a zip archive.
    NoZip = 19,
    /// `ZIP_ER_INTERNAL`: internal error.
    Internal = 20,
    /// `ZIP_ER_INCONS`: zip archive inconsistent; [`Error::detail`] says
    /// how.
    Incons = 21,
    /// `ZIP_ER_REMOVE`: can't remove file.
    Remove = 22,
    /// `ZIP_ER_DELETED`: entry has been deleted.
    Deleted = 23,
    /// `ZIP_ER_ENCRNOTSUPP`: encryption method not supported.
    EncrNotSupp = 24,
    /// `ZIP_ER_RDONLY`: read-only archive.
    RdOnly = 25,
    /// `ZIP_ER_NOPASSWD`: no password provided.
    NoPasswd = 26,
    /// `ZIP_ER_WRONGPASSWD`: wrong password provided.
    WrongPasswd = 27,
    /// `ZIP_ER_OPNOTSUPP`: operation not supported.
    OpNotSupp = 28,
    /// `ZIP_ER_INUSE`: resource still in use.
    InUse = 29,
    /// `ZIP_ER_TELL`: tell error.
    Tell = 30,
    /// `ZIP_ER_COMPRESSED_DATA`: compressed data invalid.
    CompressedData = 31,
    /// `ZIP_ER_CANCELLED`: operation cancelled.
    Cancelled = 32,
    /// `ZIP_ER_DATA_LENGTH`: unexpected length of data.
    DataLength = 33,
    /// `ZIP_ER_NOT_ALLOWED`: not allowed in torrentzip.
    NotAllowed = 34,
    /// `ZIP_ER_TRUNCATED_ZIP`: possibly truncated or corrupted zip archive.
    TruncatedZip = 35,
    /// `ZIP_ER_EF_TOO_LARGE`: extra fields too large.
    EfTooLarge = 36,
}

impl ErrorCode {
    /// The number libzip gives this error.
    pub fn number(self) -> i32 {
        self as i32
    }
}

/// `ZIP_ET_*`: what [`Error::system`] holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemType {
    /// `ZIP_ET_NONE`: nothing.
    None,
    /// `ZIP_ET_SYS`: an `errno` value.
    Sys,
    /// `ZIP_ET_ZLIB`: a zlib return code.
    Zlib,
    /// `ZIP_ET_LIBZIP`: a [`Detail`], with the index of the entry it is
    /// about.
    Libzip,
}

/// `ZIP_ER_DETAIL_*` of `zipint.h`: how an archive is inconsistent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Detail {
    /// no detail
    NoDetail = 0,
    /// central directory overlaps EOCD, or there is space between them
    CdirOverlapsEocd = 1,
    /// archive comment length incorrect
    CommentLengthInvalid = 2,
    /// central directory length invalid
    CdirLengthInvalid = 3,
    /// central header invalid
    CdirEntryInvalid = 4,
    /// central directory count of entries is incorrect
    CdirWrongEntriesCount = 5,
    /// local and central headers do not match
    EntryHeaderMismatch = 6,
    /// wrong EOCD length
    EocdLengthInvalid = 7,
    /// EOCD64 overlaps EOCD, or there is space between them
    Eocd64OverlapsEocd = 8,
    /// EOCD64 magic incorrect
    Eocd64WrongMagic = 9,
    /// EOCD64 and EOCD do not match
    Eocd64Mismatch = 10,
    /// invalid value in central directory
    CdirInvalid = 11,
    /// variable size fields overflow header
    VariableSizeOverflow = 12,
    /// invalid UTF-8 in filename
    InvalidUtf8InFilename = 13,
    /// invalid UTF-8 in comment
    InvalidUtf8InComment = 14,
    /// invalid Zip64 extra field
    InvalidZip64Ef = 15,
    /// invalid WinZip AES extra field
    InvalidWinzipaesEf = 16,
    /// garbage at end of extra fields
    EfTrailingGarbage = 17,
    /// extra field length is invalid
    InvalidEfLength = 18,
    /// file length in header doesn't match actual file length
    InvalidFileLength = 19,
    /// compressed and uncompressed sizes don't match for stored file
    StoredSizeMismatch = 20,
    /// local header and data descriptor do not match
    DataDescriptorMismatch = 21,
    /// EOCD64 and EOCD64 locator do not match
    Eocd64LocatorMismatch = 22,
    /// UTF-8 filename is ASCII and doesn't match filename
    Utf8FilenameMismatch = 23,
    /// UTF-8 comment is ASCII and doesn't match comment
    Utf8CommentMismatch = 24,
    /// garbage at end of compressed data
    CompressedDataTrailingGarbage = 25,
    /// NUL byte in file name
    NulInFilename = 26,
    /// missing Zip64 extra field
    MissingZip64Ef = 27,
}

/// `ZIP_ET_*` of each error code, and its description: `_zip_err_str`.
const ERR_STR: [(SystemType, &str); 37] = [
    (SystemType::None, "No error"),
    (SystemType::None, "Multi-disk zip archives not supported"),
    (SystemType::Sys, "Renaming temporary file failed"),
    (SystemType::Sys, "Closing zip archive failed"),
    (SystemType::Sys, "Seek error"),
    (SystemType::Sys, "Read error"),
    (SystemType::Sys, "Write error"),
    (SystemType::None, "CRC error"),
    (SystemType::None, "Containing zip archive was closed"),
    (SystemType::None, "No such file"),
    (SystemType::None, "File already exists"),
    (SystemType::Sys, "Can't open file"),
    (SystemType::Sys, "Failure to create temporary file"),
    (SystemType::Zlib, "Zlib error"),
    (SystemType::None, "Malloc failure"),
    (SystemType::None, "Entry has been changed"),
    (SystemType::None, "Compression method not supported"),
    (SystemType::None, "Premature end of file"),
    (SystemType::None, "Invalid argument"),
    (SystemType::None, "Not a zip archive"),
    (SystemType::None, "Internal error"),
    (SystemType::Libzip, "Zip archive inconsistent"),
    (SystemType::Sys, "Can't remove file"),
    (SystemType::None, "Entry has been deleted"),
    (SystemType::None, "Encryption method not supported"),
    (SystemType::None, "Read-only archive"),
    (SystemType::None, "No password provided"),
    (SystemType::None, "Wrong password provided"),
    (SystemType::None, "Operation not supported"),
    (SystemType::None, "Resource still in use"),
    (SystemType::Sys, "Tell error"),
    (SystemType::None, "Compressed data invalid"),
    (SystemType::None, "Operation cancelled"),
    (SystemType::None, "Unexpected length of data"),
    (SystemType::None, "Not allowed in torrentzip"),
    (
        SystemType::None,
        "Possibly truncated or corrupted zip archive",
    ),
    (SystemType::None, "Extra fields too large"),
];

/// Whether a detail is about one entry (`ZIP_DETAIL_ET_ENTRY`), and its
/// description: `_zip_err_details`.
const ERR_DETAILS: [(bool, &str); 28] = [
    (false, "no detail"),
    (
        false,
        "central directory overlaps EOCD, or there is space between them",
    ),
    (false, "archive comment length incorrect"),
    (false, "central directory length invalid"),
    (true, "central header invalid"),
    (false, "central directory count of entries is incorrect"),
    (true, "local and central headers do not match"),
    (false, "wrong EOCD length"),
    (
        false,
        "EOCD64 overlaps EOCD, or there is space between them",
    ),
    (false, "EOCD64 magic incorrect"),
    (false, "EOCD64 and EOCD do not match"),
    (false, "invalid value in central directory"),
    (true, "variable size fields overflow header"),
    (true, "invalid UTF-8 in filename"),
    (true, "invalid UTF-8 in comment"),
    (true, "invalid Zip64 extra field"),
    (true, "invalid WinZip AES extra field"),
    (true, "garbage at end of extra fields"),
    (true, "extra field length is invalid"),
    (
        true,
        "file length in header doesn't match actual file length",
    ),
    (
        true,
        "compressed and uncompressed sizes don't match for stored file",
    ),
    (true, "local header and data descriptor do not match"),
    (false, "EOCD64 and EOCD64 locator do not match"),
    (true, "UTF-8 filename is ASCII and doesn't match filename"),
    (true, "UTF-8 comment is ASCII and doesn't match comment"),
    (false, "garbage at end of compressed data"),
    (true, "NUL byte in file name"),
    (true, "missing Zip64 extra field"),
];

/// `MAX_DETAIL_INDEX`: the largest entry index a detail can carry.
pub(crate) const MAX_DETAIL_INDEX: u64 = 0x7f_ffff;

/// `MAKE_DETAIL_WITH_INDEX`: a detail and the index of its entry, packed as
/// libzip packs them in `sys_err`.
pub(crate) fn make_detail_with_index(detail: Detail, index: u64) -> i32 {
    ((index.min(MAX_DETAIL_INDEX) as i32) << 8) | detail as i32
}

/// `ADD_INDEX_TO_DETAIL`: the same detail, now about entry `index`.
pub(crate) fn add_index_to_detail(sys_err: i32, index: u64) -> i32 {
    ((index.min(MAX_DETAIL_INDEX) as i32) << 8) | (sys_err & 0xff)
}

/// An error: `zip_error_t`, without its cached string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    zip_err: ErrorCode,
    sys_err: i32,
}

/// What every fallible function returns.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// An error with this code and system error: `zip_error_set(error,
    /// ze, se)`.
    pub const fn new(zip_err: ErrorCode, sys_err: i32) -> Error {
        Error { zip_err, sys_err }
    }

    /// No error: what `zip_error_init` leaves.
    pub(crate) const OK: Error = Error::new(ErrorCode::Ok, 0);

    /// Whether this is an error: `zip_err != ZIP_ER_OK`.
    pub(crate) fn is_set(&self) -> bool {
        self.zip_err != ErrorCode::Ok
    }

    /// An inconsistency, with its detail: `ZIP_ER_INCONS`.
    pub(crate) fn incons(detail: Detail) -> Error {
        Error::new(ErrorCode::Incons, detail as i32)
    }

    /// An inconsistency in entry `index`.
    pub(crate) fn incons_at(detail: Detail, index: u64) -> Error {
        Error::new(ErrorCode::Incons, make_detail_with_index(detail, index))
    }

    /// The error code: `zip_error_code_zip`.
    pub fn code(&self) -> ErrorCode {
        self.zip_err
    }

    /// The system error, zlib error or detail: `zip_error_code_system`.
    pub fn system(&self) -> i32 {
        self.sys_err
    }

    /// What [`system`](Error::system) holds: `zip_error_system_type`.
    pub fn system_type(&self) -> SystemType {
        ERR_STR[self.zip_err as usize].0
    }

    /// For [`ErrorCode::Incons`], how the archive is inconsistent, and the
    /// index of the entry if the detail is about one.
    pub fn detail(&self) -> Option<(Detail, Option<u64>)> {
        if self.system_type() != SystemType::Libzip {
            return None;
        }
        let detail = DETAILS.get((self.sys_err & 0xff) as usize).copied()?;
        let index = ((self.sys_err >> 8) as u64) & MAX_DETAIL_INDEX;
        Some((detail, ERR_DETAILS[detail as usize].0.then_some(index)))
    }
}

/// The details by number.
const DETAILS: [Detail; 28] = [
    Detail::NoDetail,
    Detail::CdirOverlapsEocd,
    Detail::CommentLengthInvalid,
    Detail::CdirLengthInvalid,
    Detail::CdirEntryInvalid,
    Detail::CdirWrongEntriesCount,
    Detail::EntryHeaderMismatch,
    Detail::EocdLengthInvalid,
    Detail::Eocd64OverlapsEocd,
    Detail::Eocd64WrongMagic,
    Detail::Eocd64Mismatch,
    Detail::CdirInvalid,
    Detail::VariableSizeOverflow,
    Detail::InvalidUtf8InFilename,
    Detail::InvalidUtf8InComment,
    Detail::InvalidZip64Ef,
    Detail::InvalidWinzipaesEf,
    Detail::EfTrailingGarbage,
    Detail::InvalidEfLength,
    Detail::InvalidFileLength,
    Detail::StoredSizeMismatch,
    Detail::DataDescriptorMismatch,
    Detail::Eocd64LocatorMismatch,
    Detail::Utf8FilenameMismatch,
    Detail::Utf8CommentMismatch,
    Detail::CompressedDataTrailingGarbage,
    Detail::NulInFilename,
    Detail::MissingZip64Ef,
];

/// zlib's messages for its return codes: `zError`.
fn z_error(code: i32) -> &'static str {
    match code {
        2 => "need dictionary",
        1 => "stream end",
        -1 => "file error",
        -2 => "stream error",
        -3 => "data error",
        -4 => "insufficient memory",
        -5 => "buffer error",
        -6 => "incompatible version",
        _ => "",
    }
}

/// The message: port of `zip_error_strerror`.
///
/// Differs from libzip: a system error is described by the standard
/// library, which uses the same `strerror` text on Unix.
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, description) = ERR_STR[self.zip_err as usize];
        let system = match kind {
            SystemType::None => None,
            SystemType::Sys => {
                let text = std::io::Error::from_raw_os_error(self.sys_err).to_string();
                let suffix = format!(" (os error {})", self.sys_err);
                Some(text.strip_suffix(&suffix).unwrap_or(&text).to_string())
            }
            SystemType::Zlib => Some(z_error(self.sys_err).to_string()),
            SystemType::Libzip => {
                let error = (self.sys_err & 0xff) as usize;
                let index = (self.sys_err >> 8) as u64 & MAX_DETAIL_INDEX;
                if error == 0 {
                    None
                } else if error >= ERR_DETAILS.len() {
                    Some(format!("invalid detail error {error}"))
                } else if ERR_DETAILS[error].0 && index < MAX_DETAIL_INDEX {
                    Some(format!("entry {index}: {}", ERR_DETAILS[error].1))
                } else {
                    Some(ERR_DETAILS[error].1.to_string())
                }
            }
        };
        match system {
            None => f.write_str(description),
            Some(system) => write!(f, "{description}: {system}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_errors_as_libzip() {
        assert_eq!(
            Error::new(ErrorCode::NoZip, 0).to_string(),
            "Not a zip archive"
        );
        let error = Error::incons_at(Detail::EntryHeaderMismatch, 3);
        assert_eq!(
            error.to_string(),
            "Zip archive inconsistent: entry 3: local and central headers do not match"
        );
        assert_eq!(error.detail(), Some((Detail::EntryHeaderMismatch, Some(3))));
        let error = Error::incons(Detail::CommentLengthInvalid);
        assert_eq!(error.system(), 2);
        assert_eq!(
            error.to_string(),
            "Zip archive inconsistent: archive comment length incorrect"
        );
        assert_eq!(
            Error::new(ErrorCode::Zlib, -3).to_string(),
            "Zlib error: data error"
        );
        assert_eq!(
            Error::new(ErrorCode::Incons, 0).to_string(),
            "Zip archive inconsistent"
        );
        for (i, detail) in DETAILS.iter().enumerate() {
            assert_eq!(*detail as usize, i);
        }
    }
}
