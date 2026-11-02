//! The internal constants, types and macros of `zipint.h`, with
//! `zip_entry.c`.

use std::sync::Arc;

use crate::zip::dirent::Dirent;
use crate::zip::open::Archive;
use crate::zip::source_data::DataSource;
use crate::zip::string::ZipString;
use crate::zip::zip::{ArchiveFlags, Flags};

pub(crate) const CENTRAL_MAGIC: &[u8; 4] = b"PK\x01\x02";
pub(crate) const LOCAL_MAGIC: &[u8; 4] = b"PK\x03\x04";
pub(crate) const EOCD_MAGIC: &[u8; 4] = b"PK\x05\x06";
pub(crate) const DATADES_MAGIC: &[u8; 4] = b"PK\x07\x08";
pub(crate) const EOCD64LOC_MAGIC: &[u8; 4] = b"PK\x06\x07";
pub(crate) const EOCD64_MAGIC: &[u8; 4] = b"PK\x06\x06";
pub(crate) const MAGIC_LEN: u64 = 4;
pub(crate) const CDENTRYSIZE: u64 = 46;
pub(crate) const LENTRYSIZE: u64 = 30;
pub(crate) const MAXCOMLEN: u64 = 65536;
pub(crate) const EOCDLEN: u64 = 22;
pub(crate) const EOCD64LOCLEN: u64 = 20;
pub(crate) const EOCD64LEN: u64 = 56;
pub(crate) const CDBUFSIZE: u64 = MAXCOMLEN + EOCDLEN + EOCD64LOCLEN;
pub(crate) const MAX_DATA_DESCRIPTOR_LENGTH: u64 = 24;
pub(crate) const BUFSIZE: usize = 8192;
pub(crate) const EFZIP64SIZE: usize = 28;
pub(crate) const EF_WINZIP_AES_SIZE: usize = 7;

/// `ZIP_CRYPTO_PKWARE_HEADERLEN`: ZipCrypto's encryption header.
pub(crate) const CRYPTO_PKWARE_HEADERLEN: usize = 12;
pub(crate) const WINZIP_AES_PASSWORD_VERIFY_LENGTH: usize = 2;
pub(crate) const WINZIP_AES_MAX_HEADER_LENGTH: usize = 16 + WINZIP_AES_PASSWORD_VERIFY_LENGTH;
pub(crate) const HMAC_LENGTH: usize = 10;

/// `SALT_LENGTH`: the salt of a WinZip AES entry, by its method.
pub(crate) fn salt_length(method: u16) -> usize {
    match method {
        crate::zip::zip::em::AES_128 => 8,
        crate::zip::zip::em::AES_192 => 12,
        _ => 16,
    }
}

pub(crate) const TORRENTZIP_SIGNATURE: &[u8; 14] = b"TORRENTZIPPED-";
pub(crate) const TORRENTZIP_SIGNATURE_LENGTH: usize = 14;
pub(crate) const TORRENTZIP_CRC_LENGTH: usize = 8;
pub(crate) const TORRENTZIP_COMPRESSION_FLAGS: u32 = u16::MAX as u32;

/// A password, of an entry or the archive's default one, up to its first
/// NUL byte as libzip keeps a C string. It is overwritten when it is
/// dropped, as `_zip_crypto_clear` clears it (best effort).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Password(Vec<u8>);

impl Password {
    /// `password` up to its first NUL byte, which may leave it empty: an
    /// empty password is not none.
    pub(crate) fn new(password: &[u8]) -> Password {
        Password(crate::zip::hash::c_string(password).to_vec())
    }
}

impl std::ops::Deref for Password {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&mut self.0);
    }
}

/// Shows nothing of the password.
impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(..)")
    }
}

/// `ZIP_CM_WINZIP_AES`: WinZip AES encrypted.
pub(crate) const CM_WINZIP_AES: u16 = 99;

pub(crate) const EF_UTF_8_COMMENT: u16 = 0x6375;
pub(crate) const EF_UTF_8_NAME: u16 = 0x7075;
pub(crate) const EF_WINZIP_AES: u16 = 0x9901;
pub(crate) const EF_ZIP64: u16 = 0x0001;

/// `ZIP_EF_IS_INTERNAL`: the extra fields libzip interprets itself, and
/// removes from those it keeps.
pub(crate) fn ef_is_internal(id: u16) -> bool {
    id == EF_UTF_8_COMMENT || id == EF_UTF_8_NAME || id == EF_WINZIP_AES || id == EF_ZIP64
}

/// `ZIP_GPBF_*`: general purpose bit flags.
pub(crate) const GPBF_ENCRYPTED: u16 = 0x0001;
pub(crate) const GPBF_DATA_DESCRIPTOR: u16 = 0x0008;
pub(crate) const GPBF_STRONG_ENCRYPTION: u16 = 0x0040;
pub(crate) const GPBF_ENCODING_UTF_8: u16 = 0x0800;

/// `ZIP_EXTRA_FIELD_ALL`: every extra field, to delete.
pub const EXTRA_FIELD_ALL: u16 = u16::MAX;
/// `ZIP_EXTRA_FIELD_NEW`: a new extra field, to set.
pub const EXTRA_FIELD_NEW: u16 = u16::MAX;

/// `ZIP_EF_LOCAL`, `ZIP_EF_CENTRAL` and `ZIP_EF_BOTH`.
pub(crate) const EF_LOCAL: Flags = Flags::LOCAL;
pub(crate) const EF_CENTRAL: Flags = Flags::CENTRAL;
pub(crate) const EF_BOTH: Flags = Flags(Flags::LOCAL.0 | Flags::CENTRAL.0);

/// `ZIP_FL_FORCE_ZIP64`: force the Zip64 extra field (`_zip_dirent_write`).
pub(crate) const FL_FORCE_ZIP64: Flags = Flags(1024);
/// A local header is written before its data, and is not written again.
pub(crate) const FL_DATA_FOLLOWS: Flags = Flags(1 << 20);

/// `ZIP_FL_ENCODING_ALL`.
pub(crate) const FL_ENCODING_ALL: Flags =
    Flags(Flags::ENC_GUESS.0 | Flags::ENC_CP437.0 | Flags::ENC_UTF_8.0);

/// `ZIP_EXT_ATTRIB_DEFAULT`: a regular file, readable and writable by all.
pub(crate) const EXT_ATTRIB_DEFAULT: u32 = 0o100666 << 16;
/// `ZIP_EXT_ATTRIB_DEFAULT_DIR`: a directory, open to all.
pub(crate) const EXT_ATTRIB_DEFAULT_DIR: u32 = 0o040777 << 16;

/// `zip_encoding_type`: what a string's encoding is known or guessed to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Encoding {
    /// not yet analyzed
    Unknown,
    /// plain ASCII
    Ascii,
    /// is UTF-8
    Utf8Known,
    /// possibly UTF-8
    Utf8Guessed,
    /// Code Page 437
    Cp437,
    /// should be UTF-8 but isn't
    Error,
}

/// `zip_cdir_t`: the central directory, as read from the end of central
/// directory record and its entries.
pub(crate) struct Cdir {
    /// directory entries
    pub entry: Vec<Entry>,
    pub this_disk: u32,
    pub eocd_disk: u32,
    /// number of entries on this disk
    pub disk_entries: u64,
    /// number of entries on all disks
    pub num_entries: u64,
    /// size of central directory
    pub size: u64,
    /// offset of central directory in file
    pub offset: u64,
    /// offset of EOCD in file
    pub eocd_offset: u64,
    /// zip archive comment
    pub comment: Option<ZipString>,
    /// central directory in zip64 format
    pub is_zip64: bool,
}

/// `ZIP_DIRENT_*`: which fields of a dirent of changes are changed
/// (`ZIP_DIRENT_PASSWORD` comes with encryption).
pub(crate) mod changed {
    pub const COMP_METHOD: u32 = 0x0001;
    pub const FILENAME: u32 = 0x0002;
    pub const COMMENT: u32 = 0x0004;
    pub const EXTRA_FIELD: u32 = 0x0008;
    pub const ATTRIBUTES: u32 = 0x0010;
    pub const LAST_MOD: u32 = 0x0020;
    pub const ENCRYPTION_METHOD: u32 = 0x0040;
    pub const PASSWORD: u32 = 0x0080;
    pub const ALL: u32 = u32::MAX;
}

/// `zip_entry_t`: an entry of the archive as read, its changes, its new
/// data, and whether it is deleted. Boxed as libzip keeps pointers, so
/// that a directory sized from a large count of entries is small until the
/// entries are read.
#[derive(Clone, Default)]
pub(crate) struct Entry {
    pub orig: Option<Box<Dirent>>,
    pub changes: Option<Box<Dirent>>,
    /// the new data, shared as libzip shares a source it keeps
    pub source: Option<Arc<dyn DataSource>>,
    pub deleted: bool,
}

impl Entry {
    /// `ZIP_ENTRY_CHANGED`.
    pub(crate) fn changed(&self, f: u32) -> bool {
        self.changes.as_ref().is_some_and(|c| c.changed & f != 0)
    }

    /// `ZIP_ENTRY_DATA_CHANGED`: whether the entry has new data.
    pub(crate) fn data_changed(&self) -> bool {
        self.source.is_some()
    }

    /// `ZIP_ENTRY_HAS_CHANGES`.
    pub(crate) fn has_changes(&self) -> bool {
        self.data_changed() || self.deleted || self.changed(changed::ALL)
    }

    /// Drops the new data, and undeletes the entry: port of
    /// `_zip_unchange_data` (`zip_unchange_data.c`).
    pub(crate) fn unchange_data(&mut self) {
        self.source = None;
        self.deleted = false;
    }
}

impl<R> Archive<R> {
    /// `ZIP_IS_RDONLY`.
    pub(crate) fn is_rdonly(&self) -> bool {
        self.ch_flags.intersects(ArchiveFlags::RDONLY)
    }

    /// `ZIP_IS_TORRENTZIP`.
    pub(crate) fn is_torrentzip(&self) -> bool {
        self.flags.intersects(ArchiveFlags::IS_TORRENTZIP)
    }

    /// `ZIP_WANT_TORRENTZIP`.
    pub(crate) fn want_torrentzip(&self) -> bool {
        self.ch_flags.intersects(ArchiveFlags::WANT_TORRENTZIP)
    }
}
