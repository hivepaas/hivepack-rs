//! The flags, constants and `zip_stat_t` of `zip.h`, with `zip_stat_init`
//! (`zip_stat_init.c`).

use std::ops::BitOr;

macro_rules! flag_type {
    ($(#[$doc:meta])* $name:ident, $repr:ty) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
        pub struct $name(pub $repr);

        impl $name {
            /// Whether every flag of `other` is set.
            pub fn contains(self, other: $name) -> bool {
                self.0 & other.0 == other.0
            }

            /// Whether any flag of `other` is set.
            pub fn intersects(self, other: $name) -> bool {
                self.0 & other.0 != 0
            }
        }

        impl BitOr for $name {
            type Output = $name;

            fn bitor(self, other: $name) -> $name {
                $name(self.0 | other.0)
            }
        }
    };
}

flag_type!(
    /// Flags for `zip_open`: `ZIP_CHECKCONS` and the others.
    OpenFlags,
    u32
);

impl OpenFlags {
    /// `ZIP_CREATE`: an empty archive if the source is not there (its
    /// length fails with `ENOENT`).
    pub const CREATE: OpenFlags = OpenFlags(1);
    /// `ZIP_EXCL`: fail with `ZIP_ER_EXISTS` if the source is there.
    pub const EXCL: OpenFlags = OpenFlags(2);
    /// `ZIP_CHECKCONS`: compare every local header with the central
    /// directory, and check more strictly.
    pub const CHECKCONS: OpenFlags = OpenFlags(4);
    /// `ZIP_TRUNCATE`: an empty archive in place of what the source has,
    /// which [`Archive::close_to`](crate::zip::Archive::close_to) then says to
    /// remove if no entries are added.
    pub const TRUNCATE: OpenFlags = OpenFlags(8);
    /// `ZIP_RDONLY`: open for reading only.
    pub const RDONLY: OpenFlags = OpenFlags(16);
}

flag_type!(
    /// Flags for looking up names, reading names and comments, stat and
    /// extra fields: `ZIP_FL_*`.
    Flags,
    u32
);

impl Flags {
    /// No flags.
    pub const NONE: Flags = Flags(0);
    /// `ZIP_FL_NOCASE`: ignore case on name lookup.
    pub const NOCASE: Flags = Flags(1);
    /// `ZIP_FL_NODIR`: ignore directory component.
    pub const NODIR: Flags = Flags(2);
    /// `ZIP_FL_COMPRESSED`: read compressed data.
    pub const COMPRESSED: Flags = Flags(4);
    /// `ZIP_FL_UNCHANGED`: use original data, ignoring changes.
    pub const UNCHANGED: Flags = Flags(8);
    /// `ZIP_FL_ENCRYPTED`: read encrypted data (implies `COMPRESSED`).
    pub const ENCRYPTED: Flags = Flags(32);
    /// `ZIP_FL_ENC_GUESS`: guess string encoding (the default).
    pub const ENC_GUESS: Flags = Flags(0);
    /// `ZIP_FL_ENC_RAW`: get unmodified string.
    pub const ENC_RAW: Flags = Flags(64);
    /// `ZIP_FL_ENC_STRICT`: follow specification strictly.
    pub const ENC_STRICT: Flags = Flags(128);
    /// `ZIP_FL_LOCAL`: in local header.
    pub const LOCAL: Flags = Flags(256);
    /// `ZIP_FL_CENTRAL`: in central directory.
    pub const CENTRAL: Flags = Flags(512);
    /// `ZIP_FL_ENC_UTF_8`: string is UTF-8 encoded.
    pub const ENC_UTF_8: Flags = Flags(2048);
    /// `ZIP_FL_ENC_CP437`: string is CP437 encoded.
    pub const ENC_CP437: Flags = Flags(4096);
    /// `ZIP_FL_OVERWRITE`: when adding, replace the entry with the name.
    pub const OVERWRITE: Flags = Flags(8192);
}

flag_type!(
    /// An archive's flags: `ZIP_AFL_*`.
    ArchiveFlags,
    u32
);

impl ArchiveFlags {
    /// `ZIP_AFL_RDONLY`: read only, which cannot be cleared.
    pub const RDONLY: ArchiveFlags = ArchiveFlags(2);
    /// `ZIP_AFL_IS_TORRENTZIP`: the archive is torrentzipped.
    pub const IS_TORRENTZIP: ArchiveFlags = ArchiveFlags(4);
    /// `ZIP_AFL_WANT_TORRENTZIP`: write the archive in torrentzip format.
    pub const WANT_TORRENTZIP: ArchiveFlags = ArchiveFlags(8);
    /// `ZIP_AFL_CREATE_OR_KEEP_FILE_FOR_EMPTY_ARCHIVE`: write an archive
    /// with no entries, instead of removing it.
    pub const CREATE_OR_KEEP_FILE_FOR_EMPTY_ARCHIVE: ArchiveFlags = ArchiveFlags(16);
}

/// Compression methods: `ZIP_CM_*`.
pub mod cm {
    /// better of deflate or store, for
    /// [`Archive::set_file_compression`](crate::zip::Archive::set_file_compression)
    pub const DEFAULT: i32 = -1;
    /// stored (uncompressed)
    pub const STORE: u16 = 0;
    /// shrunk
    pub const SHRINK: u16 = 1;
    /// reduced with factor 1
    pub const REDUCE_1: u16 = 2;
    /// reduced with factor 2
    pub const REDUCE_2: u16 = 3;
    /// reduced with factor 3
    pub const REDUCE_3: u16 = 4;
    /// reduced with factor 4
    pub const REDUCE_4: u16 = 5;
    /// imploded
    pub const IMPLODE: u16 = 6;
    /// deflated
    pub const DEFLATE: u16 = 8;
    /// deflate64
    pub const DEFLATE64: u16 = 9;
    /// PKWARE imploding
    pub const PKWARE_IMPLODE: u16 = 10;
    /// compressed using BZIP2 algorithm
    pub const BZIP2: u16 = 12;
    /// LZMA (EFS)
    pub const LZMA: u16 = 14;
    /// compressed using IBM TERSE (new)
    pub const TERSE: u16 = 18;
    /// IBM LZ77 z Architecture (PFS)
    pub const LZ77: u16 = 19;
    /// LZMA2
    pub const LZMA2: u16 = 33;
    /// Zstandard compressed data
    pub const ZSTD: u16 = 93;
    /// XZ compressed data
    pub const XZ: u16 = 95;
    /// Compressed Jpeg data
    pub const JPEG: u16 = 96;
    /// WavPack compressed data
    pub const WAVPACK: u16 = 97;
    /// PPMd version I, Rev 1
    pub const PPMD: u16 = 98;
}

/// Encryption methods: `ZIP_EM_*`.
pub mod em {
    /// not encrypted
    pub const NONE: u16 = 0;
    /// traditional PKWARE encryption
    pub const TRAD_PKWARE: u16 = 1;
    /// Winzip AES encryption, 128-bit key
    pub const AES_128: u16 = 0x0101;
    /// Winzip AES encryption, 192-bit key
    pub const AES_192: u16 = 0x0102;
    /// Winzip AES encryption, 256-bit key
    pub const AES_256: u16 = 0x0103;
    /// unknown algorithm
    pub const UNKNOWN: u16 = 0xffff;
}

/// The systems an entry can be made on: `ZIP_OPSYS_*`.
pub mod opsys {
    pub const DOS: u8 = 0x00;
    pub const AMIGA: u8 = 0x01;
    pub const OPENVMS: u8 = 0x02;
    pub const UNIX: u8 = 0x03;
    pub const VM_CMS: u8 = 0x04;
    pub const ATARI_ST: u8 = 0x05;
    pub const OS_2: u8 = 0x06;
    pub const MACINTOSH: u8 = 0x07;
    pub const Z_SYSTEM: u8 = 0x08;
    pub const CPM: u8 = 0x09;
    pub const WINDOWS_NTFS: u8 = 0x0a;
    pub const MVS: u8 = 0x0b;
    pub const VSE: u8 = 0x0c;
    pub const ACORN_RISC: u8 = 0x0d;
    pub const VFAT: u8 = 0x0e;
    pub const ALTERNATE_MVS: u8 = 0x0f;
    pub const BEOS: u8 = 0x10;
    pub const TANDEM: u8 = 0x11;
    pub const OS_400: u8 = 0x12;
    pub const OS_X: u8 = 0x13;
    /// `ZIP_OPSYS_DEFAULT`
    pub const DEFAULT: u8 = UNIX;
}

/// Which fields of a [`Stat`] are set: `ZIP_STAT_*`.
pub mod stat {
    pub const NAME: u64 = 0x0001;
    pub const INDEX: u64 = 0x0002;
    pub const SIZE: u64 = 0x0004;
    pub const COMP_SIZE: u64 = 0x0008;
    pub const MTIME: u64 = 0x0010;
    pub const CRC: u64 = 0x0020;
    pub const COMP_METHOD: u64 = 0x0040;
    pub const ENCRYPTION_METHOD: u64 = 0x0080;
    pub const FLAGS: u64 = 0x0100;
}

/// What is known about an entry: `zip_stat_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat<'a> {
    /// Which fields have valid values: [`stat`] bits.
    pub valid: u64,
    /// The name of the file.
    pub name: Option<&'a [u8]>,
    /// The index within the archive.
    pub index: u64,
    /// The size of the file (uncompressed).
    pub size: u64,
    /// The size of the file (compressed).
    pub comp_size: u64,
    /// The modification time, in seconds since 1970.
    pub mtime: i64,
    /// The CRC of the file's data.
    pub crc: u32,
    /// The compression method used.
    pub comp_method: u16,
    /// The encryption method used.
    pub encryption_method: u16,
    /// Reserved for future use.
    pub flags: u32,
}

impl Default for Stat<'_> {
    /// Nothing known: port of `zip_stat_init`.
    fn default() -> Self {
        Stat {
            valid: 0,
            name: None,
            index: u64::MAX,
            size: 0,
            comp_size: 0,
            mtime: -1,
            crc: 0,
            comp_method: cm::STORE,
            encryption_method: em::NONE,
            flags: 0,
        }
    }
}

/// Takes what `src` knows into `dst`, all but the name: port of
/// `_zip_stat_merge`.
pub(crate) fn stat_merge(dst: &mut Stat<'_>, src: &Stat<'_>) {
    if src.valid & stat::INDEX != 0 {
        dst.index = src.index;
    }
    if src.valid & stat::SIZE != 0 {
        dst.size = src.size;
    }
    if src.valid & stat::COMP_SIZE != 0 {
        dst.comp_size = src.comp_size;
    }
    if src.valid & stat::MTIME != 0 {
        dst.mtime = src.mtime;
    }
    if src.valid & stat::CRC != 0 {
        dst.crc = src.crc;
    }
    if src.valid & stat::COMP_METHOD != 0 {
        dst.comp_method = src.comp_method;
    }
    if src.valid & stat::ENCRYPTION_METHOD != 0 {
        dst.encryption_method = src.encryption_method;
    }
    if src.valid & stat::FLAGS != 0 {
        dst.flags = src.flags;
    }
    dst.valid |= src.valid;
}
