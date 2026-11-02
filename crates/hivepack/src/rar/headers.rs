// hivepack::rar: a port of UnRAR 7.3.2 to Rust. UnRAR's license says:
//
// UnRAR source code may be used in any software to handle RAR archives
// without limitations free of charge, but cannot be used to develop RAR
// (WinRAR) compatible archiver and to re-create RAR compression algorithm,
// which is proprietary. Distribution of modified UnRAR source code in
// separate form or as a part of other software is permitted, provided that
// full text of this paragraph, starting from "UnRAR source code" words, is
// included in license, or in documentation if license is not available, and
// in source code comments of resulting package.

//! The headers of RAR archives and what their fields mean: UnRAR's
//! headers.hpp, headers5.hpp, headers.cpp, and the constants of
//! rardefs.hpp and crypt.hpp the headers need.

use crate::rar::time::RarTime;

/// Which RAR format an archive has.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Format {
    #[default]
    None,
    /// RAR 1.4, signature `RE~^`.
    Rar14,
    /// RAR 1.5 to 4.x, signature `Rar!\x1a\x07\x00`.
    Rar15,
    /// RAR 5.0 and later, signature `Rar!\x1a\x07\x01\x00`.
    Rar50,
    /// A signature for a format newer than this reader.
    Future,
}

pub const SIZEOF_MARKHEAD3: usize = 7;
pub const SIZEOF_MAINHEAD14: usize = 7;
pub const SIZEOF_MAINHEAD3: usize = 13;
pub const SIZEOF_FILEHEAD14: usize = 21;
pub const SIZEOF_FILEHEAD3: usize = 32;
pub const SIZEOF_SHORTBLOCKHEAD: usize = 7;
pub const SIZEOF_COMMHEAD: usize = 13;
pub const SIZEOF_MARKHEAD5: usize = 8;
pub const SIZEOF_SHORTBLOCKHEAD5: usize = 7;

pub const VER_PACK5: u32 = 50;
pub const VER_PACK7: u32 = 70;
pub const VER_UNKNOWN: u32 = 9999;

/// The size of data whose size is not known: UnRAR's `INT64NDF`.
pub const INT64NDF: i64 = 0x7fff_ffff_7fff_ffff;
pub const MAXPATHSIZE: usize = 0x10000;
pub const MAXSFXSIZE: u64 = 0x40_0000;
/// The largest dictionary UnRAR unpacks, 64 GB.
pub const UNPACK_MAX_DICT: u64 = 0x10_0000_0000;

// RAR 1.5 to 4.x main header flags.
pub const MHD_VOLUME: u32 = 0x0001;
pub const MHD_COMMENT: u32 = 0x0002;
pub const MHD_LOCK: u32 = 0x0004;
pub const MHD_SOLID: u32 = 0x0008;
pub const MHD_PACK_COMMENT: u32 = 0x0010;
pub const MHD_NEWNUMBERING: u32 = 0x0010;
pub const MHD_PROTECT: u32 = 0x0040;
pub const MHD_PASSWORD: u32 = 0x0080;
pub const MHD_FIRSTVOLUME: u32 = 0x0100;

// RAR 1.5 to 4.x file header flags.
pub const LHD_SPLIT_BEFORE: u32 = 0x0001;
pub const LHD_SPLIT_AFTER: u32 = 0x0002;
pub const LHD_PASSWORD: u32 = 0x0004;
pub const LHD_COMMENT: u32 = 0x0008;
pub const LHD_SOLID: u32 = 0x0010;
pub const LHD_WINDOWMASK: u32 = 0x00e0;
pub const LHD_DIRECTORY: u32 = 0x00e0;
pub const LHD_LARGE: u32 = 0x0100;
pub const LHD_UNICODE: u32 = 0x0200;
pub const LHD_SALT: u32 = 0x0400;
pub const LHD_VERSION: u32 = 0x0800;
pub const LHD_EXTTIME: u32 = 0x1000;
pub const SKIP_IF_UNKNOWN: u32 = 0x4000;
pub const LONG_BLOCK: u32 = 0x8000;

pub const EARC_NEXT_VOLUME: u32 = 0x0001;
pub const EARC_DATACRC: u32 = 0x0002;
pub const EARC_REVSPACE: u32 = 0x0004;
pub const EARC_VOLNUMBER: u32 = 0x0008;

// Header types: RAR 5's, then those of RAR 1.5 to 4.x. RAR 1.5 to 4.x's
// main, file, service and end headers are read as RAR 5's types.
pub const HEAD_MARK: u32 = 0x00;
pub const HEAD_MAIN: u32 = 0x01;
pub const HEAD_FILE: u32 = 0x02;
pub const HEAD_SERVICE: u32 = 0x03;
pub const HEAD_CRYPT: u32 = 0x04;
pub const HEAD_ENDARC: u32 = 0x05;
pub const HEAD_UNKNOWN: u32 = 0xff;
pub const HEAD3_MARK: u32 = 0x72;
pub const HEAD3_MAIN: u32 = 0x73;
pub const HEAD3_FILE: u32 = 0x74;
pub const HEAD3_CMT: u32 = 0x75;
pub const HEAD3_AV: u32 = 0x76;
pub const HEAD3_OLDSERVICE: u32 = 0x77;
pub const HEAD3_PROTECT: u32 = 0x78;
pub const HEAD3_SIGN: u32 = 0x79;
pub const HEAD3_SERVICE: u32 = 0x7a;
pub const HEAD3_ENDARC: u32 = 0x7b;

// RAR 2.9 and earlier service headers.
pub const EA_HEAD: u16 = 0x100;
pub const UO_HEAD: u16 = 0x101;
pub const NTACL_HEAD: u16 = 0x104;
pub const STREAM_HEAD: u16 = 0x105;

// Host systems: RAR 5's, then RAR 1.5 to 4.x's.
pub const HOST5_WINDOWS: u8 = 0;
pub const HOST5_UNIX: u8 = 1;
pub const HOST_MSDOS: u8 = 0;
pub const HOST_UNIX: u8 = 3;
pub const HOST_BEOS: u8 = 5;
pub const HOST_MAX: u8 = 6;

/// Which system an entry was archived on, whatever the format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HostSystem {
    Windows,
    Unix,
    #[default]
    Unknown,
}

/// What a link entry is: RAR 5's redirection types, which RAR 4 Unix
/// links are read as.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Redirection {
    #[default]
    None,
    UnixSymlink,
    WindowsSymlink,
    Junction,
    HardLink,
    FileCopy,
    Unknown,
}

impl Redirection {
    fn from_type(value: u64) -> Redirection {
        match value {
            0 => Redirection::None,
            1 => Redirection::UnixSymlink,
            2 => Redirection::WindowsSymlink,
            3 => Redirection::Junction,
            4 => Redirection::HardLink,
            5 => Redirection::FileCopy,
            _ => Redirection::Unknown,
        }
    }

    pub(crate) fn of(value: u64) -> Redirection {
        Redirection::from_type(value)
    }

    /// The number UnRAR gives it.
    pub fn number(self) -> u32 {
        match self {
            Redirection::None => 0,
            Redirection::UnixSymlink => 1,
            Redirection::WindowsSymlink => 2,
            Redirection::Junction => 3,
            Redirection::HardLink => 4,
            Redirection::FileCopy => 5,
            Redirection::Unknown => 6,
        }
    }
}

/// How an entry is encrypted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CryptMethod {
    #[default]
    None,
    Rar13,
    Rar15,
    Rar20,
    Rar30,
    Rar50,
    Unknown,
}

impl CryptMethod {
    /// The number UnRAR gives it.
    pub fn number(self) -> u32 {
        match self {
            CryptMethod::None => 0,
            CryptMethod::Rar13 => 1,
            CryptMethod::Rar15 => 2,
            CryptMethod::Rar20 => 3,
            CryptMethod::Rar30 => 4,
            CryptMethod::Rar50 => 5,
            CryptMethod::Unknown => 6,
        }
    }
}

// RAR 5 header flags.
pub const HFL_EXTRA: u32 = 0x0001;
pub const HFL_DATA: u32 = 0x0002;
pub const HFL_SKIPIFUNKNOWN: u32 = 0x0004;
pub const HFL_SPLITBEFORE: u32 = 0x0008;
pub const HFL_SPLITAFTER: u32 = 0x0010;
pub const HFL_CHILD: u32 = 0x0020;
pub const HFL_INHERITED: u32 = 0x0040;

pub const MHFL_VOLUME: u32 = 0x0001;
pub const MHFL_VOLNUMBER: u32 = 0x0002;
pub const MHFL_SOLID: u32 = 0x0004;
pub const MHFL_PROTECT: u32 = 0x0008;
pub const MHFL_LOCK: u32 = 0x0010;

pub const FHFL_DIRECTORY: u32 = 0x0001;
pub const FHFL_UTIME: u32 = 0x0002;
pub const FHFL_CRC32: u32 = 0x0004;
pub const FHFL_UNPUNKNOWN: u32 = 0x0008;

pub const EHFL_NEXTVOLUME: u32 = 0x0001;
pub const CHFL_CRYPT_PSWCHECK: u32 = 0x0001;

pub const FCI_SOLID: u32 = 0x0000_0040;
pub const FCI_RAR5_COMPAT: u32 = 0x0010_0000;

pub const MHEXTRA_LOCATOR: u64 = 0x01;
pub const MHEXTRA_METADATA: u64 = 0x02;
pub const MHEXTRA_LOCATOR_QLIST: u32 = 0x01;
pub const MHEXTRA_LOCATOR_RR: u32 = 0x02;
pub const MHEXTRA_METADATA_NAME: u32 = 0x01;
pub const MHEXTRA_METADATA_CTIME: u32 = 0x02;
pub const MHEXTRA_METADATA_UNIXTIME: u32 = 0x04;
pub const MHEXTRA_METADATA_UNIX_NS: u32 = 0x08;

pub const FHEXTRA_CRYPT: u64 = 0x01;
pub const FHEXTRA_HASH: u64 = 0x02;
pub const FHEXTRA_HTIME: u64 = 0x03;
pub const FHEXTRA_VERSION: u64 = 0x04;
pub const FHEXTRA_REDIR: u64 = 0x05;
pub const FHEXTRA_UOWNER: u64 = 0x06;
pub const FHEXTRA_SUBDATA: u64 = 0x07;

pub const FHEXTRA_HASH_BLAKE2: u32 = 0x00;
pub const FHEXTRA_HTIME_UNIXTIME: u8 = 0x01;
pub const FHEXTRA_HTIME_MTIME: u8 = 0x02;
pub const FHEXTRA_HTIME_CTIME: u8 = 0x04;
pub const FHEXTRA_HTIME_ATIME: u8 = 0x08;
pub const FHEXTRA_HTIME_UNIX_NS: u8 = 0x10;
pub const FHEXTRA_CRYPT_PSWCHECK: u32 = 0x01;
pub const FHEXTRA_CRYPT_HASHMAC: u32 = 0x02;
pub const FHEXTRA_REDIR_DIR: u32 = 0x01;
pub const FHEXTRA_UOWNER_UNAME: u32 = 0x01;
pub const FHEXTRA_UOWNER_GNAME: u32 = 0x02;
pub const FHEXTRA_UOWNER_NUMUID: u32 = 0x04;
pub const FHEXTRA_UOWNER_NUMGID: u32 = 0x08;

pub const SIZE_SALT50: usize = 16;
pub const SIZE_SALT30: usize = 8;
pub const SIZE_INITV: usize = 16;
pub const SIZE_PSWCHECK: usize = 8;
pub const SIZE_PSWCHECK_CSUM: usize = 4;
pub const CRYPT_BLOCK_SIZE: usize = 16;
pub const CRYPT_VERSION: u32 = 0;
pub const CRYPT5_KDF_LG2_COUNT_MAX: u32 = 24;
pub const SHA256_DIGEST_SIZE: usize = 32;
pub const BLAKE2_DIGEST_SIZE: usize = 32;

/// Service header names.
pub const SUBHEAD_TYPE_CMT: &str = "CMT";
pub const SUBHEAD_TYPE_QOPEN: &str = "QO";
pub const SUBHEAD_TYPE_RR: &str = "RR";
pub const SUBHEAD_FLAGS_INHERITED: u32 = 0x8000_0000;
pub const SUBHEAD_FLAGS_CMT_UNICODE: u32 = 1;

/// A string as UnRAR keeps one on Linux: `wchar_t`s, 32 bits each, which
/// a broken name can make into values that are not characters.
pub type WideString = Vec<u32>;

/// Which hash a file's data is checked with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HashType {
    #[default]
    None,
    /// RAR 1.4's 16-bit checksum.
    Rar14,
    Crc32,
    Blake2,
}

impl HashType {
    /// The number UnRAR gives it.
    pub fn number(self) -> u32 {
        match self {
            HashType::None => 0,
            HashType::Rar14 => 1,
            HashType::Crc32 => 2,
            HashType::Blake2 => 3,
        }
    }
}

/// A file's hash, as its header says it: `HashValue`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HashValue {
    pub kind: HashType,
    /// The CRC-32, or RAR 1.4's checksum.
    pub crc32: u32,
    /// BLAKE2sp.
    pub digest: [u8; BLAKE2_DIGEST_SIZE],
}

impl HashValue {
    /// `HashValue::Init`: the type, and the value of no data for CRCs. A
    /// BLAKE2sp digest is that of no data, which is computed with the data.
    pub(crate) fn init(&mut self, kind: HashType) {
        self.kind = kind;
        if matches!(kind, HashType::Rar14 | HashType::Crc32) {
            self.crc32 = 0;
        }
    }
}

/// What every header starts with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BaseBlock {
    pub head_crc: u32,
    /// What UnRAR keeps in its HEADER_TYPE enum, an `int`.
    pub header_type: u32,
    pub flags: u32,
    pub head_size: u32,
    pub skip_if_unknown: bool,
}

/// The signature: `MarkHeader`.
#[derive(Clone, Copy, Debug, Default)]
pub struct MarkHeader {
    pub mark: [u8; 8],
    pub head_size: u32,
}

/// The main archive header.
#[derive(Clone, Debug, Default)]
pub struct MainHeader {
    pub base: BaseBlock,
    pub high_pos_av: u16,
    pub pos_av: u32,
    pub comment_in_header: bool,
    /// RAR 1.4 only.
    pub pack_comment: bool,
    pub locator: bool,
    pub qopen_offset: u64,
    pub rr_offset: u64,
    pub orig_name: WideString,
    pub orig_time: RarTime,
}

/// A file or service header: `FileHeader`.
#[derive(Clone, Debug, Default)]
pub struct FileHeader {
    pub base: BaseBlock,
    pub data_size: u32,
    pub host_os: u8,
    pub unp_ver: u32,
    pub method: u8,
    /// The file's attributes, or for service headers their flags.
    pub file_attr: u32,
    pub file_name: WideString,
    pub sub_data: Vec<u8>,
    pub mtime: RarTime,
    pub ctime: RarTime,
    pub atime: RarTime,
    pub pack_size: i64,
    pub unp_size: i64,
    pub max_size: i64,
    pub file_hash: HashValue,
    pub file_flags: u32,
    pub split_before: bool,
    pub split_after: bool,
    pub unknown_unp_size: bool,
    pub encrypted: bool,
    pub crypt_method: CryptMethod,
    pub salt_set: bool,
    pub salt: [u8; SIZE_SALT50],
    pub init_v: [u8; SIZE_INITV],
    pub use_psw_check: bool,
    pub psw_check: [u8; SIZE_PSWCHECK],
    pub use_hash_key: bool,
    pub lg2_count: u32,
    pub solid: bool,
    pub dir: bool,
    pub comment_in_header: bool,
    pub version: bool,
    pub win_size: u64,
    pub inherited: bool,
    pub large_file: bool,
    pub sub_block: bool,
    pub hs_type: HostSystem,
    pub redir_type: Redirection,
    pub redir_name: WideString,
    pub dir_target: bool,
    pub unix_owner_set: bool,
    pub unix_owner_numeric: bool,
    pub unix_group_numeric: bool,
    pub unix_owner_name: Vec<u8>,
    pub unix_group_name: Vec<u8>,
    pub unix_owner_id: u32,
    pub unix_group_id: u32,
}

impl FileHeader {
    /// `FileHeader::Reset`: only these fields. The others keep what the
    /// previous header of the same kind set, as in UnRAR.
    pub(crate) fn reset(&mut self) {
        self.sub_data.clear();
        self.base.skip_if_unknown = false;
        self.file_hash.init(HashType::None);
        self.mtime.reset();
        self.atime.reset();
        self.ctime.reset();
        self.split_before = false;
        self.split_after = false;
        self.unknown_unp_size = false;
        self.file_attr = 0;
        self.crypt_method = CryptMethod::None;
        self.encrypted = false;
        self.salt_set = false;
        self.use_psw_check = false;
        self.use_hash_key = false;
        self.lg2_count = 0;
        self.solid = false;
        self.dir = false;
        self.win_size = 0;
        self.inherited = false;
        self.sub_block = false;
        self.comment_in_header = false;
        self.version = false;
        self.large_file = false;
        self.redir_type = Redirection::None;
        self.dir_target = false;
        self.unix_owner_set = false;
    }

    /// Whether the name is `name`: `CmpName`.
    pub fn is_named(&self, name: &str) -> bool {
        self.file_name
            .iter()
            .copied()
            .eq(name.chars().map(u32::from))
    }
}

/// The end of archive header.
#[derive(Clone, Copy, Debug, Default)]
pub struct EndArcHeader {
    pub base: BaseBlock,
    pub arc_data_crc: u32,
    pub vol_number: u32,
    pub next_volume: bool,
    pub data_crc: bool,
    pub rev_space: bool,
    pub store_vol_number: bool,
}

/// RAR 5's archive encryption header.
#[derive(Clone, Copy, Debug, Default)]
pub struct CryptHeader {
    pub base: BaseBlock,
    pub use_psw_check: bool,
    pub lg2_count: u32,
    pub salt: [u8; SIZE_SALT50],
    pub psw_check: [u8; SIZE_PSWCHECK],
}

/// RAR 2.x's comment header, inside a main or file header.
#[derive(Clone, Copy, Debug, Default)]
pub struct CommentHeader {
    pub base: BaseBlock,
    pub unp_size: u16,
    pub unp_ver: u8,
    pub method: u8,
    pub comm_crc: u16,
}

/// RAR 2.x's recovery record header.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProtectHeader {
    pub base: BaseBlock,
    pub data_size: u32,
    pub version: u8,
    pub rec_sectors: u16,
    pub total_blocks: u32,
    pub mark: [u8; 8],
}

/// RAR 2.9 and earlier's service header, and what its NTFS ACL and
/// stream kinds add.
#[derive(Clone, Debug, Default)]
pub struct SubBlockHeader {
    pub base: BaseBlock,
    pub data_size: u32,
    pub sub_type: u16,
    pub level: u8,
    pub unp_size: u32,
    pub unp_ver: u8,
    pub method: u8,
    /// The ACL's or the stream's CRC.
    pub crc: u32,
    pub stream_name: Vec<u8>,
}
