//! Port of libarchive's `archive_read_support_format_xar.c`: the reader of
//! XAR archives, the container of macOS's `.pkg` installers and `.xip`
//! files.
//!
//! A XAR archive is a 28-byte header, a table of contents (TOC) in XML
//! compressed with zlib, and a heap: the files' data and extended
//! attributes, each where the TOC says, compressed or not, with checksums.
//! The TOC's own checksum is in the heap too, where the TOC says.
//!
//! The reader reads the whole TOC first, through libxml2's reader
//! ([`crate::xar::xml`]), into a heap of files ordered by their `id`; then it
//! gives the files in that order, moving to each one's data in the heap.
//!
//! The C keeps its files in lists linked through pointers inside them;
//! here files live in a `Vec` and point at each other by index, with the
//! same links, so that a damaged TOC takes the same path through them.

use std::io::Read;

use crate::bzip2::{Decompress, InBuffer as BzIn, OutBuffer as BzOut, Status as BzStatus};
use crate::crypto::{Md5, Sha1, Sha256, Sha512};
use crate::deflate::{Flush, InBuffer, Inflate, OutBuffer, Status};
use crate::xz::{
    Action, CONCATENATED, InBuffer as XzIn, OutBuffer as XzOut, Status as XzStatus, Stream,
};

use crate::xar::entry::{
    AE_IFBLK, AE_IFCHR, AE_IFDIR, AE_IFIFO, AE_IFLNK, AE_IFMT, AE_IFREG, AE_IFSOCK, Entry, Xattr,
};
use crate::xar::error::{Error, Warning};
use crate::xar::read::{Input, Seek};
use crate::xar::string::{strncat, utf8_to_utf8};
use crate::xar::xml::{
    Severity, TextReader, XML_READER_TYPE_ELEMENT, XML_READER_TYPE_END_ELEMENT,
    XML_READER_TYPE_TEXT, XmlIo,
};

/// `HEADER_MAGIC`: "xar!".
const HEADER_MAGIC: u32 = 0x7861_7221;
/// `HEADER_SIZE`.
const HEADER_SIZE: usize = 28;
/// `HEADER_VERSION`.
const HEADER_VERSION: u16 = 1;

/// The checksum algorithms of the header and the TOC.
const CKSUM_NONE: i32 = 0;
const CKSUM_SHA1: i32 = 1;
const CKSUM_MD5: i32 = 2;
const CKSUM_SHA256: i32 = 3;
const CKSUM_SHA512: i32 = 4;

/// `MAX_SUM_SIZE`: the longest checksum kept.
const MAX_SUM_SIZE: usize = 64;

/// `OUTBUFF_SIZE`: how much is decompressed at a time.
pub(crate) const OUTBUFF_SIZE: usize = 64 * 1024;

/// How much input a decompression is given at a time; libarchive gives all
/// it has, in memory, which the decoders take the same way.
const PIECE: usize = 64 * 1024;

/// The bits of `has`: what the TOC said of a file.
const HAS_DATA: u32 = 0x00001;
const HAS_PATHNAME: u32 = 0x00002;
const HAS_SYMLINK: u32 = 0x00004;
const HAS_TIME: u32 = 0x00008;
const HAS_UID: u32 = 0x00010;
const HAS_GID: u32 = 0x00020;
const HAS_MODE: u32 = 0x00040;
const HAS_TYPE: u32 = 0x00080;
const HAS_DEV: u32 = 0x00100;
const HAS_DEVMAJOR: u32 = 0x00200;
const HAS_DEVMINOR: u32 = 0x00400;
const HAS_INO: u32 = 0x00800;
const HAS_FFLAGS: u32 = 0x01000;
const HAS_XATTR: u32 = 0x02000;
const HAS_ACL: u32 = 0x04000;
const HAS_CTIME: u32 = 0x08000;
const HAS_MTIME: u32 = 0x10000;
const HAS_ATIME: u32 = 0x20000;

fn be16(p: &[u8]) -> u16 {
    u16::from_be_bytes([p[0], p[1]])
}

fn be32(p: &[u8]) -> u32 {
    u32::from_be_bytes([p[0], p[1], p[2], p[3]])
}

fn be64(p: &[u8]) -> u64 {
    u64::from_be_bytes([p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]])
}

/// `enum enctype`: how data is compressed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum EncType {
    #[default]
    None,
    Gzip,
    Bzip2,
    Lzma,
    Xz,
}

/// `struct chksumval`: a checksum from the TOC.
#[derive(Clone, Copy, Debug)]
struct ChksumVal {
    alg: i32,
    /// What `atohex` gave: `usize::MAX` for a value that is not hex.
    len: usize,
    val: [u8; MAX_SUM_SIZE],
}

impl Default for ChksumVal {
    fn default() -> ChksumVal {
        ChksumVal {
            alg: CKSUM_NONE,
            len: 0,
            val: [0; MAX_SUM_SIZE],
        }
    }
}

/// `struct chksumwork`: a checksum being computed (`archive_digest.c`).
#[derive(Clone, Debug, Default)]
enum ChksumWork {
    #[default]
    None,
    Sha1(Sha1),
    Md5(Md5),
    Sha256(Sha256),
    Sha512(Sha512),
}

impl ChksumWork {
    /// `_checksum_init`.
    fn init(alg: i32) -> Option<ChksumWork> {
        Some(match alg {
            CKSUM_NONE => ChksumWork::None,
            CKSUM_SHA1 => ChksumWork::Sha1(Sha1::new()),
            CKSUM_MD5 => ChksumWork::Md5(Md5::new()),
            CKSUM_SHA256 => ChksumWork::Sha256(Sha256::new()),
            CKSUM_SHA512 => ChksumWork::Sha512(Sha512::new()),
            _ => return None,
        })
    }

    /// `_checksum_update`.
    fn update(&mut self, data: &[u8]) {
        match self {
            ChksumWork::None => {}
            ChksumWork::Sha1(h) => h.update(data),
            ChksumWork::Md5(h) => h.update(data),
            ChksumWork::Sha256(h) => h.update(data),
            ChksumWork::Sha512(h) => h.update(data),
        }
    }

    /// `_checksum_final`: whether the digest is `val[..len]`.
    fn finish(&self, val: &[u8], len: usize) -> bool {
        fn check(sum: &[u8], val: &[u8], len: usize) -> bool {
            len == sum.len() && val.len() >= sum.len() && val[..sum.len()] == *sum
        }
        match self {
            ChksumWork::None => true,
            ChksumWork::Sha1(h) => check(&h.out(), val, len),
            ChksumWork::Md5(h) => check(&h.out(), val, len),
            ChksumWork::Sha256(h) => check(&h.out(), val, len),
            ChksumWork::Sha512(h) => check(&h.out(), val, len),
        }
    }
}

/// libarchive's `struct archive_string` as the reader uses it: a buffer,
/// unallocated until something is written, and its bytes.
#[derive(Clone, Debug, Default)]
struct ArchiveString {
    s: Option<Vec<u8>>,
}

impl ArchiveString {
    /// `archive_strncpy`.
    fn copy(&mut self, src: &[u8]) {
        let s = self.s.get_or_insert_with(Vec::new);
        s.clear();
        strncat(s, src);
    }

    /// `archive_strlen`.
    fn len(&self) -> usize {
        self.s.as_ref().map_or(0, Vec::len)
    }

    fn bytes(&self) -> &[u8] {
        self.s.as_deref().unwrap_or(b"")
    }
}

/// `struct xattr`: an extended attribute's record in the TOC.
#[derive(Clone, Debug, Default)]
struct XattrRec {
    name: ArchiveString,
    id: u64,
    length: u64,
    offset: u64,
    size: u64,
    encoding: EncType,
    a_sum: ChksumVal,
    e_sum: ChksumVal,
    fstype: ArchiveString,
}

/// A file's index in [`Xar::files`].
type Fid = usize;

/// `struct xar_file`: a file's record in the TOC.
#[derive(Clone, Debug, Default)]
struct XarFile {
    parent: Option<Fid>,
    /// The link of the hard links' lists.
    hdnext: Option<Fid>,
    subdirs: i32,
    has: u32,
    id: u64,
    length: u64,
    offset: u64,
    size: u64,
    encoding: EncType,
    a_sum: ChksumVal,
    e_sum: ChksumVal,
    pathname: ArchiveString,
    symlink: ArchiveString,
    ctime: i64,
    mtime: i64,
    atime: i64,
    uname: ArchiveString,
    uid: i64,
    gname: ArchiveString,
    gid: i64,
    mode: u32,
    dev: u64,
    devmajor: u64,
    devminor: u64,
    ino64: i64,
    fflags_text: ArchiveString,
    link: u32,
    nlink: u32,
    hardlink: ArchiveString,
    /// `xattr_list`, by `id`.
    xattr_list: Vec<XattrRec>,
}

/// `struct hdlink`: the hard links to one original, by its `id`.
#[derive(Clone, Copy, Debug)]
struct Hdlink {
    id: u32,
    cnt: i32,
    files: Option<Fid>,
}

/// `enum xmlstatus`: where the TOC's parse is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum XmlStatus {
    #[default]
    Init,
    Xar,
    Toc,
    TocCreationTime,
    TocChecksum,
    TocChecksumOffset,
    TocChecksumSize,
    TocFile,
    FileData,
    FileDataLength,
    FileDataOffset,
    FileDataSize,
    FileDataEncoding,
    FileDataAChecksum,
    FileDataEChecksum,
    FileDataContent,
    FileEa,
    FileEaLength,
    FileEaOffset,
    FileEaSize,
    FileEaEncoding,
    FileEaAChecksum,
    FileEaEChecksum,
    FileEaName,
    FileEaFstype,
    FileCtime,
    FileMtime,
    FileAtime,
    FileGroup,
    FileGid,
    FileUser,
    FileUid,
    FileMode,
    FileDevice,
    FileDeviceMajor,
    FileDeviceMinor,
    FileDeviceno,
    FileInode,
    FileLink,
    FileType,
    FileName,
    FileAcl,
    FileAclDefault,
    FileAclAccess,
    FileAclAppleextended,
    FileFlags,
    /// One of the BSD flags, by its element's name.
    FileFlag(&'static str),
    FileExt2,
    /// One of the Linux flags, by its element's name.
    FileExt2Flag(&'static str),
    Unknown,
}

/// The BSD flags: the element in `<flags>`, and libarchive's name for it
/// (`xml_parse_file_flags`).
const FILE_FLAGS: [(&str, &str); 10] = [
    ("UserNoDump", "nodump"),
    ("UserImmutable", "uimmutable"),
    ("UserAppend", "uappend"),
    ("UserOpaque", "opaque"),
    ("UserNoUnlink", "nouunlink"),
    ("SystemArchived", "archived"),
    ("SystemImmutable", "simmutable"),
    ("SystemAppend", "sappend"),
    ("SystemNoUnlink", "nosunlink"),
    ("SystemSnapshot", "snapshot"),
];

/// The Linux flags in `<ext2>` (`xml_parse_file_ext2`).
const EXT2_FLAGS: [(&str, &str); 20] = [
    ("SecureDeletion", "securedeletion"),
    ("Undelete", "nouunlink"),
    ("Compress", "compress"),
    ("Synchronous", "sync"),
    ("Immutable", "simmutable"),
    ("AppendOnly", "sappend"),
    ("NoDump", "nodump"),
    ("NoAtime", "noatime"),
    ("CompDirty", "compdirty"),
    ("CompBlock", "comprblk"),
    ("NoCompBlock", "nocomprblk"),
    ("CompError", "comperr"),
    ("BTree", "btree"),
    ("HashIndexed", "hashidx"),
    ("iMagic", "imagic"),
    ("Journaled", "journal"),
    ("NoTail", "notail"),
    ("DirSync", "dirsync"),
    ("TopDir", "topdir"),
    ("Reserved", "reserved"),
];

/// `struct xmlattr`: an attribute as `xml2_xmlattr_setup` gives it.
struct XmlAttr {
    name: Vec<u8>,
    value: Vec<u8>,
}

/// The decompressor of `decompression_init`.
#[derive(Default)]
enum Decoder {
    #[default]
    None,
    Gzip(Inflate),
    /// libbzip2's stream, and whether `BZ2_bzDecompressEnd` ended it.
    Bzip2(Box<Decompress>, bool),
    /// liblzma's stream, or `None` once `lzma_end` ended it.
    Lzma(Option<Box<Stream>>),
}

impl core::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Decoder::None => "None",
            Decoder::Gzip(_) => "Gzip",
            Decoder::Bzip2(..) => "Bzip2",
            Decoder::Lzma(_) => "Lzma",
        })
    }
}

/// What a step of finding the next entry gave.
pub(crate) enum Next {
    Entry(Box<Entry>),
    Eof,
}

/// What a call of `xar_read_data` gave.
pub(crate) enum Data {
    /// This many bytes are in [`Xar::block`] (from the start).
    Block(usize),
    Eof,
}

/// `struct xar`: the reader's state.
#[derive(Debug, Default)]
pub(crate) struct Xar {
    /// `offset`: the position in the archive.
    offset: u64,
    /// `h_base`: where the heap starts.
    h_base: u64,
    end_of_file: bool,
    xmlsts: XmlStatus,
    xmlsts_unknown: XmlStatus,
    /// `unknowntags`: the names of the unknown elements being read.
    unknowntags: Vec<Vec<u8>>,
    base64text: bool,
    toc_remaining: u64,
    toc_total: u64,
    toc_chksum_offset: u64,
    toc_chksum_size: u64,
    rd_encoding: EncType,
    decoder: Decoder,
    a_sumwrk: ChksumWork,
    e_sumwrk: ChksumWork,
    /// Every file record made.
    files: Vec<XarFile>,
    /// `file`: the file being read (in the TOC, then from the heap).
    file: Option<Fid>,
    /// `xattr`: the extended attribute being read in the TOC, as the
    /// file's and the index in its list.
    xattr: Option<(Fid, usize)>,
    /// `file_queue`: a heap by `id`.
    file_queue: Vec<Fid>,
    hdlink_orgs: Option<Fid>,
    /// The end of the list of originals (not in libarchive).
    hdlink_orgs_last: Option<Fid>,
    hdlink_list: Vec<Hdlink>,
    entry_init: bool,
    entry_total: u64,
    entry_remaining: u64,
    entry_unconsumed: u64,
    entry_size: u64,
    pub(crate) entry_encoding: EncType,
    entry_a_sum: ChksumVal,
    entry_e_sum: ChksumVal,
    /// `outbuff`: what the last call decompressed.
    pub(crate) block: Vec<u8>,
    /// The last message libarchive set since the entry began (its error
    /// string), which a failure without one of its own keeps.
    pub(crate) last_message: Option<Vec<u8>>,
    /// `archive_format`: set once the TOC is read.
    pub(crate) format_set: bool,
}

/// `atou64`: the number in the first `p.len()` bytes, in `base`, up to the
/// first byte that is not a digit; `None` if it overflows 64 bits.
pub(crate) fn atou64(p: &[u8], base: u64) -> Option<u64> {
    let mut l: u64 = 0;
    for &c in p {
        let digit = i32::from(c) - i32::from(b'0');
        if digit < 0 || digit as u64 >= base {
            break;
        }
        l = l.checked_mul(base)?.checked_add(digit as u64)?;
    }
    Some(l)
}

/// `atohex`: the bytes of a hexadecimal string, as many as fit in `b`;
/// `usize::MAX` (the C's `(size_t)-1`) at a byte that is not hex.
pub(crate) fn atohex(b: &mut [u8], p: &[u8]) -> usize {
    fn digit(c: u8) -> Option<u8> {
        match c {
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            b'0'..=b'9' => Some(c - b'0'),
            _ => None,
        }
    }
    let mut n = 0;
    let mut i = 0;
    while n < b.len() && p.len() - i > 1 {
        let (Some(hi), Some(lo)) = (digit(p[i]), digit(p[i + 1])) else {
            return usize::MAX;
        };
        b[n] = (hi << 4) | lo;
        n += 1;
        i += 2;
    }
    n
}

/// `time_from_tm` with `timegm`, as glibc computes it: the fields may be
/// past their ranges (February 31 is March 3).
fn timegm(year: i64, mon: i64, mday: i64, hour: i64, min: i64, sec: i64) -> i64 {
    let mut year = year;
    let mut month = mon;
    year += if month >= 0 {
        month / 12
    } else {
        -((11 - month) / 12)
    };
    month = ((month % 12) + 12) % 12 + 1;
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + (153 * mp + 2) / 5;
    let days = era * 146_097 + doe - 719_468 + mday - 1;
    days * 86400 + hour * 3600 + min * 60 + sec
}

/// `parse_time`: "YYYY-MM-DDThh:mm:ssZ" in seconds since 1970; 0 for what
/// is not that.
pub(crate) fn parse_time(p: &[u8]) -> i64 {
    if p.len() != 20 {
        return 0;
    }
    let field = |at: usize, n: usize| atou64(&p[at..at + n], 10);
    let Some(year) = field(0, 4).filter(|&y| y >= 1900) else {
        return 0;
    };
    if p[4] != b'-' {
        return 0;
    }
    let Some(mon) = field(5, 2).filter(|&m| (1..=12).contains(&m)) else {
        return 0;
    };
    if p[7] != b'-' {
        return 0;
    }
    let Some(mday) = field(8, 2).filter(|&d| (1..=31).contains(&d)) else {
        return 0;
    };
    if p[10] != b'T' {
        return 0;
    }
    let Some(hour) = field(11, 2).filter(|&h| h <= 23) else {
        return 0;
    };
    if p[13] != b':' {
        return 0;
    }
    let Some(min) = field(14, 2).filter(|&m| m <= 59) else {
        return 0;
    };
    if p[16] != b':' {
        return 0;
    }
    let Some(sec) = field(17, 2).filter(|&s| s <= 60) else {
        return 0;
    };
    // The 'Z' is not checked.
    timegm(
        year as i64,
        mon as i64 - 1,
        mday as i64,
        hour as i64,
        min as i64,
        sec as i64,
    )
}

/// `base64`: the values of the base64 alphabet.
fn base64(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// `strappend_base64`: the bytes of `s`, decoded, appended to `as`
/// through a 256-byte buffer, each of whose fills stops at a NUL as
/// `archive_strncat` does; decoding stops at the first byte that is not
/// base64. Whether anything was appended: libarchive's string has a
/// buffer, and the entry a path, only if it was.
pub(crate) fn strappend_base64(out: &mut Vec<u8>, s: &[u8]) -> bool {
    let mut appended = false;
    let mut buff = [0u8; 256];
    let mut len = 0;
    let mut b = 0;
    let mut l = s.len();
    while l > 1 {
        let (Some(v0), Some(v1)) = (base64(s[b]), base64(s[b + 1])) else {
            break;
        };
        let mut n = (v0 << 18) | (v1 << 12);
        b += 2;
        buff[len] = (n >> 16) as u8;
        len += 1;
        l -= 2;
        if l > 0 {
            let Some(v) = base64(s[b]) else {
                break;
            };
            n |= v << 6;
            b += 1;
            buff[len] = ((n >> 8) & 0xff) as u8;
            len += 1;
            l -= 1;
        }
        if l > 0 {
            let Some(v) = base64(s[b]) else {
                break;
            };
            n |= v;
            b += 1;
            buff[len] = (n & 0xff) as u8;
            len += 1;
            l -= 1;
        }
        if len + 3 >= buff.len() {
            strncat(out, &buff[..len]);
            appended = true;
            len = 0;
        }
    }
    if len > 0 {
        strncat(out, &buff[..len]);
        appended = true;
    }
    appended
}

/// `is_string`: whether `data` is `known`.
fn is_string(known: &str, data: &[u8]) -> bool {
    known.as_bytes() == data
}

/// `getencoding`: the last `style` attribute that names an encoding.
fn getencoding(list: &[XmlAttr]) -> EncType {
    let mut encoding = EncType::None;
    for attr in list.iter().filter(|a| a.name == b"style") {
        match attr.value.as_slice() {
            b"application/octet-stream" => encoding = EncType::None,
            b"application/x-gzip" => encoding = EncType::Gzip,
            b"application/x-bzip2" => encoding = EncType::Bzip2,
            b"application/x-lzma" => encoding = EncType::Lzma,
            b"application/x-xz" => encoding = EncType::Xz,
            _ => {}
        }
    }
    encoding
}

/// `getsumalgorithm`: the last `style` attribute that names a checksum,
/// in any case.
fn getsumalgorithm(list: &[XmlAttr]) -> i32 {
    let mut alg = CKSUM_NONE;
    for attr in list.iter().filter(|a| a.name == b"style") {
        // The C reads the C string's bytes; past its end, its NUL.
        let v = |i: usize| attr.value.get(i).copied().unwrap_or(0);
        if v(0).eq_ignore_ascii_case(&b's')
            && v(1).eq_ignore_ascii_case(&b'h')
            && v(2).eq_ignore_ascii_case(&b'a')
        {
            if v(3) == b'1' && v(4) == 0 {
                alg = CKSUM_SHA1;
            } else if v(3) == b'2' && v(4) == b'5' && v(5) == b'6' && v(6) == 0 {
                alg = CKSUM_SHA256;
            } else if v(3) == b'5' && v(4) == b'1' && v(5) == b'2' && v(6) == 0 {
                alg = CKSUM_SHA512;
            }
        }
        if v(0).eq_ignore_ascii_case(&b'm')
            && v(1).eq_ignore_ascii_case(&b'd')
            && v(2) == b'5'
            && v(3) == 0
        {
            alg = CKSUM_MD5;
        }
    }
    alg
}

/// What one call of `decompress` did: input used, output made.
struct Decompressed {
    used: usize,
    out: usize,
}

impl Xar {
    pub(crate) fn new() -> Xar {
        Xar::default()
    }

    /// `archive_set_error`: the message libarchive's error string now has.
    fn set_error(&mut self, message: &[u8]) {
        self.last_message = Some(message.to_vec());
    }

    /// A failure, with its message kept as the last one.
    fn fail(&mut self, e: Error) -> Error {
        if let Some(m) = e.message() {
            self.set_error(&m);
        }
        e
    }

    /// `ARCHIVE_FATAL` without a message of its own.
    fn unspecified(&self) -> Error {
        Error::Unspecified(self.last_message.clone())
    }

    /// `xar_bid`: 128 for a XAR archive, 0 if not, -1 if the input is too
    /// short to tell.
    pub(crate) fn bid<R: Read>(input: &mut Input<R>) -> Result<i32, Error> {
        let h = match input.ahead(HEADER_SIZE)? {
            Ok(h) => h,
            Err(_) => return Ok(-1),
        };
        if be32(h) != HEADER_MAGIC {
            return Ok(0);
        }
        if be16(&h[4..]) as usize != HEADER_SIZE {
            return Ok(0);
        }
        if be16(&h[6..]) != HEADER_VERSION {
            return Ok(0);
        }
        match be32(&h[24..]) as i32 {
            CKSUM_NONE | CKSUM_SHA1 | CKSUM_MD5 | CKSUM_SHA256 | CKSUM_SHA512 => Ok(128),
            _ => Ok(0),
        }
    }

    /// `read_toc`: the header, the TOC and its checksum, and the hard links
    /// put together.
    fn read_toc<R: Read>(&mut self, input: &mut Input<R>) -> Result<(), Error> {
        let b = match input.ahead(HEADER_SIZE) {
            Ok(Ok(b)) => b,
            Ok(Err(_)) => return Err(self.fail(Error::TruncatedHeader)),
            Err(Error::Unspecified(_)) => return Err(self.unspecified()),
            Err(e) => return Err(e),
        };
        if be32(b) != HEADER_MAGIC {
            return Err(self.fail(Error::InvalidMagic));
        }
        if be16(&b[6..]) != HEADER_VERSION {
            let version = be16(&b[6..]);
            return Err(self.fail(Error::UnsupportedVersion(version)));
        }
        let toc_compressed_size = be64(&b[8..]);
        self.toc_remaining = toc_compressed_size;
        let toc_uncompressed_size = be64(&b[16..]);
        let toc_chksum_alg = be32(&b[24..]) as i32;
        let _ = input.consume(HEADER_SIZE as i64);
        self.offset += HEADER_SIZE as u64;
        self.toc_total = 0;

        // The TOC.
        self.move_reading_point(input, HEADER_SIZE as u64)?;
        self.rd_contents_init(EncType::Gzip, toc_chksum_alg, CKSUM_NONE)?;
        self.xml2_read_toc(input)?;

        // The heap starts here.
        self.h_base = self.offset;
        if self.toc_total != toc_uncompressed_size {
            return Err(self.fail(Error::TocSize));
        }

        // The TOC's checksum.
        if toc_chksum_alg != CKSUM_NONE {
            self.move_reading_point(input, self.toc_chksum_offset)?;
            let size = self.toc_chksum_size;
            // Only the first bytes are compared; a size that is not the
            // digest's fails either way, if the archive has that much.
            let sum = match self.look(input, size)? {
                Some(sum) => sum,
                None => return Err(self.fail(Error::TruncatedFile)),
            };
            let ok = self.a_sumwrk.finish(&sum, size as usize) && self.e_sumwrk.finish(&[], 0);
            if !ok {
                return Err(self.fail(Error::Checksum));
            }
            let _ = input.consume(size as i64);
            self.offset = self.offset.wrapping_add(size);
        }

        // The hard links, connected to their originals.
        let mut file = self.hdlink_orgs;
        while let Some(f) = file {
            let id = self.files[f].id;
            if let Some(i) = self.hdlink_list.iter().position(|h| u64::from(h.id) == id) {
                let hdlink = self.hdlink_list.remove(i);
                let nlink = (hdlink.cnt + 1) as u32;
                self.files[f].nlink = nlink;
                let pathname = self.files[f].pathname.clone();
                let mut f2 = hdlink.files;
                while let Some(g) = f2 {
                    self.files[g].nlink = nlink;
                    self.files[g].hardlink.s = Some(pathname.bytes().to_vec());
                    f2 = self.files[g].hdnext;
                }
            }
            file = self.files[f].hdnext;
        }
        self.format_set = true;
        Ok(())
    }

    /// `__archive_read_ahead(size)` for the TOC's checksum: its first
    /// `MAX_SUM_SIZE` bytes, if the archive has `size` bytes from the
    /// position; `None` if it ends first.
    ///
    /// Differs from libarchive: for a size larger than what is left,
    /// libarchive allocates a buffer of that size first, and fails with
    /// "Unable to allocate copy buffer" where it cannot have it (which
    /// depends on the system's memory); the port says "Truncated archive
    /// file" for every size the archive does not have.
    fn look<R: Read>(&mut self, input: &mut Input<R>, size: u64) -> Result<Option<Vec<u8>>, Error> {
        let keep = size.min(MAX_SUM_SIZE as u64) as usize;
        let head = input.peek(keep)?.to_vec();
        if head.len() < keep {
            return Ok(None);
        }
        // Past the digest's length the checksum fails anyway: whether the
        // archive is that long is all that is left to tell.
        if size > keep as u64 && !input.reaches(size)? {
            return Ok(None);
        }
        Ok(Some(head))
    }

    /// `xar_read_header`: the next file from the heap, and its extended
    /// attributes.
    pub(crate) fn read_header<R: Read>(&mut self, input: &mut Input<R>) -> Result<Next, Error> {
        if self.offset == 0 {
            self.read_toc(input)?;
        }
        let f = loop {
            let Some(f) = self.heap_get_entry() else {
                self.file = None;
                self.end_of_file = true;
                return Ok(Next::Eof);
            };
            self.file = Some(f);
            let file = &self.files[f];
            if file.mode & AE_IFMT != AE_IFDIR {
                break f;
            }
            if file.has != (HAS_PATHNAME | HAS_TYPE) {
                break f;
            }
            // A directory with no metadata is not given.
            self.file_free(f);
        };

        let mut entry = Entry::default();
        let mut r: Option<Warning> = None;
        {
            let file = &self.files[f];
            let h = &mut entry.header;
            if file.has & HAS_ATIME != 0 {
                h.atime = Some(file.atime);
            }
            if file.has & HAS_CTIME != 0 {
                h.ctime = Some(file.ctime);
            }
            if file.has & HAS_MTIME != 0 {
                h.mtime = Some(file.mtime);
            }
            h.gid = file.gid;
            if file.gname.len() > 0 {
                h.gname = utf8_to_utf8(file.gname.bytes());
                if h.gname.is_none() {
                    r = Some(Warning::GnameConversion);
                }
            }
            h.uid = file.uid;
            if file.uname.len() > 0 {
                h.uname = utf8_to_utf8(file.uname.bytes());
                if h.uname.is_none() {
                    r = Some(Warning::UnameConversion);
                }
            }
            h.mode = file.mode;
            if let Some(path) = &file.pathname.s {
                h.path = utf8_to_utf8(path);
                if h.path.is_none() {
                    r = Some(Warning::PathnameConversion);
                }
            }
        }
        if let Some(w) = &r {
            self.set_error(&w.message());
        }
        if self.files[f].symlink.len() > 0 {
            let target = utf8_to_utf8(self.files[f].symlink.bytes());
            if target.is_none() {
                r = Some(Warning::LinknameConversion);
                self.set_error(&Warning::LinknameConversion.message());
            }
            entry.copy_symlink_l(target);
        }
        {
            let file = &self.files[f];
            let h = &mut entry.header;
            // The number of links.
            h.nlink = if file.mode & AE_IFMT == AE_IFDIR {
                (file.subdirs + 2) as u32
            } else {
                file.nlink
            };
            // archive_entry_set_size takes an int64_t, and makes a negative
            // one 0.
            h.size = if file.size > i64::MAX as u64 {
                0
            } else {
                file.size
            };
        }
        if self.files[f].hardlink.len() > 0 {
            let target = self.files[f].hardlink.bytes().to_vec();
            entry.set_hardlink(&target);
        }
        {
            let file = &self.files[f];
            entry.header.ino = file.ino64;
            if file.has & HAS_DEV != 0 {
                entry.header.dev = Some(crate::xar::entry::Dev::Number(file.dev));
            }
        }
        let (has, devmajor, devminor) = {
            let file = &self.files[f];
            (file.has, file.devmajor, file.devminor)
        };
        if has & HAS_DEVMAJOR != 0 {
            entry.set_devmajor(devmajor);
        }
        if has & HAS_DEVMINOR != 0 {
            entry.set_devminor(devminor);
        }
        if self.files[f].fflags_text.len() > 0 {
            entry.header.fflags_text = Some(self.files[f].fflags_text.bytes().to_vec());
        }

        {
            let file = &self.files[f];
            self.entry_init = true;
            self.entry_total = 0;
            self.entry_remaining = file.length;
            self.entry_size = file.size;
            self.entry_encoding = file.encoding;
            self.entry_a_sum = file.a_sum;
            self.entry_e_sum = file.e_sum;
        }

        // The extended attributes. A warning before them is lost, as the C
        // gives its result to the first step of each.
        let xattrs = self.files[f].xattr_list.clone();
        let mut result: Result<(), Error> = Ok(());
        for xattr in &xattrs {
            r = None;
            if let Err(e) = self.move_reading_point(input, xattr.offset) {
                result = Err(e);
                break;
            }
            if let Err(e) = self.rd_contents_init(xattr.encoding, xattr.a_sum.alg, xattr.e_sum.alg)
            {
                result = Err(e);
                break;
            }
            let value = match self.rd_xattr(input, xattr) {
                Ok(v) => v,
                Err(e) => {
                    result = Err(e);
                    break;
                }
            };
            let Some(value) = value else {
                result = Err(self.fail(Error::DecompressedSize));
                break;
            };
            let ok = self.a_sumwrk.finish(&xattr.a_sum.val, xattr.a_sum.len)
                && self.e_sumwrk.finish(&xattr.e_sum.val, xattr.e_sum.len);
            if !ok {
                self.set_error(b"Checksum error");
                r = Some(Warning::XattrChecksum);
                self.set_error(&Warning::XattrChecksum.message());
                break;
            }
            let Some(name) = &xattr.name.s else {
                r = Some(Warning::XattrName);
                self.set_error(&Warning::XattrName.message());
                break;
            };
            let mut n = Vec::new();
            strncat(&mut n, name);
            entry.header.xattrs.insert(0, Xattr { name: n, value });
        }
        if let Err(e) = result {
            self.file_free(f);
            return Err(e);
        }
        if let Some(w) = r {
            // The data stays where the attributes left the place.
            self.file_free(f);
            entry.header.warning = Some(w);
            return Ok(Next::Entry(Box::new(entry)));
        }
        let offset = self.files[f].offset;
        let moved = if self.entry_remaining > 0 {
            self.move_reading_point(input, offset)
        } else {
            Ok(())
        };
        self.file_free(f);
        moved?;
        Ok(Next::Entry(Box::new(entry)))
    }

    /// One `rd_contents` of an extended attribute: its value, or `None` if
    /// it is not as long as its size (one call decompresses at most
    /// `OUTBUFF_SIZE` bytes).
    fn rd_xattr<R: Read>(
        &mut self,
        input: &mut Input<R>,
        xattr: &XattrRec,
    ) -> Result<Option<Vec<u8>>, Error> {
        if self.rd_encoding != EncType::None {
            let mut out = vec![0u8; OUTBUFF_SIZE];
            let d = self.rd_contents(input, xattr.length, &mut out)?;
            if d.out as u64 != xattr.size {
                return Ok(None);
            }
            out.truncate(d.out);
            return Ok(Some(out));
        }
        // Not compressed: the bytes themselves, all the archive has up to
        // the length, which the size must be. One byte past the size is
        // enough to tell.
        if input.peek(1)?.is_empty() {
            return Err(self.fail(Error::TruncatedFile));
        }
        let want = xattr.length.min(xattr.size.saturating_add(1));
        let value = input
            .peek(usize::try_from(want).unwrap_or(usize::MAX))?
            .to_vec();
        if value.len() as u64 != xattr.size {
            return Ok(None);
        }
        self.a_sumwrk.update(&value);
        self.e_sumwrk.update(&value);
        Ok(Some(value))
    }

    /// `xar_read_data`: the next block of the current entry's data, in
    /// [`Xar::block`], at most `want` bytes of it when it is not
    /// compressed.
    pub(crate) fn read_data<R: Read>(
        &mut self,
        input: &mut Input<R>,
        want: usize,
    ) -> Result<Data, Error> {
        if self.entry_unconsumed > 0 {
            let _ = input.consume(self.entry_unconsumed as i64);
            self.entry_unconsumed = 0;
        }
        if self.end_of_file || self.entry_remaining == 0 {
            return Ok(Data::Eof);
        }
        if self.entry_init {
            if let Err(e) = self.rd_contents_init(
                self.entry_encoding,
                self.entry_a_sum.alg,
                self.entry_e_sum.alg,
            ) {
                self.entry_remaining = 0;
                return Err(e);
            }
            self.entry_init = false;
        }
        let mut block = std::mem::take(&mut self.block);
        let d = if self.rd_encoding == EncType::None {
            self.rd_stored(input, self.entry_remaining, want, &mut block)
        } else {
            block.resize(OUTBUFF_SIZE, 0);
            self.rd_contents(input, self.entry_remaining, &mut block)
        };
        self.block = block;
        let d = d?;
        self.entry_total = self.entry_total.wrapping_add(d.out as u64);
        self.offset = self.offset.wrapping_add(d.used as u64);
        self.entry_remaining -= d.used as u64;
        self.entry_unconsumed = d.used as u64;
        if self.entry_remaining == 0 {
            if self.entry_total != self.entry_size {
                return Err(self.fail(Error::DecompressedSize));
            }
            let ok = self
                .a_sumwrk
                .finish(&self.entry_a_sum.val, self.entry_a_sum.len)
                && self
                    .e_sumwrk
                    .finish(&self.entry_e_sum.val, self.entry_e_sum.len);
            if !ok {
                return Err(self.fail(Error::Checksum));
            }
        }
        Ok(Data::Block(d.out))
    }

    /// `xar_read_data_skip`: what is left of the entry's data.
    ///
    /// Differs from libarchive, which adds the bytes of the last block read
    /// but not yet consumed to its place in the heap a second time
    /// (`xar_read_data` added them when it read the block): after data read
    /// only in part, the next entry then seems behind it, and is gone back
    /// to, which an input that cannot seek fails ("Cannot seek"). Here they
    /// count once.
    pub(crate) fn read_data_skip<R: Read>(&mut self, input: &mut Input<R>) -> Result<(), Error> {
        if self.end_of_file {
            // ARCHIVE_EOF, which archive_read_data_skip takes for success.
            return Ok(());
        }
        let request = self.entry_remaining.wrapping_add(self.entry_unconsumed) as i64;
        input.consume(request).map_err(|e| self.fail(e))?;
        if request > 0 {
            self.offset = self.offset.wrapping_add(self.entry_remaining);
        }
        self.entry_unconsumed = 0;
        Ok(())
    }

    /// `move_reading_point`: forward to `offset` in the heap, or back by
    /// seeking.
    fn move_reading_point<R: Read>(
        &mut self,
        input: &mut Input<R>,
        offset: u64,
    ) -> Result<(), Error> {
        let at = self.offset.wrapping_sub(self.h_base);
        if at == offset {
            return Ok(());
        }
        let step = offset.wrapping_sub(at) as i64;
        if step > 0 {
            input.consume(step).map_err(|e| self.fail(e))?;
            self.offset = self.offset.wrapping_add(step as u64);
        } else {
            match input.seek(self.h_base.wrapping_add(offset) as i64)? {
                Seek::Failed => return Err(self.fail(Error::CannotSeek)),
                // ARCHIVE_FATAL, which is not ARCHIVE_FAILED: libarchive
                // takes it for the position, and the input fails from now.
                Seek::Fatal => self.offset = (-30i64) as u64,
                Seek::At(pos) => self.offset = pos,
            }
        }
        Ok(())
    }

    /// `rd_contents_init`: the decompressor and the checksums for data.
    fn rd_contents_init(
        &mut self,
        encoding: EncType,
        a_sum_alg: i32,
        e_sum_alg: i32,
    ) -> Result<(), Error> {
        self.decompression_init(encoding);
        // checksum_init.
        match (ChksumWork::init(a_sum_alg), ChksumWork::init(e_sum_alg)) {
            (Some(a), Some(e)) => {
                self.a_sumwrk = a;
                self.e_sumwrk = e;
                Ok(())
            }
            _ => Err(self.fail(Error::Unspecified(Some(b"Unsupported checksum".to_vec())))),
        }
    }

    /// `decompression_init`. For lzma and xz, libarchive picks the .xz or
    /// .lzma decoder by the current file's encoding, even for an extended
    /// attribute's.
    fn decompression_init(&mut self, encoding: EncType) {
        self.rd_encoding = encoding;
        match encoding {
            EncType::None => {}
            EncType::Gzip => match &mut self.decoder {
                Decoder::Gzip(stream) => stream.reset(),
                _ => self.decoder = Decoder::Gzip(Inflate::new_default()),
            },
            EncType::Bzip2 => {
                self.decoder = Decoder::Bzip2(Box::new(Decompress::new(false)), false);
            }
            EncType::Lzma | EncType::Xz => {
                let stream = if self.entry_encoding == EncType::Xz {
                    Stream::stream_decoder(u64::MAX, CONCATENATED)
                } else {
                    Stream::alone_decoder(u64::MAX)
                };
                self.decoder = Decoder::Lzma(stream.ok().map(Box::new));
            }
        }
    }

    /// `rd_contents` of data that is not compressed: what the archive has,
    /// up to `remaining` and `want` bytes, into `block`.
    fn rd_stored<R: Read>(
        &mut self,
        input: &mut Input<R>,
        remaining: u64,
        want: usize,
        block: &mut Vec<u8>,
    ) -> Result<Decompressed, Error> {
        let take = remaining.min(want.max(1) as u64) as usize;
        let b = input.peek(take)?;
        if b.is_empty() {
            return Err(self.fail(Error::TruncatedFile));
        }
        block.clear();
        block.extend_from_slice(b);
        self.a_sumwrk.update(block);
        self.e_sumwrk.update(block);
        Ok(Decompressed {
            used: block.len(),
            out: block.len(),
        })
    }

    /// `rd_contents` with `decompress`: one call of the decompressor with
    /// all the input the archive has, up to `remaining` bytes (looked at,
    /// not consumed), into `out`; the checksums updated with what it used
    /// and made.
    fn rd_contents<R: Read>(
        &mut self,
        input: &mut Input<R>,
        remaining: u64,
        out: &mut [u8],
    ) -> Result<Decompressed, Error> {
        if input.peek(1)?.is_empty() {
            return Err(self.fail(Error::TruncatedFile));
        }
        let d = self.decompress(input, remaining, out)?;
        if remaining > 0 && d.used == 0 && d.out == 0 {
            return Err(self.fail(Error::NoProgress));
        }
        if d.used > 0 {
            let used = input.peek(d.used)?;
            self.a_sumwrk.update(used);
        }
        self.e_sumwrk.update(&out[..d.out]);
        Ok(d)
    }

    /// `decompress`: one call of the decoder with all the input there is,
    /// up to `remaining` bytes. The input is given in pieces, which the
    /// decoders take as they would take it whole: the next piece only when
    /// the decoder took all of the last one and has output space left.
    fn decompress<R: Read>(
        &mut self,
        input: &mut Input<R>,
        remaining: u64,
        out: &mut [u8],
    ) -> Result<Decompressed, Error> {
        let mut used = 0usize;
        let mut made = 0usize;
        loop {
            let take = remaining.saturating_sub(used as u64).min(PIECE as u64) as usize;
            let piece = input
                .peek(used + take)?
                .get(used..)
                .unwrap_or_default()
                .to_vec();
            let (n_in, n_out, more) = self.decode_piece(&piece, &mut out[made..])?;
            used += n_in;
            made += n_out;
            if !more
                || made == out.len()
                || n_in < piece.len()
                || piece.len() < take
                || used as u64 >= remaining
            {
                return Ok(Decompressed { used, out: made });
            }
        }
    }

    /// The decoder on one piece of input: what it read and wrote, and
    /// whether it could go on with more input.
    fn decode_piece(
        &mut self,
        piece: &[u8],
        out: &mut [u8],
    ) -> Result<(usize, usize, bool), Error> {
        let entry_xz = self.entry_encoding == EncType::Xz;
        match &mut self.decoder {
            Decoder::Gzip(stream) => {
                let mut inb = InBuffer::new(piece);
                let mut outb = OutBuffer::new(out);
                match stream.inflate(&mut outb, &mut inb, Flush::NoFlush) {
                    Ok(Status::Ok) => Ok((inb.pos, outb.pos, true)),
                    Ok(Status::StreamEnd) => Ok((inb.pos, outb.pos, false)),
                    Ok(Status::NeedDict) => Err(self.fail(Error::Inflate(2))),
                    Err(e) => {
                        let code = e.code().number();
                        Err(self.fail(Error::Inflate(code)))
                    }
                }
            }
            Decoder::Bzip2(stream, ended) => {
                if *ended {
                    return Err(self.fail(Error::Bzip2));
                }
                let mut inb = BzIn::new(piece);
                let mut outb = BzOut::new(out);
                match stream.decompress(&mut outb, &mut inb) {
                    Ok(BzStatus::StreamEnd) => {
                        *ended = true;
                        Ok((inb.pos, outb.pos, false))
                    }
                    Ok(_) => Ok((inb.pos, outb.pos, true)),
                    Err(_) => Err(self.fail(Error::Bzip2)),
                }
            }
            Decoder::Lzma(stream) => {
                let Some(s) = stream else {
                    // lzma_code after lzma_end: LZMA_PROG_ERROR.
                    return Err(self.fail(Error::Lzma {
                        xz: entry_xz,
                        code: 11,
                    }));
                };
                let mut inb = XzIn::new(piece);
                let mut outb = XzOut::new(out);
                match s.code(&mut outb, &mut inb, Action::Run) {
                    Ok(XzStatus::StreamEnd) => {
                        *stream = None;
                        Ok((inb.pos, outb.pos, false))
                    }
                    Ok(_) => Ok((inb.pos, outb.pos, true)),
                    Err(e) => Err(self.fail(Error::Lzma {
                        xz: entry_xz,
                        code: e.number(),
                    })),
                }
            }
            Decoder::None => Ok((0, 0, false)),
        }
    }

    /// `heap_add_entry`: `file` in the heap by its `id`.
    fn heap_add_entry(&mut self, file: Fid) {
        let file_id = self.files[file].id;
        let mut hole = self.file_queue.len();
        self.file_queue.push(file);
        while hole > 0 {
            let parent = (hole - 1) / 2;
            let parent_id = self.files[self.file_queue[parent]].id;
            if file_id >= parent_id {
                self.file_queue[hole] = file;
                return;
            }
            self.file_queue[hole] = self.file_queue[parent];
            hole = parent;
        }
        self.file_queue[0] = file;
    }

    /// `heap_get_entry`: the file of the lowest `id`.
    fn heap_get_entry(&mut self) -> Option<Fid> {
        let used = self.file_queue.len();
        if used < 1 {
            return None;
        }
        let r = self.file_queue[0];
        let last = self.file_queue.pop()?;
        if self.file_queue.is_empty() {
            return Some(r);
        }
        self.file_queue[0] = last;
        let mut a = 0;
        let a_id = self.files[self.file_queue[a]].id;
        loop {
            let mut b = a + a + 1;
            if b >= self.file_queue.len() {
                return Some(r);
            }
            let mut b_id = self.files[self.file_queue[b]].id;
            let c = b + 1;
            if c < self.file_queue.len() {
                let c_id = self.files[self.file_queue[c]].id;
                if c_id < b_id {
                    b = c;
                    b_id = c_id;
                }
            }
            if a_id <= b_id {
                return Some(r);
            }
            self.file_queue.swap(a, b);
            a = b;
        }
    }

    /// `file_free`: the record's strings and attributes go.
    fn file_free(&mut self, f: Fid) {
        let file = &mut self.files[f];
        file.pathname = ArchiveString::default();
        file.symlink = ArchiveString::default();
        file.uname = ArchiveString::default();
        file.gname = ArchiveString::default();
        file.hardlink = ArchiveString::default();
        file.fflags_text = ArchiveString::default();
        file.xattr_list = Vec::new();
    }

    /// `add_link`: `file` among the hard links to its `link`.
    fn add_link(&mut self, file: Fid) {
        let link = self.files[file].link;
        if let Some(h) = self.hdlink_list.iter_mut().find(|h| h.id == link) {
            self.files[file].hdnext = h.files;
            h.cnt += 1;
            h.files = Some(file);
            return;
        }
        self.files[file].hdnext = None;
        self.hdlink_list.insert(
            0,
            Hdlink {
                id: link,
                cnt: 1,
                files: Some(file),
            },
        );
    }

    /// `file_new`: a file in the TOC, in the heap.
    fn file_new(&mut self, list: &[XmlAttr]) -> Result<(), Error> {
        let mut file = XarFile {
            parent: self.file,
            mode: 0o777 | AE_IFREG,
            ..XarFile::default()
        };
        self.xattr = None;
        for attr in list.iter().filter(|a| a.name == b"id") {
            file.id = atou64(&attr.value, 10).ok_or_else(|| self.unspecified())?;
        }
        file.nlink = 1;
        let f = self.files.len();
        self.files.push(file);
        self.file = Some(f);
        self.heap_add_entry(f);
        Ok(())
    }

    /// `xattr_new`: an extended attribute of the current file, in its list
    /// by `id`.
    fn xattr_new(&mut self, list: &[XmlAttr]) -> Result<(), Error> {
        let mut xattr = XattrRec::default();
        for attr in list.iter().filter(|a| a.name == b"id") {
            xattr.id = atou64(&attr.value, 10).ok_or_else(|| self.unspecified())?;
        }
        let Some(f) = self.file else {
            return Ok(());
        };
        let xattrs = &mut self.files[f].xattr_list;
        let at = xattrs
            .iter()
            .position(|x| xattr.id < x.id)
            .unwrap_or(xattrs.len());
        xattrs.insert(at, xattr);
        self.xattr = Some((f, at));
        Ok(())
    }

    /// The extended attribute being read.
    fn cur_xattr(&mut self) -> Option<&mut XattrRec> {
        let (f, i) = self.xattr?;
        self.files.get_mut(f)?.xattr_list.get_mut(i)
    }

    /// `unknowntag_start`.
    fn unknowntag_start(&mut self, name: &[u8]) {
        if self.unknowntags.is_empty() {
            self.xmlsts_unknown = self.xmlsts;
            self.xmlsts = XmlStatus::Unknown;
        }
        self.unknowntags.push(name.to_vec());
    }

    /// `unknowntag_end`.
    fn unknowntag_end(&mut self, name: &[u8]) {
        if self.unknowntags.last().is_some_and(|t| t == name) {
            self.unknowntags.pop();
            if self.unknowntags.is_empty() {
                self.xmlsts = self.xmlsts_unknown;
            }
        }
    }

    /// The flag text of `xml_parse_file_flags` and `xml_parse_file_ext2`.
    fn add_flag(&mut self, flag: &str, bsd: bool) {
        let Some(f) = self.file else {
            return;
        };
        let file = &mut self.files[f];
        if bsd {
            file.has |= HAS_FFLAGS;
        }
        let text = file.fflags_text.s.get_or_insert_with(Vec::new);
        if !text.is_empty() {
            text.push(b',');
        }
        text.extend_from_slice(flag.as_bytes());
    }

    /// `xml_start`: an element of the TOC.
    fn xml_start(&mut self, name: &[u8], list: &[XmlAttr]) -> Result<(), Error> {
        use XmlStatus as S;
        self.base64text = false;
        let sts = self.xmlsts;
        let n = name;
        match sts {
            S::Init => {
                if n == b"xar" {
                    self.xmlsts = S::Xar;
                } else {
                    self.unknowntag_start(n);
                }
            }
            S::Xar => {
                if n == b"toc" {
                    self.xmlsts = S::Toc;
                } else {
                    self.unknowntag_start(n);
                }
            }
            S::Toc => match n {
                b"creation-time" => self.xmlsts = S::TocCreationTime,
                b"checksum" => self.xmlsts = S::TocChecksum,
                b"file" => {
                    self.file_new(list)?;
                    self.xmlsts = S::TocFile;
                }
                _ => self.unknowntag_start(n),
            },
            S::TocChecksum => match n {
                b"offset" => self.xmlsts = S::TocChecksumOffset,
                b"size" => self.xmlsts = S::TocChecksumSize,
                _ => self.unknowntag_start(n),
            },
            S::TocFile => match n {
                b"file" => self.file_new(list)?,
                b"data" => self.xmlsts = S::FileData,
                b"ea" => {
                    self.xattr_new(list)?;
                    self.xmlsts = S::FileEa;
                }
                b"ctime" => self.xmlsts = S::FileCtime,
                b"mtime" => self.xmlsts = S::FileMtime,
                b"atime" => self.xmlsts = S::FileAtime,
                b"group" => self.xmlsts = S::FileGroup,
                b"gid" => self.xmlsts = S::FileGid,
                b"user" => self.xmlsts = S::FileUser,
                b"uid" => self.xmlsts = S::FileUid,
                b"mode" => self.xmlsts = S::FileMode,
                b"device" => self.xmlsts = S::FileDevice,
                b"deviceno" => self.xmlsts = S::FileDeviceno,
                b"inode" => self.xmlsts = S::FileInode,
                b"link" => self.xmlsts = S::FileLink,
                b"type" => {
                    self.xmlsts = S::FileType;
                    for attr in list.iter().filter(|a| a.name == b"link") {
                        self.file_type_link(attr)?;
                    }
                }
                b"name" => {
                    self.xmlsts = S::FileName;
                    if list
                        .iter()
                        .any(|a| a.name == b"enctype" && a.value == b"base64")
                    {
                        self.base64text = true;
                    }
                }
                b"acl" => self.xmlsts = S::FileAcl,
                b"flags" => self.xmlsts = S::FileFlags,
                b"ext2" => self.xmlsts = S::FileExt2,
                _ => self.unknowntag_start(n),
            },
            S::FileData => match n {
                b"length" => self.xmlsts = S::FileDataLength,
                b"offset" => self.xmlsts = S::FileDataOffset,
                b"size" => self.xmlsts = S::FileDataSize,
                b"encoding" => {
                    self.xmlsts = S::FileDataEncoding;
                    if let Some(f) = self.file {
                        self.files[f].encoding = getencoding(list);
                    }
                }
                b"archived-checksum" => {
                    self.xmlsts = S::FileDataAChecksum;
                    if let Some(f) = self.file {
                        self.files[f].a_sum.alg = getsumalgorithm(list);
                    }
                }
                b"extracted-checksum" => {
                    self.xmlsts = S::FileDataEChecksum;
                    if let Some(f) = self.file {
                        self.files[f].e_sum.alg = getsumalgorithm(list);
                    }
                }
                b"content" => self.xmlsts = S::FileDataContent,
                _ => self.unknowntag_start(n),
            },
            S::FileDevice => match n {
                b"major" => self.xmlsts = S::FileDeviceMajor,
                b"minor" => self.xmlsts = S::FileDeviceMinor,
                _ => self.unknowntag_start(n),
            },
            S::FileDataContent => self.unknowntag_start(n),
            S::FileEa => match n {
                b"length" => self.xmlsts = S::FileEaLength,
                b"offset" => self.xmlsts = S::FileEaOffset,
                b"size" => self.xmlsts = S::FileEaSize,
                b"encoding" => {
                    self.xmlsts = S::FileEaEncoding;
                    let encoding = getencoding(list);
                    if let Some(x) = self.cur_xattr() {
                        x.encoding = encoding;
                    }
                }
                b"archived-checksum" => self.xmlsts = S::FileEaAChecksum,
                b"extracted-checksum" => self.xmlsts = S::FileEaEChecksum,
                b"name" => self.xmlsts = S::FileEaName,
                b"fstype" => self.xmlsts = S::FileEaFstype,
                _ => self.unknowntag_start(n),
            },
            S::FileAcl => match n {
                b"appleextended" => self.xmlsts = S::FileAclAppleextended,
                b"default" => self.xmlsts = S::FileAclDefault,
                b"access" => self.xmlsts = S::FileAclAccess,
                _ => self.unknowntag_start(n),
            },
            S::FileFlags => match FILE_FLAGS.iter().find(|(e, _)| e.as_bytes() == n) {
                Some(&(e, flag)) => {
                    self.xmlsts = S::FileFlag(e);
                    self.add_flag(flag, true);
                }
                None => self.unknowntag_start(n),
            },
            S::FileExt2 => match EXT2_FLAGS.iter().find(|(e, _)| e.as_bytes() == n) {
                Some(&(e, flag)) => {
                    self.xmlsts = S::FileExt2Flag(e);
                    self.add_flag(flag, false);
                }
                None => self.unknowntag_start(n),
            },
            _ => self.unknowntag_start(n),
        }
        Ok(())
    }

    /// The `link` attribute of a file's `<type>`: "original", or the `id`
    /// of the original this file is a hard link to.
    fn file_type_link(&mut self, attr: &XmlAttr) -> Result<(), Error> {
        let Some(f) = self.file else {
            return Ok(());
        };
        let file = &self.files[f];
        if file.hdnext.is_some() || file.link != 0 || self.hdlink_orgs == Some(f) {
            return Err(self.fail(Error::MultipleLinks));
        }
        if attr.value == b"original" {
            // Differs from libarchive: the first original of the list (its
            // last), made an original again, passes the check above, and
            // makes the list a loop, which libarchive's read_toc goes round
            // for ever. It fails here as the other repeats do.
            if self.hdlink_orgs_last == Some(f) {
                return Err(self.fail(Error::MultipleLinks));
            }
            if self.hdlink_orgs.is_none() {
                self.hdlink_orgs_last = Some(f);
            }
            self.files[f].hdnext = self.hdlink_orgs;
            self.hdlink_orgs = Some(f);
        } else {
            let val = atou64(&attr.value, 10).ok_or_else(|| self.unspecified())?;
            let Ok(val) = u32::try_from(val) else {
                return Err(self.unspecified());
            };
            self.files[f].link = val;
            if val > 0 {
                self.add_link(f);
            }
        }
        Ok(())
    }

    /// `xml_end`: the end of an element of the TOC.
    fn xml_end(&mut self, name: &[u8]) {
        use XmlStatus as S;
        let sts = self.xmlsts;
        let back = |to: XmlStatus, tag: &str| (tag.as_bytes() == name).then_some(to);
        let next = match sts {
            S::Init => None,
            S::Xar => back(S::Init, "xar"),
            S::Toc => back(S::Xar, "toc"),
            S::TocCreationTime => back(S::Toc, "creation-time"),
            S::TocChecksum => back(S::Toc, "checksum"),
            S::TocChecksumOffset => back(S::TocChecksum, "offset"),
            S::TocChecksumSize => back(S::TocChecksum, "size"),
            S::TocFile => {
                if name == b"file"
                    && let Some(f) = self.file
                {
                    let parent = self.files[f].parent;
                    if let Some(p) = parent
                        && self.files[f].mode & AE_IFMT == AE_IFDIR
                    {
                        self.files[p].subdirs = self.files[p].subdirs.wrapping_add(1);
                    }
                    self.file = parent;
                    if parent.is_none() {
                        self.xmlsts = S::Toc;
                    }
                }
                None
            }
            S::FileData => back(S::TocFile, "data"),
            S::FileDataLength => back(S::FileData, "length"),
            S::FileDataOffset => back(S::FileData, "offset"),
            S::FileDataSize => back(S::FileData, "size"),
            S::FileDataEncoding => back(S::FileData, "encoding"),
            S::FileDataAChecksum => back(S::FileData, "archived-checksum"),
            S::FileDataEChecksum => back(S::FileData, "extracted-checksum"),
            S::FileDataContent => back(S::FileData, "content"),
            S::FileEa => {
                if name == b"ea" {
                    self.xattr = None;
                }
                back(S::TocFile, "ea")
            }
            S::FileEaLength => back(S::FileEa, "length"),
            S::FileEaOffset => back(S::FileEa, "offset"),
            S::FileEaSize => back(S::FileEa, "size"),
            S::FileEaEncoding => back(S::FileEa, "encoding"),
            S::FileEaAChecksum => back(S::FileEa, "archived-checksum"),
            S::FileEaEChecksum => back(S::FileEa, "extracted-checksum"),
            S::FileEaName => back(S::FileEa, "name"),
            S::FileEaFstype => back(S::FileEa, "fstype"),
            S::FileCtime => back(S::TocFile, "ctime"),
            S::FileMtime => back(S::TocFile, "mtime"),
            S::FileAtime => back(S::TocFile, "atime"),
            S::FileGroup => back(S::TocFile, "group"),
            S::FileGid => back(S::TocFile, "gid"),
            S::FileUser => back(S::TocFile, "user"),
            S::FileUid => back(S::TocFile, "uid"),
            S::FileMode => back(S::TocFile, "mode"),
            S::FileDevice => back(S::TocFile, "device"),
            S::FileDeviceMajor => back(S::FileDevice, "major"),
            S::FileDeviceMinor => back(S::FileDevice, "minor"),
            S::FileDeviceno => back(S::TocFile, "deviceno"),
            S::FileInode => back(S::TocFile, "inode"),
            S::FileLink => back(S::TocFile, "link"),
            S::FileType => back(S::TocFile, "type"),
            S::FileName => back(S::TocFile, "name"),
            S::FileAcl => back(S::TocFile, "acl"),
            S::FileAclDefault => back(S::FileAcl, "default"),
            S::FileAclAccess => back(S::FileAcl, "access"),
            S::FileAclAppleextended => back(S::FileAcl, "appleextended"),
            S::FileFlags => back(S::TocFile, "flags"),
            S::FileFlag(e) => back(S::FileFlags, e),
            S::FileExt2 => back(S::TocFile, "ext2"),
            S::FileExt2Flag(e) => back(S::FileExt2, e),
            S::Unknown => {
                self.unknowntag_end(name);
                None
            }
        };
        if let Some(next) = next {
            self.xmlsts = next;
        }
    }

    /// `xml_data`: a text node of the TOC.
    fn xml_data(&mut self, s: &[u8]) -> Result<(), Error> {
        use XmlStatus as S;
        let sts = self.xmlsts;
        match sts {
            S::TocChecksumOffset => {
                self.toc_chksum_offset = atou64(s, 10).ok_or_else(|| self.unspecified())?;
            }
            S::TocChecksumSize => {
                self.toc_chksum_size = atou64(s, 10).ok_or_else(|| self.unspecified())?;
            }
            _ => {}
        }
        let Some(f) = self.file else {
            return Ok(());
        };
        let number = |xar: &Xar, base: u64| atou64(s, base).ok_or_else(|| xar.unspecified());
        match sts {
            S::FileName => {
                if self.files[f].has & HAS_PATHNAME != 0 {
                    return Ok(());
                }
                // The buffer libarchive's string is given only by what is
                // appended to it: a name in base64 that decodes to nothing,
                // with no parent before it, leaves the path unset.
                let mut allocated = self.files[f].pathname.s.is_some();
                let mut path = self.files[f].pathname.s.take().unwrap_or_default();
                if let Some(p) = self.files[f].parent {
                    path.extend_from_slice(self.files[p].pathname.bytes());
                    path.push(b'/');
                    allocated = true;
                }
                self.files[f].has |= HAS_PATHNAME;
                if self.base64text {
                    allocated |= strappend_base64(&mut path, s);
                } else {
                    strncat(&mut path, s);
                    allocated = true;
                }
                self.files[f].pathname.s = allocated.then_some(path);
            }
            S::FileLink => {
                let file = &mut self.files[f];
                file.has |= HAS_SYMLINK;
                file.symlink.copy(s);
            }
            S::FileType => {
                let file = &mut self.files[f];
                let types: [(&str, u32); 8] = [
                    ("file", AE_IFREG),
                    ("hardlink", AE_IFREG),
                    ("directory", AE_IFDIR),
                    ("symlink", AE_IFLNK),
                    ("character special", AE_IFCHR),
                    ("block special", AE_IFBLK),
                    ("socket", AE_IFSOCK),
                    ("fifo", AE_IFIFO),
                ];
                for (known, t) in types {
                    if is_string(known, s) {
                        file.mode = (file.mode & !AE_IFMT) | t;
                    }
                }
                file.has |= HAS_TYPE;
            }
            S::FileInode => {
                let val = number(self, 10)?;
                let Ok(val) = i64::try_from(val) else {
                    return Err(self.unspecified());
                };
                self.files[f].has |= HAS_INO;
                self.files[f].ino64 = val;
            }
            // dev_t holds 64 bits, as on Linux.
            S::FileDeviceMajor => {
                let val = number(self, 10)?;
                self.files[f].has |= HAS_DEVMAJOR;
                self.files[f].devmajor = val;
            }
            S::FileDeviceMinor => {
                let val = number(self, 10)?;
                self.files[f].has |= HAS_DEVMINOR;
                self.files[f].devminor = val;
            }
            S::FileDeviceno => {
                let val = number(self, 10)?;
                self.files[f].has |= HAS_DEV;
                self.files[f].dev = val;
            }
            S::FileMode => {
                // mode_t holds 32 bits, as on Linux.
                let val = number(self, 8)?;
                let Ok(val) = u32::try_from(val) else {
                    return Err(self.unspecified());
                };
                let file = &mut self.files[f];
                file.has |= HAS_MODE;
                file.mode = (file.mode & AE_IFMT) | (val & !AE_IFMT);
            }
            S::FileGroup => {
                self.files[f].has |= HAS_GID;
                self.files[f].gname.copy(s);
            }
            S::FileGid => {
                let val = number(self, 10)?;
                let Ok(val) = i64::try_from(val) else {
                    return Err(self.unspecified());
                };
                self.files[f].has |= HAS_GID;
                self.files[f].gid = val;
            }
            S::FileUser => {
                self.files[f].has |= HAS_UID;
                self.files[f].uname.copy(s);
            }
            S::FileUid => {
                let val = number(self, 10)?;
                let Ok(val) = i64::try_from(val) else {
                    return Err(self.unspecified());
                };
                self.files[f].has |= HAS_UID;
                self.files[f].uid = val;
            }
            S::FileCtime => {
                self.files[f].has |= HAS_TIME | HAS_CTIME;
                self.files[f].ctime = parse_time(s);
            }
            S::FileMtime => {
                self.files[f].has |= HAS_TIME | HAS_MTIME;
                self.files[f].mtime = parse_time(s);
            }
            S::FileAtime => {
                self.files[f].has |= HAS_TIME | HAS_ATIME;
                self.files[f].atime = parse_time(s);
            }
            S::FileDataLength => {
                self.files[f].length = number(self, 10)?;
                self.files[f].has |= HAS_DATA;
            }
            S::FileDataOffset => {
                self.files[f].offset = number(self, 10)?;
                self.files[f].has |= HAS_DATA;
            }
            S::FileDataSize => {
                self.files[f].size = number(self, 10)?;
                self.files[f].has |= HAS_DATA;
            }
            S::FileDataAChecksum => {
                let sum = &mut self.files[f].a_sum;
                sum.len = atohex(&mut sum.val, s);
            }
            S::FileDataEChecksum => {
                let sum = &mut self.files[f].e_sum;
                sum.len = atohex(&mut sum.val, s);
            }
            S::FileEaLength | S::FileEaOffset | S::FileEaSize => {
                let val = number(self, 10)?;
                if let Some(x) = self.cur_xattr() {
                    match sts {
                        S::FileEaLength => x.length = val,
                        S::FileEaOffset => x.offset = val,
                        _ => x.size = val,
                    }
                }
                self.files[f].has |= HAS_XATTR;
            }
            S::FileEaAChecksum | S::FileEaEChecksum => {
                self.files[f].has |= HAS_XATTR;
                if let Some(x) = self.cur_xattr() {
                    let sum = if sts == S::FileEaAChecksum {
                        &mut x.a_sum
                    } else {
                        &mut x.e_sum
                    };
                    sum.len = atohex(&mut sum.val, s);
                }
            }
            S::FileEaName => {
                self.files[f].has |= HAS_XATTR;
                if let Some(x) = self.cur_xattr() {
                    x.name.copy(s);
                }
            }
            S::FileEaFstype => {
                self.files[f].has |= HAS_XATTR;
                if let Some(x) = self.cur_xattr() {
                    x.fstype.copy(s);
                }
            }
            S::FileAclDefault | S::FileAclAccess | S::FileAclAppleextended => {
                self.files[f].has |= HAS_ACL;
            }
            _ => {}
        }
        Ok(())
    }

    /// `xml2_read_toc`: the TOC through libxml2's reader, each node to
    /// `xml_start`, `xml_end` or `xml_data`.
    fn xml2_read_toc<R: Read>(&mut self, input: &mut Input<R>) -> Result<(), Error> {
        let mut io = TocReader {
            xar: self,
            input,
            io_error: None,
        };
        let mut reader = TextReader::for_io(&mut io);
        loop {
            let r = reader.read(&mut io);
            if r != 1 {
                if r == 0 {
                    return Ok(());
                }
                let io_error = io.io_error.take();
                return Err(io.xar.xml_failure(io_error));
            }
            // The element's name, before the attributes are walked.
            let name = reader.const_local_name().to_vec();
            match reader.node_type() {
                XML_READER_TYPE_ELEMENT => {
                    let empty = reader.is_empty_element();
                    // xml2_xmlattr_setup.
                    let mut list = Vec::new();
                    let mut more = reader.move_to_first_attribute();
                    while more == 1 {
                        list.push(XmlAttr {
                            name: c_string(reader.const_local_name()),
                            value: c_string(reader.const_value().unwrap_or_default()),
                        });
                        more = reader.move_to_next_attribute();
                    }
                    io.xar.xml_start(&c_string(&name), &list)?;
                    if empty {
                        io.xar.xml_end(&c_string(&name));
                    }
                }
                XML_READER_TYPE_END_ELEMENT => io.xar.xml_end(&c_string(&name)),
                XML_READER_TYPE_TEXT => {
                    let value = c_string(reader.const_value().unwrap_or_default());
                    io.xar.xml_data(&value)?;
                }
                _ => {}
            }
        }
    }

    /// The failure of the TOC's parse: libarchive's error string then is
    /// what was set last, libxml2's report or the read callback's error.
    fn xml_failure(&self, io_error: Option<Error>) -> Error {
        const PREFIX: &[u8] = b"XML Parsing error: ";
        match &self.last_message {
            Some(m) if m.starts_with(PREFIX) => {
                Error::Xml(String::from_utf8_lossy(&m[PREFIX.len()..]).into_owned())
            }
            m => match io_error {
                Some(e) if e.message() == *m => e,
                _ => Error::Unspecified(m.clone()),
            },
        }
    }
}

/// `xml2_read_cb` and `xml2_error_hdr`: the TOC, decompressed into the
/// buffer the reader gives, and its reports as libarchive's error string.
struct TocReader<'a, R> {
    xar: &'a mut Xar,
    input: &'a mut Input<R>,
    /// The last error of the read callback.
    io_error: Option<Error>,
}

impl<R: Read> XmlIo for TocReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> i32 {
        let xar = &mut *self.xar;
        if xar.toc_remaining == 0 {
            return 0;
        }
        let remaining = xar.toc_remaining;
        let d = match xar.rd_contents(self.input, remaining, buf) {
            Ok(d) => d,
            Err(e) => {
                self.io_error = Some(e);
                // ARCHIVE_FATAL, which libxml2 reports as an I/O error.
                return -30;
            }
        };
        let _ = self.input.consume(d.used as i64);
        xar.toc_remaining -= d.used as u64;
        xar.offset = xar.offset.wrapping_add(d.used as u64);
        xar.toc_total = xar.toc_total.wrapping_add(d.out as u64);
        d.out as i32
    }

    fn error(&mut self, _severity: Severity, msg: &str) {
        let message = format!("XML Parsing error: {msg}");
        self.xar.set_error(message.as_bytes());
    }
}

/// A string as C has it: up to its first NUL.
fn c_string(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    strncat(&mut out, s);
    out
}

#[cfg(test)]
mod tests {
    use super::{atohex, atou64, parse_time, strappend_base64};

    #[test]
    fn numbers() {
        assert_eq!(atou64(b"123", 10), Some(123));
        assert_eq!(atou64(b"12x3", 10), Some(12));
        assert_eq!(atou64(b"", 10), Some(0));
        assert_eq!(atou64(b"-1", 10), Some(0));
        assert_eq!(atou64(b"0755", 8), Some(0o755));
        assert_eq!(atou64(b"0789", 8), Some(0o7));
        assert_eq!(atou64(b"18446744073709551615", 10), Some(u64::MAX));
        assert_eq!(atou64(b"18446744073709551616", 10), None);
        assert_eq!(atou64(b"99999999999999999999", 10), None);
    }

    #[test]
    fn hex() {
        let mut b = [0u8; 4];
        assert_eq!(atohex(&mut b, b"00ffA1"), 3);
        assert_eq!(b[..3], [0, 0xff, 0xa1]);
        // An odd last digit is left; past the buffer, nothing is read.
        assert_eq!(atohex(&mut b, b"123"), 1);
        assert_eq!(atohex(&mut b, b"0102030405"), 4);
        assert_eq!(atohex(&mut b, b"01zz"), usize::MAX);
        assert_eq!(atohex(&mut b, b""), 0);
    }

    #[test]
    fn times() {
        assert_eq!(parse_time(b"1970-01-01T00:00:00Z"), 0);
        assert_eq!(parse_time(b"2009-11-30T12:00:01Z"), 1_259_582_401);
        assert_eq!(parse_time(b"1969-12-31T23:59:59Z"), -1);
        assert_eq!(parse_time(b"1900-01-01T00:00:00Z"), -2_208_988_800);
        // February 31 is March 3; a leap second is the next minute.
        assert_eq!(
            parse_time(b"2021-02-31T00:00:00Z"),
            parse_time(b"2021-03-03T00:00:00Z")
        );
        assert_eq!(
            parse_time(b"2021-01-01T00:00:60Z"),
            parse_time(b"2021-01-01T00:01:00Z")
        );
        assert_eq!(parse_time(b"9999-12-31T23:59:59Z"), 253_402_300_799);
        // The 'Z' is not checked.
        assert_eq!(parse_time(b"1970-01-01T00:00:01+"), 1);
        for bad in [
            &b"1899-12-31T23:59:59Z"[..],
            b"2020-00-01T00:00:00Z",
            b"2020-13-01T00:00:00Z",
            b"2020-01-32T00:00:00Z",
            b"2020-01-01T24:00:00Z",
            b"2020-01-01T00:60:00Z",
            b"2020-01-01T00:00:61Z",
            b"2020/01-01T00:00:00Z",
            b"2020-01-01 00:00:00Z",
            b"2020-01-01T00:00:00",
            b"2020-01-01T00:00:00ZZ",
        ] {
            assert_eq!(parse_time(bad), 0, "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn base64() {
        let decode = |s: &[u8]| {
            let mut out = Vec::new();
            strappend_base64(&mut out, s);
            out
        };
        assert_eq!(decode(b"aGVsbG8="), b"hello");
        assert_eq!(decode(b"aGVsbG8"), b"hello");
        assert_eq!(decode(b"YQ"), b"a");
        assert_eq!(decode(b"Y"), b"");
        // Decoding stops at the first byte that is not base64.
        assert_eq!(decode(b"YWJj*ZGVm"), b"abc");
        // Each buffer of 253 bytes or so stops at a NUL, as archive_strncat.
        assert_eq!(decode(b"YQBi"), b"a");
        let long: Vec<u8> = b"QUJD".repeat(100);
        assert_eq!(decode(&long), b"ABC".repeat(100));
    }
}
