//! Port of libarchive's `archive_read_support_format_iso9660.c`: the reader
//! of ISO 9660 images, with the Joliet and Rock Ridge extensions and zisofs.
//!
//! An overview of ISO 9660, from libarchive:
//!
//! Each disk is laid out as 32 KiB reserved for private use, then a table
//! of volume descriptors of 2 KiB each, which say what the image holds. The
//! Primary Volume Descriptor (PVD) is defined by the standard and should
//! always be present; others include vendor extensions. Then come the
//! files and directories, each an "extent" (a starting sector and a length
//! in bytes). Directories are files of directory records, one after
//! another; the PVD holds the root directory's record.
//!
//! The reader first reads the volume descriptors, then keeps the directory
//! records it has seen in a heap ordered by where their data is. At each
//! step it takes the first one it has not read yet, moves forward to it and
//! reads it: a directory's records go into the heap, a file is returned and
//! its data read next. Most images can be read so in one pass, without
//! seeking.
//!
//! The C keeps its records in linked lists through pointers inside them;
//! here records live in a `Vec` and point at each other by index, and the
//! lists keep the C's links (one record can be in two lists through the
//! same link, as in the C), so that damaged images go the same way.

use crate::deflate::{Flush, InBuffer, Inflate, OutBuffer, Status};

use crate::iso::entry::{AE_IFDIR, AE_IFLNK, AE_IFMT, AE_IFREG, Entry};
use crate::iso::error::{Error, Warning};
use crate::iso::read::Input;
use std::io::Read;

/// `LOGICAL_BLOCK_SIZE`.
const LOGICAL_BLOCK_SIZE: usize = 2048;
/// `SYSTEM_AREA_BLOCK`.
const SYSTEM_AREA_BLOCK: i32 = 16;
/// `RESERVED_AREA`.
const RESERVED_AREA: usize = SYSTEM_AREA_BLOCK as usize * LOGICAL_BLOCK_SIZE;

/// How far the volume descriptors are looked for. Differs from libarchive:
/// with the image in memory, libarchive looks until it finds the Volume
/// Descriptor Set Terminator or the image ends, holding all of it; the port
/// holds what it looks at, so it stops after 16 MiB of descriptors (8,192
/// of them; real images have a handful).
const BID_LIMIT: usize = 16 << 20;

// The Primary Volume Descriptor (ECMA-119 8.4).
const PVD_TYPE_OFFSET: usize = 0;
const PVD_VERSION_OFFSET: usize = 6;
const PVD_RESERVED1_OFFSET: usize = 7;
const PVD_RESERVED2_OFFSET: usize = 72;
const PVD_RESERVED2_SIZE: usize = 8;
const PVD_VOLUME_SPACE_SIZE_OFFSET: usize = 80;
const PVD_RESERVED3_OFFSET: usize = 88;
const PVD_RESERVED3_SIZE: usize = 32;
const PVD_VOLUME_SET_SIZE_OFFSET: usize = 120;
const PVD_VOLUME_SEQUENCE_NUMBER_OFFSET: usize = 124;
const PVD_LOGICAL_BLOCK_SIZE_OFFSET: usize = 128;
const PVD_PATH_TABLE_SIZE_OFFSET: usize = 132;
const PVD_TYPE_1_PATH_TABLE_OFFSET: usize = 140;
const PVD_TYPE_M_PATH_TABLE_OFFSET: usize = 148;
const PVD_ROOT_DIRECTORY_RECORD_OFFSET: usize = 156;
const PVD_FILE_STRUCTURE_VERSION_OFFSET: usize = 881;
const PVD_RESERVED4_OFFSET: usize = 882;
const PVD_RESERVED4_SIZE: usize = 1;
const PVD_RESERVED5_OFFSET: usize = 1395;
const PVD_RESERVED5_SIZE: usize = 2048 - PVD_RESERVED5_OFFSET;

// A Supplementary Volume Descriptor (ECMA-119 8.5).
const SVD_TYPE_OFFSET: usize = 0;
const SVD_RESERVED1_OFFSET: usize = 72;
const SVD_RESERVED1_SIZE: usize = 8;
const SVD_VOLUME_SPACE_SIZE_OFFSET: usize = 80;
const SVD_ESCAPE_SEQUENCES_OFFSET: usize = 88;
const SVD_LOGICAL_BLOCK_SIZE_OFFSET: usize = 128;
const SVD_TYPE_L_PATH_TABLE_OFFSET: usize = 140;
const SVD_TYPE_M_PATH_TABLE_OFFSET: usize = 148;
const SVD_ROOT_DIRECTORY_RECORD_OFFSET: usize = 156;
const SVD_FILE_STRUCTURE_VERSION_OFFSET: usize = 881;
const SVD_RESERVED2_OFFSET: usize = 882;
const SVD_RESERVED2_SIZE: usize = 1;
const SVD_RESERVED3_OFFSET: usize = 1395;
const SVD_RESERVED3_SIZE: usize = 653;

// A directory record (ECMA-119 9.1). Numbers are recorded in both byte
// orders; the offsets are of the little-endian one.
const DR_LENGTH_OFFSET: usize = 0;
const DR_EXTENT_OFFSET: usize = 2;
const DR_SIZE_OFFSET: usize = 10;
const DR_DATE_OFFSET: usize = 18;
const DR_FLAGS_OFFSET: usize = 25;
const DR_VOLUME_SEQUENCE_NUMBER_OFFSET: usize = 28;
const DR_NAME_LEN_OFFSET: usize = 32;
const DR_NAME_OFFSET: usize = 33;

/// The first bytes of a file compressed with zisofs.
const ZISOFS_MAGIC: [u8; 8] = [0x37, 0xE4, 0x53, 0x96, 0xC9, 0xDB, 0xD6, 0x07];

/// `UTF16_NAME_MAX`: the longest Joliet path, in bytes.
const UTF16_NAME_MAX: usize = 1024;

/// Which of an entry's times the image gives (`time_is_set`).
const BIRTHTIME_IS_SET: u8 = 1;
const MTIME_IS_SET: u8 = 2;
const ATIME_IS_SET: u8 = 4;
const CTIME_IS_SET: u8 = 8;

/// The image's format, as `archive_format` gives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    /// `ARCHIVE_FORMAT_ISO9660`.
    Iso9660,
    /// `ARCHIVE_FORMAT_ISO9660_ROCKRIDGE`: the root directory has Rock
    /// Ridge entries.
    Iso9660RockRidge,
}

impl Format {
    /// libarchive's number for it.
    pub fn code(self) -> i32 {
        match self {
            Format::Iso9660 => 0x40000,
            Format::Iso9660RockRidge => 0x40001,
        }
    }

    /// libarchive's name for it, `archive_format_name`.
    pub fn name(self) -> &'static str {
        match self {
            Format::Iso9660 => "ISO9660",
            Format::Iso9660RockRidge => "ISO9660 with Rockridge extensions",
        }
    }
}

fn le16(p: &[u8]) -> u16 {
    u16::from_le_bytes([p[0], p[1]])
}

fn le32(p: &[u8]) -> u32 {
    u32::from_le_bytes([p[0], p[1], p[2], p[3]])
}

fn be32(p: &[u8]) -> u32 {
    u32::from_be_bytes([p[0], p[1], p[2], p[3]])
}

/// A record's index in [`Iso9660::files`].
type Fid = usize;

/// `struct content`: one extent of a file in several.
#[derive(Clone, Copy, Debug, Default)]
struct Content {
    offset: u64,
    size: u64,
}

/// Where a list's last link is: the C's `**last`, which points at the
/// list's head or at the `next` or `re_next` of its last record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tail {
    Head,
    Next(Fid),
    ReNext(Fid),
}

/// A list linked through the records, as the C's `{ first, last }`.
#[derive(Clone, Copy, Debug)]
struct List {
    first: Option<Fid>,
    last: Tail,
}

impl List {
    const fn new() -> List {
        List {
            first: None,
            last: Tail::Head,
        }
    }
}

/// `struct file_info`: a directory record, and what the extensions said.
#[derive(Debug)]
struct FileInfo {
    parent: Option<Fid>,
    /// The link of `cache_files` and the empty files' list.
    next: Option<Fid>,
    /// The link of `re_files` and of `rede_files`.
    re_next: Option<Fid>,
    subdirs: i32,
    /// The heap key.
    key: u64,
    offset: u64,
    size: u64,
    ce_offset: u32,
    ce_size: u32,
    ce_processed_end: u64,
    rr_moved: bool,
    rr_moved_has_re_only: bool,
    re: bool,
    re_descendant: bool,
    cl_offset: u64,
    time_is_set: u8,
    birthtime: i64,
    mtime: i64,
    atime: i64,
    ctime: i64,
    rdev: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    number: i64,
    nlinks: i32,
    name: ArchiveString,
    utf16be_name: Vec<u8>,
    name_continues: bool,
    symlink: ArchiveString,
    symlink_continues: bool,
    pz: bool,
    pz_log2_bs: i32,
    pz_uncompressed_size: u64,
    multi_extent: bool,
    contents: Vec<Content>,
    rede_files: List,
}

impl Default for FileInfo {
    fn default() -> FileInfo {
        FileInfo {
            parent: None,
            next: None,
            re_next: None,
            subdirs: 0,
            key: 0,
            offset: 0,
            size: 0,
            ce_offset: 0,
            ce_size: 0,
            ce_processed_end: 0,
            rr_moved: false,
            rr_moved_has_re_only: false,
            re: false,
            re_descendant: false,
            cl_offset: 0,
            time_is_set: 0,
            birthtime: 0,
            mtime: 0,
            atime: 0,
            ctime: 0,
            rdev: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            number: 0,
            nlinks: 0,
            name: ArchiveString::default(),
            utf16be_name: Vec::new(),
            name_continues: false,
            symlink: ArchiveString::default(),
            symlink_continues: false,
            pz: false,
            pz_log2_bs: 0,
            pz_uncompressed_size: 0,
            multi_extent: false,
            contents: Vec::new(),
            rede_files: List::new(),
        }
    }
}

/// libarchive's `struct archive_string`: a buffer, unallocated at first,
/// and a length. Emptying it only sets the length to 0, so the C string in
/// the buffer (what `%s` prints, `strcmp` compares, and an entry's symbolic
/// link is copied from) can still be the old one.
#[derive(Clone, Debug, Default)]
struct ArchiveString {
    s: Option<Vec<u8>>,
    length: usize,
}

impl ArchiveString {
    /// `archive_string_empty`.
    fn empty(&mut self) {
        self.length = 0;
    }

    /// `archive_strncat`: `src` up to its first NUL, appended, then a NUL.
    fn cat(&mut self, src: &[u8]) {
        let n = src.iter().position(|&b| b == 0).unwrap_or(src.len());
        let s = self.s.get_or_insert_with(Vec::new);
        let end = self.length + n;
        if s.len() < end + 1 {
            s.resize(end + 1, 0);
        }
        s[self.length..end].copy_from_slice(&src[..n]);
        s[end] = 0;
        self.length = end;
    }

    /// The bytes, by the length (`archive_strlen`, `archive_string_concat`).
    fn bytes(&self) -> &[u8] {
        self.s.as_deref().map_or(&[], |s| &s[..self.length])
    }

    /// The C string `s`, up to its NUL; `None` while unallocated.
    fn c_str(&self) -> Option<&[u8]> {
        let s = self.s.as_deref()?;
        let n = s.iter().position(|&b| b == 0).unwrap_or(s.len());
        Some(&s[..n])
    }
}

/// `struct zisofs`: the state of reading a file compressed with zisofs.
#[derive(Default)]
struct Zisofs {
    pz: bool,
    pz_log2_bs: i32,
    pz_uncompressed_size: u64,
    initialized: bool,
    uncompressed_buffer: Vec<u8>,
    uncompressed_buffer_size: usize,
    pz_offset: u32,
    header: [u8; 16],
    header_avail: usize,
    header_passed: bool,
    block_pointers: Vec<u8>,
    block_pointers_size: usize,
    block_pointers_avail: usize,
    block_off: usize,
    block_avail: u32,
    /// The zlib stream, once made (`stream_valid`).
    stream: Option<Inflate>,
}

impl core::fmt::Debug for Zisofs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Zisofs")
            .field("pz", &self.pz)
            .field("pz_log2_bs", &self.pz_log2_bs)
            .field("pz_uncompressed_size", &self.pz_uncompressed_size)
            .field("initialized", &self.initialized)
            .field("pz_offset", &self.pz_offset)
            .field("block_off", &self.block_off)
            .field("block_avail", &self.block_avail)
            .finish_non_exhaustive()
    }
}

/// `struct vd`: where a volume's root directory is.
#[derive(Clone, Copy, Debug, Default)]
struct Vd {
    location: i32,
    size: u32,
}

/// Which volume descriptor's tree is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Volume {
    Primary,
    Joliet,
}

/// What finding the next entry gave.
pub(crate) enum Step {
    File(Fid),
    Eof,
    /// `ARCHIVE_WARN` from reading a directory: an empty entry.
    Warn(Warning),
}

/// What `read_header` gives.
pub(crate) enum Next {
    Entry(Box<Entry>),
    Eof,
}

/// What one call of `read_data` gave.
pub(crate) enum Data {
    /// This many bytes of the file were copied out.
    Bytes(usize),
    /// This many decompressed bytes are in the zisofs buffer.
    Zisofs(usize),
    Eof,
    Warn(Warning),
}

/// `struct iso9660`: the reader's state.
#[derive(Debug)]
pub(crate) struct Iso9660 {
    pub(crate) opt_support_joliet: bool,
    pub(crate) opt_support_rockridge: bool,
    /// The C string `pathname.s`: the path last made, kept after the
    /// string is emptied, as the C's bytes are.
    pathname: Option<Vec<u8>>,
    seen_rockridge: bool,
    seen_susp: bool,
    seen_joliet: u8,
    susp_offset: u8,
    rr_moved: Option<Fid>,
    /// `read_ce_req`: the CE areas to read, a heap by offset.
    read_ce_req: Vec<(u64, Fid)>,
    previous_number: i64,
    previous_pathname: Option<Vec<u8>>,
    /// Every record made, which the C keeps in `use_files`.
    files: Vec<FileInfo>,
    /// `pending_files`: a heap by `key`.
    pending_files: Vec<Fid>,
    cache_files: List,
    re_files: List,
    current_position: u64,
    logical_block_size: i64,
    volume_size: u64,
    volume_block: i32,
    primary: Vd,
    joliet: Vd,
    entry_sparse_offset: i64,
    entry_bytes_remaining: i64,
    entry_zisofs: Zisofs,
    /// `entry_content`: the extent being read of a file in several, as
    /// the record and the extent's index.
    entry_content: Option<(Fid, usize)>,
    utf16be_path: Vec<u8>,
    utf16be_previous_path: Vec<u8>,
    pub(crate) format: Option<Format>,
}

impl Iso9660 {
    /// `archive_read_support_format_iso9660`: Joliet and Rock Ridge on.
    pub(crate) fn new() -> Iso9660 {
        Iso9660 {
            opt_support_joliet: true,
            opt_support_rockridge: true,
            pathname: None,
            seen_rockridge: false,
            seen_susp: false,
            seen_joliet: 0,
            susp_offset: 0,
            rr_moved: None,
            read_ce_req: Vec::new(),
            previous_number: 0,
            previous_pathname: None,
            files: Vec::new(),
            pending_files: Vec::new(),
            cache_files: List::new(),
            re_files: List::new(),
            current_position: 0,
            logical_block_size: 0,
            volume_size: 0,
            volume_block: 0,
            primary: Vd::default(),
            joliet: Vd::default(),
            entry_sparse_offset: 0,
            entry_bytes_remaining: 0,
            entry_zisofs: Zisofs::default(),
            entry_content: None,
            utf16be_path: Vec::new(),
            utf16be_previous_path: Vec::new(),
            format: None,
        }
    }

    fn vd(&self, volume: Volume) -> Vd {
        match volume {
            Volume::Primary => self.primary,
            Volume::Joliet => self.joliet,
        }
    }

    /// The bytes of the zisofs buffer that the last call decompressed.
    pub(crate) fn zisofs_output(&self, from: usize, to: usize) -> &[u8] {
        &self.entry_zisofs.uncompressed_buffer[from..to]
    }

    /// `archive_read_format_iso9660_bid`: 48 for an ISO 9660 image, 0 if
    /// not, -1 if the image is too short to tell.
    pub(crate) fn bid<R: Read>(&mut self, input: &mut Input<R>) -> Result<i32, Error> {
        // The reserved area and the first 8 volume descriptors.
        if !input.has(RESERVED_AREA + 8 * LOGICAL_BLOCK_SIZE)? {
            return Ok(-1);
        }

        // Check each volume descriptor, while more than one block is left.
        let mut seen_terminator = false;
        let mut at = RESERVED_AREA;
        while at - RESERVED_AREA < BID_LIMIT && input.has(at + LOGICAL_BLOCK_SIZE + 1)? {
            let h = &input.buffered()[at..at + LOGICAL_BLOCK_SIZE];
            at += LOGICAL_BLOCK_SIZE;
            // Do not handle undefined Volume Descriptor Types.
            if (4..=254).contains(&h[0]) {
                return Ok(0);
            }
            // The Standard Identifier must be "CD001".
            if &h[1..6] != b"CD001" {
                return Ok(0);
            }
            if self.is_pvd(h) {
                continue;
            }
            if self.joliet.location == 0 && self.is_joliet_svd(h) {
                continue;
            }
            if is_boot_record(h) {
                continue;
            }
            if is_evd(h) {
                continue;
            }
            if is_svd(h) {
                continue;
            }
            if self.is_volume_partition(h) {
                continue;
            }
            if is_vd_set_terminator(h) {
                seen_terminator = true;
                break;
            }
            return Ok(0);
        }
        // An ISO 9660 image has a Primary Volume Descriptor and a Volume
        // Descriptor Set Terminator.
        if seen_terminator && self.primary.location > 16 {
            return Ok(48);
        }
        Ok(0)
    }

    /// `isVolumePartition`.
    fn is_volume_partition(&self, h: &[u8]) -> bool {
        // The type of the Volume Partition Descriptor must be 3, its
        // version 1, and its unused field 0.
        if h[0] != 3 || h[6] != 1 || h[7] != 0 {
            return false;
        }
        let location = le32(&h[72..]) as i32;
        if location <= SYSTEM_AREA_BLOCK || location >= self.volume_block {
            return false;
        }
        location as u32 == be32(&h[76..])
    }

    /// `isJolietSVD`: a Supplementary Volume Descriptor for Joliet, whose
    /// root directory is then kept.
    fn is_joliet_svd(&mut self, h: &[u8]) -> bool {
        if !is_svd(h) {
            return false;
        }
        // The escape sequences say Joliet and its level (the Joliet
        // specification says p[1] == '\\', but images have '/').
        let p = &h[SVD_ESCAPE_SEQUENCES_OFFSET..];
        if p[0] != b'%' || p[1] != b'/' {
            return false;
        }
        let level = match p[2] {
            b'@' => 1,
            b'C' => 2,
            b'E' => 3,
            _ => return false,
        };
        self.seen_joliet = level;

        let logical_block_size = i64::from(le16(&h[SVD_LOGICAL_BLOCK_SIZE_OFFSET..]));
        let volume_block = le32(&h[SVD_VOLUME_SPACE_SIZE_OFFSET..]) as i32;
        self.logical_block_size = logical_block_size;
        self.volume_block = volume_block;
        self.volume_size = (logical_block_size as u64).wrapping_mul(volume_block as i64 as u64);
        // The root directory's record.
        let p = &h[SVD_ROOT_DIRECTORY_RECORD_OFFSET..];
        self.joliet.location = le32(&p[DR_EXTENT_OFFSET..]) as i32;
        self.joliet.size = le32(&p[DR_SIZE_OFFSET..]);
        true
    }

    /// `isPVD`: a Primary Volume Descriptor; the first one's root directory
    /// and sizes are kept.
    fn is_pvd(&mut self, h: &[u8]) -> bool {
        // The type must be 1, the version 1, the reserved fields 0.
        if h[PVD_TYPE_OFFSET] != 1 || h[PVD_VERSION_OFFSET] != 1 || h[PVD_RESERVED1_OFFSET] != 0 {
            return false;
        }
        if !is_null(h, PVD_RESERVED2_OFFSET, PVD_RESERVED2_SIZE) {
            return false;
        }
        // The volume space size, recorded both ways (7.3.3).
        if !is_valid_733_integer(&h[PVD_VOLUME_SPACE_SIZE_OFFSET..]) {
            return false;
        }
        let volume_block = le32(&h[PVD_VOLUME_SPACE_SIZE_OFFSET..]) as i32;
        if volume_block <= SYSTEM_AREA_BLOCK + 4 {
            return false;
        }
        if !is_null(h, PVD_RESERVED3_OFFSET, PVD_RESERVED3_SIZE) {
            return false;
        }
        // The volume set size, sequence number and logical block size
        // (7.2.3), and the path table size (7.3.3).
        if !is_valid_723_integer(&h[PVD_VOLUME_SET_SIZE_OFFSET..])
            || !is_valid_723_integer(&h[PVD_VOLUME_SEQUENCE_NUMBER_OFFSET..])
            || !is_valid_723_integer(&h[PVD_LOGICAL_BLOCK_SIZE_OFFSET..])
        {
            return false;
        }
        let logical_block_size = i64::from(le16(&h[PVD_LOGICAL_BLOCK_SIZE_OFFSET..]));
        if logical_block_size <= 0 {
            return false;
        }
        if !is_valid_733_integer(&h[PVD_PATH_TABLE_SIZE_OFFSET..]) {
            return false;
        }
        // The file structure version must be 1 for ISO 9660.
        if h[PVD_FILE_STRUCTURE_VERSION_OFFSET] != 1 {
            return false;
        }
        // The Type L Path Table must be within the volume.
        let location = le32(&h[PVD_TYPE_1_PATH_TABLE_OFFSET..]) as i32;
        if location < SYSTEM_AREA_BLOCK + 2 || location >= volume_block {
            return false;
        }
        // So must the Type M Path Table, though WinISO and probably other
        // programs leave it out (zero).
        let location = be32(&h[PVD_TYPE_M_PATH_TABLE_OFFSET..]) as i32;
        if (location > 0 && location < SYSTEM_AREA_BLOCK + 2) || location >= volume_block {
            return false;
        }
        // Reserved, but NetBSD's and FreeBSD's makefs write 0x20.
        for i in 0..PVD_RESERVED4_SIZE {
            let b = h[PVD_RESERVED4_OFFSET + i];
            if b != 0 && b != 0x20 {
                return false;
            }
        }
        if !is_null(h, PVD_RESERVED5_OFFSET, PVD_RESERVED5_SIZE) {
            return false;
        }
        let p = &h[PVD_ROOT_DIRECTORY_RECORD_OFFSET..];
        if !is_root_directory_record(p) {
            return false;
        }
        if self.primary.location == 0 {
            self.logical_block_size = logical_block_size;
            self.volume_block = volume_block;
            self.volume_size = (logical_block_size as u64).wrapping_mul(volume_block as i64 as u64);
            self.primary.location = le32(&p[DR_EXTENT_OFFSET..]) as i32;
            self.primary.size = le32(&p[DR_SIZE_OFFSET..]);
        }
        true
    }

    /// `read_children`: the records of a directory, into the heap; then the
    /// CE areas that are next in the image.
    fn read_children<R: Read>(
        &mut self,
        input: &mut Input<R>,
        parent: Fid,
    ) -> Result<Option<Warning>, Error> {
        let (parent_offset, parent_size) = (self.files[parent].offset, self.files[parent].size);
        if self.current_position > parent_offset {
            return Ok(Some(Warning::DirectoryOutOfOrder {
                name: self.files[parent].name.c_str().map(<[u8]>::to_vec),
                position: self.current_position as i64,
                offset: parent_offset as i64,
            }));
        }
        if parent_offset.wrapping_add(parent_size) > self.volume_size {
            return Ok(Some(Warning::DirectoryBeyondEnd {
                name: self.files[parent].name.c_str().map(<[u8]>::to_vec),
            }));
        }
        if self.current_position < parent_offset {
            input.consume(parent_offset.wrapping_sub(self.current_position) as i64)?;
            self.current_position = parent_offset;
        }

        let block_size = self.logical_block_size as u64;
        let step = parent_size.div_ceil(block_size) * block_size;
        let Some(b) = input.ahead(step as usize)? else {
            return Err(Error::DirectoryRead);
        };
        self.current_position += step;
        let block_size = block_size as usize;
        let mut multi: Option<Fid> = None;
        let mut block = 0;
        let mut left = step as usize;
        while left > 0 {
            let mut p = block;
            let end = block + block_size;
            left -= block_size;
            while p < end && end - p > DR_NAME_OFFSET && b[p] != 0 && b[p] as usize <= end - p {
                let len = b[p] as usize;
                // The records "." and "..", whose identifiers are 8-bit
                // values even on a Joliet volume.
                if b[p + DR_NAME_LEN_OFFSET] == 1
                    && (b[p + DR_NAME_OFFSET] == 0 || b[p + DR_NAME_OFFSET] == 1)
                {
                    p += len;
                    continue;
                }
                let child = self.parse_file_info(Some(parent), &b[p..end])?;
                if self.files[child].cl_offset == 0
                    && (self.files[child].multi_extent || multi.is_some())
                {
                    let m = match multi {
                        Some(m) => m,
                        None => {
                            self.files[child].contents.clear();
                            multi = Some(child);
                            child
                        }
                    };
                    let content = Content {
                        offset: self.files[child].offset,
                        size: self.files[child].size,
                    };
                    self.files[m].contents.push(content);
                    if m == child {
                        let key = self.files[child].offset;
                        self.heap_add_entry(child, key);
                    } else {
                        self.files[m].size = self.files[m].size.wrapping_add(content.size);
                        if !self.files[child].multi_extent {
                            multi = None;
                        }
                    }
                } else {
                    let key = self.files[child].offset;
                    self.heap_add_entry(child, key);
                }
                p += len;
            }
            block = end;
        }
        input.consume(step as i64)?;

        // The areas RRIP "CE" entries point at.
        self.read_ce(input)?;
        Ok(None)
    }

    /// `choose_volume`: the root directory, of the primary volume or of
    /// Joliet's; Rock Ridge wins over Joliet.
    fn choose_volume<R: Read>(&mut self, input: &mut Input<R>) -> Result<(), Error> {
        let mut volume = Volume::Primary;
        if !self.opt_support_joliet {
            self.seen_joliet = 0;
        }
        if self.seen_joliet != 0 && self.primary.location > self.joliet.location {
            // Unlikely; by way of caution.
            volume = Volume::Joliet;
        }

        let skip = LOGICAL_BLOCK_SIZE as i64 * i64::from(self.vd(volume).location);
        input.consume(skip)?;
        self.current_position = skip as u64;

        let size = self.vd(volume).size as usize;
        let Some(block) = input.ahead(size)? else {
            return Err(Error::DirectoryRead);
        };

        // While the root directory is read, Joliet is off, so that its
        // name, 0x00, is not taken as UCS-2 with the byte after it.
        let seen_joliet = self.seen_joliet;
        self.seen_joliet = 0;
        let mut file = self.parse_file_info(None, &block[..size])?;
        self.seen_joliet = seen_joliet;

        // With both Rock Ridge and Joliet, Rock Ridge is used.
        if volume == Volume::Primary && self.seen_rockridge && self.seen_joliet != 0 {
            self.seen_joliet = 0;
        }
        if volume == Volume::Primary && !self.seen_rockridge && self.seen_joliet != 0 {
            // Switch from the primary volume to Joliet's.
            volume = Volume::Joliet;
            let skip = LOGICAL_BLOCK_SIZE as i64 * i64::from(self.vd(volume).location)
                - self.current_position as i64;
            input.consume(skip)?;
            self.current_position = self.current_position.wrapping_add(skip as u64);

            let size = self.vd(volume).size as usize;
            let Some(block) = input.ahead(size)? else {
                return Err(Error::DirectoryRead);
            };
            self.seen_joliet = 0;
            file = self.parse_file_info(None, &block[..size])?;
            self.seen_joliet = seen_joliet;
        }

        // The root directory is the first pending entry.
        let key = self.files[file].offset;
        self.heap_add_entry(file, key);
        if self.seen_rockridge {
            self.format = Some(Format::Iso9660RockRidge);
        }
        Ok(())
    }

    /// `archive_read_format_iso9660_read_header`.
    pub(crate) fn read_header<R: Read>(&mut self, input: &mut Input<R>) -> Result<Next, Error> {
        if self.format.is_none() {
            self.format = Some(Format::Iso9660);
        }
        if self.current_position == 0 {
            self.choose_volume(input)?;
        }

        // The next entry after the current offset.
        let file = match self.next_entry_seek(input)? {
            Step::File(file) => file,
            Step::Eof => return Ok(Next::Eof),
            Step::Warn(warning) => {
                let mut entry = Entry::default();
                entry.header.warning = Some(warning);
                return Ok(Next::Entry(Box::new(entry)));
            }
        };

        let mut entry = Entry::default();
        let mut rd_r: Option<Warning> = None;
        if self.seen_joliet != 0 {
            // The path in UTF-16BE, converted to the locale's charset.
            self.utf16be_path = self
                .build_pathname_utf16be(file)
                .ok_or(Error::PathnameTooLong)?;
            match crate::iso::string::utf16be_to_utf8(&self.utf16be_path) {
                Some(path) => entry.header.path = Some(path),
                None => rd_r = Some(Warning::PathnameConversion),
            }
        } else {
            let path = self.build_pathname(file).ok_or(Error::PathnameTooLong)?;
            entry.header.path = Some(path.clone());
            self.pathname = Some(path);
        }

        let f = &self.files[file];
        self.entry_bytes_remaining = f.size as i64;
        // The offset for sparse-aware readers.
        self.entry_sparse_offset = 0;

        if f.offset.wrapping_add(f.size) > self.volume_size {
            entry.header.warning = Some(Warning::FileBeyondEnd {
                path: entry.header.path.clone(),
            });
            self.entry_bytes_remaining = 0;
            return Ok(Next::Entry(Box::new(entry)));
        }

        // What the record and its extensions say.
        let h = &mut entry.header;
        h.mode = f.mode;
        h.uid = f.uid;
        h.gid = f.gid;
        h.nlink = f.nlinks as u32;
        if f.time_is_set & BIRTHTIME_IS_SET != 0 {
            h.birth_time = Some(f.birthtime);
        }
        if f.time_is_set & MTIME_IS_SET != 0 {
            h.mod_time = Some(f.mtime);
        }
        if f.time_is_set & CTIME_IS_SET != 0 {
            h.change_time = Some(f.ctime);
        }
        if f.time_is_set & ATIME_IS_SET != 0 {
            h.access_time = Some(f.atime);
        }
        // Rock Ridge has 64-bit device numbers.
        h.rdev = f.rdev;
        h.size = Some(self.entry_bytes_remaining.max(0) as u64);
        if let Some(symlink) = f.symlink.c_str() {
            entry.copy_symlink(symlink);
        }

        // An input that cannot seek cannot go back for the same data, so an
        // entry with the same serial number as the one before is a hard
        // link to it.
        if f.number != -1 && f.number == self.previous_number {
            if self.seen_joliet != 0 {
                let target = crate::iso::string::utf16be_to_utf8(&self.utf16be_previous_path);
                if target.is_none() {
                    rd_r = Some(Warning::LinknameConversion);
                }
                entry.copy_hardlink_l(target);
            } else {
                entry.set_hardlink(self.previous_pathname.as_deref());
            }
            entry.header.size = None;
            self.entry_bytes_remaining = 0;
            entry.header.warning = rd_r;
            return Ok(Next::Entry(Box::new(entry)));
        }

        if f.mode & AE_IFMT != AE_IFDIR && f.offset < self.current_position {
            let offset = f.offset;
            match input.seek(offset) {
                Some(Ok(at)) if at == offset => self.current_position = at,
                Some(Err(e)) => return Err(Error::Io(e)),
                _ => {
                    // The data is behind, and the input cannot go back:
                    // only images whose directory comes after a file's
                    // data are laid out so.
                    entry.header.warning = Some(Warning::FileOutOfOrder {
                        number: self.files[file].number as u64,
                        path: self.pathname.clone(),
                        offset: offset as i64,
                        position: self.current_position as i64,
                    });
                    self.entry_bytes_remaining = 0;
                    return Ok(Next::Entry(Box::new(entry)));
                }
            }
        }

        let f = &self.files[file];
        let z = &mut self.entry_zisofs;
        z.pz = f.pz;
        if f.pz {
            z.initialized = false;
            z.pz_log2_bs = f.pz_log2_bs;
            z.pz_uncompressed_size = f.pz_uncompressed_size;
            z.pz_offset = 0;
            z.header_avail = 0;
            z.header_passed = false;
            z.block_pointers_avail = 0;
            entry.header.size = Some(f.pz_uncompressed_size);
        }

        self.previous_number = f.number;
        if self.seen_joliet != 0 {
            self.utf16be_previous_path.clone_from(&self.utf16be_path);
        } else {
            self.previous_pathname = Some(self.pathname.clone().unwrap_or_default());
        }

        // A file in several extents reads them in turn.
        self.entry_content = if f.contents.is_empty() {
            None
        } else {
            Some((file, 0))
        };
        if let Some((file, 0)) = self.entry_content {
            self.entry_bytes_remaining = self.files[file].contents[0].size as i64;
        }

        if entry.header.mode & AE_IFMT == AE_IFDIR {
            // The number of links, from the number of subdirectories.
            entry.header.nlink = 2i32.wrapping_add(self.files[file].subdirs) as u32;
            // A directory's records were read already.
            self.entry_bytes_remaining = 0;
        }
        entry.header.warning = rd_r;
        Ok(Next::Entry(Box::new(entry)))
    }

    /// `zisofs_read_data`: one call, with the rest of the file's data (as
    /// far as the image has it) available, as libarchive has it with the
    /// image in memory.
    fn zisofs_read_data<R: Read>(&mut self, input: &mut Input<R>) -> Result<Data, Error> {
        if !input.has(1)? {
            return Err(Error::ZisofsTruncated);
        }
        // What this call may read, and has read (`bytes_read - avail`).
        let budget = self.entry_bytes_remaining as u64;
        let mut consumed = 0u64;
        let mut uncompressed_size = 0usize;
        let z = &mut self.entry_zisofs;

        'next_data: {
            if !z.initialized {
                // The block pointers.
                let ceil = (z.pz_uncompressed_size + (1u64 << z.pz_log2_bs) - 1) >> z.pz_log2_bs;
                let xsize = (ceil as usize + 1) * 4;
                if z.block_pointers.len() < xsize {
                    let alloc = ((xsize >> 10) + 1) << 10;
                    z.block_pointers = vec![0; alloc];
                }
                z.block_pointers_size = xsize;

                // The decompressed block.
                let xsize = 1usize << z.pz_log2_bs;
                if z.uncompressed_buffer.len() < xsize {
                    z.uncompressed_buffer = vec![0; xsize];
                }
                z.uncompressed_buffer_size = xsize;

                // The file's header, and its magic number.
                if z.header_avail < z.header.len() {
                    let want = z.header.len() - z.header_avail;
                    let got = take(
                        input,
                        &mut z.header[z.header_avail..z.header_avail + want],
                        budget - consumed,
                    )?;
                    z.header_avail += got;
                    consumed += got as u64;
                }
                if !z.header_passed && z.header_avail == z.header.len() {
                    if z.header[..8] != ZISOFS_MAGIC
                        || u64::from(le32(&z.header[8..])) != z.pz_uncompressed_size
                        || z.header[12] != 4
                        || i32::from(z.header[13]) != z.pz_log2_bs
                    {
                        return Err(Error::ZisofsBody);
                    }
                    z.header_passed = true;
                }
                // The block pointers.
                if z.header_passed && z.block_pointers_avail < z.block_pointers_size {
                    let (from, to) = (z.block_pointers_avail, z.block_pointers_size);
                    let got = take(input, &mut z.block_pointers[from..to], budget - consumed)?;
                    z.block_pointers_avail += got;
                    consumed += got as u64;
                    if z.block_pointers_avail == z.block_pointers_size {
                        // All of them: initialized.
                        z.block_off = 0;
                        z.block_avail = 0;
                        z.initialized = true;
                    }
                }
                if !z.initialized {
                    // More data is needed.
                    break 'next_data;
                }
            }

            // The next block's offsets, from the block pointers.
            if z.block_avail == 0 {
                if z.block_off + 4 >= z.block_pointers_size {
                    // There is not a pair of offsets.
                    return Err(Error::ZisofsPointers);
                }
                let bst = le32(&z.block_pointers[z.block_off..]);
                if u64::from(bst) != u64::from(z.pz_offset) + consumed {
                    return Err(Error::ZisofsSeek);
                }
                let bed = le32(&z.block_pointers[z.block_off + 4..]);
                if bed < bst {
                    return Err(Error::ZisofsPointers);
                }
                z.block_avail = bed - bst;
                z.block_off += 4;

                // A zlib stream for the new block.
                match &mut z.stream {
                    Some(stream) => stream.reset(),
                    None => z.stream = Some(Inflate::new_default()),
                }
            }

            // The decompressed data.
            if z.block_avail == 0 {
                // An empty block is a block of zeros.
                z.uncompressed_buffer[..z.uncompressed_buffer_size].fill(0);
                uncompressed_size = z.uncompressed_buffer_size;
            } else {
                let Zisofs {
                    stream,
                    uncompressed_buffer,
                    uncompressed_buffer_size,
                    block_avail,
                    ..
                } = z;
                let stream = stream.get_or_insert_with(Inflate::new_default);
                let mut out = OutBuffer::new(&mut uncompressed_buffer[..*uncompressed_buffer_size]);
                // One inflate() of all the block the image has: in pieces as
                // the input buffers it, which zlib takes the same way.
                let mut first = true;
                loop {
                    let limit = u64::from(*block_avail).min(budget - consumed);
                    let (status, used) = {
                        let chunk: &[u8] = match input.ahead(1)? {
                            Some(chunk) if limit > 0 => &chunk[..chunk.len().min(limit as usize)],
                            _ => &[],
                        };
                        if chunk.is_empty() && !first {
                            break;
                        }
                        let mut inb = InBuffer::new(chunk);
                        let status = stream.inflate(&mut out, &mut inb, Flush::NoFlush);
                        let more = inb.pos == chunk.len();
                        (status.map(|s| (s, more)), inb.pos)
                    };
                    first = false;
                    input.consume(used as i64)?;
                    consumed += used as u64;
                    *block_avail -= used as u32;
                    match status {
                        Ok((Status::Ok, more)) => {
                            if !more || out.pos == out.dst.len() {
                                break;
                            }
                        }
                        Ok((Status::StreamEnd, _)) => break,
                        Ok((Status::NeedDict, _)) => return Err(Error::ZisofsInflate(2)),
                        Err(e) => return Err(Error::ZisofsInflate(e.code().number())),
                    }
                }
                uncompressed_size = out.pos;
            }
        }

        z.pz_offset = z.pz_offset.wrapping_add(consumed as u32);
        self.entry_sparse_offset += uncompressed_size as i64;
        self.entry_bytes_remaining -= consumed as i64;
        self.current_position += consumed;
        if uncompressed_size == 0 && consumed == 0 {
            // Differs from libarchive, which returns nothing again and
            // again here: a block whose zlib stream ended before the block.
            return Err(Error::ZisofsStuck);
        }
        Ok(Data::Zisofs(uncompressed_size))
    }

    /// `archive_read_format_iso9660_read_data`: the next piece of the
    /// current entry's data, up to `buf.len()` bytes copied into `buf`, or
    /// decompressed into the zisofs buffer.
    pub(crate) fn read_data<R: Read>(
        &mut self,
        input: &mut Input<R>,
        buf: &mut [u8],
    ) -> Result<Data, Error> {
        if self.entry_bytes_remaining <= 0 {
            if let Some((file, i)) = self.entry_content {
                self.entry_content =
                    (i + 1 < self.files[file].contents.len()).then_some((file, i + 1));
            }
            let Some((file, i)) = self.entry_content else {
                return Ok(Data::Eof);
            };
            let content = self.files[file].contents[i];
            // Forward to the extent.
            if self.current_position < content.offset {
                input.consume(content.offset.wrapping_sub(self.current_position) as i64)?;
                self.current_position = content.offset;
            }
            if content.offset < self.current_position {
                return Ok(Data::Warn(Warning::ExtentOutOfOrder {
                    path: self.pathname.clone(),
                    offset: content.offset as i64,
                    position: self.current_position as i64,
                }));
            }
            self.entry_bytes_remaining = content.size as i64;
        }
        if self.entry_zisofs.pz {
            return self.zisofs_read_data(input);
        }

        let Some(chunk) = input.ahead(1)? else {
            return Err(Error::TruncatedFile);
        };
        let n = chunk
            .len()
            .min(buf.len())
            .min(self.entry_bytes_remaining as u64 as usize);
        buf[..n].copy_from_slice(&chunk[..n]);
        input.consume(n as i64)?;
        self.entry_sparse_offset += n as i64;
        self.entry_bytes_remaining -= n as i64;
        self.current_position += n as u64;
        Ok(Data::Bytes(n))
    }

    /// `parse_file_info`: a directory record, its extensions, and what they
    /// mean for the record's place in the tree. `isodirrec` runs to the end
    /// of the logical block (`reclen`).
    fn parse_file_info(&mut self, parent: Option<Fid>, isodirrec: &[u8]) -> Result<Fid, Error> {
        let reclen = isodirrec.len();
        let dr_len = if reclen != 0 {
            isodirrec[DR_LENGTH_OFFSET] as usize
        } else {
            0
        };
        // The record fits, and is at least 34 bytes.
        if reclen == 0 || reclen < dr_len || dr_len < 34 {
            return Err(Error::RecordLength);
        }
        let mut name_len = isodirrec[DR_NAME_LEN_OFFSET] as usize;
        let location = le32(&isodirrec[DR_EXTENT_OFFSET..]) as i32;
        let fsize = u64::from(le32(&isodirrec[DR_SIZE_OFFSET..]));
        // The name fits in the record.
        if dr_len - 33 < name_len || name_len == 0 {
            return Err(Error::IdentifierLength);
        }
        // The extent is within the volume. Its location may be negative,
        // for a symbolic link or an empty file: recent mkisofs does that.
        let block_size = self.logical_block_size as u64;
        if location > 0
            && (location as u64)
                .wrapping_add(fsize.wrapping_add(block_size).wrapping_sub(1) / block_size)
                > u64::from(self.volume_block as u32)
        {
            return Err(Error::ExtentLocation);
        }
        // A file with data has a location that is not negative.
        if fsize != 0 && location < 0 {
            return Err(Error::ExtentLocation);
        }

        // The record does not make a loop.
        let offset = block_size.wrapping_mul(location as i64 as u64);
        if self.chain_has_offset(parent, offset) {
            return Err(Error::Loop);
        }

        let mut file = FileInfo {
            parent,
            offset,
            size: fsize,
            ..FileInfo::default()
        };
        let date = &isodirrec[DR_DATE_OFFSET..DR_DATE_OFFSET + 7];
        if isodate7_valid(date) {
            file.time_is_set |= MTIME_IS_SET | ATIME_IS_SET | CTIME_IS_SET;
            file.mtime = isodate7(date);
            file.ctime = file.mtime;
            file.atime = file.mtime;
        }

        let p = DR_NAME_OFFSET;
        // Rock Ridge entries, if any, follow the name (and its padding).
        let mut rr_start = p + name_len + if name_len & 1 != 0 { 0 } else { 1 };
        let rr_end = dr_len;

        if self.seen_joliet != 0 {
            // Joliet names are at most 64 characters (128 bytes) by the
            // specification, but genisoimage and mkisofs' -joliet-long
            // record up to 103 (206 bytes).
            name_len = name_len.min(206) & !1;
            // Without the trailing ";1", in UTF-16BE.
            let n = &isodirrec[p..p + name_len];
            if name_len > 4 && n[name_len - 4..] == [0, b';', 0, b'1'] {
                name_len -= 4;
            }
            file.utf16be_name = isodirrec[p..p + name_len].to_vec();
        } else {
            // Without the trailing ";1", and a trailing ".".
            let n = &isodirrec[p..p + name_len];
            if name_len > 2 && n[name_len - 2] == b';' && n[name_len - 1] == b'1' {
                name_len -= 2;
            }
            if name_len > 1 && isodirrec[p + name_len - 1] == b'.' {
                name_len -= 1;
            }
            file.name.cat(&isodirrec[p..p + name_len]);
        }

        let flags = isodirrec[DR_FLAGS_OFFSET];
        file.mode = if flags & 0x02 != 0 {
            AE_IFDIR | 0o700
        } else {
            AE_IFREG | 0o400
        };
        file.multi_extent = flags & 0x80 != 0;
        // The location is the file's serial number, which finds hard links;
        // Rock Ridge's PX overwrites it. An empty file's location points
        // anywhere, and xorriso gives symbolic links location 0.
        if file.size == 0 && location >= 0 {
            file.number = -1;
            // Not before any directory.
            file.offset = u64::MAX;
        } else {
            file.number = i64::from(location as u32);
        }

        let fid = self.files.len();
        self.files.push(file);

        // Rock Ridge overwrites what the record said.
        if self.opt_support_rockridge {
            if parent.is_none() && rr_end as isize - rr_start as isize >= 7 {
                let sp = &isodirrec[rr_start..];
                if sp[..6] == *b"SP\x07\x01\xbe\xef" {
                    // SUSP's SP entry, in the root directory: how many
                    // bytes to skip between the name and SUSP's entries.
                    // Without it, no SUSP at all.
                    self.susp_offset = sp[6];
                    self.seen_susp = true;
                    rr_start += 7;
                }
            }
            if self.seen_susp {
                self.files[fid].name_continues = false;
                self.files[fid].symlink_continues = false;
                rr_start += usize::from(self.susp_offset);
                let area = isodirrec.get(rr_start..rr_end).unwrap_or(&[]);
                self.parse_rockridge(fid, area)?;
                // makefs gives symbolic links a size and the location of
                // the next file: not a hard link.
                let f = &mut self.files[fid];
                if f.size > 0 && f.mode & AE_IFMT == AE_IFLNK {
                    f.size = 0;
                    f.number = -1;
                    f.offset = u64::MAX;
                }
            } else {
                // No SUSP: no Rock Ridge.
                self.opt_support_rockridge = false;
            }
        }

        // The number of links is worked out later.
        self.files[fid].nlinks = 1;
        // The parent's number of subdirectories.
        if let Some(parent) = parent
            && flags & 0x02 != 0
        {
            self.files[parent].subdirs = self.files[parent].subdirs.wrapping_add(1);
        }

        if self.seen_rockridge {
            let is_rr_moved = matches!(
                self.files[fid].name.c_str(),
                Some(b"rr_moved" | b".rr_moved")
            );
            if let Some(par) = parent
                && self.files[par].parent.is_none()
                && flags & 0x02 != 0
                && self.rr_moved.is_none()
                && is_rr_moved
            {
                self.rr_moved = Some(fid);
                let f = &mut self.files[fid];
                f.rr_moved = true;
                f.rr_moved_has_re_only = true;
                f.re = false;
                self.files[par].subdirs = self.files[par].subdirs.wrapping_sub(1);
            } else if self.files[fid].re {
                // The parent is rr_moved; no CL as well; a directory.
                if parent.is_none_or(|par| !self.files[par].rr_moved) {
                    return Err(Error::RockRidgeRe);
                }
                if self.files[fid].cl_offset != 0 {
                    return Err(Error::RockRidgeReCl);
                }
                if flags & 0x02 == 0 {
                    return Err(Error::RockRidgeRe);
                }
            } else if parent.is_some_and(|par| self.files[par].rr_moved) {
                self.files[fid].rr_moved_has_re_only = false;
            } else if let Some(par) = parent
                && flags & 0x02 != 0
                && (self.files[par].re || self.files[par].re_descendant)
            {
                self.files[fid].re_descendant = true;
            }
            if self.files[fid].cl_offset != 0 {
                let Some(par) = parent.filter(|&par| self.files[par].parent.is_some()) else {
                    return Err(Error::RockRidgeCl);
                };
                // A regular file.
                if flags & 0x02 != 0 {
                    return Err(Error::RockRidgeCl);
                }
                self.files[par].subdirs = self.files[par].subdirs.wrapping_add(1);
                // The CL entry comes before other directories, and after
                // the RE entry it is connected with.
                let cl_offset = self.files[fid].cl_offset;
                self.files[fid].offset = cl_offset.wrapping_add(1);
                self.files[fid].number = cl_offset.wrapping_add(1) as i64;
                // It points at neither its parents nor itself.
                if self.chain_has_offset(Some(par), cl_offset) {
                    return Err(Error::RockRidgeCl);
                }
                if cl_offset == self.files[fid].offset || self.files[par].rr_moved {
                    return Err(Error::RockRidgeCl);
                }
            }
        }
        Ok(fid)
    }

    /// Whether `file` or one of its parents is at `offset`. Differs from
    /// libarchive, whose walk up the parents never ends when they make a
    /// loop (which Rock Ridge's CL and RE entries can make): a loop counts
    /// as found.
    fn chain_has_offset(&self, file: Option<Fid>, offset: u64) -> bool {
        let mut at = file;
        let mut steps = 0;
        while let Some(f) = at {
            if self.files[f].offset == offset || steps > self.files.len() {
                return true;
            }
            steps += 1;
            at = self.files[f].parent;
        }
        false
    }

    /// `parse_rockridge`: the SUSP entries of `area`, which must have one.
    fn parse_rockridge(&mut self, fid: Fid, area: &[u8]) -> Result<(), Error> {
        let mut entry_seen = false;
        let mut p = 0;
        while p + 4 <= area.len()
            && area[p].is_ascii_uppercase()
            && area[p + 1].is_ascii_uppercase()
            && area[p + 2] >= 4
            && p + area[p + 2] as usize <= area.len()
        {
            let len = area[p + 2] as usize;
            let data = &area[p + 4..p + len];
            let version = area[p + 3];
            let file = &mut self.files[fid];
            match (area[p], area[p + 1]) {
                (b'C', b'E') if version == 1 && data.len() == 24 => {
                    // CE: the sector, offset in it and length of a
                    // continuation area.
                    let location = le32(data);
                    file.ce_offset = le32(&data[8..]);
                    file.ce_size = le32(&data[16..]);
                    self.register_ce(location, fid)?;
                }
                (b'C', b'L') if version == 1 && data.len() == 8 => {
                    file.cl_offset =
                        (self.logical_block_size as u64).wrapping_mul(u64::from(le32(data)));
                    self.seen_rockridge = true;
                }
                (b'N', b'M') if version == 1 => {
                    parse_rockridge_nm1(file, data);
                    self.seen_rockridge = true;
                }
                (b'P', b'N') if version == 1 && data.len() == 16 => {
                    file.rdev = u64::from(le32(data)) << 32 | u64::from(le32(&data[8..]));
                    self.seen_rockridge = true;
                }
                (b'P', b'X') if version == 1 => {
                    // PX: mode, links, owner, group and serial number, 8
                    // bytes each. (PD is padding, and PL never appears.)
                    if data.len() >= 8 {
                        file.mode = le32(data);
                    }
                    if data.len() >= 16 {
                        file.nlinks = le32(&data[8..]) as i32;
                    }
                    if data.len() >= 24 {
                        file.uid = le32(&data[16..]);
                    }
                    if data.len() >= 32 {
                        file.gid = le32(&data[24..]);
                    }
                    if data.len() >= 40 {
                        file.number = i64::from(le32(&data[32..]));
                    }
                    self.seen_rockridge = true;
                }
                (b'R', b'E') if version == 1 => {
                    file.re = true;
                    self.seen_rockridge = true;
                }
                (b'S', b'L') if version == 1 => {
                    parse_rockridge_sl1(file, data);
                    self.seen_rockridge = true;
                }
                (b'S', b'T') if data.is_empty() && version == 1 => {
                    // ST: the end of SUSP entries here, and of SUSP.
                    self.seen_susp = false;
                    self.seen_rockridge = false;
                    return Ok(());
                }
                (b'T', b'F') if version == 1 => {
                    parse_rockridge_tf1(file, data);
                    self.seen_rockridge = true;
                }
                (b'Z', b'F') if version == 1 => parse_rockridge_zf1(file, data),
                // RR is obsolete, and ignored as anything else is.
                _ => {}
            }
            p += len;
            entry_seen = true;
        }
        if entry_seen {
            Ok(())
        } else {
            Err(Error::NoRockRidge)
        }
    }

    /// `register_CE`: a continuation area to read when the image gets to
    /// it, which must be ahead.
    fn register_ce(&mut self, location: u32, fid: Fid) -> Result<(), Error> {
        let block_size = self.logical_block_size as u64;
        let file = &self.files[fid];
        let offset = u64::from(location) * block_size;
        let ce_len = u64::from(file.ce_offset) + u64::from(file.ce_size);
        let ce_end = offset + ce_len;
        if (file.mode & AE_IFMT == AE_IFREG && offset >= file.offset)
            || offset < self.current_position
            || ce_len > block_size
            || ce_end > self.volume_size
        {
            return Err(Error::SuspCe);
        }

        // Into the heap: start with the hole at the end, and move it up.
        let heap = &mut self.read_ce_req;
        let mut hole = heap.len();
        heap.push((offset, fid));
        while hole > 0 {
            let parent = (hole - 1) / 2;
            if offset >= heap[parent].0 {
                heap[hole] = (offset, fid);
                return Ok(());
            }
            heap[hole] = heap[parent];
            hole = parent;
        }
        heap[0] = (offset, fid);
        Ok(())
    }

    /// `next_CE`: the first continuation area out of the heap.
    fn next_ce(&mut self) {
        let heap = &mut self.read_ce_req;
        let Some(last) = heap.pop() else {
            return;
        };
        if heap.is_empty() {
            return;
        }
        // The last one at the root, then down.
        heap[0] = last;
        let a_offset = heap[0].0;
        let mut a = 0;
        loop {
            let mut b = a + a + 1;
            if b >= heap.len() {
                return;
            }
            let mut b_offset = heap[b].0;
            let c = b + 1;
            if c < heap.len() && heap[c].0 < b_offset {
                b = c;
                b_offset = heap[c].0;
            }
            if a_offset <= b_offset {
                return;
            }
            heap.swap(a, b);
            a = b;
        }
    }

    /// `read_CE`: the continuation areas in the logical blocks at the
    /// current position, one block after another.
    fn read_ce<R: Read>(&mut self, input: &mut Input<R>) -> Result<(), Error> {
        let step = self.logical_block_size as usize;
        while self
            .read_ce_req
            .first()
            .is_some_and(|&(offset, _)| offset == self.current_position)
        {
            let Some(b) = input.ahead(step)? else {
                return Err(Error::DirectoryRead);
            };
            loop {
                let (offset, fid) = self.read_ce_req[0];
                let file = &self.files[fid];
                let (ce_offset, ce_size) = (file.ce_offset as usize, file.ce_size as usize);
                if ce_offset + ce_size > step {
                    return Err(Error::MalformedCe);
                }
                let ce_start = offset + ce_offset as u64;
                let ce_end = ce_start + ce_size as u64;
                if ce_start < file.ce_processed_end {
                    return Err(Error::SuspCe);
                }
                self.files[fid].ce_processed_end = ce_end;
                self.next_ce();
                self.parse_rockridge(fid, &b[ce_offset..ce_offset + ce_size])?;
                if !self
                    .read_ce_req
                    .first()
                    .is_some_and(|&(offset, _)| offset == self.current_position)
                {
                    break;
                }
            }
            // Consumed only now: a CE entry in the area may point at this
            // same block.
            input.consume(step as i64)?;
            self.current_position += step as u64;
        }
        Ok(())
    }

    /// `next_entry_seek`: the next entry, with the position moved to its
    /// data.
    fn next_entry_seek<R: Read>(&mut self, input: &mut Input<R>) -> Result<Step, Error> {
        let file = match self.next_cache_entry(input)? {
            Step::File(file) => file,
            other => return Ok(other),
        };
        // No moving for an empty body.
        if self.files[file].size == 0 {
            self.files[file].offset = self.current_position;
        }
        // Forward to the entry.
        let offset = self.files[file].offset;
        if self.current_position < offset {
            input.consume(offset.wrapping_sub(self.current_position) as i64)?;
            self.current_position = offset;
        }
        Ok(Step::File(file))
    }

    /// `next_cache_entry`: the next entry in the order the reader gives
    /// them: directories read as they come, entries moved by Rock Ridge put
    /// back in their place, hard links together.
    fn next_cache_entry<R: Read>(&mut self, input: &mut Input<R>) -> Result<Step, Error> {
        if let Some(file) = self.cache_get_entry() {
            return Ok(Step::File(file));
        }

        let mut file;
        loop {
            let Some(next) = self.heap_get_entry() else {
                // The directories under rr_moved that are left.
                if self.re_files.first.is_some()
                    && let Some(rr_moved) = self.rr_moved
                    && self.files[rr_moved].rr_moved_has_re_only
                {
                    self.cache_add_entry(rr_moved);
                }
                while let Some(re) = self.re_get_entry() {
                    while let Some(d) = self.rede_get_entry(re) {
                        self.cache_add_entry(d);
                    }
                }
                return Ok(match self.cache_get_entry() {
                    Some(file) => Step::File(file),
                    None => Step::Eof,
                });
            };
            file = next;

            if self.files[file].cl_offset != 0 {
                // Find the RE directory this CL entry stands for.
                let mut first_re: Option<Fid> = None;
                let mut nexted_re = false;
                loop {
                    let re = self.re_get_entry();
                    if re == first_re {
                        break;
                    }
                    let Some(re) = re else {
                        break;
                    };
                    if first_re.is_none() {
                        first_re = Some(re);
                    }
                    if self.files[re].offset != self.files[file].cl_offset {
                        self.re_add_entry(re);
                        continue;
                    }
                    if let Some(old) = self.files[re].parent {
                        self.files[old].subdirs = self.files[old].subdirs.wrapping_sub(1);
                    }
                    self.files[re].parent = self.files[file].parent;
                    self.files[re].re = false;
                    if self.files[re]
                        .parent
                        .is_some_and(|parent| self.files[parent].re_descendant)
                    {
                        nexted_re = true;
                        self.files[re].re_descendant = true;
                        if self.rede_add_entry(re) < 0 {
                            return Err(self.fatal_rr(file));
                        }
                        // Its descendants go to the new ancestor.
                        while let Some(d) = self.rede_get_entry(re) {
                            if self.rede_add_entry(d) < 0 {
                                return Err(self.fatal_rr(file));
                            }
                        }
                        break;
                    }
                    // The RE directory takes the CL entry's place, and its
                    // descendants come after it.
                    file = re;
                    while let Some(d) = self.rede_get_entry(file) {
                        self.cache_add_entry(d);
                    }
                    break;
                }
                if nexted_re {
                    // Not yet: its full path is not known.
                    continue;
                }
            } else if self.files[file].mode & AE_IFMT == AE_IFDIR {
                // The directory's entries.
                if let Some(warning) = self.read_children(input, file)? {
                    return Ok(Step::Warn(warning));
                }
                if self.files[file].rr_moved {
                    // rr_moved, with only RE directories in it, comes later.
                    if self.files[file].rr_moved_has_re_only {
                        continue;
                    }
                } else if self.files[file].re {
                    // Not yet: its full path is not known.
                    self.re_add_entry(file);
                    continue;
                } else if self.files[file].re_descendant {
                    // Not before its RE directory is placed.
                    if self.rede_add_entry(file) == 0 {
                        continue;
                    }
                }
            }
            break;
        }

        if self.files[file].mode & AE_IFMT != AE_IFREG || self.files[file].number == -1 {
            return Ok(Step::File(file));
        }

        // The files with the same serial number: hard links, which go
        // together. The heap is peeked, so that a file with another number
        // stays in it.
        let mut count: i32 = 0;
        let number = self.files[file].number;
        self.cache_files = List::new();
        let mut empty_files = List::new();
        while let Some(&top) = self.pending_files.first()
            && (self.files[top].number == -1 || self.files[top].number == number)
        {
            if self.files[file].number == -1 {
                // The same offset, but the wrong one that empty files and
                // symbolic links have from old mkisofs.
                self.list_add(&mut empty_files, file, false);
            } else {
                count += 1;
                self.cache_add_entry(file);
            }
            let Some(next) = self.heap_get_entry() else {
                break;
            };
            file = next;
        }
        if count == 0 {
            return Ok(Step::File(file));
        }
        if self.files[file].number == -1 {
            self.list_add(&mut empty_files, file, false);
        } else {
            count += 1;
            self.cache_add_entry(file);
        }
        if count > 1 {
            // As many links as files.
            let mut at = self.cache_files.first;
            let mut steps = 0;
            while let Some(f) = at
                && steps <= self.files.len()
            {
                self.files[f].nlinks = count;
                at = self.files[f].next;
                steps += 1;
            }
        }
        // Empty files at the end.
        if empty_files.first.is_some() {
            let mut cache = self.cache_files;
            self.set_tail(&mut cache, empty_files.first);
            cache.last = empty_files.last;
            self.cache_files = cache;
        }
        Ok(match self.cache_get_entry() {
            Some(file) => Step::File(file),
            None => Step::Eof,
        })
    }

    /// The error at `fatal_rr`.
    fn fatal_rr(&self, file: Fid) -> Error {
        Error::ClRe {
            position: self.current_position as i64,
            cl_offset: self.files[file].cl_offset as i64,
        }
    }

    /// `*list->last = value`.
    fn set_tail(&mut self, list: &mut List, value: Option<Fid>) {
        match list.last {
            Tail::Head => list.first = value,
            Tail::Next(f) => self.files[f].next = value,
            Tail::ReNext(f) => self.files[f].re_next = value,
        }
    }

    /// A record at the end of a list, through `next` or `re_next`.
    fn list_add(&mut self, list: &mut List, file: Fid, re: bool) {
        if re {
            self.files[file].re_next = None;
        } else {
            self.files[file].next = None;
        }
        self.set_tail(list, Some(file));
        list.last = if re {
            Tail::ReNext(file)
        } else {
            Tail::Next(file)
        };
    }

    /// The first record out of a list.
    fn list_get(&self, list: &mut List, re: bool) -> Option<Fid> {
        let file = list.first?;
        list.first = if re {
            self.files[file].re_next
        } else {
            self.files[file].next
        };
        if list.first.is_none() {
            list.last = Tail::Head;
        }
        Some(file)
    }

    /// `re_add_entry`.
    fn re_add_entry(&mut self, file: Fid) {
        let mut list = self.re_files;
        self.list_add(&mut list, file, true);
        self.re_files = list;
    }

    /// `re_get_entry`.
    fn re_get_entry(&mut self) -> Option<Fid> {
        let mut list = self.re_files;
        let file = self.list_get(&mut list, true);
        self.re_files = list;
        file
    }

    /// `rede_add_entry`: a directory under an RE directory, kept with the
    /// nearest one above it; -1 when there is none.
    fn rede_add_entry(&mut self, file: Fid) -> i32 {
        // Damaged CL and RE entries can make the parents a loop without an
        // RE directory: a second pointer at half speed (Floyd's) finds it.
        let mut re = self.files[file].parent;
        let mut slow = re;
        let mut slow_turn = false;
        while let Some(r) = re
            && !self.files[r].re
        {
            re = self.files[r].parent;
            if slow_turn {
                slow = slow.and_then(|s| self.files[s].parent);
                if re == slow {
                    // The parents are a loop.
                    return -1;
                }
            }
            slow_turn = !slow_turn;
        }
        let Some(re) = re else {
            return -1;
        };
        let mut list = self.files[re].rede_files;
        self.list_add(&mut list, file, true);
        self.files[re].rede_files = list;
        0
    }

    /// `rede_get_entry`.
    fn rede_get_entry(&mut self, re: Fid) -> Option<Fid> {
        let mut list = self.files[re].rede_files;
        let file = self.list_get(&mut list, true);
        self.files[re].rede_files = list;
        file
    }

    /// `cache_add_entry`.
    fn cache_add_entry(&mut self, file: Fid) {
        let mut list = self.cache_files;
        self.list_add(&mut list, file, false);
        self.cache_files = list;
    }

    /// `cache_get_entry`.
    fn cache_get_entry(&mut self) -> Option<Fid> {
        let mut list = self.cache_files;
        let file = self.list_get(&mut list, false);
        self.cache_files = list;
        file
    }

    /// `heap_add_entry`: a record into the heap of pending ones. The key's
    /// low 16 bits keep records with the same offset in the order they
    /// came (up to 65,535 of them).
    fn heap_add_entry(&mut self, file: Fid, key: u64) {
        let key = (key << 16).wrapping_add(self.pending_files.len() as u64 & 0xffff);
        self.files[file].key = key;
        // Start with the hole at the end, and move it up.
        let mut hole = self.pending_files.len();
        self.pending_files.push(file);
        while hole > 0 {
            let parent = (hole - 1) / 2;
            if key >= self.files[self.pending_files[parent]].key {
                self.pending_files[hole] = file;
                return;
            }
            self.pending_files[hole] = self.pending_files[parent];
            hole = parent;
        }
        self.pending_files[0] = file;
    }

    /// `heap_get_entry`: the pending record with the smallest key.
    fn heap_get_entry(&mut self) -> Option<Fid> {
        let r = *self.pending_files.first()?;
        let last = self.pending_files.pop()?;
        if self.pending_files.is_empty() {
            return Some(r);
        }
        // The last one at the root, then down.
        self.pending_files[0] = last;
        let a_key = self.files[last].key;
        let mut a = 0;
        loop {
            let mut b = a + a + 1;
            if b >= self.pending_files.len() {
                return Some(r);
            }
            let mut b_key = self.files[self.pending_files[b]].key;
            let c = b + 1;
            if c < self.pending_files.len() {
                let c_key = self.files[self.pending_files[c]].key;
                if c_key < b_key {
                    b = c;
                    b_key = c_key;
                }
            }
            if a_key <= b_key {
                return Some(r);
            }
            self.pending_files.swap(a, b);
            a = b;
        }
    }

    /// `build_pathname`: the names from the root, joined by "/". A plain
    /// ISO 9660 tree is at most 8 deep; at 1,000 something is wrong.
    fn build_pathname(&self, file: Fid) -> Option<Vec<u8>> {
        let mut chain = vec![file];
        let mut at = file;
        while let Some(parent) = self.files[at].parent
            && !self.files[parent].name.bytes().is_empty()
        {
            if chain.len() > 1000 {
                return None;
            }
            chain.push(parent);
            at = parent;
        }
        let mut path = Vec::new();
        for &f in chain[1..].iter().rev() {
            path.extend_from_slice(self.files[f].name.bytes());
            path.push(b'/');
        }
        match self.files[file].name.bytes() {
            [] => path.push(b'.'),
            name => path.extend_from_slice(name),
        }
        Some(path)
    }

    /// `build_pathname_utf16be`: the same with Joliet's names, at most
    /// `UTF16_NAME_MAX` bytes. Differs from libarchive, whose recursion up
    /// the parents never ends when they make a loop: the length stops it.
    fn build_pathname_utf16be(&self, file: Fid) -> Option<Vec<u8>> {
        let own = self.files[file].utf16be_name.len().max(2);
        let mut len = own;
        let mut chain = Vec::new();
        let mut at = file;
        while let Some(parent) = self.files[at].parent
            && !self.files[parent].utf16be_name.is_empty()
        {
            len += self.files[parent].utf16be_name.len() + 2;
            if len > UTF16_NAME_MAX {
                return None;
            }
            chain.push(parent);
            at = parent;
        }
        if len > UTF16_NAME_MAX {
            return None;
        }
        let mut path = Vec::with_capacity(len);
        for &f in chain.iter().rev() {
            path.extend_from_slice(&self.files[f].utf16be_name);
            path.extend_from_slice(&[0, b'/']);
        }
        if self.files[file].utf16be_name.is_empty() {
            path.extend_from_slice(&[0, b'.']);
        } else {
            path.extend_from_slice(&self.files[file].utf16be_name);
        }
        Some(path)
    }
}

/// Copies into `dst` what the image has of the next `dst.len()` bytes, at
/// most `budget`; how many.
fn take<R: Read>(input: &mut Input<R>, dst: &mut [u8], budget: u64) -> Result<usize, Error> {
    let want = (dst.len() as u64).min(budget) as usize;
    let mut got = 0;
    while got < want {
        let Some(chunk) = input.ahead(1)? else {
            break;
        };
        let n = chunk.len().min(want - got);
        dst[got..got + n].copy_from_slice(&chunk[..n]);
        input.consume(n as i64)?;
        got += n;
    }
    Ok(got)
}

/// `isNull`: whether `bytes` bytes from `offset` are all zero.
fn is_null(h: &[u8], offset: usize, bytes: usize) -> bool {
    h[offset..offset + bytes].iter().all(|&b| b == 0)
}

/// `isBootRecord`: type 0, version 1.
fn is_boot_record(h: &[u8]) -> bool {
    h[0] == 0 && h[6] == 1
}

/// `isVDSetTerminator`: type 255, version 1, the rest zero.
fn is_vd_set_terminator(h: &[u8]) -> bool {
    h[0] == 255 && h[6] == 1 && is_null(h, 7, 2048 - 7)
}

/// `isSVD`: a Supplementary Volume Descriptor.
fn is_svd(h: &[u8]) -> bool {
    if h[SVD_TYPE_OFFSET] != 2 {
        return false;
    }
    if !is_null(h, SVD_RESERVED1_OFFSET, SVD_RESERVED1_SIZE)
        || !is_null(h, SVD_RESERVED2_OFFSET, SVD_RESERVED2_SIZE)
        || !is_null(h, SVD_RESERVED3_OFFSET, SVD_RESERVED3_SIZE)
    {
        return false;
    }
    // The file structure version must be 1 for ISO 9660.
    if h[SVD_FILE_STRUCTURE_VERSION_OFFSET] != 1 {
        return false;
    }
    if le16(&h[SVD_LOGICAL_BLOCK_SIZE_OFFSET..]) == 0 {
        return false;
    }
    let volume_block = le32(&h[SVD_VOLUME_SPACE_SIZE_OFFSET..]) as i32;
    if volume_block <= SYSTEM_AREA_BLOCK + 4 {
        return false;
    }
    // The Type L Path Table within the volume, and the Type M one, which
    // WinISO and probably others leave out (zero).
    let location = le32(&h[SVD_TYPE_L_PATH_TABLE_OFFSET..]) as i32;
    if location < SYSTEM_AREA_BLOCK + 2 || location >= volume_block {
        return false;
    }
    let location = be32(&h[SVD_TYPE_M_PATH_TABLE_OFFSET..]) as i32;
    if (location > 0 && location < SYSTEM_AREA_BLOCK + 2) || location >= volume_block {
        return false;
    }
    is_root_directory_record(&h[SVD_ROOT_DIRECTORY_RECORD_OFFSET..])
}

/// `isEVD`: an Enhanced Volume Descriptor (ISO 9660:1999).
fn is_evd(h: &[u8]) -> bool {
    // Type 2, version 2.
    if h[PVD_TYPE_OFFSET] != 2 || h[PVD_VERSION_OFFSET] != 2 || h[PVD_RESERVED1_OFFSET] != 0 {
        return false;
    }
    if !is_null(h, PVD_RESERVED2_OFFSET, PVD_RESERVED2_SIZE)
        || !is_null(h, PVD_RESERVED3_OFFSET, PVD_RESERVED3_SIZE)
    {
        return false;
    }
    if le16(&h[PVD_LOGICAL_BLOCK_SIZE_OFFSET..]) == 0 {
        return false;
    }
    let volume_block = le32(&h[PVD_VOLUME_SPACE_SIZE_OFFSET..]) as i32;
    if volume_block <= SYSTEM_AREA_BLOCK + 4 {
        return false;
    }
    // The file structure version must be 2 for ISO 9660:1999.
    if h[PVD_FILE_STRUCTURE_VERSION_OFFSET] != 2 {
        return false;
    }
    let location = le32(&h[PVD_TYPE_1_PATH_TABLE_OFFSET..]) as i32;
    if location < SYSTEM_AREA_BLOCK + 2 || location >= volume_block {
        return false;
    }
    let location = be32(&h[PVD_TYPE_M_PATH_TABLE_OFFSET..]) as i32;
    if (location > 0 && location < SYSTEM_AREA_BLOCK + 2) || location >= volume_block {
        return false;
    }
    if !is_null(h, PVD_RESERVED4_OFFSET, PVD_RESERVED4_SIZE)
        || !is_null(h, PVD_RESERVED5_OFFSET, PVD_RESERVED5_SIZE)
    {
        return false;
    }
    is_root_directory_record(&h[PVD_ROOT_DIRECTORY_RECORD_OFFSET..])
}

/// `isRootDirectoryRecord`.
fn is_root_directory_record(p: &[u8]) -> bool {
    // ECMA-119 says exactly 34 bytes, but images have up to 68.
    if p[DR_LENGTH_OFFSET] < 34 || p[DR_LENGTH_OFFSET] > 68 {
        return false;
    }
    // The location and size, recorded both ways.
    if !is_valid_733_integer(&p[DR_EXTENT_OFFSET..]) || !is_valid_733_integer(&p[DR_SIZE_OFFSET..])
    {
        return false;
    }
    // A directory (bit 1), not an associated file (bit 2), without an
    // extended attribute record (bit 3), the last record of the file (bit
    // 7).
    if p[DR_FLAGS_OFFSET] & 0x8E != 0x02 {
        return false;
    }
    if !is_valid_723_integer(&p[DR_VOLUME_SEQUENCE_NUMBER_OFFSET..]) {
        return false;
    }
    // The root directory's name is a single zero byte.
    p[DR_NAME_LEN_OFFSET] == 1 && p[DR_NAME_OFFSET] == 0
}

/// `isValid723Integer`: a 16-bit number recorded both ways (7.2.3).
fn is_valid_723_integer(p: &[u8]) -> bool {
    p[0] == p[3] && p[1] == p[2]
}

/// `isValid733Integer`: a 32-bit number recorded both ways (7.3.3).
fn is_valid_733_integer(p: &[u8]) -> bool {
    p[0] == p[7] && p[1] == p[6] && p[2] == p[5] && p[3] == p[4]
}

/// `parse_rockridge_NM1`: a name, possibly in pieces.
fn parse_rockridge_nm1(file: &mut FileInfo, data: &[u8]) {
    if !file.name_continues {
        file.name.empty();
    }
    file.name_continues = false;
    // The flag: 0 the name, 1 the name continued in the next NM entry, 2
    // ".", 4 "..", 32 implementation-specific.
    let Some(&flag) = data.first() else {
        return;
    };
    match flag {
        0 | 1 => {
            if data.len() < 2 {
                return;
            }
            file.name.cat(&data[1..]);
            file.name_continues = flag == 1;
        }
        2 => file.name.cat(b"."),
        4 => file.name.cat(b".."),
        _ => {}
    }
}

/// A date format: its size, and the functions that check and decode it.
type DateFormat = (usize, fn(&[u8]) -> bool, fn(&[u8]) -> i64);

/// `parse_rockridge_TF1`: the times, each there if its flag says so; in
/// the 17-byte format if bit 7 says so.
fn parse_rockridge_tf1(file: &mut FileInfo, data: &[u8]) {
    let Some(&flag) = data.first() else {
        return;
    };
    let mut data = &data[1..];
    let (size, valid, decode): DateFormat = if flag & 0x80 != 0 {
        (17, isodate17_valid, isodate17)
    } else {
        (7, isodate7_valid, isodate7)
    };
    let fields: [(u8, u8); 4] = [
        (1, BIRTHTIME_IS_SET),
        (2, MTIME_IS_SET),
        (4, ATIME_IS_SET),
        (8, CTIME_IS_SET),
    ];
    for (i, (bit, set)) in fields.into_iter().enumerate() {
        if flag & bit == 0 || data.len() < size {
            continue;
        }
        if valid(data) {
            file.time_is_set |= set;
            let t = decode(data);
            match set {
                BIRTHTIME_IS_SET => file.birthtime = t,
                MTIME_IS_SET => file.mtime = t,
                ATIME_IS_SET => file.atime = t,
                _ => file.ctime = t,
            }
        }
        // The change time is the last: nothing after it is skipped.
        if i < 3 {
            data = &data[size..];
        }
    }
}

/// `parse_rockridge_SL1`: a symbolic link's target, in components,
/// possibly continued in the next SL entry.
fn parse_rockridge_sl1(file: &mut FileInfo, data: &[u8]) {
    let mut separator: &[u8] = b"";
    if !file.symlink_continues || file.symlink.length < 1 {
        file.symlink.empty();
    }
    file.symlink_continues = false;

    // The flag: 0 the last SL entry of the link, 1 continued.
    let Some(&flag) = data.first() else {
        return;
    };
    match flag {
        0 => {}
        1 => file.symlink_continues = true,
        _ => return,
    }
    let mut data = &data[1..];

    // Components: a flag, a length and maybe text each.
    while data.len() >= 2 {
        let flag = data[0];
        let nlen = data[1] as usize;
        data = &data[2..];
        file.symlink.cat(separator);
        separator = b"/";
        match flag {
            // Text, usually.
            0 => {
                if data.len() < nlen {
                    return;
                }
                file.symlink.cat(&data[..nlen]);
            }
            // Text continued in the next component.
            0x01 => {
                if data.len() < nlen {
                    return;
                }
                file.symlink.cat(&data[..nlen]);
                separator = b"";
            }
            // The current directory.
            0x02 => file.symlink.cat(b"."),
            // The parent directory.
            0x04 => file.symlink.cat(b".."),
            // The root.
            0x08 => {
                file.symlink.cat(b"/");
                separator = b"";
            }
            // Undefined (once the volume root).
            0x10 => {
                file.symlink.empty();
                file.symlink.cat(b"ROOT");
            }
            // Undefined (once the host name).
            0x20 => file.symlink.cat(b"hostname"),
            _ => return,
        }
        if nlen > data.len() {
            return;
        }
        data = &data[nlen..];
    }
}

/// `parse_rockridge_ZF1`: a file compressed with zisofs ("pz"), in blocks
/// of 2^15 to 2^17 bytes.
fn parse_rockridge_zf1(file: &mut FileInfo, data: &[u8]) {
    if data.len() == 12 && data[0] == 0x70 && data[1] == 0x7a {
        file.pz = true;
        file.pz_log2_bs = i32::from(data[3]);
        if file.pz_log2_bs < 15 || file.pz_log2_bs > 17 {
            file.pz = false;
            return;
        }
        file.pz_uncompressed_size = u64::from(le32(&data[4..]));
    }
}

/// `isodate7_valid`: a 7-byte date (9.1.5) with its fields in range.
fn isodate7_valid(v: &[u8]) -> bool {
    let (month, day, hour, minute, second) = (v[1], v[2], v[3], v[4], v[5]);
    let gmt_off = v[6] as i8;
    // All zero: no date.
    if v[..6].iter().all(|&b| b == 0) && gmt_off == 0 {
        return false;
    }
    // The year can be anything; 61 seconds allows leap seconds.
    (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && hour <= 23
        && minute <= 59
        && second <= 61
        && (-48..=52).contains(&gmt_off)
}

/// `isodate7`: seconds since 1970.
fn isodate7(v: &[u8]) -> i64 {
    let mut hour = i64::from(v[3]);
    let mut minute = i64::from(v[4]);
    // The time zone, in quarter hours.
    let offset = i64::from(v[6] as i8);
    if offset > -48 && offset < 52 {
        hour -= offset / 4;
        minute -= (offset % 4) * 15;
    }
    time_from_tm(
        1900 + i64::from(v[0]),
        i64::from(v[1]) - 1,
        i64::from(v[2]),
        hour,
        minute,
        i64::from(v[5]),
    )
}

/// Two ASCII digits.
fn digits2(v: &[u8]) -> i64 {
    i64::from(v[0] - b'0') * 10 + i64::from(v[1] - b'0')
}

/// `isodate17_valid`: a 17-byte date (8.4.26.1) with its fields in range.
fn isodate17_valid(v: &[u8]) -> bool {
    // 16 ASCII digits.
    if !v[..16].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let year = digits2(&v[0..]) * 100 + digits2(&v[2..]);
    let month = digits2(&v[4..]);
    let day = digits2(&v[6..]);
    let hour = digits2(&v[8..]);
    let minute = digits2(&v[10..]);
    let second = digits2(&v[12..]);
    let hundredths = digits2(&v[14..]);
    let gmt_off = v[16] as i8;
    if year == 0
        && month == 0
        && day == 0
        && hour == 0
        && minute == 0
        && second == 0
        && hundredths == 0
        && gmt_off == 0
    {
        return false;
    }
    // Years 1900 to 2300: not in ECMA-119, but reasonable.
    (1900..=2300).contains(&year)
        && (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && hour <= 23
        && minute <= 59
        && second <= 61
        && hundredths <= 99
        && (-48..=52).contains(&gmt_off)
}

/// `isodate17`: seconds since 1970.
fn isodate17(v: &[u8]) -> i64 {
    let mut hour = digits2(&v[8..]);
    let mut minute = digits2(&v[10..]);
    let offset = i64::from(v[16] as i8);
    if offset > -48 && offset < 52 {
        hour -= offset / 4;
        minute -= (offset % 4) * 15;
    }
    time_from_tm(
        digits2(&v[0..]) * 100 + digits2(&v[2..]),
        digits2(&v[4..]) - 1,
        digits2(&v[6..]),
        hour,
        minute,
        digits2(&v[12..]),
    )
}

/// `time_from_tm`, as `timegm` does it: a date in UTC, its fields possibly
/// out of range, as seconds since 1970; -1 is 0.
fn time_from_tm(year: i64, month0: i64, day: i64, hour: i64, minute: i64, second: i64) -> i64 {
    let year = year + month0.div_euclid(12);
    let month = month0.rem_euclid(12) + 1;
    let days = days_from_civil(year, month) + day - 1;
    let t = days * 86400 + hour * 3600 + minute * 60 + second;
    if t == -1 { 0 } else { t }
}

/// Days from 1970-01-01 to the first of a month of the Gregorian calendar
/// (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_as_timegm() {
        // 2009-02-04 21:39:14 in UTC+1 (4 quarter hours).
        assert_eq!(isodate7(&[109, 2, 4, 22, 39, 14, 4]), 1233783554);
        assert_eq!(isodate7(&[70, 1, 1, 0, 0, 0, 0]), 0);
        // One second before 1970 is -1, which libarchive makes 0.
        assert_eq!(isodate7(&[69, 12, 31, 23, 59, 59, 0]), 0);
        assert_eq!(isodate7(&[69, 12, 31, 23, 59, 58, 0]), -2);
        // February 31, 2000 is March 2.
        assert_eq!(isodate7(&[100, 2, 31, 0, 0, 0, 0]), 951955200);
        assert_eq!(isodate17(b"2009020422391400\x04"), 1233783554);
        // Time zones at the edges: -48 and 52 are valid, but not applied.
        assert!(isodate7_valid(&[100, 1, 1, 0, 0, 0, 52]));
        assert_eq!(isodate7(&[100, 1, 1, 0, 0, 0, 52]), 946684800);
        assert_eq!(
            isodate7(&[100, 1, 1, 0, 0, 0, 51]),
            946684800 - 12 * 3600 - 45 * 60
        );
        assert_eq!(
            isodate7(&[100, 1, 1, 0, 0, 0, (-5i8) as u8]),
            946684800 + 3600 + 15 * 60
        );
    }
}
