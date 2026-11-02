//! Port of libarchive's `archive_read_support_format_cpio.c`: the reader of
//! cpio archives in each of their formats.
//!
//! A cpio archive is a run of entries, each a header, the path (with its
//! NUL) and the file's data, up to an entry named `TRAILER!!!`. The formats
//! differ in their headers:
//!
//! - **odc** (`070707`, POSIX.1): 76 bytes of octal numbers;
//! - **afio large ASCII** (`070727`): 116 bytes of hexadecimal, which afio
//!   writes among odc headers for what odc's fields cannot hold;
//! - **newc** (`070701`, SVR4) and **crc** (`070702`, SVR4 with a
//!   checksum, which libarchive does not check): 110 bytes of hexadecimal,
//!   the path and the data each padded to four bytes;
//! - **binary** (the PDP-11's `070707` as a 16-bit number, little- or
//!   big-endian): 26 bytes of 16-bit numbers, the path and the data each
//!   padded to two bytes.
//!
//! The reader takes the format from the first bytes, and reads every header
//! in it. In the ASCII formats it looks for the next header when one is not
//! where it should be, and says how many bytes it skipped.

use std::collections::HashMap;
use std::io::Read;

use crate::cpio::entry::{AE_IFLNK, AE_IFMT, AE_IFREG, Device, Entry, c_string};
use crate::cpio::error::{Error, Warning};
use crate::cpio::read::Input;

// The binary header (`bin_*`): 16-bit numbers in the archive's byte
// order, 32-bit ones as two of them, the high one first.
const BIN_DEV_OFFSET: usize = 2;
const BIN_INO_OFFSET: usize = 4;
const BIN_MODE_OFFSET: usize = 6;
const BIN_UID_OFFSET: usize = 8;
const BIN_GID_OFFSET: usize = 10;
const BIN_NLINK_OFFSET: usize = 12;
const BIN_RDEV_OFFSET: usize = 14;
const BIN_MTIME_OFFSET: usize = 16;
const BIN_NAMESIZE_OFFSET: usize = 20;
const BIN_FILESIZE_OFFSET: usize = 22;
const BIN_HEADER_SIZE: usize = 26;

// The odc header (`odc_*`): octal numbers.
const ODC_DEV_OFFSET: usize = 6;
const ODC_DEV_SIZE: usize = 6;
const ODC_INO_OFFSET: usize = 12;
const ODC_INO_SIZE: usize = 6;
const ODC_MODE_OFFSET: usize = 18;
const ODC_MODE_SIZE: usize = 6;
const ODC_UID_OFFSET: usize = 24;
const ODC_UID_SIZE: usize = 6;
const ODC_GID_OFFSET: usize = 30;
const ODC_GID_SIZE: usize = 6;
const ODC_NLINK_OFFSET: usize = 36;
const ODC_NLINK_SIZE: usize = 6;
const ODC_RDEV_OFFSET: usize = 42;
const ODC_RDEV_SIZE: usize = 6;
const ODC_MTIME_OFFSET: usize = 48;
const ODC_MTIME_SIZE: usize = 11;
const ODC_NAMESIZE_OFFSET: usize = 59;
const ODC_NAMESIZE_SIZE: usize = 6;
const ODC_FILESIZE_OFFSET: usize = 65;
const ODC_FILESIZE_SIZE: usize = 11;
const ODC_HEADER_SIZE: usize = 76;

// The newc header (`newc_*`): hexadecimal numbers.
const NEWC_INO_OFFSET: usize = 6;
const NEWC_INO_SIZE: usize = 8;
const NEWC_MODE_OFFSET: usize = 14;
const NEWC_MODE_SIZE: usize = 8;
const NEWC_UID_OFFSET: usize = 22;
const NEWC_UID_SIZE: usize = 8;
const NEWC_GID_OFFSET: usize = 30;
const NEWC_GID_SIZE: usize = 8;
const NEWC_NLINK_OFFSET: usize = 38;
const NEWC_NLINK_SIZE: usize = 8;
const NEWC_MTIME_OFFSET: usize = 46;
const NEWC_MTIME_SIZE: usize = 8;
const NEWC_FILESIZE_OFFSET: usize = 54;
const NEWC_FILESIZE_SIZE: usize = 8;
const NEWC_DEVMAJOR_OFFSET: usize = 62;
const NEWC_DEVMAJOR_SIZE: usize = 8;
const NEWC_DEVMINOR_OFFSET: usize = 70;
const NEWC_DEVMINOR_SIZE: usize = 8;
const NEWC_RDEVMAJOR_OFFSET: usize = 78;
const NEWC_RDEVMAJOR_SIZE: usize = 8;
const NEWC_RDEVMINOR_OFFSET: usize = 86;
const NEWC_RDEVMINOR_SIZE: usize = 8;
const NEWC_NAMESIZE_OFFSET: usize = 94;
const NEWC_NAMESIZE_SIZE: usize = 8;
const NEWC_HEADER_SIZE: usize = 110;

// The afio large ASCII header (`afiol_*`), which afio writes when a file is
// larger than 2 GB, or its inode, owner or group above 65,535, or its time
// above 0x7fffffff, which odc cannot hold: hexadecimal numbers (but for
// the mode, in octal), with a letter after some of them.
const AFIOL_DEV_OFFSET: usize = 6;
const AFIOL_DEV_SIZE: usize = 8;
const AFIOL_INO_OFFSET: usize = 14;
const AFIOL_INO_SIZE: usize = 16;
const AFIOL_INO_M_OFFSET: usize = 30;
const AFIOL_MODE_OFFSET: usize = 31;
const AFIOL_MODE_SIZE: usize = 6;
const AFIOL_UID_OFFSET: usize = 37;
const AFIOL_UID_SIZE: usize = 8;
const AFIOL_GID_OFFSET: usize = 45;
const AFIOL_GID_SIZE: usize = 8;
const AFIOL_NLINK_OFFSET: usize = 53;
const AFIOL_NLINK_SIZE: usize = 8;
const AFIOL_RDEV_OFFSET: usize = 61;
const AFIOL_RDEV_SIZE: usize = 8;
const AFIOL_MTIME_OFFSET: usize = 69;
const AFIOL_MTIME_SIZE: usize = 16;
const AFIOL_MTIME_N_OFFSET: usize = 85;
const AFIOL_NAMESIZE_OFFSET: usize = 86;
const AFIOL_NAMESIZE_SIZE: usize = 4;
const AFIOL_XSIZE_S_OFFSET: usize = 98;
const AFIOL_FILESIZE_OFFSET: usize = 99;
const AFIOL_FILESIZE_SIZE: usize = 16;
const AFIOL_FILESIZE_C_OFFSET: usize = 115;
const AFIOL_HEADER_SIZE: usize = 116;

/// `CPIO_PATHNAME_MAX`: the name field holds the whole path, with its NUL.
const CPIO_PATHNAME_MAX: u64 = 1024 * 1024;

/// The longest symbolic link target the reader takes.
const SYMLINK_MAX: i64 = 1024 * 1024;

/// How far the search for a header goes before giving up what it passed
/// over, so that garbage of any length takes little memory. libarchive,
/// with the archive in memory, passes over it all at once; the count and
/// the result are the same.
const SCAN_STEP: usize = 64 * 1024;

/// The archive's format, as `archive_format` gives it after a header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    /// `ARCHIVE_FORMAT_CPIO_POSIX`: odc.
    Posix,
    /// `ARCHIVE_FORMAT_CPIO_BIN_LE`: binary, little-endian.
    BinLe,
    /// `ARCHIVE_FORMAT_CPIO_BIN_BE`: binary, big-endian.
    BinBe,
    /// `ARCHIVE_FORMAT_CPIO_SVR4_NOCRC`: newc.
    Svr4NoCrc,
    /// `ARCHIVE_FORMAT_CPIO_SVR4_CRC`: newc with a checksum.
    Svr4Crc,
    /// `ARCHIVE_FORMAT_CPIO_AFIO_LARGE`: afio's large ASCII header.
    AfioLarge,
}

impl Format {
    /// libarchive's number for it.
    pub fn code(self) -> i32 {
        match self {
            Format::Posix => 0x10001,
            Format::BinLe => 0x10002,
            Format::BinBe => 0x10003,
            Format::Svr4NoCrc => 0x10004,
            Format::Svr4Crc => 0x10005,
            Format::AfioLarge => 0x10006,
        }
    }

    /// libarchive's name for it, `archive_format_name`.
    pub fn name(self) -> &'static str {
        match self {
            Format::Posix => "POSIX octet-oriented cpio",
            Format::BinLe => "cpio (little-endian binary)",
            Format::BinBe => "cpio (big-endian binary)",
            Format::Svr4NoCrc => "ASCII cpio (SVR4 with no CRC)",
            Format::Svr4Crc => "ASCII cpio (SVR4 with CRC)",
            Format::AfioLarge => "afio large ASCII",
        }
    }
}

/// `cpio->read_header`: which header the bid chose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeaderKind {
    /// `header_odc`, which reads afio's large headers too.
    Odc,
    /// `header_newc`.
    Newc,
    /// `header_bin_le`.
    BinLe,
    /// `header_bin_be`.
    BinBe,
}

/// `struct links_entry`: a file with more links still to come.
#[derive(Debug)]
struct LinksEntry {
    links: u32,
    name: Vec<u8>,
}

/// What reading a header gave.
#[derive(Debug)]
pub(crate) enum Next {
    Entry(Entry),
    /// The `TRAILER!!!` entry: the end of the archive.
    Eof,
}

/// `struct cpio`: the reader's state.
#[derive(Debug, Default)]
pub(crate) struct Cpio {
    read_header: Option<HeaderKind>,
    /// `links_head`: the files seen with more links to come, by device and
    /// inode. libarchive keeps a list, which never holds a key twice; a
    /// map gives the same answers, without its time on many files.
    links: HashMap<(Device, u64), LinksEntry>,
    entry_bytes_remaining: i64,
    entry_padding: i64,
    /// The `pwb` option.
    pub(crate) option_pwb: bool,
    /// `archive_format`, which each header sets.
    pub(crate) format: Option<Format>,
    /// The last message libarchive would have set since the entry began,
    /// which a failure without one of its own keeps.
    pub(crate) last_message: Option<Vec<u8>>,
}

fn le16(p: &[u8]) -> u16 {
    u16::from_le_bytes([p[0], p[1]])
}

fn be16(p: &[u8]) -> u16 {
    u16::from_be_bytes([p[0], p[1]])
}

/// `le32dec`: a 32-bit number as two little-endian 16-bit ones, the high
/// one first, as the PDP-11 stores it.
fn le32dec(p: &[u8]) -> i64 {
    (i64::from(le16(p)) << 16) | i64::from(le16(&p[2..]))
}

/// `be32dec`.
fn be32dec(p: &[u8]) -> i64 {
    (i64::from(be16(p)) << 16) | i64::from(be16(&p[2..]))
}

/// `atol8`: the octal number at the start of `p`, up to the first other
/// character.
fn atol8(p: &[u8]) -> i64 {
    let mut l: u64 = 0;
    for &c in p {
        if !(b'0'..=b'7').contains(&c) {
            break;
        }
        l = (l << 3) | u64::from(c - b'0');
    }
    l as i64
}

/// `atol16`.
fn atol16(p: &[u8]) -> i64 {
    atol16u(p) as i64
}

/// `atol16u`: the hexadecimal number at the start of `p`, up to the first
/// other character.
fn atol16u(p: &[u8]) -> u64 {
    let mut l: u64 = 0;
    for &c in p {
        let digit = match c {
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            b'0'..=b'9' => c - b'0',
            _ => break,
        };
        l = (l << 4) | u64::from(digit);
    }
    l
}

/// `is_hex`.
fn is_hex(p: &[u8]) -> bool {
    p.iter().all(u8::is_ascii_hexdigit)
}

/// `is_octal`.
fn is_octal(p: &[u8]) -> bool {
    p.iter().all(|c| (b'0'..=b'7').contains(c))
}

/// `is_afio_large`: an afio large ASCII header at the start of `h`, which
/// holds what is left of the archive.
fn is_afio_large(h: &[u8]) -> bool {
    if h.len() < AFIOL_HEADER_SIZE {
        return false;
    }
    if h[AFIOL_INO_M_OFFSET] != b'm'
        || h[AFIOL_MTIME_N_OFFSET] != b'n'
        || h[AFIOL_XSIZE_S_OFFSET] != b's'
        || h[AFIOL_FILESIZE_C_OFFSET] != b':'
    {
        return false;
    }
    is_hex(&h[AFIOL_DEV_OFFSET..AFIOL_INO_M_OFFSET])
        && is_hex(&h[AFIOL_MODE_OFFSET..AFIOL_MTIME_N_OFFSET])
        && is_hex(&h[AFIOL_NAMESIZE_OFFSET..AFIOL_XSIZE_S_OFFSET])
        && is_hex(&h[AFIOL_FILESIZE_OFFSET..AFIOL_FILESIZE_OFFSET + AFIOL_FILESIZE_SIZE])
}

/// An odc header at the start of `h`.
fn is_odc(h: &[u8]) -> bool {
    h.starts_with(b"070707") && h.len() >= ODC_HEADER_SIZE && is_octal(&h[..ODC_HEADER_SIZE])
}

/// A newc or crc header at the start of `h`.
fn is_newc(h: &[u8]) -> bool {
    h.len() >= NEWC_HEADER_SIZE
        && h.starts_with(b"07070")
        && (h[5] == b'1' || h[5] == b'2')
        && is_hex(&h[..NEWC_HEADER_SIZE])
}

/// `archive_read_format_cpio_bid` on the first bytes of an archive: 48
/// for the ASCII formats, 16 for the binary ones, 0 if this is not cpio
/// (libarchive returns `ARCHIVE_WARN` then), -1 if there are fewer than 6
/// bytes to tell.
pub fn bid(h: &[u8]) -> i32 {
    bid_kind(h).0
}

/// The bid, and the header it chooses.
fn bid_kind(h: &[u8]) -> (i32, Option<HeaderKind>) {
    if h.len() < 6 {
        return (-1, None);
    }
    if h.starts_with(b"070707") || h.starts_with(b"070727") {
        // odc (POSIX.1), or afio's large ASCII.
        (48, Some(HeaderKind::Odc))
    } else if h.starts_with(b"070701") || h.starts_with(b"070702") {
        // newc (SVR4), without or with its checksum.
        (48, Some(HeaderKind::Newc))
    } else if be16(h) == 0o70707 {
        (16, Some(HeaderKind::BinBe))
    } else if le16(h) == 0o70707 {
        (16, Some(HeaderKind::BinLe))
    } else {
        (0, None)
    }
}

impl Cpio {
    /// `archive_read_format_cpio_bid`, on the input: whether this is cpio,
    /// with the header the format reads chosen.
    pub(crate) fn bid<R: Read>(&mut self, input: &mut Input<R>) -> Result<i32, Error> {
        let Some(h) = input.ahead(6)? else {
            return Ok(-1);
        };
        let (bid, kind) = bid_kind(h);
        self.read_header = kind;
        Ok(bid)
    }

    /// The message of a warning or error libarchive sets and goes on.
    fn set_message(&mut self, message: Option<Vec<u8>>) {
        self.last_message = message;
    }

    /// `archive_read_format_cpio_read_header`.
    pub(crate) fn read_header<R: Read>(&mut self, input: &mut Input<R>) -> Result<Next, Error> {
        let mut entry = Entry::default();
        let (mut r, namelength, name_pad) = match self.read_header {
            Some(HeaderKind::Odc) => self.header_odc(input, &mut entry)?,
            Some(HeaderKind::Newc) => self.header_newc(input, &mut entry)?,
            Some(HeaderKind::BinLe) => self.header_bin_le(input, &mut entry)?,
            Some(HeaderKind::BinBe) => self.header_bin_be(input, &mut entry)?,
            None => return Err(Error::Unrecognized),
        };

        if namelength > CPIO_PATHNAME_MAX {
            return Err(Error::PathnameTooLong);
        }
        let namelength = namelength as usize;

        // The name, as bytes: libarchive converts it only with the
        // `hdrcharset` option, which is not ported.
        let Some(h) = input.ahead(namelength)? else {
            return Err(Error::Unspecified(None));
        };
        entry.header.path = c_string(&h[..namelength]).to_vec();
        // Whether this is the end, before the name is consumed.
        let is_trailer = namelength == 11 && h.starts_with(b"TRAILER!!!");

        input.consume(namelength as u64)?;
        // libarchive goes on when the archive ends in the padding, with its
        // message set: the warning's, if the entry has one, and that of a
        // failure after without one of its own.
        match input.consume(name_pad) {
            Ok(()) => {}
            Err(Error::Truncated { needed, available }) => {
                let e = Error::Truncated { needed, available };
                self.set_message(e.message());
                if r.is_some() {
                    r = Some(Warning::Truncated { needed, available });
                }
            }
            Err(e) => return Err(e),
        }

        // A symbolic link's target is its data.
        if entry.header.mode & AE_IFMT == AE_IFLNK {
            if self.entry_bytes_remaining > SYMLINK_MAX {
                return Err(Error::SymlinkTooLong);
            }
            let n = self.entry_bytes_remaining as usize;
            let Some(hl) = input.ahead(n)? else {
                return Err(Error::Unspecified(None));
            };
            entry.copy_symlink_l(&hl[..n]);
            input.consume(n as u64)?;
            self.entry_bytes_remaining = 0;
        }

        if is_trailer {
            self.last_message = None;
            return Ok(Next::Eof);
        }

        // Hard links to the entries before.
        self.record_hardlink(&mut entry);

        entry.header.warning = r;
        Ok(Next::Entry(entry))
    }

    /// `archive_read_format_cpio_read_data`: up to `buf.len()` bytes of the
    /// entry's data copied into `buf`; 0 at its end, once the padding after
    /// it is passed.
    pub(crate) fn read_data<R: Read>(
        &mut self,
        input: &mut Input<R>,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        if self.entry_bytes_remaining > 0 {
            let Some(h) = input.ahead(1)? else {
                return Err(Error::Unspecified(None));
            };
            let n = (h.len() as u64)
                .min(self.entry_bytes_remaining as u64)
                .min(buf.len() as u64) as usize;
            buf[..n].copy_from_slice(&h[..n]);
            input.consume(n as u64)?;
            self.entry_bytes_remaining -= n as i64;
            Ok(n)
        } else {
            input.consume(self.entry_padding as u64)?;
            self.entry_padding = 0;
            Ok(0)
        }
    }

    /// `archive_read_format_cpio_skip`: what is left of the entry's data,
    /// and its padding.
    pub(crate) fn skip<R: Read>(&mut self, input: &mut Input<R>) -> Result<(), Error> {
        let to_skip = self.entry_bytes_remaining + self.entry_padding;
        input.consume(to_skip as u64)?;
        self.entry_bytes_remaining = 0;
        self.entry_padding = 0;
        Ok(())
    }

    /// `find_newc_header`: the next newc header, passing over what is
    /// before it, with a warning that says how much.
    ///
    /// libarchive, with the archive in memory, searches all of it in one
    /// pass, and fails if no header is there; the port reads it in pieces,
    /// with the same steps.
    fn find_newc_header<R: Read>(
        &mut self,
        input: &mut Input<R>,
    ) -> Result<Option<Warning>, Error> {
        // The typical case first.
        let Some(h) = input.ahead(NEWC_HEADER_SIZE)? else {
            return Err(Error::Unspecified(None));
        };
        if is_newc(h) {
            return Ok(None);
        }

        // Then the slow search, for something that looks like a newc
        // header.
        let mut skipped: u64 = 0;
        let mut p = 0;
        while input.has(p + NEWC_HEADER_SIZE)? {
            let h = &input.buffered()[p..];
            match h[5] {
                b'1' | b'2' => {
                    if is_newc(h) {
                        input.consume(p as u64)?;
                        skipped += p as u64;
                        return Ok(self.skipped(skipped));
                    }
                    p += 2;
                }
                b'0' => p += 1,
                _ => p += 6,
            }
            if p >= SCAN_STEP {
                input.consume(p as u64)?;
                skipped += p as u64;
                p = 0;
            }
        }
        // libarchive then looks again where the search stopped, and fails:
        // there is no room for a header.
        input.consume(p as u64)?;
        Err(Error::Unspecified(None))
    }

    /// The warning after `skipped` bytes, if any.
    fn skipped(&mut self, skipped: u64) -> Option<Warning> {
        if skipped == 0 {
            return None;
        }
        let w = Warning::Skipped { bytes: skipped };
        self.set_message(Some(w.message()));
        Some(w)
    }

    /// `header_newc`.
    fn header_newc<R: Read>(
        &mut self,
        input: &mut Input<R>,
        entry: &mut Entry,
    ) -> Result<(Option<Warning>, u64, u64), Error> {
        let r = self.find_newc_header(input)?;

        // The fixed-size part of the header.
        let Some(header) = input.ahead(NEWC_HEADER_SIZE)? else {
            return Err(Error::Unspecified(None));
        };
        if header.starts_with(b"070701") {
            self.format = Some(Format::Svr4NoCrc);
        } else if header.starts_with(b"070702") {
            self.format = Some(Format::Svr4Crc);
        }

        let field = |offset: usize, size: usize| atol16(&header[offset..offset + size]);
        let h = &mut entry.header;
        h.dev = Device::Split {
            major: field(NEWC_DEVMAJOR_OFFSET, NEWC_DEVMAJOR_SIZE) as u32,
            minor: field(NEWC_DEVMINOR_OFFSET, NEWC_DEVMINOR_SIZE) as u32,
        };
        h.ino = field(NEWC_INO_OFFSET, NEWC_INO_SIZE) as u64;
        h.mode = field(NEWC_MODE_OFFSET, NEWC_MODE_SIZE) as u32;
        h.uid = field(NEWC_UID_OFFSET, NEWC_UID_SIZE) as u32;
        h.gid = field(NEWC_GID_OFFSET, NEWC_GID_SIZE) as u32;
        h.nlink = field(NEWC_NLINK_OFFSET, NEWC_NLINK_SIZE) as u32;
        h.rdev = Device::Split {
            major: field(NEWC_RDEVMAJOR_OFFSET, NEWC_RDEVMAJOR_SIZE) as u32,
            minor: field(NEWC_RDEVMINOR_OFFSET, NEWC_RDEVMINOR_SIZE) as u32,
        };
        h.mod_time = field(NEWC_MTIME_OFFSET, NEWC_MTIME_SIZE);
        let namelength = field(NEWC_NAMESIZE_OFFSET, NEWC_NAMESIZE_SIZE) as u64;
        // The name is padded to 2 more than a multiple of 4 (with the 110
        // bytes of the header, to a multiple of 4). libarchive's check that
        // the padded length fits in a `size_t` cannot fail with 64 bits.
        let name_pad = 2u64.wrapping_sub(namelength) & 3;

        self.entry_bytes_remaining = field(NEWC_FILESIZE_OFFSET, NEWC_FILESIZE_SIZE);
        h.size = self.entry_bytes_remaining as u64;
        // The data is padded to a multiple of 4.
        self.entry_padding = 3 & self.entry_bytes_remaining.wrapping_neg();
        input.consume(NEWC_HEADER_SIZE as u64)?;
        Ok((r, namelength, name_pad))
    }

    /// `find_odc_header`: the next odc or afio large header, as
    /// `find_newc_header` finds newc's.
    ///
    /// The search needs room for afio's 116 bytes; with less left, only
    /// for odc's 76. libarchive looks again where the search stopped, and
    /// takes a header found right there without the warning: so does the
    /// port.
    fn find_odc_header<R: Read>(&mut self, input: &mut Input<R>) -> Result<Option<Warning>, Error> {
        let mut skipped: u64 = 0;
        loop {
            let header_size = if input.has(AFIOL_HEADER_SIZE)? {
                AFIOL_HEADER_SIZE
            } else if input.buffered().len() >= ODC_HEADER_SIZE {
                ODC_HEADER_SIZE
            } else {
                return Err(Error::Unspecified(None));
            };

            // The typical case first.
            let h = input.buffered();
            if is_odc(h) {
                return Ok(None);
            }
            if h.starts_with(b"070727") && is_afio_large(h) {
                self.format = Some(Format::AfioLarge);
                return Ok(None);
            }

            // Then the slow search.
            let mut p = 0;
            while input.has(p + header_size)? {
                let h = &input.buffered()[p..];
                match h[5] {
                    b'7' => {
                        if is_odc(h) || (h.starts_with(b"070727") && is_afio_large(h)) {
                            let afio = h[4] == b'2';
                            input.consume(p as u64)?;
                            skipped += p as u64;
                            if afio {
                                self.format = Some(Format::AfioLarge);
                            }
                            return Ok(self.skipped(skipped));
                        }
                        p += 2;
                    }
                    b'0' => p += 1,
                    _ => p += 6,
                }
                if p >= SCAN_STEP {
                    input.consume(p as u64)?;
                    skipped += p as u64;
                    p = 0;
                }
            }
            input.consume(p as u64)?;
            skipped += p as u64;
        }
    }

    /// `header_odc`, and `header_afiol` for afio's large headers.
    fn header_odc<R: Read>(
        &mut self,
        input: &mut Input<R>,
        entry: &mut Entry,
    ) -> Result<(Option<Warning>, u64, u64), Error> {
        self.format = Some(Format::Posix);

        // The start of the next header.
        let r = self.find_odc_header(input)?;

        if self.format == Some(Format::AfioLarge) {
            let (namelength, name_pad) = self.header_afiol(input, entry)?;
            return Ok((r, namelength, name_pad));
        }

        // The fixed-size part of the header.
        let Some(header) = input.ahead(ODC_HEADER_SIZE)? else {
            return Err(Error::Unspecified(None));
        };
        let field = |offset: usize, size: usize| atol8(&header[offset..offset + size]);
        let h = &mut entry.header;
        h.dev = Device::Number(field(ODC_DEV_OFFSET, ODC_DEV_SIZE) as u32);
        h.ino = field(ODC_INO_OFFSET, ODC_INO_SIZE) as u64;
        h.mode = field(ODC_MODE_OFFSET, ODC_MODE_SIZE) as u32;
        h.uid = field(ODC_UID_OFFSET, ODC_UID_SIZE) as u32;
        h.gid = field(ODC_GID_OFFSET, ODC_GID_SIZE) as u32;
        h.nlink = field(ODC_NLINK_OFFSET, ODC_NLINK_SIZE) as u32;
        h.rdev = Device::Number(field(ODC_RDEV_OFFSET, ODC_RDEV_SIZE) as u32);
        h.mod_time = field(ODC_MTIME_OFFSET, ODC_MTIME_SIZE);
        let namelength = field(ODC_NAMESIZE_OFFSET, ODC_NAMESIZE_SIZE) as u64;
        // No padding after the name, nor after the data.
        self.entry_bytes_remaining = field(ODC_FILESIZE_OFFSET, ODC_FILESIZE_SIZE);
        h.size = self.entry_bytes_remaining as u64;
        self.entry_padding = 0;
        input.consume(ODC_HEADER_SIZE as u64)?;
        Ok((r, namelength, 0))
    }

    /// `header_afiol`. A name ending in ".z" is a file afio gzipped:
    /// libarchive gives it as it is, without the size it has uncompressed,
    /// which the header does not hold.
    fn header_afiol<R: Read>(
        &mut self,
        input: &mut Input<R>,
        entry: &mut Entry,
    ) -> Result<(u64, u64), Error> {
        self.format = Some(Format::AfioLarge);

        // The fixed-size part of the header.
        let Some(header) = input.ahead(AFIOL_HEADER_SIZE)? else {
            return Err(Error::Unspecified(None));
        };
        let field = |offset: usize, size: usize| atol16(&header[offset..offset + size]);
        let h = &mut entry.header;
        h.dev = Device::Number(field(AFIOL_DEV_OFFSET, AFIOL_DEV_SIZE) as u32);
        // libarchive 3 keeps the inode in an int64_t.
        h.ino =
            atol16u(&header[AFIOL_INO_OFFSET..AFIOL_INO_OFFSET + AFIOL_INO_SIZE]) & i64::MAX as u64;
        h.mode = atol8(&header[AFIOL_MODE_OFFSET..AFIOL_MODE_OFFSET + AFIOL_MODE_SIZE]) as u32;
        h.uid = field(AFIOL_UID_OFFSET, AFIOL_UID_SIZE) as u32;
        h.gid = field(AFIOL_GID_OFFSET, AFIOL_GID_SIZE) as u32;
        h.nlink = field(AFIOL_NLINK_OFFSET, AFIOL_NLINK_SIZE) as u32;
        h.rdev = Device::Number(field(AFIOL_RDEV_OFFSET, AFIOL_RDEV_SIZE) as u32);
        h.mod_time = field(AFIOL_MTIME_OFFSET, AFIOL_MTIME_SIZE);
        let namelength = field(AFIOL_NAMESIZE_OFFSET, AFIOL_NAMESIZE_SIZE) as u64;

        let t = field(AFIOL_FILESIZE_OFFSET, AFIOL_FILESIZE_SIZE);
        if t < 0 {
            return Err(Error::NonsensicalSize);
        }
        self.entry_bytes_remaining = t;
        h.size = t as u64;
        self.entry_padding = 0;
        input.consume(AFIOL_HEADER_SIZE as u64)?;
        Ok((namelength, 0))
    }

    /// `header_bin_le`.
    fn header_bin_le<R: Read>(
        &mut self,
        input: &mut Input<R>,
        entry: &mut Entry,
    ) -> Result<(Option<Warning>, u64, u64), Error> {
        self.header_bin(input, entry, false)
    }

    /// `header_bin_be`.
    fn header_bin_be<R: Read>(
        &mut self,
        input: &mut Input<R>,
        entry: &mut Entry,
    ) -> Result<(Option<Warning>, u64, u64), Error> {
        self.header_bin(input, entry, true)
    }

    /// What `header_bin_le` and `header_bin_be` share, which differ only in
    /// the byte order. A binary header is not looked for: whatever is where
    /// the next one should be is read as one.
    fn header_bin<R: Read>(
        &mut self,
        input: &mut Input<R>,
        entry: &mut Entry,
        big_endian: bool,
    ) -> Result<(Option<Warning>, u64, u64), Error> {
        self.format = Some(if big_endian {
            Format::BinBe
        } else {
            Format::BinLe
        });

        // The fixed-size part of the header.
        let Some(header) = input.ahead(BIN_HEADER_SIZE)? else {
            return Err(Error::EndOfFile);
        };
        let n16 = if big_endian { be16 } else { le16 };
        let n32 = if big_endian { be32dec } else { le32dec };
        let h = &mut entry.header;
        h.dev = Device::Number(u32::from(n16(&header[BIN_DEV_OFFSET..])));
        h.ino = u64::from(n16(&header[BIN_INO_OFFSET..]));
        h.mode = u32::from(n16(&header[BIN_MODE_OFFSET..]));
        if self.option_pwb {
            // The bits a V6 inode leaves in the mode are taken off.
            h.mode &= 0o67777;
            if h.mode & AE_IFMT == 0 {
                h.mode |= AE_IFREG;
            }
        }
        h.uid = u32::from(n16(&header[BIN_UID_OFFSET..]));
        h.gid = u32::from(n16(&header[BIN_GID_OFFSET..]));
        h.nlink = u32::from(n16(&header[BIN_NLINK_OFFSET..]));
        h.rdev = Device::Number(u32::from(n16(&header[BIN_RDEV_OFFSET..])));
        h.mod_time = n32(&header[BIN_MTIME_OFFSET..]);
        let namelength = u64::from(n16(&header[BIN_NAMESIZE_OFFSET..]));
        // The name and the data are padded to an even length.
        let name_pad = namelength & 1;
        self.entry_bytes_remaining = n32(&header[BIN_FILESIZE_OFFSET..]);
        h.size = self.entry_bytes_remaining as u64;
        self.entry_padding = self.entry_bytes_remaining & 1;
        input.consume(BIN_HEADER_SIZE as u64)?;
        Ok((None, namelength, name_pad))
    }

    /// `record_hardlink`: an entry with more than one link is a hard link
    /// to the first entry with its device and inode, while that one has
    /// links left.
    fn record_hardlink(&mut self, entry: &mut Entry) {
        let h = &entry.header;
        if h.nlink <= 1 {
            return;
        }
        let key = (h.dev, h.ino);

        // A file already seen: this entry is a hard link to it.
        if let Some(le) = self.links.get_mut(&key) {
            entry.copy_hardlink(&le.name);
            le.links -= 1;
            if le.links == 0 {
                self.links.remove(&key);
            }
            return;
        }

        // libarchive fails with "Invalid hardlink entry with no pathname"
        // when the path could not be converted, which bytes always are.
        let le = LinksEntry {
            links: h.nlink - 1,
            name: h.path.clone(),
        };
        self.links.insert(key, le);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_stop_at_the_first_other_character() {
        assert_eq!(atol8(b"000777"), 0o777);
        assert_eq!(atol8(b"0778x9"), 0o77);
        assert_eq!(atol8(b"9"), 0);
        assert_eq!(atol16(b"0000Ff1g"), 0xff1);
        assert_eq!(atol16(b"ffffffffffffffff"), -1);
        assert_eq!(atol16u(b"8000000000000000"), 1 << 63);
    }

    #[test]
    fn binary_numbers_are_in_pdp_11_order() {
        assert_eq!(le32dec(&[0x34, 0x12, 0x78, 0x56]), 0x1234_5678);
        assert_eq!(be32dec(&[0x12, 0x34, 0x56, 0x78]), 0x1234_5678);
        assert_eq!(le32dec(&[0xff; 4]), 0xffff_ffff);
    }

    #[test]
    fn bids() {
        assert_eq!(bid(b"07070"), -1);
        assert_eq!(bid(b"070707"), 48);
        assert_eq!(bid(b"070727"), 48);
        assert_eq!(bid(b"070701"), 48);
        assert_eq!(bid(b"070702"), 48);
        assert_eq!(bid(b"070703"), 0);
        assert_eq!(bid(&[0xc7, 0x71, 0, 0, 0, 0]), 16);
        assert_eq!(bid(&[0x71, 0xc7, 0, 0, 0, 0]), 16);
        assert_eq!(bid(b"\xed\xab\xee\xdb\x03\x00"), 0);
    }

    #[test]
    fn afio_headers_need_their_letters() {
        // The second header of libarchive's test_read_format_cpio_afio.
        let header = b"0707270000006300000000000DAAE6m10064400010000000003E90000000100000\
000000000004B694A10n000600000000s0000000000000011:";
        assert!(is_afio_large(header));
        assert!(!is_afio_large(&header[..115]));
        let mut broken = header.to_vec();
        broken[30] = b'n';
        assert!(!is_afio_large(&broken));
        broken[30] = b'm';
        broken[40] = b'g';
        assert!(!is_afio_large(&broken));
    }
}
