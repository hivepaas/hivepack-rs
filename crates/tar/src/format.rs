//! The 512-byte header block and its layouts: port of `format.go`.
//!
//! - V7: name, mode, uid, gid, size, mtime, checksum, type, link name.
//! - USTAR (POSIX.1-1988), and PAX on top of it: magic `ustar\0`, version
//!   `00`, owner and group names, device numbers, a 155-byte name prefix.
//! - GNU: magic `ustar `, version ` \0`; atime and ctime in place of the
//!   prefix, and the old sparse map.
//! - STAR: USTAR with a 131-byte prefix, atime, ctime, and `tar\0` at the
//!   end.

use crate::common::{BLOCK_SIZE, Format};
use crate::strconv::{Formatter, Parser};

/// A header block.
pub(crate) type Block = [u8; BLOCK_SIZE];

/// The fields of a block, by offset and length.
pub(crate) mod field {
    pub(crate) const NAME: (usize, usize) = (0, 100);
    pub(crate) const MODE: (usize, usize) = (100, 8);
    pub(crate) const UID: (usize, usize) = (108, 8);
    pub(crate) const GID: (usize, usize) = (116, 8);
    pub(crate) const SIZE: (usize, usize) = (124, 12);
    pub(crate) const MOD_TIME: (usize, usize) = (136, 12);
    pub(crate) const CHKSUM: (usize, usize) = (148, 8);
    pub(crate) const TYPE_FLAG: (usize, usize) = (156, 1);
    pub(crate) const LINK_NAME: (usize, usize) = (157, 100);
    pub(crate) const MAGIC: (usize, usize) = (257, 6);
    pub(crate) const VERSION: (usize, usize) = (263, 2);
    pub(crate) const USER_NAME: (usize, usize) = (265, 32);
    pub(crate) const GROUP_NAME: (usize, usize) = (297, 32);
    pub(crate) const DEV_MAJOR: (usize, usize) = (329, 8);
    pub(crate) const DEV_MINOR: (usize, usize) = (337, 8);
    /// USTAR's.
    pub(crate) const USTAR_PREFIX: (usize, usize) = (345, 155);
    /// GNU's.
    pub(crate) const GNU_ACCESS_TIME: (usize, usize) = (345, 12);
    pub(crate) const GNU_CHANGE_TIME: (usize, usize) = (357, 12);
    pub(crate) const GNU_SPARSE: (usize, usize) = (386, 24 * 4 + 1);
    pub(crate) const GNU_REAL_SIZE: (usize, usize) = (483, 12);
    /// STAR's.
    pub(crate) const STAR_PREFIX: (usize, usize) = (345, 131);
    pub(crate) const STAR_ACCESS_TIME: (usize, usize) = (476, 12);
    pub(crate) const STAR_CHANGE_TIME: (usize, usize) = (488, 12);
    pub(crate) const STAR_TRAILER: (usize, usize) = (508, 4);
}

/// A field of `b`.
pub(crate) fn get(b: &Block, (at, len): (usize, usize)) -> &[u8] {
    &b[at..at + len]
}

/// A field of `b`, to fill in.
pub(crate) fn get_mut(b: &mut Block, (at, len): (usize, usize)) -> &mut [u8] {
    &mut b[at..at + len]
}

const MAGIC_GNU: &[u8] = b"ustar ";
const VERSION_GNU: &[u8] = b" \x00";
const MAGIC_USTAR: &[u8] = b"ustar\x00";
const VERSION_USTAR: &[u8] = b"00";
const TRAILER_STAR: &[u8] = b"tar\x00";

/// `computeChecksum`: the block's bytes summed, unsigned and signed (some
/// old tars summed signed bytes), the checksum field counted as spaces.
pub(crate) fn compute_checksum(b: &Block) -> (i64, i64) {
    let mut unsigned = 0i64;
    let mut signed = 0i64;
    for (i, &c) in b.iter().enumerate() {
        let c = if (148..156).contains(&i) { b' ' } else { c };
        unsigned += i64::from(c);
        signed += i64::from(c as i8);
    }
    (unsigned, signed)
}

/// `getFormat`: the format the block says, if its checksum is right.
pub(crate) fn get_format(b: &Block) -> Format {
    let mut p = Parser::default();
    let value = p.parse_octal(get(b, field::CHKSUM));
    let (chksum1, chksum2) = compute_checksum(b);
    if p.err || (value != chksum1 && value != chksum2) {
        return Format::UNKNOWN;
    }
    let magic = get(b, field::MAGIC);
    let version = get(b, field::VERSION);
    let trailer = get(b, field::STAR_TRAILER);
    if magic == MAGIC_USTAR && trailer == TRAILER_STAR {
        Format::STAR
    } else if magic == MAGIC_USTAR {
        Format::USTAR.union(Format::PAX)
    } else if magic == MAGIC_GNU && version == VERSION_GNU {
        Format::GNU
    } else {
        Format::V7
    }
}

/// `setFormat`, for the formats the writer writes: GNU's magic, or USTAR's
/// for USTAR and PAX, and the checksum, which ends in a NUL and a space.
pub(crate) fn set_format(b: &mut Block, format: Format) {
    if format.has(Format::GNU) {
        get_mut(b, field::MAGIC).copy_from_slice(MAGIC_GNU);
        get_mut(b, field::VERSION).copy_from_slice(VERSION_GNU);
    } else {
        get_mut(b, field::MAGIC).copy_from_slice(MAGIC_USTAR);
        get_mut(b, field::VERSION).copy_from_slice(VERSION_USTAR);
    }
    let (chksum, _) = compute_checksum(b); // From 256 to 128776.
    let sum = get_mut(b, field::CHKSUM);
    Formatter::default().format_octal(&mut sum[..7], chksum); // 128776 < 262143.
    sum[7] = b' ';
}

/// `sparseArray`: entries of 24 bytes, an offset and a length of 12 each,
/// then one byte that says whether an extension block follows.
pub(crate) struct SparseArray<'a>(pub(crate) &'a [u8]);

impl SparseArray<'_> {
    /// `maxEntries`.
    pub(crate) fn max_entries(&self) -> usize {
        self.0.len() / 24
    }

    /// `entry(i).offset()` and `entry(i).length()`.
    pub(crate) fn entry(&self, i: usize) -> (&[u8], &[u8]) {
        let e = &self.0[i * 24..];
        (&e[..12], &e[12..24])
    }

    /// `isExtended()[0]`.
    pub(crate) fn is_extended(&self) -> u8 {
        self.0[24 * self.max_entries()]
    }
}
