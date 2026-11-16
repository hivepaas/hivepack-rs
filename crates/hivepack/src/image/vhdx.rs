//! VHDX, the disk image Hyper-V and WSL2 use (`.vhdx`): two headers, a table
//! of the regions the file is made of, metadata that says what the disk is,
//! and a table of where each of its blocks lies.
//!
//! Nothing is ported here. The layout is Microsoft's published *VHDX Format
//! Specification* (1.00), under its Open Specification Promise, and every
//! number in it is little-endian — where VHD, its elder, was big-endian
//! throughout. Each header and table carries a CRC-32C, Castagnoli's, and
//! not the CRC-32 a GUID partition table uses. How it is checked against
//! `qemu-img` is in the repository: `docs/image.md`.
//!
//! Unlike every other container here, a VHDX **says what a sector is on the
//! disk it holds** ([`Vhdx::sector`]), which is what
//! [`partitions_in`](super::partitions_in) wants: a master boot record's own
//! numbers cannot tell.

use std::io;

use super::crc32c::crc32c;
use super::disk::Disk;
use super::error::{Error, Unsupported};

/// The file's own first bytes.
const SIGNATURE: &[u8; 8] = b"vhdxfile";

/// Where each of the two headers is, and each of the two region tables, and
/// how long each is. The specification fixes all of them.
const HEADERS: [u64; 2] = [64 << 10, 128 << 10];
const HEADER_LEN: usize = 4096;
const REGIONS: [u64; 2] = [192 << 10, 256 << 10];
const REGION_LEN: usize = 64 << 10;

/// The regions that matter, by the identifier the specification gives each,
/// as the GUID's bytes lie in the file.
const BAT_REGION: [u8; 16] = [
    0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08,
];
const METADATA_REGION: [u8; 16] = [
    0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B, 0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E,
];

/// The metadata items that matter, the same way.
const FILE_PARAMETERS: [u8; 16] = [
    0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D, 0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B,
];
const VIRTUAL_DISK_SIZE: [u8; 16] = [
    0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48, 0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8,
];
const LOGICAL_SECTOR_SIZE: [u8; 16] = [
    0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47, 0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F,
];
/// The two standard items nothing here needs, named so that they are not
/// taken for items this does not know: every one of the five the
/// specification defines is marked as needed, which says that a reader
/// which cannot make sense of it must not read the disk — and a reader is
/// meant to know these.
const PAGE_83_DATA: [u8; 16] = [
    0xAB, 0x12, 0xCA, 0xBE, 0xE6, 0xB2, 0x23, 0x45, 0x93, 0xEF, 0xC3, 0x09, 0xE0, 0x00, 0xC7, 0x46,
];
const PHYSICAL_SECTOR_SIZE: [u8; 16] = [
    0xC7, 0x48, 0xA3, 0xCD, 0x5D, 0x44, 0x71, 0x44, 0x9C, 0xC9, 0xE9, 0x88, 0x52, 0x51, 0xC5, 0x56,
];
const PARENT_LOCATOR: [u8; 16] = [
    0x2D, 0x5F, 0xD3, 0xA8, 0x0B, 0xB3, 0x4D, 0x45, 0xAB, 0xF7, 0xD3, 0xD8, 0x48, 0x34, 0xAB, 0x0C,
];

/// What a block's entry in the table says of it.
const NOT_PRESENT: u64 = 0;
const UNDEFINED: u64 = 1;
const ZERO: u64 = 2;
const UNMAPPED: u64 = 3;
const FULLY_PRESENT: u64 = 6;
const PARTIALLY_PRESENT: u64 = 7;

/// A block's place is kept in megabytes, in the entry's upper bits.
const MEGABYTE: u64 = 1 << 20;

/// What a block may be: the specification's own bounds.
const LEAST_BLOCK: u64 = 1 << 20;
const MOST_BLOCK: u64 = 256 << 20;

/// How many entries of the table are read at most: it is held in memory,
/// and a disk of 64 TiB in 32 MiB blocks has two million.
const MOST_ENTRIES: u64 = 1 << 22;

/// A VHDX image, as the disk it holds: reads of the disk are reads of the
/// blocks that have been written, and zeroes everywhere else.
pub struct Vhdx<D> {
    inner: D,
    size: u64,
    block: u64,
    /// How many bytes a sector of the disk is: 512 or 4096, as the image's
    /// own metadata says.
    sector: u64,
    /// How many of the table's entries are blocks of the disk before one
    /// that is a bitmap instead.
    chunk: u64,
    table: Vec<u64>,
}

/// Where a region of the file is, and how long it is.
struct Region {
    at: u64,
    len: u64,
}

impl<D: Disk> Vhdx<D> {
    /// The image in `inner`, if it is one.
    ///
    /// An image whose log holds entries that were never applied is refused:
    /// what they say belongs in the tables, and putting it there is
    /// writing. So is one that holds only what changed from another image.
    pub fn open(inner: D) -> Result<Vhdx<D>, Error> {
        let whole = inner.size()?;
        let mut signature = [0u8; 8];
        if whole < REGIONS[1] + REGION_LEN as u64
            || inner.read_at(0, &mut signature)? < signature.len()
            || &signature != SIGNATURE
        {
            return Err(Error::Unrecognized);
        }
        let header = Self::header(&inner)?;
        // A log that was written and not applied: a reader that passed over
        // it would answer with what the disk held before.
        if header[48..64].iter().any(|b| *b != 0) {
            return Err(Error::Needs(Unsupported::Log));
        }
        if le16(&header, 66) != 1 {
            return Err(Error::VhdxSays);
        }
        let (bat, metadata) = Self::regions(&inner, whole)?;
        let (size, block, sector) = Self::metadata(&inner, &metadata)?;
        if size == 0 || !size.is_multiple_of(sector) {
            return Err(Error::VhdxSays);
        }
        if !(LEAST_BLOCK..=MOST_BLOCK).contains(&block) || !block.is_power_of_two() {
            return Err(Error::VhdxSays);
        }
        // Blocks of the disk come in runs of `chunk`, each run followed by
        // one entry that is a bitmap rather than a block of the disk.
        let chunk = (1u64 << 23) * sector / block;
        if chunk == 0 {
            return Err(Error::VhdxSays);
        }
        let blocks = size.div_ceil(block);
        let entries = blocks + (blocks - 1) / chunk;
        if entries > MOST_ENTRIES || entries * 8 > bat.len {
            return Err(Error::VhdxSays);
        }
        let mut raw = vec![0u8; (entries * 8) as usize];
        inner.read_exact_at(bat.at, &mut raw)?;
        let table = raw
            .as_chunks::<8>()
            .0
            .iter()
            .map(|eight| u64::from_le_bytes(*eight))
            .collect();
        Ok(Vhdx {
            inner,
            size,
            block,
            sector,
            chunk,
            table,
        })
    }

    /// How many bytes a sector of the disk is, as the image says: what
    /// [`partitions_in`](super::partitions_in) is given for a disk whose
    /// sectors are its own, since a master boot record cannot say.
    pub fn sector(&self) -> u64 {
        self.sector
    }

    /// The header that counts: of the two, the one whose own CRC-32C holds
    /// and whose sequence number is the greater, as whatever wrote the file
    /// last left it.
    fn header(inner: &D) -> Result<Vec<u8>, Error> {
        let mut best: Option<(u64, Vec<u8>)> = None;
        for at in HEADERS {
            let mut head = vec![0u8; HEADER_LEN];
            inner.read_exact_at(at, &mut head)?;
            if &head[..4] != b"head" || !checks(&mut head.clone(), 4) {
                continue;
            }
            let sequence = le64(&head, 8);
            if best.as_ref().is_none_or(|(seen, _)| sequence > *seen) {
                best = Some((sequence, head));
            }
        }
        best.map(|(_, head)| head).ok_or(Error::VhdxCheck)
    }

    /// Where the table of blocks and the metadata are, from whichever of the
    /// two region tables holds.
    fn regions(inner: &D, whole: u64) -> Result<(Region, Region), Error> {
        let mut why = Error::VhdxCheck;
        for at in REGIONS {
            let mut table = vec![0u8; REGION_LEN];
            inner.read_exact_at(at, &mut table)?;
            if &table[..4] != b"regi" || !checks(&mut table.clone(), 4) {
                continue;
            }
            let count = le32(&table, 8) as usize;
            if count > (REGION_LEN - 16) / 32 {
                why = Error::VhdxSays;
                continue;
            }
            let (mut bat, mut metadata) = (None, None);
            let mut wrong = None;
            for i in 0..count {
                let entry = 16 + i * 32;
                let Ok(guid) = <[u8; 16]>::try_from(&table[entry..entry + 16]) else {
                    wrong = Some(Error::VhdxSays);
                    break;
                };
                let region = Region {
                    at: le64(&table, entry + 16),
                    len: u64::from(le32(&table, entry + 24)),
                };
                let required = le32(&table, entry + 28) & 1 != 0;
                if region
                    .at
                    .checked_add(region.len)
                    .is_none_or(|end| end > whole)
                {
                    wrong = Some(Error::VhdxSays);
                    break;
                }
                match guid {
                    BAT_REGION => bat = Some(region),
                    METADATA_REGION => metadata = Some(region),
                    // A region the image says is needed and this does not
                    // know: what is in it may be what the disk is.
                    _ if required => {
                        wrong = Some(Error::Needs(Unsupported::Feature));
                        break;
                    }
                    _ => {}
                }
            }
            if let Some(e) = wrong {
                return Err(e);
            }
            match (bat, metadata) {
                (Some(bat), Some(metadata)) => return Ok((bat, metadata)),
                _ => why = Error::VhdxSays,
            }
        }
        Err(why)
    }

    /// What the metadata says the disk is: how long it is, how large a block
    /// is, and how many bytes a sector is.
    fn metadata(inner: &D, region: &Region) -> Result<(u64, u64, u64), Error> {
        // The table at the region's start: its own header, then an entry for
        // each item.
        let mut head = [0u8; 32];
        inner.read_exact_at(region.at, &mut head)?;
        if &head[..8] != b"metadata" {
            return Err(Error::VhdxSays);
        }
        let count = usize::from(le16(&head, 10));
        let room = 32 + count * 32;
        if count > 2047 || room as u64 > region.len {
            return Err(Error::VhdxSays);
        }
        let mut entries = vec![0u8; room];
        inner.read_exact_at(region.at, &mut entries)?;
        let (mut size, mut block, mut sector) = (None, None, None);
        for i in 0..count {
            let entry = 32 + i * 32;
            let Ok(guid) = <[u8; 16]>::try_from(&entries[entry..entry + 16]) else {
                return Err(Error::VhdxSays);
            };
            // Where the item is, counted from the region's own start.
            let at = u64::from(le32(&entries, entry + 16));
            let len = u64::from(le32(&entries, entry + 20));
            let required = le32(&entries, entry + 24) & (1 << 2) != 0;
            if at.checked_add(len).is_none_or(|end| end > region.len) {
                return Err(Error::VhdxSays);
            }
            let mut item = vec![0u8; len as usize];
            inner.read_exact_at(region.at + at, &mut item)?;
            match guid {
                FILE_PARAMETERS if len >= 8 => {
                    block = Some(u64::from(le32(&item, 0)));
                    // Bit 1: it holds only what changed from another disk,
                    // which the parent locator names.
                    if le32(&item, 4) & (1 << 1) != 0 {
                        return Err(Error::Needs(Unsupported::Backing));
                    }
                }
                VIRTUAL_DISK_SIZE if len >= 8 => size = Some(le64(&item, 0)),
                LOGICAL_SECTOR_SIZE if len >= 4 => sector = Some(u64::from(le32(&item, 0))),
                PARENT_LOCATOR => return Err(Error::Needs(Unsupported::Backing)),
                // Standard, and nothing here needs what they hold: what
                // tells a disk apart, and the size its hardware writes in.
                PAGE_83_DATA | PHYSICAL_SECTOR_SIZE => {}
                // An item the image says is needed and this does not know.
                _ if required => return Err(Error::Needs(Unsupported::Feature)),
                _ => {}
            }
        }
        let (Some(size), Some(block), Some(sector)) = (size, block, sector) else {
            return Err(Error::VhdxSays);
        };
        if sector != 512 && sector != 4096 {
            return Err(Error::VhdxSays);
        }
        Ok((size, block, sector))
    }

    /// Where the `at` byte of the disk is in the file, if its block is there
    /// at all, and how many bytes of that block follow it.
    fn place(&self, at: u64) -> io::Result<Option<(u64, u64)>> {
        let block = at / self.block;
        let into = at % self.block;
        // The bitmap entry after each run of blocks is counted over.
        let index = block + block / self.chunk;
        let Some(entry) = self.table.get(index as usize).copied() else {
            return Ok(None);
        };
        match entry & 7 {
            FULLY_PRESENT => Ok(Some(((entry >> 20) * MEGABYTE + into, self.block - into))),
            // Nothing has been written there, or the image says it reads as
            // zeroes, or it has been trimmed.
            NOT_PRESENT | UNDEFINED | ZERO | UNMAPPED => Ok(None),
            // Only an image with another behind it has these, and such an
            // image is refused when it is opened.
            PARTIALLY_PRESENT => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "a block is only partly here, which needs the image behind this one",
            )),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "a block's entry says a state the format does not have",
            )),
        }
    }
}

impl<D: Disk> Disk for Vhdx<D> {
    fn size(&self) -> io::Result<u64> {
        Ok(self.size)
    }

    fn read_at(&self, at: u64, buf: &mut [u8]) -> io::Result<usize> {
        let Some(left) = self.size.checked_sub(at) else {
            return Ok(0);
        };
        let want = (buf.len() as u64).min(left) as usize;
        if want == 0 {
            return Ok(0);
        }
        let mut done = 0;
        while done < want {
            let at = at + done as u64;
            match self.place(at)? {
                Some((there, block_left)) => {
                    // No read crosses a block: the next one is elsewhere in
                    // the file, or nowhere.
                    let take = (want - done).min(block_left as usize);
                    let read = self.inner.read_at(there, &mut buf[done..done + take])?;
                    if read == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "the image ends inside a block its table names",
                        ));
                    }
                    done += read;
                }
                None => {
                    let take = (want - done).min((self.block - at % self.block) as usize);
                    buf[done..done + take].fill(0);
                    done += take;
                }
            }
        }
        Ok(done)
    }
}

/// Whether the structure's own CRC-32C is what it says, `at` being where its
/// four bytes are. Those are read as zeroes, which leaves `of` changed, so
/// the caller passes a copy.
fn checks(of: &mut [u8], at: usize) -> bool {
    let told = le32(of, at);
    of[at..at + 4].fill(0);
    crc32c(of) == told
}

fn le16(of: &[u8], at: usize) -> u16 {
    of.get(at..at + 2)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u16::from_le_bytes)
}

fn le32(of: &[u8], at: usize) -> u32 {
    of.get(at..at + 4)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

fn le64(of: &[u8], at: usize) -> u64 {
    of.get(at..at + 8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}
