//! VHD, the disk image of Virtual PC and Hyper-V (`.vhd`, QEMU's `vpc`):
//! a footer at the file's end, and, for one that grows, a table of the
//! blocks that have been written.
//!
//! Nothing is ported here. The layout is Microsoft's published *Virtual Hard
//! Disk Image Format Specification* (1.0), under its Open Specification
//! Promise, and every number in it is big-endian. How it is checked against
//! `qemu-img` is in the repository: `docs/image.md`.

use std::io;

use super::disk::Disk;
use super::error::Error;

/// The footer's cookie, and the dynamic header's.
const FOOTER_COOKIE: &[u8; 8] = b"conectix";
const DYNAMIC_COOKIE: &[u8; 8] = b"cxsparse";

/// How long each is, and how long a sector is.
const FOOTER: u64 = 512;
const DYNAMIC: u64 = 1024;
const SECTOR: u64 = 512;

/// What the footer's disk type says the image is.
const FIXED: u32 = 2;
const DYNAMIC_DISK: u32 = 3;
const DIFFERENCING: u32 = 4;

/// An entry of the block allocation table that says the block has never
/// been written: it reads as zeroes.
const UNUSED: u32 = u32::MAX;

/// How many entries of the table are read at most: a disk of 8 TiB in the
/// 2 MiB blocks every tool writes has four million, and the table is held
/// in memory.
const MOST_ENTRIES: u32 = 1 << 22;

/// A VHD image, as the disk it holds: reads of the disk are reads of the
/// blocks that have been written, and zeroes everywhere else.
pub struct Vhd<D> {
    inner: D,
    /// How long the disk is, which the footer gives and which is not how
    /// long the file is.
    size: u64,
    grows: Option<Grows>,
}

/// What a disk that grows needs beside its footer: where each block is.
struct Grows {
    /// How many bytes a block is: a power of two, 2 MiB in every image
    /// anything writes.
    block: u64,
    /// How many bytes the bitmap before each block takes, its length
    /// rounded up to a whole sector, as the specification says it is.
    bitmap: u64,
    /// Where each block's bitmap is, in sectors, or [`UNUSED`].
    table: Vec<u32>,
}

impl<D: Disk> Vhd<D> {
    /// The image in `inner`, if it is one.
    ///
    /// A differencing disk is refused: it holds only what changed from
    /// another disk, which is a file this cannot reach.
    pub fn open(inner: D) -> Result<Vhd<D>, Error> {
        let whole = inner.size()?;
        if whole < FOOTER {
            return Err(Error::Unrecognized);
        }
        // The footer is at the file's end. A disk that grows keeps a copy at
        // the start as well, which is what is read when the end is lost;
        // the one at the end is the one that counts.
        let mut footer = [0u8; FOOTER as usize];
        inner.read_exact_at(whole - FOOTER, &mut footer)?;
        if &footer[..8] != FOOTER_COOKIE || !checks(&footer, 64) {
            inner.read_exact_at(0, &mut footer)?;
            if &footer[..8] != FOOTER_COOKIE || !checks(&footer, 64) {
                return Err(Error::Unrecognized);
            }
        }
        let size = be64(&footer, 48);
        let kind = be32(&footer, 60);
        if size == 0 || !size.is_multiple_of(SECTOR) {
            return Err(Error::VhdSays);
        }
        match kind {
            FIXED => {
                // The data is the file itself, the footer apart.
                if whole - FOOTER < size {
                    return Err(Error::VhdSays);
                }
                Ok(Vhd {
                    inner,
                    size,
                    grows: None,
                })
            }
            DYNAMIC_DISK => {
                let at = be64(&footer, 16);
                let grows = Self::grows(&inner, at, size, whole)?;
                Ok(Vhd {
                    inner,
                    size,
                    grows: Some(grows),
                })
            }
            DIFFERENCING => Err(Error::Differencing),
            _ => Err(Error::VhdSays),
        }
    }

    /// The table of a disk that grows, from the dynamic header at `at`.
    fn grows(inner: &D, at: u64, size: u64, whole: u64) -> Result<Grows, Error> {
        if at == u64::MAX || at.checked_add(DYNAMIC).is_none_or(|end| end > whole) {
            return Err(Error::VhdSays);
        }
        let mut header = [0u8; DYNAMIC as usize];
        inner.read_exact_at(at, &mut header)?;
        if &header[..8] != DYNAMIC_COOKIE || !checks(&header, 36) {
            return Err(Error::VhdCheck);
        }
        let table_at = be64(&header, 16);
        let entries = be32(&header, 28);
        let block = u64::from(be32(&header, 32));
        if block < SECTOR || !block.is_power_of_two() || entries == 0 || entries > MOST_ENTRIES {
            return Err(Error::VhdSays);
        }
        // The table has to reach the whole disk, and be on the file.
        if u64::from(entries).saturating_mul(block) < size {
            return Err(Error::VhdSays);
        }
        let room = u64::from(entries) * 4;
        if table_at.checked_add(room).is_none_or(|end| end > whole) {
            return Err(Error::VhdSays);
        }
        let mut raw = vec![0u8; room as usize];
        inner.read_exact_at(table_at, &mut raw)?;
        let table = raw
            .as_chunks::<4>()
            .0
            .iter()
            .map(|four| u32::from_be_bytes(*four))
            .collect();
        // A bitmap of one bit for each sector of a block, its length
        // rounded up to a whole sector.
        let bits = block / SECTOR;
        let bitmap = bits.div_ceil(8).div_ceil(SECTOR) * SECTOR;
        Ok(Grows {
            block,
            bitmap,
            table,
        })
    }

    /// Where the `at` byte of the disk is in the file, if it has been
    /// written, and how many bytes of the block follow it there.
    fn place(&self, at: u64) -> Option<(u64, u64)> {
        let Some(grows) = &self.grows else {
            // A fixed disk is the file itself.
            return Some((at, self.size - at));
        };
        let block = (at / grows.block) as usize;
        let into = at % grows.block;
        let sector = grows.table.get(block).copied()?;
        if sector == UNUSED {
            return None;
        }
        let data = u64::from(sector) * SECTOR + grows.bitmap;
        Some((data + into, grows.block - into))
    }
}

impl<D: Disk> Disk for Vhd<D> {
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
            match self.place(at) {
                Some((there, block_left)) => {
                    // No read crosses a block: each is somewhere else in
                    // the file, and the one after it may never have been
                    // written at all.
                    let take = (want - done).min(block_left as usize);
                    let read = self.inner.read_at(there, &mut buf[done..done + take])?;
                    if read == 0 {
                        // The file ends inside a block the table names.
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "the image ends inside a block its table names",
                        ));
                    }
                    done += read;
                }
                None => {
                    // A block that was never written: zeroes, as the disk
                    // reads where nothing has been put.
                    let block = self.grows.as_ref().map_or(self.size, |g| g.block);
                    let take = (want - done).min((block - at % block) as usize);
                    buf[done..done + take].fill(0);
                    done += take;
                }
            }
        }
        Ok(done)
    }
}

/// Whether the structure's own checksum is what it says: the ones'
/// complement of the sum of every byte, the four of the checksum itself
/// read as zeroes. `at` is where those four are.
fn checks(of: &[u8], at: usize) -> bool {
    let told = be32(of, at);
    let sum = of
        .iter()
        .enumerate()
        .filter(|(i, _)| !(at..at + 4).contains(i))
        .fold(0u32, |sum, (_, b)| sum.wrapping_add(u32::from(*b)));
    !sum == told
}

fn be32(of: &[u8], at: usize) -> u32 {
    of.get(at..at + 4)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_be_bytes)
}

fn be64(of: &[u8], at: usize) -> u64 {
    of.get(at..at + 8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_be_bytes)
}
