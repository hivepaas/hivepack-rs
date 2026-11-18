//! VDI, the disk image of VirtualBox (`.vdi`, QEMU's `vdi`): a header after
//! the line of text that says what wrote it, and a map of the blocks that
//! have been written.
//!
//! Nothing is ported here. VDI is the one container here with no published
//! specification: what the header holds is read off the images themselves,
//! and every field is checked against what `qemu-img` writes and reads. Its
//! numbers are little-endian, which no other disk image here is. How it is
//! checked is in the repository: `docs/image.md`.

use std::io;

use super::disk::Disk;
use super::error::{Error, Unsupported};

/// The signature every VDI carries, 64 bytes in: the text in front of it
/// says what wrote the image (`<<< Oracle VM VirtualBox Disk Image >>>`,
/// and QEMU's own line), so it is the signature that tells one.
const SIGNATURE: u32 = 0xbeda_107f;

/// Where the signature is, and how much of the file the header's own fields
/// reach: the structure is 400 bytes from the type that follows the
/// signature, the version and the size.
const SIGNATURE_AT: usize = 0x40;
const HEADER_END: usize = 0x1dc;

/// The version read here, major and minor: what QEMU writes and reads, and
/// what VirtualBox has written since 2007. An older layout holds its map
/// elsewhere and is refused rather than read as this one.
const VERSION: u32 = 0x0001_0001;

/// What the header's image type says the image is: one that grows as it is
/// written, one written whole at once, and the two that hold only what
/// changed from another image.
const DYNAMIC: u32 = 1;
const FIXED: u32 = 2;
const UNDO: u32 = 3;
const DIFF: u32 = 4;

/// A block that has never been written, and one written as zeroes and given
/// back: both read as zeroes, and neither is anywhere in the file.
const FREE: u32 = u32::MAX;
const ZERO: u32 = u32::MAX - 1;

/// How long a sector is, which a block is a whole number of.
const SECTOR: u64 = 512;

/// How many blocks of the map are read at most: a disk of 4 TiB in the 1 MiB
/// blocks every tool writes has four million, and the map is held in memory.
const MOST_BLOCKS: u32 = 1 << 22;

/// A VDI image, as the disk it holds: reads of the disk are reads of the
/// blocks that have been written, and zeroes everywhere else.
pub struct Vdi<D> {
    inner: D,
    /// How long the disk is, which the header gives and which is not how
    /// long the file is.
    size: u64,
    /// How many bytes a block is: 1 MiB in every image anything writes.
    block: u64,
    /// Where the first block is. Each one after it is a block further on,
    /// in the order the map gives, which is not the order of the disk.
    data: u64,
    /// Which block of the file holds each block of the disk, or [`FREE`] or
    /// [`ZERO`] for one that is nowhere in it.
    map: Vec<u32>,
}

impl<D: Disk> Vdi<D> {
    /// The image in `inner`, if it is one.
    ///
    /// A differencing image, and the undo image of a snapshot, are refused:
    /// each holds only what changed from another image, which is a file this
    /// cannot reach.
    pub fn open(inner: D) -> Result<Vdi<D>, Error> {
        let whole = inner.size()?;
        if whole < HEADER_END as u64 {
            return Err(Error::Unrecognized);
        }
        let mut header = [0u8; HEADER_END];
        inner.read_exact_at(0, &mut header)?;
        if le32(&header, SIGNATURE_AT) != SIGNATURE {
            return Err(Error::Unrecognized);
        }
        // Past here the file says it is a VDI, so what it says is wrong
        // rather than somebody else's.
        if le32(&header, 0x44) != VERSION {
            return Err(Error::Needs(Unsupported::Feature));
        }
        match le32(&header, 0x4c) {
            DYNAMIC | FIXED => {}
            UNDO | DIFF => return Err(Error::Needs(Unsupported::Backing)),
            _ => return Err(Error::VdiSays),
        }
        let map_at = u64::from(le32(&header, 0x154));
        let data = u64::from(le32(&header, 0x158));
        let size = le64(&header, 0x170);
        let block = u64::from(le32(&header, 0x178));
        let extra = le32(&header, 0x17c);
        let blocks = le32(&header, 0x180);
        // Extra bytes kept in front of each block: nothing writes them, and
        // reading past them is not read here rather than untested.
        if extra != 0 {
            return Err(Error::Needs(Unsupported::Feature));
        }
        if size == 0 || block == 0 || !block.is_multiple_of(SECTOR) {
            return Err(Error::VdiSays);
        }
        if blocks == 0 || blocks > MOST_BLOCKS {
            return Err(Error::VdiSays);
        }
        // The map has to reach the whole disk, and be on the file, and the
        // blocks it points into have to start on it.
        if u64::from(blocks).saturating_mul(block) < size {
            return Err(Error::VdiSays);
        }
        let room = u64::from(blocks) * 4;
        if map_at.checked_add(room).is_none_or(|end| end > whole) || data > whole {
            return Err(Error::VdiSays);
        }
        let mut raw = vec![0u8; room as usize];
        inner.read_exact_at(map_at, &mut raw)?;
        let map = raw
            .as_chunks::<4>()
            .0
            .iter()
            .map(|four| u32::from_le_bytes(*four))
            .collect();
        Ok(Vdi {
            inner,
            size,
            block,
            data,
            map,
        })
    }

    /// Where the `at` byte of the disk is in the file, if it has been
    /// written, and how many bytes of the block follow it there.
    ///
    /// The map reaches the whole disk, which [`Vdi::open`] checked, so a
    /// byte inside the disk has an entry. Where it is counted with no room
    /// to spare the counting saturates rather than wrapping: the place
    /// stays past the file's end, where the read fails.
    fn place(&self, at: u64) -> Option<(u64, u64)> {
        let block = (at / self.block) as usize;
        let into = at % self.block;
        let which = self.map.get(block).copied()?;
        if which == FREE || which == ZERO {
            return None;
        }
        let there = u64::from(which)
            .saturating_mul(self.block)
            .saturating_add(self.data)
            .saturating_add(into);
        Some((there, self.block - into))
    }
}

impl<D: Disk> Disk for Vdi<D> {
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
                    // No read crosses a block: each is somewhere else in the
                    // file, and the one after it may never have been written
                    // at all.
                    let take = (want - done).min(block_left as usize);
                    let read = self.inner.read_at(there, &mut buf[done..done + take])?;
                    if read == 0 {
                        // The file ends inside a block the map names.
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "the image ends inside a block its map names",
                        ));
                    }
                    done += read;
                }
                None => {
                    // A block that was never written, or given back: zeroes,
                    // as the disk reads where nothing has been put.
                    let take = (want - done).min((self.block - at % self.block) as usize);
                    buf[done..done + take].fill(0);
                    done += take;
                }
            }
        }
        Ok(done)
    }
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
