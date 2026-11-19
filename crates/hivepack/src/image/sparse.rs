//! Android's sparse image (`sparse.img`, `super.img` out of a ROM, what
//! `img2simg` writes): a header, then chunks that each say what a run of
//! blocks holds — bytes in the file, one four-byte value over and over, or
//! nothing at all.
//!
//! It is not a disk image of the kind the containers beside it are. There
//! is no table of blocks to look things up in and no room for one: the
//! chunks come in the order of the disk, one after another, so where a
//! block is, is known only by reading the chunks from the start. That is
//! what opening one does, and what it keeps.
//!
//! Nothing is ported here. The layout is the one AOSP's `libsparse` fixes
//! in `sparse_format.h`, which is a header of field names and numbers; how
//! it is checked is in the repository: `docs/image.md`.

use std::io;

use super::disk::Disk;
use super::error::{Error, Unsupported};

/// What a sparse image begins with, little-endian.
const MAGIC: u32 = 0xed26_ff3a;

/// How long the two headers are, as every writer writes them. A later
/// version may make either longer, and the bytes it adds are stepped over.
const HEADER: u64 = 28;
const CHUNK_HEADER: u64 = 12;

/// What a chunk says it holds.
const RAW: u16 = 0xCAC1;
const FILL: u16 = 0xCAC2;
const DONT_CARE: u16 = 0xCAC3;
const CRC32: u16 = 0xCAC4;

/// How many chunks are read at most. A 4 GiB image of one block to a chunk
/// would have a million of them; the runs are held in memory, and no tool
/// writes an image anywhere near this.
const MOST_CHUNKS: u32 = 1 << 22;

/// A run of the disk, and where its bytes come from.
struct Run {
    /// Where the run begins on the disk, and how long it is.
    at: u64,
    len: u64,
    what: What,
}

enum What {
    /// The bytes are in the file, from here.
    Data(u64),
    /// Four bytes over and over, as the chunk gives them.
    Fill([u8; 4]),
    /// Nothing was ever written here: it reads as zeroes.
    Hole,
}

/// An Android sparse image, as the disk it holds: reads of the disk are
/// reads of the chunks that hold its blocks, and zeroes where nothing was
/// written.
pub struct AndroidSparse<D> {
    inner: D,
    /// How long the disk is: the blocks the header counts, times a block.
    size: u64,
    block: u64,
    /// The runs, in the order of the disk, which is the order the chunks
    /// are in. A block no chunk covers is not here and reads as zeroes.
    runs: Vec<Run>,
}

impl<D: Disk> AndroidSparse<D> {
    /// The image in `inner`, if it is one.
    pub fn open(inner: D) -> Result<AndroidSparse<D>, Error> {
        let whole = inner.size()?;
        if whole < HEADER {
            return Err(Error::Unrecognized);
        }
        let mut header = [0u8; HEADER as usize];
        inner.read_exact_at(0, &mut header)?;
        if le32(&header, 0) != MAGIC {
            return Err(Error::Unrecognized);
        }
        // Past here the file says it is a sparse image, so what it says is
        // wrong rather than somebody else's.
        if le16(&header, 4) != 1 {
            return Err(Error::Needs(Unsupported::Feature));
        }
        let header_len = u64::from(le16(&header, 8));
        let chunk_header_len = u64::from(le16(&header, 10));
        let block = u64::from(le32(&header, 12));
        let blocks = u64::from(le32(&header, 16));
        let chunks = le32(&header, 20);
        if header_len < HEADER || chunk_header_len < CHUNK_HEADER {
            return Err(Error::SparseSays);
        }
        // A block is a whole number of four bytes, which is what a fill
        // chunk's four-byte value needs to come out even.
        if block == 0 || !block.is_multiple_of(4) || chunks > MOST_CHUNKS {
            return Err(Error::SparseSays);
        }
        // Two 32-bit numbers multiplied fit a 64-bit one, so this cannot
        // go over: the largest a header can say is 2^64 - 5 × 2^32.
        let size = blocks * block;

        let mut runs = Vec::new();
        let mut at = header_len;
        let mut block_at = 0u64;
        for _ in 0..chunks {
            let mut chunk = [0u8; CHUNK_HEADER as usize];
            inner.read_exact_at(at, &mut chunk)?;
            let kind = le16(&chunk, 0);
            let how_many = u64::from(le32(&chunk, 4));
            let whole_chunk = u64::from(le32(&chunk, 8));
            // Every chunk holds its own header, and the file has to hold
            // the chunk.
            if whole_chunk < chunk_header_len {
                return Err(Error::SparseSays);
            }
            let next = at.checked_add(whole_chunk).ok_or(Error::SparseSays)?;
            if next > whole {
                return Err(Error::SparseSays);
            }
            // As above: a chunk's blocks and a block are both 32-bit.
            let len = how_many * block;
            // The chunks are the disk in order, so they cannot cover more
            // of it than there is.
            let after = block_at.checked_add(len).ok_or(Error::SparseSays)?;
            if after > size {
                return Err(Error::SparseSays);
            }
            let data = at + chunk_header_len;
            match kind {
                RAW => {
                    if whole_chunk != chunk_header_len + len {
                        return Err(Error::SparseSays);
                    }
                    runs.push(Run {
                        at: block_at,
                        len,
                        what: What::Data(data),
                    });
                }
                FILL => {
                    if whole_chunk != chunk_header_len + 4 {
                        return Err(Error::SparseSays);
                    }
                    let mut four = [0u8; 4];
                    inner.read_exact_at(data, &mut four)?;
                    runs.push(Run {
                        at: block_at,
                        len,
                        what: What::Fill(four),
                    });
                }
                DONT_CARE => {
                    if whole_chunk != chunk_header_len {
                        return Err(Error::SparseSays);
                    }
                    runs.push(Run {
                        at: block_at,
                        len,
                        what: What::Hole,
                    });
                }
                // A running checksum of what the image holds so far. It
                // covers no blocks of its own, and what it says is not
                // checked: see `docs/image.md`.
                CRC32 => {
                    if whole_chunk != chunk_header_len + 4 || len != 0 {
                        return Err(Error::SparseSays);
                    }
                }
                // A kind this does not know. Stepping over it would read
                // the blocks it covers as holes, and read every chunk
                // after it at the wrong place on the disk.
                _ => return Err(Error::Needs(Unsupported::Feature)),
            }
            block_at = after;
            at = next;
        }
        Ok(AndroidSparse {
            inner,
            size,
            block,
            runs,
        })
    }

    /// How many bytes a block is, which the chunks count in.
    pub fn block_size(&self) -> u64 {
        self.block
    }

    /// The run holding the `at` byte, if a chunk covers it.
    fn run(&self, at: u64) -> Option<&Run> {
        let i = self.runs.partition_point(|run| run.at <= at);
        let run = self.runs.get(i.checked_sub(1)?)?;
        (at < run.at + run.len).then_some(run)
    }

    /// How far the next run begins from `at`, or to the disk's end where
    /// there is none: what reads as zeroes where no chunk covers `at`.
    fn next_run(&self, at: u64) -> u64 {
        let i = self.runs.partition_point(|run| run.at <= at);
        self.runs.get(i).map_or(self.size, |run| run.at)
    }
}

impl<D: Disk> Disk for AndroidSparse<D> {
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
            match self.run(at) {
                Some(run) => {
                    let into = at - run.at;
                    let take = (want - done).min((run.len - into) as usize);
                    match run.what {
                        What::Data(from) => {
                            let read = self
                                .inner
                                .read_at(from + into, &mut buf[done..done + take])?;
                            if read == 0 {
                                // The file ends inside a chunk the header
                                // counted.
                                return Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "the image ends inside a chunk it counts",
                                ));
                            }
                            done += read;
                        }
                        What::Fill(four) => {
                            for (i, byte) in buf[done..done + take].iter_mut().enumerate() {
                                *byte = four[((into + i as u64) % 4) as usize];
                            }
                            done += take;
                        }
                        What::Hole => {
                            buf[done..done + take].fill(0);
                            done += take;
                        }
                    }
                }
                // Past the last chunk, or in a gap no chunk covers: zeroes,
                // as the disk reads where nothing has been put.
                None => {
                    let until = self.next_run(at);
                    let take = (want - done).min((until - at) as usize);
                    buf[done..done + take].fill(0);
                    done += take;
                }
            }
        }
        Ok(done)
    }
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
