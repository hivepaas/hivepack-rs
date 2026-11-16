//! QCOW2, QEMU's own disk image (`.qcow2`): a header, two levels of tables
//! that say where each cluster of the disk is kept, and clusters that may be
//! compressed.
//!
//! Nothing is ported here. The layout is QEMU's published interoperability
//! specification, `docs/interop/qcow2.txt`, written for other programs to
//! read and write the format; QEMU's own driver is GPL-2.0, and this module
//! is under the crate's own license. How it is checked against `qemu-img` is
//! in the repository: `docs/image.md`.
//!
//! What is read is the disk as it is now. Snapshots are other tables in the
//! same file and are not read, and neither is an image that needs another
//! one behind it.

use std::io;

use super::disk::Disk;
use super::error::{Error, Unsupported};

/// The first four bytes of every QCOW2 image.
const MAGIC: &[u8; 4] = b"QFI\xfb";

/// How long a header is at the least: version 2's, which version 3 grew.
const HEADER_2: usize = 72;
const HEADER_3: usize = 104;

/// The cluster sizes the format allows: 512 bytes to 2 MiB, as `cluster_bits`
/// gives them.
const LEAST_BITS: u32 = 9;
const MOST_BITS: u32 = 21;

/// What a table entry says, of what matters to read an image.
const COPIED: u64 = 1 << 63;
const COMPRESSED: u64 = 1 << 62;
/// Where a cluster is, in the bits an entry keeps it in: a byte offset, a
/// whole number of clusters, so its low nine bits are always zero.
const OFFSET: u64 = 0x00ff_ffff_ffff_fe00;
/// Version 3: the cluster reads as zeroes, whatever else the entry says.
const ZERO: u64 = 1;

/// The features an image may say it needs, which stop it being read if it
/// needs one that is not understood. Bit 0, a dirty refcount table, is not
/// among them: refcounts say which clusters are free, which only writing
/// needs.
const INCOMPATIBLE_CORRUPT: u64 = 1 << 1;
const INCOMPATIBLE_EXTERNAL_DATA: u64 = 1 << 2;
const INCOMPATIBLE_COMPRESSION: u64 = 1 << 3;
const INCOMPATIBLE_EXTENDED_L2: u64 = 1 << 4;
const INCOMPATIBLE_KNOWN: u64 = 1
    | INCOMPATIBLE_CORRUPT
    | INCOMPATIBLE_EXTERNAL_DATA
    | INCOMPATIBLE_COMPRESSION
    | INCOMPATIBLE_EXTENDED_L2;

/// How large the first level of tables may be: an entry for each table of
/// the second level, and the format's own greatest is 32 MiB of them.
const MOST_L1: u64 = 4 << 20;

/// How a compressed cluster is compressed, which version 3 may say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Squeezed {
    /// Deflate, with no zlib header: what every image before the field had.
    Deflate,
    /// Zstandard, which version 3 may ask for.
    Zstd,
}

/// A QCOW2 image, as the disk it holds: reads of the disk are reads of the
/// clusters that have been written, and zeroes everywhere else.
pub struct Qcow2<D> {
    inner: D,
    /// How long the disk is, which the header gives.
    size: u64,
    cluster: u64,
    cluster_bits: u32,
    /// How many entries a table of the second level holds.
    l2_entries: u64,
    /// The first level of tables, read once: where each table of the second
    /// level is, or 0 for a part of the disk nothing has been written to.
    l1: Vec<u64>,
    squeezed: Squeezed,
    /// Whether an entry's lowest bit means the cluster reads as zeroes,
    /// which version 3 gave it.
    zeroes_by_bit: bool,
}

impl<D: Disk> Qcow2<D> {
    /// The image in `inner`, if it is one.
    ///
    /// An image that needs another one behind it is refused, as is one whose
    /// data is in a file of its own, one that is encrypted, one marked as
    /// damaged, and one that needs a feature this does not have: each of
    /// those would otherwise be read as a disk of holes.
    pub fn open(inner: D) -> Result<Qcow2<D>, Error> {
        let whole = inner.size()?;
        if whole < HEADER_2 as u64 {
            return Err(Error::Unrecognized);
        }
        let mut head = [0u8; HEADER_3];
        let read = inner.read_at(0, &mut head)?;
        if read < HEADER_2 || &head[..4] != MAGIC {
            return Err(Error::Unrecognized);
        }
        let version = be32(&head, 4);
        if version < 2 {
            return Err(Error::Unrecognized);
        }
        if be64(&head, 8) != 0 {
            // A backing file: what is not in this image is in another, named
            // by a path written when the image was made.
            return Err(Error::Needs(Unsupported::Backing));
        }
        let cluster_bits = be32(&head, 20);
        if !(LEAST_BITS..=MOST_BITS).contains(&cluster_bits) {
            return Err(Error::Qcow2Says);
        }
        let cluster = 1u64 << cluster_bits;
        let size = be64(&head, 24);
        if be32(&head, 32) != 0 {
            return Err(Error::Needs(Unsupported::Encrypted));
        }
        let mut squeezed = Squeezed::Deflate;
        let mut zeroes_by_bit = false;
        if version >= 3 {
            if read < HEADER_3 {
                return Err(Error::Qcow2Says);
            }
            zeroes_by_bit = true;
            let incompatible = be64(&head, 72);
            if incompatible & !INCOMPATIBLE_KNOWN != 0 {
                return Err(Error::Needs(Unsupported::Feature));
            }
            if incompatible & INCOMPATIBLE_CORRUPT != 0 {
                return Err(Error::Needs(Unsupported::Corrupt));
            }
            if incompatible & INCOMPATIBLE_EXTERNAL_DATA != 0 {
                return Err(Error::Needs(Unsupported::ExternalData));
            }
            if incompatible & INCOMPATIBLE_EXTENDED_L2 != 0 {
                return Err(Error::Needs(Unsupported::ExtendedL2));
            }
            if incompatible & INCOMPATIBLE_COMPRESSION != 0 {
                // The kind is a byte of the header, which has to be long
                // enough to hold it.
                let length = be32(&head, 100) as usize;
                if length <= HEADER_3 {
                    return Err(Error::Qcow2Says);
                }
                let mut kind = [0u8; 1];
                inner.read_exact_at(HEADER_3 as u64, &mut kind)?;
                squeezed = match kind[0] {
                    0 => Squeezed::Deflate,
                    1 => Squeezed::Zstd,
                    _ => return Err(Error::Needs(Unsupported::Feature)),
                };
            }
            if squeezed == Squeezed::Zstd && !cfg!(feature = "zstd") {
                return Err(Error::Needs(Unsupported::Zstd));
            }
        }
        // Each table of the second level is a cluster of entries of eight
        // bytes, and the first level has one entry for each of those.
        let l2_entries = cluster / 8;
        let wanted = size.div_ceil(cluster * l2_entries);
        let l1_size = u64::from(be32(&head, 36));
        if l1_size < wanted || l1_size > MOST_L1 {
            return Err(Error::Qcow2Says);
        }
        let l1_at = be64(&head, 40);
        let room = l1_size * 8;
        if l1_at == 0
            || !l1_at.is_multiple_of(cluster)
            || l1_at.checked_add(room).is_none_or(|end| end > whole)
        {
            return Err(Error::Qcow2Says);
        }
        let mut raw = vec![0u8; room as usize];
        inner.read_exact_at(l1_at, &mut raw)?;
        let l1 = raw
            .as_chunks::<8>()
            .0
            .iter()
            .map(|eight| u64::from_be_bytes(*eight))
            .collect();
        Ok(Qcow2 {
            inner,
            size,
            cluster,
            cluster_bits,
            l2_entries,
            l1,
            squeezed,
            zeroes_by_bit,
        })
    }

    /// How long the disk is.
    pub fn disk_size(&self) -> u64 {
        self.size
    }

    /// What the entry for the cluster holding the `at` byte of the disk
    /// says. Read when it is wanted: eight bytes, and nothing is kept, as
    /// what reads an image reads it in order.
    fn entry(&self, at: u64) -> io::Result<u64> {
        let cluster = at >> self.cluster_bits;
        let (first, second) = (cluster / self.l2_entries, cluster % self.l2_entries);
        let Some(l1) = self.l1.get(first as usize).copied() else {
            return Ok(0);
        };
        let l2_at = l1 & OFFSET;
        if l2_at == 0 {
            return Ok(0);
        }
        let mut raw = [0u8; 8];
        self.inner.read_exact_at(l2_at + second * 8, &mut raw)?;
        Ok(u64::from_be_bytes(raw))
    }

    /// Where a compressed cluster's bytes are: from where the entry says,
    /// to the end of the last sector it says they take. The offset is not
    /// aligned to anything, and the last sector is not full — it ends
    /// wherever a cluster of data has come out.
    fn squeezed_at(&self, entry: u64) -> (u64, u64) {
        let bits = 62 - (self.cluster_bits - 8);
        let at = entry & ((1 << bits) - 1);
        let sectors = (entry >> bits) & ((1 << (62 - bits)) - 1);
        let from = at / 512 * 512;
        (at, from + (sectors + 1) * 512 - at)
    }

    /// A compressed cluster, whole.
    fn squeezed_cluster(&self, entry: u64) -> io::Result<Vec<u8>> {
        let (at, room) = self.squeezed_at(entry);
        let mut packed = vec![0u8; room as usize];
        let read = self.inner.read_at(at, &mut packed)?;
        packed.truncate(read);
        let mut cluster = vec![0u8; self.cluster as usize];
        match self.squeezed {
            Squeezed::Deflate => {
                use crate::deflate::{InBuffer, Inflate, OutBuffer};

                let mut inflate = Inflate::new(-15)
                    .map_err(|_| io::Error::other("deflate could not be started"))?;
                let mut out = OutBuffer::new(&mut cluster);
                let mut input = InBuffer::new(&packed);
                // A cluster's worth of data is all that is wanted: the
                // stream is not read to its end, as the last sector it is
                // in holds whatever came after it, and a cluster full is
                // where QEMU stops too.
                let _ = inflate.inflate(&mut out, &mut input, crate::deflate::Flush::Finish);
                let done = out.pos;
                if done < cluster.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "a compressed cluster came out short",
                    ));
                }
            }
            Squeezed::Zstd => {
                #[cfg(feature = "zstd")]
                {
                    // The sectors the entry says a cluster takes are not
                    // the frame's own length: the last of them holds
                    // whatever came after it, and one frame is all that
                    // decompressing takes.
                    let frame = crate::zstd::find_frame_compressed_size(&packed).map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "a compressed cluster is not a Zstandard frame",
                        )
                    })?;
                    let done =
                        crate::zstd::decompress(&mut cluster, &packed[..frame]).map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "a compressed cluster could not be decompressed",
                            )
                        })?;
                    if done < cluster.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "a compressed cluster came out short",
                        ));
                    }
                }
                #[cfg(not(feature = "zstd"))]
                {
                    return Err(io::Error::other(
                        "a cluster is compressed with Zstandard, which this build leaves out",
                    ));
                }
            }
        }
        Ok(cluster)
    }
}

impl<D: Disk> Disk for Qcow2<D> {
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
            let into = at % self.cluster;
            // No read crosses a cluster: the next one is somewhere else in
            // the file, or nowhere.
            let take = (want - done).min((self.cluster - into) as usize);
            let entry = self.entry(at)?;
            let holds = entry & OFFSET;
            if entry & COMPRESSED != 0 {
                let cluster = self.squeezed_cluster(entry)?;
                let from = into as usize;
                buf[done..done + take].copy_from_slice(&cluster[from..from + take]);
            } else if holds == 0 || (self.zeroes_by_bit && entry & ZERO != 0) {
                // A cluster nothing was written to, or one the image says
                // reads as zeroes.
                buf[done..done + take].fill(0);
            } else {
                let read = self
                    .inner
                    .read_at(holds + into, &mut buf[done..done + take])?;
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the image ends inside a cluster its tables name",
                    ));
                }
                done += read;
                continue;
            }
            done += take;
        }
        Ok(done)
    }
}

/// Whether the entry says the cluster is only in this image: not read, as
/// what it answers is the same either way, and kept so that the bit is
/// named somewhere.
#[allow(dead_code)]
const fn only_here(entry: u64) -> bool {
    entry & COPIED != 0
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
