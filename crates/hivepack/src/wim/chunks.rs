//! A compressed resource, which is not one compressed stream but a run of
//! chunks with a table of where each begins.
//!
//! **Measured, not read off a specification.** Microsoft's 2007 *Windows
//! Imaging File Format (WIM)* paper is not published on its own site any
//! more, and the copies that are about are other people's, so the layout
//! here was taken off what `wimlib-imagex` writes and every number is
//! checked against it — the same way `image::Vdi` is held to `qemu-img`.
//! What was measured, on a 140000-byte file in chunks of 32768:
//!
//! ```text
//! size=140000 packed=41124 chunks=5          (chunks = ceil(size / chunk))
//! table = 4 entries of 4 bytes               (one for every chunk but the first)
//! table = [32768, 40283, 40558, 40833]       (each the offset of a chunk,
//!                                             counted from the table's end)
//!   chunk 0: 32768 <- 32768 bytes   stored, since compressing it did not pay
//!   chunk 1:   7515 <- 32768 bytes   XPRESS
//!   chunk 2:    275 <- 32768 bytes   XPRESS
//!   chunk 3:    275 <- 32768 bytes   XPRESS
//!   chunk 4:    275 <-  8928 bytes   XPRESS, the last one holding the rest
//! ```
//!
//! So a chunk's compressed length is the gap between its offset and the
//! next one's, the last reaching the end of the resource, and **a chunk
//! whose compressed length equals its uncompressed length is held as it
//! is** rather than compressed. An entry is four bytes, or eight where the
//! resource holds more than 4 GiB.
//!
//! **A resource is read as a stream of its chunks** ([`Reading`]): one is
//! decompressed as it is reached and given out, so a file of any length is
//! read through a buffer of one chunk rather than one of the file. `read`
//! is that reader read through, for a resource that is to be held whole —
//! an image's metadata, which is the tree itself.

use std::io::{self, Read, Seek, SeekFrom};

use super::error::{Error, Unsupported};
use super::{Compression, Resource, le32, le64, lzx, xpress};

/// The decoder a compression needs, built when a chunk is really
/// compressed rather than for the resource: one of stored chunks needs
/// none, and an archive whose chunk size no decoder can take still reads
/// the chunks it stored.
enum Decoder {
    Xpress(xpress::Decoder),
    Lzx(lzx::Decoder),
}

impl Decoder {
    fn new(compression: Compression, chunk: u64) -> Result<Decoder, Error> {
        match compression {
            Compression::Xpress => Ok(Decoder::Xpress(xpress::Decoder::new())),
            Compression::Lzx => Ok(Decoder::Lzx(lzx::Decoder::new(chunk)?)),
            // `read_resource` has refused these above; they are here so
            // that adding a decoder is a change the compiler asks for.
            Compression::None => Err(Error::Says),
            Compression::Lzms => Err(Error::Needs(Unsupported::Lzms)),
        }
    }

    fn decompress(&mut self, packed: &[u8], into: &mut [u8]) -> Result<(), Error> {
        match self {
            Decoder::Xpress(decoder) => xpress::decompress(decoder, packed, into),
            Decoder::Lzx(decoder) => decoder.decompress(packed, into),
        }
    }
}

/// Where a chunk's entry says it begins, from the table's end.
fn entry(raw: &[u8], at: usize, wide: bool) -> u64 {
    if wide {
        le64(raw, at)
    } else {
        u64::from(le32(raw, at))
    }
}

/// Where the chunks of one resource are, read from its table: every
/// chunk's beginning, the end of the last one after them, and where the
/// first begins on the file.
struct Chunks {
    /// One more than the chunks: each chunk's start, counted from the
    /// first chunk's own start, and the data's end last of all.
    bounds: Vec<u64>,
    /// Where the first chunk begins on the file.
    at: u64,
    /// How many bytes each chunk holds, uncompressed. The last holds the
    /// rest.
    each: u64,
    /// How long the resource is, uncompressed.
    size: u64,
}

/// Reads the table of chunks of `resource` and says where each one is.
fn chunks_of<R: Read + Seek>(
    reader: &mut R,
    resource: &Resource,
    whole: u64,
    chunk: u32,
) -> Result<Chunks, Error> {
    let chunk = u64::from(chunk);
    if chunk == 0 {
        // A compressed resource in an archive whose header says no chunks
        // at all: its own flags and its header disagree.
        return Err(Error::Says);
    }
    let size = resource.size;
    let count = size.div_ceil(chunk);
    // The table holds every chunk's beginning but the first, which is
    // always the table's own end.
    let wide = size > u64::from(u32::MAX);
    let each = if wide { 8 } else { 4 };
    let table_bytes = count.saturating_sub(1).saturating_mul(each);
    if table_bytes > resource.packed {
        return Err(Error::Resource);
    }
    let data = resource.packed - table_bytes;

    reader.seek(SeekFrom::Start(resource.at))?;
    let mut table = vec![0u8; usize::try_from(table_bytes).map_err(|_| Error::Resource)?];
    reader.read_exact(&mut table)?;

    // Where each chunk begins and ends, counted from the data's start.
    let mut bounds = Vec::with_capacity(count as usize + 1);
    bounds.push(0u64);
    for i in 0..count.saturating_sub(1) {
        let at = entry(&table, (i * each) as usize, wide);
        if at < *bounds.last().unwrap_or(&0) || at > data {
            // Chunks that do not follow one another, or reach past the
            // resource: the table is not one.
            return Err(Error::Resource);
        }
        bounds.push(at);
    }
    bounds.push(data);

    let at = resource
        .at
        .checked_add(table_bytes)
        .filter(|at| at.checked_add(data).is_some_and(|end| end <= whole))
        .ok_or(Error::Resource)?;
    Ok(Chunks {
        bounds,
        at,
        each: chunk,
        size,
    })
}

/// A compressed resource read as a stream: its chunks in order, each
/// decompressed as it is reached.
///
/// **One chunk is held, not the file.** A chunk holds what the header says
/// (32768 bytes, or what the archive was written with), so a 4 GiB file in
/// an image is read through a buffer of that size, and the reader never
/// has to hold the file itself.
pub(crate) struct Reading<'a, R> {
    reader: &'a mut R,
    compression: Compression,
    chunks: Chunks,
    /// Which chunk comes next.
    next: u64,
    /// Built when a chunk is really compressed: see [`Decoder`].
    decoder: Option<Decoder>,
    /// The chunk now held, and how much of it has been given out.
    held: Vec<u8>,
    given: usize,
    /// What a chunk's compressed bytes are read into, kept between chunks.
    packed: Vec<u8>,
    /// How much of the resource is still to come.
    left: u64,
}

impl<'a, R: Read + Seek> Reading<'a, R> {
    /// The resource in `reader`, to be read from its start.
    pub(crate) fn new(
        reader: &'a mut R,
        resource: &Resource,
        whole: u64,
        compression: Compression,
        chunk: u32,
    ) -> Result<Reading<'a, R>, Error> {
        let chunks = chunks_of(reader, resource, whole, chunk)?;
        let left = chunks.size;
        Ok(Reading {
            reader,
            compression,
            chunks,
            next: 0,
            decoder: None,
            held: Vec::new(),
            given: 0,
            packed: Vec::new(),
            left,
        })
    }

    /// The next bytes of the resource into `buf`, and 0 once it is whole.
    pub(crate) fn pull(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.given == self.held.len() {
            if self.left == 0 {
                return Ok(0);
            }
            self.fill()?;
        }
        let take = buf.len().min(self.held.len() - self.given);
        buf[..take].copy_from_slice(&self.held[self.given..self.given + take]);
        self.given += take;
        self.left -= take as u64;
        Ok(take)
    }

    /// Reads the next chunk, decompressed where it is compressed.
    ///
    /// Each chunk is read and decompressed on its own, as it was
    /// compressed: nothing refers to the chunk before it, which is what
    /// lets a reader reach one byte of a 4 GiB file without the rest.
    fn fill(&mut self) -> Result<(), Error> {
        let i = self.next;
        let chunks = &self.chunks;
        let (Some(&from), Some(&to)) = (
            chunks.bounds.get(i as usize),
            chunks.bounds.get(i as usize + 1),
        ) else {
            // The chunks are read through and the resource is not whole:
            // its own numbers disagree.
            return Err(Error::Resource);
        };
        let held = to - from;
        let holds = usize::try_from(chunks.each.min(chunks.size - i * chunks.each))
            .map_err(|_| Error::Resource)?;
        self.packed.clear();
        self.packed
            .resize(usize::try_from(held).map_err(|_| Error::Resource)?, 0);
        self.reader.seek(SeekFrom::Start(chunks.at + from))?;
        self.reader.read_exact(&mut self.packed)?;

        self.held.clear();
        self.held.resize(holds, 0);
        self.given = 0;
        self.next += 1;
        if held as usize == holds {
            // Compressing it did not pay, so it is held as it is.
            self.held.copy_from_slice(&self.packed);
            return Ok(());
        }
        if held as usize > holds {
            // Longer compressed than it is uncompressed, which no chunk is.
            return Err(Error::Resource);
        }
        let each = chunks.each;
        let decoder = match self.decoder {
            Some(ref mut decoder) => decoder,
            None => self.decoder.insert(Decoder::new(self.compression, each)?),
        };
        decoder.decompress(&self.packed, &mut self.held)
    }
}

impl<R: Read + Seek> Read for Reading<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.pull(buf).map_err(io::Error::from)
    }
}
