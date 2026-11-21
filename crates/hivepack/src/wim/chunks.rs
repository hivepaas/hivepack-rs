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

use std::io::{Read, Seek, SeekFrom};

use super::error::{Error, Unsupported};
use super::{Compression, Resource, le32, le64, xpress};

/// Where a chunk's entry says it begins, from the table's end.
fn entry(raw: &[u8], at: usize, wide: bool) -> u64 {
    if wide {
        le64(raw, at)
    } else {
        u64::from(le32(raw, at))
    }
}

/// A compressed resource read whole, `most` bytes of it at most.
///
/// Each chunk is read and decompressed on its own, as it was compressed:
/// nothing refers to the chunk before it, which is what lets a reader
/// reach one byte of a 4 GiB file without the rest.
pub(crate) fn read<R: Read + Seek>(
    reader: &mut R,
    resource: &Resource,
    whole: u64,
    compression: Compression,
    chunk: u32,
    most: u64,
) -> Result<Vec<u8>, Error> {
    // `read_resource` has already refused a compression with no decoder,
    // so what reaches here is one that has one.
    if resource.size > most {
        return Err(Error::TooMany);
    }
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

    let mut out = vec![0u8; usize::try_from(size).map_err(|_| Error::Resource)?];
    let mut decoder = xpress::Decoder::new();
    let mut packed = Vec::new();
    for i in 0..count {
        let from = bounds[i as usize];
        let to = bounds[i as usize + 1];
        let held = to - from;
        let at = (i * chunk) as usize;
        let holds = usize::try_from(chunk.min(size - i * chunk)).map_err(|_| Error::Resource)?;
        let into = &mut out[at..at + holds];

        let begins = resource
            .at
            .checked_add(table_bytes)
            .and_then(|at| at.checked_add(from))
            .ok_or(Error::Resource)?;
        if begins.checked_add(held).is_none_or(|end| end > whole) {
            return Err(Error::Resource);
        }
        packed.clear();
        packed.resize(usize::try_from(held).map_err(|_| Error::Resource)?, 0);
        reader.seek(SeekFrom::Start(begins))?;
        reader.read_exact(&mut packed)?;

        if held as usize == holds {
            // Compressing it did not pay, so it is held as it is.
            into.copy_from_slice(&packed);
            continue;
        }
        if held as usize > holds {
            // Longer compressed than it is uncompressed, which no chunk is.
            return Err(Error::Resource);
        }
        match compression {
            Compression::Xpress => xpress::decompress(&mut decoder, &packed, into)?,
            // `needs` has refused these above; this is here so that adding
            // a decoder is a change the compiler asks for.
            Compression::None => return Err(Error::Says),
            Compression::Lzx => return Err(Error::Needs(Unsupported::Lzx)),
            Compression::Lzms => return Err(Error::Needs(Unsupported::Lzms)),
        }
    }
    Ok(out)
}
