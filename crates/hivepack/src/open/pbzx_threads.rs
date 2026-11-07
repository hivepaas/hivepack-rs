//! pbzx's chunks, each an xz stream of its own, decoded a chunk in each
//! thread ([`Threaded`]).
//!
//! Each chunk's header gives its size and the size of what stores it, so
//! the input is cut where the file says. A stored chunk is given out as it
//! is; a compressed one goes to a thread, which decodes it into memory, and
//! its output is taken only when it is one xz stream that ends where the
//! chunk does and decompresses to exactly its size. Anything else (a header
//! cut short or larger than the block size, a stream that fails, an error
//! of the reader under) hands what is left, from that chunk's start, to the
//! decoder of one thread, which reads it as it would have.
//!
//! What it holds is bounded by `Limits::xz_memlimit`, or by less where an
//! extraction says (`Opener::threads_memory`): each chunk in flight counts
//! what stores it, what it decodes to and what its decoder needs, as
//! liblzma counts it.

use std::io::Read;
use std::sync::Arc;

use crate::open::decode::{Decoder, PBZX_CHUNK_HEADER, PBZX_HEADER, PbzxCodec, be64};
use crate::open::detect::Layer;
use crate::open::pieces::{Left, Pieces, Plan, Threaded, Work};
use crate::xz::{Action, InBuffer, OutBuffer, Status, Stream};

/// What is read of a compressed chunk before it is read whole, to tell
/// what its decoder needs: its Stream Header and first Block Header.
const PEEK: usize = 12 + 1024;

/// What a thread does with a compressed chunk: `stored`, an xz stream that
/// decompresses to `size`, decoded under `memlimit`, if it is that.
fn decode_chunk(stored: &[u8], size: u64, memlimit: u64) -> Option<Vec<u8>> {
    let mut s = Stream::stream_decoder(memlimit, 0).ok()?;
    // A byte more, to tell a stream that decompresses to more.
    let mut out = vec![0; usize::try_from(size).ok()?.checked_add(1)?];
    let mut input = InBuffer::new(stored);
    let mut output = OutBuffer::new(&mut out);
    loop {
        let (read, written) = (input.pos, output.pos);
        match s.code(&mut output, &mut input, Action::Finish) {
            Ok(Status::StreamEnd) => break,
            Ok(_) if input.pos == read && output.pos == written => return None,
            Ok(_) => {}
            Err(_) => return None,
        }
    }
    let (read, written) = (input.pos, output.pos);
    if read != stored.len() || written as u64 != size {
        return None;
    }
    out.truncate(written);
    Some(out)
}

/// pbzx, cut into its header and chunks.
#[derive(Clone)]
pub(super) struct Pbzx {
    /// What each chunk's decoder may use, as with one thread.
    xz_memlimit: u64,
    /// The block size, once the file's header is taken.
    block: Option<u64>,
}

impl Pbzx {
    /// A chunk's size and the size of what stores it, from its header.
    fn sizes(header: &[u8]) -> (u64, u64) {
        (be64(&header[..8]), be64(&header[8..PBZX_CHUNK_HEADER]))
    }
}

impl Pieces for Pbzx {
    fn plan(&self, read: &[u8]) -> Plan {
        let Some(block) = self.block else {
            if read.len() < PBZX_HEADER {
                return Plan::Need(PBZX_HEADER);
            }
            if !read.starts_with(b"pbzx") {
                return Plan::Stop;
            }
            return Plan::Piece {
                len: PBZX_HEADER,
                cost: 0,
            };
        };
        if read.len() < PBZX_CHUNK_HEADER {
            return Plan::Need(PBZX_CHUNK_HEADER);
        }
        let (size, stored) = Pbzx::sizes(read);
        if size > block || stored > block {
            return Plan::Stop;
        }
        let Some(len) = usize::try_from(stored)
            .ok()
            .and_then(|n| n.checked_add(PBZX_CHUNK_HEADER))
        else {
            return Plan::Stop;
        };
        if stored == size {
            return Plan::Piece { len, cost: stored };
        }
        // What its decoder needs, from the start of its stream.
        let peek = len.min(PBZX_CHUNK_HEADER + PEEK);
        if read.len() < peek {
            return Plan::Need(peek);
        }
        let stream = &read[PBZX_CHUNK_HEADER..len.min(read.len())];
        match crate::xz::first_block_memusage(stream) {
            // Past its limit: one thread says so.
            Some(decoder) if decoder <= self.xz_memlimit => Plan::Piece {
                len,
                cost: stored.saturating_add(size).saturating_add(decoder),
            },
            _ => Plan::Stop,
        }
    }

    fn take(&mut self, bytes: &Arc<Vec<u8>>) -> Work {
        if self.block.is_none() {
            self.block = Some(be64(&bytes[4..PBZX_HEADER]));
            return Work::Nothing;
        }
        let (size, stored) = Pbzx::sizes(bytes);
        if stored == size {
            return Work::Stored(PBZX_CHUNK_HEADER);
        }
        let memlimit = crate::xz::first_block_memusage(&bytes[PBZX_CHUNK_HEADER..])
            .unwrap_or(self.xz_memlimit);
        let bytes = Arc::clone(bytes);
        Work::Decode(Box::new(move || {
            decode_chunk(&bytes[PBZX_CHUNK_HEADER..], size, memlimit)
        }))
    }

    fn may_end(&self) -> bool {
        self.block.is_some()
    }

    fn serial<'a, R: Read + Send + 'a>(&self, left: Left<R>) -> Box<dyn Read + Send + 'a> {
        let codec = match self.block {
            Some(block) => PbzxCodec::within(self.xz_memlimit, block),
            None => PbzxCodec::new(self.xz_memlimit),
        };
        Box::new(Decoder::new(left, codec, Layer::Pbzx))
    }
}

/// pbzx over `inner`, in `threads` threads, each decoder under
/// `xz_memlimit` and the chunks in flight holding `memory` at most.
pub(super) fn pbzx_threads<'a, R: Read + Send + 'a>(
    inner: R,
    threads: u32,
    xz_memlimit: u64,
    memory: u64,
) -> Threaded<'a, R, Pbzx> {
    let format = Pbzx {
        xz_memlimit,
        block: None,
    };
    Threaded::new(inner, format, threads, memory, "hivepack-pbzx")
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;
    use crate::xz::Check;

    fn xz(data: &[u8]) -> Vec<u8> {
        let mut s = Stream::easy_encoder(1, Check::NONE).unwrap();
        let mut out = vec![0; data.len() + 1024];
        let mut input = InBuffer::new(data);
        let mut output = OutBuffer::new(&mut out);
        assert!(s.code(&mut output, &mut input, Action::Finish).unwrap() == Status::StreamEnd);
        let n = output.pos;
        out.truncate(n);
        out
    }

    fn chunk(size: u64, stored: &[u8]) -> Vec<u8> {
        let mut chunk = size.to_be_bytes().to_vec();
        chunk.extend((stored.len() as u64).to_be_bytes());
        chunk.extend(stored);
        chunk
    }

    fn file(block: u64, chunks: &[Vec<u8>]) -> Vec<u8> {
        let mut file = b"pbzx".to_vec();
        file.extend(block.to_be_bytes());
        file.extend(chunks.concat());
        file
    }

    fn text(len: usize) -> Vec<u8> {
        let mut seed = 7u32;
        (0..len)
            .map(|_| {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
                b"abcdefgh  \n"[(seed >> 16) as usize % 11]
            })
            .collect()
    }

    /// A file of `data`, every `cut` bytes a chunk, compressed or, each
    /// third, stored.
    fn pbzx(data: &[u8], cut: usize) -> Vec<u8> {
        let chunks: Vec<_> = data
            .chunks(cut)
            .enumerate()
            .map(|(i, c)| {
                if i % 3 == 2 {
                    chunk(c.len() as u64, c)
                } else {
                    chunk(c.len() as u64, &xz(c))
                }
            })
            .collect();
        file(cut as u64, &chunks)
    }

    /// What `reader` reads to, in pieces, and the error's message.
    fn read_all(mut reader: impl Read) -> (Vec<u8>, Option<String>) {
        let mut data = Vec::new();
        let mut piece = vec![0; 1000];
        loop {
            match reader.read(&mut piece) {
                Ok(0) => return (data, None),
                Ok(n) => data.extend(&piece[..n]),
                Err(e) => return (data, Some(e.to_string())),
            }
        }
    }

    fn one(file: &[u8], memlimit: u64) -> (Vec<u8>, Option<String>) {
        let codec = PbzxCodec::new(memlimit);
        read_all(Decoder::new(file, codec, Layer::Pbzx))
    }

    fn threads(file: &[u8], threads: u32, memlimit: u64) -> (Vec<u8>, Option<String>) {
        read_all(pbzx_threads(file, threads, memlimit, memlimit))
    }

    #[test]
    fn chunks_come_out_as_one_thread_reads_them() {
        let data = text(200_000);
        let file = pbzx(&data, 16 << 10);
        assert!(one(&file, 1 << 30) == (data.clone(), None));
        for n in [2, 5] {
            assert!(threads(&file, n, 1 << 30) == (data.clone(), None));
        }
        // Every chunk taken from the threads, none read by one.
        let mut reader = pbzx_threads(&file[..], 3, 1 << 30, 1 << 30);
        assert!(read_all(&mut reader) == (data.clone(), None));
        assert!(!reader.is_serial());
        // Room for one chunk at a time, or for none: one thread reads them.
        for memory in [2 << 20, 1 << 10] {
            let reader = pbzx_threads(&file[..], 4, 1 << 30, memory);
            assert!(read_all(reader) == (data.clone(), None));
        }
    }

    #[test]
    fn damage_anywhere_comes_out_as_one_thread_reads_it() {
        let file = pbzx(&text(60_000), 8 << 10);
        let step = (file.len() / 40).max(1);
        for at in (0..file.len()).step_by(step) {
            let mut damaged = file.clone();
            damaged[at] ^= 0x5A;
            assert!(
                threads(&damaged, 3, 1 << 30) == one(&damaged, 1 << 30),
                "{at}"
            );
        }
        for len in (0..file.len()).step_by(step) {
            let cut = &file[..len];
            assert!(threads(cut, 3, 1 << 30) == one(cut, 1 << 30), "{len}");
        }
        let mut after = file.clone();
        after.push(0);
        assert!(threads(&after, 3, 1 << 30) == one(&after, 1 << 30));
        // A limit that one decoder does not fit.
        assert!(threads(&file, 3, 4 << 10) == one(&file, 4 << 10));
        assert!(one(&file, 4 << 10).1.is_some());
    }

    #[test]
    fn an_error_of_the_reader_under_comes_where_one_thread_meets_it() {
        struct Failing<'a>(&'a [u8]);
        impl Read for Failing<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.0.is_empty() {
                    return Err(io::Error::other("the disk is gone"));
                }
                let n = buf.len().min(self.0.len()).min(700);
                buf[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        let file = pbzx(&text(50_000), 8 << 10);
        let cut = &file[..file.len() * 2 / 3];
        let codec = PbzxCodec::new(1 << 30);
        let alone = read_all(Decoder::new(Failing(cut), codec, Layer::Pbzx));
        assert!(alone.1.as_deref() == Some("the disk is gone"));
        assert!(read_all(pbzx_threads(Failing(cut), 3, 1 << 30, 1 << 30)) == alone);
    }
}
