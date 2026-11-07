//! pbzx's chunks, each an xz stream of its own, decoded a chunk in each
//! thread.
//!
//! The input is read ahead a chunk at a time: its header gives its size and
//! the size of what stores it, so each chunk is cut where the file says,
//! never where the threads would. A stored chunk is given out as it is; a
//! compressed one goes to a thread, which decodes it into memory, and its
//! output is taken only when it is one xz stream that ends where the chunk
//! does and decompresses to exactly its size. Anything else (a header cut
//! short or larger than the block size, a stream that fails, an error of
//! the reader under) hands what is left, from that chunk's start, to the
//! decoder of one thread, which reads it as it would have: the same data,
//! the same error.
//!
//! What it holds is bounded by `Limits::xz_memlimit`, or by less where an
//! extraction says (`Opener::threads_memory`): each chunk in flight counts
//! what stores it, what it decodes to and what its decoder needs, as
//! liblzma counts it, and a chunk that would go past the bound waits for
//! those before it. A chunk that alone would go past is read by one thread,
//! with all that follows.

use std::collections::VecDeque;
use std::io::{self, Cursor, Read};
use std::sync::Arc;

use crate::bzip2::mt::{Pending, Pool};
use crate::open::bzip2_threads::Rest;
use crate::open::decode::{Decoder, PBZX_CHUNK_HEADER, PBZX_HEADER, PbzxCodec, be64};
use crate::open::detect::Layer;
use crate::xz::{Action, InBuffer, OutBuffer, Status, Stream};

/// What the input is read in, beyond what a chunk needs.
const READ: usize = 256 << 10;

/// What is read of a compressed chunk before it is read whole, to tell
/// what its decoder needs: its Stream Header and first Block Header.
const PEEK: usize = 12 + 1024;

/// A chunk's data, once read.
enum Data {
    /// Stored as it is: given out as it is.
    Stored,
    /// An xz stream, decoded in a thread: what it decodes to, or none when
    /// one thread reads it.
    Xz(Pending<Option<Vec<u8>>>),
}

/// A chunk in flight.
struct Chunk {
    /// Its header and what stores it, as read.
    bytes: Arc<Vec<u8>>,
    /// What it holds, against the limit.
    cost: u64,
    data: Data,
}

/// What the next chunk does.
enum Next {
    /// It is in flight.
    Given,
    /// It waits for room under the limit.
    Wait,
    /// No more chunks: the rest is one thread's.
    Stop,
}

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

/// One thread's decoder, over what is left.
type Serial<R> = Decoder<io::Chain<Cursor<Vec<u8>>, Rest<R>>, PbzxCodec>;

/// pbzx's decoder in threads.
pub(super) struct PbzxThreads<R> {
    /// The reader under, until one thread reads the rest.
    inner: Option<R>,
    pool: Pool,
    /// The chunks in flight at most.
    in_flight: usize,
    /// What each chunk's decoder may use, as with one thread.
    xz_memlimit: u64,
    /// What the chunks in flight may hold.
    memory: u64,
    /// The block size, once the file's header is read.
    block: Option<u64>,
    /// What is read and in no chunk yet: from a chunk's start, or from the
    /// file's before its header is read.
    read: Vec<u8>,
    eof: bool,
    /// The error the reader under gave, after `read`.
    error: Option<io::Error>,
    /// No more chunks: the rest, `read` and after, is one thread's.
    stopped: bool,
    chunks: VecDeque<Chunk>,
    /// What the chunks in flight and the one being read out hold.
    held: u64,
    /// The oldest chunk's data, being read out, from `out_pos` to `out_end`.
    out: Arc<Vec<u8>>,
    out_pos: usize,
    out_end: usize,
    /// What that chunk holds.
    out_cost: u64,
    serial: Option<Serial<R>>,
}

impl<R: Read> PbzxThreads<R> {
    /// Over `inner`, in `threads` threads, each decoder under `xz_memlimit`
    /// and the chunks in flight holding `memory` at most.
    pub(super) fn new(inner: R, threads: u32, xz_memlimit: u64, memory: u64) -> PbzxThreads<R> {
        let threads = usize::try_from(threads).unwrap_or(usize::MAX);
        PbzxThreads {
            inner: Some(inner),
            pool: Pool::named(threads, "hivepack-pbzx"),
            in_flight: threads.saturating_mul(2),
            xz_memlimit,
            memory,
            block: None,
            read: Vec::new(),
            eof: false,
            error: None,
            stopped: false,
            chunks: VecDeque::new(),
            held: 0,
            out: Arc::default(),
            out_pos: 0,
            out_end: 0,
            out_cost: 0,
            serial: None,
        }
    }

    /// At least `want` bytes read, unless the reader under ends or fails
    /// first: whether they are.
    fn read_to(&mut self, want: usize) -> bool {
        while self.read.len() < want {
            if self.eof || self.error.is_some() {
                return false;
            }
            let Some(inner) = &mut self.inner else {
                return false;
            };
            let len = self.read.len();
            self.read.resize(want.max(len + READ), 0);
            let result = loop {
                match inner.read(&mut self.read[len..]) {
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    result => break result,
                }
            };
            match result {
                Ok(n) => {
                    self.read.truncate(len + n);
                    self.eof = n == 0;
                }
                Err(e) => {
                    self.read.truncate(len);
                    self.error = Some(e);
                }
            }
        }
        true
    }

    /// Whether a chunk holding `cost` more waits for room: one alone never
    /// does.
    fn waits(&self, cost: u64) -> bool {
        !self.chunks.is_empty() && self.held.saturating_add(cost) > self.memory
    }

    /// Chunks given to the threads, as many as may be in flight and fit
    /// the limit, unless the input stops first.
    fn fill(&mut self) {
        while self.chunks.len() < self.in_flight && !self.stopped {
            match self.next_chunk() {
                Next::Given => {}
                Next::Wait => return,
                Next::Stop => self.stopped = true,
            }
        }
    }

    /// The next chunk read and given to a thread, if it can be.
    fn next_chunk(&mut self) -> Next {
        let block = match self.block {
            Some(block) => block,
            None => {
                if !self.read_to(PBZX_HEADER) || !self.read.starts_with(b"pbzx") {
                    return Next::Stop;
                }
                let block = be64(&self.read[4..PBZX_HEADER]);
                self.read.drain(..PBZX_HEADER);
                self.block = Some(block);
                block
            }
        };
        if !self.read_to(PBZX_CHUNK_HEADER) {
            return Next::Stop;
        }
        let size = be64(&self.read[..8]);
        let stored = be64(&self.read[8..PBZX_CHUNK_HEADER]);
        if size > block || stored > block {
            return Next::Stop;
        }
        let Some(end) = usize::try_from(stored)
            .ok()
            .and_then(|n| n.checked_add(PBZX_CHUNK_HEADER))
        else {
            return Next::Stop;
        };
        let (cost, decoder) = if stored == size {
            (stored, None)
        } else {
            // What its decoder needs, from the start of its stream.
            if !self.read_to(end.min(PBZX_CHUNK_HEADER + PEEK)) {
                return Next::Stop;
            }
            let peek = &self.read[PBZX_CHUNK_HEADER..end.min(self.read.len())];
            let Some(decoder) = crate::xz::first_block_memusage(peek) else {
                return Next::Stop;
            };
            // Past its limit: one thread says so.
            if decoder > self.xz_memlimit {
                return Next::Stop;
            }
            let cost = stored.saturating_add(size).saturating_add(decoder);
            (cost, Some(decoder))
        };
        if cost > self.memory {
            return Next::Stop;
        }
        if self.waits(cost) {
            return Next::Wait;
        }
        if !self.read_to(end) {
            return Next::Stop;
        }
        // Its own bytes, no more, and what was read after kept.
        let after = self.read.split_off(end);
        let bytes = Arc::new(std::mem::replace(&mut self.read, after));
        let data = match decoder {
            None => Data::Stored,
            Some(memlimit) => {
                let given = Arc::clone(&bytes);
                Data::Xz(
                    self.pool
                        .run(move || decode_chunk(&given[PBZX_CHUNK_HEADER..], size, memlimit)),
                )
            }
        };
        self.held += cost;
        self.chunks.push_back(Chunk { bytes, cost, data });
        Next::Given
    }

    /// One thread reads the rest, from `from`, as it would have.
    fn serial(&mut self, from: &[u8]) -> Option<&mut Serial<R>> {
        let inner = self.inner.take()?;
        let chunks: usize = self.chunks.iter().map(|chunk| chunk.bytes.len()).sum();
        let mut rest = Vec::with_capacity(from.len() + chunks + self.read.len());
        rest.extend_from_slice(from);
        for chunk in self.chunks.drain(..) {
            rest.extend_from_slice(&chunk.bytes);
        }
        rest.append(&mut self.read);
        self.stopped = true;
        // The chunks given and not started are not decoded.
        self.pool = Pool::new(1);
        let after = Rest::new(self.error.take(), inner, self.eof);
        let codec = match self.block {
            Some(block) => PbzxCodec::within(self.xz_memlimit, block),
            None => PbzxCodec::new(self.xz_memlimit),
        };
        let reader = Cursor::new(rest).chain(after);
        self.serial = Some(Decoder::new(reader, codec, Layer::Pbzx));
        self.serial.as_mut()
    }
}

impl<R: Read> Read for PbzxThreads<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(serial) = &mut self.serial {
                return serial.read(buf);
            }
            if self.out_pos < self.out_end {
                let n = buf.len().min(self.out_end - self.out_pos);
                buf[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
                self.out_pos += n;
                return Ok(n);
            }
            if buf.is_empty() {
                return Ok(0);
            }
            self.out = Arc::default();
            self.held -= std::mem::take(&mut self.out_cost);
            self.fill();
            let Some(chunk) = self.chunks.pop_front() else {
                // At a chunk's start, at the end, as one thread ends.
                if self.block.is_some() && self.read.is_empty() && self.eof && self.error.is_none()
                {
                    return Ok(0);
                }
                return match self.serial(&[]) {
                    Some(serial) => serial.read(buf),
                    None => Ok(0),
                };
            };
            self.out_cost = chunk.cost;
            match chunk.data {
                Data::Stored => {
                    self.out_end = chunk.bytes.len();
                    self.out_pos = PBZX_CHUNK_HEADER;
                    self.out = chunk.bytes;
                }
                Data::Xz(pending) => match pending.wait() {
                    Some(out) => {
                        self.out_end = out.len();
                        self.out_pos = 0;
                        self.out = Arc::new(out);
                    }
                    None => {
                        return match self.serial(&chunk.bytes) {
                            Some(serial) => serial.read(buf),
                            None => Ok(0),
                        };
                    }
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
        read_all(PbzxThreads::new(file, threads, memlimit, memlimit))
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
        let mut reader = PbzxThreads::new(&file[..], 3, 1 << 30, 1 << 30);
        assert!(read_all(&mut reader) == (data.clone(), None));
        assert!(reader.serial.is_none());
        // Room for one chunk at a time, or for none: one thread reads them.
        for memory in [2 << 20, 1 << 10] {
            let reader = PbzxThreads::new(&file[..], 4, 1 << 30, memory);
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
        assert!(read_all(PbzxThreads::new(Failing(cut), 3, 1 << 30, 1 << 30)) == alone);
    }
}
