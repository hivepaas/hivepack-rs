//! bzip2 streams one after the other, as pbzip2 and
//! [`CompressMt`](crate::bzip2::CompressMt) write them, decoded a stream
//! in each thread.
//!
//! The input is read ahead for where streams start: `BZh`, a block size
//! from `1` to `9`, then a block's magic (`0x314159265359`) or the end's
//! (`0x177245385090`, a stream of nothing), all on a byte. Each piece from
//! one such start to the next goes to a thread, which decodes it into
//! memory. Those bytes can also turn up inside a stream's data, so a
//! piece's output is taken only when it is exactly one stream that ends
//! exactly where the piece does: then one thread reads what the threads
//! read, the next stream starting where this one ends. A piece that ends
//! inside its stream is joined with the next and decoded again. Anything
//! else (an error, a stream that ends before the piece does, a stream too
//! large to hold) hands what is left, from that piece's start, to the
//! decoder of one thread, which reads it as it would have and gives the
//! same data and the same error.
//!
//! A stream larger than a piece, as `bzip2` writes a file, is decoded a
//! block in each thread instead ([`BlockThreads`]): its blocks' magic is
//! found on any bit, each block from one magic to the next goes to a
//! thread, which decodes it as the decoder of one thread would from there,
//! and its output is taken only if it ends exactly where the next block
//! starts. Anything else hands the rest, from that block's start, to the
//! decoder of one thread, made where that one would be.
//!
//! What it holds is bounded by the constants below, [`memory_usage`] of
//! them, and `Limits::bzip2_memlimit` lowers the threads to fit it.

use std::collections::VecDeque;
use std::io::{self, Cursor, Read};
use std::sync::Arc;

use crate::bzip2::mt::{Pending, Pool};
use crate::bzip2::{Decompress, InBuffer, OutBuffer, Status};
use crate::open::decode::{Bzip2Codec, Decoder};
use crate::open::detect::Layer;

/// The most compressed bytes a piece may have; a stream that does not end
/// within them is read on the caller's thread with all that follows. A
/// stream of one block at block size 9 is about 910 KB at most.
const MAX_PIECE: usize = 2 << 20;

/// The most a piece may decode to in a thread: a stream of the pieces
/// of [`CompressMt`](crate::bzip2::CompressMt) and pbzip2 decodes to 900
/// KB at most.
const MAX_OUTPUT: usize = 4 << 20;

/// The most a block of a stream decodes to: 900,000 symbols at block size
/// 9, the most as runs of four bytes and their count, each five giving 255
/// bytes, 45.9 MB. A block of [`BlockThreads`] past [`MAX_OUTPUT`] is decoded
/// on the caller's thread, within this.
const MAX_BLOCK_OUTPUT: usize = 46 << 20;

/// What the input is read in.
const READ: usize = 256 << 10;

/// `BZh`, the block size, and the magic after it.
const START_LEN: usize = 10;

/// The most bytes the decoder takes in `threads` threads, two pieces in
/// flight for each: for each piece, what was read (twice, while the rest
/// goes to one thread) and what it decodes to; for each thread, a decoder;
/// and what is read and not in a piece, the output being read (a block's
/// whole where it is decoded on the caller's thread), and the decoder of one
/// thread that may take what is left.
pub(super) fn memory_usage(threads: u32) -> u64 {
    let threads = u64::from(threads);
    let decoder = crate::bzip2::decompress_memory();
    let read = (MAX_PIECE + READ) as u64;
    let piece = 2 * read + MAX_OUTPUT as u64;
    threads * (2 * piece + decoder) + 2 * read + MAX_BLOCK_OUTPUT as u64 + decoder + (1 << 20)
}

/// The threads to decode in, at most `threads`, whose [`memory_usage`] fits
/// `limit`: one, the decoder of one thread, if no more than one does.
pub(super) fn threads_within(threads: u32, limit: u64) -> u32 {
    let mut threads = threads.max(1);
    while threads > 1 && memory_usage(threads) > limit {
        threads -= 1;
    }
    threads
}

/// What a thread made of a piece.
enum Outcome {
    /// One stream, ending where the piece does: its data.
    Stream(Vec<u8>),
    /// A stream that goes on after the piece.
    Short,
    /// Anything else: one thread reads it.
    Other,
}

/// A piece of the input, from a stream's start.
struct Piece {
    data: Arc<Vec<u8>>,
    /// Nothing follows it.
    last: bool,
    outcome: Pending<Outcome>,
}

/// What a thread does with a piece: `last` when nothing follows it.
fn decode_piece(data: &[u8], last: bool) -> Outcome {
    let mut d = Decompress::new(false);
    let mut input = InBuffer::new(data);
    let mut out = vec![0; data.len().saturating_mul(4).clamp(1 << 16, MAX_OUTPUT)];
    let mut written = 0;
    loop {
        let mut output = OutBuffer {
            dst: &mut out,
            pos: written,
        };
        let result = d.decompress(&mut output, &mut input);
        written = output.pos;
        match result {
            Err(_) => return Outcome::Other,
            Ok(Status::StreamEnd) => {
                let rest = &data[input.pos..];
                // Zeros after the last stream, as one thread allows them.
                if rest.is_empty() || (last && rest.iter().all(|&c| c == 0)) {
                    out.truncate(written);
                    return Outcome::Stream(out);
                }
                return Outcome::Other;
            }
            Ok(_) if written < out.len() => {
                return if input.pos == data.len() {
                    Outcome::Short
                } else {
                    Outcome::Other
                };
            }
            Ok(_) if out.len() >= MAX_OUTPUT => return Outcome::Other,
            Ok(_) => {
                let more = (out.len() * 2).min(MAX_OUTPUT);
                // No more than that, as [`memory_usage`] counts it.
                out.reserve_exact(more - out.len());
                out.resize(more, 0);
            }
        }
    }
}

/// Where a stream may start in `data`, from `from` on: `Ok` with where,
/// or `Err` with where to look again once there is more.
fn find_start(data: &[u8], from: usize) -> Result<usize, usize> {
    let mut at = from;
    while let Some(i) = data
        .get(at..)
        .and_then(|rest| rest.iter().position(|&c| c == b'B'))
    {
        let i = at + i;
        let Some(start) = data.get(i..i + START_LEN) else {
            return Err(i);
        };
        if start.starts_with(b"BZh")
            && (b'1'..=b'9').contains(&start[3])
            && (start[4..] == [0x31, 0x41, 0x59, 0x26, 0x53, 0x59]
                || start[4..] == [0x17, 0x72, 0x45, 0x38, 0x50, 0x90])
        {
            return Ok(i);
        }
        at = i + 1;
    }
    Err(data.len())
}

/// The reader under, after what was read of it: the error it gave, once,
/// then the reader again, as one thread would have met them.
pub(super) struct Rest<R> {
    error: Option<io::Error>,
    inner: R,
    eof: bool,
}

impl<R> Rest<R> {
    /// `inner` after `error`, if it gave one, or after its end (`eof`).
    pub(super) fn new(error: Option<io::Error>, inner: R, eof: bool) -> Rest<R> {
        Rest { error, inner, eof }
    }
}

impl<R: Read> Read for Rest<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(e) = self.error.take() {
            return Err(e);
        }
        if self.eof {
            return Ok(0);
        }
        self.inner.read(buf)
    }
}

/// One thread's decoder, over what is left.
type Serial<R> = Decoder<io::Chain<Cursor<Vec<u8>>, Rest<R>>, Bzip2Codec>;

/// bzip2's decoder in threads.
pub(super) struct Bzip2Threads<R> {
    /// The reader under, until one thread reads the rest.
    inner: Option<R>,
    /// Where a stream may start: [`find_start`], but for tests.
    find: fn(&[u8], usize) -> Result<usize, usize>,
    /// [`MAX_PIECE`], but for tests.
    max_piece: usize,
    /// Where a block may start: [`find_magic`], but for tests.
    magic: MagicFn,
    pool: Pool,
    /// The pieces in flight at most.
    in_flight: usize,
    /// What is read and in no piece yet, from a stream's start.
    read: Vec<u8>,
    /// Where in `read` to look for a start again.
    looked: usize,
    eof: bool,
    /// The error the reader under gave, after `read`.
    error: Option<io::Error>,
    /// No more pieces: the rest, `read` and after, is one thread's.
    stopped: bool,
    /// Stopped for a stream larger than a piece, which [`BlockThreads`]
    /// decodes, rather than at the end or an error.
    large: bool,
    pieces: VecDeque<Piece>,
    /// A stream was read: what is left starts after one, not at the
    /// start.
    after_stream: bool,
    /// The data of the oldest piece, being read out.
    out: Vec<u8>,
    out_pos: usize,
    serial: Option<Serial<R>>,
    /// The stream larger than a piece, its blocks in threads, then the rest.
    blocks: Option<Box<BlockThreads<R>>>,
}

impl<R: Read> Bzip2Threads<R> {
    pub(super) fn new(inner: R, threads: u32) -> Bzip2Threads<R> {
        let threads = usize::try_from(threads).unwrap_or(usize::MAX);
        Bzip2Threads {
            inner: Some(inner),
            find: find_start,
            max_piece: MAX_PIECE,
            magic: find_magic,
            pool: Pool::new(threads),
            in_flight: threads.saturating_mul(2),
            read: Vec::new(),
            looked: 1,
            eof: false,
            error: None,
            stopped: false,
            large: false,
            pieces: VecDeque::new(),
            after_stream: false,
            out: Vec::new(),
            out_pos: 0,
            serial: None,
            blocks: None,
        }
    }

    /// Pieces given to the threads, as many as may be in flight, unless
    /// the input stops first.
    fn fill(&mut self) {
        while self.pieces.len() < self.in_flight && !self.stopped {
            self.next_piece();
        }
    }

    /// The next piece given to a thread, or `stopped`.
    fn next_piece(&mut self) {
        loop {
            match (self.find)(&self.read, self.looked) {
                Ok(at) => {
                    // Its own bytes, no more, and the room read in kept.
                    let data = self.read[..at].to_vec();
                    self.read.drain(..at);
                    self.looked = 1;
                    self.give(data, false);
                    return;
                }
                Err(again) => self.looked = again.max(1),
            }
            if self.eof {
                if !self.read.is_empty() {
                    let data = std::mem::take(&mut self.read);
                    self.give(data, true);
                }
                self.stopped = true;
                return;
            }
            if self.read.len() >= self.max_piece {
                self.stopped = true;
                self.large = true;
                return;
            }
            let Some(inner) = &mut self.inner else {
                self.stopped = true;
                return;
            };
            let len = self.read.len();
            self.read.resize(len + READ, 0);
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
                    self.stopped = true;
                    return;
                }
            }
        }
    }

    fn give(&mut self, data: Vec<u8>, last: bool) {
        let piece = self.piece(data, last);
        self.pieces.push_back(piece);
    }

    /// `data` given to a thread.
    fn piece(&mut self, data: Vec<u8>, last: bool) -> Piece {
        let data = Arc::new(data);
        let given = Arc::clone(&data);
        let outcome = self.pool.run(move || decode_piece(&given, last));
        Piece {
            data,
            last,
            outcome,
        }
    }

    /// What is left, from `from`, as one buffer, and the reader after it.
    fn rest(&mut self, from: &[u8]) -> Option<(Vec<u8>, Rest<R>)> {
        // As much as there is, no more, as [`memory_usage`] counts it.
        let pieces: usize = self.pieces.iter().map(|piece| piece.data.len()).sum();
        let mut rest = Vec::with_capacity(from.len() + pieces + self.read.len());
        rest.extend_from_slice(from);
        for piece in self.pieces.drain(..) {
            rest.extend_from_slice(&piece.data);
        }
        rest.append(&mut self.read);
        let inner = self.inner.take()?;
        self.stopped = true;
        Some((
            rest,
            Rest {
                error: self.error.take(),
                inner,
                eof: self.eof,
            },
        ))
    }

    /// The stream at `from`'s start, larger than a piece, a block in each
    /// thread, then what follows it.
    fn blocks(&mut self, from: &[u8]) -> Option<&mut BlockThreads<R>> {
        let (rest, after) = self.rest(from)?;
        let pool = std::mem::replace(&mut self.pool, Pool::new(1));
        let mut blocks = BlockThreads::new(rest, after, pool, self.in_flight);
        blocks.max_piece = self.max_piece;
        blocks.magic = self.magic;
        self.blocks = Some(Box::new(blocks));
        self.blocks.as_deref_mut()
    }

    /// One thread reads the rest, from `from`, as it would have.
    fn serial(&mut self, from: &[u8]) -> Option<&mut Serial<R>> {
        let (rest, after) = self.rest(from)?;
        let reader = Cursor::new(rest).chain(after);
        let mut serial = Decoder::new(reader, Bzip2Codec::new(), Layer::Bzip2);
        if self.after_stream {
            serial.after_a_stream();
        }
        self.serial = Some(serial);
        self.serial.as_mut()
    }
}

impl<R: Read> Read for Bzip2Threads<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(serial) = &mut self.serial {
                return serial.read(buf);
            }
            if let Some(blocks) = &mut self.blocks {
                return blocks.read(buf);
            }
            if self.out_pos < self.out.len() {
                let n = buf.len().min(self.out.len() - self.out_pos);
                buf[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
                self.out_pos += n;
                return Ok(n);
            }
            if buf.is_empty() {
                return Ok(0);
            }
            self.fill();
            let Some(piece) = self.pieces.pop_front() else {
                if self.read.is_empty() && self.error.is_none() && self.eof {
                    // Every stream read, and zeros after the last.
                    return Ok(0);
                }
                if self.large
                    && let Some(blocks) = self.blocks(&[])
                {
                    return blocks.read(buf);
                }
                match self.serial(&[]) {
                    Some(serial) => return serial.read(buf),
                    None => return Ok(0),
                }
            };
            match piece.outcome.wait() {
                Outcome::Stream(out) => {
                    self.out = out;
                    self.out_pos = 0;
                    self.after_stream = true;
                }
                Outcome::Short => {
                    self.fill();
                    let next = self.pieces.pop_front();
                    match next {
                        // Not where a stream starts after all: the two
                        // pieces are one.
                        Some(next) if piece.data.len() + next.data.len() <= self.max_piece => {
                            let mut data = Vec::with_capacity(piece.data.len() + next.data.len());
                            data.extend_from_slice(&piece.data);
                            data.extend_from_slice(&next.data);
                            let joined = self.piece(data, next.last);
                            self.pieces.push_front(joined);
                        }
                        next => {
                            let large = next.is_some() || self.large;
                            if let Some(next) = next {
                                self.pieces.push_front(next);
                            }
                            // A stream larger than a piece, from its start.
                            if large && let Some(blocks) = self.blocks(&piece.data) {
                                return blocks.read(buf);
                            }
                            if let Some(serial) = self.serial(&piece.data) {
                                return serial.read(buf);
                            }
                            return Ok(0);
                        }
                    }
                }
                Outcome::Other => {
                    if let Some(serial) = self.serial(&piece.data) {
                        return serial.read(buf);
                    }
                    return Ok(0);
                }
            }
        }
    }
}

/// A block's magic, `0x314159265359`, and the end of a stream's,
/// `0x177245385090`, each 48 bits on any bit.
const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
const END_MAGIC: u64 = 0x1772_4538_5090;

/// For each byte, whether it can be the second of eight read at a magic's
/// start: the first whole byte of a magic that starts on any of the first's
/// bits. A quick look before the bits are compared.
const SECOND: [bool; 256] = {
    let mut table = [false; 256];
    let mut k = 0;
    while k < 8 {
        let block = ((BLOCK_MAGIC << (16 - k)) >> 48) & 0xff;
        let end = ((END_MAGIC << (16 - k)) >> 48) & 0xff;
        table[block as usize] = true;
        table[end as usize] = true;
        k += 1;
    }
    table
};

/// The first magic in `data`, whose first byte is at bit `base * 8`, at bit
/// `from` or after, and whether it is the end's: `Err` with where to look
/// again once there is more, or none at its end (`eof`).
fn find_magic(data: &[u8], base: u64, from: u64, eof: bool) -> Result<(u64, bool), u64> {
    let first = ((from / 8).saturating_sub(base)) as usize;
    // Eight bytes from each, the last ones with zeros after at the end.
    let last = if eof {
        data.len()
    } else {
        data.len().saturating_sub(7)
    };
    for i in first..last {
        if !SECOND[usize::from(data.get(i + 1).copied().unwrap_or(0))] {
            continue;
        }
        let mut word = [0u8; 8];
        let n = (data.len() - i).min(8);
        word[..n].copy_from_slice(&data[i..i + n]);
        let v = u64::from_be_bytes(word);
        for k in 0..8u64 {
            let at = (base + i as u64) * 8 + k;
            if at < from {
                continue;
            }
            let bits = (v >> (16 - k)) & 0xFFFF_FFFF_FFFF;
            if bits == BLOCK_MAGIC {
                return Ok((at, false));
            }
            if bits == END_MAGIC {
                return Ok((at, true));
            }
        }
    }
    Err((base + last as u64) * 8)
}

/// [`find_magic`]'s kind.
type MagicFn = fn(&[u8], u64, u64, bool) -> Result<(u64, bool), u64>;

/// What a thread made of a block.
enum BlockOutcome {
    /// Its output and its CRC, and where it ended, in bits.
    Block { data: Vec<u8>, crc: u32, end: u64 },
    /// It decodes to more than it was let: the caller's thread decodes it,
    /// with more room.
    TooLarge,
    /// Anything else: one thread reads from its start.
    Other,
}

/// A block of a stream of blocks of `level` × 100,000 bytes, its magic at
/// bit `start`, `bytes` from the byte that bit is in: decoded as the decoder
/// of one thread would from there, to at most `most` bytes.
fn decode_block(level: i32, bytes: &[u8], start: u64, most: usize) -> BlockOutcome {
    let off = (start % 8) as u32;
    let (bits, live, input) = match (off, bytes.split_first()) {
        (0, _) => (0, 0, bytes),
        (_, Some((&byte, rest))) => (
            u32::from(byte) & ((1 << (8 - off)) - 1),
            8 - off as i32,
            rest,
        ),
        _ => return BlockOutcome::Other,
    };
    // Where `input` starts, in bits.
    let input_at = start.div_ceil(8) * 8;
    let mut d = Decompress::at_block(level, 0, bits, live, true);
    let mut out = vec![0; 1 << 20];
    let mut written = 0;
    let mut inp = InBuffer::new(input);
    loop {
        let mut output = OutBuffer {
            dst: &mut out,
            pos: written,
        };
        let result = d.decompress_block(&mut output, &mut inp);
        written = output.pos;
        match result {
            Ok(true) => {
                out.truncate(written);
                let (_, live) = d.bits_left();
                let end = input_at + inp.pos as u64 * 8 - live as u64;
                return BlockOutcome::Block {
                    data: out,
                    crc: d.block_crc(),
                    end,
                };
            }
            // It wants more input than the block has.
            Ok(false) if written < out.len() => return BlockOutcome::Other,
            Ok(false) if out.len() >= most => return BlockOutcome::TooLarge,
            Ok(false) => {
                let more = (out.len() * 2).min(most);
                out.reserve_exact(more - out.len());
                out.resize(more, 0);
            }
            Err(_) => return BlockOutcome::Other,
        }
    }
}

/// A block given to a thread: from its magic to the next magic, in bits.
struct BlockJob {
    start: u64,
    end: u64,
    outcome: Pending<BlockOutcome>,
}

/// What a stream is read from: what was read of it, then the reader under.
type Source<R> = io::Chain<Cursor<Vec<u8>>, Rest<R>>;

/// One thread's decoder from within the stream, over what is left.
type WithinSerial<R> = Decoder<io::Chain<Cursor<Vec<u8>>, Rest<Source<R>>>, Bzip2Codec>;

/// A stream larger than a piece, its blocks decoded in threads; once
/// anything is not as it should be, at its end too, one thread's decoder,
/// made where the decoder of one thread would be, reads the rest: the end of
/// the stream, its combined CRC, and what follows.
pub(super) struct BlockThreads<R> {
    /// [`MAX_PIECE`] and [`find_magic`], but for tests.
    max_piece: usize,
    magic: MagicFn,
    source: Option<Source<R>>,
    pool: Pool,
    in_flight: usize,
    /// The stream's block size, from its header.
    level: i32,
    /// The stream read ahead, from the byte `base`.
    input: Vec<u8>,
    base: u64,
    eof: bool,
    error: Option<io::Error>,
    /// Where to look for the next magic, in bits.
    scan: u64,
    /// The last block's magic, whose end is not found yet.
    last: Option<u64>,
    /// No more blocks for the threads.
    scan_done: bool,
    jobs: VecDeque<BlockJob>,
    /// Where the next block starts, in bits, and the combined CRC of the
    /// blocks before it: where the decoder of one thread would be.
    pos: u64,
    combined: u32,
    out: Vec<u8>,
    out_pos: usize,
    serial: Option<WithinSerial<R>>,
    /// The blocks taken from the threads.
    taken: usize,
}

impl<R: Read> BlockThreads<R> {
    /// The stream at the start of `read`, then `after`.
    fn new(read: Vec<u8>, after: Rest<R>, pool: Pool, in_flight: usize) -> BlockThreads<R> {
        let level = read.get(3).map_or(0, |&c| i32::from(c) - i32::from(b'0'));
        let header = read.starts_with(b"BZh") && (1..=9).contains(&level);
        BlockThreads {
            max_piece: MAX_PIECE,
            magic: find_magic,
            source: Some(Cursor::new(Vec::new()).chain(after)),
            pool,
            in_flight,
            level,
            input: read,
            base: 0,
            eof: false,
            error: None,
            scan: 32,
            last: None,
            // Not a stream's start after all: one thread reads it all.
            scan_done: !header,
            jobs: VecDeque::new(),
            pos: 32,
            combined: 0,
            out: Vec::new(),
            out_pos: 0,
            serial: None,
            taken: 0,
        }
    }

    /// More of the stream read ahead; `eof` or `error` once it ends.
    fn read_more(&mut self) {
        let Some(source) = &mut self.source else {
            self.eof = true;
            return;
        };
        let len = self.input.len();
        self.input.resize(len + READ, 0);
        let result = loop {
            match source.read(&mut self.input[len..]) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                result => break result,
            }
        };
        match result {
            Ok(n) => {
                self.input.truncate(len + n);
                self.eof = n == 0;
            }
            Err(e) => {
                // Given once by one thread's decoder, which reads on after
                // it, as the reader under would be read.
                self.input.truncate(len);
                self.error = Some(e);
            }
        }
    }

    /// Blocks given to the threads, as many as may be in flight, until the
    /// stream's end, or anything the scan cannot go on from.
    fn fill(&mut self) {
        while self.jobs.len() < self.in_flight && !self.scan_done {
            match (self.magic)(&self.input, self.base, self.scan, self.eof) {
                Ok((at, end)) => {
                    if let Some(start) = self.last.take() {
                        let from = (start / 8 - self.base) as usize;
                        let to = (at.div_ceil(8) - self.base) as usize;
                        let bytes = self.input[from..to].to_vec();
                        let level = self.level;
                        let outcome = self
                            .pool
                            .run(move || decode_block(level, &bytes, start, MAX_OUTPUT));
                        self.jobs.push_back(BlockJob {
                            start,
                            end: at,
                            outcome,
                        });
                    }
                    if end {
                        self.scan_done = true;
                    } else {
                        self.last = Some(at);
                        self.scan = at + 48;
                    }
                }
                Err(again) => {
                    self.scan = self.scan.max(again);
                    // A block no thread takes: larger than a piece, or the
                    // stream's last, cut short.
                    let from = self.last.unwrap_or(self.scan);
                    let ahead = (self.base + self.input.len() as u64) * 8 - from;
                    if self.eof || self.error.is_some() || ahead > self.max_piece as u64 * 8 {
                        self.scan_done = true;
                    } else {
                        self.read_more();
                    }
                }
            }
        }
    }

    /// The block from bit `start` to bit `end`, decoded on this thread, to
    /// at most [`MAX_BLOCK_OUTPUT`] bytes.
    fn decode_here(&self, start: u64, end: u64) -> BlockOutcome {
        let from = (start / 8 - self.base) as usize;
        let to = (end.div_ceil(8) - self.base) as usize;
        match self.input.get(from..to) {
            Some(bytes) => decode_block(self.level, bytes, start, MAX_BLOCK_OUTPUT),
            None => BlockOutcome::Other,
        }
    }

    /// One thread's decoder reads the rest, from `pos`, made as the decoder
    /// of one thread would be there.
    fn serial(&mut self) -> Option<&mut WithinSerial<R>> {
        self.jobs.clear();
        let byte = (self.pos / 8 - self.base) as usize;
        let off = (self.pos % 8) as u32;
        let (bits, live, rest) = match (off, self.input.get(byte)) {
            (0, _) => (0, 0, byte),
            (_, Some(&b)) => (
                u32::from(b) & ((1 << (8 - off)) - 1),
                8 - off as i32,
                byte + 1,
            ),
            _ => (0, 0, byte),
        };
        let rest = self.input.get(rest..).unwrap_or_default().to_vec();
        self.input = Vec::new();
        let source = self.source.take()?;
        let after = Rest {
            error: self.error.take(),
            inner: source,
            eof: self.eof,
        };
        let d = Decompress::at_block(self.level, self.combined, bits, live, false);
        let reader = Cursor::new(rest).chain(after);
        self.serial = Some(Decoder::new(reader, Bzip2Codec::within(d), Layer::Bzip2));
        self.serial.as_mut()
    }
}

impl<R: Read> Read for BlockThreads<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(serial) = &mut self.serial {
                return serial.read(buf);
            }
            if self.out_pos < self.out.len() {
                let n = buf.len().min(self.out.len() - self.out_pos);
                buf[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
                self.out_pos += n;
                return Ok(n);
            }
            if buf.is_empty() {
                return Ok(0);
            }
            self.fill();
            let ours = self.jobs.front().is_some_and(|job| job.start == self.pos);
            let job = if ours { self.jobs.pop_front() } else { None };
            let outcome = job.map(|job| match job.outcome.wait() {
                // Runs of the same byte decode to more than a thread holds:
                // decoded here, where the decoder of one thread would decode
                // it, and the threads go on after it.
                BlockOutcome::TooLarge => (job.end, self.decode_here(job.start, job.end)),
                outcome => (job.end, outcome),
            });
            match outcome {
                Some((at, BlockOutcome::Block { data, crc, end })) if end == at => {
                    self.combined = self.combined.rotate_left(1) ^ crc;
                    self.taken += 1;
                    self.pos = end;
                    self.out = data;
                    self.out_pos = 0;
                    // What is behind the next block is no longer needed.
                    let behind = self.pos / 8 - self.base;
                    if behind > self.max_piece as u64 {
                        self.input.drain(..behind as usize);
                        self.base += behind;
                    }
                }
                _ => match self.serial() {
                    Some(serial) => return serial.read(buf),
                    None => return Ok(0),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::bzip2::{Action, CompressMt, MtOptions};

    const BLOCK: [u8; 6] = [0x31, 0x41, 0x59, 0x26, 0x53, 0x59];
    const END: [u8; 6] = [0x17, 0x72, 0x45, 0x38, 0x50, 0x90];

    #[test]
    fn starts_are_found() {
        let mut data = b"xxBZh9".to_vec();
        data.extend(BLOCK);
        assert_eq!(find_start(&data, 0), Ok(2));
        assert_eq!(find_start(&data, 3), Err(data.len()));
        // The end's magic, a stream of nothing; each block size.
        for level in b'1'..=b'9' {
            let mut data = vec![b'B', b'Z', b'h', level];
            data.extend(END);
            assert_eq!(find_start(&data, 0), Ok(0));
        }
        // Not quite: another digit or letter, another magic.
        for start in [b"BZh0", b"BZh:", b"BZH9", b"bZh9"] {
            let mut data = start.to_vec();
            data.extend(BLOCK);
            assert_eq!(find_start(&data, 0), Err(data.len()));
        }
        let mut data = b"BZh9".to_vec();
        data.extend([0x31, 0x41, 0x59, 0x26, 0x53, 0x58]);
        assert_eq!(find_start(&data, 0), Err(data.len()));
        // Cut short: looked at again from its `B` once there is more.
        let mut data = b"abcBBZh9".to_vec();
        data.extend(&BLOCK[..5]);
        assert_eq!(find_start(&data, 0), Err(4));
        data.push(BLOCK[5]);
        assert_eq!(find_start(&data, 4), Ok(4));
    }

    /// Text that compresses, of `len` bytes, bzip2's magic in it.
    fn text(len: usize) -> Vec<u8> {
        let words: [&[u8]; 6] = [
            b"alpha ",
            b"beta ",
            b"gamma\n",
            b"    delta ",
            b"BZh91AY&SY ",
            b"\0\0\0\0",
        ];
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut out = Vec::with_capacity(len + 16);
        while out.len() < len {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            out.extend_from_slice(words[(seed % 6) as usize]);
            out.extend_from_slice(format!("{} ", seed >> 48).as_bytes());
        }
        out.truncate(len);
        out
    }

    /// `data` in streams of `piece` bytes.
    fn streams(data: &[u8], piece: usize) -> Vec<u8> {
        let options = MtOptions {
            block_size_100k: 1,
            piece_size: piece,
            ..MtOptions::default()
        };
        let mut c = CompressMt::with_options(&options).unwrap();
        let mut out = vec![0; data.len() + 100_000];
        let mut output = OutBuffer::new(&mut out);
        let status = c
            .compress(&mut output, &mut InBuffer::new(data), Action::Finish)
            .unwrap();
        assert_eq!(status, Status::StreamEnd);
        let len = output.pos;
        out.truncate(len);
        out
    }

    /// A start 1,000 bytes into each piece as well as where there is one:
    /// most of them inside a stream.
    fn often(data: &[u8], from: usize) -> Result<usize, usize> {
        let fake = 1000;
        match find_start(data, from) {
            Ok(at) if at <= fake => Ok(at),
            _ if from <= fake && data.len() > fake => Ok(fake),
            found => found,
        }
    }

    fn read_all(reader: &mut impl Read) -> (Vec<u8>, Option<String>) {
        let mut data = Vec::new();
        let mut piece = vec![0; 777];
        loop {
            match reader.read(&mut piece) {
                Ok(0) => return (data, None),
                Ok(n) => data.extend(&piece[..n]),
                Err(e) => return (data, Some(e.to_string())),
            }
        }
    }

    /// `data` in one stream of blocks of 100,000 bytes, as `bzip2 -1`
    /// writes a file.
    fn one_stream(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0; data.len() + data.len() / 50 + 1000];
        let n = crate::bzip2::buff_to_buff_compress(&mut out, data, 1, 30).unwrap();
        out.truncate(n);
        out
    }

    /// What is read: the data, and the error that ended it.
    type Read2 = (Vec<u8>, Option<String>);

    /// What one thread reads of `file`, and what threads read with pieces
    /// of `piece` bytes, and how many blocks they took from threads.
    fn both(file: &[u8], threads: u32, piece: usize, magic: MagicFn) -> (Read2, Read2, usize) {
        let mut one = Decoder::new(Cursor::new(file), Bzip2Codec::new(), Layer::Bzip2);
        let alone = read_all(&mut one);
        let mut threaded = Bzip2Threads::new(Cursor::new(file), threads);
        threaded.max_piece = piece;
        threaded.magic = magic;
        let read = read_all(&mut threaded);
        let taken = threaded.blocks.as_ref().map_or(0, |b| b.taken);
        (alone, read, taken)
    }

    /// Blocks of runs of one byte, as programs and disk images have, decode
    /// to more than a thread holds (at block size 1, 5.1 MB of 100,000
    /// symbols): each is decoded on the caller's thread, and the threads
    /// take the blocks after it, where one thread used to read all the rest.
    #[test]
    fn blocks_too_large_for_a_thread_are_decoded_on_the_callers() {
        let mut data = text(300_000);
        data.extend(vec![0u8; 12 << 20]);
        data.extend(text(300_000));
        data.extend(vec![7u8; 6 << 20]);
        data.extend(text(250_000));
        let file = one_stream(&data);
        // Every block's magic in the stream.
        let mut blocks = 0;
        let mut from = 32;
        while let Ok((at, end)) = find_magic(&file, 0, from, true) {
            if end {
                break;
            }
            blocks += 1;
            from = at + 48;
        }
        for threads in [2, 8] {
            let (alone, read, taken) = both(&file, threads, 60_000, find_magic);
            assert!(alone == (data.clone(), None));
            assert!(read == alone, "{threads} threads");
            assert_eq!(taken, blocks, "{threads} threads");
        }
    }

    #[test]
    fn blocks_of_one_stream_come_out_as_one_thread_reads_them() {
        let data = text(700_000);
        let file = one_stream(&data);
        let mut followed = file.clone();
        followed.extend(one_stream(&data[..150_000]));
        followed.extend([0; 7]);
        let mut cases = vec![("whole", file.clone()), ("followed", followed)];
        for at in [12, file.len() / 3, file.len() / 2, file.len() - 3] {
            let mut damaged = file.clone();
            damaged[at] ^= 0x04;
            cases.push(("damaged", damaged));
        }
        for len in [file.len() / 2, file.len() - 1] {
            cases.push(("cut", file[..len].to_vec()));
        }
        for (label, case) in &cases {
            for threads in [2, 8] {
                let (alone, read, taken) = both(case, threads, 20_000, find_magic);
                assert!(read == alone, "{label}, {threads} threads");
                // Every block of the whole stream, the last too, as the
                // stream's end follows it.
                if *label == "whole" {
                    assert_eq!(taken, 8, "{threads} threads");
                }
            }
        }
        let (alone, _, _) = both(&file, 2, 20_000, find_magic);
        assert!(alone == (data, None));
    }

    /// Damage anywhere in a stream of blocks, a bit changed, a byte, or the
    /// stream cut short: what threads read is what one thread reads.
    #[test]
    fn damage_anywhere_comes_out_as_one_thread_reads_it() {
        let data = text(300_000);
        let file = one_stream(&data);
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        for round in 0..60 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let at = (seed as usize) % file.len();
            let mut damaged = file.clone();
            match round % 3 {
                0 => damaged[at] ^= 1 << (seed >> 61),
                1 => damaged[at] = (seed >> 40) as u8,
                _ => damaged.truncate(at),
            }
            let (alone, read, _) = both(&damaged, 3, 20_000, find_magic);
            assert!(read == alone, "round {round}, byte {at}");
        }
    }

    /// A magic 5,000 bits on from each place the scan looks: inside a
    /// block, whose thread then ends elsewhere.
    fn fake_magic(data: &[u8], base: u64, from: u64, eof: bool) -> Result<(u64, bool), u64> {
        match find_magic(data, base, from, eof) {
            Ok((at, end)) if at > from + 5000 && from > 32 => {
                let _ = end;
                Ok((from + 4999, false))
            }
            found => found,
        }
    }

    #[test]
    fn a_magic_inside_a_block_is_read_by_one_thread() {
        let data = text(400_000);
        let file = one_stream(&data);
        for threads in [2, 8] {
            let (alone, read, taken) = both(&file, threads, 20_000, fake_magic);
            assert!(read == alone, "{threads} threads");
            // The first block's thread ends elsewhere than the fake magic:
            // one thread reads it all.
            assert_eq!(taken, 0, "{threads} threads");
        }
    }

    #[test]
    fn starts_inside_a_stream_join_pieces() {
        let data = text(200_000);
        let file = streams(&data, 30_000);
        // Seven streams, each of several pieces of 1,000 bytes.
        assert!(file.len() > 7 * 3000, "{}", file.len());
        let mut damaged = file.clone();
        let at = damaged.len() / 2;
        damaged[at] ^= 0x10;
        for (file, sound) in [(&file, true), (&damaged, false)] {
            let mut one = Decoder::new(Cursor::new(file), Bzip2Codec::new(), Layer::Bzip2);
            let alone = read_all(&mut one);
            assert_eq!(alone.1.is_none(), sound);
            if sound {
                assert!(alone.0 == data);
            }
            for threads in [2, 8] {
                let mut threaded = Bzip2Threads::new(Cursor::new(file), threads);
                threaded.find = often;
                assert!(read_all(&mut threaded) == alone, "{threads} threads");
                // Pieces were joined until each was a stream: one thread
                // read nothing but the damaged stream and what follows.
                assert_eq!(threaded.serial.is_none(), sound);
            }
        }
    }
}
