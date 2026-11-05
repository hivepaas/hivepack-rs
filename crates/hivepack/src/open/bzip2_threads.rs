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
//! A file of one stream, as `bzip2` writes it, has nothing to share: once
//! [`MAX_PIECE`] bytes are read without another start, it is all decoded
//! on the caller's thread.

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

/// What the input is read in.
const READ: usize = 256 << 10;

/// `BZh`, the block size, and the magic after it.
const START_LEN: usize = 10;

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
    pieces: VecDeque<Piece>,
    /// A stream was read: what is left starts after one, not at the
    /// start.
    after_stream: bool,
    /// The data of the oldest piece, being read out.
    out: Vec<u8>,
    out_pos: usize,
    serial: Option<Serial<R>>,
}

impl<R: Read> Bzip2Threads<R> {
    pub(super) fn new(inner: R, threads: u32) -> Bzip2Threads<R> {
        let threads = usize::try_from(threads).unwrap_or(usize::MAX);
        Bzip2Threads {
            inner: Some(inner),
            find: find_start,
            pool: Pool::new(threads),
            in_flight: threads.saturating_mul(2),
            read: Vec::new(),
            looked: 1,
            eof: false,
            error: None,
            stopped: false,
            pieces: VecDeque::new(),
            after_stream: false,
            out: Vec::new(),
            out_pos: 0,
            serial: None,
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
                    let rest = self.read.split_off(at);
                    let data = std::mem::replace(&mut self.read, rest);
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
            if self.read.len() >= MAX_PIECE {
                self.stopped = true;
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

    /// One thread reads the rest, from `from`, as it would have.
    fn serial(&mut self, from: &[u8]) -> Option<&mut Serial<R>> {
        let mut rest = from.to_vec();
        for piece in self.pieces.drain(..) {
            rest.extend_from_slice(&piece.data);
        }
        rest.append(&mut self.read);
        let inner = self.inner.take()?;
        let after = Rest {
            error: self.error.take(),
            inner,
            eof: self.eof,
        };
        self.stopped = true;
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
                        Some(next) if piece.data.len() + next.data.len() <= MAX_PIECE => {
                            let mut data = piece.data.to_vec();
                            data.extend_from_slice(&next.data);
                            let joined = self.piece(data, next.last);
                            self.pieces.push_front(joined);
                        }
                        next => {
                            if let Some(next) = next {
                                self.pieces.push_front(next);
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
