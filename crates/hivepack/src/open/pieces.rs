//! What pbzx's and zstd's decoders in threads share: a stream cut into
//! pieces where its own headers say, never where the threads would, each
//! piece decoded in a thread into memory and its output taken only when it
//! is what one thread would decode there; and anything else left, from that
//! piece's start, to the decoder of one thread, which reads it as it would
//! have: the same data, the same error.
//!
//! What the pieces in flight hold, as their format counts it, is bounded:
//! a piece that would go past the bound waits for those before it, and one
//! that alone would go past is left to one thread, with all that follows.

use std::collections::VecDeque;
use std::io::{self, Cursor, Read};
use std::sync::Arc;

use crate::bzip2::mt::{Pending, Pool};
use crate::open::bzip2_threads::Rest;

/// What the input is read in, beyond what a piece needs.
const READ: usize = 256 << 10;

/// What is left for one thread: what was read and not taken, then the
/// reader under.
pub(super) type Left<R> = io::Chain<Cursor<Vec<u8>>, Rest<R>>;

/// What a format tells of the next piece, from what is read of it.
pub(super) enum Plan {
    /// At least this many bytes are needed to tell, more than are read.
    Need(usize),
    /// A piece of `len` bytes, holding `cost` while in flight.
    Piece { len: usize, cost: u64 },
    /// No more pieces: one thread reads the rest.
    Stop,
}

/// What comes of a piece taken.
pub(super) enum Work {
    /// Nothing comes out of it.
    Nothing,
    /// Its bytes from this one on come out as they are.
    Stored(usize),
    /// A thread decodes it: what comes out, or none for one thread to read
    /// it from its start.
    Decode(Box<dyn FnOnce() -> Option<Vec<u8>> + Send>),
}

/// A format cut into pieces.
pub(super) trait Pieces: Clone + Send {
    /// The next piece, from `read`, which starts where it does.
    fn plan(&self, read: &[u8]) -> Plan;
    /// The piece `bytes` taken, as [`Pieces::plan`] told it.
    fn take(&mut self, bytes: &Arc<Vec<u8>>) -> Work;
    /// Whether the input may end where the pieces taken end.
    fn may_end(&self) -> bool;
    /// The decoder of one thread over `left`, which starts where the pieces
    /// taken end.
    fn serial<'a, R: Read + Send + 'a>(&self, left: Left<R>) -> Box<dyn Read + Send + 'a>;
}

/// What a piece in flight gives out.
enum Out {
    /// Its bytes from this one on.
    Stored(usize),
    /// What a thread decodes it to, or none.
    Decoded(Pending<Option<Vec<u8>>>),
}

/// A piece in flight.
struct Piece<P> {
    bytes: Arc<Vec<u8>>,
    cost: u64,
    out: Out,
    /// The format as it was before the piece was taken, for one thread to
    /// read on from its start.
    before: P,
}

/// What the next piece does.
enum Next {
    /// It is in flight.
    Given,
    /// It waits for room.
    Wait,
    /// No more pieces.
    Stop,
}

/// A format's decoder in threads.
pub(super) struct Threaded<'a, R, P> {
    /// The reader under, until one thread reads the rest.
    inner: Option<R>,
    format: P,
    pool: Pool,
    /// The pieces in flight at most.
    in_flight: usize,
    /// What the pieces in flight, and the one read out, may hold.
    memory: u64,
    /// What is read and in no piece yet, from a piece's start.
    read: Vec<u8>,
    eof: bool,
    /// The error the reader under gave, after `read`.
    error: Option<io::Error>,
    stopped: bool,
    pieces: VecDeque<Piece<P>>,
    /// What the pieces in flight and the one being read out hold.
    held: u64,
    /// The oldest piece's data, read out from `out_pos` to its end.
    out: Arc<Vec<u8>>,
    out_pos: usize,
    out_cost: u64,
    serial: Option<Box<dyn Read + Send + 'a>>,
}

impl<'a, R: Read + Send + 'a, P: Pieces> Threaded<'a, R, P> {
    /// `format` over `inner`, in `threads` threads, its pieces in flight
    /// holding `memory` at most; `name` the threads' name.
    pub(super) fn new(
        inner: R,
        format: P,
        threads: u32,
        memory: u64,
        name: &'static str,
    ) -> Threaded<'a, R, P> {
        let threads = usize::try_from(threads).unwrap_or(usize::MAX);
        Threaded {
            inner: Some(inner),
            format,
            pool: Pool::named(threads, name),
            in_flight: threads.saturating_mul(2),
            memory,
            read: Vec::new(),
            eof: false,
            error: None,
            stopped: false,
            pieces: VecDeque::new(),
            held: 0,
            out: Arc::default(),
            out_pos: 0,
            out_cost: 0,
            serial: None,
        }
    }

    /// Whether one thread reads the rest.
    #[cfg(test)]
    pub(super) fn is_serial(&self) -> bool {
        self.serial.is_some()
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

    /// Pieces given to the threads, as many as may be in flight and fit,
    /// unless the input stops first.
    fn fill(&mut self) {
        while self.pieces.len() < self.in_flight && !self.stopped {
            match self.next_piece() {
                Next::Given => {}
                Next::Wait => return,
                Next::Stop => self.stopped = true,
            }
        }
    }

    /// The next piece read and given to a thread, if it can be.
    fn next_piece(&mut self) -> Next {
        loop {
            let (len, cost) = match self.format.plan(&self.read) {
                Plan::Need(n) if n > self.read.len() => {
                    if !self.read_to(n) {
                        return Next::Stop;
                    }
                    continue;
                }
                Plan::Piece { len, cost } if len > 0 => (len, cost),
                Plan::Need(_) | Plan::Piece { .. } | Plan::Stop => return Next::Stop,
            };
            if cost > self.memory {
                return Next::Stop;
            }
            // One alone never waits.
            if !self.pieces.is_empty() && self.held.saturating_add(cost) > self.memory {
                return Next::Wait;
            }
            if !self.read_to(len) {
                return Next::Stop;
            }
            // Its own bytes, no more, and what was read after kept.
            let after = self.read.split_off(len);
            let bytes = Arc::new(std::mem::replace(&mut self.read, after));
            let before = self.format.clone();
            let out = match self.format.take(&bytes) {
                Work::Nothing => Out::Stored(len),
                Work::Stored(from) => Out::Stored(from.min(len)),
                Work::Decode(decode) => Out::Decoded(self.pool.run(decode)),
            };
            self.held += cost;
            self.pieces.push_back(Piece {
                bytes,
                cost,
                out,
                before,
            });
            return Next::Given;
        }
    }

    /// One thread reads the rest, from `from`, the piece of which `before`
    /// is the format before it, or from where the pieces taken end.
    fn serial(&mut self, from: Option<(&[u8], P)>) -> Option<&mut Box<dyn Read + Send + 'a>> {
        let inner = self.inner.take()?;
        let (from, format) = match from {
            Some((bytes, before)) => (bytes, before),
            None => (&[][..], self.format.clone()),
        };
        let pieces: usize = self.pieces.iter().map(|piece| piece.bytes.len()).sum();
        let mut rest = Vec::with_capacity(from.len() + pieces + self.read.len());
        rest.extend_from_slice(from);
        for piece in self.pieces.drain(..) {
            rest.extend_from_slice(&piece.bytes);
        }
        rest.append(&mut self.read);
        self.stopped = true;
        // The pieces given and not started are not decoded.
        self.pool = Pool::new(1);
        let after = Rest::new(self.error.take(), inner, self.eof);
        self.serial = Some(format.serial(Cursor::new(rest).chain(after)));
        self.serial.as_mut()
    }
}

impl<'a, R: Read + Send + 'a, P: Pieces> Read for Threaded<'a, R, P> {
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
            self.out = Arc::default();
            self.out_pos = 0;
            self.held -= std::mem::take(&mut self.out_cost);
            self.fill();
            let Some(piece) = self.pieces.pop_front() else {
                // Where a piece would start, at the end, as one thread ends.
                if self.format.may_end() && self.read.is_empty() && self.eof && self.error.is_none()
                {
                    return Ok(0);
                }
                return match self.serial(None) {
                    Some(serial) => serial.read(buf),
                    None => Ok(0),
                };
            };
            self.out_cost = piece.cost;
            match piece.out {
                Out::Stored(from) => {
                    self.out_pos = from;
                    self.out = piece.bytes;
                }
                Out::Decoded(pending) => match pending.wait() {
                    Some(out) => self.out = Arc::new(out),
                    None => {
                        return match self.serial(Some((&piece.bytes, piece.before))) {
                            Some(serial) => serial.read(buf),
                            None => Ok(0),
                        };
                    }
                },
            }
        }
    }
}
