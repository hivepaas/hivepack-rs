//! The parts of libarchive's `archive_read.c` that the ar reader calls:
//! `__archive_read_ahead` and `__archive_read_consume`
//! (`__archive_read_filter_ahead` and `__archive_read_filter_consume`), over
//! an `io::Read`.
//!
//! The input behaves as libarchive's does with the whole archive in memory
//! (`archive_read_open_memory`): what the reader asks to look ahead at is
//! there if the archive has it, however the input comes in pieces. The
//! input is read as far as asked, and what is looked at stays buffered
//! until consumed. The reader never seeks.

use std::io::{self, Read};

use crate::ar::error::Error;

/// How much is read from the input at a time.
const READ_SIZE: usize = 64 * 1024;

/// The input, as libarchive's read filter holds it: a position, and the
/// bytes from there that were read ahead.
#[derive(Debug)]
pub(crate) struct Input<R> {
    r: R,
    buf: Vec<u8>,
    /// The unconsumed bytes are `buf[start..end]`.
    start: usize,
    end: usize,
    eof: bool,
}

impl<R: Read> Input<R> {
    pub(crate) fn new(r: R) -> Input<R> {
        Input {
            r,
            buf: Vec::new(),
            start: 0,
            end: 0,
            eof: false,
        }
    }

    pub(crate) fn into_inner(self) -> R {
        self.r
    }

    /// Reads until `min` bytes are buffered, or the input ends.
    fn fill(&mut self, min: usize) -> io::Result<()> {
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        }
        while self.end - self.start < min && !self.eof {
            if self.start > 0 && self.buf.len() - self.start < min.max(READ_SIZE) {
                self.buf.copy_within(self.start..self.end, 0);
                self.end -= self.start;
                self.start = 0;
            }
            let want = (self.start + min).max(self.end + READ_SIZE);
            if self.buf.len() < want {
                self.buf
                    .try_reserve(want - self.buf.len())
                    .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
                self.buf.resize(want, 0);
            }
            match self.r.read(&mut self.buf[self.end..]) {
                Ok(0) => self.eof = true,
                Ok(n) => self.end += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// `__archive_read_ahead`: at least `min` bytes from the position (at
    /// least one if `min` is 0), or `None` if the archive ends first; with
    /// `min` 0 at the end, an empty slice. After `None`, [`Input::buffered`]
    /// is what is left, which libarchive gives back in `avail`.
    pub(crate) fn ahead(&mut self, min: usize) -> io::Result<Option<&[u8]>> {
        self.fill(min.max(1))?;
        let avail = self.end - self.start;
        if avail >= min.max(1) || (min == 0 && avail == 0) {
            Ok(Some(&self.buf[self.start..self.end]))
        } else {
            Ok(None)
        }
    }

    /// `__archive_read_consume`: moves the position forward by `request`.
    /// An archive that ends first is "Truncated input file (needed N bytes,
    /// only M available)", with the position at its end.
    pub(crate) fn consume(&mut self, request: u64) -> Result<(), Error> {
        if request == 0 {
            return Ok(());
        }
        let mut left = request;
        while left > 0 {
            if self.start == self.end {
                self.fill(1)?;
            }
            let n = ((self.end - self.start) as u64).min(left);
            if n == 0 {
                return Err(Error::Truncated {
                    needed: request as i64,
                    available: (request - left) as i64,
                });
            }
            self.start += n as usize;
            left -= n;
        }
        Ok(())
    }
}
