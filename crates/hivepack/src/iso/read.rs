//! The parts of libarchive's `archive_read.c` that the ISO 9660 reader
//! calls: `__archive_read_ahead`, `__archive_read_consume` and
//! `__archive_read_seek`, over an `io::Read`.
//!
//! The reader behaves as libarchive does with the whole image in memory
//! (`archive_read_open_memory`): what it asks to look ahead at is there if
//! the image has it, however the input comes in pieces. The input is read
//! as far as asked, and what is looked at stays buffered until consumed.

use std::io::{self, Read, SeekFrom};

use crate::iso::error::Error;

/// `Seek::seek` of the input, when it can seek.
pub(crate) type SeekFn<R> = fn(&mut R, SeekFrom) -> io::Result<u64>;

/// How much is read from the input at a time.
const READ_SIZE: usize = 64 * 1024;

/// The input, as libarchive's read filter holds it: a position, and the
/// bytes from there that were read ahead.
#[derive(Debug)]
pub(crate) struct Input<R> {
    r: R,
    seek: Option<SeekFn<R>>,
    /// Where the input was when reading began: positions count from there.
    base: Option<u64>,
    /// The input's length from `base`, once a seek needed it.
    len: Option<u64>,
    buf: Vec<u8>,
    /// The unconsumed bytes are `buf[start..end]`.
    start: usize,
    end: usize,
    eof: bool,
    /// Where `buf[start]` is in the image: libarchive's `position`.
    position: u64,
}

impl<R: Read> Input<R> {
    pub(crate) fn new(r: R, seek: Option<SeekFn<R>>) -> Input<R> {
        Input {
            r,
            seek,
            base: None,
            len: None,
            buf: Vec::new(),
            start: 0,
            end: 0,
            eof: false,
            position: 0,
        }
    }

    pub(crate) fn into_inner(self) -> R {
        self.r
    }

    /// Where the input is, for seeking: found before anything is read.
    fn base(&mut self) -> io::Result<u64> {
        match (self.base, self.seek) {
            (Some(base), _) => Ok(base),
            (None, Some(seek)) => {
                let base = seek(&mut self.r, SeekFrom::Current(0))?;
                self.base = Some(base);
                Ok(base)
            }
            (None, None) => Ok(0),
        }
    }

    /// Reads until `min` bytes are buffered, or the input ends.
    fn fill(&mut self, min: usize) -> io::Result<()> {
        if self.seek.is_some() && self.base.is_none() {
            self.base()?;
        }
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
    /// least one if `min` is 0), or `None` if the image ends first; with
    /// `min` 0 at the end, an empty slice.
    pub(crate) fn ahead(&mut self, min: usize) -> io::Result<Option<&[u8]>> {
        self.fill(min.max(1))?;
        let avail = self.end - self.start;
        if avail >= min.max(1) || (min == 0 && avail == 0) {
            Ok(Some(&self.buf[self.start..self.end]))
        } else {
            Ok(None)
        }
    }

    /// Whether the image has `n` bytes from the position, reading ahead as
    /// far as that.
    pub(crate) fn has(&mut self, n: usize) -> io::Result<bool> {
        self.fill(n)?;
        Ok(self.end - self.start >= n)
    }

    /// The bytes buffered from the position, without reading more.
    pub(crate) fn buffered(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }

    /// `__archive_read_consume`: moves the position forward by `request`.
    /// An image that ends first is "Truncated input file (needed N bytes,
    /// only M available)", with the position at its end; a negative
    /// request is `ARCHIVE_FATAL` without a message.
    pub(crate) fn consume(&mut self, request: i64) -> Result<(), Error> {
        if request < 0 {
            return Err(Error::Unspecified(None));
        }
        if request == 0 {
            return Ok(());
        }
        let request = request as u64;
        let mut left = request;
        let in_buf = ((self.end - self.start) as u64).min(left);
        self.start += in_buf as usize;
        self.position += in_buf;
        left -= in_buf;
        if left == 0 {
            return Ok(());
        }
        self.start = 0;
        self.end = 0;
        if let Some(seek) = self.seek {
            let base = self.base()?;
            let len = match self.len {
                Some(len) => len,
                None => {
                    let len = seek(&mut self.r, SeekFrom::End(0))?.saturating_sub(base);
                    self.len = Some(len);
                    len
                }
            };
            let skip = left.min(len.saturating_sub(self.position));
            self.position += skip;
            seek(&mut self.r, SeekFrom::Start(base + self.position))?;
            self.eof = false;
            if skip < left {
                return Err(Error::Truncated {
                    needed: request as i64,
                    available: (request - left + skip) as i64,
                });
            }
            return Ok(());
        }
        while left > 0 {
            self.fill(1)?;
            let n = ((self.end - self.start) as u64).min(left);
            if n == 0 {
                return Err(Error::Truncated {
                    needed: request as i64,
                    available: (request - left) as i64,
                });
            }
            self.start += n as usize;
            self.position += n;
            left -= n;
        }
        Ok(())
    }

    /// `__archive_read_seek` to `offset`: `None` when the input cannot
    /// seek (`ARCHIVE_FAILED`), else where it went.
    pub(crate) fn seek(&mut self, offset: u64) -> Option<io::Result<u64>> {
        let seek = self.seek?;
        Some((|| {
            let base = self.base()?;
            seek(&mut self.r, SeekFrom::Start(base + offset))?;
            self.start = 0;
            self.end = 0;
            self.eof = false;
            self.position = offset;
            Ok(offset)
        })())
    }
}
