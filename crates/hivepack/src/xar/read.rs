//! The parts of libarchive's `archive_read.c` that the XAR reader calls:
//! `__archive_read_ahead`, `__archive_read_consume` and
//! `__archive_read_seek`, over an `io::Read`.
//!
//! The reader behaves as libarchive does with the whole archive in memory
//! (`archive_read_open_memory`), or given in one block by a callback that
//! cannot seek: what it asks to look ahead at is there if the archive has
//! it, however the input comes in pieces. The input is read as far as
//! asked, and what is looked at stays buffered until consumed. As in
//! libarchive, a seek out of the archive fails the input for good
//! (`f->fatal`); every later look and skip fails too.

use std::io::{self, Read, SeekFrom};

use crate::xar::error::Error;

/// `Seek::seek` of the input, when it can seek.
pub(crate) type SeekFn<R> = fn(&mut R, SeekFrom) -> io::Result<u64>;

/// How much is read from the input at a time.
const READ_SIZE: usize = 64 * 1024;

/// What `__archive_read_seek` gave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Seek {
    /// The new position.
    At(u64),
    /// `ARCHIVE_FAILED`: the input cannot seek; nothing changed.
    Failed,
    /// `ARCHIVE_FATAL`: out of the archive; the input failed for good.
    Fatal,
}

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
    /// `f->fatal`.
    fatal: bool,
    /// Where `buf[start]` is in the archive: libarchive's `position`.
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
            fatal: false,
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
            let want = (self.start.saturating_add(min)).max(self.end + READ_SIZE);
            // Not more than one more read's worth at a time: the input may
            // end before `min`.
            let want = want.min(self.end + READ_SIZE.max(self.buf.len() - self.end));
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
    /// least one if `min` is 0); `Ok(Err(n))` with the `n` bytes left if
    /// the archive ends first; `Err` once the input failed.
    pub(crate) fn ahead(&mut self, min: usize) -> Result<Result<&[u8], usize>, Error> {
        if self.fatal {
            return Err(Error::Unspecified(None));
        }
        self.fill(min.max(1)).map_err(Error::Io)?;
        let avail = self.end - self.start;
        if avail >= min.max(1) {
            Ok(Ok(&self.buf[self.start..self.end]))
        } else {
            Ok(Err(avail))
        }
    }

    /// Up to `len` bytes from the position, fewer where the archive ends:
    /// what `__archive_read_ahead(1)` makes available, as far as needed.
    pub(crate) fn peek(&mut self, len: usize) -> Result<&[u8], Error> {
        if self.fatal {
            return Err(Error::Unspecified(None));
        }
        self.fill(len).map_err(Error::Io)?;
        let n = (self.end - self.start).min(len);
        Ok(&self.buf[self.start..self.start + n])
    }

    /// Whether the archive has `n` bytes from the position. An input that
    /// cannot seek is read through to tell, as far as `n`: what was read
    /// is lost, which only a caller that fails either way may do.
    pub(crate) fn reaches(&mut self, n: u64) -> Result<bool, Error> {
        if self.fatal {
            return Err(Error::Unspecified(None));
        }
        if ((self.end - self.start) as u64) >= n {
            return Ok(true);
        }
        if self.seek.is_some() {
            let len = self.length().map_err(Error::Io)?;
            return Ok(len.saturating_sub(self.position) >= n);
        }
        let mut seen = (self.end - self.start) as u64;
        self.start = 0;
        self.end = 0;
        while seen < n {
            self.fill(1).map_err(Error::Io)?;
            if self.end == self.start {
                return Ok(false);
            }
            seen += (self.end - self.start) as u64;
            self.start = 0;
            self.end = 0;
        }
        Ok(true)
    }

    /// `__archive_read_consume`: moves the position forward by `request`.
    /// An archive that ends first is "Truncated input file (needed N bytes,
    /// only M available)", with the position at its end; a negative
    /// request is `ARCHIVE_FATAL` without a message.
    pub(crate) fn consume(&mut self, request: i64) -> Result<(), Error> {
        if request < 0 {
            return Err(Error::Unspecified(None));
        }
        if request == 0 {
            return Ok(());
        }
        if self.fatal {
            return Err(Error::Truncated {
                needed: request,
                available: 0,
            });
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
            let len = self.length().map_err(Error::Io)?;
            let base = self.base().map_err(Error::Io)?;
            let skip = left.min(len.saturating_sub(self.position));
            self.position += skip;
            seek(&mut self.r, SeekFrom::Start(base + self.position)).map_err(Error::Io)?;
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
            self.fill(1).map_err(Error::Io)?;
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

    /// The input's length from where reading began.
    fn length(&mut self) -> io::Result<u64> {
        if let Some(len) = self.len {
            return Ok(len);
        }
        let Some(seek) = self.seek else {
            return Ok(u64::MAX);
        };
        let base = self.base()?;
        let len = seek(&mut self.r, SeekFrom::End(0))?.saturating_sub(base);
        seek(
            &mut self.r,
            SeekFrom::Start(base + self.position + (self.end - self.start) as u64),
        )?;
        self.len = Some(len);
        Ok(len)
    }

    /// `__archive_read_seek` to `offset` (`SEEK_SET`): as libarchive's
    /// memory input, a place out of the archive fails it for good.
    pub(crate) fn seek(&mut self, offset: i64) -> Result<Seek, Error> {
        if self.fatal {
            return Ok(Seek::Fatal);
        }
        let Some(seek) = self.seek else {
            return Ok(Seek::Failed);
        };
        let len = self.length().map_err(Error::Io)?;
        self.start = 0;
        self.end = 0;
        self.eof = false;
        if offset < 0 || offset as u64 > len {
            self.fatal = true;
            return Ok(Seek::Fatal);
        }
        let base = self.base().map_err(Error::Io)?;
        seek(&mut self.r, SeekFrom::Start(base + offset as u64)).map_err(Error::Io)?;
        self.position = offset as u64;
        Ok(Seek::At(offset as u64))
    }
}
