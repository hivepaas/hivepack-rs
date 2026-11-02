//! What an archive is read from.
//!
//! libzip reads an archive through a `zip_source_t`, a stack of callbacks
//! with a position. The port reads through [`ReadAt`], reads at a position,
//! and [`Source`] keeps the position and the rules libzip's file and buffer
//! sources follow: port of the reading parts of `zip_source_seek.c`,
//! `zip_source_read.c`, `zip_source_tell.c`, `zip_source_stat.c` and
//! `zip_source_accept_empty.c`, with the commands of
//! `zip_source_file_common.c` and `zip_source_buffer.c`.

use std::io;

use crate::zip::error::{Error, ErrorCode, Result};

/// Something an archive can be read from, at any position.
///
/// Reads may run in parallel: they take `&self`.
pub trait ReadAt {
    /// The length in bytes, read once when an archive is opened, as
    /// libzip's sources `stat` it.
    fn size(&self) -> io::Result<u64>;

    /// Reads bytes at `offset` into `buf`, as many as there are, up to its
    /// length. Fewer only at the end.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;

    /// Whether an empty source is an empty archive: `ZIP_SOURCE_ACCEPT_EMPTY`.
    /// libzip's file sources say no, so `zip_open` refuses an empty file as
    /// not a zip archive, and its buffer sources say yes.
    fn accept_empty(&self) -> bool {
        false
    }

    /// Not in libzip: where each volume starts, for a source that joins
    /// the volumes of a split archive ([`Volumes`](crate::zip::Volumes)), whose
    /// disk numbers are then read as those volumes. `None` for a source in
    /// one piece, where an archive of several disks is refused with
    /// `ZIP_ER_MULTIDISK`, as libzip refuses it.
    fn volume_starts(&self) -> Option<&[u64]> {
        None
    }
}

impl ReadAt for [u8] {
    fn size(&self) -> io::Result<u64> {
        Ok(self.len() as u64)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(self.len());
        let n = buf.len().min(self.len() - start);
        buf[..n].copy_from_slice(&self[start..start + n]);
        Ok(n)
    }

    fn accept_empty(&self) -> bool {
        true
    }
}

impl ReadAt for Vec<u8> {
    fn size(&self) -> io::Result<u64> {
        self.as_slice().size()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.as_slice().read_at(offset, buf)
    }

    fn accept_empty(&self) -> bool {
        true
    }
}

impl<T: ReadAt + ?Sized> ReadAt for &T {
    fn size(&self) -> io::Result<u64> {
        (**self).size()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read_at(offset, buf)
    }

    fn accept_empty(&self) -> bool {
        (**self).accept_empty()
    }

    fn volume_starts(&self) -> Option<&[u64]> {
        (**self).volume_starts()
    }
}

#[cfg(any(unix, windows))]
impl ReadAt for std::fs::File {
    fn size(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let mut done = 0;
        while done < buf.len() {
            #[cfg(unix)]
            let n =
                std::os::unix::fs::FileExt::read_at(self, &mut buf[done..], offset + done as u64);
            #[cfg(windows)]
            let n = std::os::windows::fs::FileExt::seek_read(
                self,
                &mut buf[done..],
                offset + done as u64,
            );
            match n {
                Ok(0) => break,
                Ok(n) => done += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(done)
    }
}

/// Where a seek counts from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Whence {
    Set,
    Cur,
    End,
}

/// The least and the most [`Source`] reads ahead at a time.
const READ_AHEAD_MIN: usize = 1 << 12;
const READ_AHEAD_MAX: usize = 1 << 20;

/// What was read past what was asked for, while an archive is opened.
///
/// Differs from libzip, which leaves this to `stdio`: without it, each central
/// directory entry would be a system call or two, as `ReadAt` is `pread`.
#[derive(Clone)]
pub(crate) struct ReadAhead {
    buf: Vec<u8>,
    start: u64,
    /// How much of `buf` is the source's, from `start`.
    len: usize,
    /// How much the last read asked for: twice as much each time reads go on
    /// from where it ended, back to the least when they go elsewhere.
    size: usize,
}

/// An archive's source while it is read: its length when opened, the
/// position, and whether a read has failed.
#[derive(Clone)]
pub(crate) struct Source<R: ?Sized> {
    /// The length the source had when opened (`ctx->len`); reads stop
    /// there.
    size: u64,
    offset: u64,
    /// The error of a failed read: libzip's sources fail every read after
    /// one (`had_read_error`).
    read_error: Option<Error>,
    ahead: Option<ReadAhead>,
    inner: R,
}

impl<R: ReadAt> Source<R> {
    /// The source, of `size` bytes, as `stat` gives it.
    pub(crate) fn with_size(inner: R, size: u64) -> Source<R> {
        Source {
            size,
            offset: 0,
            read_error: None,
            ahead: None,
            inner,
        }
    }
}

/// The length of `inner`: `zip_source_stat`, with the error of libzip's
/// file sources.
pub(crate) fn stat<R: ReadAt + ?Sized>(inner: &R) -> Result<u64> {
    inner.size().map_err(read_error)
}

impl<R: ReadAt + ?Sized> Source<R> {
    /// The same source with a position of its own, for one reader of the
    /// archive's data. libzip's readers share the archive's source and
    /// seek it before each read; a view does the same without sharing.
    /// Differs from libzip: a failed read fails only that view's later
    /// reads.
    pub(crate) fn view(&self) -> Source<&R> {
        Source {
            size: self.size,
            offset: 0,
            read_error: self.read_error,
            ahead: None,
            inner: &self.inner,
        }
    }

    /// [`Source::view`], which goes on with what another view read ahead, so
    /// that what is read in order across entries is a read now and then.
    pub(crate) fn view_with(&self, ahead: Option<ReadAhead>) -> Source<&R> {
        let mut view = self.view();
        view.ahead = ahead;
        view
    }

    /// Reads ahead from now on, if it does not yet.
    pub(crate) fn ensure_read_ahead(&mut self) {
        if self.ahead.is_none() {
            self.start_read_ahead();
        }
    }

    /// What was read ahead, for the next view.
    pub(crate) fn take_read_ahead(&mut self) -> Option<ReadAhead> {
        self.ahead.take()
    }

    /// Reads ahead from now on, until [`Source::stop_read_ahead`].
    pub(crate) fn start_read_ahead(&mut self) {
        self.ahead = Some(ReadAhead {
            buf: Vec::new(),
            start: 0,
            len: 0,
            size: READ_AHEAD_MIN,
        });
    }

    /// Goes back to reading only what is asked for.
    pub(crate) fn stop_read_ahead(&mut self) {
        self.ahead = None;
    }

    /// As much as can be of `buf`, from what was read ahead or by reading
    /// ahead. A failure is not kept: it comes again to the read that gets past
    /// what this leaves, as it would without reading ahead.
    fn read_through_ahead(&mut self, buf: &mut [u8]) -> usize {
        let Some(ahead) = &mut self.ahead else {
            return 0;
        };
        let mut done = 0;
        while done < buf.len() {
            let from = self.offset.wrapping_sub(ahead.start);
            if self.offset >= ahead.start && from < ahead.len as u64 {
                let from = from as usize;
                let n = (ahead.len - from).min(buf.len() - done);
                buf[done..done + n].copy_from_slice(&ahead.buf[from..from + n]);
                done += n;
                self.offset += n as u64;
                continue;
            }
            ahead.size = if self.offset == ahead.start + ahead.len as u64 {
                (ahead.size * 2).min(READ_AHEAD_MAX)
            } else {
                READ_AHEAD_MIN
            };
            let want = (ahead.size as u64).min(self.size - self.offset) as usize;
            if buf.len() - done >= want {
                // No use in copying it.
                break;
            }
            ahead.buf.resize(want, 0);
            ahead.start = self.offset;
            ahead.len = 0;
            while ahead.len < want {
                let at = ahead.start + ahead.len as u64;
                match self.inner.read_at(at, &mut ahead.buf[ahead.len..want]) {
                    Ok(got) if got > 0 => ahead.len += got,
                    _ => break,
                }
            }
            if ahead.len == 0 {
                break;
            }
        }
        done
    }

    /// `st.size` of `zip_source_stat`.
    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    /// `zip_source_accept_empty`.
    pub(crate) fn accept_empty(&self) -> bool {
        self.inner.accept_empty()
    }

    /// Not in libzip: where each volume of a split archive starts, if the
    /// source joins them.
    pub(crate) fn volume_starts(&self) -> Option<Vec<u64>> {
        self.inner.volume_starts().map(<[u64]>::to_vec)
    }

    /// Moves the position: port of `zip_source_seek`, with
    /// `zip_source_seek_compute_offset` and `_zip_offset_add`. A position
    /// before the start or past the end is refused with `ZIP_ER_INVAL`.
    pub(crate) fn seek(&mut self, offset: i64, whence: Whence) -> Result<()> {
        let new_offset = match whence {
            Whence::Cur => offset_add(self.offset, offset),
            Whence::End => offset_add(self.size, offset),
            Whence::Set => u64::try_from(offset).ok().filter(|&o| o <= self.size),
        };
        match new_offset {
            Some(new_offset) if new_offset <= self.size => {
                self.offset = new_offset;
                Ok(())
            }
            _ => Err(Error::new(ErrorCode::Inval, 0)),
        }
    }

    /// `zip_source_tell`.
    pub(crate) fn tell(&self) -> u64 {
        self.offset
    }

    /// Reads up to `buf.len()` bytes, fewer only at the end: port of
    /// `zip_source_read`, and the file source's `ZIP_SOURCE_READ`, which
    /// stops at the length the file had when opened.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if let Some(error) = self.read_error {
            return Err(error);
        }
        let n = (buf.len() as u64).min(self.size - self.offset) as usize;
        let mut done = self.read_through_ahead(&mut buf[..n]);
        while done < n {
            match self.inner.read_at(self.offset, &mut buf[done..n]) {
                Ok(0) => break,
                Ok(got) => {
                    done += got;
                    self.offset += got as u64;
                }
                Err(e) => {
                    let error = read_error(e);
                    self.read_error = Some(error);
                    if done == 0 {
                        return Err(error);
                    }
                    break;
                }
            }
        }
        Ok(done)
    }
}

/// `_zip_offset_add`: `None` where libzip gives `ZIP_UINT64_MAX`.
fn offset_add(offset: u64, delta: i64) -> Option<u64> {
    if delta >= 0 {
        let delta = delta as u64;
        if offset > i64::MAX as u64 - delta {
            return None;
        }
        Some(offset + delta)
    } else {
        offset.checked_sub(delta.unsigned_abs())
    }
}

/// A failed read, as the file source reports it: `ZIP_ER_READ` with
/// `errno`.
fn read_error(error: io::Error) -> Error {
    Error::new(ErrorCode::Read, error.raw_os_error().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeks_as_libzip() {
        let data = [0u8; 10];
        let mut src = Source::with_size(&data[..], data.len() as u64);
        assert!(src.seek(-4, Whence::End).is_ok());
        assert_eq!(src.tell(), 6);
        let mut buf = [0; 8];
        assert_eq!(src.read(&mut buf).ok(), Some(4));
        assert_eq!(src.read(&mut buf).ok(), Some(0));
        assert_eq!(
            src.seek(11, Whence::Set).map_err(|e| e.code()),
            Err(ErrorCode::Inval)
        );
        assert_eq!(
            src.seek(-11, Whence::End).map_err(|e| e.code()),
            Err(ErrorCode::Inval)
        );
        assert_eq!(
            src.seek(1, Whence::Cur).map_err(|e| e.code()),
            Err(ErrorCode::Inval)
        );
        assert!(src.seek(0, Whence::Set).is_ok());
        assert!(src.seek(i64::MIN, Whence::Cur).is_err());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod read_ahead_tests {
    use super::*;

    /// A source of `len` bytes that gives at most `most` at a time, and fails
    /// at `fails_at` and past it.
    struct Flaky {
        len: u64,
        most: usize,
        fails_at: u64,
    }

    impl ReadAt for Flaky {
        fn size(&self) -> io::Result<u64> {
            Ok(self.len)
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            if offset >= self.fails_at {
                return Err(io::Error::other("a failure"));
            }
            let n = (self.fails_at - offset)
                .min(self.len - offset)
                .min(self.most as u64) as usize;
            let n = n.min(buf.len());
            for (i, byte) in buf[..n].iter_mut().enumerate() {
                *byte = ((offset + i as u64) % 251) as u8;
            }
            Ok(n)
        }
    }

    /// Reading ahead changes nothing a reader can see: not the bytes, the
    /// position, the end, or where a failure comes and that it stays.
    #[test]
    fn reading_ahead_gives_the_same_as_not() {
        let mut state = 0x5eed_u64;
        let mut next = move |below: u64| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) % below
        };
        for round in 0..200 {
            let len = 1 + next(1 << 21);
            let source = |fails_at| Flaky {
                len,
                most: 1 + (round % 7) * 1000,
                fails_at,
            };
            let fails_at = if round % 3 == 0 { next(len) } else { u64::MAX };
            let mut plain = Source::with_size(source(fails_at), len);
            let mut ahead = Source::with_size(source(fails_at), len);
            ahead.start_read_ahead();
            for _ in 0..300 {
                if next(10) == 0 {
                    let to = next(len + 1) as i64;
                    plain.seek(to, Whence::Set).unwrap();
                    ahead.seek(to, Whence::Set).unwrap();
                }
                let size = match next(4) {
                    0 => 46,
                    1 => next(200) as usize,
                    2 => next(20_000) as usize,
                    _ => next(3 << 20) as usize,
                };
                let (mut a, mut b) = (vec![0; size], vec![0; size]);
                let (got_plain, got_ahead) = (plain.read(&mut a), ahead.read(&mut b));
                match (got_plain, got_ahead) {
                    (Ok(x), Ok(y)) => {
                        assert_eq!(x, y);
                        assert_eq!(a[..x], b[..y]);
                    }
                    (Err(x), Err(y)) => assert_eq!(x.code(), y.code()),
                    (x, y) => panic!("{:?} and {:?}", x.is_ok(), y.is_ok()),
                }
                assert_eq!(plain.tell(), ahead.tell());
            }
        }
    }
}
