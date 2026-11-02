//! A part of another source, the entry's data in the archive or its new
//! data: port of `zip_source_window.c`, for reading.

use std::sync::Arc;

use crate::zip::error::{Detail, Error, ErrorCode, Result};
use crate::zip::file_get_offset::file_get_offset;
use crate::zip::source::{ReadAt, Source, Whence};
use crate::zip::source_data::{DataSource, FileAttributes};
use crate::zip::zip::{Stat, stat, stat_merge};

/// What a window reads from: the archive, the empty buffer libzip makes for
/// an entry with no data, or an entry's new data.
pub(crate) enum Lower<'a, R: ?Sized> {
    Archive(Source<&'a R>),
    Empty,
    Data {
        source: Arc<dyn DataSource>,
        offset: u64,
    },
}

impl<R: ReadAt + ?Sized> Lower<'_, R> {
    /// The length the lower source's `zip_source_stat` gives, if it gives
    /// one.
    pub(crate) fn known_size(&self) -> Option<u64> {
        match self {
            Lower::Archive(src) => Some(src.size()),
            Lower::Empty => Some(0),
            Lower::Data { .. } => {
                let st = self.stat();
                (st.valid & stat::SIZE != 0).then_some(st.size)
            }
        }
    }

    /// `zip_source_stat` of the lower source, for the window to merge its
    /// own over: the length of the archive or empty buffer, or what the new
    /// data says, nothing if that fails. A buffer source, which takes an
    /// empty buffer for an empty archive (`ZIP_SOURCE_ACCEPT_EMPTY`), gives
    /// its length as the compressed size too, stored and not encrypted; a
    /// file source only its length. The window replaces them all but where
    /// the entry's compression method was changed, which leaves its
    /// compressed size unknown: a layer that decrypts then takes the
    /// buffer's length (the time either gives is always replaced).
    pub(crate) fn stat(&self) -> Stat<'static> {
        match self {
            Lower::Archive(src) if src.accept_empty() => Stat {
                valid: stat::SIZE | stat::COMP_SIZE | stat::COMP_METHOD | stat::ENCRYPTION_METHOD,
                size: src.size(),
                comp_size: src.size(),
                comp_method: crate::zip::zip::cm::STORE,
                encryption_method: crate::zip::zip::em::NONE,
                ..Stat::default()
            },
            Lower::Archive(src) => Stat {
                valid: stat::SIZE,
                size: src.size(),
                ..Stat::default()
            },
            Lower::Empty => Stat {
                valid: stat::SIZE,
                ..Stat::default()
            },
            Lower::Data { source, .. } => source.stat().unwrap_or_default(),
        }
    }

    /// `zip_source_get_file_attributes` of the lower source: those of the
    /// new data, none of the archive's.
    pub(crate) fn file_attributes(&self) -> Result<FileAttributes> {
        match self {
            Lower::Data { source, .. } => source.file_attributes(),
            _ => Ok(FileAttributes::default()),
        }
    }

    fn seek(&mut self, to: u64) -> Result<()> {
        match self {
            Lower::Archive(src) => src.seek(to as i64, Whence::Set),
            Lower::Empty if to == 0 => Ok(()),
            Lower::Empty => Err(Error::new(ErrorCode::Inval, 0)),
            Lower::Data { source, offset } => {
                if let Ok(st) = source.stat()
                    && st.valid & stat::SIZE != 0
                    && to > st.size
                {
                    return Err(Error::new(ErrorCode::Inval, 0));
                }
                *offset = to;
                Ok(())
            }
        }
    }

    fn read(&mut self, data: &mut [u8]) -> Result<usize> {
        match self {
            Lower::Archive(src) => src.read(data),
            Lower::Empty => Ok(0),
            Lower::Data { source, offset } => {
                let n = source.read_at(*offset, data)?;
                *offset += n as u64;
                Ok(n)
            }
        }
    }
}

/// `struct window`: where the data starts and ends, the entry it belongs
/// to until it is opened, and the stat it adds.
pub(crate) struct Window {
    /// where in file we start reading
    start: u64,
    /// where in file we stop reading
    end: u64,
    /// whether end is set, otherwise read until EOF
    end_valid: bool,
    /// if set, read file data for the entry whose local header is here
    source_archive: Option<u64>,
    /// offset in src for next read
    offset: u64,
    stat: Stat<'static>,
    stat_invalid: u64,
    attributes: FileAttributes,
    /// the time as stored, which the window gives if set
    dostime: Option<(u16, u16)>,
    pub(crate) error: Error,
}

impl Window {
    /// A window on `lower` from `start`, `length` bytes long (or to the end
    /// if -1), with `st` as its stat but for `st_invalid`, and the
    /// `attributes` and DOS time it gives. With `source_archive`, the local
    /// header at that offset is skipped when the window opens. Port of
    /// `_zip_source_window_new`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new<R: ReadAt + ?Sized>(
        lower: &Lower<'_, R>,
        start: u64,
        length: i64,
        st: &Stat<'_>,
        st_invalid: u64,
        attributes: FileAttributes,
        dostime: Option<(u16, u16)>,
        source_archive: Option<u64>,
    ) -> Result<Window> {
        if length < -1 {
            return Err(Error::new(ErrorCode::Inval, 0));
        }
        if length > 0 && start.checked_add(length as u64).is_none() {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        if let Some(lower_size) = lower.known_size()
            && (start > lower_size || (length > 0 && start + length as u64 > lower_size))
        {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        let mut stat = Stat::default();
        stat_merge(&mut stat, st);
        Ok(Window {
            start,
            end: if length == -1 {
                0
            } else {
                start + length as u64
            },
            end_valid: length != -1,
            source_archive,
            offset: 0,
            stat,
            stat_invalid: st_invalid,
            attributes,
            dostime,
            error: Error::OK,
        })
    }

    /// `ZIP_SOURCE_GET_FILE_ATTRIBUTES`.
    pub(crate) fn file_attributes(&self) -> FileAttributes {
        self.attributes
    }

    /// `ZIP_SOURCE_GET_DOS_TIME`.
    pub(crate) fn dos_time(&self) -> Option<(u16, u16)> {
        self.dostime
    }

    /// `ZIP_SOURCE_OPEN`: past the local header, for an entry's data.
    pub(crate) fn open<R: ReadAt + ?Sized>(
        &mut self,
        lower: &mut Lower<'_, R>,
        index: u64,
    ) -> Result<()> {
        if let Some(header) = self.source_archive {
            let Lower::Archive(src) = lower else {
                self.error = Error::new(ErrorCode::Internal, 0);
                return Err(self.error);
            };
            let offset = match file_get_offset(src, header) {
                Ok(offset) => offset,
                Err(e) => {
                    self.error = e;
                    return Err(e);
                }
            };
            if self.end_valid {
                let Some(end) = self.end.checked_add(offset) else {
                    // zip archive data claims end of data past zip64 limits
                    self.error = Error::incons_at(Detail::CdirEntryInvalid, index);
                    return Err(self.error);
                };
                self.end = end;
            }
            self.start += offset;
            self.source_archive = None;
        }
        // The lower sources can seek, so nothing is skipped by reading.
        self.offset = self.start;
        Ok(())
    }

    /// `ZIP_SOURCE_READ`.
    pub(crate) fn read<R: ReadAt + ?Sized>(
        &mut self,
        lower: &mut Lower<'_, R>,
        data: &mut [u8],
    ) -> Result<usize> {
        let mut len = data.len() as u64;
        if self.end_valid && len > self.end - self.offset {
            len = self.end - self.offset;
        }
        if len == 0 {
            return Ok(0);
        }

        if let Err(e) = lower.seek(self.offset) {
            // We validated ctx->offset in ZIP_SEEK.
            self.error = if e.code() == ErrorCode::Inval {
                Error::new(ErrorCode::Eof, 0)
            } else {
                e
            };
            return Err(self.error);
        }

        let ret = match lower.read(&mut data[..len as usize]) {
            Ok(ret) => ret,
            Err(e) => {
                self.error = e;
                return Err(e);
            }
        };
        if ret == 0 && self.end_valid && self.offset < self.end {
            self.error = Error::new(ErrorCode::Eof, 0);
            return Err(self.error);
        }
        self.offset += ret as u64;
        Ok(ret)
    }

    /// `ZIP_SOURCE_STAT`, on the lower source's stat.
    pub(crate) fn stat(&self, st: &mut Stat<'_>) {
        stat_merge(st, &self.stat);
        if self.stat.valid & stat::SIZE == 0 {
            if self.end_valid {
                st.valid |= stat::SIZE;
                st.size = self.end - self.start;
            } else if st.valid & stat::SIZE != 0 {
                if st.size < self.start {
                    st.valid &= !stat::SIZE;
                } else {
                    st.size -= self.start;
                }
            }
        }
        st.valid &= !self.stat_invalid;
    }

    /// `ZIP_SOURCE_AT_EOF`, which a window with an end answers itself.
    pub(crate) fn at_eof(&self) -> Option<bool> {
        self.end_valid.then_some(self.offset == self.end)
    }
}

/// `BUFSIZE`: the pieces a window that cannot seek skips in.
const BUFSIZE: usize = 8192;

/// A window on the decompressed data, for part of an entry: the same
/// `struct window` on a source that cannot seek, which skips to the start
/// by reading.
pub(crate) struct UpperWindow {
    start: u64,
    end: u64,
    end_valid: bool,
    offset: u64,
    pub(crate) error: Error,
}

impl UpperWindow {
    /// Port of `_zip_source_window_new`, on a lower source of `lower_size`
    /// bytes if it is known, with no stat, attributes or DOS time of its
    /// own.
    /// `ZIP_SOURCE_STAT`, on the lower source's stat: the length of the
    /// part, or what is left past the start.
    pub(crate) fn stat(&self, st: &mut Stat<'_>) {
        if self.end_valid {
            st.valid |= stat::SIZE;
            st.size = self.end - self.start;
        } else if st.valid & stat::SIZE != 0 {
            if st.size < self.start {
                st.valid &= !stat::SIZE;
            } else {
                st.size -= self.start;
            }
        }
    }

    pub(crate) fn new(lower_size: Option<u64>, start: u64, length: i64) -> Result<UpperWindow> {
        if length < -1 {
            return Err(Error::new(ErrorCode::Inval, 0));
        }
        if length > 0 && start.checked_add(length as u64).is_none() {
            return Err(Error::new(ErrorCode::Inval, 0));
        }
        if let Some(size) = lower_size
            && (start > size || (length > 0 && start + length as u64 > size))
        {
            return Err(Error::new(ErrorCode::Inval, 0));
        }
        Ok(UpperWindow {
            start,
            end: if length == -1 {
                0
            } else {
                start + length as u64
            },
            end_valid: length != -1,
            offset: 0,
            error: Error::OK,
        })
    }

    /// `ZIP_SOURCE_OPEN`: the bytes before the start read and dropped, as
    /// the lower source cannot seek.
    pub(crate) fn open(&mut self, lower: &mut dyn FnMut(&mut [u8]) -> Result<usize>) -> Result<()> {
        let mut b = vec![0; BUFSIZE];
        let mut n = 0;
        while n < self.start {
            let i = (self.start - n).min(BUFSIZE as u64) as usize;
            match lower(&mut b[..i]) {
                Err(e) => {
                    self.error = e;
                    return Err(e);
                }
                Ok(0) => {
                    self.error = Error::new(ErrorCode::Eof, 0);
                    return Err(self.error);
                }
                Ok(ret) => n += ret as u64,
            }
        }
        self.offset = self.start;
        Ok(())
    }

    /// `ZIP_SOURCE_READ`, without seeking.
    pub(crate) fn read(
        &mut self,
        data: &mut [u8],
        lower: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
    ) -> Result<usize> {
        let mut len = data.len() as u64;
        if self.end_valid && len > self.end - self.offset {
            len = self.end - self.offset;
        }
        if len == 0 {
            return Ok(0);
        }
        let ret = match lower(&mut data[..len as usize]) {
            Ok(ret) => ret,
            Err(e) => {
                self.error = e;
                return Err(e);
            }
        };
        if ret == 0 && self.end_valid && self.offset < self.end {
            self.error = Error::new(ErrorCode::Eof, 0);
            return Err(self.error);
        }
        self.offset += ret as u64;
        Ok(ret)
    }
}
