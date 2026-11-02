//! An entry of an archive as the new data of an entry of another: port of
//! `zip_source_zip.c` (`zip_source_zip_file`).
//!
//! Differs from libzip: the entry is read once, in whole, the first time
//! its data is asked for, so that it can be read at any position.

use std::sync::{Arc, OnceLock};

use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::source_data::{DataSource, FileAttributes};
use crate::zip::zip::{Flags, Stat};

/// Entry `index` of an archive, as new data: its data decompressed, or as
/// stored with [`Flags::COMPRESSED`], in which case it is copied as it is
/// when its method is kept. Port of `zip_source_zip_file`.
pub struct ZipFileSource<R> {
    archive: Arc<Archive<R>>,
    index: u64,
    flags: Flags,
    start: u64,
    len: i64,
    stat: Stat<'static>,
    attributes: FileAttributes,
    dos_time: Option<(u16, u16)>,
    /// the data, and the stat once read, as the stack gives them
    read: OnceLock<std::result::Result<(Vec<u8>, Stat<'static>), Error>>,
}

impl<R: ReadAt> ZipFileSource<R> {
    /// `len` bytes of entry `index` of `archive` from `start` (the rest if
    /// `None`), as `flags` ask: `zip_source_zip_file`. It fails as
    /// `zip_source_zip_file_create` fails, with `ZIP_ER_CHANGED` for an
    /// entry deleted, or raw with new data.
    pub fn new(
        archive: Arc<Archive<R>>,
        index: u64,
        flags: Flags,
        start: u64,
        len: Option<u64>,
    ) -> Result<ZipFileSource<R>> {
        let len = match len {
            Some(len) => i64::try_from(len).map_err(|_| Error::new(ErrorCode::Inval, 0))?,
            None => -1,
        };
        let stack = archive.source_zip_file_create(index, flags, start, len, None)?;
        let stat = stack.stat()?;
        let attributes = stack.file_attributes()?;
        let dos_time = stack.dos_time();
        drop(stack);
        Ok(ZipFileSource {
            archive,
            index,
            flags,
            start,
            len,
            stat,
            attributes,
            dos_time,
            read: OnceLock::new(),
        })
    }

    /// Reads the entry through its stack, as `copy_source` would; closing
    /// fails nothing.
    fn read_all(&self) -> std::result::Result<(Vec<u8>, Stat<'static>), Error> {
        let mut stack = self
            .archive
            .source_zip_file_create(self.index, self.flags, self.start, self.len, None)?;
        stack.open()?;
        let mut data = Vec::new();
        let mut buf = vec![0; 8192];
        loop {
            match stack.read(&mut buf)? {
                0 => break,
                n => data.extend_from_slice(&buf[..n]),
            }
        }
        let stat = stack.stat()?;
        let _ = stack.close();
        Ok((data, stat))
    }
}

impl<R: ReadAt + Send + Sync> DataSource for ZipFileSource<R> {
    /// The stat of the entry's stack: as it is before the entry is read,
    /// and after, with what reading found.
    fn stat(&self) -> Result<Stat<'static>> {
        match self.read.get() {
            Some(Ok((_, stat))) => Ok(*stat),
            _ => Ok(self.stat),
        }
    }

    fn file_attributes(&self) -> Result<FileAttributes> {
        Ok(self.attributes)
    }

    fn dos_time(&self) -> Result<Option<(u16, u16)>> {
        Ok(self.dos_time)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let (data, _) = self
            .read
            .get_or_init(|| self.read_all())
            .as_ref()
            .map_err(|e| *e)?;
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(data.len());
        let n = buf.len().min(data.len() - start);
        buf[..n].copy_from_slice(&data[start..start + n]);
        Ok(n)
    }
}
