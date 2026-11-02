//! Port of `zip_file_get_offset.c`.

use crate::zip::dirent::dirent_size;
use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::extra_field::EFBIG;
use crate::zip::open::Archive;
use crate::zip::source::{ReadAt, Source, Whence};
use crate::zip::zip::Flags;
use crate::zip::zipint::{DATADES_MAGIC, GPBF_DATA_DESCRIPTOR};

impl<R: ReadAt> Archive<R> {
    /// Where the data of entry `idx` starts, past its local header: port of
    /// `_zip_file_get_offset`.
    pub fn file_get_offset(&self, idx: u64) -> Result<u64> {
        let Some(orig) = self
            .entry
            .get(usize::try_from(idx).unwrap_or(usize::MAX))
            .and_then(|e| e.orig.as_deref())
        else {
            return Err(Error::new(ErrorCode::Internal, 0));
        };
        file_get_offset(&mut self.src.view(), orig.offset)
    }
}

/// Where the data starts of the entry whose local header is at `offset`:
/// the body of `_zip_file_get_offset`.
pub(crate) fn file_get_offset<R: ReadAt + ?Sized>(src: &mut Source<R>, offset: u64) -> Result<u64> {
    src.seek(offset as i64, Whence::Set)?;

    // TODO in libzip: cache?
    let size = dirent_size(src, true)?;

    if offset + u64::from(size) > i64::MAX as u64 {
        return Err(Error::new(ErrorCode::Seek, EFBIG));
    }

    Ok(offset + u64::from(size))
}

impl<R: ReadAt> Archive<R> {
    /// Where the data of entry `index` ends, with its data descriptor:
    /// port of `_zip_file_get_end`.
    pub(crate) fn file_get_end(&self, index: u64) -> Result<u64> {
        let offset = self.file_get_offset(index)?;
        let Some(entry) = self.entry[index as usize].orig.as_deref() else {
            return Err(Error::new(ErrorCode::Internal, 0));
        };

        let offset = match offset.checked_add(entry.comp_size) {
            Some(end) if end <= i64::MAX as u64 => end,
            _ => return Err(Error::new(ErrorCode::Seek, EFBIG)),
        };
        if entry.bitflags & GPBF_DATA_DESCRIPTOR == 0 {
            return Ok(offset);
        }

        let mut src = self.src.view();
        src.seek(offset as i64, Whence::Set)?;
        let mut buf = [0; 4];
        if src.read(&mut buf)? != 4 {
            // zip_error_set_from_source: the source's error, none for a
            // short read.
            return Err(Error::new(ErrorCode::Ok, 0));
        }
        let mut offset = offset;
        if &buf == DATADES_MAGIC {
            offset += 4;
        }
        offset += 12;
        if entry.needs_zip64(Flags::NONE) {
            offset += 8;
        }
        if offset > i64::MAX as u64 {
            return Err(Error::new(ErrorCode::Seek, EFBIG));
        }
        Ok(offset)
    }
}
