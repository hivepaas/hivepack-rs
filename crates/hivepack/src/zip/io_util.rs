//! Reading exact lengths: port of `zip_io_util.c`, the reading half.

use crate::zip::buffer::Buffer;
use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::source::{ReadAt, Source};
use crate::zip::string::ZipString;
use crate::zip::zip::Flags;

/// Fills `b` from `src`, or fails with `ZIP_ER_EOF` if the source ends
/// first: port of `_zip_read`.
pub(crate) fn read<R: ReadAt + ?Sized>(src: &mut Source<R>, b: &mut [u8]) -> Result<()> {
    let n = src.read(b)?;
    if n < b.len() {
        return Err(Error::new(ErrorCode::Eof, 0));
    }
    Ok(())
}

/// `length` bytes, from `buffer` if there is one, else from `src`: port of
/// `_zip_read_data`. Differs from libzip: no terminating NUL is added, and
/// the callers never ask for nothing.
pub(crate) fn read_data<R: ReadAt + ?Sized>(
    buffer: Option<&mut Buffer<'_>>,
    src: &mut Source<R>,
    length: usize,
) -> Result<Vec<u8>> {
    match buffer {
        Some(buffer) => match buffer.get(length as u64) {
            Some(data) => Ok(data.to_vec()),
            None => Err(Error::new(ErrorCode::Memory, 0)),
        },
        None => {
            let mut r = vec![0; length];
            read(src, &mut r)?;
            Ok(r)
        }
    }
}

/// A string of `len` bytes, its encoding to be guessed: port of
/// `_zip_read_string`. `len` is never 0.
pub(crate) fn read_string<R: ReadAt + ?Sized>(
    buffer: Option<&mut Buffer<'_>>,
    src: &mut Source<R>,
    len: u16,
) -> Result<Option<ZipString>> {
    match buffer {
        Some(buffer) => match buffer.get(u64::from(len)) {
            Some(raw) => ZipString::new(raw, Flags::ENC_GUESS),
            None => Err(Error::new(ErrorCode::Memory, 0)),
        },
        None => ZipString::new(&read_data(None, src, usize::from(len))?, Flags::ENC_GUESS),
    }
}
