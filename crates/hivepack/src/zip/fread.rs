//! Port of `zip_fread.c`.

use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::fopen_index_encrypted::ZipFile;
use crate::zip::source::ReadAt;

impl<R: ReadAt + ?Sized> ZipFile<'_, R> {
    /// Reads up to `outbuf.len()` bytes, fewer only at the end of the
    /// entry, or where an error stops it: port of `zip_fread`. Once a read
    /// fails, every later one fails with the same error. A CRC-32 or length
    /// that does not match fails the read after the last byte.
    pub fn fread(&mut self, outbuf: &mut [u8]) -> Result<usize> {
        if self.error.is_set() {
            return Err(self.error);
        }
        if outbuf.is_empty() {
            return Ok(0);
        }
        let Some(src) = self.src.as_mut() else {
            return Err(Error::new(ErrorCode::Inval, 0));
        };
        match src.read(outbuf) {
            Ok(n) => Ok(n),
            Err(e) => {
                self.error = e;
                Err(e)
            }
        }
    }
}

impl<R: ReadAt + ?Sized> std::io::Read for ZipFile<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.fread(buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}
