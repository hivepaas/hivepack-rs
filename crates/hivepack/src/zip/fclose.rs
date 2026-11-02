//! Port of `zip_fclose.c`.

use crate::zip::error::Result;
use crate::zip::fopen_index_encrypted::ZipFile;
use crate::zip::source::ReadAt;

impl<R: ReadAt + ?Sized> ZipFile<'_, R> {
    /// Closes the entry: port of `zip_fclose`. Fails with the error of the
    /// last failed read, if any, or of closing: an entry read to its last
    /// byte, but not past it, has its CRC-32 and length checked here.
    pub fn fclose(mut self) -> Result<()> {
        if let Some(mut src) = self.src.take()
            && let Err(e) = src.close()
        {
            self.error = e;
        }
        if self.error.is_set() {
            Err(self.error)
        } else {
            Ok(())
        }
    }
}
