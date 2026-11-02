// hivepack::rar: a port of UnRAR 7.3.2 to Rust. UnRAR's license says:
//
// UnRAR source code may be used in any software to handle RAR archives
// without limitations free of charge, but cannot be used to develop RAR
// (WinRAR) compatible archiver and to re-create RAR compression algorithm,
// which is proprietary. Distribution of modified UnRAR source code in
// separate form or as a part of other software is permitted, provided that
// full text of this paragraph, starting from "UnRAR source code" words, is
// included in license, or in documentation if license is not available, and
// in source code comments of resulting package.

//! Where an archive is read from: anything read at an offset, with a
//! position kept as UnRAR's `File` keeps one (file.cpp).

use std::io;

/// Bytes read at an offset: a slice, a vector, or a file.
pub trait ReadAt {
    /// Reads at `offset` into `buf`: how many bytes, 0 at the end.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;
    /// How long it is.
    fn size(&self) -> io::Result<u64>;
}

impl ReadAt for [u8] {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(self.len());
        let n = buf.len().min(self.len() - start);
        buf[..n].copy_from_slice(&self[start..start + n]);
        Ok(n)
    }

    fn size(&self) -> io::Result<u64> {
        Ok(self.len() as u64)
    }
}

impl ReadAt for Vec<u8> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.as_slice().read_at(offset, buf)
    }

    fn size(&self) -> io::Result<u64> {
        Ok(self.len() as u64)
    }
}

impl<T: ReadAt + ?Sized> ReadAt for &T {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read_at(offset, buf)
    }

    fn size(&self) -> io::Result<u64> {
        (**self).size()
    }
}

impl ReadAt for std::fs::File {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            std::os::unix::fs::FileExt::read_at(self, buf, offset)
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::FileExt::seek_read(self, buf, offset)
        }
        #[cfg(not(any(unix, windows)))]
        {
            use std::io::{Read, Seek, SeekFrom};
            let mut file = self;
            file.seek(SeekFrom::Start(offset))?;
            file.read(buf)
        }
    }

    fn size(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }
}

/// A source and the position in it: UnRAR's `File` as `Archive` uses it,
/// `Seek`, `Tell` and `Read`.
pub(crate) struct Cursor<'a> {
    pub(crate) src: &'a dyn ReadAt,
    pub(crate) pos: &'a mut u64,
}

impl Cursor<'_> {
    /// Reads as much of `buf` as there is, from the position, and moves
    /// past it: `File::Read`, which reads until `buf` is full or the end.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut total = 0;
        while total < buf.len() {
            let n = self
                .src
                .read_at(self.pos.saturating_add(total as u64), &mut buf[total..])?;
            if n == 0 {
                break;
            }
            total += n;
        }
        *self.pos = self.pos.saturating_add(total as u64);
        Ok(total)
    }
}
