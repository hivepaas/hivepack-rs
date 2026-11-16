//! The block device a disk image holds: a size, and reads at offsets.

use std::io;

/// A disk: as many bytes as it is long, read wherever asked. A raw image
/// (`.img`, a `dd` of a card) is one as it is; a container that holds a disk
/// in less room than it is long presents one.
///
/// Reads are at offsets and never move a position, so one disk can be read
/// from more than one thread, as the file systems inside it are read.
pub trait Disk {
    /// How many bytes the disk holds.
    fn size(&self) -> io::Result<u64>;

    /// Reads at `at` into `buf`, as many bytes as there are, up to its
    /// length. Fewer only at the disk's end.
    fn read_at(&self, at: u64, buf: &mut [u8]) -> io::Result<usize>;

    /// Reads at `at` to fill `buf`, and fails where the disk ends first:
    /// what reads a structure of a size the format fixes.
    fn read_exact_at(&self, at: u64, buf: &mut [u8]) -> io::Result<()> {
        if self.read_at(at, buf)? == buf.len() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the disk ends inside what was to be read",
            ))
        }
    }
}

impl<T: Disk + ?Sized> Disk for &T {
    fn size(&self) -> io::Result<u64> {
        (**self).size()
    }

    fn read_at(&self, at: u64, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read_at(at, buf)
    }
}

impl Disk for [u8] {
    fn size(&self) -> io::Result<u64> {
        Ok(self.len() as u64)
    }

    fn read_at(&self, at: u64, buf: &mut [u8]) -> io::Result<usize> {
        let Ok(at) = usize::try_from(at) else {
            return Ok(0);
        };
        let Some(from) = self.get(at.min(self.len())..) else {
            return Ok(0);
        };
        let n = from.len().min(buf.len());
        buf[..n].copy_from_slice(&from[..n]);
        Ok(n)
    }
}

impl Disk for Vec<u8> {
    fn size(&self) -> io::Result<u64> {
        self.as_slice().size()
    }

    fn read_at(&self, at: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.as_slice().read_at(at, buf)
    }
}

#[cfg(any(unix, windows))]
impl Disk for std::fs::File {
    fn size(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }

    fn read_at(&self, at: u64, buf: &mut [u8]) -> io::Result<usize> {
        let mut done = 0;
        while done < buf.len() {
            #[cfg(unix)]
            let n = std::os::unix::fs::FileExt::read_at(self, &mut buf[done..], at + done as u64);
            #[cfg(windows)]
            let n =
                std::os::windows::fs::FileExt::seek_read(self, &mut buf[done..], at + done as u64);
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

/// One partition of a disk, as a disk of its own: what the file system in it
/// is read from, which then sees nothing of the rest.
pub struct Part<D> {
    disk: D,
    at: u64,
    size: u64,
}

impl<D: Disk> Part<D> {
    /// The `size` bytes at `at` of `disk`.
    pub fn new(disk: D, at: u64, size: u64) -> Part<D> {
        Part { disk, at, size }
    }
}

impl<D: Disk> Disk for Part<D> {
    fn size(&self) -> io::Result<u64> {
        Ok(self.size)
    }

    fn read_at(&self, at: u64, buf: &mut [u8]) -> io::Result<usize> {
        let Some(left) = self.size.checked_sub(at) else {
            return Ok(0);
        };
        let want = (buf.len() as u64).min(left) as usize;
        if want == 0 {
            return Ok(0);
        }
        self.disk.read_at(self.at + at, &mut buf[..want])
    }
}
