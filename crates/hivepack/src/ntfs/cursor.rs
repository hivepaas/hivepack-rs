//! A [`Disk`] as the `Read` and `Seek` the library asks for.
//!
//! The rest of this crate reads at offsets and keeps no position, so that
//! one file system can be read from more than one thread. The library that
//! reads NTFS wants a stream instead, so each call that goes into it gets
//! a cursor of its own: a position, and the disk to read at it.

use std::io::{self, Read, Seek, SeekFrom};

use crate::image::Disk;

/// A position on a disk, and the disk to read there.
pub(crate) struct Cursor<'a, D> {
    disk: &'a D,
    /// How long the disk is, which `SeekFrom::End` needs and nothing else
    /// does. Read once, as a disk does not change under a reader.
    len: u64,
    at: u64,
}

impl<'a, D: Disk> Cursor<'a, D> {
    pub(crate) fn new(disk: &'a D, len: u64) -> Cursor<'a, D> {
        Cursor { disk, len, at: 0 }
    }
}

impl<D: Disk> Read for Cursor<'_, D> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.disk.read_at(self.at, buf)?;
        // Saturating, as a disk longer than `u64::MAX` is not one: a read
        // that would pass the end leaves the position where it is.
        self.at = self.at.saturating_add(read as u64);
        Ok(read)
    }
}

impl<D: Disk> Seek for Cursor<'_, D> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let at = match to {
            SeekFrom::Start(at) => Some(at),
            SeekFrom::End(by) => self.len.checked_add_signed(by),
            SeekFrom::Current(by) => self.at.checked_add_signed(by),
        };
        // A position past the end is allowed, as it is for a file: the read
        // there is what answers. Before the start is not.
        match at {
            Some(at) => {
                self.at = at;
                Ok(at)
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a seek to before the disk's start",
            )),
        }
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        Ok(self.at)
    }
}
