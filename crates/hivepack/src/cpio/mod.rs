//! Reading cpio archives in safe Rust, ported from libarchive 3.8.10's
//! reader (`archive_read_support_format_cpio.c`), and the payload of RPM
//! packages, from its RPM filter (`archive_read_support_filter_rpm.c`).
//!
//! [`Reader`] reads the entries of a cpio archive in order: odc (POSIX.1),
//! newc and crc (SVR4, which Linux's initramfs and RPM packages use), afio's
//! large ASCII headers, and the old binary format in either byte order.
//! Each entry comes with what libarchive gives for it, warnings included,
//! and the same errors. [`rpm::Reader`] takes the lead and headers off an
//! RPM package and gives its payload, a cpio archive that is usually
//! compressed, as libarchive's filter gives it.
//!
//! The rules the port follows, and how it is checked against libarchive,
//! are in the repository: `docs/cpio.md`.
//!
//! ```no_run
//! use std::io::Read;
//!
//! let mut cpio = hivepack::cpio::Reader::new(std::fs::File::open("initrd.cpio")?);
//! while let Some(header) = cpio.next()? {
//!     let mut data = Vec::new();
//!     cpio.read_to_end(&mut data)?;
//!     println!("{} {} bytes", String::from_utf8_lossy(&header.path), data.len());
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod entry;
mod error;
mod read;
mod read_support_filter_rpm;
mod read_support_format_cpio;

use std::io::{self, Read};

pub use entry::{
    AE_IFBLK, AE_IFCHR, AE_IFDIR, AE_IFIFO, AE_IFLNK, AE_IFMT, AE_IFREG, AE_IFSOCK, Device, Header,
};
pub use error::{Error, Warning};
pub use read_support_format_cpio::{Format, bid};

use read::Input;
use read_support_format_cpio::{Cpio, Next};

/// The libarchive release whose cpio reader and RPM filter this crate
/// follows.
pub const UPSTREAM_VERSION: &str = "3.8.10";

/// RPM packages: libarchive's RPM filter, which takes off the lead and the
/// headers and gives the payload as it is in the package.
///
/// The payload is a cpio archive (newc), most often compressed: with gzip,
/// bzip2, xz, LZMA or Zstandard, as the package's header says
/// (`PAYLOADCOMPRESSOR`), which the filter does not read. Decompressing it,
/// then reading it with [`crate::cpio::Reader`], is up to the caller, as it is
/// up to libarchive's other filters.
///
/// ```no_run
/// use std::io::Read;
///
/// let mut file = std::fs::File::open("package.rpm")?;
/// let mut head = [0; 8];
/// file.read_exact(&mut head)?;
/// assert!(hivepack::cpio::rpm::bid(&head) > 0);
/// let mut payload = Vec::new();
/// hivepack::cpio::rpm::Reader::new((&head[..]).chain(file)).read_to_end(&mut payload)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub mod rpm {
    pub use crate::cpio::read_support_filter_rpm::{BID_SIZE, Reader, bid};
}

/// Where the reader is.
#[derive(Debug)]
enum State {
    /// Not opened: the first `next` bids.
    New,
    /// Between entries.
    Header,
    /// After a header: its data can be read.
    Data,
    /// The end of the archive.
    Eof,
    /// Failed, for good.
    Fatal(Error),
}

/// A cpio archive, read in order: libarchive's reader. [`Reader::next`]
/// gives the next entry's header, and `io::Read` its data; data not read
/// is skipped by the next call to `next`.
///
/// An entry's data ends with `Ok(0)`. A failure is an `io::Error` that
/// holds an [`Error`], which `Error::from` takes back out. Once a read or
/// `next` fails, every later call fails the same way.
#[derive(Debug)]
pub struct Reader<R> {
    input: Input<R>,
    cpio: Cpio,
    state: State,
    /// The current entry's data has ended.
    data_end: bool,
}

impl<R: Read> Reader<R> {
    /// A reader of the archive `r`, which any `io::Read` gives: a file, a
    /// decompressing reader, or an [`rpm::Reader`]. It is read from as far
    /// as the reader looks, and never seeked.
    pub fn new(r: R) -> Reader<R> {
        Reader {
            input: Input::new(r),
            cpio: Cpio::default(),
            state: State::New,
            data_end: false,
        }
    }

    /// libarchive's `pwb` option: binary archives are read as PWB/UNIX's
    /// cpio wrote them, with the mode bits a V6 inode leaves taken off,
    /// and a file without a type a regular file (no by default).
    pub fn set_pwb(&mut self, on: bool) {
        self.cpio.option_pwb = on;
    }

    /// The format of the last header read, which one archive can mix
    /// (odc with afio's large headers); `None` before the first.
    pub fn format(&self) -> Option<Format> {
        self.cpio.format
    }

    /// The input, as far as it was read.
    pub fn into_inner(self) -> R {
        self.input.into_inner()
    }

    /// The next entry's header, or `None` at the end of the archive (the
    /// entry `TRAILER!!!`). What is left of the current entry's data is
    /// skipped. The first call checks that this is a cpio archive
    /// ([`Error::Unrecognized`] if not).
    ///
    /// Not an `Iterator`: the entry's data is read from the reader itself,
    /// until the next call.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Header>, Error> {
        self.cpio.last_message = None;
        match &self.state {
            State::Eof => return Ok(None),
            State::Fatal(e) => return Err(e.again()),
            State::New => {
                // libarchive's archive_read_open: the format's bid.
                match self.cpio.bid(&mut self.input) {
                    Ok(bid) if bid >= 1 => {}
                    Ok(_) => return Err(self.fail(Error::Unrecognized)),
                    Err(e) => return Err(self.fail(e)),
                }
            }
            State::Data => {
                // archive_read_data_skip.
                if let Err(e) = self.cpio.skip(&mut self.input) {
                    return Err(self.fail(e));
                }
            }
            State::Header => {}
        }
        self.state = State::Header;
        self.data_end = false;
        match self.cpio.read_header(&mut self.input) {
            Ok(Next::Entry(entry)) => {
                self.state = State::Data;
                Ok(Some(entry.into_header()))
            }
            Ok(Next::Eof) => {
                self.state = State::Eof;
                Ok(None)
            }
            Err(e) => Err(self.fail(e)),
        }
    }

    /// Fails for good with `e`.
    fn fail(&mut self, e: Error) -> Error {
        let e = match e {
            Error::Unspecified(None) => Error::Unspecified(self.cpio.last_message.take()),
            e => e,
        };
        self.state = State::Fatal(e.again());
        e
    }
}

impl<R: Read> Read for Reader<R> {
    /// The current entry's data.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &self.state {
            State::Fatal(e) => return Err(e.again().into()),
            State::Data => {}
            State::New | State::Header | State::Eof => return Ok(0),
        }
        if buf.is_empty() || self.data_end {
            return Ok(0);
        }
        match self.cpio.read_data(&mut self.input, buf) {
            Ok(0) => {
                self.data_end = true;
                Ok(0)
            }
            Ok(n) => Ok(n),
            Err(e) => Err(self.fail(e).into()),
        }
    }
}
