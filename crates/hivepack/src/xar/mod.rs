//! Reading XAR archives in safe Rust, ported from libarchive 3.8.10's
//! reader (`archive_read_support_format_xar.c`).
//!
//! XAR is the archive format of macOS's installer packages (`.pkg`), of
//! `.xip` files and of Safari extensions. [`Reader`] reads its files in
//! the order of their `id` in the table of contents: paths, types,
//! permissions, owners, times, devices, inodes, hard and symbolic links,
//! file flags and extended attributes, and the data decompressed (gzip,
//! bzip2, lzma or xz) with its checksums checked (MD5, SHA-1, SHA-256 or
//! SHA-512). Each entry comes with what libarchive gives for it, warnings
//! included, and the same errors.
//!
//! The table of contents is XML, read by a port of the parts of libxml2
//! 2.15.4 that libarchive uses (its `xmlTextReader`), so that a damaged
//! one reads as it does with libarchive.
//!
//! The rules the port follows, and how it is checked against libarchive,
//! are in the repository: `docs/xar.md`.
//!
//! ```no_run
//! use std::io::Read;
//!
//! let mut xar = hivepack::xar::Reader::seekable(std::fs::File::open("Install.pkg")?);
//! while let Some(header) = xar.next()? {
//!     let mut data = Vec::new();
//!     xar.read_to_end(&mut data)?;
//!     let path = header.path.unwrap_or_default();
//!     println!("{} {} bytes", String::from_utf8_lossy(&path), data.len());
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod entry;
mod error;
mod read;
mod read_support_format_xar;
mod string;
mod xml;

use std::io::{self, Read, Seek};

pub use entry::{
    AE_IFBLK, AE_IFCHR, AE_IFDIR, AE_IFIFO, AE_IFLNK, AE_IFMT, AE_IFREG, AE_IFSOCK, Dev, Header,
    Xattr,
};
pub use error::{Error, Warning};

use read::Input;
use read_support_format_xar::{Data, Next, Xar};

/// The libarchive release whose XAR reader this crate follows.
pub const UPSTREAM_VERSION: &str = "3.8.10";

/// Where the reader is.
#[derive(Debug)]
enum State {
    /// Not opened: the table of contents is read by the first `next`.
    New,
    /// After a header: its data can be read.
    Data,
    /// After [`Error::CannotSeek`]: libarchive's
    /// `ARCHIVE_STATE_DATA_RECOVERY`. There is no data, and the next
    /// `next` goes on.
    Recovery,
    /// The end of the archive.
    Eof,
    /// Failed, for good.
    Fatal(Error),
}

/// A XAR archive, read in order: libarchive's reader. [`Reader::next`]
/// gives the next entry's header, and `io::Read` its data; data not read
/// is skipped by the next call to `next`.
///
/// An entry's data ends with `Ok(0)`. A failure is an `io::Error` that
/// holds an [`Error`], which `Error::from` takes back out. Once a read or
/// `next` fails, every later call fails the same way, except for
/// [`Error::CannotSeek`] from `next`: the entry is lost, and the next call
/// goes on.
#[derive(Debug)]
pub struct Reader<R> {
    input: Input<R>,
    xar: Xar,
    state: State,
    /// Data not yet read: the block's `from..to`.
    from: usize,
    to: usize,
    /// The current entry's data has ended.
    data_end: bool,
}

impl<R: Read> Reader<R> {
    /// A reader of an archive that cannot seek: as libarchive does with an
    /// input it cannot seek in, a file whose data or extended attributes
    /// are before what was read already fails with [`Error::CannotSeek`].
    pub fn new(r: R) -> Reader<R> {
        Reader::with_input(Input::new(r, None))
    }

    fn with_input(input: Input<R>) -> Reader<R> {
        Reader {
            input,
            xar: Xar::new(),
            state: State::New,
            from: 0,
            to: 0,
            data_end: false,
        }
    }

    /// libarchive's `archive_format_name`: "xar" once the first `next`
    /// read the table of contents and its checksum (and `None` if that
    /// failed, even with [`Error::CannotSeek`], after which libarchive
    /// goes on with the files anyway).
    pub fn format_name(&self) -> Option<&'static str> {
        self.xar.format_set.then_some("xar")
    }

    /// The input, as far as it was read.
    pub fn into_inner(self) -> R {
        self.input.into_inner()
    }

    /// The next entry's header, or `None` at the end of the archive. What
    /// is left of the current entry's data is skipped. The first call
    /// checks that this is a XAR archive ([`Error::Unrecognized`] if not)
    /// and reads its table of contents.
    ///
    /// Not an `Iterator`: the entry's data is read from the reader itself,
    /// until the next call.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Header>, Error> {
        // archive_clear_error.
        self.xar.last_message = None;
        match &self.state {
            State::Eof => return Ok(None),
            State::Fatal(e) => return Err(e.again()),
            State::New => {
                // libarchive's archive_read_open: the format's bid.
                match Xar::bid(&mut self.input) {
                    Ok(bid) if bid >= 1 => {}
                    Ok(_) => return Err(self.fail(Error::Unrecognized)),
                    Err(e) => return Err(self.fail(e)),
                }
            }
            State::Data | State::Recovery => {
                if let Err(e) = self.xar.read_data_skip(&mut self.input) {
                    return Err(self.fail(e));
                }
            }
        }
        self.from = 0;
        self.to = 0;
        self.data_end = false;
        match self.xar.read_header(&mut self.input) {
            Ok(Next::Entry(entry)) => {
                self.state = State::Data;
                Ok(Some(entry.into_header()))
            }
            Ok(Next::Eof) => {
                self.state = State::Eof;
                Ok(None)
            }
            Err(Error::CannotSeek) => {
                self.state = State::Recovery;
                Err(Error::CannotSeek)
            }
            Err(e) => Err(self.fail(e)),
        }
    }

    /// Fails for good with `e`.
    fn fail(&mut self, e: Error) -> Error {
        let e = match e {
            Error::Unspecified(None) => Error::Unspecified(self.xar.last_message.clone()),
            e => e,
        };
        self.state = State::Fatal(e.again());
        e
    }
}

impl<R: Read + Seek> Reader<R> {
    /// A reader of an archive that can seek, as a file: a file whose data
    /// is before what was read already is read by going back, as libarchive
    /// does. Positions count from where the input is when reading begins.
    pub fn seekable(r: R) -> Reader<R> {
        Reader::with_input(Input::new(r, Some(<R as Seek>::seek)))
    }
}

impl<R: Read> Read for Reader<R> {
    /// The current entry's data, decompressed. Its checksums are checked
    /// as it ends: a wrong one fails the read that would give the last
    /// bytes, which are not given.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &self.state {
            State::Fatal(e) => return Err(e.again().into()),
            State::Data => {}
            State::New | State::Recovery | State::Eof => return Ok(0),
        }
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.from < self.to {
                let n = buf.len().min(self.to - self.from);
                buf[..n].copy_from_slice(&self.xar.block[self.from..self.from + n]);
                self.from += n;
                return Ok(n);
            }
            if self.data_end {
                return Ok(0);
            }
            match self.xar.read_data(&mut self.input, buf.len()) {
                Ok(Data::Block(n)) => {
                    self.from = 0;
                    self.to = n;
                }
                Ok(Data::Eof) => {
                    self.data_end = true;
                    return Ok(0);
                }
                Err(e) => return Err(self.fail(e).into()),
            }
        }
    }
}
