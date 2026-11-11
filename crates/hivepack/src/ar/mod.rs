//! Reading ar archives in safe Rust, ported from libarchive 3.8.10's reader
//! (`archive_read_support_format_ar.c`).
//!
//! [`Reader`] reads the entries of an ar archive in order: GNU/SVR4's, with
//! long names in a filename table, and BSD's, with long names before the
//! data, as libarchive tells them apart. Debian packages (`.deb`) are ar
//! archives: `debian-binary`, then `control.tar` and `data.tar`, each
//! compressed or not. The symbol table of a static library (`/`) and the
//! GNU filename table (`//`) are not entries. Each entry comes with what
//! libarchive gives for it, and the same errors.
//!
//! The rules the port follows, and how it is checked against libarchive,
//! are in the repository: `docs/ar.md`.
//!
//! ```no_run
//! use std::io::Read;
//!
//! let mut ar = hivepack::ar::Reader::new(std::fs::File::open("hello.deb")?);
//! while let Some(header) = ar.next()? {
//!     let mut data = Vec::new();
//!     ar.read_to_end(&mut data)?;
//!     println!("{} {} bytes", String::from_utf8_lossy(&header.path), data.len());
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod entry;
mod error;
mod read;
mod read_support_format_ar;

use std::io::{self, Read};

pub use entry::{AE_IFMT, AE_IFREG, Header};
pub use error::Error;
pub use read_support_format_ar::{Format, bid};

use read::Input;
use read_support_format_ar::{Ar, Next};

/// The libarchive release whose ar reader this module follows.
pub const UPSTREAM_VERSION: &str = "3.8.10";

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

/// An ar archive, read in order: libarchive's reader. [`Reader::next`] gives
/// the next entry's header, and `io::Read` its data; data not read is
/// skipped by the next call to `next`.
///
/// An entry's data ends with `Ok(0)`. A failure is an `io::Error` that holds
/// an [`Error`], which `Error::from` takes back out. Once a read or `next`
/// fails, every later call fails the same way.
#[derive(Debug)]
pub struct Reader<R> {
    input: Input<R>,
    ar: Ar,
    state: State,
    /// The current entry's data has ended.
    data_end: bool,
}

impl<R: Read> Reader<R> {
    /// A reader of the archive `r`, which any `io::Read` gives. It is read
    /// from as far as the reader looks, and never seeked.
    pub fn new(r: R) -> Reader<R> {
        Reader {
            input: Input::new(r),
            ar: Ar::default(),
            state: State::New,
            data_end: false,
        }
    }

    /// The variant of ar, as far as the names read so far tell it; `None`
    /// before the first `next`.
    pub fn format(&self) -> Option<Format> {
        self.ar.format
    }

    /// The input, as far as it was read.
    pub fn into_inner(self) -> R {
        self.input.into_inner()
    }

    /// The next entry's header, or `None` at the end of the archive, where
    /// no whole header is left. What is left of the current entry's data is
    /// skipped. The first call checks that this is an ar archive
    /// ([`Error::Unrecognized`] if not).
    ///
    /// Not an `Iterator`: the entry's data is read from the reader itself,
    /// until the next call.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Header>, Error> {
        match &self.state {
            State::Eof => return Ok(None),
            State::Fatal(e) => return Err(e.again()),
            State::New => {
                // libarchive's archive_read_open: the format's bid.
                match self.ar.bid(&mut self.input) {
                    Ok(bid) if bid >= 1 => {}
                    Ok(_) => return Err(self.fail(Error::Unrecognized)),
                    Err(e) => return Err(self.fail(e)),
                }
            }
            State::Data => {
                // archive_read_data_skip.
                if let Err(e) = self.ar.skip(&mut self.input) {
                    return Err(self.fail(e));
                }
            }
            State::Header => {}
        }
        self.state = State::Header;
        self.data_end = false;
        match self.ar.read_header(&mut self.input) {
            Ok(Next::Entry(entry)) => {
                self.state = State::Data;
                Ok(Some(entry))
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
        match self.ar.read_data(&mut self.input, buf) {
            Ok(0) => {
                self.data_end = true;
                Ok(0)
            }
            Ok(n) => Ok(n),
            Err(e) => Err(self.fail(e).into()),
        }
    }
}
