//! Reading ISO 9660 images in safe Rust, ported from libarchive 3.8.10's
//! reader (`archive_read_support_format_iso9660.c`).
//!
//! [`Reader`] reads the files of a CD or DVD image in the order their data
//! is on it: ISO 9660 at every level, with Rock Ridge (POSIX names,
//! permissions, links, devices, deep directories moved to `rr_moved`),
//! Joliet (Unicode names, used when there is no Rock Ridge), files in
//! several extents, and files compressed with zisofs. Each entry comes with
//! what libarchive gives for it, warnings included, and the same errors.
//!
//! UDF, which DVDs and Windows' installation images use, is another file
//! system: an image with both is read as ISO 9660 here.
//!
//! The rules the port follows, and how it is checked against libarchive,
//! are in the repository: `docs/iso.md`.
//!
//! ```no_run
//! use std::io::Read;
//!
//! let mut iso = hivepack::iso::Reader::seekable(std::fs::File::open("disc.iso")?);
//! while let Some(header) = iso.next()? {
//!     let mut data = Vec::new();
//!     iso.read_to_end(&mut data)?;
//!     let path = header.path.unwrap_or_default();
//!     println!("{} {} bytes", String::from_utf8_lossy(&path), data.len());
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod entry;
mod error;
mod read;
mod read_support_format_iso9660;
mod string;

use std::io::{self, Read, Seek};

pub use entry::{
    AE_IFBLK, AE_IFCHR, AE_IFDIR, AE_IFIFO, AE_IFLNK, AE_IFMT, AE_IFREG, AE_IFSOCK, Header,
};
pub use error::{Error, Warning};
pub use read_support_format_iso9660::Format;

use read::Input;
use read_support_format_iso9660::{Data, Iso9660, Next};

/// The libarchive release whose ISO 9660 reader this crate follows.
pub const UPSTREAM_VERSION: &str = "3.8.10";

/// Where the reader is.
#[derive(Debug)]
enum State {
    /// Not opened: the volume descriptors are read by the first `next`.
    New,
    /// After a header: its data can be read.
    Data,
    /// The end of the image.
    Eof,
    /// Failed, for good.
    Fatal(Error),
}

/// An ISO 9660 image, read in order: libarchive's reader. [`Reader::next`]
/// gives the next entry's header, and `io::Read` its data; data not read
/// is skipped by the next call to `next`.
///
/// An entry's data ends with `Ok(0)`. A failure is an `io::Error` that
/// holds an [`Error`], which `Error::from` takes back out. Once a read or
/// `next` fails, every later call fails the same way, except for an
/// [`Error::Warning`] while reading data: reading goes on after it.
#[derive(Debug)]
pub struct Reader<R> {
    input: Input<R>,
    iso: Iso9660,
    state: State,
    /// Decompressed zisofs data not yet read: the buffer's `from..to`.
    from: usize,
    to: usize,
    /// The current entry's data has ended.
    data_end: bool,
    /// The last message libarchive would have set since the entry began,
    /// which a failure without one of its own keeps.
    last_message: Option<Vec<u8>>,
}

impl<R: Read> Reader<R> {
    /// A reader of an image that cannot seek: as libarchive does with an
    /// input it cannot seek in, a file whose data is before its directory
    /// comes with [`Warning::FileOutOfOrder`] and no data.
    pub fn new(r: R) -> Reader<R> {
        Reader::with_input(Input::new(r, None))
    }

    fn with_input(input: Input<R>) -> Reader<R> {
        Reader {
            input,
            iso: Iso9660::new(),
            state: State::New,
            from: 0,
            to: 0,
            data_end: false,
            last_message: None,
        }
    }

    /// libarchive's `joliet` option: whether Joliet's names are used, when
    /// there is no Rock Ridge (yes by default). Before the first `next`.
    pub fn set_joliet(&mut self, on: bool) {
        self.iso.opt_support_joliet = on;
    }

    /// libarchive's `rockridge` option: whether Rock Ridge is used (yes by
    /// default). Before the first `next`.
    pub fn set_rock_ridge(&mut self, on: bool) {
        self.iso.opt_support_rockridge = on;
    }

    /// The image's format, once the first `next` read it.
    pub fn format(&self) -> Option<Format> {
        self.iso.format
    }

    /// The input, as far as it was read.
    pub fn into_inner(self) -> R {
        self.input.into_inner()
    }

    /// The next entry's header, or `None` at the end of the image. What is
    /// left of the current entry's data is skipped. The first call checks
    /// that this is an ISO 9660 image ([`Error::Unrecognized`] if not).
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
                match self.iso.bid(&mut self.input) {
                    Ok(bid) if bid >= 1 => {}
                    Ok(_) => return Err(self.fail(Error::Unrecognized)),
                    Err(e) => return Err(self.fail(e)),
                }
            }
            State::Data => {}
        }
        self.from = 0;
        self.to = 0;
        self.data_end = false;
        self.last_message = None;
        match self.iso.read_header(&mut self.input) {
            Ok(Next::Entry(entry)) => {
                self.state = State::Data;
                let header = entry.into_header();
                self.last_message = header.warning.as_ref().map(Warning::message);
                Ok(Some(header))
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
            Error::Unspecified(None) => Error::Unspecified(self.last_message.take()),
            e => e,
        };
        self.state = State::Fatal(e.again());
        e
    }
}

impl<R: Read + Seek> Reader<R> {
    /// A reader of an image that can seek, as a file: a file whose data is
    /// before its directory is read by going back, as libarchive does.
    /// Positions count from where the input is when reading begins.
    pub fn seekable(r: R) -> Reader<R> {
        Reader::with_input(Input::new(r, Some(<R as Seek>::seek)))
    }
}

impl<R: Read> Read for Reader<R> {
    /// The current entry's data; a file compressed with zisofs comes out
    /// decompressed.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &self.state {
            State::Fatal(e) => return Err(e.again().into()),
            State::Data => {}
            State::New | State::Eof => return Ok(0),
        }
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.from < self.to {
                let n = buf.len().min(self.to - self.from);
                buf[..n].copy_from_slice(self.iso.zisofs_output(self.from, self.from + n));
                self.from += n;
                return Ok(n);
            }
            if self.data_end {
                return Ok(0);
            }
            match self.iso.read_data(&mut self.input, buf) {
                Ok(Data::Bytes(0)) => {}
                Ok(Data::Bytes(n)) => return Ok(n),
                Ok(Data::Zisofs(n)) => {
                    self.from = 0;
                    self.to = n;
                }
                Ok(Data::Eof) => {
                    self.data_end = true;
                    return Ok(0);
                }
                Ok(Data::Warn(w)) => {
                    self.last_message = Some(w.message());
                    return Err(Error::Warning(w).into());
                }
                Err(e) => return Err(self.fail(e).into()),
            }
        }
    }
}
