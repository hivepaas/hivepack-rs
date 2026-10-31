//! Extracting archives to disk, safe by default: nothing is written
//! outside the destination, through a link, over what is there, or past
//! limits set against archive bombs.
//!
//! What extractors get wrong is logic, not memory: names that climb out of
//! the destination (`../`, `/etc`, `C:`, `a:stream`), links in the archive
//! or already on disk that lead elsewhere, the same path given twice,
//! setuid bits, and archives whose entries share one compressed stream to
//! write terabytes. This crate refuses rather than repairs, so that an
//! archive extracts the same everywhere:
//!
//! - **Names**: [`check_name`] refuses names that are absolute, climb with
//!   `..`, carry a backslash, a colon, a control character or a Windows
//!   device name, or end a component with a space or a dot, on every
//!   system alike. Two entries may not name the same path, ignoring case
//!   and how accents are written (`é` as one character or as `e` and an
//!   accent), with the tables of one Unicode version ([`UNICODE_VERSION`]).
//! - **Links** are not created, unless [`Options::links`] says to create
//!   those that stay inside the destination; a device or FIFO in a ZIP
//!   archive, only a mode with data, is written as a file.
//! - **Writing** goes through handles: each directory is opened from its
//!   parent without following a link, and each file is created new, so a
//!   link already in the destination, or put there while extracting, is
//!   not followed, and nothing is overwritten.
//! - **Limits** ([`Limits`]) count entries, the bytes each writes and all
//!   write, and the bytes written for each compressed byte; entries whose
//!   compressed data overlap are refused before anything is written.
//! - **Integrity**: a file whose data fails its check (CRC-32, or WinZip
//!   AES's authentication code) is removed.
//! - **Permissions** are masked: no setuid, setgid or sticky bit, and
//!   nothing writable by group or others.
//! - **Time**: an extraction can be given a time limit
//!   ([`Options::time_limit`]), stopped from another thread ([`Cancel`]),
//!   and followed ([`Options::progress`]).
//! - **Marks of origin**: the archive's Mark of the Web on Windows, or its
//!   quarantine on macOS ([`Origin`]), is carried to every file written.
//!
//! ```no_run
//! use hivepack_extract::{Options, Origin, extract_zip};
//! use hivepack_zip::{Archive, OpenFlags, Volumes};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let path = std::path::Path::new("archive.zip");
//! // The file, or the volumes of a split archive (archive.z01, … archive.zip).
//! let archive = Archive::open(Volumes::open(path)?, OpenFlags::CHECKCONS)?;
//! let mut options = Options::default();
//! // Downloaded files are marked; what is extracted from them must be too.
//! options.origin = Origin::of(path)?;
//! let summary = extract_zip(&archive, "out".as_ref(), &options)?;
//! println!("{} files, {} bytes", summary.files, summary.bytes);
//! # Ok(())
//! # }
//! ```
//!
//! [`extract_tar`] extracts tar archives with the same rules, reading them
//! twice: once to check, once to write; [`extract_cpio`] cpio archives
//! (RPM packages' payloads among them), [`extract_xar`] XAR archives
//! (macOS packages, their payloads expanded) and [`extract_iso`] ISO 9660
//! images, the same way; [`extract_udf`] UDF volumes and [`extract_7z`] 7z
//! archives, checked first, as ZIP archives are.
//!
//! With the feature `rar`, off by default as it takes UnRAR's license,
//! `extract_rar` extracts RAR archives the same way, reading them twice.
//!
//! The design is in the repository's `docs/extract.md`.

mod cpio;
mod destination;
mod error;
mod iso;
mod name;
mod origin;
mod plan;
mod progress;
#[cfg(feature = "rar")]
mod rar;
mod sevenz;
mod tar;
mod udf;
mod unicode;
mod xar;
mod zip;

pub use cpio::extract_cpio;
#[cfg(feature = "rar")]
pub use error::RarProblem;
pub use error::{Error, ErrorKind};
pub use iso::extract_iso;
pub use name::{MAX_COMPONENT, Name, NameError, check_name};
pub use origin::Origin;
pub use plan::{Limits, Links, Names, OnRefused, Options, Packages, Permissions};
pub use progress::{Cancel, Progress, ProgressFn};
#[cfg(feature = "rar")]
pub use rar::extract_rar;
pub use sevenz::extract_7z;
pub use tar::extract_tar;
pub use udf::extract_udf;
/// The version of Unicode names are compared with: major, minor, update.
pub use unicode::VERSION as UNICODE_VERSION;
pub use xar::extract_xar;
pub use zip::{Summary, extract_zip};
