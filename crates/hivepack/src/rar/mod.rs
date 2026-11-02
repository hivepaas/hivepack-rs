#![forbid(unsafe_code)]
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

//! Reading RAR archives in safe Rust: a port of UnRAR 7.3.2, RARLAB's
//! source, under UnRAR's license. It reads RAR and never writes it.
//!
//! An [`Archive`] reads an archive's headers in order, as UnRAR's
//! `Archive` does: [`Archive::open`] finds the signature (after a
//! self-extracting module too) and the main header, then
//! [`Archive::read_header`] reads each header and
//! [`Archive::seek_to_next`] moves past its data. Every format is read,
//! RAR 1.4, RAR 1.5 to 4.x and RAR 5, with what UnRAR reads of each
//! header, broken ones included.
//!
//! ```no_run
//! use hivepack::rar::{Archive, HEAD_FILE, name};
//!
//! # fn main() -> Result<(), hivepack::rar::Error> {
//! let file = std::fs::File::open("archive.rar")?;
//! let mut archive = Archive::open(file, false)?;
//! while archive.read_header()? != 0 {
//!     if archive.cur_header_type == HEAD_FILE {
//!         println!("{}", name::to_string_lossy(&archive.file_head.file_name));
//!     }
//!     archive.seek_to_next();
//! }
//! # Ok(())
//! # }
//! ```
//!
//! An [`Extract`] goes through the entries as UnRAR does when testing an
//! archive, giving out each one's data and checking its hash:
//!
//! ```no_run
//! use hivepack::rar::{Archive, Error, Extract};
//!
//! # fn main() -> Result<(), Error> {
//! let file = std::fs::File::open("archive.rar")?;
//! let mut archive = Archive::open(file, true)?;
//! let mut extract = Extract::new();
//! loop {
//!     let size = archive.read_header()?;
//!     let mut bytes = 0;
//!     let go_on = extract.current_file(&mut archive, size, &mut |data| {
//!         bytes += data.len();
//!         Ok(())
//!     })?;
//!     if !go_on {
//!         break;
//!     }
//! }
//! println!("{:?}", archive.exit_code());
//! # Ok(())
//! # }
//! ```
//!
//! An archive that is encrypted is opened with
//! [`Archive::open_with_password`], and one of many volumes with
//! [`Archive::open_volumes`], which is told how to open the next. The plan is
//! the repository's `docs/rar.md`.

mod archive;
mod comment;
mod crypt;
mod error;
mod extract;
mod hash;
mod headers;
pub mod name;
mod quick_open;
mod raw;
mod source;
mod time;
mod unpack;

pub use archive::Archive;
pub use error::{Error, ExitCode};
pub use extract::{Extract, Output};
pub use hash::DataHash;
pub use headers::*;
pub use source::ReadAt;
pub use time::RarTime;
