//! ZIP archives in safe Rust, the container logic ported from
//! [libzip](https://libzip.org).
//!
//! It opens archives and reads what their central directory and local
//! headers say, with libzip's rules and errors: where the end of central
//! directory record is looked for and which one is taken, the Zip64
//! records, Info-ZIP's count of entries modulo 65,536, file names in UTF-8
//! or CP437 and the Info-ZIP Unicode extra fields, WinZip AES headers,
//! torrentzip, and, with [`OpenFlags::CHECKCONS`], the comparison of every
//! local header with the central directory. It reads stored, deflated,
//! bzip2, LZMA, XZ, Zstandard and Deflate64 entries, decrypts ZipCrypto and WinZip AES
//! ones with a password, and checks the CRC-32 and length of an entry read
//! to its end, as libzip does. It edits archives as libzip does too: entries
//! are added from a [`DataSource`], replaced, deleted, renamed, given comments,
//! times, attributes, compression methods and encryption (ZipCrypto or
//! WinZip AES, with [`Archive::file_set_encryption`]), the archive a
//! comment, and [`Archive::close_to`] writes the archive with its changes,
//! byte for byte as libzip writes it with the same random bytes. Beyond
//! libzip, [`Writer`] writes an archive an entry at a time, each read once
//! from a reader as it is added, [`Archive::set_threads`] has new data
//! compressed and encrypted in threads ahead of the entry written, the
//! archive the same byte for byte, [`Archive::set_deflate_library`] has it
//! deflated by libdeflate's compressor, whose levels 10 to 12 make smaller
//! entries than zlib's 9, and it reads split archives from their
//! volumes, joined by
//! [`Volumes`] (`name.z01`, …, `name.zip`, or 7-Zip's `name.zip.001`, …).
//! The rules the port follows are in the repository's `docs/zip.md`.
//!
//! ```
//! use std::io::Read;
//!
//! use hivepack::zip::{Archive, BufferSource, Closed, Flags, OpenFlags};
//!
//! // An archive with one stored file, "hi.txt".
//! let zip: &[u8] = &[
//!     0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x5d, 0x5d, 0x1b, 0x38,
//!     0x72, 0xcb, 0x0b, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x68, 0x69,
//!     0x2e, 0x74, 0x78, 0x74, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x7a, 0x69, 0x70, 0x0a, 0x50,
//!     0x4b, 0x01, 0x02, 0x14, 0x03, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x5d, 0x5d, 0x1b,
//!     0x38, 0x72, 0xcb, 0x0b, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x68, 0x69, 0x2e,
//!     0x74, 0x78, 0x74, 0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x34,
//!     0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00,
//! ];
//! let archive = Archive::open(zip, OpenFlags::CHECKCONS)?;
//! assert_eq!(archive.get_num_entries(Flags::NONE), 1);
//! assert_eq!(archive.get_name(0, Flags::NONE)?, b"hi.txt");
//!
//! let mut text = String::new();
//! let mut file = archive.fopen(b"hi.txt", Flags::NONE)?;
//! file.read_to_string(&mut text)?;
//! assert_eq!(text, "hello, zip\n");
//! file.fclose()?;
//!
//! // Renamed, with a file added, and written with the changes.
//! let mut archive = Archive::open(zip, OpenFlags::CHECKCONS)?;
//! archive.file_rename(0, b"hello.txt", Flags::NONE)?;
//! archive.file_add(b"more.txt", BufferSource::new(b"more\n".to_vec()), Flags::NONE)?;
//! let mut out = std::io::Cursor::new(Vec::new());
//! assert_eq!(archive.close_to(&mut out)?, Closed::Written);
//! let written = out.into_inner();
//! let archive = Archive::open(written.as_slice(), OpenFlags::CHECKCONS)?;
//! assert_eq!(archive.get_name(0, Flags::NONE)?, b"hello.txt");
//! let mut more = String::new();
//! archive.fopen(b"more.txt", Flags::NONE)?.read_to_string(&mut more)?;
//! assert_eq!(more, "more\n");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod add_entry;
mod algorithm_bzip2;
mod algorithm_deflate;
mod algorithm_ppmd;
mod algorithm_xz;
mod algorithm_zstd;
mod buffer;
mod close;
mod close_threads;
mod delete;
mod dir_add;
mod dirent;
mod error;
mod extra_field;
mod extra_field_api;
mod fclose;
mod file_add;
mod file_get_comment;
mod file_get_external_attributes;
mod file_get_offset;
mod file_rename;
mod file_replace;
mod file_set_comment;
mod file_set_encryption;
mod file_set_external_attributes;
mod file_set_mtime;
mod fopen;
mod fopen_encrypted;
mod fopen_index;
mod fopen_index_encrypted;
mod fread;
mod get_archive_comment;
mod get_archive_flag;
mod get_encryption_implementation;
mod get_name;
mod get_num_entries;
mod hash;
mod io_util;
mod name_locate;
mod open;
mod pkware;
mod ppmd8;
#[cfg(test)]
mod ppmd8_oracle;
mod random;
mod set_archive_comment;
mod set_archive_flag;
mod set_default_password;
mod set_file_compression;
mod set_name;
mod source;
mod source_compress;
mod source_crc;
mod source_data;
mod source_pkware_decode;
mod source_pkware_encode;
mod source_stack;
mod source_window;
mod source_winzip_aes_decode;
mod source_winzip_aes_encode;
mod source_write;
mod source_zip;
mod source_zip_new;
mod stat_index;
mod string;
mod unchange;
mod unchange_all;
mod unchange_archive;
mod utf_8;
mod volumes;
mod winzip_aes;
mod writer;
mod zip;
mod zipint;

pub use close::Closed;
pub use error::{Detail, Error, ErrorCode, Result, SystemType};
pub use fopen_index_encrypted::ZipFile;
pub use get_encryption_implementation::encryption_method_supported;
pub use open::Archive;
pub use random::RandomSource;
pub use source::ReadAt;
pub use source_data::{BufferSource, DataSource, FileAttributes, FileSource, file_attributes};
pub use source_zip::ZipFileSource;
pub use volumes::{Volumes, volume_paths};
pub use writer::{NewEntry, Writer};
pub use zip::{ArchiveFlags, Flags, OpenFlags, Stat, cm, em, opsys, stat};
pub use zipint::{EXTRA_FIELD_ALL, EXTRA_FIELD_NEW};

/// The libzip release this crate follows.
pub const UPSTREAM_VERSION: &str = "1.12.1";
