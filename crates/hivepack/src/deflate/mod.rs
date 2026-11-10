//! Deflate, zlib and gzip compression and decompression in safe Rust,
//! ported from the official library, [zlib](https://zlib.net).
//!
//! Compression ([`Deflate`]) gives zlib's output, byte for byte, at every
//! level, strategy and flush, and decompression ([`Inflate`]) zlib's
//! results and messages, both with the zlib and gzip wrappers, dictionaries
//! and gzip headers; so do the checksums ([`crc32`], [`adler32`]).
//! [`InflateBack9`] decodes Deflate64, method 9 of ZIP archives, as zlib's
//! `contrib/infback9` does, and [`Inflate9`] decodes it as `infback9` does
//! but a piece at a time, as [`Inflate`] decodes deflate. [`DeflateMt`],
//! which is not part of the port, compresses in threads as pigz does, into
//! one stream of [`Deflate`]'s blocks, or of [`Compressor`]'s
//! ([`Library::Libdeflate`]). [`Compressor`] is a second port,
//! beside zlib's, of libdeflate 1.26's compressor: a whole buffer at once,
//! at levels 0 to 12, with libdeflate's output, byte for byte; its levels
//! 10 to 12 make smaller streams than zlib's level 9. The rules the ports
//! follow, and how they are checked, are in the repository:
//! `docs/deflate.md` and `docs/safety.md`.
//!
//! ```
//! # fn main() -> Result<(), hivepack::deflate::Error> {
//! use hivepack::deflate::{Flush, InBuffer, Inflate, OutBuffer, Status};
//!
//! // "hello", deflated with no header or trailer, as in a ZIP archive.
//! let raw = [0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];
//! let mut inflate = Inflate::new(-15)?;
//! let mut decoded = Vec::new();
//! let mut piece = [0; 2];
//! let mut input = InBuffer::new(&raw);
//! loop {
//!     // The output can come in pieces, and so can the input: each call
//!     // reads and writes what it can.
//!     let mut output = OutBuffer::new(&mut piece);
//!     let status = inflate.inflate(&mut output, &mut input, Flush::NoFlush)?;
//!     let written = output.pos;
//!     decoded.extend_from_slice(&piece[..written]);
//!     if status == Status::StreamEnd {
//!         break;
//!     }
//! }
//! assert_eq!(decoded, b"hello");
//! assert_eq!(hivepack::deflate::crc32(0, &decoded), 0x3610_a686);
//! # Ok(())
//! # }
//! ```

// No unsafe code at all, unless the `unsafe-fast` feature is on: then only
// where a module allows it (see `docs/unsafe.md`).
#![cfg_attr(not(feature = "deflate-unsafe-fast"), forbid(unsafe_code))]
// Loops keep zlib's indices, so the port reads side by side with the C.
#![allow(clippy::needless_range_loop)]

mod adler32;
mod crc32;
mod deflate;
mod infback9;
mod inffast;
mod inffix9;
mod inffixed;
mod inflate;
mod inflate9;
mod inftree9;
mod inftrees;
mod libdeflate;
mod mt;
mod trees;
mod zutil;

/// Whether this build has the `unsafe-fast` feature: CRC-32 with the
/// processor's instructions on arm64, and folded with its carry-less
/// multiplication on x86-64. Cargo turns a feature on for the whole
/// build as soon as one crate asks for it, so a program can check which it got.
pub const UNSAFE_FAST: bool = cfg!(feature = "deflate-unsafe-fast");

pub use adler32::{ADLER32_INIT, adler32, adler32_combine};
#[cfg(fuzzing)]
#[doc(hidden)]
pub use crc32::fuzz_crc32_braided;
pub use crc32::{crc32, crc32_combine, crc32_combine_gen, crc32_combine_op, get_crc_table};
pub use deflate::{
    DEF_MEM_LEVEL, Deflate, MAX_MEM_LEVEL, Z_DEFAULT_COMPRESSION, Z_DEFAULT_STRATEGY, Z_FILTERED,
    Z_FIXED, Z_HUFFMAN_ONLY, Z_RLE,
};
pub use infback9::{Back9, BackIn, BackOut, InflateBack9};
pub use inflate::{GzHeader, InBuffer, Inflate, OutBuffer};
pub use inflate9::Inflate9;
pub use libdeflate::{Compressor, LIBDEFLATE_VERSION};
pub use mt::{
    BLOCK_SIZE, DeflateMt, LIBDEFLATE_BLOCK_SIZE, LIBDEFLATE_BLOCKS, Library, MtOptions,
    libdeflate_block_size,
};
pub use zutil::{Error, ErrorCode, Flush, MAX_WBITS, Result, Status};

/// The zlib release this crate follows, as zlib's `ZLIB_VERSION` gives it.
pub const UPSTREAM_VERSION: &str = "1.3.2";
