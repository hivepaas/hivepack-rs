//! bzip2 compression and decompression in safe Rust, ported from the
//! official library, [libbzip2](https://sourceware.org/bzip2/) 1.0.8.
//!
//! Compression ([`Compress`]) gives libbzip2's output, byte for byte, at
//! every block size and work factor, whatever pieces the input and output
//! come in, and decompression ([`Decompress`]) libbzip2's results, in its
//! fast and small modes, randomised blocks included. Beside the port,
//! [`CompressMt`] compresses in threads, as pbzip2 does: a stream for each
//! piece of the input, one after the other. The rules the port follows,
//! and how it is checked, are in the repository: `docs/bzip2.md` and
//! `docs/safety.md`.
//!
//! ```
//! # fn main() -> Result<(), hivepack::bzip2::Error> {
//! use hivepack::bzip2::{Action, Compress, Decompress, InBuffer, OutBuffer, Status};
//!
//! let text = b"hello, hello, hello, hello";
//! let mut compressed = [0; 128];
//! let mut output = OutBuffer::new(&mut compressed);
//! let mut compress = Compress::new(9, 0)?;
//! let status = compress.compress(&mut output, &mut InBuffer::new(text), Action::Finish)?;
//! assert_eq!(status, Status::StreamEnd);
//! let len = output.pos;
//!
//! let mut decompress = Decompress::new(false);
//! let mut input = InBuffer::new(&compressed[..len]);
//! let mut decoded = Vec::new();
//! let mut piece = [0; 5];
//! loop {
//!     // The output can come in pieces, and so can the input: each call
//!     // reads and writes what it can.
//!     let mut output = OutBuffer::new(&mut piece);
//!     let status = decompress.decompress(&mut output, &mut input)?;
//!     let written = output.pos;
//!     decoded.extend_from_slice(&piece[..written]);
//!     if status == Status::StreamEnd {
//!         break;
//!     }
//! }
//! assert_eq!(decoded, text);
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
// Loops keep libbzip2's indices, so the port reads side by side with the
// C.
#![allow(clippy::needless_range_loop)]

mod blocksort;
mod bzlib;
mod compress;
mod crctable;
mod decompress;
mod huffman;
pub(crate) mod mt;
mod private;
mod randtable;

pub(crate) use bzlib::compress_memory;
#[cfg(feature = "open")]
pub(crate) use bzlib::decompress_memory;
pub use bzlib::{
    Action, Compress, Decompress, Error, InBuffer, OutBuffer, Result, Status,
    buff_to_buff_compress, buff_to_buff_decompress, version,
};
pub use mt::{CompressMt, MtOptions, piece_size};

/// The libbzip2 release this crate follows.
pub const UPSTREAM_VERSION: &str = "1.0.8";
