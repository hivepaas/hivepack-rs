//! LZO1X decompression in safe Rust, ported from
//! [lzokay](https://github.com/jackoalan/lzokay)'s decompressor, with the
//! results of liblzo2's `lzo1x_decompress_safe`.
//!
//! LZO1X is the format of liblzo2's `lzo1x_*` compressors: a block of
//! compressed data, ended by its own marker, that decompresses to a size
//! the caller must know or bound. SquashFS stores the blocks of an image
//! made with `-comp lzo` that way, and so do UBIFS, Btrfs and others.
//! [`decompress`] decodes one block: the bytes liblzo2 2.10's safe decoder
//! gives, and on a damaged block the same error, with the same bytes left
//! in the output. Only raw blocks, not the `.lzo` files of `lzop`; and no
//! compression.
//!
//! lzokay has no releases: the port follows a commit of it,
//! [`UPSTREAM_VERSION`]. The rules the port follows, and how it is checked
//! against liblzo2 and lzokay, are in the repository: `docs/lzo.md` and
//! `docs/safety.md`.
//!
//! ```
//! # fn main() -> Result<(), hivepack::lzo::Error> {
//! // "hello" six times, between commas, as lzo1x_999_compress makes it: 7
//! // literals, a match of 33 bytes 7 back and a literal "\n", then the
//! // end-of-stream marker.
//! let block = [
//!     0x18, b'h', b'e', b'l', b'l', b'o', b',', b' ', 0x3f, 0x19, 0x00, b'\n',
//!     0x11, 0x00, 0x00,
//! ];
//! let mut text = [0; 64];
//! let len = hivepack::lzo::decompress(&block, &mut text)?;
//! assert_eq!(&text[..len], b"hello, hello, hello, hello, hello, hello\n");
//!
//! // An output one byte short fails, as liblzo2 does.
//! let mut short = [0; 40];
//! assert_eq!(
//!     hivepack::lzo::decompress(&block, &mut short),
//!     Err(hivepack::lzo::Error::OutputOverrun)
//! );
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

mod lzokay;

pub use lzokay::{Error, decompress};

/// The lzokay commit this module follows: lzokay has no releases, and this
/// is the latest commit of its `master` branch (22 October 2023).
pub const UPSTREAM_VERSION: &str = "db2df1fcbebc2ed06c10f727f72567d40f06a2be";

/// The liblzo2 release whose `lzo1x_decompress_safe` gives the results the
/// port gives, which the tests compare it with.
pub const LIBLZO2_VERSION: &str = "2.10";
