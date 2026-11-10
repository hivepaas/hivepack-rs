//! libdeflate's DEFLATE compressor, ported from
//! [libdeflate](https://github.com/ebiggers/libdeflate) 1.26 beside the
//! port of zlib.
//!
//! [`Compressor`] compresses a whole buffer at once, at a level from 0 to
//! 12, with libdeflate's output, byte for byte; levels 10 to 12 parse the
//! input near-optimally, and make smaller streams than zlib's level 9.
//! Only the compressor is ported, and only raw DEFLATE: zlib's and gzip's
//! wrappers, and decompression, are the zlib port's. Not in libdeflate,
//! [`Compressor::deflate_compress_part`] compresses a part of a stream that
//! is not its last, which [`DeflateMt`](crate::deflate::DeflateMt) joins
//! to others.
//!
//! Each file of libdeflate's `lib/` that the compressor needs is a module
//! of the same name: `deflate_compress.c` becomes `deflate_compress.rs`,
//! `hc_matchfinder.h` becomes `hc_matchfinder.rs`. The rules are those of
//! the zlib port (`docs/deflate.md`), and differences are marked with a
//! comment starting `Differs from libdeflate:`.

mod bt_matchfinder;
mod common_defs;
mod deflate_compress;
mod deflate_constants;
mod hc_matchfinder;
mod ht_matchfinder;
mod matchfinder_common;

pub use deflate_compress::Compressor;

/// The libdeflate release the compressor follows, as libdeflate's
/// `LIBDEFLATE_VERSION_STRING` gives it.
pub const LIBDEFLATE_VERSION: &str = "1.26";
