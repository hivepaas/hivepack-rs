//! Port of `lib/common`: the parts shared by compression and decompression.

pub(crate) mod bits;
pub(crate) mod bitstream;
pub(crate) mod entropy_common;
pub mod error_private;
pub(crate) mod fse;
pub(crate) mod fse_decompress;
pub(crate) mod huf;
pub(crate) mod mem;
pub(crate) mod pool;
/// `PREFETCH_L1`: with the `unsafe-fast` feature, a prefetch instruction.
pub(crate) mod prefetch;
pub(crate) mod xxhash;
pub(crate) mod zstd_internal;
