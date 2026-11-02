//! Port of `lib/decompress`.

pub(crate) mod huf_decompress;
/// The `unsafe-fast` feature's unchecked copies, on 64-bit machines.
#[cfg(all(feature = "zstd-unsafe-fast", target_pointer_width = "64"))]
pub(crate) mod unchecked;
pub(crate) mod zstd_ddict;
pub(crate) mod zstd_decompress;
pub(crate) mod zstd_decompress_block;
pub(crate) mod zstd_decompress_internal;
