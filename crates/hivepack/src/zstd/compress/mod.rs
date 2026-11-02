//! Port of `lib/compress`.

pub(crate) mod clevels;
pub(crate) mod fse_compress;
pub(crate) mod hist;
pub(crate) mod huf_compress;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_dict_lazy;
#[cfg(test)]
mod tests_mt;
pub(crate) mod zstd_cdict;
pub(crate) mod zstd_compress;
pub(crate) mod zstd_compress_internal;
pub(crate) mod zstd_compress_literals;
pub(crate) mod zstd_compress_sequences;
pub(crate) mod zstd_compress_superblock;
pub(crate) mod zstd_double_fast;
pub(crate) mod zstd_fast;
pub(crate) mod zstd_lazy;
pub(crate) mod zstd_ldm;
pub(crate) mod zstd_ldm_geartab;
pub(crate) mod zstd_opt;
pub(crate) mod zstd_pre_split;
pub(crate) mod zstdmt_compress;
