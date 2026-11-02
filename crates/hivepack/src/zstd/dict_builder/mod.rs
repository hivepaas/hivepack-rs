//! Port of `lib/dictBuilder`: training zstd dictionaries from samples.
//!
//! - `zdict.rs`, from `zdict.c`: a dictionary's header and entropy tables
//!   from samples ([`finalize_dictionary`], `ZDICT_analyzeEntropy`), the
//!   default trainer ([`train_from_buffer`]), and the helpers
//!   ([`get_dict_id`], [`get_dict_header_size`]).
//! - `cover.rs`, from `cover.c`: the COVER trainer, which picks the
//!   segments of the samples whose dmers (`d`-byte substrings) are in the
//!   most samples ([`train_from_buffer_cover`]), and its optimizer, which
//!   tries values of `k` and `d` and keeps the dictionary that compresses
//!   the samples best ([`optimize_train_from_buffer_cover`]).
//! - `fastcover.rs`, from `fastcover.c`: the same with the dmers' hashes
//!   counted in a table of `2^f` cells instead of a suffix array
//!   ([`train_from_buffer_fast_cover`],
//!   [`optimize_train_from_buffer_fast_cover`]), which the default trainer
//!   runs.
//! - `legacy.rs`, from `zdict.c`: the legacy trainer, which keeps the
//!   repeated segments that save the most, found with a suffix array
//!   ([`train_from_buffer_legacy`]).
//! - `divsufsort.rs`, from `divsufsort.c`: that suffix array.
//!
//! The dictionaries are libzstd's, byte for byte, for the same samples and
//! parameters. libzstd's notifications on stderr (`notificationLevel`) are
//! left out: the parameter is taken and has no effect.
//!
//! The samples are one buffer, `samples`, cut into pieces of
//! `sample_sizes`, in order, as libzstd takes them. libzstd trusts the
//! sizes; here they must add up to at most `samples.len()` (what follows
//! is not read), and there must be fewer than 2^32 of them, or the
//! functions fail with [`ErrorCode::SrcSizeWrong`](crate::zstd::ErrorCode).
//!
//! [`finalize_dictionary`]: crate::zstd::finalize_dictionary
//! [`train_from_buffer`]: crate::zstd::train_from_buffer
//! [`get_dict_id`]: crate::zstd::get_dict_id
//! [`get_dict_header_size`]: crate::zstd::get_dict_header_size
//! [`train_from_buffer_cover`]: crate::zstd::train_from_buffer_cover
//! [`optimize_train_from_buffer_cover`]: crate::zstd::optimize_train_from_buffer_cover
//! [`train_from_buffer_fast_cover`]: crate::zstd::train_from_buffer_fast_cover
//! [`optimize_train_from_buffer_fast_cover`]: crate::zstd::optimize_train_from_buffer_fast_cover
//! [`train_from_buffer_legacy`]: crate::zstd::train_from_buffer_legacy

pub(crate) mod cover;
pub(crate) mod divsufsort;
pub(crate) mod fastcover;
pub(crate) mod legacy;
pub(crate) mod zdict;

use crate::zstd::common::error_private::{Result, error};

/// `len` default values (zeros), or `MemoryAllocation` where that much
/// memory is not to be had, as libzstd's `malloc` and `calloc` return
/// `NULL`, rather than an abort.
pub(crate) fn zeroed<T: Clone + Default>(len: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    if values.try_reserve_exact(len).is_err() {
        return error!(MemoryAllocation);
    }
    values.resize(len, T::default());
    Ok(values)
}

/// Whether `sample_sizes` describe pieces of `samples`: they add up to at
/// most its length, and there are fewer than 2^32 of them (libzstd's
/// `unsigned nbSamples`). Fails with `SrcSizeWrong` otherwise.
///
/// Differs from libzstd: libzstd trusts the sizes, and reads past the
/// buffer when they add up to more.
pub(crate) fn check_samples(samples: &[u8], sample_sizes: &[usize]) -> Result<()> {
    let total = sample_sizes
        .iter()
        .try_fold(0usize, |total, &size| total.checked_add(size));
    match total {
        Some(total) if total <= samples.len() && u32::try_from(sample_sizes.len()).is_ok() => {
            Ok(())
        }
        _ => error!(SrcSizeWrong),
    }
}
