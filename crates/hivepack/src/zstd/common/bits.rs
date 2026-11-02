//! Bit counting: port of `common/bits.h`.
//!
//! libzstd picks a compiler builtin or a fallback for each of these. Rust's
//! integer methods compile to the same instructions.

/// `ZSTD_countTrailingZeros32`. `val` must not be 0.
#[inline(always)]
pub(crate) fn count_trailing_zeros32(val: u32) -> u32 {
    debug_assert!(val != 0);
    val.trailing_zeros()
}

/// `ZSTD_countLeadingZeros32`. `val` must not be 0.
#[inline(always)]
pub(crate) fn count_leading_zeros32(val: u32) -> u32 {
    debug_assert!(val != 0);
    val.leading_zeros()
}

/// `ZSTD_countTrailingZeros64`. `val` must not be 0.
#[inline(always)]
pub(crate) fn count_trailing_zeros64(val: u64) -> u32 {
    debug_assert!(val != 0);
    val.trailing_zeros()
}

/// `ZSTD_countLeadingZeros64`. `val` must not be 0.
#[inline(always)]
pub(crate) fn count_leading_zeros64(val: u64) -> u32 {
    debug_assert!(val != 0);
    val.leading_zeros()
}

/// `ZSTD_NbCommonBytes` for a word read in little-endian order: the number
/// of equal leading bytes in two words, given their XOR.
///
/// Differs from libzstd: the C version also handles words read in native
/// big-endian order. The port reads words as little-endian on every machine,
/// so this one case is enough.
#[inline(always)]
pub(crate) fn nb_common_bytes(val: u64) -> u32 {
    count_trailing_zeros64(val) >> 3
}

/// `ZSTD_highbit32`: the position of the highest set bit. `val` must not be 0.
#[inline(always)]
pub(crate) fn highbit32(val: u32) -> u32 {
    debug_assert!(val != 0);
    31 - count_leading_zeros32(val)
}

/// `ZSTD_rotateRight_U64`
#[inline(always)]
pub(crate) fn rotate_right_u64(value: u64, count: u32) -> u64 {
    debug_assert!(count < 64);
    value.rotate_right(count & 0x3F)
}

/// `ZSTD_rotateRight_U32`
#[inline(always)]
pub(crate) fn rotate_right_u32(value: u32, count: u32) -> u32 {
    debug_assert!(count < 32);
    value.rotate_right(count & 0x1F)
}

/// `ZSTD_rotateRight_U16`
#[inline(always)]
pub(crate) fn rotate_right_u16(value: u16, count: u32) -> u16 {
    debug_assert!(count < 16);
    value.rotate_right(count & 0x0F)
}
