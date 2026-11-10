//! What the compressor takes from `common_defs.h` and `lib_common.h`: the
//! highest set bit, and unaligned loads.
//!
//! Differs from libdeflate: loads read the input as little-endian whatever
//! the machine. libdeflate loads in the machine's order where it only
//! compares the values (`load_u32_unaligned`, `load_u24_unaligned`), and
//! as little-endian where the order matters (`get_unaligned_le32`, for the
//! hashes; `lz_extend` counts the equal bytes from the lowest on a
//! little-endian machine and from the highest on a big-endian one), so its
//! output is the same on both, and so is the port's.

/// `bsr32`: the index of the highest set bit of `v`, which is not 0.
#[inline(always)]
pub(crate) fn bsr32(v: u32) -> u32 {
    31 - v.leading_zeros()
}

/// `get_unaligned_le32`, `load_u32_unaligned`: four bytes of `data` at
/// `pos`, as a little-endian number.
#[inline(always)]
pub(crate) fn get_unaligned_le32(data: &[u8], pos: usize) -> u32 {
    let mut bytes = [0; 4];
    bytes.copy_from_slice(&data[pos..pos + 4]);
    u32::from_le_bytes(bytes)
}

/// `load_word_unaligned`: a machine word, eight bytes, of `data` at
/// `pos`, as a little-endian number.
#[inline(always)]
pub(crate) fn load_word_unaligned(data: &[u8], pos: usize) -> u64 {
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&data[pos..pos + 8]);
    u64::from_le_bytes(bytes)
}
