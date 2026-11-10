//! What the match finders share: port of `matchfinder_common.h`.
//!
//! Positions are kept as 16-bit numbers relative to a base in the input,
//! which moves forward a window at a time (`matchfinder_rebase`).
//!
//! Differs from libdeflate: `matchfinder_init` and `matchfinder_rebase`
//! are plain loops, which the compiler vectorizes; libdeflate has versions
//! of its own for SSE2, AVX2, NEON and RISC-V vectors, which give the same
//! tables. The input is a slice and positions in it are indices, where
//! libdeflate has pointers.

use crate::deflate::libdeflate::common_defs::{get_unaligned_le32, load_word_unaligned};
use crate::deflate::libdeflate::deflate_constants::DEFLATE_WINDOW_ORDER;

/// `MATCHFINDER_WINDOW_ORDER`: `DEFLATE_WINDOW_ORDER`, as
/// `deflate_compress.c` sets it.
pub(crate) const MATCHFINDER_WINDOW_ORDER: u32 = DEFLATE_WINDOW_ORDER;

/// `MATCHFINDER_WINDOW_SIZE`.
pub(crate) const MATCHFINDER_WINDOW_SIZE: usize = 1 << MATCHFINDER_WINDOW_ORDER;

/// `mf_pos_t`: a position relative to the base.
pub(crate) type MfPos = i16;

/// `MATCHFINDER_INITVAL`: a position always out of the window.
pub(crate) const MATCHFINDER_INITVAL: MfPos = -(MATCHFINDER_WINDOW_SIZE as i32) as MfPos;

/// `loaded_u32_to_u24`: the first three bytes of a value read with
/// `load_u32_unaligned` (little-endian, see `common_defs.rs`).
#[inline(always)]
pub(crate) fn loaded_u32_to_u24(v: u32) -> u32 {
    v & 0xFF_FFFF
}

/// `load_u24_unaligned`: the three bytes of `data` at `pos`. Four bytes
/// must be there, as in libdeflate.
#[inline(always)]
pub(crate) fn load_u24_unaligned(data: &[u8], pos: usize) -> u32 {
    loaded_u32_to_u24(get_unaligned_le32(data, pos))
}

/// `matchfinder_init`: every entry of a hash table set to
/// `MATCHFINDER_INITVAL`.
#[inline]
pub(crate) fn matchfinder_init(data: &mut [MfPos]) {
    data.fill(MATCHFINDER_INITVAL);
}

/// `matchfinder_rebase`: each entry moved back by a window, those already
/// out of it kept at `-MATCHFINDER_WINDOW_SIZE`. The window is 32768
/// bytes, so this is libdeflate's branchless form: subtracting 32768 with
/// signed saturation.
#[inline]
pub(crate) fn matchfinder_rebase(data: &mut [MfPos]) {
    const _: () = assert!(MATCHFINDER_WINDOW_SIZE == 32768);
    for entry in data.iter_mut() {
        *entry = MATCHFINDER_INITVAL | (*entry & !(*entry >> 15));
    }
}

/// `lz_hash`: the hash of the bytes in the low bits of `seq`, on
/// `num_bits` bits.
#[inline(always)]
pub(crate) fn lz_hash(seq: u32, num_bits: u32) -> u32 {
    seq.wrapping_mul(0x1E35_A7BD) >> (32 - num_bits)
}

/// `lz_extend`: how many bytes at `matchptr` are the same as at `strptr`,
/// both indices of `data`, up to `max_len`, the first `start_len` known
/// to be. The bytes are compared a word at a time, the first that differs
/// found from the lowest set bit, as libdeflate does on a little-endian
/// machine; libdeflate's first four words, compared without a loop, give
/// the same length.
#[inline(always)]
pub(crate) fn lz_extend(
    data: &[u8],
    strptr: usize,
    matchptr: usize,
    start_len: u32,
    max_len: u32,
) -> u32 {
    let max = max_len as usize;
    let mut len = start_len as usize;
    let s = &data[strptr..strptr + max];
    let m = &data[matchptr..matchptr + max];
    while len + 8 <= max {
        let v_word = load_word_unaligned(m, len) ^ load_word_unaligned(s, len);
        if v_word != 0 {
            return (len + (v_word.trailing_zeros() >> 3) as usize) as u32;
        }
        len += 8;
    }
    while len < max && m[len] == s[len] {
        len += 1;
    }
    len as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebase_saturates() {
        let mut data = [0i16, 1, 32767, -1, -32768, -100];
        matchfinder_rebase(&mut data);
        assert_eq!(data, [-32768, -32767, -1, -32768, -32768, -32768]);
    }

    #[test]
    fn extend_counts_equal_bytes() {
        let data: Vec<u8> = (0..300).map(|i| (i % 7) as u8).collect();
        // Seven back, everything matches.
        assert_eq!(lz_extend(&data, 100, 93, 0, 150), 150);
        assert_eq!(lz_extend(&data, 100, 93, 3, 5), 5);
        // One back, nothing does.
        assert_eq!(lz_extend(&data, 100, 99, 0, 150), 0);
        let mut other = data.clone();
        other[100 + 37] = 99;
        assert_eq!(lz_extend(&other, 100, 93, 4, 150), 37);
        other[100 + 9] = 99;
        assert_eq!(lz_extend(&other, 100, 93, 4, 12), 9);
    }
}
