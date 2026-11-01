//! ChaCha20 on several blocks at once with vector instructions, for the
//! `unsafe-fast` feature: eight blocks with AVX2 on x86-64, and four with NEON
//! on arm64. The cipher has no tables and no branches on its data, so this runs
//! in constant time as `chacha20_ct.rs` does.
//!
//! Not in BearSSL. The rounds are the same, on a word from each block side by
//! side.
//!
//! The only unsafe code is calling functions with a `target_feature` once the
//! processor is known to have it, which [`blocks`] checks, and storing 32 or 16
//! bytes into an array. See `docs/unsafe.md` in the repository.
#![allow(unsafe_code)]

/// As many whole groups of blocks of `data` as the processor can take at once,
/// XORed with the key stream, starting at block `cc`, which moves on past them.
/// Returns what is left: all of `data` if it cannot.
pub(crate) fn blocks<'a>(input: &[u32; 16], cc: &mut u32, data: &'a mut [u8]) -> &'a mut [u8] {
    if !imp::detected() || data.len() < imp::GROUP {
        return data;
    }
    let whole = data.len() / imp::GROUP * imp::GROUP;
    let (groups, rest) = data.split_at_mut(whole);
    for group in groups.as_chunks_mut::<{ imp::GROUP }>().0 {
        // SAFETY: the processor has what this needs, checked above.
        unsafe { imp::group(input, *cc, group) };
        *cc = cc.wrapping_add((imp::GROUP / 64) as u32);
    }
    rest
}

/// `group`, a whole group of blocks, XORed with `ks`, a word of each block side
/// by side.
#[inline]
fn xor_words<const LANES: usize>(group: &mut [u8], ks: &[[u32; LANES]; 16]) {
    for (block, chunk) in group.as_chunks_mut::<64>().0.iter_mut().enumerate() {
        for (word, bytes) in chunk.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            *bytes = (u32::from_le_bytes(*bytes) ^ ks[word][block]).to_le_bytes();
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod imp {
    use std::arch::x86_64::{
        __m256i, _mm256_add_epi32, _mm256_or_si256, _mm256_set_epi8, _mm256_set_epi32,
        _mm256_set1_epi32, _mm256_shuffle_epi8, _mm256_slli_epi32, _mm256_srli_epi32,
        _mm256_storeu_si256, _mm256_xor_si256,
    };

    /// Bytes in a group.
    pub(super) const GROUP: usize = 8 * 64;

    pub(super) fn detected() -> bool {
        std::is_x86_feature_detected!("avx2")
    }

    #[target_feature(enable = "avx2")]
    pub(super) fn group(input: &[u32; 16], cc: u32, data: &mut [u8]) {
        let rot16 = _mm256_set_epi8(
            13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2, 13, 12, 15, 14, 9, 8, 11, 10, 5,
            4, 7, 6, 1, 0, 3, 2,
        );
        let rot8 = _mm256_set_epi8(
            14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3, 14, 13, 12, 15, 10, 9, 8, 11, 6,
            5, 4, 7, 2, 1, 0, 3,
        );
        let mut start: [__m256i; 16] = input.map(|word| _mm256_set1_epi32(word as i32));
        start[12] = _mm256_add_epi32(
            _mm256_set1_epi32(cc as i32),
            _mm256_set_epi32(7, 6, 5, 4, 3, 2, 1, 0),
        );
        let mut x = start;
        macro_rules! qround {
            ($a:expr, $b:expr, $c:expr, $d:expr) => {
                x[$a] = _mm256_add_epi32(x[$a], x[$b]);
                x[$d] = _mm256_shuffle_epi8(_mm256_xor_si256(x[$d], x[$a]), rot16);
                x[$c] = _mm256_add_epi32(x[$c], x[$d]);
                let t = _mm256_xor_si256(x[$b], x[$c]);
                x[$b] = _mm256_or_si256(_mm256_slli_epi32::<12>(t), _mm256_srli_epi32::<20>(t));
                x[$a] = _mm256_add_epi32(x[$a], x[$b]);
                x[$d] = _mm256_shuffle_epi8(_mm256_xor_si256(x[$d], x[$a]), rot8);
                x[$c] = _mm256_add_epi32(x[$c], x[$d]);
                let t = _mm256_xor_si256(x[$b], x[$c]);
                x[$b] = _mm256_or_si256(_mm256_slli_epi32::<7>(t), _mm256_srli_epi32::<25>(t));
            };
        }
        for _ in 0..10 {
            qround!(0, 4, 8, 12);
            qround!(1, 5, 9, 13);
            qround!(2, 6, 10, 14);
            qround!(3, 7, 11, 15);
            qround!(0, 5, 10, 15);
            qround!(1, 6, 11, 12);
            qround!(2, 7, 8, 13);
            qround!(3, 4, 9, 14);
        }
        let mut ks = [[0u32; 8]; 16];
        for ((out, x), start) in ks.iter_mut().zip(x).zip(start) {
            // SAFETY: the array has its 32 bytes, and this store takes any
            // alignment.
            unsafe { _mm256_storeu_si256(out.as_mut_ptr().cast(), _mm256_add_epi32(x, start)) };
        }
        super::xor_words(data, &ks);
    }
}

#[cfg(target_arch = "aarch64")]
mod imp {
    use std::arch::aarch64::{
        uint32x4_t, vaddq_u32, vdupq_n_u32, veorq_u32, vld1q_u32, vorrq_u32, vshlq_n_u32,
        vshrq_n_u32, vst1q_u32,
    };

    /// Bytes in a group.
    pub(super) const GROUP: usize = 4 * 64;

    pub(super) fn detected() -> bool {
        std::arch::is_aarch64_feature_detected!("neon")
    }

    #[target_feature(enable = "neon")]
    pub(super) fn group(input: &[u32; 16], cc: u32, data: &mut [u8]) {
        let mut start: [uint32x4_t; 16] = input.map(|word| vdupq_n_u32(word));
        let counter = [
            cc,
            cc.wrapping_add(1),
            cc.wrapping_add(2),
            cc.wrapping_add(3),
        ];
        // SAFETY: the array has its 16 bytes, and this load takes any alignment.
        start[12] = unsafe { vld1q_u32(counter.as_ptr()) };
        let mut x = start;
        macro_rules! rotate {
            ($v:expr, $left:literal, $right:literal) => {{
                let t = $v;
                vorrq_u32(vshlq_n_u32::<$left>(t), vshrq_n_u32::<$right>(t))
            }};
        }
        macro_rules! qround {
            ($a:expr, $b:expr, $c:expr, $d:expr) => {
                x[$a] = vaddq_u32(x[$a], x[$b]);
                x[$d] = rotate!(veorq_u32(x[$d], x[$a]), 16, 16);
                x[$c] = vaddq_u32(x[$c], x[$d]);
                x[$b] = rotate!(veorq_u32(x[$b], x[$c]), 12, 20);
                x[$a] = vaddq_u32(x[$a], x[$b]);
                x[$d] = rotate!(veorq_u32(x[$d], x[$a]), 8, 24);
                x[$c] = vaddq_u32(x[$c], x[$d]);
                x[$b] = rotate!(veorq_u32(x[$b], x[$c]), 7, 25);
            };
        }
        for _ in 0..10 {
            qround!(0, 4, 8, 12);
            qround!(1, 5, 9, 13);
            qround!(2, 6, 10, 14);
            qround!(3, 7, 11, 15);
            qround!(0, 5, 10, 15);
            qround!(1, 6, 11, 12);
            qround!(2, 7, 8, 13);
            qround!(3, 4, 9, 14);
        }
        let mut ks = [[0u32; 4]; 16];
        for ((out, x), start) in ks.iter_mut().zip(x).zip(start) {
            // SAFETY: the array has its 16 bytes, and this store takes any
            // alignment.
            unsafe { vst1q_u32(out.as_mut_ptr(), vaddq_u32(x, start)) };
        }
        super::xor_words(data, &ks);
    }
}
