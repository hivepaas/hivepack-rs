//! SHA-1 and SHA-256 with the processor's instructions, for the `unsafe-fast`
//! feature: the SHA extensions on x86-64, and the SHA instructions of ARMv8 on
//! arm64. A block goes in the state as `sha1.rs` and `sha2small.rs` do it.
//!
//! Not in BearSSL. The order of the instructions is the one Intel's and Arm's
//! manuals give for these functions.
//!
//! The only unsafe code is calling functions with a `target_feature` once the
//! processor is known to have it, which each function here checks first, and
//! loading and storing 16 bytes of an array. See `docs/unsafe.md` in the
//! repository.
#![allow(unsafe_code)]

/// One block into the SHA-1 state, if the processor can: `false` if not, and
/// the state is as it was.
#[inline]
pub(crate) fn sha1_round(buf: &[u8; 64], val: &mut [u32; 5]) -> bool {
    if !imp::detected() {
        return false;
    }
    // SAFETY: the processor has what these need, just checked.
    unsafe { imp::sha1(buf, val) };
    true
}

/// One block into the SHA-256 state, if the processor can: `false` if not, and
/// the state is as it was. `k`: its constants.
#[inline]
pub(crate) fn sha256_round(buf: &[u8; 64], val: &mut [u32; 8], k: &[u32; 64]) -> bool {
    if !imp::detected() {
        return false;
    }
    // SAFETY: the processor has what these need, just checked.
    unsafe { imp::sha256(buf, val, k) };
    true
}

#[cfg(target_arch = "x86_64")]
mod imp {
    use std::arch::x86_64::{
        __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_blend_epi16, _mm_extract_epi32,
        _mm_loadu_si128, _mm_set_epi32, _mm_set_epi64x, _mm_sha1msg1_epu32, _mm_sha1msg2_epu32,
        _mm_sha1nexte_epu32, _mm_sha1rnds4_epu32, _mm_sha256msg1_epu32, _mm_sha256msg2_epu32,
        _mm_sha256rnds2_epu32, _mm_shuffle_epi8, _mm_shuffle_epi32, _mm_storeu_si128,
        _mm_xor_si128,
    };

    #[inline]
    pub(super) fn detected() -> bool {
        std::is_x86_feature_detected!("sha")
            && std::is_x86_feature_detected!("ssse3")
            && std::is_x86_feature_detected!("sse4.1")
    }

    #[inline]
    #[target_feature(enable = "sse2")]
    fn block(buf: &[u8; 64], i: usize) -> __m128i {
        let bytes = &buf.as_chunks::<16>().0[i];
        // SAFETY: the 16 bytes are there, and this load takes any alignment.
        unsafe { _mm_loadu_si128(bytes.as_ptr().cast()) }
    }

    #[target_feature(enable = "sha,ssse3,sse4.1")]
    pub(super) fn sha1(buf: &[u8; 64], val: &mut [u32; 5]) {
        let swap = _mm_set_epi64x(0x0001_0203_0405_0607, 0x0809_0A0B_0C0D_0E0F);
        let start = _mm_shuffle_epi32::<0x1B>(_mm_set_epi32(
            val[3] as i32,
            val[2] as i32,
            val[1] as i32,
            val[0] as i32,
        ));
        let start_e = _mm_set_epi32(val[4] as i32, 0, 0, 0);
        let mut abcd = start;
        let mut e = start_e;
        let mut m = [_mm_set_epi64x(0, 0); 20];
        for i in 0..20 {
            m[i] = if i < 4 {
                _mm_shuffle_epi8(block(buf, i), swap)
            } else {
                _mm_sha1msg2_epu32(
                    _mm_xor_si128(_mm_sha1msg1_epu32(m[i - 4], m[i - 3]), m[i - 2]),
                    m[i - 1],
                )
            };
            let with = if i == 0 {
                _mm_add_epi32(e, m[0])
            } else {
                _mm_sha1nexte_epu32(e, m[i])
            };
            e = abcd;
            abcd = match i / 5 {
                0 => _mm_sha1rnds4_epu32::<0>(abcd, with),
                1 => _mm_sha1rnds4_epu32::<1>(abcd, with),
                2 => _mm_sha1rnds4_epu32::<2>(abcd, with),
                _ => _mm_sha1rnds4_epu32::<3>(abcd, with),
            };
        }
        let e = _mm_sha1nexte_epu32(e, start_e);
        let abcd = _mm_shuffle_epi32::<0x1B>(_mm_add_epi32(abcd, start));
        let mut out = [0u32; 4];
        // SAFETY: the 16 bytes are there, and this store takes any alignment.
        unsafe { _mm_storeu_si128(out.as_mut_ptr().cast(), abcd) };
        val[..4].copy_from_slice(&out);
        val[4] = _mm_extract_epi32::<3>(e) as u32;
    }

    #[target_feature(enable = "sha,ssse3,sse4.1")]
    pub(super) fn sha256(buf: &[u8; 64], val: &mut [u32; 8], k: &[u32; 64]) {
        let swap = _mm_set_epi64x(0x0C0D_0E0F_0809_0A0B, 0x0405_0607_0001_0203);
        let dcba = _mm_shuffle_epi32::<0xB1>(_mm_set_epi32(
            val[3] as i32,
            val[2] as i32,
            val[1] as i32,
            val[0] as i32,
        ));
        let efgh = _mm_shuffle_epi32::<0x1B>(_mm_set_epi32(
            val[7] as i32,
            val[6] as i32,
            val[5] as i32,
            val[4] as i32,
        ));
        let start0 = _mm_alignr_epi8::<8>(dcba, efgh);
        let start1 = _mm_blend_epi16::<0xF0>(efgh, dcba);
        let (mut state0, mut state1) = (start0, start1);
        let mut m = [_mm_set_epi64x(0, 0); 16];
        for i in 0..16 {
            m[i] = if i < 4 {
                _mm_shuffle_epi8(block(buf, i), swap)
            } else {
                _mm_sha256msg2_epu32(
                    _mm_add_epi32(
                        _mm_sha256msg1_epu32(m[i - 4], m[i - 3]),
                        _mm_alignr_epi8::<4>(m[i - 1], m[i - 2]),
                    ),
                    m[i - 1],
                )
            };
            let round = &k[i * 4..i * 4 + 4];
            let with = _mm_add_epi32(
                m[i],
                _mm_set_epi32(
                    round[3] as i32,
                    round[2] as i32,
                    round[1] as i32,
                    round[0] as i32,
                ),
            );
            state1 = _mm_sha256rnds2_epu32(state1, state0, with);
            state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32::<0x0E>(with));
        }
        let state0 = _mm_add_epi32(state0, start0);
        let state1 = _mm_add_epi32(state1, start1);
        let feba = _mm_shuffle_epi32::<0x1B>(state0);
        let dchg = _mm_shuffle_epi32::<0xB1>(state1);
        let mut out = [0u32; 8];
        let (low, high) = out.split_at_mut(4);
        // SAFETY: each half has its 16 bytes, and this store takes any alignment.
        unsafe {
            _mm_storeu_si128(low.as_mut_ptr().cast(), _mm_blend_epi16::<0xF0>(feba, dchg));
            _mm_storeu_si128(high.as_mut_ptr().cast(), _mm_alignr_epi8::<8>(dchg, feba));
        }
        *val = out;
    }
}

#[cfg(target_arch = "aarch64")]
mod imp {
    use std::arch::aarch64::{
        uint32x4_t, vaddq_u32, vdupq_n_u32, vgetq_lane_u32, vld1q_u8, vld1q_u32,
        vreinterpretq_u32_u8, vrev32q_u8, vsha1cq_u32, vsha1h_u32, vsha1mq_u32, vsha1pq_u32,
        vsha1su0q_u32, vsha1su1q_u32, vsha256h2q_u32, vsha256hq_u32, vsha256su0q_u32,
        vsha256su1q_u32, vst1q_u32,
    };

    #[inline]
    pub(super) fn detected() -> bool {
        std::arch::is_aarch64_feature_detected!("sha2")
    }

    #[inline]
    #[target_feature(enable = "neon")]
    fn block(buf: &[u8; 64], i: usize) -> uint32x4_t {
        let bytes = &buf.as_chunks::<16>().0[i];
        // SAFETY: the 16 bytes are there, and this load takes any alignment.
        vreinterpretq_u32_u8(vrev32q_u8(unsafe { vld1q_u8(bytes.as_ptr()) }))
    }

    #[inline]
    #[target_feature(enable = "neon")]
    fn words(w: &[u32]) -> uint32x4_t {
        let w: &[u32; 4] = &w.as_chunks::<4>().0[0];
        // SAFETY: the 16 bytes are there, and this load takes any alignment.
        unsafe { vld1q_u32(w.as_ptr()) }
    }

    #[inline]
    #[target_feature(enable = "neon")]
    fn put(out: &mut [u32], w: uint32x4_t) {
        let out: &mut [u32; 4] = &mut out.as_chunks_mut::<4>().0[0];
        // SAFETY: the 16 bytes are there, and this store takes any alignment.
        unsafe { vst1q_u32(out.as_mut_ptr(), w) }
    }

    #[target_feature(enable = "neon,sha2")]
    pub(super) fn sha1(buf: &[u8; 64], val: &mut [u32; 5]) {
        const K: [u32; 4] = [0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xCA62_C1D6];
        let start = words(&val[..4]);
        let start_e = val[4];
        let mut abcd = start;
        let mut e = start_e;
        let mut m = [vdupq_n_u32(0); 20];
        for i in 0..20 {
            m[i] = if i < 4 {
                block(buf, i)
            } else {
                vsha1su1q_u32(vsha1su0q_u32(m[i - 4], m[i - 3], m[i - 2]), m[i - 1])
            };
            let with = vaddq_u32(m[i], vdupq_n_u32(K[i / 5]));
            let next_e = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
            abcd = match i / 5 {
                0 => vsha1cq_u32(abcd, e, with),
                2 => vsha1mq_u32(abcd, e, with),
                _ => vsha1pq_u32(abcd, e, with),
            };
            e = next_e;
        }
        put(&mut val[..4], vaddq_u32(abcd, start));
        val[4] = e.wrapping_add(start_e);
    }

    #[target_feature(enable = "neon,sha2")]
    pub(super) fn sha256(buf: &[u8; 64], val: &mut [u32; 8], k: &[u32; 64]) {
        let start0 = words(&val[..4]);
        let start1 = words(&val[4..]);
        let (mut abcd, mut efgh) = (start0, start1);
        let mut m = [vdupq_n_u32(0); 16];
        for i in 0..16 {
            m[i] = if i < 4 {
                block(buf, i)
            } else {
                vsha256su1q_u32(vsha256su0q_u32(m[i - 4], m[i - 3]), m[i - 2], m[i - 1])
            };
            let with = vaddq_u32(m[i], words(&k[i * 4..i * 4 + 4]));
            let before = abcd;
            abcd = vsha256hq_u32(abcd, efgh, with);
            efgh = vsha256h2q_u32(efgh, before, with);
        }
        put(&mut val[..4], vaddq_u32(abcd, start0));
        put(&mut val[4..], vaddq_u32(efgh, start1));
    }
}
