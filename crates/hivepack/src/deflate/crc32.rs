//! CRC-32: port of `crc32.c`, the braided calculation with N = 5 braids of
//! W = 8-byte words, which zlib uses on x86-64 and arm64.
//!
//! zlib's tables are in `crc32.h`, which `crc32.c` writes when built with
//! `MAKECRCH`. The port computes them while compiling, with the same
//! functions (`make_crc_table`, `braid`), and the tests compare entries
//! with `crc32.h`.

/// `POLY`: p(x) reflected, with x^32 implied.
const POLY: u32 = 0xedb8_8320;

/// `N`: the number of braids.
const N: usize = 5;

/// `W`: the bytes in a word.
const W: usize = 8;

/// a(x) multiplied by b(x) modulo p(x), where p(x) is the CRC polynomial,
/// reflected. For speed, this requires that a not be zero.
///
/// Port of `multmodp`, `crc32.c`.
const fn multmodp(a: u32, mut b: u32) -> u32 {
    let mut m: u32 = 1 << 31;
    let mut p: u32 = 0;
    loop {
        if a & m != 0 {
            p ^= b;
            if a & (m - 1) == 0 {
                break;
            }
        }
        m >>= 1;
        b = if b & 1 != 0 { (b >> 1) ^ POLY } else { b >> 1 };
    }
    p
}

/// x^(n * 2^k) modulo p(x). n must not be negative.
///
/// Port of `x2nmodp`, `crc32.c`.
const fn x2nmodp(mut n: i64, mut k: u32) -> u32 {
    let mut p: u32 = 1 << 31; // x^0 == 1
    while n != 0 {
        if n & 1 != 0 {
            p = multmodp(X2N_TABLE[(k & 31) as usize], p);
        }
        n >>= 1;
        k += 1;
    }
    p
}

/// The CRC of each byte, and x^2^n mod p(x) for n in 0..32.
///
/// Port of the first half of `make_crc_table`, `crc32.c`.
const fn make_crc_table() -> ([u32; 256], [u32; 32]) {
    let mut crc_table = [0u32; 256];
    // initialize the CRC of bytes tables
    let mut i = 0;
    while i < 256 {
        let mut p = i as u32;
        let mut j = 0;
        while j < 8 {
            p = if p & 1 != 0 { (p >> 1) ^ POLY } else { p >> 1 };
            j += 1;
        }
        crc_table[i] = p;
        i += 1;
    }

    // initialize the x^2^n mod p(x) table
    let mut x2n_table = [0u32; 32];
    let mut p: u32 = 1 << 30; // x^1
    x2n_table[0] = p;
    let mut n = 1;
    while n < 32 {
        p = multmodp(p, p);
        x2n_table[n] = p;
        n += 1;
    }
    (crc_table, x2n_table)
}

/// The little-endian braiding tables for N braids of W-byte words.
///
/// Port of `braid` (the `ltl` half), `crc32.c`. Differs from zlib: the port
/// reads words as little-endian on every machine, so it needs no
/// big-endian tables.
const fn braid() -> [[u32; 256]; W] {
    let mut ltl = [[0u32; 256]; W];
    let mut k = 0;
    while k < W {
        let p = x2nmodp(((N * W + 3 - k) << 3) as i64, 0);
        let mut i = 1;
        while i < 256 {
            ltl[k][i] = multmodp((i as u32) << 24, p);
            i += 1;
        }
        k += 1;
    }
    ltl
}

/// `crc_table`: the CRC of each byte value.
static CRC_TABLE: [u32; 256] = make_crc_table().0;

/// `x2n_table`: x^2^n mod p(x), for n in 0..32.
const X2N_TABLE: [u32; 32] = make_crc_table().1;

/// `crc_braid_table`.
static CRC_BRAID_TABLE: [[u32; 256]; W] = braid();

/// The table of CRCs of each byte value, as zlib's `get_crc_table`
/// returns it.
pub fn get_crc_table() -> &'static [u32; 256] {
    &CRC_TABLE
}

/// The CRC of the W bytes in `data`, taking its least-significant byte as
/// the first, without pre- or post-conditioning. Used to combine the CRCs
/// of the braids.
///
/// Port of `crc_word`, `crc32.c`.
#[inline(always)]
fn crc_word(mut data: u64) -> u32 {
    for _ in 0..W {
        data = (data >> 8) ^ u64::from(CRC_TABLE[(data & 0xff) as usize]);
    }
    data as u32
}

#[inline(always)]
fn read_word(buf: &[u8], pos: usize) -> u64 {
    let mut word = [0; W];
    word.copy_from_slice(&buf[pos..pos + W]);
    u64::from_le_bytes(word)
}

/// The CRC-32 of `buf`, continuing from `crc`: start from 0, the CRC of no
/// bytes.
///
/// Port of `crc32_z` (and `crc32`), `crc32.c`. The ARMv8 CRC instructions,
/// which zlib uses only when built for a processor that has them, are here
/// with the `unsafe-fast` feature, if the processor has them; and so is
/// x86-64's carry-less multiplication (`PCLMULQDQ`), as zlib-ng and Linux
/// fold with it, where zlib has none.
pub fn crc32(crc: u32, buf: &[u8]) -> u32 {
    #[cfg(all(feature = "deflate-unsafe-fast", target_arch = "aarch64"))]
    if std::arch::is_aarch64_feature_detected!("crc") {
        // SAFETY: the processor has the `crc` feature, just checked, which is
        // all `arm_crc32` asks of its caller.
        #[allow(unsafe_code)]
        return unsafe { arm_crc32(crc, buf) };
    }
    #[cfg(all(feature = "deflate-unsafe-fast", target_arch = "x86_64", not(miri)))]
    if buf.len() >= FOLD_LEAST
        && std::arch::is_x86_feature_detected!("pclmulqdq")
        && std::arch::is_x86_feature_detected!("sse4.1")
    {
        // SAFETY: the processor has the `pclmulqdq` and `sse4.1` features,
        // just checked, which is all `fold_crc32` asks of its caller.
        #[allow(unsafe_code)]
        return unsafe { fold_crc32(crc, buf) };
    }
    crc32_braided(crc, buf)
}

/// The least that [`fold_crc32`] is given: four blocks of 16 bytes, its four
/// lanes. Less goes to the braided calculation, as fast for so little.
#[cfg(all(feature = "deflate-unsafe-fast", target_arch = "x86_64", not(miri)))]
const FOLD_LEAST: usize = 64;

/// The CRC of `buf`, at least [`FOLD_LEAST`] bytes, by folding: four lanes
/// of 128 bits, each multiplied without carries by x^512 mod p(x) and the
/// next 64 bytes added, then folded into one, 16 bytes at a time, and
/// reduced to 32 bits by Barrett's reduction. Intel's "Fast CRC Computation
/// for Generic Polynomials Using PCLMULQDQ Instruction" (2009), as zlib-ng's
/// `crc32_fold_pclmulqdq`, crc32fast and Linux's `crc32-pclmul` compute
/// it, with their constants for the reflected polynomial; the bytes past the
/// last block of 16 go to the braided calculation.
///
/// Every step is safe code: `std::arch`'s intrinsics are, in a function
/// with their features. Calling it takes `unsafe`, as the compiler refuses a
/// call to a function with a `target_feature` otherwise.
#[cfg(all(feature = "deflate-unsafe-fast", target_arch = "x86_64", not(miri)))]
#[target_feature(enable = "pclmulqdq,sse4.1")]
fn fold_crc32(crc: u32, buf: &[u8]) -> u32 {
    use std::arch::x86_64::{
        __m128i, _mm_and_si128, _mm_clmulepi64_si128, _mm_cvtsi32_si128, _mm_extract_epi32,
        _mm_set_epi32, _mm_set_epi64x, _mm_srli_si128, _mm_xor_si128,
    };
    // x^(4*128+32) and x^(4*128-32) mod p(x), reflected, for four lanes;
    // x^(128+32) and x^(128-32) for one; x^64 for the last 64 bits; p(x)
    // and its Barrett constant, floor(x^64 / p(x)).
    const K1: i64 = 0x1_5444_2bd4;
    const K2: i64 = 0x1_c6e4_1596;
    const K3: i64 = 0x1_7519_97d0;
    const K4: i64 = 0x0_ccaa_009e;
    const K5: i64 = 0x1_63cd_6124;
    const P_X: i64 = 0x1_DB71_0641;
    const U_PRIME: i64 = 0x1_F701_1641;

    /// 16 bytes, the first the lowest.
    #[inline]
    #[target_feature(enable = "pclmulqdq,sse4.1")]
    fn load(block: &[u8; 16]) -> __m128i {
        let low = u64::from_le_bytes([
            block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7],
        ]);
        let high = u64::from_le_bytes([
            block[8], block[9], block[10], block[11], block[12], block[13], block[14], block[15],
        ]);
        _mm_set_epi64x(high as i64, low as i64)
    }
    /// `lane` folded over the 128 bits of `keys` and `next` added.
    #[inline]
    #[target_feature(enable = "pclmulqdq,sse4.1")]
    fn fold(lane: __m128i, next: __m128i, keys: __m128i) -> __m128i {
        let low = _mm_clmulepi64_si128::<0x00>(lane, keys);
        let high = _mm_clmulepi64_si128::<0x11>(lane, keys);
        _mm_xor_si128(_mm_xor_si128(next, low), high)
    }

    let (blocks, rest) = buf.as_chunks::<16>();
    // At least four, as `FOLD_LEAST` is.
    let Some((first, blocks)) = blocks.split_first_chunk::<4>() else {
        return crc32_braided(crc, buf);
    };
    let (fours, ones) = blocks.as_chunks::<4>();

    // Four lanes, the CRC so far added to the first.
    let mut x3 = _mm_xor_si128(load(&first[0]), _mm_cvtsi32_si128(!crc as i32));
    let mut x2 = load(&first[1]);
    let mut x1 = load(&first[2]);
    let mut x0 = load(&first[3]);
    let k1k2 = _mm_set_epi64x(K2, K1);
    for four in fours {
        x3 = fold(x3, load(&four[0]), k1k2);
        x2 = fold(x2, load(&four[1]), k1k2);
        x1 = fold(x1, load(&four[2]), k1k2);
        x0 = fold(x0, load(&four[3]), k1k2);
    }
    // Into one lane, and the blocks of 16 left.
    let k3k4 = _mm_set_epi64x(K4, K3);
    let mut x = fold(x3, x2, k3k4);
    x = fold(x, x1, k3k4);
    x = fold(x, x0, k3k4);
    for one in ones {
        x = fold(x, load(one), k3k4);
    }
    // 128 bits to 64, then to 32 with Barrett's reduction.
    let low32 = _mm_set_epi32(0, 0, 0, !0);
    let x = _mm_xor_si128(
        _mm_clmulepi64_si128::<0x10>(x, k3k4),
        _mm_srli_si128::<8>(x),
    );
    let x = _mm_xor_si128(
        _mm_clmulepi64_si128::<0x00>(_mm_and_si128(x, low32), _mm_set_epi64x(0, K5)),
        _mm_srli_si128::<4>(x),
    );
    let pu = _mm_set_epi64x(U_PRIME, P_X);
    let t1 = _mm_clmulepi64_si128::<0x10>(_mm_and_si128(x, low32), pu);
    let t2 = _mm_clmulepi64_si128::<0x00>(_mm_and_si128(t1, low32), pu);
    let crc = !(_mm_extract_epi32::<1>(_mm_xor_si128(x, t2)) as u32);
    crc32_braided(crc, rest)
}

/// `crc32_z`'s `ARMCRC32` branch, without its alignment to words, as loading
/// a word here does not ask for one.
#[cfg(all(feature = "deflate-unsafe-fast", target_arch = "aarch64"))]
#[target_feature(enable = "crc")]
fn arm_crc32(crc: u32, buf: &[u8]) -> u32 {
    use std::arch::aarch64::{__crc32b, __crc32d};
    let mut crc = !crc;
    let (words, rest) = buf.as_chunks::<8>();
    for word in words {
        crc = __crc32d(crc, u64::from_le_bytes(*word));
    }
    for &byte in rest {
        crc = __crc32b(crc, byte);
    }
    !crc
}

/// [`crc32`] without the processor's instructions, to compare with.
#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_crc32_braided(crc: u32, buf: &[u8]) -> u32 {
    crc32_braided(crc, buf)
}

/// The braided calculation of `crc32_z`.
fn crc32_braided(crc: u32, buf: &[u8]) -> u32 {
    // Differs from zlib: there is no null pointer to ask for the initial
    // value, which is 0.
    let mut len = buf.len();
    let mut pos = 0;

    // Pre-condition the CRC
    let mut crc = !crc;

    // If provided enough bytes, do a braided CRC calculation.
    if len >= N * W + W - 1 {
        // Compute the CRC up to a word boundary.
        while len != 0 && (buf[pos..].as_ptr().addr() & (W - 1)) != 0 {
            len -= 1;
            crc = (crc >> 8) ^ CRC_TABLE[((crc ^ u32::from(buf[pos])) & 0xff) as usize];
            pos += 1;
        }

        // Compute the CRC on as many N word blocks as are available.
        let mut blks = len / (N * W);
        len -= blks * N * W;

        // Differs from zlib: the words are read as little-endian, whatever
        // the machine, so only zlib's little-endian branch is needed.

        // Initialize the CRC for each braid.
        let mut crc0 = u64::from(crc);
        let mut crc1 = 0u64;
        let mut crc2 = 0u64;
        let mut crc3 = 0u64;
        let mut crc4 = 0u64;

        // Process the first blks-1 blocks, computing the CRCs on each braid
        // independently.
        blks -= 1;
        while blks != 0 {
            blks -= 1;
            // Load the word for each braid into registers.
            let word0 = crc0 ^ read_word(buf, pos);
            let word1 = crc1 ^ read_word(buf, pos + W);
            let word2 = crc2 ^ read_word(buf, pos + 2 * W);
            let word3 = crc3 ^ read_word(buf, pos + 3 * W);
            let word4 = crc4 ^ read_word(buf, pos + 4 * W);
            pos += N * W;

            // Compute and update the CRC for each word. The loop should get
            // unrolled.
            crc0 = u64::from(CRC_BRAID_TABLE[0][(word0 & 0xff) as usize]);
            crc1 = u64::from(CRC_BRAID_TABLE[0][(word1 & 0xff) as usize]);
            crc2 = u64::from(CRC_BRAID_TABLE[0][(word2 & 0xff) as usize]);
            crc3 = u64::from(CRC_BRAID_TABLE[0][(word3 & 0xff) as usize]);
            crc4 = u64::from(CRC_BRAID_TABLE[0][(word4 & 0xff) as usize]);
            for k in 1..W {
                let shift = k << 3;
                crc0 ^= u64::from(CRC_BRAID_TABLE[k][((word0 >> shift) & 0xff) as usize]);
                crc1 ^= u64::from(CRC_BRAID_TABLE[k][((word1 >> shift) & 0xff) as usize]);
                crc2 ^= u64::from(CRC_BRAID_TABLE[k][((word2 >> shift) & 0xff) as usize]);
                crc3 ^= u64::from(CRC_BRAID_TABLE[k][((word3 >> shift) & 0xff) as usize]);
                crc4 ^= u64::from(CRC_BRAID_TABLE[k][((word4 >> shift) & 0xff) as usize]);
            }
        }

        // Process the last block, combining the CRCs of the N braids at the
        // same time.
        let mut c = crc_word(crc0 ^ read_word(buf, pos));
        c = crc_word(crc1 ^ read_word(buf, pos + W) ^ u64::from(c));
        c = crc_word(crc2 ^ read_word(buf, pos + 2 * W) ^ u64::from(c));
        c = crc_word(crc3 ^ read_word(buf, pos + 3 * W) ^ u64::from(c));
        c = crc_word(crc4 ^ read_word(buf, pos + 4 * W) ^ u64::from(c));
        crc = c;
        pos += N * W;
    }

    // Complete the computation of the CRC on any remaining bytes.
    for &byte in &buf[pos..pos + len] {
        crc = (crc >> 8) ^ CRC_TABLE[((crc ^ u32::from(byte)) & 0xff) as usize];
    }

    // Return the CRC, post-conditioned.
    !crc
}

/// The operator that [`crc32_combine_op`] takes to combine with a second
/// piece of `len2` bytes. A negative length gives 0.
///
/// Port of `crc32_combine_gen64` (and `crc32_combine_gen`), `crc32.c`.
pub fn crc32_combine_gen(len2: i64) -> u32 {
    if len2 < 0 {
        return 0;
    }
    x2nmodp(len2, 3)
}

/// The CRC-32 of two pieces one after the other, from the CRC-32 of each
/// and an operator from [`crc32_combine_gen`] for the second's length.
///
/// Port of `crc32_combine_op`, `crc32.c`.
pub fn crc32_combine_op(crc1: u32, crc2: u32, op: u32) -> u32 {
    if op == 0 {
        return 0;
    }
    multmodp(op, crc1) ^ crc2
}

/// The CRC-32 of two pieces one after the other, from the CRC-32 of each
/// and the length of the second.
///
/// Port of `crc32_combine64` (and `crc32_combine`), `crc32.c`.
pub fn crc32_combine(crc1: u32, crc2: u32, len2: i64) -> u32 {
    crc32_combine_op(crc1, crc2, crc32_combine_gen(len2))
}

#[cfg(test)]
mod tests {

    /// The instructions, where they run, against the braided calculation.
    #[test]
    fn same_as_braided() {
        let mut state = 0x0123_4567_89AB_CDEFu64;
        let bytes: Vec<u8> = (0..4096)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        for start in 0..16 {
            for len in (0..300).chain([1024, 4000]) {
                let piece = &bytes[start..start + len];
                for from in [0, 1, 0xFFFF_FFFF, 0x89AB_CDEF] {
                    assert_eq!(crc32(from, piece), crc32_braided(from, piece));
                }
            }
        }
    }

    use super::*;

    /// The folding against the braided calculation, called itself where the
    /// processor has its instructions, whatever `crc32` chooses: every
    /// length from its least to past a few rounds of four lanes, at every
    /// offset of a block, from several values.
    #[cfg(all(feature = "deflate-unsafe-fast", target_arch = "x86_64", not(miri)))]
    #[test]
    fn folding_is_braided() {
        if !(std::arch::is_x86_feature_detected!("pclmulqdq")
            && std::arch::is_x86_feature_detected!("sse4.1"))
        {
            return;
        }
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let bytes: Vec<u8> = (0..8192)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        for start in 0..16 {
            for len in (FOLD_LEAST..400).chain([1000, 4096, 8000]) {
                let piece = &bytes[start..start + len];
                for from in [0, 1, 0xFFFF_FFFF, 0x1234_5678] {
                    // SAFETY: the processor has the features, checked above.
                    #[allow(unsafe_code)]
                    let folded = unsafe { fold_crc32(from, piece) };
                    assert_eq!(folded, crc32_braided(from, piece), "{start} {len} {from:x}");
                }
            }
        }
        // As one call, and in pieces.
        let whole = crc32(0, &bytes);
        let pieces = bytes.chunks(777).fold(0, crc32);
        assert_eq!(whole, pieces);
        assert_eq!(whole, reference(0, &bytes));
    }

    /// The definition, one bit at a time.
    fn reference(crc: u32, buf: &[u8]) -> u32 {
        let mut c = !crc;
        for &byte in buf {
            c ^= u32::from(byte);
            for _ in 0..8 {
                c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            }
        }
        !c
    }

    fn bytes(len: usize, seed: u32) -> Vec<u8> {
        let mut x = seed.wrapping_mul(2654435761).wrapping_add(1);
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn tables_match_crc32_h() {
        // First and last entries of each table in zlib 1.3.2's crc32.h,
        // for N = 5 and W = 8.
        assert_eq!(CRC_TABLE[1], 0x7707_3096);
        assert_eq!(CRC_TABLE[128], 0xedb8_8320);
        assert_eq!(CRC_TABLE[255], 0x2d02_ef8d);
        let braids = [
            (0xaf44_9247, 0xe994_7565),
            (0x4e89_0ba9, 0xf7d0_5006),
            (0x8d88_fde2, 0xb207_5b94),
            (0x80f0_171f, 0xba50_bcb9),
            (0x9570_d495, 0x808a_bcf4),
            (0xcf9e_17c8, 0xefdb_3f95),
            (0x2482_5136, 0x0e2f_bf43),
            (0x36f2_90f3, 0xf437_7108),
        ];
        for (k, &(first, last)) in braids.iter().enumerate() {
            assert_eq!(CRC_BRAID_TABLE[k][0], 0);
            assert_eq!(CRC_BRAID_TABLE[k][1], first, "braid {k}");
            assert_eq!(CRC_BRAID_TABLE[k][255], last, "braid {k}");
        }
        assert_eq!(X2N_TABLE[0], 0x4000_0000);
        assert_eq!(X2N_TABLE[1], 0x2000_0000);
        assert_eq!(X2N_TABLE[31], 0xc4e2_2c3c);
    }

    #[test]
    fn known_values() {
        assert_eq!(crc32(0, b""), 0);
        assert_eq!(crc32(0, b"123456789"), 0xcbf4_3926);
        assert_eq!(
            crc32(0, b"The quick brown fox jumps over the lazy dog"),
            0x414f_a339
        );
    }

    #[test]
    fn matches_the_definition() {
        // Around the braided threshold (N * W + W - 1 = 47) and block
        // multiples, at every alignment.
        let buf = bytes(2008, 1);
        for len in (0..120).chain([399, 400, 401, 1000, 1999]) {
            for start in 0..8 {
                let piece = &buf[start..start + len];
                for crc in [0, 0x1234_5678] {
                    assert_eq!(crc32(crc, piece), reference(crc, piece), "len {len}");
                }
            }
        }
    }

    #[test]
    fn combine() {
        let buf = bytes(10000, 3);
        for split in [0, 1, 47, 4096, 9999, 10000] {
            let (a, b) = buf.split_at(split);
            let whole = crc32(0, &buf);
            assert_eq!(
                crc32_combine(crc32(0, a), crc32(0, b), b.len() as i64),
                whole
            );
            let op = crc32_combine_gen(b.len() as i64);
            assert_eq!(crc32_combine_op(crc32(0, a), crc32(0, b), op), whole);
        }
        assert_eq!(crc32_combine_gen(-1), 0);
    }
}
