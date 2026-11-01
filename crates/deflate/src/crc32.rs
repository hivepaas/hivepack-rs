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
/// with the `unsafe-fast` feature, if the processor has them.
pub fn crc32(crc: u32, buf: &[u8]) -> u32 {
    #[cfg(all(feature = "unsafe-fast", target_arch = "aarch64"))]
    if std::arch::is_aarch64_feature_detected!("crc") {
        // SAFETY: the processor has the `crc` feature, just checked, which is
        // all `arm_crc32` asks of its caller.
        #[allow(unsafe_code)]
        return unsafe { arm_crc32(crc, buf) };
    }
    crc32_braided(crc, buf)
}

/// `crc32_z`'s `ARMCRC32` branch, without its alignment to words, as loading
/// a word here does not ask for one.
#[cfg(all(feature = "unsafe-fast", target_arch = "aarch64"))]
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
