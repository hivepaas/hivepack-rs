//! Integrity checks: port of `check/check.{h,c}`, with CRC32 and CRC64
//! (`check/crc32_fast.c`, `check/crc64_fast.c`, from their tables) and
//! SHA-256 (`check/sha256.c`).
//!
//! liblzma computes its CRC tables in `crc32_tablegen.c` and
//! `crc64_tablegen.c` and keeps them as source; the port computes the
//! same tables while compiling, slice-by-eight as liblzma's generic code
//! reads them, and a test checks them against their definitions. It has
//! none of liblzma's CLMUL, ARM64 or LoongArch versions, which give the
//! same values.

/// `lzma_check`: the type of the integrity check of a Stream, with the
/// same numbers. Any value up to [`CHECK_ID_MAX`] can be in a Stream's
/// header; only some are defined.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Check(pub u32);

impl Check {
    /// `LZMA_CHECK_NONE`.
    pub const NONE: Check = Check(0);
    /// `LZMA_CHECK_CRC32`.
    pub const CRC32: Check = Check(1);
    /// `LZMA_CHECK_CRC64`.
    pub const CRC64: Check = Check(4);
    /// `LZMA_CHECK_SHA256`.
    pub const SHA256: Check = Check(10);

    /// `lzma_check_is_supported`: whether the port computes this check.
    pub fn is_supported(self) -> bool {
        matches!(self.0, 0 | 1 | 4 | 10)
    }

    /// `lzma_check_size`: the size of the check, from its id, also for the
    /// ids that are not defined; `u32::MAX` past [`CHECK_ID_MAX`].
    pub fn size(self) -> u32 {
        const CHECK_SIZES: [u8; CHECK_ID_MAX as usize + 1] =
            [0, 4, 4, 4, 8, 8, 8, 16, 16, 16, 32, 32, 32, 64, 64, 64];
        if self.0 > CHECK_ID_MAX {
            return u32::MAX;
        }
        u32::from(CHECK_SIZES[self.0 as usize])
    }
}

/// `LZMA_CHECK_ID_MAX`.
pub const CHECK_ID_MAX: u32 = 15;

/// `LZMA_CHECK_SIZE_MAX`.
pub(crate) const CHECK_SIZE_MAX: usize = 64;

/// `LZMA_CHECK_BEST`: SHA-256, as the port has it.
pub(crate) const CHECK_BEST: Check = Check::SHA256;

/// `lzma_check_state`: the state of a check being computed, and the check
/// once finished, as `buffer` holds it.
#[derive(Clone)]
pub(crate) struct CheckState {
    /// The finished check, as it is written in the Stream.
    pub(crate) buffer: [u8; 64],
    crc32: u32,
    crc64: u64,
    sha256: Sha256,
}

impl CheckState {
    /// `lzma_check_init`.
    pub(crate) fn new(check: Check) -> CheckState {
        let _ = check;
        CheckState {
            buffer: [0; 64],
            crc32: 0,
            crc64: 0,
            sha256: Sha256::new(),
        }
    }

    /// `lzma_check_update`.
    pub(crate) fn update(&mut self, check: Check, buf: &[u8]) {
        match check {
            Check::CRC32 => self.crc32 = crc32(buf, self.crc32),
            Check::CRC64 => self.crc64 = crc64(buf, self.crc64),
            Check::SHA256 => self.sha256.update(buf),
            _ => {}
        }
    }

    /// `lzma_check_finish`.
    pub(crate) fn finish(&mut self, check: Check) {
        match check {
            Check::CRC32 => self.buffer[..4].copy_from_slice(&self.crc32.to_le_bytes()),
            Check::CRC64 => self.buffer[..8].copy_from_slice(&self.crc64.to_le_bytes()),
            Check::SHA256 => {
                let digest = self.sha256.finish();
                self.buffer[..32].copy_from_slice(&digest);
            }
            _ => {}
        }
    }
}

/// The eight tables of a slice-by-eight CRC, reflected, for `poly`.
const fn crc_tables<const N: usize>(poly: u64, bits: u32) -> [[u64; 256]; N] {
    let mut tables = [[0u64; 256]; N];
    let mask = if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let mut b = 0;
    while b < 256 {
        let mut r = b as u64;
        let mut i = 0;
        while i < 8 {
            r = if r & 1 != 0 { (r >> 1) ^ poly } else { r >> 1 };
            i += 1;
        }
        tables[0][b] = r & mask;
        b += 1;
    }
    let mut s = 1;
    while s < N {
        let mut b = 0;
        while b < 256 {
            let r = tables[s - 1][b];
            tables[s][b] = (tables[0][(r & 0xff) as usize] ^ (r >> 8)) & mask;
            b += 1;
        }
        s += 1;
    }
    tables
}

/// `lzma_crc32_table`, slice-by-eight.
static CRC32_TABLE: [[u64; 256]; 8] = crc_tables::<8>(0xEDB8_8320, 32);

/// `lzma_crc64_table`, slice-by-eight.
static CRC64_TABLE: [[u64; 256]; 8] = crc_tables::<8>(0xC96C_5795_D787_0F42, 64);

/// `lzma_crc32`: the CRC32 of `buf` after `crc`.
pub(crate) fn crc32(buf: &[u8], crc: u32) -> u32 {
    let t = &CRC32_TABLE;
    let mut crc = u64::from(!crc);
    let (chunks, rest) = buf.as_chunks::<8>();
    for c in chunks {
        let lo = u64::from(u32::from_le_bytes([c[0], c[1], c[2], c[3]])) ^ crc;
        let hi = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
        crc = t[7][(lo & 0xff) as usize]
            ^ t[6][((lo >> 8) & 0xff) as usize]
            ^ t[5][((lo >> 16) & 0xff) as usize]
            ^ t[4][(lo >> 24) as usize]
            ^ t[3][(hi & 0xff) as usize]
            ^ t[2][((hi >> 8) & 0xff) as usize]
            ^ t[1][((hi >> 16) & 0xff) as usize]
            ^ t[0][(hi >> 24) as usize];
    }
    for &b in rest {
        crc = t[0][((crc ^ u64::from(b)) & 0xff) as usize] ^ (crc >> 8);
    }
    !(crc as u32)
}

/// `lzma_crc64`: the CRC64 of `buf` after `crc`.
pub(crate) fn crc64(buf: &[u8], crc: u64) -> u64 {
    let t = &CRC64_TABLE;
    let mut crc = !crc;
    let (chunks, rest) = buf.as_chunks::<8>();
    for c in chunks {
        let v = u64::from_le_bytes(*c) ^ crc;
        crc = t[7][(v & 0xff) as usize]
            ^ t[6][((v >> 8) & 0xff) as usize]
            ^ t[5][((v >> 16) & 0xff) as usize]
            ^ t[4][((v >> 24) & 0xff) as usize]
            ^ t[3][((v >> 32) & 0xff) as usize]
            ^ t[2][((v >> 40) & 0xff) as usize]
            ^ t[1][((v >> 48) & 0xff) as usize]
            ^ t[0][(v >> 56) as usize];
    }
    for &b in rest {
        crc = t[0][((crc ^ u64::from(b)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

/// SHA-256's round constants.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// The state of `lzma_sha256_*`: the hash so far, the bytes of the block
/// not yet hashed, and how many bytes were given.
#[derive(Clone)]
struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    size: u64,
}

impl Sha256 {
    /// `lzma_sha256_init`.
    fn new() -> Sha256 {
        Sha256 {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            block: [0; 64],
            size: 0,
        }
    }

    /// `transform`: one block into the state.
    fn transform(state: &mut [u32; 8], data: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                data[4 * i],
                data[4 * i + 1],
                data[4 * i + 2],
                data[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }

    /// `lzma_sha256_update`.
    fn update(&mut self, mut buf: &[u8]) {
        while !buf.is_empty() {
            let used = (self.size & 0x3f) as usize;
            let copy_size = (64 - used).min(buf.len());
            self.block[used..used + copy_size].copy_from_slice(&buf[..copy_size]);
            buf = &buf[copy_size..];
            self.size += copy_size as u64;
            if self.size & 0x3f == 0 {
                Sha256::transform(&mut self.state, &self.block);
            }
        }
    }

    /// `lzma_sha256_finish`: the digest.
    fn finish(&mut self) -> [u8; 32] {
        // Add padding as described in RFC 3174 (it describes SHA-1 but the
        // same padding style is used for SHA-256 too).
        let mut pos = (self.size & 0x3f) as usize;
        self.block[pos] = 0x80;
        pos += 1;
        while pos != 64 - 8 {
            if pos == 64 {
                Sha256::transform(&mut self.state, &self.block);
                pos = 0;
            }
            self.block[pos] = 0x00;
            pos += 1;
        }

        // Convert the message size from bytes to bits.
        let bits = self.size.wrapping_mul(8);
        self.block[56..64].copy_from_slice(&bits.to_be_bytes());
        Sha256::transform(&mut self.state, &self.block);

        let mut digest = [0u8; 32];
        for (i, s) in self.state.iter().enumerate() {
            digest[4 * i..4 * i + 4].copy_from_slice(&s.to_be_bytes());
        }
        digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The check values of the CRC catalogue entries CRC-32/ISO-HDLC and
    /// CRC-64/XZ, and the digest of "abc".
    #[test]
    fn check_values() {
        assert_eq!(crc32(b"123456789", 0), 0xcbf4_3926);
        assert_eq!(crc64(b"123456789", 0), 0x995d_c9bb_df19_39fa);
        // In pieces, of every alignment.
        for split in 0..9 {
            let (a, b) = b"123456789".split_at(split);
            assert_eq!(crc32(b, crc32(a, 0)), 0xcbf4_3926);
            assert_eq!(crc64(b, crc64(a, 0)), 0x995d_c9bb_df19_39fa);
        }
        // FIPS 180-2's examples: one block and two.
        for (message, digest) in [
            (
                &b"abc"[..],
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                &b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"[..],
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ] {
            let mut sha = Sha256::new();
            sha.update(message);
            let hex: String = sha.finish().iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(hex, digest);
        }
        // Lengths around the padding's edges, in pieces.
        let data: Vec<u8> = (0..200u8).collect();
        let mut whole = Sha256::new();
        whole.update(&data[..119]);
        let mut pieces = Sha256::new();
        for piece in data[..119].chunks(7) {
            pieces.update(piece);
        }
        assert_eq!(whole.finish(), pieces.finish());
    }

    /// The CRCs from the tables, slice-by-eight, against the CRCs computed
    /// a bit at a time from their polynomials, for lengths and alignments
    /// around the eight bytes each step takes.
    #[test]
    fn tables_follow_the_polynomials() {
        fn bitwise32(data: &[u8]) -> u32 {
            let mut crc = !0u32;
            for &byte in data {
                crc ^= u32::from(byte);
                for _ in 0..8 {
                    crc = (crc >> 1) ^ (0xEDB8_8320 & 0u32.wrapping_sub(crc & 1));
                }
            }
            !crc
        }
        fn bitwise64(data: &[u8]) -> u64 {
            let mut crc = !0u64;
            for &byte in data {
                crc ^= u64::from(byte);
                for _ in 0..8 {
                    crc = (crc >> 1) ^ (0xC96C_5795_D787_0F42 & 0u64.wrapping_sub(crc & 1));
                }
            }
            !crc
        }
        let data: Vec<u8> = (0..600u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        for start in 0..9 {
            for len in (0..40).chain([255, 256, 257, 500]) {
                let piece = &data[start..start + len];
                assert_eq!(crc32(piece, 0), bitwise32(piece), "crc32 {start} {len}");
                assert_eq!(crc64(piece, 0), bitwise64(piece), "crc64 {start} {len}");
            }
        }
    }
}
