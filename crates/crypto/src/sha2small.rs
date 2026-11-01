//! SHA-256: port of `sha2small.c`.
//!
//! Differs from BearSSL: SHA-256 only, without SHA-224, which nothing here
//! uses.

use crate::clear::clear;
use crate::digest::Digest;

/// The length of a SHA-256 digest, in bytes.
pub const SHA256_LENGTH: usize = 32;

/// The length of a block of SHA-256's input, in bytes.
const BLOCK_LENGTH: usize = 64;

fn ch(x: u32, y: u32, z: u32) -> u32 {
    ((y ^ z) & x) ^ z
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (y & z) | ((y | z) & x)
}

fn bsg2_0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

fn bsg2_1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

fn ssg2_0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

fn ssg2_1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// `br_sha256_IV`.
const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

#[rustfmt::skip]
const K: [u32; 64] = [
    0x428A_2F98, 0x7137_4491, 0xB5C0_FBCF, 0xE9B5_DBA5,
    0x3956_C25B, 0x59F1_11F1, 0x923F_82A4, 0xAB1C_5ED5,
    0xD807_AA98, 0x1283_5B01, 0x2431_85BE, 0x550C_7DC3,
    0x72BE_5D74, 0x80DE_B1FE, 0x9BDC_06A7, 0xC19B_F174,
    0xE49B_69C1, 0xEFBE_4786, 0x0FC1_9DC6, 0x240C_A1CC,
    0x2DE9_2C6F, 0x4A74_84AA, 0x5CB0_A9DC, 0x76F9_88DA,
    0x983E_5152, 0xA831_C66D, 0xB003_27C8, 0xBF59_7FC7,
    0xC6E0_0BF3, 0xD5A7_9147, 0x06CA_6351, 0x1429_2967,
    0x27B7_0A85, 0x2E1B_2138, 0x4D2C_6DFC, 0x5338_0D13,
    0x650A_7354, 0x766A_0ABB, 0x81C2_C92E, 0x9272_2C85,
    0xA2BF_E8A1, 0xA81A_664B, 0xC24B_8B70, 0xC76C_51A3,
    0xD192_E819, 0xD699_0624, 0xF40E_3585, 0x106A_A070,
    0x19A4_C116, 0x1E37_6C08, 0x2748_774C, 0x34B0_BCB5,
    0x391C_0CB3, 0x4ED8_AA4A, 0x5B9C_CA4F, 0x682E_6FF3,
    0x748F_82EE, 0x78A5_636F, 0x84C8_7814, 0x8CC7_0208,
    0x90BE_FFFA, 0xA450_6CEB, 0xBEF9_A3F7, 0xC671_78F2,
];

/// `br_sha2small_round`: one block into the state, with the processor's
/// instructions where the build and the processor have them.
#[inline]
pub(crate) fn round(buf: &[u8; BLOCK_LENGTH], val: &mut [u32; 8]) {
    #[cfg(all(
        feature = "unsafe-fast",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    if crate::sha_hw::sha256_round(buf, val, &K) {
        return;
    }
    round_code(buf, val);
}

pub(crate) fn round_code(buf: &[u8; BLOCK_LENGTH], val: &mut [u32; 8]) {
    let mut w = [0u32; 64];
    for (word, bytes) in w.iter_mut().zip(buf.as_chunks().0) {
        *word = u32::from_be_bytes(*bytes);
    }
    for i in 16..64 {
        w[i] = ssg2_1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(ssg2_0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *val;

    // `SHA2_STEP`, with the roles of the variables rotating, as BearSSL
    // writes it.
    macro_rules! step {
        ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $j:expr) => {
            let t1 = $h
                .wrapping_add(bsg2_1($e))
                .wrapping_add(ch($e, $f, $g))
                .wrapping_add(K[$j])
                .wrapping_add(w[$j]);
            let t2 = bsg2_0($a).wrapping_add(maj($a, $b, $c));
            $d = $d.wrapping_add(t1);
            $h = t1.wrapping_add(t2);
        };
    }
    for i in (0..64).step_by(8) {
        step!(a, b, c, d, e, f, g, h, i);
        step!(h, a, b, c, d, e, f, g, i + 1);
        step!(g, h, a, b, c, d, e, f, i + 2);
        step!(f, g, h, a, b, c, d, e, i + 3);
        step!(e, f, g, h, a, b, c, d, i + 4);
        step!(d, e, f, g, h, a, b, c, i + 5);
        step!(c, d, e, f, g, h, a, b, i + 6);
        step!(b, c, d, e, f, g, h, a, i + 7);
    }
    for (v, x) in val.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *v = v.wrapping_add(x);
    }
}

/// A SHA-256 computation: `br_sha256_context`.
///
/// What it has hashed is overwritten when it is dropped (best effort).
#[derive(Clone)]
pub struct Sha256 {
    buf: [u8; BLOCK_LENGTH],
    count: u64,
    val: [u32; 8],
}

impl Sha256 {
    /// `br_sha256_init`.
    pub fn new() -> Sha256 {
        Sha256 {
            buf: [0; BLOCK_LENGTH],
            count: 0,
            val: IV,
        }
    }

    /// `br_sha256_update` (`sha2small_update`): more data.
    pub fn update(&mut self, mut data: &[u8]) {
        let mut ptr = (self.count & 63) as usize;
        self.count = self.count.wrapping_add(data.len() as u64);
        while !data.is_empty() {
            let clen = (BLOCK_LENGTH - ptr).min(data.len());
            self.buf[ptr..ptr + clen].copy_from_slice(&data[..clen]);
            ptr += clen;
            data = &data[clen..];
            if ptr == BLOCK_LENGTH {
                round(&self.buf, &mut self.val);
                ptr = 0;
            }
        }
    }

    /// `br_sha256_out` (`sha2small_out`): the digest of the data so far.
    /// The computation can go on with more data.
    pub fn out(&self) -> [u8; SHA256_LENGTH] {
        let mut buf = [0u8; BLOCK_LENGTH];
        let mut val = self.val;
        let mut ptr = (self.count & 63) as usize;
        buf[..ptr].copy_from_slice(&self.buf[..ptr]);
        buf[ptr] = 0x80;
        ptr += 1;
        if ptr > 56 {
            round(&buf, &mut val);
            buf[..56].fill(0);
        }
        buf[56..].copy_from_slice(&(self.count << 3).to_be_bytes());
        round(&buf, &mut val);
        let mut dst = [0u8; SHA256_LENGTH];
        for (bytes, word) in dst.as_chunks_mut().0.iter_mut().zip(val) {
            *bytes = word.to_be_bytes();
        }
        clear(&mut buf);
        clear(&mut val);
        dst
    }
}

impl Digest for Sha256 {
    type Output = [u8; SHA256_LENGTH];
    const OUTPUT_LENGTH: usize = SHA256_LENGTH;
    const BLOCK_LENGTH: usize = BLOCK_LENGTH;

    fn new() -> Sha256 {
        Sha256::new()
    }

    fn update(&mut self, data: &[u8]) {
        self.update(data);
    }

    fn out(&self) -> [u8; SHA256_LENGTH] {
        self.out()
    }

    /// `br_sha224_state`, which SHA-256 shares.
    fn state(&self) -> ([u8; SHA256_LENGTH], u64) {
        let mut dst = [0u8; SHA256_LENGTH];
        for (bytes, word) in dst.as_chunks_mut().0.iter_mut().zip(self.val) {
            *bytes = word.to_be_bytes();
        }
        (dst, self.count)
    }

    /// `br_sha224_set_state`, which SHA-256 shares.
    fn set_state(&mut self, stb: &[u8; SHA256_LENGTH], count: u64) {
        for (word, bytes) in self.val.iter_mut().zip(stb.as_chunks().0) {
            *word = u32::from_be_bytes(*bytes);
        }
        self.count = count;
    }
}

impl Default for Sha256 {
    fn default() -> Sha256 {
        Sha256::new()
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        clear(&mut self.buf);
        clear(&mut self.val);
    }
}

/// Shows how much was hashed, not the data or the state.
impl std::fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sha256")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

#[cfg(all(
    test,
    feature = "unsafe-fast",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod hw_tests {
    use super::*;

    /// The instructions, where they run, against the code.
    #[test]
    fn instructions_same_as_code() {
        let mut state = 0x0123_4567_89AB_CDEFu64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..2000 {
            let mut buf = [0u8; 64];
            buf.fill_with(|| next() as u8);
            let mut code = [0u32; 8];
            code.fill_with(|| next() as u32);
            let mut hw = code;
            if crate::sha_hw::sha256_round(&buf, &mut hw, &K) {
                round_code(&buf, &mut code);
                assert_eq!(hw, code);
            }
        }
    }
}
