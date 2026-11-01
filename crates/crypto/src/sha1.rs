//! SHA-1: port of `sha1.c`.

use crate::clear::clear;
use crate::digest::Digest;

/// The length of a SHA-1 digest, in bytes.
pub const SHA1_LENGTH: usize = 20;

/// The length of a block of SHA-1's input, in bytes.
const BLOCK_LENGTH: usize = 64;

fn f(b: u32, c: u32, d: u32) -> u32 {
    ((c ^ d) & b) ^ d
}

fn g(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}

fn h(b: u32, c: u32, d: u32) -> u32 {
    (d & c) | ((d | c) & b)
}

const K1: u32 = 0x5A82_7999;
const K2: u32 = 0x6ED9_EBA1;
const K3: u32 = 0x8F1B_BCDC;
const K4: u32 = 0xCA62_C1D6;

/// `br_sha1_IV`.
const IV: [u32; 5] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];

/// `br_sha1_round`: one block into the state, with the processor's
/// instructions where the build and the processor have them.
#[inline]
pub(crate) fn round(buf: &[u8; BLOCK_LENGTH], val: &mut [u32; 5]) {
    #[cfg(all(
        feature = "unsafe-fast",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    if crate::sha_hw::sha1_round(buf, val) {
        return;
    }
    round_code(buf, val);
}

pub(crate) fn round_code(buf: &[u8; BLOCK_LENGTH], val: &mut [u32; 5]) {
    let mut m = [0u32; 80];
    let [mut a, mut b, mut c, mut d, mut e] = *val;
    for (word, bytes) in m.iter_mut().zip(buf.as_chunks().0) {
        *word = u32::from_be_bytes(*bytes);
    }
    for i in 16..80 {
        let x = m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16];
        m[i] = x.rotate_left(1);
    }

    // Five steps, with the roles of the variables rotating, as BearSSL
    // writes them.
    macro_rules! steps {
        ($func:ident, $k:expr, $w:expr) => {
            e = e
                .wrapping_add(a.rotate_left(5))
                .wrapping_add($func(b, c, d))
                .wrapping_add($k)
                .wrapping_add($w[0]);
            b = b.rotate_left(30);
            d = d
                .wrapping_add(e.rotate_left(5))
                .wrapping_add($func(a, b, c))
                .wrapping_add($k)
                .wrapping_add($w[1]);
            a = a.rotate_left(30);
            c = c
                .wrapping_add(d.rotate_left(5))
                .wrapping_add($func(e, a, b))
                .wrapping_add($k)
                .wrapping_add($w[2]);
            e = e.rotate_left(30);
            b = b
                .wrapping_add(c.rotate_left(5))
                .wrapping_add($func(d, e, a))
                .wrapping_add($k)
                .wrapping_add($w[3]);
            d = d.rotate_left(30);
            a = a
                .wrapping_add(b.rotate_left(5))
                .wrapping_add($func(c, d, e))
                .wrapping_add($k)
                .wrapping_add($w[4]);
            c = c.rotate_left(30);
        };
    }
    let (groups, _) = m.as_chunks::<5>();
    for w in &groups[0..4] {
        steps!(f, K1, w);
    }
    for w in &groups[4..8] {
        steps!(g, K2, w);
    }
    for w in &groups[8..12] {
        steps!(h, K3, w);
    }
    for w in &groups[12..16] {
        // BearSSL's `I`, the same function as `G`.
        steps!(g, K4, w);
    }

    val[0] = val[0].wrapping_add(a);
    val[1] = val[1].wrapping_add(b);
    val[2] = val[2].wrapping_add(c);
    val[3] = val[3].wrapping_add(d);
    val[4] = val[4].wrapping_add(e);
}

/// A SHA-1 computation: `br_sha1_context`.
///
/// What it has hashed is overwritten when it is dropped (best effort).
#[derive(Clone)]
pub struct Sha1 {
    buf: [u8; BLOCK_LENGTH],
    count: u64,
    val: [u32; 5],
}

impl Sha1 {
    /// `br_sha1_init`.
    pub fn new() -> Sha1 {
        Sha1 {
            buf: [0; BLOCK_LENGTH],
            count: 0,
            val: IV,
        }
    }

    /// `br_sha1_update`: more data.
    pub fn update(&mut self, mut data: &[u8]) {
        let mut ptr = (self.count & 63) as usize;
        while !data.is_empty() {
            let clen = (BLOCK_LENGTH - ptr).min(data.len());
            self.buf[ptr..ptr + clen].copy_from_slice(&data[..clen]);
            ptr += clen;
            data = &data[clen..];
            self.count = self.count.wrapping_add(clen as u64);
            if ptr == BLOCK_LENGTH {
                round(&self.buf, &mut self.val);
                ptr = 0;
            }
        }
    }

    /// `br_sha1_out`: the digest of the data so far. The computation can
    /// go on with more data.
    pub fn out(&self) -> [u8; SHA1_LENGTH] {
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
        let mut dst = [0u8; SHA1_LENGTH];
        for (bytes, word) in dst.as_chunks_mut().0.iter_mut().zip(val) {
            *bytes = word.to_be_bytes();
        }
        clear(&mut buf);
        clear(&mut val);
        dst
    }
}

impl Digest for Sha1 {
    type Output = [u8; SHA1_LENGTH];
    const OUTPUT_LENGTH: usize = SHA1_LENGTH;
    const BLOCK_LENGTH: usize = BLOCK_LENGTH;

    fn new() -> Sha1 {
        Sha1::new()
    }

    fn update(&mut self, data: &[u8]) {
        self.update(data);
    }

    fn out(&self) -> [u8; SHA1_LENGTH] {
        self.out()
    }

    /// `br_sha1_state`.
    fn state(&self) -> ([u8; SHA1_LENGTH], u64) {
        let mut dst = [0u8; SHA1_LENGTH];
        for (bytes, word) in dst.as_chunks_mut().0.iter_mut().zip(self.val) {
            *bytes = word.to_be_bytes();
        }
        (dst, self.count)
    }

    /// `br_sha1_set_state`.
    fn set_state(&mut self, stb: &[u8; SHA1_LENGTH], count: u64) {
        for (word, bytes) in self.val.iter_mut().zip(stb.as_chunks().0) {
            *word = u32::from_be_bytes(*bytes);
        }
        self.count = count;
    }
}

impl Default for Sha1 {
    fn default() -> Sha1 {
        Sha1::new()
    }
}

impl Drop for Sha1 {
    fn drop(&mut self) {
        clear(&mut self.buf);
        clear(&mut self.val);
    }
}

/// Shows how much was hashed, not the data or the state.
impl std::fmt::Debug for Sha1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sha1")
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
            let mut code = [0u32; 5];
            code.fill_with(|| next() as u32);
            let mut hw = code;
            if crate::sha_hw::sha1_round(&buf, &mut hw) {
                round_code(&buf, &mut code);
                assert_eq!(hw, code);
            }
        }
    }
}
