//! ChaCha20 (RFC 8439): port of `chacha20_ct.c`, BearSSL's portable
//! constant-time ChaCha20.

use crate::clear::clear;

/// The length of a ChaCha20 key, in bytes.
pub const CHACHA20_KEY_LENGTH: usize = 32;

/// The length of a ChaCha20 nonce (BearSSL's IV), in bytes.
pub const CHACHA20_NONCE_LENGTH: usize = 12;

/// "expand 32-byte k".
const CW: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// `br_chacha20_ct_run`: XORs `data` with the ChaCha20 key stream for
/// `key` and the nonce `iv`, starting at block `cc`, which encrypts and
/// decrypts alike. Returns the number of the block after the last one
/// used, from which more data can go on.
pub fn chacha20(
    key: &[u8; CHACHA20_KEY_LENGTH],
    iv: &[u8; CHACHA20_NONCE_LENGTH],
    mut cc: u32,
    data: &mut [u8],
) -> u32 {
    let mut kw = [0u32; 8];
    let mut ivw = [0u32; 3];
    for (word, bytes) in kw.iter_mut().zip(key.as_chunks().0) {
        *word = u32::from_le_bytes(*bytes);
    }
    for (word, bytes) in ivw.iter_mut().zip(iv.as_chunks().0) {
        *word = u32::from_le_bytes(*bytes);
    }
    #[cfg(all(
        feature = "unsafe-fast",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    let data = {
        let mut input = [0u32; 16];
        input[..4].copy_from_slice(&CW);
        input[4..12].copy_from_slice(&kw);
        input[13..].copy_from_slice(&ivw);
        let rest = crate::chacha_hw::blocks(&input, &mut cc, data);
        clear(&mut input);
        rest
    };
    cc = one_block_at_a_time(&kw, &ivw, cc, data);
    clear(&mut kw);
    cc
}

/// The blocks of `data` one at a time, starting at block `cc`; the number of the
/// block after the last one.
fn one_block_at_a_time(kw: &[u32; 8], ivw: &[u32; 3], mut cc: u32, data: &mut [u8]) -> u32 {
    for buf in data.chunks_mut(64) {
        let mut state = [0u32; 16];
        state[..4].copy_from_slice(&CW);
        state[4..12].copy_from_slice(kw);
        state[12] = cc;
        state[13..].copy_from_slice(ivw);

        macro_rules! qround {
            ($a:expr, $b:expr, $c:expr, $d:expr) => {
                state[$a] = state[$a].wrapping_add(state[$b]);
                state[$d] ^= state[$a];
                state[$d] = state[$d].rotate_left(16);
                state[$c] = state[$c].wrapping_add(state[$d]);
                state[$b] ^= state[$c];
                state[$b] = state[$b].rotate_left(12);
                state[$a] = state[$a].wrapping_add(state[$b]);
                state[$d] ^= state[$a];
                state[$d] = state[$d].rotate_left(8);
                state[$c] = state[$c].wrapping_add(state[$d]);
                state[$b] ^= state[$c];
                state[$b] = state[$b].rotate_left(7);
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

        // The key stream, as words: the state plus the input.
        let mut ks = [0u32; 16];
        for u in 0..4 {
            ks[u] = state[u].wrapping_add(CW[u]);
        }
        for u in 4..12 {
            ks[u] = state[u].wrapping_add(kw[u - 4]);
        }
        ks[12] = state[12].wrapping_add(cc);
        for u in 13..16 {
            ks[u] = state[u].wrapping_add(ivw[u - 13]);
        }

        // Differs from BearSSL: a whole block is XORed a word at a time,
        // which is faster here; the last, partial one a byte at a time.
        if let Ok(block) = <&mut [u8; 64]>::try_from(&mut *buf) {
            for (bytes, k) in block.as_chunks_mut::<4>().0.iter_mut().zip(ks) {
                *bytes = (u32::from_le_bytes(*bytes) ^ k).to_le_bytes();
            }
        } else {
            let tmp = ks.map(u32::to_le_bytes);
            for (byte, k) in buf.iter_mut().zip(tmp.as_flattened()) {
                *byte ^= k;
            }
        }
        cc = cc.wrapping_add(1);
    }
    cc
}

#[cfg(all(
    test,
    feature = "unsafe-fast",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod tests {
    use super::*;

    /// The instructions, where they run, against the code above: on either
    /// side of a group, and with the counter wrapping inside one.
    #[test]
    fn instructions_same_as_code() {
        let mut state = 0x0123_4567_89AB_CDEFu64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for len in (0..1400).step_by(7).chain([256, 512, 768, 1024, 4096]) {
            for cc in [0, 1, u32::MAX - 2, u32::MAX] {
                let mut key = [0u8; 32];
                let mut iv = [0u8; 12];
                key.fill_with(|| next() as u8);
                iv.fill_with(|| next() as u8);
                let mut a = vec![0u8; len];
                a.fill_with(|| next() as u8);
                let mut b = a.clone();
                let got = chacha20(&key, &iv, cc, &mut a);
                let mut kw = [0u32; 8];
                let mut ivw = [0u32; 3];
                for (word, bytes) in kw.iter_mut().zip(key.as_chunks().0) {
                    *word = u32::from_le_bytes(*bytes);
                }
                for (word, bytes) in ivw.iter_mut().zip(iv.as_chunks().0) {
                    *word = u32::from_le_bytes(*bytes);
                }
                assert_eq!(got, one_block_at_a_time(&kw, &ivw, cc, &mut b));
                assert_eq!(a, b, "{len} bytes from block {cc}");
            }
        }
    }
}
