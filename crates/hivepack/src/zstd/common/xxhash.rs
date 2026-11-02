//! XXH64, the checksum of zstd frames: port of the 64-bit part of
//! `common/xxhash.h` (xxHash 0.8, by Yann Collet).
//!
//! zstd only uses XXH64: in one call, and streamed, to check frame content.

use super::mem::{read_le32, read_le64};

const XXH_PRIME64_1: u64 = 0x9E37_79B1_85EB_CA87;
const XXH_PRIME64_2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const XXH_PRIME64_3: u64 = 0x1656_67B1_9E37_79F9;
const XXH_PRIME64_4: u64 = 0x85EB_CA77_C2B2_AE63;
const XXH_PRIME64_5: u64 = 0x27D4_EB2F_1656_67C5;

/// `XXH64_round`
#[inline(always)]
fn xxh64_round(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(XXH_PRIME64_2))
        .rotate_left(31)
        .wrapping_mul(XXH_PRIME64_1)
}

/// `XXH64_mergeRound`
#[inline(always)]
fn xxh64_merge_round(acc: u64, val: u64) -> u64 {
    let val = xxh64_round(0, val);
    (acc ^ val)
        .wrapping_mul(XXH_PRIME64_1)
        .wrapping_add(XXH_PRIME64_4)
}

/// `XXH64_avalanche`
#[inline(always)]
fn xxh64_avalanche(mut hash: u64) -> u64 {
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(XXH_PRIME64_2);
    hash ^= hash >> 29;
    hash = hash.wrapping_mul(XXH_PRIME64_3);
    hash ^= hash >> 32;
    hash
}

/// `XXH64_finalize`: mixes in the last `len & 31` bytes of `input`.
fn xxh64_finalize(mut hash: u64, input: &[u8]) -> u64 {
    let mut p = 0;
    let mut len = input.len() & 31;
    while len >= 8 {
        let k1 = xxh64_round(0, read_le64(input, p));
        p += 8;
        hash ^= k1;
        hash = hash
            .rotate_left(27)
            .wrapping_mul(XXH_PRIME64_1)
            .wrapping_add(XXH_PRIME64_4);
        len -= 8;
    }
    if len >= 4 {
        hash ^= u64::from(read_le32(input, p)).wrapping_mul(XXH_PRIME64_1);
        p += 4;
        hash = hash
            .rotate_left(23)
            .wrapping_mul(XXH_PRIME64_2)
            .wrapping_add(XXH_PRIME64_3);
        len -= 4;
    }
    while len > 0 {
        hash ^= u64::from(input[p]).wrapping_mul(XXH_PRIME64_5);
        p += 1;
        hash = hash.rotate_left(11).wrapping_mul(XXH_PRIME64_1);
        len -= 1;
    }
    xxh64_avalanche(hash)
}

/// The four accumulators of XXH64, seeded.
fn xxh64_init_accs(seed: u64) -> [u64; 4] {
    [
        seed.wrapping_add(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_2),
        seed.wrapping_add(XXH_PRIME64_2),
        seed,
        seed.wrapping_sub(XXH_PRIME64_1),
    ]
}

/// Feeds one 32-byte stripe to the accumulators.
#[inline(always)]
fn xxh64_consume_stripe(acc: &mut [u64; 4], stripe: &[u8; 32]) {
    for (i, lane) in acc.iter_mut().enumerate() {
        *lane = xxh64_round(*lane, read_le64(stripe, 8 * i));
    }
}

/// Merges the accumulators into one hash, for inputs of 32 bytes or more.
fn xxh64_merge_accs(acc: &[u64; 4]) -> u64 {
    let mut hash = acc[0]
        .rotate_left(1)
        .wrapping_add(acc[1].rotate_left(7))
        .wrapping_add(acc[2].rotate_left(12))
        .wrapping_add(acc[3].rotate_left(18));
    for &lane in acc {
        hash = xxh64_merge_round(hash, lane);
    }
    hash
}

/// `XXH64`: the hash of `input` with `seed`, in one call.
pub(crate) fn xxh64(input: &[u8], seed: u64) -> u64 {
    let len = input.len();
    let mut hash;
    let mut tail = input;
    if len >= 32 {
        let mut acc = xxh64_init_accs(seed);
        let (stripes, rest) = input.as_chunks::<32>();
        for stripe in stripes {
            xxh64_consume_stripe(&mut acc, stripe);
        }
        tail = rest;
        hash = xxh64_merge_accs(&acc);
    } else {
        hash = seed.wrapping_add(XXH_PRIME64_5);
    }
    hash = hash.wrapping_add(len as u64);
    xxh64_finalize(hash, tail)
}

/// `XXH64_state_t`: XXH64 over input given in pieces.
#[derive(Clone)]
pub(crate) struct Xxh64State {
    total_len: u64,
    acc: [u64; 4],
    mem64: [u8; 32],
    memsize: usize,
}

impl Xxh64State {
    /// `XXH64_reset`
    pub(crate) fn new(seed: u64) -> Self {
        Xxh64State {
            total_len: 0,
            acc: xxh64_init_accs(seed),
            mem64: [0; 32],
            memsize: 0,
        }
    }

    /// `XXH64_update`
    pub(crate) fn update(&mut self, mut input: &[u8]) {
        self.total_len = self.total_len.wrapping_add(input.len() as u64);

        if self.memsize + input.len() < 32 {
            // Not enough for a stripe yet.
            self.mem64[self.memsize..self.memsize + input.len()].copy_from_slice(input);
            self.memsize += input.len();
            return;
        }

        if self.memsize > 0 {
            // Complete the stripe kept from before.
            let fill = 32 - self.memsize;
            self.mem64[self.memsize..].copy_from_slice(&input[..fill]);
            let stripe = self.mem64;
            xxh64_consume_stripe(&mut self.acc, &stripe);
            input = &input[fill..];
            self.memsize = 0;
        }

        let (stripes, rest) = input.as_chunks::<32>();
        for stripe in stripes {
            xxh64_consume_stripe(&mut self.acc, stripe);
        }
        self.mem64[..rest.len()].copy_from_slice(rest);
        self.memsize = rest.len();
    }

    /// `XXH64_digest`
    pub(crate) fn digest(&self) -> u64 {
        let mut hash = if self.total_len >= 32 {
            xxh64_merge_accs(&self.acc)
        } else {
            // acc[2] is the seed.
            self.acc[2].wrapping_add(XXH_PRIME64_5)
        };
        hash = hash.wrapping_add(self.total_len);
        xxh64_finalize(hash, &self.mem64[..self.memsize])
    }
}
