//! XXH32, the checksum of the LZ4 frame format: the 32-bit half of the
//! xxhash.c (xxHash 0.6.5) that liblz4 ships, in one call ([`xxh32`]) or
//! streaming ([`Xxh32`]).

const PRIME32_1: u32 = 2_654_435_761;
const PRIME32_2: u32 = 2_246_822_519;
const PRIME32_3: u32 = 3_266_489_917;
const PRIME32_4: u32 = 668_265_263;
const PRIME32_5: u32 = 374_761_393;

fn read_le32(bytes: &[u8], at: usize) -> u32 {
    let mut word = [0; 4];
    word.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(word)
}

fn round(seed: u32, input: u32) -> u32 {
    seed.wrapping_add(input.wrapping_mul(PRIME32_2))
        .rotate_left(13)
        .wrapping_mul(PRIME32_1)
}

/// `XXH32_avalanche`: mixes all bits.
fn avalanche(mut h32: u32) -> u32 {
    h32 ^= h32 >> 15;
    h32 = h32.wrapping_mul(PRIME32_2);
    h32 ^= h32 >> 13;
    h32 = h32.wrapping_mul(PRIME32_3);
    h32 ^= h32 >> 16;
    h32
}

/// `XXH32_finalize`: the last `len & 15` bytes of `p`, four at a time and
/// then one at a time.
fn finalize(mut h32: u32, p: &[u8]) -> u32 {
    let mut at = 0;
    while p.len() - at >= 4 {
        h32 = h32.wrapping_add(read_le32(p, at).wrapping_mul(PRIME32_3));
        h32 = h32.rotate_left(17).wrapping_mul(PRIME32_4);
        at += 4;
    }
    for &byte in &p[at..] {
        h32 = h32.wrapping_add(u32::from(byte).wrapping_mul(PRIME32_5));
        h32 = h32.rotate_left(11).wrapping_mul(PRIME32_1);
    }
    avalanche(h32)
}

/// `XXH32`: the hash of `input` with `seed`, in one call.
pub fn xxh32(input: &[u8], seed: u32) -> u32 {
    let len = input.len();
    let mut p = 0;
    let mut h32;
    if len >= 16 {
        let limit = len - 15;
        let mut v1 = seed.wrapping_add(PRIME32_1).wrapping_add(PRIME32_2);
        let mut v2 = seed.wrapping_add(PRIME32_2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME32_1);
        loop {
            v1 = round(v1, read_le32(input, p));
            v2 = round(v2, read_le32(input, p + 4));
            v3 = round(v3, read_le32(input, p + 8));
            v4 = round(v4, read_le32(input, p + 12));
            p += 16;
            if p >= limit {
                break;
            }
        }
        h32 = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
    } else {
        h32 = seed.wrapping_add(PRIME32_5);
    }
    // The length modulo 2^32, as `(U32)len`.
    h32 = h32.wrapping_add(len as u32);
    finalize(h32, &input[p..])
}

/// `XXH32_state_t`: XXH32 over input given in pieces.
#[derive(Clone, Debug)]
pub struct Xxh32 {
    total_len_32: u32,
    large_len: bool,
    v1: u32,
    v2: u32,
    v3: u32,
    v4: u32,
    mem32: [u8; 16],
    memsize: usize,
}

impl Xxh32 {
    /// `XXH32_reset`.
    pub fn new(seed: u32) -> Self {
        Xxh32 {
            total_len_32: 0,
            large_len: false,
            v1: seed.wrapping_add(PRIME32_1).wrapping_add(PRIME32_2),
            v2: seed.wrapping_add(PRIME32_2),
            v3: seed,
            v4: seed.wrapping_sub(PRIME32_1),
            mem32: [0; 16],
            memsize: 0,
        }
    }

    /// `XXH32_reset`, on this state.
    pub fn reset(&mut self, seed: u32) {
        *self = Xxh32::new(seed);
    }

    /// `XXH32_update`.
    pub fn update(&mut self, input: &[u8]) {
        let len = input.len();
        self.total_len_32 = self.total_len_32.wrapping_add(len as u32);
        self.large_len |= len >= 16 || self.total_len_32 >= 16;

        if self.memsize + len < 16 {
            // Not a whole stripe yet: kept for later.
            self.mem32[self.memsize..self.memsize + len].copy_from_slice(input);
            self.memsize += len;
            return;
        }

        let mut p = 0;
        if self.memsize > 0 {
            // Some data was left by the last update: one stripe with it.
            let fill = 16 - self.memsize;
            self.mem32[self.memsize..].copy_from_slice(&input[..fill]);
            self.v1 = round(self.v1, read_le32(&self.mem32, 0));
            self.v2 = round(self.v2, read_le32(&self.mem32, 4));
            self.v3 = round(self.v3, read_le32(&self.mem32, 8));
            self.v4 = round(self.v4, read_le32(&self.mem32, 12));
            p = fill;
            self.memsize = 0;
        }

        if p + 16 <= len {
            let limit = len - 16;
            let (mut v1, mut v2, mut v3, mut v4) = (self.v1, self.v2, self.v3, self.v4);
            loop {
                v1 = round(v1, read_le32(input, p));
                v2 = round(v2, read_le32(input, p + 4));
                v3 = round(v3, read_le32(input, p + 8));
                v4 = round(v4, read_le32(input, p + 12));
                p += 16;
                if p > limit {
                    break;
                }
            }
            (self.v1, self.v2, self.v3, self.v4) = (v1, v2, v3, v4);
        }

        if p < len {
            self.mem32[..len - p].copy_from_slice(&input[p..]);
            self.memsize = len - p;
        }
    }

    /// `XXH32_digest`: the hash of all the input so far. The state is not
    /// changed, and more input can follow.
    pub fn digest(&self) -> u32 {
        let mut h32 = if self.large_len {
            self.v1
                .rotate_left(1)
                .wrapping_add(self.v2.rotate_left(7))
                .wrapping_add(self.v3.rotate_left(12))
                .wrapping_add(self.v4.rotate_left(18))
        } else {
            // v3 is the seed.
            self.v3.wrapping_add(PRIME32_5)
        };
        h32 = h32.wrapping_add(self.total_len_32);
        finalize(h32, &self.mem32[..self.memsize])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_values() {
        // From xxHash's own sanity checks (xxhsum.c, 0.6.5): the first
        // bytes of its generated buffer, with seeds 0 and PRIME32.
        let mut buffer = [0u8; 101];
        let mut byte_gen: u32 = PRIME32_1;
        for byte in buffer.iter_mut() {
            *byte = (byte_gen >> 24) as u8;
            byte_gen = byte_gen.wrapping_mul(byte_gen);
        }
        let cases: [(usize, u32, u32); 6] = [
            (0, 0, 0x02CC_5D05),
            (0, PRIME32_1, 0x36B7_8AE7),
            (1, 0, 0xB85C_BEE5),
            (1, PRIME32_1, 0xD584_5D64),
            (14, 0, 0xE5AA_0AB4),
            (101, 0, 0x1F1A_A412),
        ];
        for (len, seed, hash) in cases {
            assert_eq!(xxh32(&buffer[..len], seed), hash, "len {len} seed {seed:x}");
            let mut state = Xxh32::new(seed);
            for piece in buffer[..len].chunks(3) {
                state.update(piece);
            }
            assert_eq!(state.digest(), hash, "streamed, len {len} seed {seed:x}");
        }
    }
}
