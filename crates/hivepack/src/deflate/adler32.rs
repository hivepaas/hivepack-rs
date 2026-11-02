//! Adler-32: port of `adler32.c`.
//!
//! zlib keeps the sums in `unsigned long`, which is 64 bits on the 64-bit
//! Unix machines it mostly runs on; the port uses `u64` too, so that even a
//! starting value outside the valid range gives what zlib gives there.

/// `BASE`: the largest prime smaller than 65536.
const BASE: u64 = 65521;

/// `NMAX`: the largest n such that 255n(n+1)/2 + (n+1)(BASE-1) <= 2^32-1.
const NMAX: usize = 5552;

/// What `adler32(0, Z_NULL, 0)` returns: the Adler-32 of no bytes, to start
/// from.
pub const ADLER32_INIT: u32 = 1;

/// `DO16`: sixteen sums, unrolled.
#[inline(always)]
fn do16(adler: &mut u64, sum2: &mut u64, buf: &[u8]) {
    for &byte in &buf[..16] {
        *adler += u64::from(byte);
        *sum2 += *adler;
    }
}

/// The Adler-32 of `buf`, continuing from `adler`: start from
/// [`ADLER32_INIT`].
///
/// Port of `adler32_z` (and `adler32`), `adler32.c`.
pub fn adler32(adler: u32, buf: &[u8]) -> u32 {
    let mut len = buf.len();
    let mut pos = 0;

    // split Adler-32 into component sums
    let mut sum2 = u64::from(adler >> 16) & 0xffff;
    let mut adler = u64::from(adler) & 0xffff;

    // in case user likes doing a byte at a time, keep it fast
    if len == 1 {
        adler += u64::from(buf[0]);
        if adler >= BASE {
            adler -= BASE;
        }
        sum2 += adler;
        if sum2 >= BASE {
            sum2 -= BASE;
        }
        return (adler | (sum2 << 16)) as u32;
    }

    // Differs from zlib: there is no null pointer to ask for the initial
    // value; that is ADLER32_INIT.

    // in case short lengths are provided, keep it somewhat fast
    if len < 16 {
        for &byte in buf {
            adler += u64::from(byte);
            sum2 += adler;
        }
        if adler >= BASE {
            adler -= BASE;
        }
        sum2 %= BASE; // only added so many BASE's
        return (adler | (sum2 << 16)) as u32;
    }

    // do length NMAX blocks -- requires just one modulo operation
    while len >= NMAX {
        len -= NMAX;
        // NMAX is divisible by 16
        for _ in 0..NMAX / 16 {
            do16(&mut adler, &mut sum2, &buf[pos..]);
            pos += 16;
        }
        adler %= BASE;
        sum2 %= BASE;
    }

    // do remaining bytes (less than NMAX, still just one modulo)
    if len != 0 {
        // avoid modulos if none remaining
        while len >= 16 {
            len -= 16;
            do16(&mut adler, &mut sum2, &buf[pos..]);
            pos += 16;
        }
        for &byte in &buf[pos..] {
            adler += u64::from(byte);
            sum2 += adler;
        }
        adler %= BASE;
        sum2 %= BASE;
    }

    // return recombined sums
    (adler | (sum2 << 16)) as u32
}

/// The Adler-32 of two pieces one after the other, from the Adler-32 of
/// each and the length of the second. A negative length gives 0xffffffff.
///
/// Port of `adler32_combine_` (and `adler32_combine`, `adler32_combine64`),
/// `adler32.c`.
pub fn adler32_combine(adler1: u32, adler2: u32, len2: i64) -> u32 {
    // for negative len, return invalid adler32 as a clue for debugging
    if len2 < 0 {
        return 0xffff_ffff;
    }

    // the derivation of this formula is left as an exercise for the reader
    let rem = (len2 as u64 % BASE) as u32; // MOD63, assumes len2 >= 0
    let mut sum1 = u64::from(adler1) & 0xffff;
    let mut sum2 = u64::from(rem) * sum1;
    sum2 %= BASE;
    sum1 += (u64::from(adler2) & 0xffff) + BASE - 1;
    sum2 += ((u64::from(adler1) >> 16) & 0xffff) + ((u64::from(adler2) >> 16) & 0xffff) + BASE
        - u64::from(rem);
    if sum1 >= BASE {
        sum1 -= BASE;
    }
    if sum1 >= BASE {
        sum1 -= BASE;
    }
    if sum2 >= BASE << 1 {
        sum2 -= BASE << 1;
    }
    if sum2 >= BASE {
        sum2 -= BASE;
    }
    (sum1 | (sum2 << 16)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The definition, one byte at a time.
    fn reference(adler: u32, buf: &[u8]) -> u32 {
        let mut a = u64::from(adler & 0xffff);
        let mut b = u64::from(adler >> 16);
        for &byte in buf {
            a = (a + u64::from(byte)) % BASE;
            b = (b + a) % BASE;
        }
        (a | (b << 16)) as u32
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
    fn known_values() {
        assert_eq!(adler32(ADLER32_INIT, b""), 1);
        assert_eq!(adler32(ADLER32_INIT, b"a"), 0x0062_0062);
        assert_eq!(adler32(ADLER32_INIT, b"Wikipedia"), 0x11e6_0398);
    }

    #[test]
    fn matches_the_definition() {
        // Lengths around 16 and NMAX, all-0xff bytes (the largest sums), and
        // starting values other than 1.
        for len in [
            0, 1, 2, 15, 16, 17, 31, 5551, 5552, 5553, 11104, 11105, 20000,
        ] {
            for (seed, start) in [(1, ADLER32_INIT), (2, 0x1234_5678), (3, 0xfff0_fff0)] {
                let buf = bytes(len, seed);
                assert_eq!(adler32(start, &buf), reference(start, &buf), "len {len}");
            }
            let ones = vec![0xff; len];
            assert_eq!(adler32(ADLER32_INIT, &ones), reference(ADLER32_INIT, &ones));
        }
    }

    #[test]
    fn combine() {
        let buf = bytes(30000, 7);
        for split in [0, 1, 100, 5552, 29999, 30000] {
            let (a, b) = buf.split_at(split);
            let whole = adler32(ADLER32_INIT, &buf);
            let combined = adler32_combine(
                adler32(ADLER32_INIT, a),
                adler32(ADLER32_INIT, b),
                b.len() as i64,
            );
            assert_eq!(combined, whole, "split at {split}");
        }
        assert_eq!(adler32_combine(1, 1, -1), 0xffff_ffff);
    }
}
