//! X25519 (RFC 7748): port of `ec_c25519_m31.c`, BearSSL's Curve25519
//! with 30-bit words and 64-bit products. The Montgomery ladder runs in
//! constant time.
//!
//! Differs from BearSSL: only `mul` and `mulgen`, as [`x25519`] and
//! [`x25519_base`], on 32-byte arrays; BearSSL's `br_ec_impl` also has the
//! curve's order, and `muladd`, which Curve25519 does not implement.

use crate::clear::clear;
use crate::ct::ccopy;

/// The length of an X25519 scalar and of a point's u-coordinate, in bytes.
pub const X25519_LENGTH: usize = 32;

/// `MUL31`.
fn mul31(x: u32, y: u32) -> u64 {
    u64::from(x) * u64::from(y)
}

/// `ARSH`: the arithmetic right shift.
fn arsh(x: u32, n: u32) -> u32 {
    ((x as i32) >> n) as u32
}

/// `le8_to_le30`: little-endian bytes into 30-bit words, little-endian.
/// The last, partial word is returned.
fn le8_to_le30(dst: &mut [u32], src: &[u8]) -> u32 {
    let mut acc = 0u32;
    let mut acc_len = 0;
    let mut d = 0;
    for &b in src {
        let b = u32::from(b);
        if acc_len < 22 {
            acc |= b << acc_len;
            acc_len += 8;
        } else {
            dst[d] = (acc | (b << acc_len)) & 0x3FFF_FFFF;
            d += 1;
            acc = b >> (30 - acc_len);
            acc_len -= 22;
        }
    }
    acc
}

/// `le30_to_le8`: 30-bit words, little-endian, into little-endian bytes,
/// filling all of `dst`.
fn le30_to_le8(dst: &mut [u8], src: &[u32]) {
    let mut acc = 0u32;
    let mut acc_len = 0;
    let mut s = 0;
    for byte in dst {
        if acc_len < 8 {
            let w = src[s];
            s += 1;
            *byte = (acc | (w << acc_len)) as u8;
            acc = w >> (8 - acc_len);
            acc_len += 22;
        } else {
            *byte = acc as u8;
            acc >>= 8;
            acc_len -= 8;
        }
    }
}

/// `mul9`: the product of two integers of nine 30-bit words, in 18 words.
fn mul9(d: &mut [u32; 18], a: &[u32; 9], b: &[u32; 9]) {
    // Each column is at most 9 products of 30-bit words, plus a carry
    // below 9663676407: it fits in 64 bits, as BearSSL shows.
    let mut t = [0u64; 17];
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() {
            t[i + j] += mul31(x, y);
        }
    }
    let mut cc = 0u64;
    for (word, &column) in d.iter_mut().zip(&t) {
        let w = column + cc;
        *word = w as u32 & 0x3FFF_FFFF;
        cc = w >> 30;
    }
    d[17] = cc as u32;
}

/// `square9`: the square of an integer of nine 30-bit words, in 18 words.
fn square9(d: &mut [u32; 18], a: &[u32; 9]) {
    let mut t = [0u64; 17];
    for i in 0..9 {
        t[2 * i] += mul31(a[i], a[i]);
        for j in i + 1..9 {
            t[i + j] += mul31(a[i], a[j]) << 1;
        }
    }
    let mut cc = 0u64;
    for (word, &column) in d.iter_mut().zip(&t) {
        let w = column + cc;
        *word = w as u32 & 0x3FFF_FFFF;
        cc = w >> 30;
    }
    d[17] = cc as u32;
}

/// `reduce_final_f255`: a value below twice the modulus reduced below it.
/// Returns 1 if the modulus was subtracted, 0 if not.
fn reduce_final_f255(d: &mut [u32; 9]) -> u32 {
    let mut t = *d;
    let mut cc = 19;
    for word in &mut t {
        let w = *word + cc;
        cc = w >> 30;
        *word = w & 0x3FFF_FFFF;
    }
    cc = t[8] >> 15;
    t[8] &= 0x7FFF;
    ccopy(cc, d, &t);
    cc
}

/// The reduction that ends `f255_mul` and `f255_square`: an 18-word
/// product modulo 2^255 - 19, below twice the modulus. Word 9 + k is
/// at 270 + 30k bits, so it is added to word k times 19 × 2^15 = 622592.
fn reduce_f255(d: &mut [u32; 9], t: &mut [u32; 18]) {
    let mut cc = mul31(t[8] >> 15, 19);
    t[8] &= 0x7FFF;
    let mut w = 0u64;
    for i in 0..9 {
        w = u64::from(t[i]) + cc + mul31(t[i + 9], 622_592);
        t[i] = w as u32 & 0x3FFF_FFFF;
        cc = w >> 30;
    }
    cc = (w >> 15) * 19;
    t[8] &= 0x7FFF;
    for (word, &x) in d.iter_mut().zip(&t[..9]) {
        let w = u64::from(x) + cc;
        *word = w as u32 & 0x3FFF_FFFF;
        cc = w >> 30;
    }
}

/// `f255_mul`: `a` × `b` modulo 2^255 - 19. The operands may be up to
/// 2^256 - 1; the result is below twice the modulus.
fn f255_mul(d: &mut [u32; 9], a: &[u32; 9], b: &[u32; 9]) {
    let mut t = [0u32; 18];
    mul9(&mut t, a, b);
    reduce_f255(d, &mut t);
}

/// `f255_square`: `a`² modulo 2^255 - 19.
fn f255_square(d: &mut [u32; 9], a: &[u32; 9]) {
    let mut t = [0u32; 18];
    square9(&mut t, a);
    reduce_f255(d, &mut t);
}

/// `f255_add`: `a` + `b`, below twice the modulus.
fn f255_add(d: &mut [u32; 9], a: &[u32; 9], b: &[u32; 9]) {
    let mut cc = 0;
    let mut w = 0;
    for i in 0..9 {
        w = a[i] + b[i] + cc;
        d[i] = w & 0x3FFF_FFFF;
        cc = w >> 30;
    }
    cc = (w >> 15) * 19;
    d[8] &= 0x7FFF;
    for word in d.iter_mut() {
        w = *word + cc;
        *word = w & 0x3FFF_FFFF;
        cc = w >> 30;
    }
}

/// `f255_sub`: `a` - `b`, below twice the modulus. It computes
/// `a` - `b` + 2p, so that the value stays positive.
fn f255_sub(d: &mut [u32; 9], a: &[u32; 9], b: &[u32; 9]) {
    let mut cc = 38u32.wrapping_neg();
    let mut w = 0u32;
    for i in 0..9 {
        w = a[i].wrapping_sub(b[i]).wrapping_add(cc);
        d[i] = w & 0x3FFF_FFFF;
        cc = arsh(w, 30);
    }
    cc = (w.wrapping_add(0x10000) >> 15) * 19;
    d[8] &= 0x7FFF;
    for word in d.iter_mut() {
        w = *word + cc;
        *word = w & 0x3FFF_FFFF;
        cc = w >> 30;
    }
}

/// `f255_mul_a24`: `a` × 121665 (the curve's `A24`), below twice the
/// modulus.
fn f255_mul_a24(d: &mut [u32; 9], a: &[u32; 9]) {
    let mut cc = 0u64;
    let mut w = 0u64;
    for i in 0..9 {
        w = mul31(a[i], 121_665) + cc;
        d[i] = w as u32 & 0x3FFF_FFFF;
        cc = w >> 30;
    }
    cc = mul31((w >> 15) as u32, 19);
    d[8] &= 0x7FFF;
    for word in d.iter_mut() {
        w = u64::from(*word) + cc;
        *word = w as u32 & 0x3FFF_FFFF;
        cc = w >> 30;
    }
}

/// `GEN`: the base point, u = 9.
const GEN: [u8; X25519_LENGTH] = {
    let mut g = [0; X25519_LENGTH];
    g[0] = 9;
    g
};

/// `cswap`: swaps `a` and `b` if `ctl` is 1, in the same time either way.
fn cswap(a: &mut [u32; 9], b: &mut [u32; 9], ctl: u32) {
    let ctl = ctl.wrapping_neg();
    for (aw, bw) in a.iter_mut().zip(b.iter_mut()) {
        let tw = ctl & (*aw ^ *bw);
        *aw ^= tw;
        *bw ^= tw;
    }
}

/// `api_mul`: X25519 of the scalar `kb` and the u-coordinate `g`, as
/// RFC 7748 defines it: the scalar is clamped, and the top bit of the
/// coordinate ignored.
///
/// Like BearSSL, it does not look at the result: a point of small order
/// gives all zeros, which callers that need a shared secret refuse (RFC
/// 7748, section 6.1).
pub fn x25519(kb: &[u8; X25519_LENGTH], g: &[u8; X25519_LENGTH]) -> [u8; X25519_LENGTH] {
    let mut g = *g;
    g[31] &= 0x7F;

    let mut x1 = [0u32; 9];
    x1[8] = le8_to_le30(&mut x1, &g);
    let mut x2 = [0u32; 9];
    x2[0] = 1;
    let mut z2 = [0u32; 9];
    let mut x3 = x1;
    let mut z3 = [0u32; 9];
    z3[0] = 1;

    let mut k = *kb;
    k[0] &= 0xF8;
    k[31] &= 0x7F;
    k[31] |= 0x40;

    let mut a = [0u32; 9];
    let mut aa = [0u32; 9];
    let mut b = [0u32; 9];
    let mut bb = [0u32; 9];
    let mut c = [0u32; 9];
    let mut d = [0u32; 9];
    let mut e = [0u32; 9];
    let mut da = [0u32; 9];
    let mut cb = [0u32; 9];
    let mut t = [0u32; 9];

    let mut swap = 0;
    for i in (0..=254).rev() {
        let kt = u32::from(k[i >> 3] >> (i & 7)) & 1;
        swap ^= kt;
        cswap(&mut x2, &mut x3, swap);
        cswap(&mut z2, &mut z3, swap);
        swap = kt;

        f255_add(&mut a, &x2, &z2);
        f255_square(&mut aa, &a);
        f255_sub(&mut b, &x2, &z2);
        f255_square(&mut bb, &b);
        f255_sub(&mut e, &aa, &bb);
        f255_add(&mut c, &x3, &z3);
        f255_sub(&mut d, &x3, &z3);
        f255_mul(&mut da, &d, &a);
        f255_mul(&mut cb, &c, &b);

        f255_add(&mut t, &da, &cb);
        f255_square(&mut x3, &t);
        f255_sub(&mut t, &da, &cb);
        f255_square(&mut z3, &t);
        t = z3;
        f255_mul(&mut z3, &t, &x1);
        f255_mul(&mut x2, &aa, &bb);
        f255_mul_a24(&mut z2, &e);
        t = z2;
        f255_add(&mut z2, &t, &aa);
        t = z2;
        f255_mul(&mut z2, &e, &t);
    }
    cswap(&mut x2, &mut x3, swap);
    cswap(&mut z2, &mut z3, swap);

    // z2 inverted by raising it to p - 2 = 2^255 - 21, mostly ones, so
    // most multiplications are shared.
    a = z2;
    for _ in 0..15 {
        t = a;
        f255_square(&mut a, &t);
        t = a;
        f255_mul(&mut a, &t, &z2);
    }
    b = a;
    for _ in 0..14 {
        for _ in 0..16 {
            t = b;
            f255_square(&mut b, &t);
        }
        t = b;
        f255_mul(&mut b, &t, &a);
    }
    for i in (0..=14).rev() {
        t = b;
        f255_square(&mut b, &t);
        if (0xFFEB >> i) & 1 != 0 {
            t = b;
            f255_mul(&mut b, &z2, &t);
        }
    }
    t = x2;
    f255_mul(&mut x2, &t, &b);
    reduce_final_f255(&mut x2);
    le30_to_le8(&mut g, &x2);
    clear(&mut k);
    g
}

/// `a` to the power 2^`bits` - 1 less the bits at `holes`, from the top bit down:
/// the exponents below, which are almost all ones.
fn f255_pow(a: &[u32; 9], bits: u32, holes: &[u32]) -> [u32; 9] {
    let mut r = *a;
    let mut t = [0u32; 9];
    for bit in (0..bits - 1).rev() {
        f255_square(&mut t, &r);
        r = t;
        if !holes.contains(&bit) {
            f255_mul(&mut t, &r, a);
            r = t;
        }
    }
    r
}

/// A value as its 32 bytes, fully reduced.
fn f255_bytes(a: &[u32; 9]) -> [u8; X25519_LENGTH] {
    let mut d = *a;
    reduce_final_f255(&mut d);
    let mut out = [0; X25519_LENGTH];
    le30_to_le8(&mut out, &d);
    out
}

/// The curve's constant `d`, -121665/121666, little-endian.
const EDWARDS_D: [u8; X25519_LENGTH] = [
    0xA3, 0x78, 0x59, 0x13, 0xCA, 0x4D, 0xEB, 0x75, 0xAB, 0xD8, 0x41, 0x41, 0x4D, 0x0A, 0x70, 0x00,
    0x98, 0xE8, 0x79, 0x77, 0x79, 0x40, 0xC7, 0x8C, 0x73, 0xFE, 0x6F, 0x2B, 0xEE, 0x6C, 0x03, 0x52,
];

/// An Ed25519 public key as the X25519 point it is on the birational map, as
/// SSH keys are used to encrypt to: `None` if it is no point of the curve.
///
/// Not in BearSSL. Written from RFC 8032, section 5.1.3, whose square root tells
/// whether `x` exists, and RFC 7748, section 4.1, u = (1 + y) / (1 - y). It runs
/// on a public key, and its time depends on the key.
///
/// Differs from RFC 8032 as `filippo.io/edwards25519` does, which age uses: a `y`
/// of the modulus or more is reduced, and the sign of an `x` of zero is not
/// looked at. `y` = 1 has no u; it gives 0, as inverting zero does there.
pub fn ed25519_public_to_x25519(public: &[u8; X25519_LENGTH]) -> Option<[u8; X25519_LENGTH]> {
    let load = |bytes: &[u8; X25519_LENGTH]| {
        let mut masked = *bytes;
        masked[31] &= 0x7F;
        let mut d = [0u32; 9];
        d[8] = le8_to_le30(&mut d, &masked);
        d
    };
    let y = load(public);
    let d = load(&EDWARDS_D);
    let mut one = [0u32; 9];
    one[0] = 1;
    let zero = [0u32; 9];

    // x² = u / v, with u = y² - 1 and v = d y² + 1.
    let (mut y2, mut u, mut v, mut t) = ([0u32; 9], [0u32; 9], [0u32; 9], [0u32; 9]);
    f255_square(&mut y2, &y);
    f255_sub(&mut u, &y2, &one);
    f255_mul(&mut t, &d, &y2);
    f255_add(&mut v, &t, &one);

    // A root candidate: u v³ (u v⁷)^((p - 5) / 8), where (p - 5) / 8 = 2^252 - 3.
    let (mut v3, mut v7, mut uv3, mut uv7) = ([0u32; 9], [0u32; 9], [0u32; 9], [0u32; 9]);
    f255_square(&mut t, &v);
    f255_mul(&mut v3, &t, &v);
    f255_square(&mut t, &v3);
    f255_mul(&mut v7, &t, &v);
    f255_mul(&mut uv3, &u, &v3);
    f255_mul(&mut uv7, &u, &v7);
    let power = f255_pow(&uv7, 252, &[1]);
    let mut x = [0u32; 9];
    f255_mul(&mut x, &uv3, &power);

    // It is a root of u / v or of -u / v; with neither, there is no point.
    let mut check = [0u32; 9];
    f255_square(&mut t, &x);
    f255_mul(&mut check, &t, &v);
    let mut minus_u = [0u32; 9];
    f255_sub(&mut minus_u, &zero, &u);
    let check = f255_bytes(&check);
    if check != f255_bytes(&u) && check != f255_bytes(&minus_u) {
        return None;
    }

    // u = (1 + y) / (1 - y), inverting by p - 2 = 2^255 - 21.
    let (mut top, mut bottom, mut out) = ([0u32; 9], [0u32; 9], [0u32; 9]);
    f255_add(&mut top, &one, &y);
    f255_sub(&mut bottom, &one, &y);
    let inverse = f255_pow(&bottom, 255, &[2, 4]);
    f255_mul(&mut out, &top, &inverse);
    Some(f255_bytes(&out))
}

/// `api_mulgen`: X25519 of the scalar `x` and the base point: the public
/// key of the private key `x`.
pub fn x25519_base(x: &[u8; X25519_LENGTH]) -> [u8; X25519_LENGTH] {
    crate::x25519(x, &GEN)
}
