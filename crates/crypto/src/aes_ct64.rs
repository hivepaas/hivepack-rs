//! AES, bitsliced on 64-bit words: port of `aes_ct64.c`, the S-box, the
//! changes of representation and the key schedule.
//!
//! Four blocks are encrypted at once, their 512 bits spread over eight
//! words, so that the S-box is a circuit of logical operations: no table
//! is indexed with secret data, and the time taken depends neither on the
//! key nor on the data.

use crate::clear::clear;

/// `br_aes_ct64_bitslice_Sbox`: the S-box on the eight words.
///
/// A straightforward translation of the circuit described by Boyar and
/// Peralta in "A new combinational logic minimization technique with
/// applications to cryptology" (<https://eprint.iacr.org/2009/191.pdf>).
/// The inputs `x*` and outputs `s*` are numbered in "reverse" order: `x0`
/// is the high bit, `x7` the low bit.
pub(crate) fn bitslice_sbox(q: &mut [u64; 8]) {
    let x0 = q[7];
    let x1 = q[6];
    let x2 = q[5];
    let x3 = q[4];
    let x4 = q[3];
    let x5 = q[2];
    let x6 = q[1];
    let x7 = q[0];

    // Top linear transformation.
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;

    // Non-linear section.
    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;

    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;

    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;

    // Bottom linear transformation.
    let t46 = z15 ^ z16;
    let t47 = z10 ^ z11;
    let t48 = z5 ^ z13;
    let t49 = z9 ^ z10;
    let t50 = z2 ^ z12;
    let t51 = z2 ^ z5;
    let t52 = z7 ^ z8;
    let t53 = z0 ^ z3;
    let t54 = z6 ^ z7;
    let t55 = z16 ^ z17;
    let t56 = z12 ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z4 ^ t46;
    let t59 = z3 ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z14 ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z4 ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z1 ^ t63;
    let s0 = t59 ^ t63;
    let s6 = t56 ^ !t62;
    let s7 = t48 ^ !t60;
    let t67 = t64 ^ t65;
    let s3 = t53 ^ t66;
    let s4 = t51 ^ t66;
    let s5 = t47 ^ t65;
    let s1 = t64 ^ !s3;
    let s2 = t55 ^ !t67;

    q[7] = s0;
    q[6] = s1;
    q[5] = s2;
    q[4] = s3;
    q[3] = s4;
    q[2] = s5;
    q[1] = s6;
    q[0] = s7;
}

/// `SWAPN`: exchanges the bits of `q[x]` that `ch` selects with those of
/// `q[y]` that `cl` selects, `s` places apart.
fn swapn(q: &mut [u64; 8], cl: u64, ch: u64, s: u32, x: usize, y: usize) {
    let a = q[x];
    let b = q[y];
    q[x] = (a & cl) | ((b & cl) << s);
    q[y] = ((a & ch) >> s) | (b & ch);
}

fn swap2(q: &mut [u64; 8], x: usize, y: usize) {
    swapn(q, 0x5555_5555_5555_5555, 0xAAAA_AAAA_AAAA_AAAA, 1, x, y);
}

fn swap4(q: &mut [u64; 8], x: usize, y: usize) {
    swapn(q, 0x3333_3333_3333_3333, 0xCCCC_CCCC_CCCC_CCCC, 2, x, y);
}

fn swap8(q: &mut [u64; 8], x: usize, y: usize) {
    swapn(q, 0x0F0F_0F0F_0F0F_0F0F, 0xF0F0_F0F0_F0F0_F0F0, 4, x, y);
}

/// `br_aes_ct64_ortho`: to the bitsliced representation and back, as it is
/// its own inverse.
pub(crate) fn ortho(q: &mut [u64; 8]) {
    swap2(q, 0, 1);
    swap2(q, 2, 3);
    swap2(q, 4, 5);
    swap2(q, 6, 7);

    swap4(q, 0, 2);
    swap4(q, 1, 3);
    swap4(q, 4, 6);
    swap4(q, 5, 7);

    swap8(q, 0, 4);
    swap8(q, 1, 5);
    swap8(q, 2, 6);
    swap8(q, 3, 7);
}

/// `br_aes_ct64_interleave_in`: a block's four words, spread over two
/// words, ready for [`ortho`].
pub(crate) fn interleave_in(w: &[u32; 4]) -> (u64, u64) {
    let mut x0 = u64::from(w[0]);
    let mut x1 = u64::from(w[1]);
    let mut x2 = u64::from(w[2]);
    let mut x3 = u64::from(w[3]);
    x0 |= x0 << 16;
    x1 |= x1 << 16;
    x2 |= x2 << 16;
    x3 |= x3 << 16;
    x0 &= 0x0000_FFFF_0000_FFFF;
    x1 &= 0x0000_FFFF_0000_FFFF;
    x2 &= 0x0000_FFFF_0000_FFFF;
    x3 &= 0x0000_FFFF_0000_FFFF;
    x0 |= x0 << 8;
    x1 |= x1 << 8;
    x2 |= x2 << 8;
    x3 |= x3 << 8;
    x0 &= 0x00FF_00FF_00FF_00FF;
    x1 &= 0x00FF_00FF_00FF_00FF;
    x2 &= 0x00FF_00FF_00FF_00FF;
    x3 &= 0x00FF_00FF_00FF_00FF;
    (x0 | (x2 << 8), x1 | (x3 << 8))
}

/// `br_aes_ct64_interleave_out`: the inverse of [`interleave_in`].
pub(crate) fn interleave_out(q0: u64, q1: u64) -> [u32; 4] {
    let mut x0 = q0 & 0x00FF_00FF_00FF_00FF;
    let mut x1 = q1 & 0x00FF_00FF_00FF_00FF;
    let mut x2 = (q0 >> 8) & 0x00FF_00FF_00FF_00FF;
    let mut x3 = (q1 >> 8) & 0x00FF_00FF_00FF_00FF;
    x0 |= x0 >> 8;
    x1 |= x1 >> 8;
    x2 |= x2 >> 8;
    x3 |= x3 >> 8;
    x0 &= 0x0000_FFFF_0000_FFFF;
    x1 &= 0x0000_FFFF_0000_FFFF;
    x2 &= 0x0000_FFFF_0000_FFFF;
    x3 &= 0x0000_FFFF_0000_FFFF;
    [
        x0 as u32 | (x0 >> 16) as u32,
        x1 as u32 | (x1 >> 16) as u32,
        x2 as u32 | (x2 >> 16) as u32,
        x3 as u32 | (x3 >> 16) as u32,
    ]
}

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

/// `sub_word`: the S-box on each byte of a word.
fn sub_word(x: u32) -> u32 {
    let mut q = [0u64; 8];
    q[0] = u64::from(x);
    ortho(&mut q);
    bitslice_sbox(&mut q);
    ortho(&mut q);
    q[0] as u32
}

/// The first half of `br_aes_ct64_keysched`: the number of rounds and the
/// words of the round keys, or `None` if the key is not 16, 24 or 32 bytes
/// long.
pub(crate) fn round_words(key: &[u8]) -> Option<(usize, [u32; 60])> {
    let num_rounds = match key.len() {
        16 => 10,
        24 => 12,
        32 => 14,
        _ => return None,
    };
    let nk = key.len() >> 2;
    let nkf = (num_rounds + 1) << 2;
    let mut skey = [0u32; 60];
    for (word, bytes) in skey.iter_mut().zip(key.as_chunks().0) {
        *word = u32::from_le_bytes(*bytes);
    }
    let mut tmp = skey[nk - 1];
    let (mut j, mut k) = (0, 0);
    for i in nk..nkf {
        if j == 0 {
            tmp = tmp.rotate_right(8);
            tmp = sub_word(tmp) ^ u32::from(RCON[k]);
        } else if nk > 6 && j == 4 {
            tmp = sub_word(tmp);
        }
        tmp ^= skey[i - nk];
        skey[i] = tmp;
        j += 1;
        if j == nk {
            j = 0;
            k += 1;
        }
    }
    Some((num_rounds, skey))
}

/// `br_aes_ct64_keysched`: the number of rounds and the compressed
/// subkeys, two words per round key, or `None` if the key is not 16, 24 or
/// 32 bytes long.
///
/// Differs from BearSSL: an unsupported length is `None`, where BearSSL
/// returns 0 rounds.
pub(crate) fn keysched(key: &[u8]) -> Option<(usize, [u64; 30])> {
    let (num_rounds, mut skey) = round_words(key)?;
    let nkf = (num_rounds + 1) << 2;

    let mut comp_skey = [0u64; 30];
    for (round, pair) in skey[..nkf]
        .as_chunks()
        .0
        .iter()
        .zip(comp_skey.as_chunks_mut::<2>().0)
    {
        let mut q = [0u64; 8];
        (q[0], q[4]) = interleave_in(round);
        q[1] = q[0];
        q[2] = q[0];
        q[3] = q[0];
        q[5] = q[4];
        q[6] = q[4];
        q[7] = q[4];
        ortho(&mut q);
        pair[0] = (q[0] & 0x1111_1111_1111_1111)
            | (q[1] & 0x2222_2222_2222_2222)
            | (q[2] & 0x4444_4444_4444_4444)
            | (q[3] & 0x8888_8888_8888_8888);
        pair[1] = (q[4] & 0x1111_1111_1111_1111)
            | (q[5] & 0x2222_2222_2222_2222)
            | (q[6] & 0x4444_4444_4444_4444)
            | (q[7] & 0x8888_8888_8888_8888);
    }
    clear(&mut skey);
    Some((num_rounds, comp_skey))
}

/// `br_aes_ct64_skey_expand`: the subkeys, eight words per round key, from
/// the compressed ones.
pub(crate) fn skey_expand(num_rounds: usize, comp_skey: &[u64; 30]) -> [u64; 120] {
    let mut skey = [0u64; 120];
    let n = (num_rounds + 1) << 1;
    for (&word, expanded) in comp_skey[..n].iter().zip(skey.as_chunks_mut::<4>().0) {
        let x0 = word & 0x1111_1111_1111_1111;
        let x1 = (word & 0x2222_2222_2222_2222) >> 1;
        let x2 = (word & 0x4444_4444_4444_4444) >> 2;
        let x3 = (word & 0x8888_8888_8888_8888) >> 3;
        expanded[0] = (x0 << 4).wrapping_sub(x0);
        expanded[1] = (x1 << 4).wrapping_sub(x1);
        expanded[2] = (x2 << 4).wrapping_sub(x2);
        expanded[3] = (x3 << 4).wrapping_sub(x3);
    }
    skey
}
