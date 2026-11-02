//! Block sorting machinery: port of `blocksort.c`.
//!
//! The Burrows-Wheeler transform sorts every rotation of the block.
//! `mainSort` does it with a radix sort on the first two bytes, then a
//! three-way quicksort and a shell sort, caching what it learns in
//! `quadrant`; when a block is so repetitive that this takes more than
//! the work factor allows, or the block is small, `fallbackSort` does it
//! instead, with a doubling algorithm in the way of Manber and Myers.

use crate::bzip2::compress::EState;
use crate::bzip2::private::{BZ_N_OVERSHOOT, BZ_N_QSORT, BZ_N_RADIX};

// --- Fallback O(N log(N)^2) sorting algorithm, for repetitive blocks ---

/// `fallbackSimpleSort`: an insertion sort of `fmap[lo..=hi]` by
/// `eclass`.
#[inline(always)]
fn fallback_simple_sort(fmap: &mut [u32], eclass: &[u32], lo: i32, hi: i32) {
    if lo == hi {
        return;
    }

    if hi - lo > 3 {
        let mut i = hi - 4;
        while i >= lo {
            let tmp = fmap[i as usize];
            let ec_tmp = eclass[tmp as usize];
            let mut j = i + 4;
            while j <= hi && ec_tmp > eclass[fmap[j as usize] as usize] {
                fmap[(j - 4) as usize] = fmap[j as usize];
                j += 4;
            }
            fmap[(j - 4) as usize] = tmp;
            i -= 1;
        }
    }

    let mut i = hi - 1;
    while i >= lo {
        let tmp = fmap[i as usize];
        let ec_tmp = eclass[tmp as usize];
        let mut j = i + 1;
        while j <= hi && ec_tmp > eclass[fmap[j as usize] as usize] {
            fmap[(j - 1) as usize] = fmap[j as usize];
            j += 1;
        }
        fmap[(j - 1) as usize] = tmp;
        i -= 1;
    }
}

const FALLBACK_QSORT_SMALL_THRESH: i32 = 10;
const FALLBACK_QSORT_STACK_SIZE: usize = 100;

/// `fallbackQSort3`: a three-way quicksort of `fmap[lo_st..=hi_st]` by
/// `eclass`.
fn fallback_qsort3(fmap: &mut [u32], eclass: &[u32], lo_st: i32, hi_st: i32) {
    let mut stack_lo = [0i32; FALLBACK_QSORT_STACK_SIZE];
    let mut stack_hi = [0i32; FALLBACK_QSORT_STACK_SIZE];

    // `fswap`.
    let fswap = |fmap: &mut [u32], a: i32, b: i32| fmap.swap(a as usize, b as usize);
    // `fvswap`.
    let fvswap = |fmap: &mut [u32], mut yyp1: i32, mut yyp2: i32, mut yyn: i32| {
        while yyn > 0 {
            fmap.swap(yyp1 as usize, yyp2 as usize);
            yyp1 += 1;
            yyp2 += 1;
            yyn -= 1;
        }
    };

    let mut r: u32 = 0;

    let mut sp = 0;
    stack_lo[sp] = lo_st;
    stack_hi[sp] = hi_st;
    sp += 1;

    while sp > 0 {
        // AssertH(sp < FALLBACK_QSORT_STACK_SIZE - 1, 1004): the smaller
        // part is pushed last, so the stack holds at most a log of the
        // block's size.

        sp -= 1;
        let lo = stack_lo[sp];
        let hi = stack_hi[sp];
        if hi - lo < FALLBACK_QSORT_SMALL_THRESH {
            fallback_simple_sort(fmap, eclass, lo, hi);
            continue;
        }

        // Random partitioning. Median of 3 sometimes fails to avoid bad
        // cases. Median of 9 seems to help but looks rather expensive.
        // This too seems to work but is cheaper. Guidance for the magic
        // constants 7621 and 32768 is taken from Sedgewick's algorithms
        // book, chapter 35.
        r = ((r * 7621) + 1) % 32768;
        let r3 = r % 3;
        let med = if r3 == 0 {
            eclass[fmap[lo as usize] as usize]
        } else if r3 == 1 {
            eclass[fmap[((lo + hi) >> 1) as usize] as usize]
        } else {
            eclass[fmap[hi as usize] as usize]
        };

        let mut un_lo = lo;
        let mut lt_lo = lo;
        let mut un_hi = hi;
        let mut gt_hi = hi;

        loop {
            loop {
                if un_lo > un_hi {
                    break;
                }
                let n = eclass[fmap[un_lo as usize] as usize] as i32 - med as i32;
                if n == 0 {
                    fswap(fmap, un_lo, lt_lo);
                    lt_lo += 1;
                    un_lo += 1;
                    continue;
                }
                if n > 0 {
                    break;
                }
                un_lo += 1;
            }
            loop {
                if un_lo > un_hi {
                    break;
                }
                let n = eclass[fmap[un_hi as usize] as usize] as i32 - med as i32;
                if n == 0 {
                    fswap(fmap, un_hi, gt_hi);
                    gt_hi -= 1;
                    un_hi -= 1;
                    continue;
                }
                if n < 0 {
                    break;
                }
                un_hi -= 1;
            }
            if un_lo > un_hi {
                break;
            }
            fswap(fmap, un_lo, un_hi);
            un_lo += 1;
            un_hi -= 1;
        }

        if gt_hi < lt_lo {
            continue;
        }

        let n = (lt_lo - lo).min(un_lo - lt_lo);
        fvswap(fmap, lo, un_lo - n, n);
        let m = (hi - gt_hi).min(gt_hi - un_hi);
        fvswap(fmap, un_lo, hi - m + 1, m);

        let n = lo + un_lo - lt_lo - 1;
        let m = hi - (gt_hi - un_hi) + 1;

        if n - lo > hi - m {
            stack_lo[sp] = lo;
            stack_hi[sp] = n;
            sp += 1;
            stack_lo[sp] = m;
            stack_hi[sp] = hi;
            sp += 1;
        } else {
            stack_lo[sp] = m;
            stack_hi[sp] = hi;
            sp += 1;
            stack_lo[sp] = lo;
            stack_hi[sp] = n;
            sp += 1;
        }
    }
}

/// `fallbackSort`.
///
/// Pre: nblock > 0, block holds the block, eclass and fmap exist for
/// [0 .. nblock-1]. Post: fmap [0 .. nblock-1] holds sorted order, eclass
/// and bhtab [0 .. 2+(nblock/32)] destroyed.
///
/// Differs from libbzip2: libbzip2's `eclass` is the block's own memory,
/// read as bytes for the first radix sort and rebuilt from the sorted
/// order at the end; the port's is apart from the block, which it reads
/// directly and leaves as it was.
fn fallback_sort(
    fmap: &mut [u32],
    eclass: &mut [u32],
    bhtab: &mut [u32],
    block: &[u8],
    nblock: i32,
) {
    let mut ftab = [0i32; 257];
    let nblock_u = nblock as usize;

    // `SET_BH`, `CLEAR_BH`, `ISSET_BH`, `WORD_BH` and `UNALIGNED_BH`.
    macro_rules! set_bh {
        ($zz:expr) => {{
            let zz = ($zz) as usize;
            bhtab[zz >> 5] |= 1u32 << (zz & 31);
        }};
    }
    macro_rules! clear_bh {
        ($zz:expr) => {{
            let zz = ($zz) as usize;
            bhtab[zz >> 5] &= !(1u32 << (zz & 31));
        }};
    }
    macro_rules! isset_bh {
        ($zz:expr) => {{
            let zz = ($zz) as usize;
            bhtab[zz >> 5] & (1u32 << (zz & 31)) != 0
        }};
    }
    macro_rules! word_bh {
        ($zz:expr) => {
            bhtab[(($zz) as usize) >> 5]
        };
    }
    macro_rules! unaligned_bh {
        ($zz:expr) => {
            ($zz) & 0x01f != 0
        };
    }

    // Initial 1-char radix sort to generate initial fmap and initial BH
    // bits.
    for &b in &block[..nblock_u] {
        ftab[usize::from(b)] += 1;
    }
    for i in 1..257 {
        ftab[i] += ftab[i - 1];
    }

    for i in 0..nblock_u {
        let j = usize::from(block[i]);
        let k = ftab[j] - 1;
        ftab[j] = k;
        fmap[k as usize] = i as u32;
    }

    let n_bhtab = 2 + (nblock_u / 32);
    for w in bhtab.iter_mut().take(n_bhtab) {
        *w = 0;
    }
    for &f in &ftab[..256] {
        set_bh!(f);
    }

    // Inductively refine the buckets. Kind-of an "exponential radix sort"
    // (!), inspired by the Manber-Myers suffix array construction
    // algorithm.

    // Set sentinel bits for block-end detection.
    for i in 0..32 {
        set_bh!(nblock + 2 * i);
        clear_bh!(nblock + 2 * i + 1);
    }

    // The log(N) loop.
    let mut h = 1;
    loop {
        let mut j = 0;
        for i in 0..nblock {
            if isset_bh!(i) {
                j = i;
            }
            let mut k = fmap[i as usize] as i32 - h;
            if k < 0 {
                k += nblock;
            }
            eclass[k as usize] = j as u32;
        }

        let mut n_not_done = 0;
        let mut r = -1;
        loop {
            // Find the next non-singleton bucket.
            let mut k = r + 1;
            while isset_bh!(k) && unaligned_bh!(k) {
                k += 1;
            }
            if isset_bh!(k) {
                while word_bh!(k) == 0xffff_ffff {
                    k += 32;
                }
                while isset_bh!(k) {
                    k += 1;
                }
            }
            let l = k - 1;
            if l >= nblock {
                break;
            }
            while !isset_bh!(k) && unaligned_bh!(k) {
                k += 1;
            }
            if !isset_bh!(k) {
                while word_bh!(k) == 0x0000_0000 {
                    k += 32;
                }
                while !isset_bh!(k) {
                    k += 1;
                }
            }
            r = k - 1;
            if r >= nblock {
                break;
            }

            // Now [l, r] bracket current bucket.
            if r > l {
                n_not_done += r - l + 1;
                fallback_qsort3(fmap, eclass, l, r);

                // Scan bucket and generate header bits.
                let mut cc: i32 = -1;
                for i in l..=r {
                    let cc1 = eclass[fmap[i as usize] as usize] as i32;
                    if cc != cc1 {
                        set_bh!(i);
                        cc = cc1;
                    }
                }
            }
        }

        h *= 2;
        if h > nblock || n_not_done == 0 {
            break;
        }
    }

    // libbzip2 reconstructs the original block here, since its eclass was
    // the block; the port's block was never touched.
}

// --- The main, O(N^2 log(N)) sorting algorithm. Faster for "normal"
// non-repetitive blocks. ---

/// The 8 bytes of `block` from `i`, as a big-endian number: two such
/// numbers compare as the bytes do, the first that differs deciding.
#[inline(always)]
fn be64(block: &[u8], i: usize) -> u64 {
    let w = &block[i..i + 8];
    u64::from_be_bytes([w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]])
}

/// The same for 4 bytes.
#[inline(always)]
fn be32(block: &[u8], i: usize) -> u32 {
    let w = &block[i..i + 4];
    u32::from_be_bytes([w[0], w[1], w[2], w[3]])
}

/// `mainGtU`: whether the rotation at `i1` sorts after the one at `i2`,
/// counting the steps against `budget`.
///
/// Differs from libbzip2, with the same result and budget: libbzip2
/// compares a byte at a time, 12 of them, then 8 at a time each followed
/// by its quadrant value; the port compares 8 bytes at once (then 4), as
/// big-endian numbers, and the quadrant values in front of the first byte
/// that differs. Every index stays in the block and its overshoot, as in
/// libbzip2: `i1` and `i2` start below `nblock` + 15, and wrap below
/// `nblock` after each round of 8.
#[inline(always)]
fn main_gt_u(
    i1: u32,
    i2: u32,
    block: &[u8],
    quadrant: &[u16],
    nblock: u32,
    budget: &mut i32,
) -> bool {
    // AssertD(i1 != i2, "mainGtU")
    let (mut i1, mut i2) = (i1 as usize, i2 as usize);
    let nblock_u = nblock as usize;

    // 1 to 12.
    let (c1, c2) = (be64(block, i1), be64(block, i2));
    if c1 != c2 {
        return c1 > c2;
    }
    let (c1, c2) = (be32(block, i1 + 8), be32(block, i2 + 8));
    if c1 != c2 {
        return c1 > c2;
    }
    i1 += 12;
    i2 += 12;

    let mut k = nblock as i32 + 8;

    loop {
        // 1 to 8: the bytes up to the first that differs, each after its
        // quadrant value.
        let (c1, c2) = (be64(block, i1), be64(block, i2));
        let same = match c1 ^ c2 {
            0 => 8,
            x => (x.leading_zeros() / 8) as usize,
        };
        let (s1, s2) = (&quadrant[i1..i1 + 8], &quadrant[i2..i2 + 8]);
        for j in 0..same {
            if s1[j] != s2[j] {
                return s1[j] > s2[j];
            }
        }
        if same < 8 {
            return c1 > c2;
        }
        i1 += 8;
        i2 += 8;

        if i1 >= nblock_u {
            i1 -= nblock_u;
        }
        if i2 >= nblock_u {
            i2 -= nblock_u;
        }

        k -= 8;
        *budget -= 1;
        if k < 0 {
            break;
        }
    }

    false
}

/// Knuth's increments seem to work better than Incerpi-Sedgewick here.
/// Possibly because the number of elems to sort is usually small,
/// typically <= 20.
static INCS: [i32; 14] = [
    1, 4, 13, 40, 121, 364, 1093, 3280, 9841, 29524, 88573, 265720, 797161, 2391484,
];

/// `mainSimpleSort`: a shell sort of `ptr[lo..=hi]`, comparing from byte
/// `d` on.
#[allow(clippy::too_many_arguments)]
fn main_simple_sort(
    ptr: &mut [u32],
    block: &[u8],
    quadrant: &[u16],
    nblock: i32,
    lo: i32,
    hi: i32,
    d: i32,
    budget: &mut i32,
) {
    let big_n = hi - lo + 1;
    if big_n < 2 {
        return;
    }

    let mut hp = 0;
    while INCS[hp] < big_n {
        hp += 1;
    }

    let d = d as u32;
    let nblock = nblock as u32;
    for hp in (0..hp).rev() {
        let h = INCS[hp];

        // One insertion: copy 1, 2 or 3.
        macro_rules! copy {
            ($i:expr) => {{
                let v = ptr[$i as usize];
                let mut j = $i;
                while main_gt_u(
                    ptr[(j - h) as usize] + d,
                    v + d,
                    block,
                    quadrant,
                    nblock,
                    budget,
                ) {
                    ptr[j as usize] = ptr[(j - h) as usize];
                    j -= h;
                    if j <= (lo + h - 1) {
                        break;
                    }
                }
                ptr[j as usize] = v;
            }};
        }

        let mut i = lo + h;
        loop {
            if i > hi {
                break;
            }
            copy!(i);
            i += 1;

            if i > hi {
                break;
            }
            copy!(i);
            i += 1;

            if i > hi {
                break;
            }
            copy!(i);
            i += 1;

            if *budget < 0 {
                return;
            }
        }
    }
}

/// `mmed3`.
#[inline(always)]
fn mmed3(mut a: u8, mut b: u8, c: u8) -> u8 {
    if a > b {
        core::mem::swap(&mut a, &mut b);
    }
    if b > c {
        b = c;
        if a > b {
            b = a;
        }
    }
    b
}

const MAIN_QSORT_SMALL_THRESH: i32 = 20;
const MAIN_QSORT_DEPTH_THRESH: i32 = BZ_N_RADIX + BZ_N_QSORT;
const MAIN_QSORT_STACK_SIZE: usize = 100;

/// `mainQSort3`: the three-way quicksort for strings of Sedgewick and
/// Bentley ("Fast Algorithms for Sorting and Searching Strings"), on
/// `ptr[lo_st..=hi_st]` from byte `d_st` on.
#[allow(clippy::too_many_arguments)]
fn main_qsort3(
    ptr: &mut [u32],
    block: &[u8],
    quadrant: &[u16],
    nblock: i32,
    lo_st: i32,
    hi_st: i32,
    d_st: i32,
    budget: &mut i32,
) {
    let mut stack_lo = [0i32; MAIN_QSORT_STACK_SIZE];
    let mut stack_hi = [0i32; MAIN_QSORT_STACK_SIZE];
    let mut stack_d = [0i32; MAIN_QSORT_STACK_SIZE];

    let mut next_lo = [0i32; 3];
    let mut next_hi = [0i32; 3];
    let mut next_d = [0i32; 3];

    // `mvswap`.
    let mvswap = |ptr: &mut [u32], mut yyp1: i32, mut yyp2: i32, mut yyn: i32| {
        while yyn > 0 {
            ptr.swap(yyp1 as usize, yyp2 as usize);
            yyp1 += 1;
            yyp2 += 1;
            yyn -= 1;
        }
    };

    let mut sp = 0;
    stack_lo[sp] = lo_st;
    stack_hi[sp] = hi_st;
    stack_d[sp] = d_st;
    sp += 1;

    while sp > 0 {
        // AssertH(sp < MAIN_QSORT_STACK_SIZE - 2, 1001): the largest part
        // is pushed first, so the stack holds at most a log of the
        // block's size.

        sp -= 1;
        let lo = stack_lo[sp];
        let hi = stack_hi[sp];
        let d = stack_d[sp];
        if hi - lo < MAIN_QSORT_SMALL_THRESH || d > MAIN_QSORT_DEPTH_THRESH {
            main_simple_sort(ptr, block, quadrant, nblock, lo, hi, d, budget);
            if *budget < 0 {
                return;
            }
            continue;
        }

        let at = |p: i32| block[(ptr[p as usize] as i32 + d) as usize];
        let med = i32::from(mmed3(at(lo), at(hi), at((lo + hi) >> 1)));

        let mut un_lo = lo;
        let mut lt_lo = lo;
        let mut un_hi = hi;
        let mut gt_hi = hi;

        loop {
            loop {
                if un_lo > un_hi {
                    break;
                }
                let n = i32::from(block[(ptr[un_lo as usize] as i32 + d) as usize]) - med;
                if n == 0 {
                    ptr.swap(un_lo as usize, lt_lo as usize);
                    lt_lo += 1;
                    un_lo += 1;
                    continue;
                }
                if n > 0 {
                    break;
                }
                un_lo += 1;
            }
            loop {
                if un_lo > un_hi {
                    break;
                }
                let n = i32::from(block[(ptr[un_hi as usize] as i32 + d) as usize]) - med;
                if n == 0 {
                    ptr.swap(un_hi as usize, gt_hi as usize);
                    gt_hi -= 1;
                    un_hi -= 1;
                    continue;
                }
                if n < 0 {
                    break;
                }
                un_hi -= 1;
            }
            if un_lo > un_hi {
                break;
            }
            ptr.swap(un_lo as usize, un_hi as usize);
            un_lo += 1;
            un_hi -= 1;
        }

        // AssertD(unHi == unLo-1, "mainQSort3(2)")

        if gt_hi < lt_lo {
            stack_lo[sp] = lo;
            stack_hi[sp] = hi;
            stack_d[sp] = d + 1;
            sp += 1;
            continue;
        }

        let n = (lt_lo - lo).min(un_lo - lt_lo);
        mvswap(ptr, lo, un_lo - n, n);
        let m = (hi - gt_hi).min(gt_hi - un_hi);
        mvswap(ptr, un_lo, hi - m + 1, m);

        let n = lo + un_lo - lt_lo - 1;
        let m = hi - (gt_hi - un_hi) + 1;

        next_lo[0] = lo;
        next_hi[0] = n;
        next_d[0] = d;
        next_lo[1] = m;
        next_hi[1] = hi;
        next_d[1] = d;
        next_lo[2] = n + 1;
        next_hi[2] = m - 1;
        next_d[2] = d + 1;

        // `mnextsize` and `mnextswap`.
        macro_rules! mnextsize {
            ($az:expr) => {
                next_hi[$az] - next_lo[$az]
            };
        }
        macro_rules! mnextswap {
            ($az:expr, $bz:expr) => {{
                next_lo.swap($az, $bz);
                next_hi.swap($az, $bz);
                next_d.swap($az, $bz);
            }};
        }
        if mnextsize!(0) < mnextsize!(1) {
            mnextswap!(0, 1);
        }
        if mnextsize!(1) < mnextsize!(2) {
            mnextswap!(1, 2);
        }
        if mnextsize!(0) < mnextsize!(1) {
            mnextswap!(0, 1);
        }

        // AssertD(mnextsize(0) >= mnextsize(1), "mainQSort3(8)") and
        // AssertD(mnextsize(1) >= mnextsize(2), "mainQSort3(9)")

        for z in 0..3 {
            stack_lo[sp] = next_lo[z];
            stack_hi[sp] = next_hi[z];
            stack_d[sp] = next_d[z];
            sp += 1;
        }
    }
}

const SETMASK: u32 = 1 << 21;
const CLEARMASK: u32 = !SETMASK;

/// `mainSort`.
///
/// Pre: nblock > N_OVERSHOOT, block holds the block, ptr exists for
/// [0 .. nblock-1]. Post: block holds the block followed by the first
/// N_OVERSHOOT bytes again, ftab [0 .. 65536] destroyed, ptr [0 ..
/// nblock-1] holds sorted order; if (*budget < 0), sorting was abandoned.
fn main_sort(
    ptr: &mut [u32],
    block: &mut Vec<u8>,
    quadrant: &mut Vec<u16>,
    ftab: &mut [u32],
    nblock: i32,
    budget: &mut i32,
) {
    let mut running_order = [0i32; 256];
    let mut big_done = [false; 256];
    let mut copy_start = [0i32; 256];
    let mut copy_end = [0i32; 256];
    let nblock_u = nblock as usize;

    // `BIGFREQ`.
    let big_freq = |ftab: &[u32], b: i32| ftab[((b + 1) << 8) as usize] - ftab[(b << 8) as usize];

    // Set up the 2-byte frequency table.
    for f in ftab.iter_mut().take(65537) {
        *f = 0;
    }

    // Differs from libbzip2: quadrant is cleared here, for the block and
    // the overshoot, as libbzip2 clears it in the loops below.
    quadrant.clear();
    quadrant.resize(nblock_u + BZ_N_OVERSHOOT as usize, 0);

    let mut j = u32::from(block[0]) << 8;
    let mut i = nblock - 1;
    while i >= 3 {
        for o in 0..4 {
            j = (j >> 8) | (u32::from(block[(i - o) as usize]) << 8);
            ftab[j as usize] += 1;
        }
        i -= 4;
    }
    while i >= 0 {
        j = (j >> 8) | (u32::from(block[i as usize]) << 8);
        ftab[j as usize] += 1;
        i -= 1;
    }

    // (Emphasises close relationship of block & quadrant.)
    block.truncate(nblock_u);
    block.extend_from_within(..BZ_N_OVERSHOOT as usize);

    // Complete the initial radix sort.
    for i in 1..=65536 {
        ftab[i] += ftab[i - 1];
    }

    let mut s: u16 = u16::from(block[0]) << 8;
    let mut i = nblock - 1;
    while i >= 3 {
        for o in 0..4 {
            s = (s >> 8) | (u16::from(block[(i - o) as usize]) << 8);
            let j = ftab[s as usize] - 1;
            ftab[s as usize] = j;
            ptr[j as usize] = (i - o) as u32;
        }
        i -= 4;
    }
    while i >= 0 {
        s = (s >> 8) | (u16::from(block[i as usize]) << 8);
        let j = ftab[s as usize] - 1;
        ftab[s as usize] = j;
        ptr[j as usize] = i as u32;
        i -= 1;
    }

    // Now ftab contains the first loc of every small bucket. Calculate the
    // running order, from smallest to largest big bucket.
    for (i, r) in running_order.iter_mut().enumerate() {
        *r = i as i32;
    }

    {
        let mut h = 1;
        loop {
            h = 3 * h + 1;
            if h > 256 {
                break;
            }
        }
        loop {
            h /= 3;
            for i in h..=255 {
                let vv = running_order[i as usize];
                let mut j = i;
                while big_freq(ftab, running_order[(j - h) as usize]) > big_freq(ftab, vv) {
                    running_order[j as usize] = running_order[(j - h) as usize];
                    j -= h;
                    if j <= (h - 1) {
                        break;
                    }
                }
                running_order[j as usize] = vv;
            }
            if h == 1 {
                break;
            }
        }
    }

    // The main sorting loop.

    for i in 0..=255 {
        // Process big buckets, starting with the least full. Basically
        // this is a 3-step process in which we call mainQSort3 to sort the
        // small buckets [ss, j], but also make a big effort to avoid the
        // calls if we can.
        let ss = running_order[i];

        // Step 1: Complete the big bucket [ss] by quicksorting any
        // unsorted small buckets [ss, j], for j != ss. Hopefully previous
        // pointer-scanning phases have already completed many of the small
        // buckets [ss, j], so we don't have to sort them at all.
        for j in 0..=255 {
            if j != ss {
                let sb = ((ss << 8) + j) as usize;
                if ftab[sb] & SETMASK == 0 {
                    let lo = (ftab[sb] & CLEARMASK) as i32;
                    let hi = (ftab[sb + 1] & CLEARMASK) as i32 - 1;
                    if hi > lo {
                        main_qsort3(ptr, block, quadrant, nblock, lo, hi, BZ_N_RADIX, budget);
                        if *budget < 0 {
                            return;
                        }
                    }
                }
                ftab[sb] |= SETMASK;
            }
        }

        // AssertH(!bigDone[ss], 1006): every bucket is in the running
        // order once.

        // Step 2: Now scan this big bucket [ss] so as to synthesise the
        // sorted order for small buckets [t, ss] for all t, including,
        // magically, the bucket [ss,ss] too. This will avoid doing Real
        // Work in subsequent Step 1's.
        {
            for j in 0..=255usize {
                copy_start[j] = (ftab[(j << 8) + ss as usize] & CLEARMASK) as i32;
                copy_end[j] = (ftab[(j << 8) + ss as usize + 1] & CLEARMASK) as i32 - 1;
            }
            let mut j = (ftab[(ss << 8) as usize] & CLEARMASK) as i32;
            while j < copy_start[ss as usize] {
                let mut k = ptr[j as usize] as i32 - 1;
                if k < 0 {
                    k += nblock;
                }
                let c1 = usize::from(block[k as usize]);
                if !big_done[c1] {
                    ptr[copy_start[c1] as usize] = k as u32;
                    copy_start[c1] += 1;
                }
                j += 1;
            }
            let mut j = (ftab[((ss + 1) << 8) as usize] & CLEARMASK) as i32 - 1;
            while j > copy_end[ss as usize] {
                let mut k = ptr[j as usize] as i32 - 1;
                if k < 0 {
                    k += nblock;
                }
                let c1 = usize::from(block[k as usize]);
                if !big_done[c1] {
                    ptr[copy_end[c1] as usize] = k as u32;
                    copy_end[c1] -= 1;
                }
                j -= 1;
            }
        }

        // AssertH((copyStart[ss]-1 == copyEnd[ss]) || (copyStart[ss] == 0
        // && copyEnd[ss] == nblock-1), 1007): both scans fill the bucket
        // [ss, ss] exactly.

        for j in 0..=255usize {
            ftab[(j << 8) + ss as usize] |= SETMASK;
        }

        // Step 3: The [ss] big bucket is now done. Record this fact, and
        // update the quadrant descriptors. Remember to update quadrants in
        // the overshoot area too, if necessary. The "if (i < 255)" test
        // merely skips this updating for the last bucket processed, since
        // updating for the last bucket is pointless.
        //
        // The quadrant array provides a way to incrementally cache sort
        // orderings, as they appear, so as to make subsequent comparisons
        // in fullGtU() complete faster. For repetitive blocks this makes a
        // big difference (but not big enough to be able to avoid the
        // fallback sorting mechanism, exponential radix sort).
        //
        // The precise meaning is: at all times, for 0 <= i < nblock and
        // 0 <= j <= nblock, if block[i] != block[j], then the relative
        // values of quadrant[i] and quadrant[j] are meaningless. Else, if
        // quadrant[i] < quadrant[j] then the string starting at i
        // lexicographically precedes the string starting at j, else if
        // quadrant[i] > quadrant[j] then the string starting at j
        // lexicographically precedes the string starting at i, else the
        // relative ordering of the strings starting at i and j has not yet
        // been determined.
        big_done[ss as usize] = true;

        if i < 255 {
            let bb_start = (ftab[(ss << 8) as usize] & CLEARMASK) as i32;
            let bb_size = (ftab[((ss + 1) << 8) as usize] & CLEARMASK) as i32 - bb_start;
            let mut shifts = 0;

            while (bb_size >> shifts) > 65534 {
                shifts += 1;
            }

            let mut j = bb_size - 1;
            while j >= 0 {
                let a2update = ptr[(bb_start + j) as usize] as usize;
                let q_val = (j >> shifts) as u16;
                quadrant[a2update] = q_val;
                if a2update < BZ_N_OVERSHOOT as usize {
                    quadrant[a2update + nblock_u] = q_val;
                }
                j -= 1;
            }
            // AssertH(((bbSize-1) >> shifts) <= 65535, 1002): shifts was
            // chosen for it.
        }
    }
}

/// `BZ2_blockSort`: the block's rotations sorted into `ptr`, and
/// `orig_ptr` set to where the block itself is among them.
///
/// Pre: nblock > 0, block holds the block. Post: block holds the block
/// (and maybe the overshoot after it), ftab [0 .. 65536] destroyed, ptr
/// [0 .. nblock-1] holds sorted order.
pub(crate) fn block_sort(s: &mut EState) {
    let nblock = s.nblock;
    let mut wfact = s.work_factor;

    s.ptr.clear();
    s.ptr.resize(nblock as usize, 0);

    if nblock < 10000 {
        s.eclass.clear();
        s.eclass.resize(nblock as usize, 0);
        fallback_sort(&mut s.ptr, &mut s.eclass, &mut s.ftab, &s.block, nblock);
    } else {
        // (wfact-1) / 3 puts the default-factor-30 transition point at
        // very roughly the same place as with v0.1 and v0.9.0. Not that it
        // particularly matters any more, since the resulting compressed
        // stream is now the same regardless of whether or not we use the
        // main sort or fallback sort.
        wfact = wfact.clamp(1, 100);
        let budget_init = nblock * ((wfact - 1) / 3);
        let mut budget = budget_init;

        main_sort(
            &mut s.ptr,
            &mut s.block,
            &mut s.quadrant,
            &mut s.ftab,
            nblock,
            &mut budget,
        );
        if budget < 0 {
            s.eclass.clear();
            s.eclass.resize(nblock as usize, 0);
            fallback_sort(&mut s.ptr, &mut s.eclass, &mut s.ftab, &s.block, nblock);
        }
    }

    s.orig_ptr = -1;
    for i in 0..nblock as usize {
        if s.ptr[i] == 0 {
            s.orig_ptr = i as i32;
            break;
        }
    }

    // AssertH(s->origPtr != -1, 1003): one rotation is the block itself.
}
