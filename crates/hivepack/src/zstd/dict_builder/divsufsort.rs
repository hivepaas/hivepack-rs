// divsufsort.c for libdivsufsort-lite
// Copyright (c) 2003-2008 Yuta Mori All Rights Reserved.
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

//! Suffix arrays: port of `dictBuilder/divsufsort.c`, Yuta Mori's
//! libdivsufsort-lite as libzstd 1.5.7 ships it. This file is under the MIT
//! license above, which the crate's `LICENSE` repeats.
//!
//! [`divsufsort`] sorts the suffixes of a text; the legacy dictionary
//! trainer (`ZDICT_trainBuffer_legacy`) sorts its samples with it. It sorts
//! the type B* suffixes first, by their substrings (`sssort`, a multikey
//! introsort in blocks merged together) then by their ranks (`trsort`, a
//! tandem repeat sort), and the other suffixes follow from them
//! (`construct_SA`).
//!
//! libdivsufsort works with pointers into one `int` array, the suffix
//! array, which also holds its workspaces: the type B* suffixes (`PAb`),
//! their ranks (`ISAb`), the buffer of the merges. The port keeps that
//! array and that layout. Its pointers become offsets into the array, of
//! type `isize` ([`Ints`] is the array indexed by them), and the values it
//! holds stay `i32`, the C's `int`, with the same bitwise complements as
//! marks. Each function reads beside the C, and reads and writes the cells
//! libdivsufsort reads and writes: some of them past the range a function
//! sorts, but always within the array.
//!
//! Not ported: `divbwt` and its `construct_BWT` and `construct_BWT_indexes`,
//! the Burrows-Wheeler transform, which libzstd does not use; and the
//! OpenMP build (`LIBBSC_OPENMP`), which libzstd never turns on.
//! libdivsufsort's assertions, which libzstd's build keeps, are
//! `debug_assert!`s.

use core::ops::{Index, IndexMut};

use crate::zstd::common::error_private::{Result, error};

/// `ALPHABET_SIZE`: the byte values.
const ALPHABET_SIZE: i32 = 256;
/// `BUCKET_A_SIZE`: one bucket per first character.
const BUCKET_A_SIZE: usize = ALPHABET_SIZE as usize;
/// `BUCKET_B_SIZE`: one bucket per first two characters.
const BUCKET_B_SIZE: usize = (ALPHABET_SIZE * ALPHABET_SIZE) as usize;
/// `SS_INSERTIONSORT_THRESHOLD`: the largest group `ss_mintrosort` sorts
/// by insertion.
const SS_INSERTIONSORT_THRESHOLD: isize = 8;
/// `SS_BLOCKSIZE`: `sssort` sorts its range in blocks of this size, then
/// merges them.
const SS_BLOCKSIZE: isize = 1024;
/// `SS_MISORT_STACKSIZE`, for `SS_BLOCKSIZE` up to 4096.
const SS_MISORT_STACKSIZE: usize = 16;
/// `SS_SMERGE_STACKSIZE`
const SS_SMERGE_STACKSIZE: usize = 32;
/// `TR_INSERTIONSORT_THRESHOLD`: the largest group `tr_introsort` sorts
/// by insertion.
const TR_INSERTIONSORT_THRESHOLD: isize = 8;
/// `TR_STACKSIZE`
const TR_STACKSIZE: usize = 64;

/// How often each of the sort's rarer paths ran, so the tests can check
/// they reach all of them: `ss_heapsort`, `ss_rotate`, `ss_inplacemerge`,
/// `ss_mergeforward`, `ss_mergebackward`, the division of `ss_swapmerge`,
/// the last suffix of `sssort`, `tr_heapsort`, `tr_copy`,
/// `tr_partialcopy`, a budget spent (`trbudget_check`), and a second pass
/// of `trsort`.
#[cfg(test)]
pub(crate) static PATH_RUNS: [std::sync::atomic::AtomicUsize; 12] =
    [const { std::sync::atomic::AtomicUsize::new(0) }; 12];

/// Counts a run of the path `which` (see `PATH_RUNS`).
#[cfg(test)]
fn count_path(which: usize) {
    PATH_RUNS[which].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Nothing, outside the tests.
#[cfg(not(test))]
#[inline(always)]
fn count_path(_which: usize) {}

/// libdivsufsort's `int` array, the suffix array with its workspaces,
/// indexed by the offsets that the C's pointers into it have. An offset
/// out of the array is a bug, and panics.
struct Ints<'a>(&'a mut [i32]);

impl Index<isize> for Ints<'_> {
    type Output = i32;

    #[inline(always)]
    fn index(&self, i: isize) -> &i32 {
        &self.0[i as usize]
    }
}

impl IndexMut<isize> for Ints<'_> {
    #[inline(always)]
    fn index_mut(&mut self, i: isize) -> &mut i32 {
        &mut self.0[i as usize]
    }
}

impl Ints<'_> {
    /// The same array, in a wrapper of the caller's own. A function that
    /// takes the array as `&mut Ints` starts with `let sa = &mut sa.local();`:
    /// the optimizer then keeps the slice's address and length in registers
    /// rather than reading them again after each store into it, which takes
    /// 10 to 30% off the sort's time.
    #[inline(always)]
    fn local(&mut self) -> Ints<'_> {
        Ints(&mut *self.0)
    }

    /// `SWAP(*a, *b)`
    #[inline(always)]
    fn swap(&mut self, a: isize, b: isize) {
        self.0.swap(a as usize, b as usize);
    }

    /// `p[0]` and `p[1]`: where `ss_compare` reads a type B* substring, the
    /// start of the suffix and that of the next type B* suffix.
    #[inline(always)]
    fn pair(&self, p: isize) -> (i32, i32) {
        (self[p], self[p + 1])
    }

    /// `PA + v`: where the start of the type B* suffix `v` is, in their
    /// list at `pa`.
    #[inline(always)]
    fn at_pa(pa: isize, v: i32) -> isize {
        pa + v as isize
    }
}

/// The text, indexed by the offsets that the C's pointers into it have.
struct Text<'a>(&'a [u8]);

impl Index<isize> for Text<'_> {
    type Output = u8;

    #[inline(always)]
    fn index(&self, i: isize) -> &u8 {
        &self.0[i as usize]
    }
}

/// `lg_table`: the base-2 logarithm of each byte, `-1` for 0.
const LG_TABLE: [i32; 256] = [
    -1, 0, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7,
];

/// `ss_ilg`, as `SS_BLOCKSIZE` 1024 has it: the base-2 logarithm of `n`,
/// from its low 16 bits.
#[inline(always)]
fn ss_ilg(n: isize) -> i32 {
    let n = n as i32;
    if n & 0xff00 != 0 {
        8 + LG_TABLE[((n >> 8) & 0xff) as usize]
    } else {
        LG_TABLE[(n & 0xff) as usize]
    }
}

/// `sqq_table`: square roots of the bytes, times 16.
const SQQ_TABLE: [i32; 256] = [
    0, 16, 22, 27, 32, 35, 39, 42, 45, 48, 50, 53, 55, 57, 59, 61, 64, 65, 67, 69, 71, 73, 75, 76,
    78, 80, 81, 83, 84, 86, 87, 89, 90, 91, 93, 94, 96, 97, 98, 99, 101, 102, 103, 104, 106, 107,
    108, 109, 110, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 128,
    128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 144, 145,
    146, 147, 148, 149, 150, 150, 151, 152, 153, 154, 155, 155, 156, 157, 158, 159, 160, 160, 161,
    162, 163, 163, 164, 165, 166, 167, 167, 168, 169, 170, 170, 171, 172, 173, 173, 174, 175, 176,
    176, 177, 178, 178, 179, 180, 181, 181, 182, 183, 183, 184, 185, 185, 186, 187, 187, 188, 189,
    189, 190, 191, 192, 192, 193, 193, 194, 195, 195, 196, 197, 197, 198, 199, 199, 200, 201, 201,
    202, 203, 203, 204, 204, 205, 206, 206, 207, 208, 208, 209, 209, 210, 211, 211, 212, 212, 213,
    214, 214, 215, 215, 216, 217, 217, 218, 218, 219, 219, 220, 221, 221, 222, 222, 223, 224, 224,
    225, 225, 226, 226, 227, 227, 228, 229, 229, 230, 230, 231, 231, 232, 232, 233, 234, 234, 235,
    235, 236, 236, 237, 237, 238, 238, 239, 240, 240, 241, 241, 242, 242, 243, 243, 244, 244, 245,
    245, 246, 246, 247, 247, 248, 248, 249, 249, 250, 250, 251, 251, 252, 252, 253, 253, 254, 254,
    255,
];

/// `ss_isqrt`: the integer square root of `x`, at most `SS_BLOCKSIZE`.
fn ss_isqrt(x: isize) -> isize {
    if x >= SS_BLOCKSIZE * SS_BLOCKSIZE {
        return SS_BLOCKSIZE;
    }
    // Below 2^20, so an `int` as in the C, whose logarithm the C works out
    // as `tr_ilg` does.
    let x = x as i32;
    let e = tr_ilg(x);
    let mut y;
    if e >= 16 {
        y = SQQ_TABLE[(x >> ((e - 6) - (e & 1))) as usize] << ((e >> 1) - 7);
        if e >= 24 {
            y = (y + 1 + x / y) >> 1;
        }
        y = (y + 1 + x / y) >> 1;
    } else if e >= 8 {
        y = (SQQ_TABLE[(x >> ((e - 6) - (e & 1))) as usize] >> (7 - (e >> 1))) + 1;
    } else {
        return (SQQ_TABLE[x as usize] >> 4) as isize;
    }
    (if x < y * y { y - 1 } else { y }) as isize
}

/// `ss_compare`: compares two suffixes from `depth` on, each given by the
/// pair `PA[i], PA[i + 1]` of its type B* substring, which ends 2 bytes
/// past the start of the next type B* suffix. Negative, 0 or positive, as
/// `memcmp`.
#[inline(always)]
fn ss_compare(t: &Text<'_>, p1: (i32, i32), p2: (i32, i32), depth: i32) -> i32 {
    let mut u1 = (depth + p1.0) as isize;
    let mut u2 = (depth + p2.0) as isize;
    let u1n = p1.1 as isize + 2;
    let u2n = p2.1 as isize + 2;
    // Differs from libzstd: the bytes are compared as two slices, which
    // finds the same first difference as the C's loop.
    if u1 < u1n && u2 < u2n {
        let len = (u1n - u1).min(u2n - u2) as usize;
        let a = &t.0[u1 as usize..][..len];
        let b = &t.0[u2 as usize..][..len];
        let same = a.iter().zip(b).take_while(|(x, y)| x == y).count();
        u1 += same as isize;
        u2 += same as isize;
    }
    if u1 < u1n {
        if u2 < u2n {
            i32::from(t[u1]) - i32::from(t[u2])
        } else {
            1
        }
    } else if u2 < u2n {
        -1
    } else {
        0
    }
}

/// `Td[PA[*a]]`: the byte at `td` into the type B* suffix in `sa[a]`.
#[inline(always)]
fn td_pa(t: &Text<'_>, td: isize, sa: &Ints<'_>, pa: isize, a: isize) -> i32 {
    i32::from(t[td + sa[Ints::at_pa(pa, sa[a])] as isize])
}

/// `ss_insertionsort`: sorts the suffixes of `sa[first..last]` from
/// `depth` on, by insertion, marking each suffix equal to the one before
/// (its complement).
fn ss_insertionsort(
    t: &Text<'_>,
    sa: &mut Ints<'_>,
    pa: isize,
    first: isize,
    last: isize,
    depth: i32,
) {
    let sa = &mut sa.local();
    let mut i = last - 2;
    while first <= i {
        let tv = sa[i];
        let mut j = i + 1;
        let mut r;
        loop {
            r = ss_compare(
                t,
                sa.pair(Ints::at_pa(pa, tv)),
                sa.pair(Ints::at_pa(pa, sa[j])),
                depth,
            );
            if r <= 0 {
                break;
            }
            loop {
                sa[j - 1] = sa[j];
                j += 1;
                if !(j < last && sa[j] < 0) {
                    break;
                }
            }
            if last <= j {
                break;
            }
        }
        if r == 0 {
            sa[j] = !sa[j];
        }
        sa[j - 1] = tv;
        i -= 1;
    }
}

/// `ss_fixdown`: sifts `sa[base + i]` down the heap of `size` at `base`,
/// keyed by `Td[PA[*]]`.
#[inline(always)]
fn ss_fixdown(
    t: &Text<'_>,
    td: isize,
    pa: isize,
    sa: &mut Ints<'_>,
    base: isize,
    mut i: isize,
    size: isize,
) {
    let sa = &mut sa.local();
    let v = sa[base + i];
    let c = i32::from(t[td + sa[Ints::at_pa(pa, v)] as isize]);
    loop {
        let mut j = 2 * i + 1;
        if j >= size {
            break;
        }
        let mut k = j;
        j += 1;
        let mut d = td_pa(t, td, sa, pa, base + k);
        let e = td_pa(t, td, sa, pa, base + j);
        if d < e {
            k = j;
            d = e;
        }
        if d <= c {
            break;
        }
        sa[base + i] = sa[base + k];
        i = k;
    }
    sa[base + i] = v;
}

/// `ss_heapsort`: sorts the `size` suffixes at `base` by `Td[PA[*]]`, a
/// simple top-down heapsort.
fn ss_heapsort(t: &Text<'_>, td: isize, pa: isize, sa: &mut Ints<'_>, base: isize, size: isize) {
    let sa = &mut sa.local();
    count_path(0);
    let mut m = size;
    if size % 2 == 0 {
        m -= 1;
        if td_pa(t, td, sa, pa, base + m / 2) < td_pa(t, td, sa, pa, base + m) {
            sa.swap(base + m, base + m / 2);
        }
    }
    let mut i = m / 2 - 1;
    while 0 <= i {
        ss_fixdown(t, td, pa, sa, base, i, m);
        i -= 1;
    }
    if size % 2 == 0 {
        sa.swap(base, base + m);
        ss_fixdown(t, td, pa, sa, base, 0, m);
    }
    let mut i = m - 1;
    while 0 < i {
        let tv = sa[base];
        sa[base] = sa[base + i];
        ss_fixdown(t, td, pa, sa, base, 0, i);
        sa[base + i] = tv;
        i -= 1;
    }
}

/// `ss_median3`: where the median of three elements is.
#[inline(always)]
fn ss_median3(
    t: &Text<'_>,
    td: isize,
    pa: isize,
    sa: &Ints<'_>,
    mut v1: isize,
    mut v2: isize,
    v3: isize,
) -> isize {
    if td_pa(t, td, sa, pa, v1) > td_pa(t, td, sa, pa, v2) {
        core::mem::swap(&mut v1, &mut v2);
    }
    if td_pa(t, td, sa, pa, v2) > td_pa(t, td, sa, pa, v3) {
        if td_pa(t, td, sa, pa, v1) > td_pa(t, td, sa, pa, v3) {
            return v1;
        }
        return v3;
    }
    v2
}

/// `ss_median5`: where the median of five elements is.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn ss_median5(
    t: &Text<'_>,
    td: isize,
    pa: isize,
    sa: &Ints<'_>,
    mut v1: isize,
    mut v2: isize,
    mut v3: isize,
    mut v4: isize,
    mut v5: isize,
) -> isize {
    let key = |v: isize| td_pa(t, td, sa, pa, v);
    if key(v2) > key(v3) {
        core::mem::swap(&mut v2, &mut v3);
    }
    if key(v4) > key(v5) {
        core::mem::swap(&mut v4, &mut v5);
    }
    if key(v2) > key(v4) {
        core::mem::swap(&mut v2, &mut v4);
        core::mem::swap(&mut v3, &mut v5);
    }
    if key(v1) > key(v3) {
        core::mem::swap(&mut v1, &mut v3);
    }
    if key(v1) > key(v4) {
        core::mem::swap(&mut v1, &mut v4);
        core::mem::swap(&mut v3, &mut v5);
    }
    if key(v3) > key(v4) {
        return v4;
    }
    v3
}

/// `ss_pivot`: where the pivot of `sa[first..last]` is.
#[inline(always)]
fn ss_pivot(
    t: &Text<'_>,
    td: isize,
    pa: isize,
    sa: &Ints<'_>,
    mut first: isize,
    mut last: isize,
) -> isize {
    let mut tn = last - first;
    let mut middle = first + tn / 2;
    if tn <= 512 {
        if tn <= 32 {
            return ss_median3(t, td, pa, sa, first, middle, last - 1);
        }
        tn >>= 2;
        return ss_median5(
            t,
            td,
            pa,
            sa,
            first,
            first + tn,
            middle,
            last - 1 - tn,
            last - 1,
        );
    }
    tn >>= 3;
    first = ss_median3(t, td, pa, sa, first, first + tn, first + (tn << 1));
    middle = ss_median3(t, td, pa, sa, middle - tn, middle, middle + tn);
    last = ss_median3(t, td, pa, sa, last - 1 - (tn << 1), last - 1 - tn, last - 1);
    ss_median3(t, td, pa, sa, first, middle, last)
}

/// `ss_partition`: moves the suffixes of `sa[first..last]` whose type B*
/// substring ends before `depth` to the front, marked, and returns where
/// the others start. The comparisons are the C's, as written.
#[allow(clippy::int_plus_one)]
#[inline(always)]
fn ss_partition(sa: &mut Ints<'_>, pa: isize, first: isize, last: isize, depth: i32) -> isize {
    let sa = &mut sa.local();
    let mut a = first - 1;
    let mut b = last;
    loop {
        loop {
            a += 1;
            if !(a < b) {
                break;
            }
            let (start, next) = sa.pair(Ints::at_pa(pa, sa[a]));
            if !(start + depth >= next + 1) {
                break;
            }
            sa[a] = !sa[a];
        }
        loop {
            b -= 1;
            if !(a < b) {
                break;
            }
            let (start, next) = sa.pair(Ints::at_pa(pa, sa[b]));
            if !(start + depth < next + 1) {
                break;
            }
        }
        if b <= a {
            break;
        }
        let tv = !sa[b];
        sa[b] = sa[a];
        sa[a] = tv;
    }
    if first < a {
        sa[first] = !sa[first];
    }
    a
}

/// `ss_mintrosort`: sorts the suffixes of `sa[first..last]` from `depth`
/// on, a multikey introsort for groups of medium size.
fn ss_mintrosort(
    t: &Text<'_>,
    sa: &mut Ints<'_>,
    pa: isize,
    mut first: isize,
    mut last: isize,
    mut depth: i32,
) {
    let sa = &mut sa.local();
    let mut stack = [(0isize, 0isize, 0i32, 0i32); SS_MISORT_STACKSIZE];
    let mut ssize = 0;
    let mut limit = ss_ilg(last - first);
    let mut x = 0;
    macro_rules! push {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {{
            stack[ssize] = ($a, $b, $c, $d);
            ssize += 1;
        }};
    }
    macro_rules! pop {
        () => {{
            if ssize == 0 {
                return;
            }
            ssize -= 1;
            (first, last, depth, limit) = stack[ssize];
        }};
    }
    loop {
        if last - first <= SS_INSERTIONSORT_THRESHOLD {
            if 1 < last - first {
                ss_insertionsort(t, sa, pa, first, last, depth);
            }
            pop!();
            continue;
        }

        let td = depth as isize;
        let was = limit;
        limit -= 1;
        if was == 0 {
            ss_heapsort(t, td, pa, sa, first, last - first);
        }
        if limit < 0 {
            let mut a = first + 1;
            let mut v = td_pa(t, td, sa, pa, first);
            while a < last {
                x = td_pa(t, td, sa, pa, a);
                if x != v {
                    if 1 < a - first {
                        break;
                    }
                    v = x;
                    first = a;
                }
                a += 1;
            }
            if i32::from(t[td + sa[Ints::at_pa(pa, sa[first])] as isize - 1]) < v {
                first = ss_partition(sa, pa, first, a, depth);
            }
            if a - first <= last - a {
                if 1 < a - first {
                    push!(a, last, depth, -1);
                    last = a;
                    depth += 1;
                    limit = ss_ilg(a - first);
                } else {
                    first = a;
                    limit = -1;
                }
            } else if 1 < last - a {
                push!(first, a, depth + 1, ss_ilg(a - first));
                first = a;
                limit = -1;
            } else {
                last = a;
                depth += 1;
                limit = ss_ilg(a - first);
            }
            continue;
        }

        // Choose the pivot.
        let mut a = ss_pivot(t, td, pa, sa, first, last);
        let v = td_pa(t, td, sa, pa, a);
        sa.swap(first, a);

        // Partition.
        let mut b = first;
        loop {
            b += 1;
            if !(b < last) {
                break;
            }
            x = td_pa(t, td, sa, pa, b);
            if x != v {
                break;
            }
        }
        a = b;
        if a < last && x < v {
            loop {
                b += 1;
                if !(b < last) {
                    break;
                }
                x = td_pa(t, td, sa, pa, b);
                if !(x <= v) {
                    break;
                }
                if x == v {
                    sa.swap(b, a);
                    a += 1;
                }
            }
        }
        let mut c = last;
        loop {
            c -= 1;
            if !(b < c) {
                break;
            }
            x = td_pa(t, td, sa, pa, c);
            if x != v {
                break;
            }
        }
        let mut d = c;
        if b < d && x > v {
            loop {
                c -= 1;
                if !(b < c) {
                    break;
                }
                x = td_pa(t, td, sa, pa, c);
                if !(x >= v) {
                    break;
                }
                if x == v {
                    sa.swap(c, d);
                    d -= 1;
                }
            }
        }
        while b < c {
            sa.swap(b, c);
            loop {
                b += 1;
                if !(b < c) {
                    break;
                }
                x = td_pa(t, td, sa, pa, b);
                if !(x <= v) {
                    break;
                }
                if x == v {
                    sa.swap(b, a);
                    a += 1;
                }
            }
            loop {
                c -= 1;
                if !(b < c) {
                    break;
                }
                x = td_pa(t, td, sa, pa, c);
                if !(x >= v) {
                    break;
                }
                if x == v {
                    sa.swap(c, d);
                    d -= 1;
                }
            }
        }

        if a <= d {
            c = b - 1;

            let mut s = a - first;
            let tn = b - a;
            if s > tn {
                s = tn;
            }
            let (mut e, mut f) = (first, b - s);
            while 0 < s {
                sa.swap(e, f);
                s -= 1;
                e += 1;
                f += 1;
            }
            let mut s = d - c;
            let tn = last - d - 1;
            if s > tn {
                s = tn;
            }
            let (mut e, mut f) = (b, last - s);
            while 0 < s {
                sa.swap(e, f);
                s -= 1;
                e += 1;
                f += 1;
            }

            a = first + (b - a);
            c = last - (d - c);
            b = if v <= i32::from(t[td + sa[Ints::at_pa(pa, sa[a])] as isize - 1]) {
                a
            } else {
                ss_partition(sa, pa, a, c, depth)
            };

            if a - first <= last - c {
                if last - c <= c - b {
                    push!(b, c, depth + 1, ss_ilg(c - b));
                    push!(c, last, depth, limit);
                    last = a;
                } else if a - first <= c - b {
                    push!(c, last, depth, limit);
                    push!(b, c, depth + 1, ss_ilg(c - b));
                    last = a;
                } else {
                    push!(c, last, depth, limit);
                    push!(first, a, depth, limit);
                    first = b;
                    last = c;
                    depth += 1;
                    limit = ss_ilg(c - b);
                }
            } else if a - first <= c - b {
                push!(b, c, depth + 1, ss_ilg(c - b));
                push!(first, a, depth, limit);
                first = c;
            } else if last - c <= c - b {
                push!(first, a, depth, limit);
                push!(b, c, depth + 1, ss_ilg(c - b));
                first = c;
            } else {
                push!(first, a, depth, limit);
                push!(c, last, depth, limit);
                first = b;
                last = c;
                depth += 1;
                limit = ss_ilg(c - b);
            }
        } else {
            limit += 1;
            if i32::from(t[td + sa[Ints::at_pa(pa, sa[first])] as isize - 1]) < v {
                first = ss_partition(sa, pa, first, last, depth);
                limit = ss_ilg(last - first);
            }
            depth += 1;
        }
    }
}

/// `ss_blockswap`: swaps the `n` cells at `a` with the `n` at `b`.
#[inline(always)]
fn ss_blockswap(sa: &mut Ints<'_>, mut a: isize, mut b: isize, mut n: isize) {
    let sa = &mut sa.local();
    while 0 < n {
        sa.swap(a, b);
        n -= 1;
        a += 1;
        b += 1;
    }
}

/// `ss_rotate`: rotates `sa[first..last]` so that `middle` comes first.
#[inline(always)]
fn ss_rotate(sa: &mut Ints<'_>, mut first: isize, middle: isize, mut last: isize) {
    let sa = &mut sa.local();
    count_path(1);
    let mut l = middle - first;
    let mut r = last - middle;
    while 0 < l && 0 < r {
        if l == r {
            ss_blockswap(sa, first, middle, l);
            break;
        }
        if l < r {
            let mut a = last - 1;
            let mut b = middle - 1;
            let mut tv = sa[a];
            loop {
                sa[a] = sa[b];
                a -= 1;
                sa[b] = sa[a];
                b -= 1;
                if b < first {
                    sa[a] = tv;
                    last = a;
                    r -= l + 1;
                    if r <= l {
                        break;
                    }
                    a -= 1;
                    b = middle - 1;
                    tv = sa[a];
                }
            }
        } else {
            let mut a = first;
            let mut b = middle;
            let mut tv = sa[a];
            loop {
                sa[a] = sa[b];
                a += 1;
                sa[b] = sa[a];
                b += 1;
                if last <= b {
                    sa[a] = tv;
                    first = a + 1;
                    l -= r + 1;
                    if l <= r {
                        break;
                    }
                    a += 1;
                    b = middle;
                    tv = sa[a];
                }
            }
        }
    }
}

/// `ss_inplacemerge`: merges the sorted `sa[first..middle]` and
/// `sa[middle..last]` without a buffer.
fn ss_inplacemerge(
    t: &Text<'_>,
    sa: &mut Ints<'_>,
    pa: isize,
    first: isize,
    mut middle: isize,
    mut last: isize,
    depth: i32,
) {
    let sa = &mut sa.local();
    count_path(2);
    loop {
        let (x, p) = if sa[last - 1] < 0 {
            (1, Ints::at_pa(pa, !sa[last - 1]))
        } else {
            (0, Ints::at_pa(pa, sa[last - 1]))
        };
        let mut a = first;
        let mut len = middle - first;
        let mut half = len >> 1;
        let mut r = -1;
        while 0 < len {
            let b = a + half;
            let vb = sa[b];
            let q = ss_compare(
                t,
                sa.pair(Ints::at_pa(pa, if 0 <= vb { vb } else { !vb })),
                sa.pair(p),
                depth,
            );
            if q < 0 {
                a = b + 1;
                half -= (len & 1) ^ 1;
            } else {
                r = q;
            }
            len = half;
            half >>= 1;
        }
        if a < middle {
            if r == 0 {
                sa[a] = !sa[a];
            }
            ss_rotate(sa, a, middle, last);
            last -= middle - a;
            middle = a;
            if first == middle {
                break;
            }
        }
        last -= 1;
        if x != 0 {
            loop {
                last -= 1;
                if !(sa[last] < 0) {
                    break;
                }
            }
        }
        if middle == last {
            break;
        }
    }
}

/// `ss_mergeforward`: merges `sa[first..middle]` and `sa[middle..last]`,
/// the first half moved to the buffer at `buf`.
#[allow(clippy::too_many_arguments)]
fn ss_mergeforward(
    t: &Text<'_>,
    sa: &mut Ints<'_>,
    pa: isize,
    first: isize,
    middle: isize,
    last: isize,
    buf: isize,
    depth: i32,
) {
    let sa = &mut sa.local();
    count_path(3);
    let bufend = buf + (middle - first) - 1;
    ss_blockswap(sa, buf, first, middle - first);

    let mut a = first;
    let tv = sa[a];
    let mut b = buf;
    let mut c = middle;
    loop {
        let r = ss_compare(
            t,
            sa.pair(Ints::at_pa(pa, sa[b])),
            sa.pair(Ints::at_pa(pa, sa[c])),
            depth,
        );
        if r < 0 {
            loop {
                sa[a] = sa[b];
                a += 1;
                if bufend <= b {
                    sa[bufend] = tv;
                    return;
                }
                sa[b] = sa[a];
                b += 1;
                if !(sa[b] < 0) {
                    break;
                }
            }
        } else if r > 0 {
            loop {
                sa[a] = sa[c];
                a += 1;
                sa[c] = sa[a];
                c += 1;
                if last <= c {
                    while b < bufend {
                        sa[a] = sa[b];
                        a += 1;
                        sa[b] = sa[a];
                        b += 1;
                    }
                    sa[a] = sa[b];
                    sa[b] = tv;
                    return;
                }
                if !(sa[c] < 0) {
                    break;
                }
            }
        } else {
            sa[c] = !sa[c];
            loop {
                sa[a] = sa[b];
                a += 1;
                if bufend <= b {
                    sa[bufend] = tv;
                    return;
                }
                sa[b] = sa[a];
                b += 1;
                if !(sa[b] < 0) {
                    break;
                }
            }
            loop {
                sa[a] = sa[c];
                a += 1;
                sa[c] = sa[a];
                c += 1;
                if last <= c {
                    while b < bufend {
                        sa[a] = sa[b];
                        a += 1;
                        sa[b] = sa[a];
                        b += 1;
                    }
                    sa[a] = sa[b];
                    sa[b] = tv;
                    return;
                }
                if !(sa[c] < 0) {
                    break;
                }
            }
        }
    }
}

/// `ss_mergebackward`: merges `sa[first..middle]` and `sa[middle..last]`,
/// the second half moved to the buffer at `buf`.
#[allow(clippy::too_many_arguments)]
fn ss_mergebackward(
    t: &Text<'_>,
    sa: &mut Ints<'_>,
    pa: isize,
    first: isize,
    middle: isize,
    last: isize,
    buf: isize,
    depth: i32,
) {
    let sa = &mut sa.local();
    count_path(4);
    let bufend = buf + (last - middle) - 1;
    ss_blockswap(sa, buf, middle, last - middle);

    let mut x = 0;
    let mut p1 = if sa[bufend] < 0 {
        x |= 1;
        Ints::at_pa(pa, !sa[bufend])
    } else {
        Ints::at_pa(pa, sa[bufend])
    };
    let mut p2 = if sa[middle - 1] < 0 {
        x |= 2;
        Ints::at_pa(pa, !sa[middle - 1])
    } else {
        Ints::at_pa(pa, sa[middle - 1])
    };
    let mut a = last - 1;
    let tv = sa[a];
    let mut b = bufend;
    let mut c = middle - 1;
    loop {
        let r = ss_compare(t, sa.pair(p1), sa.pair(p2), depth);
        if 0 < r {
            if x & 1 != 0 {
                loop {
                    sa[a] = sa[b];
                    a -= 1;
                    sa[b] = sa[a];
                    b -= 1;
                    if !(sa[b] < 0) {
                        break;
                    }
                }
                x ^= 1;
            }
            sa[a] = sa[b];
            a -= 1;
            if b <= buf {
                sa[buf] = tv;
                break;
            }
            sa[b] = sa[a];
            b -= 1;
            if sa[b] < 0 {
                p1 = Ints::at_pa(pa, !sa[b]);
                x |= 1;
            } else {
                p1 = Ints::at_pa(pa, sa[b]);
            }
        } else if r < 0 {
            if x & 2 != 0 {
                loop {
                    sa[a] = sa[c];
                    a -= 1;
                    sa[c] = sa[a];
                    c -= 1;
                    if !(sa[c] < 0) {
                        break;
                    }
                }
                x ^= 2;
            }
            sa[a] = sa[c];
            a -= 1;
            sa[c] = sa[a];
            c -= 1;
            if c < first {
                while buf < b {
                    sa[a] = sa[b];
                    a -= 1;
                    sa[b] = sa[a];
                    b -= 1;
                }
                sa[a] = sa[b];
                sa[b] = tv;
                break;
            }
            if sa[c] < 0 {
                p2 = Ints::at_pa(pa, !sa[c]);
                x |= 2;
            } else {
                p2 = Ints::at_pa(pa, sa[c]);
            }
        } else {
            if x & 1 != 0 {
                loop {
                    sa[a] = sa[b];
                    a -= 1;
                    sa[b] = sa[a];
                    b -= 1;
                    if !(sa[b] < 0) {
                        break;
                    }
                }
                x ^= 1;
            }
            sa[a] = !sa[b];
            a -= 1;
            if b <= buf {
                sa[buf] = tv;
                break;
            }
            sa[b] = sa[a];
            b -= 1;
            if x & 2 != 0 {
                loop {
                    sa[a] = sa[c];
                    a -= 1;
                    sa[c] = sa[a];
                    c -= 1;
                    if !(sa[c] < 0) {
                        break;
                    }
                }
                x ^= 2;
            }
            sa[a] = sa[c];
            a -= 1;
            sa[c] = sa[a];
            c -= 1;
            if c < first {
                while buf < b {
                    sa[a] = sa[b];
                    a -= 1;
                    sa[b] = sa[a];
                    b -= 1;
                }
                sa[a] = sa[b];
                sa[b] = tv;
                break;
            }
            if sa[b] < 0 {
                p1 = Ints::at_pa(pa, !sa[b]);
                x |= 1;
            } else {
                p1 = Ints::at_pa(pa, sa[b]);
            }
            if sa[c] < 0 {
                p2 = Ints::at_pa(pa, !sa[c]);
                x |= 2;
            } else {
                p2 = Ints::at_pa(pa, sa[c]);
            }
        }
    }
}

/// `GETIDX`: a type B* suffix, its mark taken off.
#[inline(always)]
fn getidx(a: i32) -> i32 {
    if 0 <= a { a } else { !a }
}

/// `ss_swapmerge`: merges the sorted `sa[first..middle]` and
/// `sa[middle..last]`, dividing and conquering, with a buffer of
/// `bufsize` at `buf`.
#[allow(clippy::too_many_arguments)]
fn ss_swapmerge(
    t: &Text<'_>,
    sa: &mut Ints<'_>,
    pa: isize,
    mut first: isize,
    mut middle: isize,
    mut last: isize,
    buf: isize,
    bufsize: isize,
    depth: i32,
) {
    let sa = &mut sa.local();
    // `MERGE_CHECK(a, b, c)`: marks the suffix at `a`, and the one at `b`,
    // equal to the one before them, as `c` says to or a comparison finds.
    let merge_check = |sa: &mut Ints<'_>, a: isize, b: isize, c: i32| {
        if c & 1 != 0
            || (c & 2 != 0
                && ss_compare(
                    t,
                    sa.pair(Ints::at_pa(pa, getidx(sa[a - 1]))),
                    sa.pair(Ints::at_pa(pa, sa[a])),
                    depth,
                ) == 0)
        {
            sa[a] = !sa[a];
        }
        if c & 4 != 0
            && ss_compare(
                t,
                sa.pair(Ints::at_pa(pa, getidx(sa[b - 1]))),
                sa.pair(Ints::at_pa(pa, sa[b])),
                depth,
            ) == 0
        {
            sa[b] = !sa[b];
        }
    };
    let mut stack = [(0isize, 0isize, 0isize, 0i32); SS_SMERGE_STACKSIZE];
    let mut ssize = 0;
    let mut check = 0;
    macro_rules! push {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {{
            stack[ssize] = ($a, $b, $c, $d);
            ssize += 1;
        }};
    }
    macro_rules! pop {
        () => {{
            if ssize == 0 {
                return;
            }
            ssize -= 1;
            (first, middle, last, check) = stack[ssize];
        }};
    }
    loop {
        if last - middle <= bufsize {
            if first < middle && middle < last {
                ss_mergebackward(t, sa, pa, first, middle, last, buf, depth);
            }
            merge_check(sa, first, last, check);
            pop!();
            continue;
        }

        if middle - first <= bufsize {
            if first < middle {
                ss_mergeforward(t, sa, pa, first, middle, last, buf, depth);
            }
            merge_check(sa, first, last, check);
            pop!();
            continue;
        }

        let mut m = 0;
        let mut len = (middle - first).min(last - middle);
        let mut half = len >> 1;
        while 0 < len {
            if ss_compare(
                t,
                sa.pair(Ints::at_pa(pa, getidx(sa[middle + m + half]))),
                sa.pair(Ints::at_pa(pa, getidx(sa[middle - m - half - 1]))),
                depth,
            ) < 0
            {
                m += half + 1;
                half -= (len & 1) ^ 1;
            }
            len = half;
            half >>= 1;
        }

        if 0 < m {
            count_path(5);
            let lm = middle - m;
            let rm = middle + m;
            ss_blockswap(sa, lm, middle, m);
            let mut l = middle;
            let mut r = middle;
            let mut next = 0;
            if rm < last {
                if sa[rm] < 0 {
                    sa[rm] = !sa[rm];
                    if first < lm {
                        loop {
                            l -= 1;
                            if !(sa[l] < 0) {
                                break;
                            }
                        }
                        next |= 4;
                    }
                    next |= 1;
                } else if first < lm {
                    while sa[r] < 0 {
                        r += 1;
                    }
                    next |= 2;
                }
            }

            if l - first <= last - r {
                push!(r, rm, last, (next & 3) | (check & 4));
                middle = lm;
                last = l;
                check = (check & 3) | (next & 4);
            } else {
                if next & 2 != 0 && r == middle {
                    next ^= 6;
                }
                push!(first, lm, l, (check & 3) | (next & 4));
                first = r;
                middle = rm;
                check = (next & 3) | (check & 4);
            }
        } else {
            if ss_compare(
                t,
                sa.pair(Ints::at_pa(pa, getidx(sa[middle - 1]))),
                sa.pair(Ints::at_pa(pa, sa[middle])),
                depth,
            ) == 0
            {
                sa[middle] = !sa[middle];
            }
            merge_check(sa, first, last, check);
            pop!();
        }
    }
}

/// `sssort`: sorts the type B* suffixes of `sa[first..last]` by their
/// substrings from `depth` on, in blocks of `SS_BLOCKSIZE` merged
/// together, with the buffer of `bufsize` at `buf` (or one at the end of
/// the range). With `lastsuffix`, the first one is the last type B* suffix
/// of the text, sorted apart, as its substring runs to the end of the text.
#[allow(clippy::too_many_arguments)]
fn sssort(
    t: &Text<'_>,
    sa: &mut Ints<'_>,
    pa: isize,
    mut first: isize,
    last: isize,
    mut buf: isize,
    mut bufsize: isize,
    depth: i32,
    n: i32,
    lastsuffix: bool,
) {
    let sa = &mut sa.local();
    if lastsuffix {
        first += 1;
    }

    // The C's `(bufsize < SS_BLOCKSIZE) && (bufsize < (last - first)) &&
    // (bufsize < (limit = ss_isqrt(last - first)))`, `bufsize` being at
    // least 0.
    let middle;
    let mut limit = 0;
    if bufsize < SS_BLOCKSIZE && bufsize < last - first {
        limit = ss_isqrt(last - first);
    }
    if bufsize < limit {
        if SS_BLOCKSIZE < limit {
            limit = SS_BLOCKSIZE;
        }
        buf = last - limit;
        middle = buf;
        bufsize = limit;
    } else {
        middle = last;
        limit = 0;
    }
    let mut a = first;
    let mut i = 0i32;
    while SS_BLOCKSIZE < middle - a {
        ss_mintrosort(t, sa, pa, a, a + SS_BLOCKSIZE, depth);
        let mut curbufsize = last - (a + SS_BLOCKSIZE);
        let mut curbuf = a + SS_BLOCKSIZE;
        if curbufsize <= bufsize {
            curbufsize = bufsize;
            curbuf = buf;
        }
        let mut b = a;
        let mut k = SS_BLOCKSIZE;
        let mut j = i;
        while j & 1 != 0 {
            ss_swapmerge(t, sa, pa, b - k, b, b + k, curbuf, curbufsize, depth);
            b -= k;
            k <<= 1;
            j >>= 1;
        }
        a += SS_BLOCKSIZE;
        i += 1;
    }
    ss_mintrosort(t, sa, pa, a, middle, depth);
    let mut k = SS_BLOCKSIZE;
    while i != 0 {
        if i & 1 != 0 {
            ss_swapmerge(t, sa, pa, a - k, a, middle, buf, bufsize, depth);
            a -= k;
        }
        k <<= 1;
        i >>= 1;
    }
    if limit != 0 {
        ss_mintrosort(t, sa, pa, middle, last, depth);
        ss_inplacemerge(t, sa, pa, first, middle, last, depth);
    }

    if lastsuffix {
        count_path(6);
        // Insert the last type B* suffix.
        let pai = (sa[Ints::at_pa(pa, sa[first - 1])], n - 2);
        let i = sa[first - 1];
        let mut a = first;
        while a < last
            && (sa[a] < 0 || 0 < ss_compare(t, pai, sa.pair(Ints::at_pa(pa, sa[a])), depth))
        {
            sa[a - 1] = sa[a];
            a += 1;
        }
        sa[a - 1] = i;
    }
}

/// `tr_ilg`: the base-2 logarithm of `n`, `-1` for 0.
#[inline(always)]
fn tr_ilg(n: i32) -> i32 {
    let u = n as u32;
    if u & 0xffff_0000 != 0 {
        if u & 0xff00_0000 != 0 {
            24 + LG_TABLE[((n >> 24) & 0xff) as usize]
        } else {
            16 + LG_TABLE[((n >> 16) & 0xff) as usize]
        }
    } else if u & 0x0000_ff00 != 0 {
        8 + LG_TABLE[((n >> 8) & 0xff) as usize]
    } else {
        LG_TABLE[(n & 0xff) as usize]
    }
}

/// `ISAd[*a]`: the rank, at the depth of `isad`, of the suffix in `sa[a]`.
#[inline(always)]
fn isad_at(sa: &Ints<'_>, isad: isize, a: isize) -> i32 {
    sa[isad + sa[a] as isize]
}

/// `tr_insertionsort`: sorts `sa[first..last]` by their ranks at `isad`,
/// by insertion, marking each suffix equal to the one after it.
fn tr_insertionsort(sa: &mut Ints<'_>, isad: isize, first: isize, last: isize) {
    let sa = &mut sa.local();
    let mut a = first + 1;
    while a < last {
        let tv = sa[a];
        let mut b = a - 1;
        let mut r;
        loop {
            r = sa[isad + tv as isize] - isad_at(sa, isad, b);
            if !(0 > r) {
                break;
            }
            loop {
                sa[b + 1] = sa[b];
                b -= 1;
                if !(first <= b && sa[b] < 0) {
                    break;
                }
            }
            if b < first {
                break;
            }
        }
        if r == 0 {
            sa[b] = !sa[b];
        }
        sa[b + 1] = tv;
        a += 1;
    }
}

/// `tr_fixdown`: sifts `sa[base + i]` down the heap of `size` at `base`,
/// keyed by the ranks at `isad`.
#[inline(always)]
fn tr_fixdown(sa: &mut Ints<'_>, isad: isize, base: isize, mut i: isize, size: isize) {
    let sa = &mut sa.local();
    let v = sa[base + i];
    let c = sa[isad + v as isize];
    loop {
        let mut j = 2 * i + 1;
        if j >= size {
            break;
        }
        let mut k = j;
        j += 1;
        let mut d = isad_at(sa, isad, base + k);
        let e = isad_at(sa, isad, base + j);
        if d < e {
            k = j;
            d = e;
        }
        if d <= c {
            break;
        }
        sa[base + i] = sa[base + k];
        i = k;
    }
    sa[base + i] = v;
}

/// `tr_heapsort`: sorts the `size` suffixes at `base` by their ranks at
/// `isad`, a simple top-down heapsort.
fn tr_heapsort(sa: &mut Ints<'_>, isad: isize, base: isize, size: isize) {
    let sa = &mut sa.local();
    count_path(7);
    let mut m = size;
    if size % 2 == 0 {
        m -= 1;
        if isad_at(sa, isad, base + m / 2) < isad_at(sa, isad, base + m) {
            sa.swap(base + m, base + m / 2);
        }
    }
    let mut i = m / 2 - 1;
    while 0 <= i {
        tr_fixdown(sa, isad, base, i, m);
        i -= 1;
    }
    if size % 2 == 0 {
        sa.swap(base, base + m);
        tr_fixdown(sa, isad, base, 0, m);
    }
    let mut i = m - 1;
    while 0 < i {
        let tv = sa[base];
        sa[base] = sa[base + i];
        tr_fixdown(sa, isad, base, 0, i);
        sa[base + i] = tv;
        i -= 1;
    }
}

/// `tr_median3`: where the median of three elements is.
#[inline(always)]
fn tr_median3(sa: &Ints<'_>, isad: isize, mut v1: isize, mut v2: isize, v3: isize) -> isize {
    if isad_at(sa, isad, v1) > isad_at(sa, isad, v2) {
        core::mem::swap(&mut v1, &mut v2);
    }
    if isad_at(sa, isad, v2) > isad_at(sa, isad, v3) {
        if isad_at(sa, isad, v1) > isad_at(sa, isad, v3) {
            return v1;
        }
        return v3;
    }
    v2
}

/// `tr_median5`: where the median of five elements is.
#[inline(always)]
fn tr_median5(
    sa: &Ints<'_>,
    isad: isize,
    mut v1: isize,
    mut v2: isize,
    mut v3: isize,
    mut v4: isize,
    mut v5: isize,
) -> isize {
    let key = |v: isize| isad_at(sa, isad, v);
    if key(v2) > key(v3) {
        core::mem::swap(&mut v2, &mut v3);
    }
    if key(v4) > key(v5) {
        core::mem::swap(&mut v4, &mut v5);
    }
    if key(v2) > key(v4) {
        core::mem::swap(&mut v2, &mut v4);
        core::mem::swap(&mut v3, &mut v5);
    }
    if key(v1) > key(v3) {
        core::mem::swap(&mut v1, &mut v3);
    }
    if key(v1) > key(v4) {
        core::mem::swap(&mut v1, &mut v4);
        core::mem::swap(&mut v3, &mut v5);
    }
    if key(v3) > key(v4) {
        return v4;
    }
    v3
}

/// `tr_pivot`: where the pivot of `sa[first..last]` is.
#[inline(always)]
fn tr_pivot(sa: &Ints<'_>, isad: isize, mut first: isize, mut last: isize) -> isize {
    let mut tn = last - first;
    let mut middle = first + tn / 2;
    if tn <= 512 {
        if tn <= 32 {
            return tr_median3(sa, isad, first, middle, last - 1);
        }
        tn >>= 2;
        return tr_median5(sa, isad, first, first + tn, middle, last - 1 - tn, last - 1);
    }
    tn >>= 3;
    first = tr_median3(sa, isad, first, first + tn, first + (tn << 1));
    middle = tr_median3(sa, isad, middle - tn, middle, middle + tn);
    last = tr_median3(sa, isad, last - 1 - (tn << 1), last - 1 - tn, last - 1);
    tr_median3(sa, isad, first, middle, last)
}

/// `trbudget_t`: how much more `tr_introsort` may sort before it gives
/// up on a group, leaving it for the next pass of `trsort`.
struct TrBudget {
    chance: i32,
    remain: i32,
    incval: i32,
    count: i32,
}

impl TrBudget {
    /// `trbudget_init`
    fn new(chance: i32, incval: i32) -> Self {
        TrBudget {
            chance,
            remain: incval,
            incval,
            count: 0,
        }
    }

    /// `trbudget_check`: whether a group of `size` may be sorted, which
    /// spends it.
    #[inline(always)]
    fn check(&mut self, size: isize) -> bool {
        let size = size as i32;
        if size <= self.remain {
            self.remain -= size;
            return true;
        }
        if self.chance == 0 {
            count_path(10);
            self.count += size;
            return false;
        }
        self.remain += self.incval - size;
        self.chance -= 1;
        true
    }
}

/// `tr_partition`: partitions `sa[first..last]`, from `middle` on, around
/// the rank `v` at `isad`, and returns where the suffixes of that rank are,
/// `(*pa, *pb)`.
#[inline(always)]
fn tr_partition(
    sa: &mut Ints<'_>,
    isad: isize,
    mut first: isize,
    middle: isize,
    mut last: isize,
    v: i32,
) -> (isize, isize) {
    let sa = &mut sa.local();
    let mut x = 0;
    let mut b = middle - 1;
    loop {
        b += 1;
        if !(b < last) {
            break;
        }
        x = isad_at(sa, isad, b);
        if x != v {
            break;
        }
    }
    let mut a = b;
    if a < last && x < v {
        loop {
            b += 1;
            if !(b < last) {
                break;
            }
            x = isad_at(sa, isad, b);
            if !(x <= v) {
                break;
            }
            if x == v {
                sa.swap(b, a);
                a += 1;
            }
        }
    }
    let mut c = last;
    loop {
        c -= 1;
        if !(b < c) {
            break;
        }
        x = isad_at(sa, isad, c);
        if x != v {
            break;
        }
    }
    let mut d = c;
    if b < d && x > v {
        loop {
            c -= 1;
            if !(b < c) {
                break;
            }
            x = isad_at(sa, isad, c);
            if !(x >= v) {
                break;
            }
            if x == v {
                sa.swap(c, d);
                d -= 1;
            }
        }
    }
    while b < c {
        sa.swap(b, c);
        loop {
            b += 1;
            if !(b < c) {
                break;
            }
            x = isad_at(sa, isad, b);
            if !(x <= v) {
                break;
            }
            if x == v {
                sa.swap(b, a);
                a += 1;
            }
        }
        loop {
            c -= 1;
            if !(b < c) {
                break;
            }
            x = isad_at(sa, isad, c);
            if !(x >= v) {
                break;
            }
            if x == v {
                sa.swap(c, d);
                d -= 1;
            }
        }
    }

    if a <= d {
        c = b - 1;
        let mut s = a - first;
        let tn = b - a;
        if s > tn {
            s = tn;
        }
        let (mut e, mut f) = (first, b - s);
        while 0 < s {
            sa.swap(e, f);
            s -= 1;
            e += 1;
            f += 1;
        }
        let mut s = d - c;
        let tn = last - d - 1;
        if s > tn {
            s = tn;
        }
        let (mut e, mut f) = (b, last - s);
        while 0 < s {
            sa.swap(e, f);
            s -= 1;
            e += 1;
            f += 1;
        }
        first += b - a;
        last -= d - c;
    }
    (first, last)
}

/// `tr_copy`: sorts the suffixes of the middle partition, `sa[a..b]`, by
/// the sorted order of those of the left and right partitions, `depth`
/// further on. The ranks are at `isa`, and `sa` starts at 0.
fn tr_copy(
    sa: &mut Ints<'_>,
    isa: isize,
    first: isize,
    a: isize,
    b: isize,
    last: isize,
    depth: i32,
) {
    let sa = &mut sa.local();
    count_path(8);
    let v = (b - 1) as i32;
    let mut c = first;
    let mut d = a - 1;
    while c <= d {
        let s = sa[c] - depth;
        if 0 <= s && sa[isa + s as isize] == v {
            d += 1;
            sa[d] = s;
            sa[isa + s as isize] = d as i32;
        }
        c += 1;
    }
    let mut c = last - 1;
    let e = d + 1;
    let mut d = b;
    while e < d {
        let s = sa[c] - depth;
        if 0 <= s && sa[isa + s as isize] == v {
            d -= 1;
            sa[d] = s;
            sa[isa + s as isize] = d as i32;
        }
        c -= 1;
    }
}

/// `tr_partialcopy`: [`tr_copy`], for a middle partition whose suffixes
/// are not all sorted, which gives them their new ranks.
fn tr_partialcopy(
    sa: &mut Ints<'_>,
    isa: isize,
    first: isize,
    a: isize,
    b: isize,
    last: isize,
    depth: i32,
) {
    let sa = &mut sa.local();
    count_path(9);
    let mut newrank = -1;
    let v = (b - 1) as i32;
    let mut lastrank = -1;
    let mut c = first;
    let mut d = a - 1;
    while c <= d {
        let s = sa[c] - depth;
        if 0 <= s && sa[isa + s as isize] == v {
            d += 1;
            sa[d] = s;
            let rank = sa[isa + (s + depth) as isize];
            if lastrank != rank {
                lastrank = rank;
                newrank = d as i32;
            }
            sa[isa + s as isize] = newrank;
        }
        c += 1;
    }

    lastrank = -1;
    let mut e = d;
    while first <= e {
        let rank = sa[isa + sa[e] as isize];
        if lastrank != rank {
            lastrank = rank;
            newrank = e as i32;
        }
        if newrank != rank {
            let at = isa + sa[e] as isize;
            sa[at] = newrank;
        }
        e -= 1;
    }

    lastrank = -1;
    let mut c = last - 1;
    let e = d + 1;
    let mut d = b;
    while e < d {
        let s = sa[c] - depth;
        if 0 <= s && sa[isa + s as isize] == v {
            d -= 1;
            sa[d] = s;
            let rank = sa[isa + (s + depth) as isize];
            if lastrank != rank {
                lastrank = rank;
                newrank = d as i32;
            }
            sa[isa + s as isize] = newrank;
        }
        c -= 1;
    }
}

/// An entry of `tr_introsort`'s stack: `ISAd`, `first`, `last`, `limit`
/// and `trlink`, or for a tandem repeat, its middle partition and whether
/// it is sorted.
#[derive(Clone, Copy, Default)]
struct TrStackEntry {
    a: isize,
    b: isize,
    c: isize,
    d: i32,
    e: i32,
}

/// `tr_introsort`: sorts `sa[first..last]` by their ranks at `isad`, then
/// further on, an introsort that also finds tandem repeats. The ranks are
/// at `isa`, and `sa` starts at 0.
fn tr_introsort(
    sa: &mut Ints<'_>,
    isa: isize,
    mut isad: isize,
    mut first: isize,
    mut last: isize,
    budget: &mut TrBudget,
) {
    let sa = &mut sa.local();
    let mut stack = [TrStackEntry::default(); TR_STACKSIZE];
    let incr = isad - isa;
    let mut ssize = 0;
    let mut trlink: i32 = -1;
    let mut limit = tr_ilg((last - first) as i32);
    macro_rules! push5 {
        ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr) => {{
            stack[ssize] = TrStackEntry {
                a: $a,
                b: $b,
                c: $c,
                d: $d,
                e: $e,
            };
            ssize += 1;
        }};
    }
    macro_rules! pop5 {
        () => {{
            if ssize == 0 {
                return;
            }
            ssize -= 1;
            let entry = stack[ssize];
            isad = entry.a;
            first = entry.b;
            last = entry.c;
            limit = entry.d;
            trlink = entry.e;
        }};
    }
    loop {
        if limit < 0 {
            if limit == -1 {
                // Tandem repeat partition.
                let (a, b) = tr_partition(sa, isad - incr, first, first, last, (last - 1) as i32);

                // Update the ranks.
                if a < last {
                    let v = (a - 1) as i32;
                    for c in first..a {
                        let at = isa + sa[c] as isize;
                        sa[at] = v;
                    }
                }
                if b < last {
                    let v = (b - 1) as i32;
                    for c in a..b {
                        let at = isa + sa[c] as isize;
                        sa[at] = v;
                    }
                }

                // Push.
                if 1 < b - a {
                    push5!(0, a, b, 0, 0);
                    push5!(isad - incr, first, last, -2, trlink);
                    trlink = ssize as i32 - 2;
                }
                if a - first <= last - b {
                    if 1 < a - first {
                        push5!(isad, b, last, tr_ilg((last - b) as i32), trlink);
                        last = a;
                        limit = tr_ilg((a - first) as i32);
                    } else if 1 < last - b {
                        first = b;
                        limit = tr_ilg((last - b) as i32);
                    } else {
                        pop5!();
                    }
                } else if 1 < last - b {
                    push5!(isad, first, a, tr_ilg((a - first) as i32), trlink);
                    first = b;
                    limit = tr_ilg((last - b) as i32);
                } else if 1 < a - first {
                    last = a;
                    limit = tr_ilg((a - first) as i32);
                } else {
                    pop5!();
                }
            } else if limit == -2 {
                // Tandem repeat copy.
                ssize -= 1;
                let a = stack[ssize].b;
                let b = stack[ssize].c;
                if stack[ssize].d == 0 {
                    tr_copy(sa, isa, first, a, b, last, (isad - isa) as i32);
                } else {
                    if 0 <= trlink {
                        stack[trlink as usize].d = -1;
                    }
                    tr_partialcopy(sa, isa, first, a, b, last, (isad - isa) as i32);
                }
                pop5!();
            } else {
                // Sorted partition.
                if 0 <= sa[first] {
                    let mut a = first;
                    loop {
                        let at = isa + sa[a] as isize;
                        sa[at] = a as i32;
                        a += 1;
                        if !(a < last && 0 <= sa[a]) {
                            break;
                        }
                    }
                    first = a;
                }
                if first < last {
                    let mut a = first;
                    loop {
                        sa[a] = !sa[a];
                        a += 1;
                        if !(sa[a] < 0) {
                            break;
                        }
                    }
                    let next = if sa[isa + sa[a] as isize] != isad_at(sa, isad, a) {
                        tr_ilg((a - first + 1) as i32)
                    } else {
                        -1
                    };
                    a += 1;
                    if a < last {
                        let v = (a - 1) as i32;
                        for b in first..a {
                            let at = isa + sa[b] as isize;
                            sa[at] = v;
                        }
                    }

                    // Push.
                    if budget.check(a - first) {
                        if a - first <= last - a {
                            push5!(isad, a, last, -3, trlink);
                            isad += incr;
                            last = a;
                            limit = next;
                        } else if 1 < last - a {
                            push5!(isad + incr, first, a, next, trlink);
                            first = a;
                            limit = -3;
                        } else {
                            isad += incr;
                            last = a;
                            limit = next;
                        }
                    } else {
                        if 0 <= trlink {
                            stack[trlink as usize].d = -1;
                        }
                        if 1 < last - a {
                            first = a;
                            limit = -3;
                        } else {
                            pop5!();
                        }
                    }
                } else {
                    pop5!();
                }
            }
            continue;
        }

        if last - first <= TR_INSERTIONSORT_THRESHOLD {
            tr_insertionsort(sa, isad, first, last);
            limit = -3;
            continue;
        }

        let was = limit;
        limit -= 1;
        if was == 0 {
            tr_heapsort(sa, isad, first, last - first);
            let mut a = last - 1;
            while first < a {
                let x = isad_at(sa, isad, a);
                let mut b = a - 1;
                while first <= b && isad_at(sa, isad, b) == x {
                    sa[b] = !sa[b];
                    b -= 1;
                }
                a = b;
            }
            limit = -3;
            continue;
        }

        // Choose the pivot.
        let a = tr_pivot(sa, isad, first, last);
        sa.swap(first, a);
        let v = isad_at(sa, isad, first);

        // Partition.
        let (a, b) = tr_partition(sa, isad, first, first + 1, last, v);
        if last - first != b - a {
            let next = if sa[isa + sa[a] as isize] != v {
                tr_ilg((b - a) as i32)
            } else {
                -1
            };

            // Update the ranks.
            let v = (a - 1) as i32;
            for c in first..a {
                let at = isa + sa[c] as isize;
                sa[at] = v;
            }
            if b < last {
                let v = (b - 1) as i32;
                for c in a..b {
                    let at = isa + sa[c] as isize;
                    sa[at] = v;
                }
            }

            // Push.
            if 1 < b - a && budget.check(b - a) {
                if a - first <= last - b {
                    if last - b <= b - a {
                        if 1 < a - first {
                            push5!(isad + incr, a, b, next, trlink);
                            push5!(isad, b, last, limit, trlink);
                            last = a;
                        } else if 1 < last - b {
                            push5!(isad + incr, a, b, next, trlink);
                            first = b;
                        } else {
                            isad += incr;
                            first = a;
                            last = b;
                            limit = next;
                        }
                    } else if a - first <= b - a {
                        if 1 < a - first {
                            push5!(isad, b, last, limit, trlink);
                            push5!(isad + incr, a, b, next, trlink);
                            last = a;
                        } else {
                            push5!(isad, b, last, limit, trlink);
                            isad += incr;
                            first = a;
                            last = b;
                            limit = next;
                        }
                    } else {
                        push5!(isad, b, last, limit, trlink);
                        push5!(isad, first, a, limit, trlink);
                        isad += incr;
                        first = a;
                        last = b;
                        limit = next;
                    }
                } else if a - first <= b - a {
                    if 1 < last - b {
                        push5!(isad + incr, a, b, next, trlink);
                        push5!(isad, first, a, limit, trlink);
                        first = b;
                    } else if 1 < a - first {
                        push5!(isad + incr, a, b, next, trlink);
                        last = a;
                    } else {
                        isad += incr;
                        first = a;
                        last = b;
                        limit = next;
                    }
                } else if last - b <= b - a {
                    if 1 < last - b {
                        push5!(isad, first, a, limit, trlink);
                        push5!(isad + incr, a, b, next, trlink);
                        first = b;
                    } else {
                        push5!(isad, first, a, limit, trlink);
                        isad += incr;
                        first = a;
                        last = b;
                        limit = next;
                    }
                } else {
                    push5!(isad, first, a, limit, trlink);
                    push5!(isad, b, last, limit, trlink);
                    isad += incr;
                    first = a;
                    last = b;
                    limit = next;
                }
            } else {
                if 1 < b - a && 0 <= trlink {
                    stack[trlink as usize].d = -1;
                }
                if a - first <= last - b {
                    if 1 < a - first {
                        push5!(isad, b, last, limit, trlink);
                        last = a;
                    } else if 1 < last - b {
                        first = b;
                    } else {
                        pop5!();
                    }
                } else if 1 < last - b {
                    push5!(isad, first, a, limit, trlink);
                    first = b;
                } else if 1 < a - first {
                    last = a;
                } else {
                    pop5!();
                }
            }
        } else if budget.check(last - first) {
            limit = tr_ilg((last - first) as i32);
            isad += incr;
        } else {
            if 0 <= trlink {
                stack[trlink as usize].d = -1;
            }
            pop5!();
        }
    }
}

/// `trsort`: the tandem repeat sort, which sorts the `n` suffixes of
/// `sa[..n]` by their ranks at `isa`, doubling the depth from `depth` until
/// each has a rank of its own.
fn trsort(sa: &mut Ints<'_>, isa: isize, n: i32, depth: i32) {
    let sa = &mut sa.local();
    let mut budget = TrBudget::new(tr_ilg(n) * 2 / 3, n);
    let mut isad = isa + depth as isize;
    let end = n as isize;
    while -n < sa[0] {
        let mut first = 0isize;
        let mut skip = 0i32;
        let mut unsorted = 0i32;
        loop {
            let tv = sa[first];
            if tv < 0 {
                first -= tv as isize;
                skip += tv;
            } else {
                if skip != 0 {
                    sa[first + skip as isize] = skip;
                    skip = 0;
                }
                let last = sa[isa + tv as isize] as isize + 1;
                if 1 < last - first {
                    budget.count = 0;
                    tr_introsort(sa, isa, isad, first, last, &mut budget);
                    if budget.count != 0 {
                        unsorted += budget.count;
                    } else {
                        skip = (first - last) as i32;
                    }
                } else if last - first == 1 {
                    skip = -1;
                }
                first = last;
            }
            if !(first < end) {
                break;
            }
        }
        if skip != 0 {
            sa[first + skip as isize] = skip;
        }
        if unsorted == 0 {
            break;
        }
        count_path(11);
        isad += isad - isa;
    }
}

/// The two bucket arrays of [`sort_type_bstar`] and [`construct_sa`]:
/// `bucket_A`, by first character, and `bucket_B`, by first two, which
/// `BUCKET_B` and `BUCKET_BSTAR` index in the two orders.
struct Buckets<'a> {
    a: &'a mut [i32],
    b: &'a mut [i32],
}

impl Buckets<'_> {
    /// The same arrays, in a wrapper of the caller's own, as
    /// [`Ints::local`].
    #[inline(always)]
    fn local(&mut self) -> Buckets<'_> {
        Buckets {
            a: &mut *self.a,
            b: &mut *self.b,
        }
    }

    /// `BUCKET_A(c0)`
    #[inline(always)]
    fn a(&mut self, c0: i32) -> &mut i32 {
        &mut self.a[c0 as usize]
    }

    /// `BUCKET_B(c0, c1)`
    #[inline(always)]
    fn b(&mut self, c0: i32, c1: i32) -> &mut i32 {
        &mut self.b[((c1 << 8) | c0) as usize]
    }

    /// `BUCKET_BSTAR(c0, c1)`
    #[inline(always)]
    fn bstar(&mut self, c0: i32, c1: i32) -> &mut i32 {
        &mut self.b[((c0 << 8) | c1) as usize]
    }
}

/// `sort_typeBstar`: sorts the type B* suffixes of the text into `sa`,
/// counts the suffixes of each bucket, and returns how many type B*
/// suffixes there are.
fn sort_type_bstar(t: &Text<'_>, sa: &mut Ints<'_>, bk: &mut Buckets<'_>, n: i32) -> i32 {
    let sa = &mut sa.local();
    let bk = &mut bk.local();
    // Initialize the bucket arrays.
    bk.a.fill(0);
    bk.b.fill(0);
    let tc = |i: i32| i32::from(t[i as isize]);

    // Count the number of occurrences of the first one or two characters of
    // each type A, B and B* suffix. Moreover, store the beginning position
    // of all type B* suffixes into the array SA.
    let mut i = n - 1;
    let mut m = n;
    let mut c0 = tc(n - 1);
    let mut c1;
    while 0 <= i {
        // Type A suffix.
        loop {
            c1 = c0;
            *bk.a(c1) += 1;
            i -= 1;
            if !(0 <= i) {
                break;
            }
            c0 = tc(i);
            if !(c0 >= c1) {
                break;
            }
        }
        if 0 <= i {
            // Type B* suffix.
            *bk.bstar(c0, c1) += 1;
            m -= 1;
            sa[m as isize] = i;
            // Type B suffix.
            i -= 1;
            c1 = c0;
            while 0 <= i {
                c0 = tc(i);
                if !(c0 <= c1) {
                    break;
                }
                *bk.b(c0, c1) += 1;
                i -= 1;
                c1 = c0;
            }
        }
    }
    m = n - m;
    // Note: a type B* suffix is lexicographically smaller than a type B
    // suffix that begins with the same first two characters.

    // Calculate the index of start/end point of each bucket.
    let mut i = 0;
    let mut j = 0;
    for c0 in 0..ALPHABET_SIZE {
        let tv = i + *bk.a(c0);
        *bk.a(c0) = i + j; // start point
        i = tv + *bk.b(c0, c0);
        for c1 in c0 + 1..ALPHABET_SIZE {
            j += *bk.bstar(c0, c1);
            *bk.bstar(c0, c1) = j; // end point
            i += *bk.b(c0, c1);
        }
    }

    if 0 < m {
        // Sort the type B* suffixes by their first two characters.
        let pab = (n - m) as isize;
        let isab = m as isize;
        let mut i = m - 2;
        while 0 <= i {
            let tv = sa[pab + i as isize];
            let (c0, c1) = (tc(tv), tc(tv + 1));
            let at = bk.bstar(c0, c1);
            *at -= 1;
            sa[*at as isize] = i;
            i -= 1;
        }
        let tv = sa[pab + (m - 1) as isize];
        let (c0, c1) = (tc(tv), tc(tv + 1));
        let at = bk.bstar(c0, c1);
        *at -= 1;
        sa[*at as isize] = m - 1;

        // Sort the type B* substrings using sssort.
        let buf = m as isize;
        let bufsize = (n - 2 * m) as isize;
        let mut c0 = ALPHABET_SIZE - 2;
        let mut j = m;
        while 0 < j {
            let mut c1 = ALPHABET_SIZE - 1;
            while c0 < c1 {
                let i = *bk.bstar(c0, c1);
                if 1 < j - i {
                    let lastsuffix = sa[i as isize] == m - 1;
                    sssort(
                        t, sa, pab, i as isize, j as isize, buf, bufsize, 2, n, lastsuffix,
                    );
                }
                j = i;
                c1 -= 1;
            }
            c0 -= 1;
        }

        // Compute the ranks of the type B* substrings.
        let mut i = (m - 1) as isize;
        while 0 <= i {
            if 0 <= sa[i] {
                let j = i;
                loop {
                    let at = isab + sa[i] as isize;
                    sa[at] = i as i32;
                    i -= 1;
                    if !(0 <= i && 0 <= sa[i]) {
                        break;
                    }
                }
                sa[i + 1] = (i - j) as i32;
                if i <= 0 {
                    break;
                }
            }
            let j = i as i32;
            loop {
                let v = !sa[i];
                sa[i] = v;
                sa[isab + v as isize] = j;
                i -= 1;
                if !(sa[i] < 0) {
                    break;
                }
            }
            let at = isab + sa[i] as isize;
            sa[at] = j;
            i -= 1;
        }

        // Construct the inverse suffix array of the type B* suffixes using
        // trsort.
        trsort(sa, isab, m, 1);

        // Set the sorted order of the type B* suffixes.
        let mut i = n - 1;
        let mut j = m;
        let mut c0 = tc(n - 1);
        while 0 <= i {
            i -= 1;
            let mut c1 = c0;
            while 0 <= i {
                c0 = tc(i);
                if !(c0 >= c1) {
                    break;
                }
                i -= 1;
                c1 = c0;
            }
            if 0 <= i {
                let tv = i;
                i -= 1;
                c1 = c0;
                while 0 <= i {
                    c0 = tc(i);
                    if !(c0 <= c1) {
                        break;
                    }
                    i -= 1;
                    c1 = c0;
                }
                j -= 1;
                let at = sa[isab + j as isize] as isize;
                sa[at] = if tv == 0 || 1 < tv - i { tv } else { !tv };
            }
        }

        // Calculate the index of start/end point of each bucket.
        *bk.b(ALPHABET_SIZE - 1, ALPHABET_SIZE - 1) = n; // end point
        let mut k = m - 1;
        let mut c0 = ALPHABET_SIZE - 2;
        while 0 <= c0 {
            let mut i = *bk.a(c0 + 1) - 1;
            let mut c1 = ALPHABET_SIZE - 1;
            while c0 < c1 {
                let tv = i - *bk.b(c0, c1);
                *bk.b(c0, c1) = i; // end point

                // Move all type B* suffixes to the correct position.
                i = tv;
                let j = *bk.bstar(c0, c1);
                while j <= k {
                    sa[i as isize] = sa[k as isize];
                    i -= 1;
                    k -= 1;
                }
                c1 -= 1;
            }
            *bk.bstar(c0, c0 + 1) = i - *bk.b(c0, c0) + 1; // start point
            *bk.b(c0, c0) = i; // end point
            c0 -= 1;
        }
    }

    m
}

/// `construct_SA`: the suffix array, from the sorted order of the `m`
/// type B* suffixes.
fn construct_sa(t: &Text<'_>, sa: &mut Ints<'_>, bk: &mut Buckets<'_>, n: i32, m: i32) {
    let sa = &mut sa.local();
    let bk = &mut bk.local();
    let tc = |i: i32| i32::from(t[i as isize]);
    if 0 < m {
        // Construct the sorted order of the type B suffixes by using the
        // sorted order of the type B* suffixes.
        let mut c1 = ALPHABET_SIZE - 2;
        while 0 <= c1 {
            // Scan the suffix array from right to left.
            let i = *bk.bstar(c1, c1 + 1) as isize;
            let mut j = *bk.a(c1 + 1) as isize - 1;
            let mut k = 0isize;
            let mut c2 = -1;
            while i <= j {
                let mut s = sa[j];
                if 0 < s {
                    debug_assert!(tc(s) == c1);
                    debug_assert!(s + 1 < n && tc(s) <= tc(s + 1));
                    debug_assert!(tc(s - 1) <= tc(s));
                    sa[j] = !s;
                    s -= 1;
                    let c0 = tc(s);
                    if 0 < s && tc(s - 1) > c0 {
                        s = !s;
                    }
                    if c0 != c2 {
                        if 0 <= c2 {
                            *bk.b(c2, c1) = k as i32;
                        }
                        c2 = c0;
                        k = *bk.b(c2, c1) as isize;
                    }
                    debug_assert!(k < j);
                    sa[k] = s;
                    k -= 1;
                } else {
                    debug_assert!((s == 0 && tc(s) == c1) || s < 0);
                    sa[j] = !s;
                }
                j -= 1;
            }
            c1 -= 1;
        }
    }

    // Construct the suffix array by using the sorted order of the type B
    // suffixes.
    let mut c2 = tc(n - 1);
    let mut k = *bk.a(c2) as isize;
    sa[k] = if tc(n - 2) < c2 { !(n - 1) } else { n - 1 };
    k += 1;
    // Scan the suffix array from left to right.
    for i in 0..n as isize {
        let mut s = sa[i];
        if 0 < s {
            debug_assert!(tc(s - 1) >= tc(s));
            s -= 1;
            let c0 = tc(s);
            if s == 0 || tc(s - 1) < c0 {
                s = !s;
            }
            if c0 != c2 {
                *bk.a(c2) = k as i32;
                c2 = c0;
                k = *bk.a(c2) as isize;
            }
            debug_assert!(i < k);
            sa[k] = s;
            k += 1;
        } else {
            debug_assert!(s < 0);
            sa[i] = !s;
        }
    }
}

/// `divsufsort`: the suffix array of `t` into `sa[..t.len()]`: the start of
/// each suffix of `t`, from the smallest suffix to the largest.
///
/// Fails with `Generic` where libdivsufsort returns -1, for a text longer
/// than an `int` or a suffix array too short for it, and with
/// `MemoryAllocation` where it returns -2.
///
/// Differs from libzstd: no `openMP` argument, which without
/// `LIBBSC_OPENMP`, as libzstd builds it, does nothing; and the suffix array
/// is a slice, which may be longer than the text.
pub(crate) fn divsufsort(t: &[u8], sa: &mut [i32]) -> Result<()> {
    // Check the arguments.
    let Ok(n) = i32::try_from(t.len()) else {
        return error!(Generic);
    };
    let Some(sa) = sa.get_mut(..t.len()) else {
        return error!(Generic);
    };
    match n {
        0 => return Ok(()),
        1 => {
            sa[0] = 0;
            return Ok(());
        }
        2 => {
            let m = usize::from(t[0] < t[1]);
            sa[m ^ 1] = 0;
            sa[m] = 1;
            return Ok(());
        }
        _ => {}
    }

    let mut bucket_a = Vec::new();
    let mut bucket_b = Vec::new();
    if bucket_a.try_reserve_exact(BUCKET_A_SIZE).is_err()
        || bucket_b.try_reserve_exact(BUCKET_B_SIZE).is_err()
    {
        return error!(MemoryAllocation);
    }
    bucket_a.resize(BUCKET_A_SIZE, 0);
    bucket_b.resize(BUCKET_B_SIZE, 0);
    let mut buckets = Buckets {
        a: &mut bucket_a,
        b: &mut bucket_b,
    };

    // Suffixsort.
    let t = Text(t);
    let mut sa = Ints(sa);
    let m = sort_type_bstar(&t, &mut sa, &mut buckets, n);
    construct_sa(&t, &mut sa, &mut buckets, n, m);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zstd::oracle::Rng;

    /// The suffix array by sorting the suffixes as slices.
    fn naive(t: &[u8]) -> Vec<i32> {
        let mut sa: Vec<i32> = (0..t.len() as i32).collect();
        sa.sort_by(|&a, &b| t[a as usize..].cmp(&t[b as usize..]));
        sa
    }

    fn port(t: &[u8]) -> Vec<i32> {
        let mut sa = vec![0; t.len()];
        divsufsort(t, &mut sa).expect("sorted");
        sa
    }

    /// Texts that reach every part of the sort: tiny ones, runs, periods
    /// short and long, few symbols, random bytes, text, and repeats.
    fn texts(rng: &mut Rng, count: usize, max_len: u64) -> Vec<Vec<u8>> {
        let mut texts = vec![
            vec![],
            vec![7],
            vec![1, 2],
            vec![2, 1],
            vec![3, 3],
            b"banana".to_vec(),
            b"mississippi".to_vec(),
            b"abracadabra".to_vec(),
            (0..=255u8).collect(),
            (0..=255u8).rev().collect(),
            vec![0; 5000],
            vec![255; 3000],
        ];
        for i in 0..count {
            let len = rng.range(0, max_len) as usize;
            let text = match i % 8 {
                0 => rng.bytes(len),
                1 => {
                    let alphabet = rng.range(1, 4);
                    (0..len).map(|_| rng.range(0, alphabet - 1) as u8).collect()
                }
                2 => {
                    let period = rng.range(1, 40) as usize;
                    let unit = rng.bytes(period);
                    (0..len).map(|i| unit[i % period]).collect()
                }
                3 => rng.huffman_data(len),
                4 => rng.lz_data(len),
                5 => {
                    // Runs of one byte, of every length.
                    let mut text = Vec::new();
                    while text.len() < len {
                        let run = rng.range(1, 300) as usize;
                        let byte = rng.range(0, 3) as u8;
                        text.extend(std::iter::repeat_n(byte, run));
                    }
                    text.truncate(len);
                    text
                }
                6 => {
                    // A Fibonacci word: tandem repeats at every scale.
                    let (mut a, mut b) = (vec![b'a'], vec![b'a', b'b']);
                    while b.len() < len {
                        let next = [b.clone(), a].concat();
                        a = b;
                        b = next;
                    }
                    b.truncate(len);
                    b
                }
                _ => {
                    // One random block repeated with a few changes.
                    let block_len = rng.range(1, 2000) as usize;
                    let block = rng.bytes(block_len);
                    let mut text = Vec::new();
                    while text.len() < len {
                        text.extend_from_slice(&block);
                        if rng.range(0, 3) == 0 && !text.is_empty() {
                            let at = rng.range(0, text.len() as u64 - 1) as usize;
                            text[at] ^= 1;
                        }
                    }
                    text.truncate(len);
                    text
                }
            };
            texts.push(text);
        }
        texts
    }

    /// Whether `sa` is the suffix array of `t`, in linear time: a
    /// permutation in which each suffix is smaller than the next, by its
    /// first byte or, that byte equal, by the ranks of the suffixes after.
    pub(crate) fn is_suffix_array(t: &[u8], sa: &[i32]) -> bool {
        let n = t.len();
        if sa.len() != n {
            return false;
        }
        let mut rank = vec![usize::MAX; n + 1];
        for (k, &s) in sa.iter().enumerate() {
            let Ok(s) = usize::try_from(s) else {
                return false;
            };
            if s >= n || rank[s] != usize::MAX {
                return false;
            }
            rank[s] = k;
        }
        // The empty suffix comes before every other.
        rank[n] = 0;
        let after = |s: usize| if s + 1 == n { 0 } else { rank[s + 1] + 1 };
        sa.windows(2).all(|pair| {
            let (a, b) = (pair[0] as usize, pair[1] as usize);
            t[a] < t[b] || (t[a] == t[b] && after(a) < after(b))
        })
    }

    #[test]
    fn matches_naive_suffix_sort() {
        let mut rng = Rng::new(0xD155_0001);
        let count = if cfg!(debug_assertions) { 300 } else { 1500 };
        for text in texts(&mut rng, count, 1200) {
            assert_eq!(port(&text), naive(&text), "text of {} bytes", text.len());
        }
    }

    #[test]
    fn checker_refuses_wrong_arrays() {
        let t = b"mississippi";
        let mut sa = naive(t);
        assert!(is_suffix_array(t, &sa));
        sa.swap(3, 4);
        assert!(!is_suffix_array(t, &sa));
        sa.swap(3, 4);
        sa[0] = sa[1];
        assert!(!is_suffix_array(t, &sa));
        assert!(!is_suffix_array(t, &sa[1..]));
    }

    #[test]
    fn every_short_text_of_a_few_symbols() {
        // Every text of up to 9 bytes over {0, 1}, and up to 6 over {0, 1, 2}.
        for (symbols, longest) in [(2u32, 9u32), (3, 6)] {
            for len in 0..=longest {
                for code in 0..symbols.pow(len) {
                    let mut c = code;
                    let text: Vec<u8> = (0..len)
                        .map(|_| {
                            let b = (c % symbols) as u8;
                            c /= symbols;
                            b
                        })
                        .collect();
                    assert_eq!(port(&text), naive(&text), "{text:?}");
                }
            }
        }
    }

    #[test]
    fn larger_suffix_arrays_are_valid() {
        let mut rng = Rng::new(0xD155_0002);
        let (count, max_len) = if cfg!(debug_assertions) {
            (60, 40_000)
        } else {
            (400, 200_000)
        };
        for text in texts(&mut rng, count, max_len) {
            assert!(
                is_suffix_array(&text, &port(&text)),
                "text of {} bytes",
                text.len()
            );
        }
        // A few large ones.
        let len = if cfg!(debug_assertions) {
            100_000
        } else {
            1_500_000
        };
        let periodic: Vec<u8> = (0..len).map(|i| b"abcab"[i % 5]).collect();
        let runs: Vec<u8> = (0..len).map(|i| (i / 997 % 3) as u8).collect();
        for text in [
            rng.lz_data(len),
            rng.huffman_data(len),
            periodic,
            runs,
            vec![0; len],
        ] {
            assert!(is_suffix_array(&text, &port(&text)));
        }
    }

    #[test]
    fn refuses_a_short_suffix_array() {
        let mut sa = [0; 3];
        assert!(divsufsort(b"four", &mut sa).is_err());
        let mut sa = [9; 6];
        divsufsort(b"four", &mut sa).expect("sorted");
        assert_eq!(sa, [0, 1, 3, 2, 9, 9]);
    }

    /// The port's speed, the best of `HIVEPACK_DIVSUFSORT_RUNS` (5) runs
    /// over the first `HIVEPACK_DIVSUFSORT_LEN` bytes (4 MiB) of each file
    /// of `HIVEPACK_DIVSUFSORT_FILES` (comma-separated), in a release
    /// build: `cargo test -p hivepack --all-features --release divsufsort_speed --
    /// --ignored --nocapture`.
    #[test]
    #[ignore = "a measure, not a test"]
    fn divsufsort_speed() {
        let var = |name: &str, default: usize| {
            std::env::var(name)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        };
        let len = var("HIVEPACK_DIVSUFSORT_LEN", 4 << 20);
        let runs = var("HIVEPACK_DIVSUFSORT_RUNS", 5);
        let files = std::env::var("HIVEPACK_DIVSUFSORT_FILES").unwrap_or_default();
        for file in files.split(',').filter(|f| !f.is_empty()) {
            let mut text = std::fs::read(file).expect("the file");
            text.truncate(len);
            let mut sa = vec![0; text.len()];
            let mut best = f64::MAX;
            for _ in 0..runs {
                let start = std::time::Instant::now();
                divsufsort(&text, &mut sa).expect("sorted");
                best = best.min(start.elapsed().as_secs_f64());
            }
            eprintln!(
                "{file:60} {:8} bytes  {:7.1} ms  {:6.1} MB/s",
                text.len(),
                best * 1e3,
                text.len() as f64 / best / 1e6
            );
        }
    }
}
