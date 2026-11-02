//! Huffman trees and block output: port of `trees.{h,c}`.
//!
//! The deflate algorithm uses two Huffman trees per block: one for literal
//! bytes and match lengths, one for match distances, both sent before the
//! block in a compressed form that a third tree, for the code lengths,
//! encodes. Literals and matches are tallied as they are found
//! ([`DeflateState::tr_tally_lit`], [`DeflateState::tr_tally_dist`]); when
//! the symbol buffer is full or a flush is asked for,
//! [`DeflateState::tr_flush_block`] builds the trees and writes the block,
//! as a stored block, with the static trees, or with its own, whichever is
//! smallest.
//!
//! zlib's static tables (`trees.h`, which `trees.c` writes with
//! `GEN_TREES_H`) are computed while compiling, with the same functions
//! (`tr_static_init`); the tests compare them with `trees.h`.

use crate::deflate::deflate::{DeflateState, Pending, Z_FIXED};

/// `LENGTH_CODES`: number of length codes, not counting the special
/// END_BLOCK code.
pub(crate) const LENGTH_CODES: usize = 29;
/// `LITERALS`: number of literal bytes 0..255.
pub(crate) const LITERALS: usize = 256;
/// `L_CODES`: number of Literal or Length codes, including the END_BLOCK
/// code.
pub(crate) const L_CODES: usize = LITERALS + 1 + LENGTH_CODES;
/// `D_CODES`: number of distance codes.
pub(crate) const D_CODES: usize = 30;
/// `BL_CODES`: number of codes used to transfer the bit lengths.
pub(crate) const BL_CODES: usize = 19;
/// `HEAP_SIZE`: maximum heap size.
pub(crate) const HEAP_SIZE: usize = 2 * L_CODES + 1;
/// `MAX_BITS`: all codes must not exceed MAX_BITS bits.
pub(crate) const MAX_BITS: usize = 15;
/// `Buf_size`: size of bit buffer in bi_buf.
const BUF_SIZE: i32 = 16;
/// `MAX_BL_BITS`: bit length codes must not exceed MAX_BL_BITS bits.
const MAX_BL_BITS: u32 = 7;
/// `END_BLOCK`: end of block literal code.
const END_BLOCK: usize = 256;
/// `REP_3_6`: repeat previous bit length 3-6 times (2 bits of repeat
/// count).
const REP_3_6: usize = 16;
/// `REPZ_3_10`: repeat a zero length 3-10 times (3 bits of repeat count).
const REPZ_3_10: usize = 17;
/// `REPZ_11_138`: repeat a zero length 11-138 times (7 bits of repeat
/// count).
const REPZ_11_138: usize = 18;
/// The block types: `STORED_BLOCK`, `STATIC_TREES`, `DYN_TREES`.
const STORED_BLOCK: u32 = 0;
const STATIC_TREES: u32 = 1;
const DYN_TREES: u32 = 2;
/// `MIN_MATCH`, `MAX_MATCH`: the shortest and longest matches.
pub(crate) const MIN_MATCH: usize = 3;
pub(crate) const MAX_MATCH: usize = 258;
/// `DIST_CODE_LEN`: see the definition of `DIST_CODE` below.
const DIST_CODE_LEN: usize = 512;
/// The data types `detect_data_type` tells apart, as `strm->data_type`
/// holds them.
pub(crate) const Z_BINARY: i32 = 0;
pub(crate) const Z_TEXT: i32 = 1;
pub(crate) const Z_UNKNOWN: i32 = 2;

/// Extra bits for each length code.
static EXTRA_LBITS: [i32; LENGTH_CODES] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
/// Extra bits for each distance code.
static EXTRA_DBITS: [i32; D_CODES] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// Extra bits for each bit length code.
static EXTRA_BLBITS: [i32; BL_CODES] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7];
/// The lengths of the bit length codes are sent in order of decreasing
/// probability, to avoid transmitting the lengths for unused bit length
/// codes.
static BL_ORDER: [u8; BL_CODES] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// `ct_data`: a value and its code string. `fc` is the frequency count
/// (`Freq`) or the bit string (`Code`), `dl` the father node in the
/// Huffman tree (`Dad`) or the length of the bit string (`Len`).
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct CtData {
    pub fc: u16,
    pub dl: u16,
}

/// `static_tree_desc`.
pub(crate) struct StaticTreeDesc {
    /// static tree or None
    static_tree: Option<&'static [CtData]>,
    /// extra bits for each code
    extra_bits: &'static [i32],
    /// base index for extra_bits
    extra_base: usize,
    /// max number of elements in the tree
    elems: usize,
    /// max bit length for the codes
    max_length: u32,
}

/// `tree_desc`, without the pointer to the dynamic tree, which the code
/// that uses it passes along.
#[derive(Clone, Copy)]
pub(crate) struct TreeDesc {
    /// largest code with non zero frequency
    pub max_code: i32,
    /// the corresponding static tree
    pub stat_desc: &'static StaticTreeDesc,
}

/// The tables `tr_static_init` computes: port of `tr_static_init`,
/// `trees.c`, run while compiling.
struct StaticTables {
    static_ltree: [CtData; L_CODES + 2],
    static_dtree: [CtData; D_CODES],
    dist_code: [u8; DIST_CODE_LEN],
    length_code: [u8; MAX_MATCH - MIN_MATCH + 1],
    base_length: [i32; LENGTH_CODES],
    base_dist: [i32; D_CODES],
}

/// Reverses the first `len` bits of a code, using straightforward code
/// (a faster method would use a table). `1 <= len <= 15`.
///
/// Port of `bi_reverse`, `trees.c`.
const fn bi_reverse(mut code: u32, mut len: u32) -> u32 {
    let mut res = 0;
    loop {
        res |= code & 1;
        code >>= 1;
        res <<= 1;
        len -= 1;
        if len == 0 {
            break;
        }
    }
    res >> 1
}

const fn tr_static_init() -> StaticTables {
    let mut t = StaticTables {
        static_ltree: [CtData { fc: 0, dl: 0 }; L_CODES + 2],
        static_dtree: [CtData { fc: 0, dl: 0 }; D_CODES],
        dist_code: [0; DIST_CODE_LEN],
        length_code: [0; MAX_MATCH - MIN_MATCH + 1],
        base_length: [0; LENGTH_CODES],
        base_dist: [0; D_CODES],
    };

    // Initialize the mapping length (0..255) -> length code (0..28)
    let mut length = 0;
    let mut code = 0;
    while code < LENGTH_CODES - 1 {
        t.base_length[code] = length as i32;
        let mut n = 0;
        while n < (1 << EXTRA_LBITS[code]) {
            t.length_code[length] = code as u8;
            length += 1;
            n += 1;
        }
        code += 1;
    }
    // Note that the length 255 (match length 258) can be represented in two
    // different ways: code 284 + 5 bits or code 285, so we overwrite
    // length_code[255] to use the best encoding:
    t.length_code[length - 1] = code as u8;

    // Initialize the mapping dist (0..32K) -> dist code (0..29)
    let mut dist = 0;
    code = 0;
    while code < 16 {
        t.base_dist[code] = dist as i32;
        let mut n = 0;
        while n < (1 << EXTRA_DBITS[code]) {
            t.dist_code[dist] = code as u8;
            dist += 1;
            n += 1;
        }
        code += 1;
    }
    dist >>= 7; // from now on, all distances are divided by 128
    while code < D_CODES {
        t.base_dist[code] = (dist << 7) as i32;
        let mut n = 0;
        while n < (1 << (EXTRA_DBITS[code] - 7)) {
            t.dist_code[256 + dist] = code as u8;
            dist += 1;
            n += 1;
        }
        code += 1;
    }

    // Construct the codes of the static literal tree
    let mut bl_count = [0u16; MAX_BITS + 1];
    let mut n = 0;
    while n <= 287 {
        let len = if n <= 143 {
            8
        } else if n <= 255 {
            9
        } else if n <= 279 {
            7
        } else {
            8
        };
        t.static_ltree[n].dl = len;
        bl_count[len as usize] += 1;
        n += 1;
    }
    // Codes 286 and 287 do not exist, but we must include them in the tree
    // construction to get a canonical Huffman tree (longest code all ones)
    gen_codes_const(&mut t.static_ltree, L_CODES + 1, &bl_count);

    // The static distance tree is trivial:
    n = 0;
    while n < D_CODES {
        t.static_dtree[n].dl = 5;
        t.static_dtree[n].fc = bi_reverse(n as u32, 5) as u16;
        n += 1;
    }
    t
}

/// `gen_codes` for the static literal tree, while compiling.
const fn gen_codes_const(
    tree: &mut [CtData; L_CODES + 2],
    max_code: usize,
    bl_count: &[u16; MAX_BITS + 1],
) {
    let mut next_code = [0u16; MAX_BITS + 1];
    let mut code: u32 = 0;
    let mut bits = 1;
    while bits <= MAX_BITS {
        code = (code + bl_count[bits - 1] as u32) << 1;
        next_code[bits] = code as u16;
        bits += 1;
    }
    let mut n = 0;
    while n <= max_code {
        let len = tree[n].dl as usize;
        if len != 0 {
            tree[n].fc = bi_reverse(next_code[len] as u32, len as u32) as u16;
            next_code[len] += 1;
        }
        n += 1;
    }
}

const TABLES: StaticTables = tr_static_init();

/// `static_ltree`: the static literal tree. Since the bit lengths are
/// imposed, there is no need for the L_CODES extra codes used during heap
/// construction. However the codes 286 and 287 are needed to build a
/// canonical tree (see `_tr_init`).
pub(crate) static STATIC_LTREE: [CtData; L_CODES + 2] = TABLES.static_ltree;
/// `static_dtree`: the static distance tree. (Actually a trivial tree since
/// all codes use 5 bits.)
pub(crate) static STATIC_DTREE: [CtData; D_CODES] = TABLES.static_dtree;
/// `_dist_code`: distance codes. The first 256 values correspond to the
/// distances 3 .. 258, the last 256 values correspond to the top 8 bits of
/// the 15 bit distances.
pub(crate) static DIST_CODE: [u8; DIST_CODE_LEN] = TABLES.dist_code;
/// `_length_code`: length code for each normalized match length (0 ==
/// MIN_MATCH).
pub(crate) static LENGTH_CODE: [u8; MAX_MATCH - MIN_MATCH + 1] = TABLES.length_code;
/// `base_length`: first normalized length for each code (0 = MIN_MATCH).
static BASE_LENGTH: [i32; LENGTH_CODES] = TABLES.base_length;
/// `base_dist`: first normalized distance for each code (0 = distance of
/// 1).
static BASE_DIST: [i32; D_CODES] = TABLES.base_dist;

pub(crate) static STATIC_L_DESC: StaticTreeDesc = StaticTreeDesc {
    static_tree: Some(&STATIC_LTREE),
    extra_bits: &EXTRA_LBITS,
    extra_base: LITERALS + 1,
    elems: L_CODES,
    max_length: MAX_BITS as u32,
};
pub(crate) static STATIC_D_DESC: StaticTreeDesc = StaticTreeDesc {
    static_tree: Some(&STATIC_DTREE),
    extra_bits: &EXTRA_DBITS,
    extra_base: 0,
    elems: D_CODES,
    max_length: MAX_BITS as u32,
};
pub(crate) static STATIC_BL_DESC: StaticTreeDesc = StaticTreeDesc {
    static_tree: None,
    extra_bits: &EXTRA_BLBITS,
    extra_base: 0,
    elems: BL_CODES,
    max_length: MAX_BL_BITS,
};

/// `d_code`: mapping from a distance to a distance code. `dist` is the
/// distance - 1.
#[inline(always)]
pub(crate) fn d_code(dist: usize) -> usize {
    if dist < 256 {
        DIST_CODE[dist] as usize
    } else {
        DIST_CODE[256 + (dist >> 7)] as usize
    }
}

/// The working space of the tree builder: `heap`, `heap_len`, `heap_max`,
/// `depth` and `bl_count` of `deflate_state`, with the block lengths it
/// adds to.
///
/// Differs from zlib: gathered in one value, so that a tree, which is
/// another field of the state, and the space it is built in can be borrowed
/// at the same time.
#[derive(Clone)]
pub(crate) struct Heap {
    /// number of codes at each bit length for an optimal tree
    pub bl_count: [u16; MAX_BITS + 1],
    /// heap used to build the Huffman trees
    pub heap: [i32; 2 * L_CODES + 1],
    /// number of elements in the heap
    pub heap_len: i32,
    /// element of largest frequency
    pub heap_max: i32,
    /// Depth of each subtree used as tie breaker for trees of equal
    /// frequency
    pub depth: [u8; 2 * L_CODES + 1],
    /// bit length of current block with optimal trees
    pub opt_len: u64,
    /// bit length of current block with static trees
    pub static_len: u64,
}

impl Default for Heap {
    fn default() -> Heap {
        Heap {
            bl_count: [0; MAX_BITS + 1],
            heap: [0; 2 * L_CODES + 1],
            heap_len: 0,
            heap_max: 0,
            depth: [0; 2 * L_CODES + 1],
            opt_len: 0,
            static_len: 0,
        }
    }
}

/// `SMALLEST`: index within the heap array of least frequent node in the
/// Huffman tree.
const SMALLEST: usize = 1;

impl Heap {
    /// Compares two subtrees, using the tree depth as tie breaker when the
    /// subtrees have equal frequency. This minimizes the worst case length.
    ///
    /// Port of the macro `smaller`, `trees.c`.
    #[inline(always)]
    fn smaller(&self, tree: &[CtData], n: i32, m: i32) -> bool {
        let (n, m) = (n as usize, m as usize);
        tree[n].fc < tree[m].fc || (tree[n].fc == tree[m].fc && self.depth[n] <= self.depth[m])
    }

    /// Restores the heap property by moving down the tree starting at node
    /// k, exchanging a node with the smallest of its two sons if necessary,
    /// stopping when the heap property is re-established (each father
    /// smaller than its two sons).
    ///
    /// Port of `pqdownheap`, `trees.c`.
    fn pqdownheap(&mut self, tree: &[CtData], mut k: usize) {
        let v = self.heap[k];
        let mut j = k << 1; // left son of k
        while j as i32 <= self.heap_len {
            // Set j to the smallest of the two sons:
            if (j as i32) < self.heap_len && self.smaller(tree, self.heap[j + 1], self.heap[j]) {
                j += 1;
            }
            // Exit if v is smaller than both sons
            if self.smaller(tree, v, self.heap[j]) {
                break;
            }
            // Exchange v with the smallest son
            self.heap[k] = self.heap[j];
            k = j;
            // And continue down the tree, setting j to the left son of k
            j <<= 1;
        }
        self.heap[k] = v;
    }

    /// Removes the smallest element from the heap and recreates the heap
    /// with one less element.
    ///
    /// Port of the macro `pqremove`, `trees.c`.
    fn pqremove(&mut self, tree: &[CtData]) -> i32 {
        let top = self.heap[SMALLEST];
        self.heap[SMALLEST] = self.heap[self.heap_len as usize];
        self.heap_len -= 1;
        self.pqdownheap(tree, SMALLEST);
        top
    }

    /// Computes the optimal bit lengths for a tree and updates the total
    /// bit length for the current block. In: the fields freq and dad are
    /// set, heap[heap_max] and above are the tree nodes sorted by
    /// increasing frequency. Out: the field len is set to the optimal bit
    /// length, the array bl_count contains the frequencies for each bit
    /// length. The length opt_len is updated; static_len is also updated if
    /// stree is not null.
    ///
    /// Port of `gen_bitlen`, `trees.c`.
    fn gen_bitlen(&mut self, tree: &mut [CtData], desc: &TreeDesc) {
        let max_code = desc.max_code;
        let stree = desc.stat_desc.static_tree;
        let extra = desc.stat_desc.extra_bits;
        let base = desc.stat_desc.extra_base;
        let max_length = desc.stat_desc.max_length;
        let mut overflow = 0; // number of elements with bit length too large

        self.bl_count = [0; MAX_BITS + 1];

        // In a first pass, compute the optimal bit lengths (which may
        // overflow in the case of the bit length tree).
        tree[self.heap[self.heap_max as usize] as usize].dl = 0; // root of the heap

        let mut h = self.heap_max as usize + 1;
        while h < HEAP_SIZE {
            let n = self.heap[h] as usize;
            let mut bits = u32::from(tree[tree[n].dl as usize].dl) + 1;
            if bits > max_length {
                bits = max_length;
                overflow += 1;
            }
            tree[n].dl = bits as u16;
            // We overwrite tree[n].Dad which is no longer needed
            h += 1;
            if n as i32 > max_code {
                continue; // not a leaf node
            }

            self.bl_count[bits as usize] += 1;
            let xbits = if n >= base { extra[n - base] as u32 } else { 0 };
            let f = u64::from(tree[n].fc);
            // zlib's unsigned long wraps: build_tree() may have taken it
            // below zero.
            self.opt_len = self.opt_len.wrapping_add(f * u64::from(bits + xbits));
            if let Some(stree) = stree {
                self.static_len = self
                    .static_len
                    .wrapping_add(f * u64::from(u32::from(stree[n].dl) + xbits));
            }
        }
        if overflow == 0 {
            return;
        }

        // This happens for example on obj2 and pic of the Calgary corpus

        // Find the first bit length which could increase:
        loop {
            let mut bits = max_length as usize - 1;
            while self.bl_count[bits] == 0 {
                bits -= 1;
            }
            self.bl_count[bits] -= 1; // move one leaf down the tree
            self.bl_count[bits + 1] += 2; // move one overflow item as its brother
            self.bl_count[max_length as usize] -= 1;
            // The brother of the overflow item also moves one step up, but
            // this does not affect bl_count[max_length]
            overflow -= 2;
            if overflow <= 0 {
                break;
            }
        }

        // Now recompute all bit lengths, scanning in increasing frequency. h
        // is still equal to HEAP_SIZE. (It is simpler to reconstruct all
        // lengths instead of fixing only the wrong ones. This idea is taken
        // from 'ar' written by Haruhiko Okumura.)
        let mut bits = max_length;
        while bits != 0 {
            let mut n = self.bl_count[bits as usize];
            while n != 0 {
                h -= 1;
                let m = self.heap[h] as usize;
                if m as i32 > max_code {
                    continue;
                }
                if u32::from(tree[m].dl) != bits {
                    // zlib computes this in unsigned long, wrapping when
                    // the length goes down.
                    self.opt_len = self.opt_len.wrapping_add(
                        (u64::from(bits).wrapping_sub(u64::from(tree[m].dl)))
                            .wrapping_mul(u64::from(tree[m].fc)),
                    );
                    tree[m].dl = bits as u16;
                }
                n -= 1;
            }
            bits -= 1;
        }
    }

    /// Constructs one Huffman tree and assigns the code bit strings and
    /// lengths. Updates the total bit length for the current block. In: the
    /// field freq is set for all tree elements. Out: the fields len and code
    /// are set to the optimal bit length and corresponding code. The length
    /// opt_len is updated; static_len is also updated if stree is not null.
    /// The field max_code is set.
    ///
    /// Port of `build_tree`, `trees.c`.
    fn build_tree(&mut self, tree: &mut [CtData], desc: &mut TreeDesc) {
        let stree = desc.stat_desc.static_tree;
        let elems = desc.stat_desc.elems;
        let mut max_code: i32 = -1; // largest code with non zero frequency

        // Construct the initial heap, with least frequent element in
        // heap[SMALLEST]. The sons of heap[n] are heap[2*n] and heap[2*n + 1].
        // heap[0] is not used.
        self.heap_len = 0;
        self.heap_max = HEAP_SIZE as i32;

        for n in 0..elems {
            if tree[n].fc != 0 {
                self.heap_len += 1;
                max_code = n as i32;
                self.heap[self.heap_len as usize] = max_code;
                self.depth[n] = 0;
            } else {
                tree[n].dl = 0;
            }
        }

        // The pkzip format requires that at least one distance code exists,
        // and that at least one bit should be sent even if there is only one
        // possible code. So to avoid special checks later on we force at
        // least two codes of non zero frequency.
        while self.heap_len < 2 {
            let node = if max_code < 2 {
                max_code += 1;
                max_code
            } else {
                0
            };
            self.heap_len += 1;
            self.heap[self.heap_len as usize] = node;
            let node = node as usize;
            tree[node].fc = 1;
            self.depth[node] = 0;
            // zlib computes this in unsigned long, wrapping below zero.
            self.opt_len = self.opt_len.wrapping_sub(1);
            if let Some(stree) = stree {
                self.static_len = self.static_len.wrapping_sub(u64::from(stree[node].dl));
            }
            // node is 0 or 1 so it does not have extra bits
        }
        desc.max_code = max_code;

        // The elements heap[heap_len/2 + 1 .. heap_len] are leaves of the
        // tree, establish sub-heaps of increasing lengths:
        let mut n = self.heap_len / 2;
        while n >= 1 {
            self.pqdownheap(tree, n as usize);
            n -= 1;
        }

        // Construct the Huffman tree by repeatedly combining the least two
        // frequent nodes.
        let mut node = elems; // next internal node of the tree
        loop {
            let n = self.pqremove(tree) as usize; // n = node of least frequency
            let m = self.heap[SMALLEST] as usize; // m = node of next least frequency

            self.heap_max -= 1;
            self.heap[self.heap_max as usize] = n as i32; // keep the nodes sorted by frequency
            self.heap_max -= 1;
            self.heap[self.heap_max as usize] = m as i32;

            // Create a new node father of n and m
            tree[node].fc = tree[n].fc.wrapping_add(tree[m].fc);
            self.depth[node] = self.depth[n].max(self.depth[m]) + 1;
            tree[n].dl = node as u16;
            tree[m].dl = node as u16;

            // and insert the new node in the heap
            self.heap[SMALLEST] = node as i32;
            node += 1;
            self.pqdownheap(tree, SMALLEST);
            if self.heap_len < 2 {
                break;
            }
        }

        self.heap_max -= 1;
        self.heap[self.heap_max as usize] = self.heap[SMALLEST];

        // At this point, the fields freq and dad are set. We can now
        // generate the bit lengths.
        self.gen_bitlen(tree, desc);

        // The field len is now set, we can generate the bit codes
        gen_codes(tree, max_code, &self.bl_count);
    }
}

/// Generates the codes for a given tree and bit counts (which need not be
/// optimal). In: the array bl_count contains the bit length statistics for
/// the given tree and the field len is set for all tree elements. Out: the
/// field code is set for all tree elements of non zero code length.
///
/// Port of `gen_codes`, `trees.c`.
fn gen_codes(tree: &mut [CtData], max_code: i32, bl_count: &[u16; MAX_BITS + 1]) {
    let mut next_code = [0u16; MAX_BITS + 1]; // next code value for each bit length
    let mut code: u32 = 0; // running code value

    // The distribution counts are first used to generate the code values
    // without bit reversal.
    for bits in 1..=MAX_BITS {
        code = (code + u32::from(bl_count[bits - 1])) << 1;
        next_code[bits] = code as u16;
    }

    for n in 0..=max_code.max(-1) {
        let n = n as usize;
        let len = tree[n].dl as usize;
        if len == 0 {
            continue;
        }
        // Now reverse the bits
        tree[n].fc = bi_reverse(u32::from(next_code[len]), len as u32) as u16;
        next_code[len] = next_code[len].wrapping_add(1);
    }
}

impl Pending {
    /// `put_byte`: outputs a byte on the stream. There must be enough room
    /// in pending_buf.
    #[inline(always)]
    pub(crate) fn put_byte(&mut self, c: u8) {
        self.buf[self.pending] = c;
        self.pending += 1;
    }

    /// `put_short`: outputs a short LSB first on the stream.
    #[inline(always)]
    pub(crate) fn put_short(&mut self, w: u16) {
        self.put_byte(w as u8);
        self.put_byte((w >> 8) as u8);
    }

    /// Sends a value on a given number of bits. `length <= 16` and the
    /// value fits in length bits.
    ///
    /// Port of the macro `send_bits`, `trees.c`.
    ///
    /// Differs from zlib: the shifts are made on 32 bits, as C makes them
    /// once `ush` is promoted to `int`: `bi_valid` can be 16, and a 16-bit
    /// shift by 16 is not defined in Rust.
    #[inline(always)]
    pub(crate) fn send_bits(&mut self, value: i32, length: i32) {
        let val = u32::from(value as u16);
        if self.bi_valid > BUF_SIZE - length {
            self.bi_buf |= (val << self.bi_valid) as u16;
            self.put_short(self.bi_buf);
            self.bi_buf = (val >> (BUF_SIZE - self.bi_valid)) as u16;
            self.bi_valid += length - BUF_SIZE;
        } else {
            self.bi_buf |= (val << self.bi_valid) as u16;
            self.bi_valid += length;
        }
    }

    /// `send_code`: sends a code of the given tree.
    #[inline(always)]
    fn send_code(&mut self, c: usize, tree: &[CtData]) {
        self.send_bits(i32::from(tree[c].fc), i32::from(tree[c].dl));
    }

    /// Flushes the bit buffer, keeping at most 7 bits in it.
    ///
    /// Port of `bi_flush`, `trees.c`.
    pub(crate) fn bi_flush(&mut self) {
        if self.bi_valid == 16 {
            self.put_short(self.bi_buf);
            self.bi_buf = 0;
            self.bi_valid = 0;
        } else if self.bi_valid >= 8 {
            self.put_byte(self.bi_buf as u8);
            self.bi_buf >>= 8;
            self.bi_valid -= 8;
        }
    }

    /// Flushes the bit buffer and aligns the output on a byte boundary.
    ///
    /// Port of `bi_windup`, `trees.c`.
    pub(crate) fn bi_windup(&mut self) {
        if self.bi_valid > 8 {
            self.put_short(self.bi_buf);
        } else if self.bi_valid > 0 {
            self.put_byte(self.bi_buf as u8);
        }
        self.bi_used = ((self.bi_valid - 1) & 7) + 1;
        self.bi_buf = 0;
        self.bi_valid = 0;
    }

    /// Sends a literal or distance tree in compressed form, using the codes
    /// in bl_tree.
    ///
    /// Port of `send_tree`, `trees.c`.
    fn send_tree(&mut self, tree: &[CtData], max_code: i32, bl_tree: &[CtData]) {
        let mut prevlen: i32 = -1; // last emitted length
        let mut nextlen = i32::from(tree[0].dl); // length of next code
        let mut count = 0; // repeat count of the current code
        let mut max_count = 7; // max repeat count
        let mut min_count = 4; // min repeat count

        // tree[max_code + 1].Len = -1;  -- guard already set
        if nextlen == 0 {
            max_count = 138;
            min_count = 3;
        }

        for n in 0..=max_code as usize {
            let curlen = nextlen;
            nextlen = i32::from(tree[n + 1].dl);
            count += 1;
            if count < max_count && curlen == nextlen {
                continue;
            } else if count < min_count {
                loop {
                    self.send_code(curlen as usize, bl_tree);
                    count -= 1;
                    if count == 0 {
                        break;
                    }
                }
            } else if curlen != 0 {
                if curlen != prevlen {
                    self.send_code(curlen as usize, bl_tree);
                    count -= 1;
                }
                self.send_code(REP_3_6, bl_tree);
                self.send_bits(count - 3, 2);
            } else if count <= 10 {
                self.send_code(REPZ_3_10, bl_tree);
                self.send_bits(count - 3, 3);
            } else {
                self.send_code(REPZ_11_138, bl_tree);
                self.send_bits(count - 11, 7);
            }
            count = 0;
            prevlen = curlen;
            if nextlen == 0 {
                max_count = 138;
                min_count = 3;
            } else if curlen == nextlen {
                max_count = 6;
                min_count = 3;
            } else {
                max_count = 7;
                min_count = 4;
            }
        }
    }

    /// Sends the block data compressed using the given Huffman trees, from
    /// the symbols at `sym_buf..sym_buf + sym_next` of the same buffer.
    ///
    /// Port of `compress_block`, `trees.c`.
    fn compress_block(
        &mut self,
        sym_buf: usize,
        sym_next: usize,
        ltree: &[CtData],
        dtree: &[CtData],
    ) {
        let mut sx = 0; // running index in symbol buffers
        if sym_next != 0 {
            loop {
                let mut dist = usize::from(self.buf[sym_buf + sx]);
                dist += usize::from(self.buf[sym_buf + sx + 1]) << 8;
                let mut lc = i32::from(self.buf[sym_buf + sx + 2]);
                sx += 3;
                if dist == 0 {
                    self.send_code(lc as usize, ltree); // send a literal byte
                } else {
                    // Here, lc is the match length - MIN_MATCH
                    let code = usize::from(LENGTH_CODE[lc as usize]);
                    self.send_code(code + LITERALS + 1, ltree); // send length code
                    let extra = EXTRA_LBITS[code];
                    if extra != 0 {
                        lc -= BASE_LENGTH[code];
                        self.send_bits(lc, extra); // send the extra length bits
                    }
                    dist -= 1; // dist is now the match distance - 1
                    let code = d_code(dist);
                    self.send_code(code, dtree); // send the distance code
                    let extra = EXTRA_DBITS[code];
                    if extra != 0 {
                        let dist = dist as i32 - BASE_DIST[code];
                        self.send_bits(dist, extra); // send the extra bits
                    }
                } // literal or match pair ?
                if sx >= sym_next {
                    break;
                }
            }
        }
        self.send_code(END_BLOCK, ltree);
    }
}

impl DeflateState {
    /// Initializes a new block.
    ///
    /// Port of `init_block`, `trees.c`.
    fn init_block(&mut self) {
        // Initialize the trees.
        for n in 0..L_CODES {
            self.dyn_ltree[n].fc = 0;
        }
        for n in 0..D_CODES {
            self.dyn_dtree[n].fc = 0;
        }
        for n in 0..BL_CODES {
            self.bl_tree[n].fc = 0;
        }

        self.dyn_ltree[END_BLOCK].fc = 1;
        self.heap.opt_len = 0;
        self.heap.static_len = 0;
        self.sym_next = 0;
        self.matches = 0;
    }

    /// Initializes the tree data structures for a new zlib stream.
    ///
    /// Port of `_tr_init`, `trees.c`.
    pub(crate) fn tr_init(&mut self) {
        self.l_desc = TreeDesc {
            max_code: 0,
            stat_desc: &STATIC_L_DESC,
        };
        self.d_desc = TreeDesc {
            max_code: 0,
            stat_desc: &STATIC_D_DESC,
        };
        self.bl_desc = TreeDesc {
            max_code: 0,
            stat_desc: &STATIC_BL_DESC,
        };

        self.out.bi_buf = 0;
        self.out.bi_valid = 0;
        self.out.bi_used = 0;

        // Initialize the first block of the first file:
        self.init_block();
    }

    /// Scans a literal or distance tree to determine the frequencies of
    /// the codes in the bit length tree.
    ///
    /// Port of `scan_tree`, `trees.c`.
    fn scan_tree(tree: &mut [CtData], max_code: i32, bl_tree: &mut [CtData]) {
        let mut prevlen: i32 = -1; // last emitted length
        let mut nextlen = i32::from(tree[0].dl); // length of next code
        let mut count = 0; // repeat count of the current code
        let mut max_count = 7; // max repeat count
        let mut min_count = 4; // min repeat count

        if nextlen == 0 {
            max_count = 138;
            min_count = 3;
        }
        tree[(max_code + 1) as usize].dl = 0xffff; // guard

        for n in 0..=max_code as usize {
            let curlen = nextlen;
            nextlen = i32::from(tree[n + 1].dl);
            count += 1;
            if count < max_count && curlen == nextlen {
                continue;
            } else if count < min_count {
                bl_tree[curlen as usize].fc =
                    bl_tree[curlen as usize].fc.wrapping_add(count as u16);
            } else if curlen != 0 {
                if curlen != prevlen {
                    bl_tree[curlen as usize].fc = bl_tree[curlen as usize].fc.wrapping_add(1);
                }
                bl_tree[REP_3_6].fc = bl_tree[REP_3_6].fc.wrapping_add(1);
            } else if count <= 10 {
                bl_tree[REPZ_3_10].fc = bl_tree[REPZ_3_10].fc.wrapping_add(1);
            } else {
                bl_tree[REPZ_11_138].fc = bl_tree[REPZ_11_138].fc.wrapping_add(1);
            }
            count = 0;
            prevlen = curlen;
            if nextlen == 0 {
                max_count = 138;
                min_count = 3;
            } else if curlen == nextlen {
                max_count = 6;
                min_count = 3;
            } else {
                max_count = 7;
                min_count = 4;
            }
        }
    }

    /// Constructs the Huffman tree for the bit lengths and returns the
    /// index in bl_order of the last bit length code to send.
    ///
    /// Port of `build_bl_tree`, `trees.c`.
    fn build_bl_tree(&mut self) -> usize {
        // Determine the bit length frequencies for literal and distance trees
        DeflateState::scan_tree(&mut self.dyn_ltree, self.l_desc.max_code, &mut self.bl_tree);
        DeflateState::scan_tree(&mut self.dyn_dtree, self.d_desc.max_code, &mut self.bl_tree);

        // Build the bit length tree:
        self.heap.build_tree(&mut self.bl_tree, &mut self.bl_desc);
        // opt_len now includes the length of the tree representations,
        // except the lengths of the bit lengths codes and the 5 + 5 + 4 bits
        // for the counts.

        // Determine the number of bit length codes to send. The pkzip format
        // requires that at least 4 bit length codes be sent. (appnote.txt
        // says 3 but the actual value used is 4.)
        let mut max_blindex = BL_CODES - 1;
        while max_blindex >= 3 {
            if self.bl_tree[BL_ORDER[max_blindex] as usize].dl != 0 {
                break;
            }
            max_blindex -= 1;
        }
        // Update opt_len to include the bit length tree and counts
        self.heap.opt_len = self
            .heap
            .opt_len
            .wrapping_add(3 * (max_blindex as u64 + 1) + 5 + 5 + 4);
        max_blindex
    }

    /// Sends the header for a block using dynamic Huffman trees: the
    /// counts, the lengths of the bit length codes, the literal tree and the
    /// distance tree. `lcodes >= 257, dcodes >= 1, blcodes >= 4`.
    ///
    /// Port of `send_all_trees`, `trees.c`.
    fn send_all_trees(&mut self, lcodes: i32, dcodes: i32, blcodes: i32) {
        self.out.send_bits(lcodes - 257, 5); // not +255 as stated in appnote.txt
        self.out.send_bits(dcodes - 1, 5);
        self.out.send_bits(blcodes - 4, 4); // not -3 as stated in appnote.txt
        for rank in 0..blcodes as usize {
            self.out
                .send_bits(i32::from(self.bl_tree[BL_ORDER[rank] as usize].dl), 3);
        }
        self.out
            .send_tree(&self.dyn_ltree, lcodes - 1, &self.bl_tree); // literal tree
        self.out
            .send_tree(&self.dyn_dtree, dcodes - 1, &self.bl_tree); // distance tree
    }

    /// Sends a stored block of `stored_len` bytes from the window at `buf`,
    /// or none if `buf` is `None` (then `stored_len` is 0, or the caller
    /// writes the bytes itself).
    ///
    /// Port of `_tr_stored_block`, `trees.c`. Differs from zlib: the block
    /// is an offset into the window instead of a pointer.
    pub(crate) fn tr_stored_block(&mut self, buf: Option<usize>, stored_len: usize, last: bool) {
        self.out
            .send_bits(((STORED_BLOCK << 1) + u32::from(last)) as i32, 3); // send block type
        self.out.bi_windup(); // align on byte boundary
        self.out.put_short(stored_len as u16);
        self.out.put_short(!(stored_len as u16));
        if stored_len != 0
            && let Some(buf) = buf
        {
            let pending = self.out.pending;
            self.out.buf[pending..pending + stored_len]
                .copy_from_slice(&self.window[buf..buf + stored_len]);
        }
        self.out.pending += stored_len;
    }

    /// Flushes the bits in the bit buffer to pending output (leaves at most
    /// 7 bits).
    ///
    /// Port of `_tr_flush_bits`, `trees.c`.
    pub(crate) fn tr_flush_bits(&mut self) {
        self.out.bi_flush();
    }

    /// Sends one empty static block to give enough lookahead for inflate.
    /// This takes 10 bits, of which 7 may remain in the bit buffer.
    ///
    /// Port of `_tr_align`, `trees.c`.
    pub(crate) fn tr_align(&mut self) {
        self.out.send_bits((STATIC_TREES << 1) as i32, 3);
        self.out.send_code(END_BLOCK, &STATIC_LTREE);
        self.out.bi_flush();
    }

    /// Checks if the data type is TEXT or BINARY, using the following
    /// algorithm:
    /// - TEXT if the two conditions below are satisfied:
    ///   a) There are no non-portable control characters belonging to the
    ///   "block list" (0..6, 14..25, 28..31).
    ///   b) There is at least one printable character belonging to the
    ///   "allow list" (9 {TAB}, 10 {LF}, 13 {CR}, 32..255).
    /// - BINARY otherwise.
    /// - The following partially-portable control characters form a "gray
    ///   list" that is ignored in this detection algorithm: (7 {BEL}, 8
    ///   {BS}, 11 {VT}, 12 {FF}, 26 {SUB}, 27 {ESC}).
    ///
    /// The fields Freq of dyn_ltree must be set.
    ///
    /// Port of `detect_data_type`, `trees.c`.
    fn detect_data_type(&self) -> i32 {
        // block_mask is the bit mask of block-listed bytes set bits 0..6,
        // 14..25, and 28..31 0xf3ffc07f = binary
        // 11110011111111111100000001111111
        let mut block_mask: u32 = 0xf3ff_c07f;

        // Check for non-textual ("block-listed") bytes.
        for n in 0..=31 {
            if (block_mask & 1) != 0 && self.dyn_ltree[n].fc != 0 {
                return Z_BINARY;
            }
            block_mask >>= 1;
        }

        // Check for textual ("allow-listed") bytes.
        if self.dyn_ltree[9].fc != 0 || self.dyn_ltree[10].fc != 0 || self.dyn_ltree[13].fc != 0 {
            return Z_TEXT;
        }
        for n in 32..LITERALS {
            if self.dyn_ltree[n].fc != 0 {
                return Z_TEXT;
            }
        }

        // There are no "block-listed" or "allow-listed" bytes: this stream
        // either is empty or has tolerated ("gray-listed") bytes only.
        Z_BINARY
    }

    /// Determines the best encoding for the current block: dynamic trees,
    /// static trees or store, and writes out the encoded block. `buf` is
    /// where the block's bytes start in the window, if they are still
    /// there, and `data_type` is `strm->data_type`.
    ///
    /// Port of `_tr_flush_block`, `trees.c`.
    pub(crate) fn tr_flush_block(
        &mut self,
        buf: Option<usize>,
        stored_len: usize,
        last: bool,
        data_type: &mut i32,
    ) {
        let mut opt_lenb; // opt_len in bytes
        let static_lenb; // static_len in bytes
        let mut max_blindex = 0; // index of last bit length code of non zero freq

        // Build the Huffman trees unless a stored block is forced
        if self.level > 0 {
            // Check if the file is binary or text
            if *data_type == Z_UNKNOWN {
                *data_type = self.detect_data_type();
            }

            // Construct the literal and distance trees
            self.heap.build_tree(&mut self.dyn_ltree, &mut self.l_desc);
            self.heap.build_tree(&mut self.dyn_dtree, &mut self.d_desc);
            // At this point, opt_len and static_len are the total bit
            // lengths of the compressed block data, excluding the tree
            // representations.

            // Build the bit length tree for the above two trees, and get the
            // index in bl_order of the last bit length code to send.
            max_blindex = self.build_bl_tree();

            // Determine the best encoding. Compute the block lengths in
            // bytes.
            opt_lenb = self.heap.opt_len.wrapping_add(3 + 7) >> 3;
            static_lenb = self.heap.static_len.wrapping_add(3 + 7) >> 3;

            if static_lenb <= opt_lenb || self.strategy == Z_FIXED {
                opt_lenb = static_lenb;
            }
        } else {
            opt_lenb = stored_len as u64 + 5; // force a stored block
            static_lenb = opt_lenb;
        }

        if stored_len as u64 + 4 <= opt_lenb && buf.is_some() {
            // 4: two words for the lengths
            // The test buf != NULL is only necessary if LIT_BUFSIZE > WSIZE.
            // Otherwise we can't have processed more than WSIZE input bytes
            // since the last block flush, because compression would have
            // been successful. If LIT_BUFSIZE <= WSIZE, it is never too late
            // to transform a block into a stored block.
            self.tr_stored_block(buf, stored_len, last);
        } else if static_lenb == opt_lenb {
            self.out
                .send_bits(((STATIC_TREES << 1) + u32::from(last)) as i32, 3);
            self.out
                .compress_block(self.sym_buf, self.sym_next, &STATIC_LTREE, &STATIC_DTREE);
        } else {
            self.out
                .send_bits(((DYN_TREES << 1) + u32::from(last)) as i32, 3);
            self.send_all_trees(
                self.l_desc.max_code + 1,
                self.d_desc.max_code + 1,
                max_blindex as i32 + 1,
            );
            self.out.compress_block(
                self.sym_buf,
                self.sym_next,
                &self.dyn_ltree,
                &self.dyn_dtree,
            );
        }
        // The above check is made mod 2^32, for files larger than 512 MB and
        // uLong implemented on 32 bits.
        self.init_block();

        if last {
            self.out.bi_windup();
        }
    }

    /// `_tr_tally_lit`: saves a literal and tallies its frequency. Returns
    /// true if the current block must be flushed.
    #[inline(always)]
    pub(crate) fn tr_tally_lit(&mut self, c: u8) -> bool {
        let sym = self.sym_buf + self.sym_next;
        self.out.buf[sym] = 0;
        self.out.buf[sym + 1] = 0;
        self.out.buf[sym + 2] = c;
        self.sym_next += 3;
        self.dyn_ltree[c as usize].fc = self.dyn_ltree[c as usize].fc.wrapping_add(1);
        self.sym_next == self.sym_end
    }

    /// `_tr_tally_dist`: saves a match of `length` (less MIN_MATCH)
    /// `distance` back and tallies its frequency. Returns true if the
    /// current block must be flushed.
    #[inline(always)]
    pub(crate) fn tr_tally_dist(&mut self, distance: usize, length: usize) -> bool {
        let len = length as u8;
        let dist = distance as u16;
        let sym = self.sym_buf + self.sym_next;
        self.out.buf[sym] = dist as u8;
        self.out.buf[sym + 1] = (dist >> 8) as u8;
        self.out.buf[sym + 2] = len;
        self.sym_next += 3;
        let dist = usize::from(dist.wrapping_sub(1));
        let l = usize::from(LENGTH_CODE[len as usize]) + LITERALS + 1;
        self.dyn_ltree[l].fc = self.dyn_ltree[l].fc.wrapping_add(1);
        let d = d_code(dist);
        self.dyn_dtree[d].fc = self.dyn_dtree[d].fc.wrapping_add(1);
        self.sym_next == self.sym_end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `trees.h` from the zlib release, when `scripts/testdata.py` has
    /// fetched it.
    fn trees_h() -> Option<String> {
        let cache = std::env::var_os("HIVEPACK_TESTDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/testdata")
            });
        std::fs::read_to_string(cache.join("zlib-1.3.2-source/zlib-1.3.2/trees.h")).ok()
    }

    fn numbers(text: &str, table: &str) -> Vec<u32> {
        let start = text
            .find(table)
            .unwrap_or_else(|| panic!("{table} in trees.h"));
        let body = &text[start..];
        let body = &body[body.find('{').unwrap_or(0) + 1..body.find("};").unwrap_or(0)];
        body.split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .map(|s| s.parse().unwrap_or(0))
            .collect()
    }

    #[test]
    fn tables_match_trees_h() {
        // A few entries, everywhere.
        assert_eq!(STATIC_LTREE[0], CtData { fc: 12, dl: 8 });
        assert_eq!(STATIC_LTREE[144], CtData { fc: 19, dl: 9 });
        assert_eq!(STATIC_LTREE[287], CtData { fc: 227, dl: 8 });
        assert_eq!(STATIC_DTREE[1], CtData { fc: 16, dl: 5 });
        assert_eq!(BASE_DIST[29], 24576);
        // All of them, where the zlib sources were fetched.
        let Some(text) = trees_h() else {
            eprintln!("skipping the full comparison: the zlib sources are not fetched");
            return;
        };
        let ltree: Vec<u32> = STATIC_LTREE
            .iter()
            .flat_map(|c| [u32::from(c.fc), u32::from(c.dl)])
            .collect();
        assert_eq!(numbers(&text, "static_ltree"), ltree);
        let dtree: Vec<u32> = STATIC_DTREE
            .iter()
            .flat_map(|c| [u32::from(c.fc), u32::from(c.dl)])
            .collect();
        assert_eq!(numbers(&text, "static_dtree"), dtree);
        assert_eq!(
            numbers(&text, "_dist_code[DIST_CODE_LEN]"),
            DIST_CODE.iter().map(|&c| u32::from(c)).collect::<Vec<_>>()
        );
        assert_eq!(
            numbers(&text, "_length_code[MAX_MATCH-MIN_MATCH+1]"),
            LENGTH_CODE
                .iter()
                .map(|&c| u32::from(c))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            numbers(&text, "base_length[LENGTH_CODES]"),
            BASE_LENGTH.iter().map(|&c| c as u32).collect::<Vec<_>>()
        );
        assert_eq!(
            numbers(&text, "base_dist[D_CODES]"),
            BASE_DIST.iter().map(|&c| c as u32).collect::<Vec<_>>()
        );
    }
}
