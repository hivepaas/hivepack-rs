//! Lempel-Ziv match finding with binary trees: port of `bt_matchfinder.h`,
//! for the near-optimal compressor (levels 10 to 12).
//!
//! Each hash bucket of the first four bytes holds a binary tree of the
//! earlier positions with that hash, sorted by the bytes that follow them.
//! At each position the tree is searched and re-rooted at the new position
//! in one walk down it, which finds a match of each length at the smallest
//! offset it is at. A hash table of the first three bytes, two ways, gives
//! a match of length 3.
//!
//! The input is a slice and positions in it are indices, where libdeflate
//! has pointers; `in_base` is the index the positions in the tables are
//! relative to, and the links libdeflate writes through pointers into the
//! child table are indices of it.
//!
//! Differs from libdeflate: the next position's hash buckets are not
//! prefetched (`prefetchw`), which safe Rust cannot do; it changes nothing
//! but the speed.

use crate::deflate::libdeflate::common_defs::get_unaligned_le32;
use crate::deflate::libdeflate::matchfinder_common::{
    MATCHFINDER_INITVAL, MATCHFINDER_WINDOW_SIZE, MfPos, load_u24_unaligned, lz_extend, lz_hash,
    matchfinder_init, matchfinder_rebase,
};

/// `BT_MATCHFINDER_HASH3_ORDER`, `BT_MATCHFINDER_HASH3_WAYS`,
/// `BT_MATCHFINDER_HASH4_ORDER`.
const BT_MATCHFINDER_HASH3_ORDER: u32 = 16;
const BT_MATCHFINDER_HASH3_WAYS: usize = 2;
const BT_MATCHFINDER_HASH4_ORDER: u32 = 16;

const HASH3_SIZE: usize = 1 << BT_MATCHFINDER_HASH3_ORDER;
const HASH4_SIZE: usize = 1 << BT_MATCHFINDER_HASH4_ORDER;
const WINDOW_MASK: usize = MATCHFINDER_WINDOW_SIZE - 1;

/// `BT_MATCHFINDER_REQUIRED_NBYTES`: the least `max_len` for
/// `bt_matchfinder_get_matches` and `bt_matchfinder_skip_byte`. There must
/// be enough bytes left to load 32 bits from the *next* position.
pub(crate) const BT_MATCHFINDER_REQUIRED_NBYTES: u32 = 5;

/// `struct lz_match`: a match the binary trees found; in the compressor's
/// match cache, after the matches of a position, how many there are
/// (`length`) and the byte at the position (`offset`).
#[derive(Clone, Copy, Default)]
pub(crate) struct LzMatch {
    /// The number of bytes matched.
    pub(crate) length: u16,
    /// The offset back from the current position that was matched.
    pub(crate) offset: u16,
}

/// `struct bt_matchfinder`.
pub(crate) struct BtMatchfinder {
    /// The hash table for finding length 3 matches.
    hash3_tab: [[MfPos; BT_MATCHFINDER_HASH3_WAYS]; HASH3_SIZE],
    /// The hash table which contains the roots of the binary trees for
    /// finding length 4+ matches.
    hash4_tab: [MfPos; HASH4_SIZE],
    /// The child node references for the binary trees. The left and right
    /// children of the node for the sequence with position `pos` are
    /// `child_tab[pos * 2]` and `child_tab[pos * 2 + 1]`.
    child_tab: [MfPos; 2 * MATCHFINDER_WINDOW_SIZE],
}

/// `bt_left_child`: the index in `child_tab` of the left child of `node`.
#[inline(always)]
fn bt_left_child(node: i32) -> usize {
    2 * (node as usize & WINDOW_MASK)
}

/// `bt_right_child`: the index in `child_tab` of the right child of
/// `node`.
#[inline(always)]
fn bt_right_child(node: i32) -> usize {
    2 * (node as usize & WINDOW_MASK) + 1
}

impl BtMatchfinder {
    /// A match finder on the heap, ready for `bt_matchfinder_init`.
    pub(crate) fn new() -> Box<BtMatchfinder> {
        Box::new(BtMatchfinder {
            hash3_tab: [[0; BT_MATCHFINDER_HASH3_WAYS]; HASH3_SIZE],
            hash4_tab: [0; HASH4_SIZE],
            child_tab: [0; 2 * MATCHFINDER_WINDOW_SIZE],
        })
    }

    /// `bt_matchfinder_init`: prepare the matchfinder for a new input
    /// buffer. The children are left as they are: a position's are written
    /// when it goes into a tree, before they are read.
    pub(crate) fn init(&mut self) {
        matchfinder_init(self.hash3_tab.as_flattened_mut());
        matchfinder_init(&mut self.hash4_tab);
    }

    /// `bt_matchfinder_slide_window`.
    pub(crate) fn slide_window(&mut self) {
        matchfinder_rebase(self.hash3_tab.as_flattened_mut());
        matchfinder_rebase(&mut self.hash4_tab);
        matchfinder_rebase(&mut self.child_tab);
    }

    /// `bt_matchfinder_advance_one_byte`: advance the binary tree
    /// matchfinder by one byte, recording the matches in `matches` from
    /// `lz_matchptr` on if `RECORD_MATCHES`. Returns where the next match
    /// would go.
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    fn advance_one_byte<const RECORD_MATCHES: bool>(
        &mut self,
        data: &[u8],
        in_base: usize,
        cur_pos: usize,
        max_len: u32,
        nice_len: u32,
        max_search_depth: u32,
        next_hashes: &mut [u32; 2],
        matches: &mut [LzMatch],
        mut lz_matchptr: usize,
    ) -> usize {
        let in_next = in_base + cur_pos;
        let mut depth_remaining = max_search_depth;
        let cutoff = cur_pos as i32 - MATCHFINDER_WINDOW_SIZE as i32;
        let at = |node: i32| in_base.wrapping_add_signed(node as isize);
        let mut best_len: u32 = 3;

        let next_hashseq = get_unaligned_le32(data, in_next + 1);

        let hash3 = next_hashes[0] as usize & (HASH3_SIZE - 1);
        let hash4 = next_hashes[1] as usize & (HASH4_SIZE - 1);

        next_hashes[0] = lz_hash(next_hashseq & 0xFF_FFFF, BT_MATCHFINDER_HASH3_ORDER);
        next_hashes[1] = lz_hash(next_hashseq, BT_MATCHFINDER_HASH4_ORDER);

        let ways = &mut self.hash3_tab[hash3];
        let mut cur_node = i32::from(ways[0]);
        ways[0] = cur_pos as MfPos;
        let cur_node_2 = i32::from(ways[1]);
        ways[1] = cur_node as MfPos;
        if RECORD_MATCHES && cur_node > cutoff {
            let seq3 = load_u24_unaligned(data, in_next);
            if seq3 == load_u24_unaligned(data, at(cur_node)) {
                matches[lz_matchptr] = LzMatch {
                    length: 3,
                    offset: (in_next - at(cur_node)) as u16,
                };
                lz_matchptr += 1;
            } else if cur_node_2 > cutoff && seq3 == load_u24_unaligned(data, at(cur_node_2)) {
                matches[lz_matchptr] = LzMatch {
                    length: 3,
                    offset: (in_next - at(cur_node_2)) as u16,
                };
                lz_matchptr += 1;
            }
        }

        cur_node = i32::from(self.hash4_tab[hash4]);
        self.hash4_tab[hash4] = cur_pos as MfPos;

        let mut pending_lt_ptr = bt_left_child(cur_pos as i32);
        let mut pending_gt_ptr = bt_right_child(cur_pos as i32);

        if cur_node <= cutoff {
            self.child_tab[pending_lt_ptr] = MATCHFINDER_INITVAL;
            self.child_tab[pending_gt_ptr] = MATCHFINDER_INITVAL;
            return lz_matchptr;
        }

        let mut best_lt_len = 0;
        let mut best_gt_len = 0;
        let mut len: u32 = 0;
        // The bytes at the current position the match can take, and the
        // most of them a match's position can have before it.
        let max = max_len as usize;
        let cur = &data[in_next..in_next + max];

        loop {
            let matchptr = at(cur_node);
            let candidate = &data[matchptr..matchptr + max];

            if candidate[len as usize] == cur[len as usize] {
                len = lz_extend(data, in_next, matchptr, len + 1, max_len);
                if !RECORD_MATCHES || len > best_len {
                    if RECORD_MATCHES {
                        best_len = len;
                        matches[lz_matchptr] = LzMatch {
                            length: len as u16,
                            offset: (in_next - matchptr) as u16,
                        };
                        lz_matchptr += 1;
                    }
                    if len >= nice_len {
                        self.child_tab[pending_lt_ptr] = self.child_tab[bt_left_child(cur_node)];
                        self.child_tab[pending_gt_ptr] = self.child_tab[bt_right_child(cur_node)];
                        return lz_matchptr;
                    }
                }
            }

            if candidate[len as usize] < cur[len as usize] {
                self.child_tab[pending_lt_ptr] = cur_node as MfPos;
                pending_lt_ptr = bt_right_child(cur_node);
                cur_node = i32::from(self.child_tab[pending_lt_ptr]);
                best_lt_len = len;
                if best_gt_len < len {
                    len = best_gt_len;
                }
            } else {
                self.child_tab[pending_gt_ptr] = cur_node as MfPos;
                pending_gt_ptr = bt_left_child(cur_node);
                cur_node = i32::from(self.child_tab[pending_gt_ptr]);
                best_gt_len = len;
                if best_lt_len < len {
                    len = best_lt_len;
                }
            }

            depth_remaining -= 1;
            if cur_node <= cutoff || depth_remaining == 0 {
                self.child_tab[pending_lt_ptr] = MATCHFINDER_INITVAL;
                self.child_tab[pending_gt_ptr] = MATCHFINDER_INITVAL;
                return lz_matchptr;
            }
        }
    }

    /// `bt_matchfinder_get_matches`: the matches at `in_base + cur_pos`,
    /// written to `matches` from `lz_matchptr` on, by strictly increasing
    /// length and increasing offset. Returns where the next match would go.
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    pub(crate) fn get_matches(
        &mut self,
        data: &[u8],
        in_base: usize,
        cur_pos: usize,
        max_len: u32,
        nice_len: u32,
        max_search_depth: u32,
        next_hashes: &mut [u32; 2],
        matches: &mut [LzMatch],
        lz_matchptr: usize,
    ) -> usize {
        self.advance_one_byte::<true>(
            data,
            in_base,
            cur_pos,
            max_len,
            nice_len,
            max_search_depth,
            next_hashes,
            matches,
            lz_matchptr,
        )
    }

    /// `bt_matchfinder_skip_byte`: advance the matchfinder without
    /// recording any matches.
    #[inline(always)]
    pub(crate) fn skip_byte(
        &mut self,
        data: &[u8],
        in_base: usize,
        cur_pos: usize,
        nice_len: u32,
        max_search_depth: u32,
        next_hashes: &mut [u32; 2],
    ) {
        self.advance_one_byte::<false>(
            data,
            in_base,
            cur_pos,
            nice_len,
            nice_len,
            max_search_depth,
            next_hashes,
            &mut [],
            0,
        );
    }
}
