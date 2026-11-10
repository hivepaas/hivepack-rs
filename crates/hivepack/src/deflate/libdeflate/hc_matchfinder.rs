//! Lempel-Ziv match finding with a hash table of linked lists: port of
//! `hc_matchfinder.h`, for the greedy and lazy compressors (levels 2 to 9).
//!
//! A hash table of the first four bytes of each position heads a list of
//! the earlier positions with the same hash, most recent first; a second
//! table, of the first three bytes and without lists, gives one close match
//! of length 3. The search follows the list until it has looked at
//! `max_search_depth` positions or found a match of `nice_len`.
//!
//! The input is a slice and positions in it are indices, where libdeflate
//! has pointers; `in_base` is the index the positions in the tables are
//! relative to.
//!
//! Differs from libdeflate: the next position's hash buckets are not
//! prefetched (`prefetchw`), which safe Rust cannot do; it changes nothing
//! but the speed.

use crate::deflate::libdeflate::common_defs::get_unaligned_le32;
use crate::deflate::libdeflate::matchfinder_common::{
    MATCHFINDER_WINDOW_SIZE, MfPos, load_u24_unaligned, loaded_u32_to_u24, lz_extend, lz_hash,
    matchfinder_init, matchfinder_rebase,
};

/// `HC_MATCHFINDER_HASH3_ORDER`, `HC_MATCHFINDER_HASH4_ORDER`.
const HC_MATCHFINDER_HASH3_ORDER: u32 = 15;
const HC_MATCHFINDER_HASH4_ORDER: u32 = 16;

const HASH3_SIZE: usize = 1 << HC_MATCHFINDER_HASH3_ORDER;
const HASH4_SIZE: usize = 1 << HC_MATCHFINDER_HASH4_ORDER;
const WINDOW_MASK: usize = MATCHFINDER_WINDOW_SIZE - 1;

/// `struct hc_matchfinder`.
pub(crate) struct HcMatchfinder {
    /// The hash table for finding length 3 matches.
    hash3_tab: [MfPos; HASH3_SIZE],
    /// The hash table which contains the first nodes of the linked lists
    /// for finding length 4+ matches.
    hash4_tab: [MfPos; HASH4_SIZE],
    /// The "next node" references for the linked lists. The "next node"
    /// of the node for the sequence with position `pos` is
    /// `next_tab[pos]`.
    next_tab: [MfPos; MATCHFINDER_WINDOW_SIZE],
}

impl HcMatchfinder {
    /// A match finder on the heap, ready for `hc_matchfinder_init`.
    pub(crate) fn new() -> Box<HcMatchfinder> {
        Box::new(HcMatchfinder {
            hash3_tab: [0; HASH3_SIZE],
            hash4_tab: [0; HASH4_SIZE],
            next_tab: [0; MATCHFINDER_WINDOW_SIZE],
        })
    }

    /// `hc_matchfinder_init`: prepare the matchfinder for a new input
    /// buffer. The links are left as they are: a position's is written
    /// before it is read.
    pub(crate) fn init(&mut self) {
        matchfinder_init(&mut self.hash3_tab);
        matchfinder_init(&mut self.hash4_tab);
    }

    /// `hc_matchfinder_slide_window`.
    fn slide_window(&mut self) {
        matchfinder_rebase(&mut self.hash3_tab);
        matchfinder_rebase(&mut self.hash4_tab);
        matchfinder_rebase(&mut self.next_tab);
    }

    /// `hc_matchfinder_longest_match`: the longest match longer than
    /// `best_len` bytes at `in_next`, at most `max_len` long, the search
    /// stopping at a match of `nice_len` or after `max_search_depth`
    /// positions. `next_hashes` are the hashes at `in_next`, and become
    /// those at `in_next + 1`. Returns the match's length, or `best_len`
    /// if none is longer, and sets `offset_ret` to how far back it is.
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    pub(crate) fn longest_match(
        &mut self,
        data: &[u8],
        in_base_p: &mut usize,
        in_next: usize,
        mut best_len: u32,
        max_len: u32,
        nice_len: u32,
        max_search_depth: u32,
        next_hashes: &mut [u32; 2],
        offset_ret: &mut u32,
    ) -> u32 {
        let mut depth_remaining = max_search_depth;
        let mut best_matchptr = in_next;
        let mut cur_pos = in_next - *in_base_p;

        if cur_pos == MATCHFINDER_WINDOW_SIZE {
            self.slide_window();
            *in_base_p += MATCHFINDER_WINDOW_SIZE;
            cur_pos = 0;
        }

        let in_base = *in_base_p;
        let cutoff = (cur_pos as i32 - MATCHFINDER_WINDOW_SIZE as i32) as MfPos;
        // The input at a position of the tables, which is in the window.
        let at = |node: MfPos| in_base.wrapping_add_signed(node as isize);

        'out: {
            if max_len < 5 {
                // Can 4 bytes be read from `in_next + 1`?
                break 'out;
            }

            // Get the precomputed hash codes.
            let hash3 = next_hashes[0] as usize & (HASH3_SIZE - 1);
            let hash4 = next_hashes[1] as usize & (HASH4_SIZE - 1);

            // From the hash buckets, get the first node of each linked list.
            let cur_node3 = self.hash3_tab[hash3];
            let mut cur_node4 = self.hash4_tab[hash4];

            // Update for length 3 matches. This replaces the singleton node
            // in the 'hash3' bucket with the node for the current sequence.
            self.hash3_tab[hash3] = cur_pos as MfPos;

            // Update for length 4 matches. This prepends the node for the
            // current sequence to the linked list in the 'hash4' bucket.
            self.hash4_tab[hash4] = cur_pos as MfPos;
            self.next_tab[cur_pos & WINDOW_MASK] = cur_node4;

            // Compute the next hash codes.
            let next_hashseq = get_unaligned_le32(data, in_next + 1);
            next_hashes[0] = lz_hash(next_hashseq & 0xFF_FFFF, HC_MATCHFINDER_HASH3_ORDER);
            next_hashes[1] = lz_hash(next_hashseq, HC_MATCHFINDER_HASH4_ORDER);

            let seq4 = get_unaligned_le32(data, in_next);
            if best_len < 4 {
                // No match of length >= 4 found yet? Check for a length 3
                // match if needed.
                if cur_node3 <= cutoff {
                    break 'out;
                }
                if best_len < 3 {
                    let matchptr = at(cur_node3);
                    if load_u24_unaligned(data, matchptr) == loaded_u32_to_u24(seq4) {
                        best_len = 3;
                        best_matchptr = matchptr;
                    }
                }

                // Check for a length 4 match.
                if cur_node4 <= cutoff {
                    break 'out;
                }
                let mut matchptr;
                loop {
                    // No length 4 match found yet. Check the first 4 bytes.
                    matchptr = at(cur_node4);
                    if get_unaligned_le32(data, matchptr) == seq4 {
                        break;
                    }
                    // The first 4 bytes did not match. Keep trying.
                    cur_node4 = self.next_tab[cur_node4 as usize & WINDOW_MASK];
                    depth_remaining -= 1;
                    if cur_node4 <= cutoff || depth_remaining == 0 {
                        break 'out;
                    }
                }

                // Found a match of length >= 4. Extend it to its full
                // length.
                best_matchptr = matchptr;
                best_len = lz_extend(data, in_next, best_matchptr, 4, max_len);
                if best_len >= nice_len {
                    break 'out;
                }
                cur_node4 = self.next_tab[cur_node4 as usize & WINDOW_MASK];
                depth_remaining -= 1;
                if cur_node4 <= cutoff || depth_remaining == 0 {
                    break 'out;
                }
            } else if cur_node4 <= cutoff || best_len >= nice_len {
                break 'out;
            }

            // Check for matches of length >= 5.
            loop {
                let mut matchptr;
                loop {
                    matchptr = at(cur_node4);
                    // Already found a length 4 match. Try for a longer
                    // match; start by checking the last 4 bytes and the
                    // first 4 bytes. (The last byte, the one which would
                    // extend the match length by 1, is the most important.)
                    let tail = (best_len - 3) as usize;
                    if get_unaligned_le32(data, matchptr + tail)
                        == get_unaligned_le32(data, in_next + tail)
                        && get_unaligned_le32(data, matchptr) == seq4
                    {
                        break;
                    }
                    // Continue to the next node in the list.
                    cur_node4 = self.next_tab[cur_node4 as usize & WINDOW_MASK];
                    depth_remaining -= 1;
                    if cur_node4 <= cutoff || depth_remaining == 0 {
                        break 'out;
                    }
                }

                let len = lz_extend(data, in_next, matchptr, 4, max_len);
                if len > best_len {
                    // This is the new longest match.
                    best_len = len;
                    best_matchptr = matchptr;
                    if best_len >= nice_len {
                        break 'out;
                    }
                }

                // Continue to the next node in the list.
                cur_node4 = self.next_tab[cur_node4 as usize & WINDOW_MASK];
                depth_remaining -= 1;
                if cur_node4 <= cutoff || depth_remaining == 0 {
                    break 'out;
                }
            }
        }
        *offset_ret = (in_next - best_matchptr) as u32;
        best_len
    }

    /// `hc_matchfinder_skip_bytes`: advance the matchfinder by `count`
    /// bytes, which is not 0, without searching for matches.
    /// `next_hashes` are the hashes at `in_next`, and become those at
    /// `in_next + count`.
    #[inline(always)]
    pub(crate) fn skip_bytes(
        &mut self,
        data: &[u8],
        in_base_p: &mut usize,
        mut in_next: usize,
        in_end: usize,
        count: u32,
        next_hashes: &mut [u32; 2],
    ) {
        let mut remaining = count;

        if count as usize + 5 > in_end - in_next {
            return;
        }

        let mut cur_pos = in_next - *in_base_p;
        let mut hash3 = next_hashes[0] as usize & (HASH3_SIZE - 1);
        let mut hash4 = next_hashes[1] as usize & (HASH4_SIZE - 1);
        loop {
            if cur_pos == MATCHFINDER_WINDOW_SIZE {
                self.slide_window();
                *in_base_p += MATCHFINDER_WINDOW_SIZE;
                cur_pos = 0;
            }
            self.hash3_tab[hash3] = cur_pos as MfPos;
            self.next_tab[cur_pos & WINDOW_MASK] = self.hash4_tab[hash4];
            self.hash4_tab[hash4] = cur_pos as MfPos;

            in_next += 1;
            let next_hashseq = get_unaligned_le32(data, in_next);
            hash3 = lz_hash(next_hashseq & 0xFF_FFFF, HC_MATCHFINDER_HASH3_ORDER) as usize;
            hash4 = lz_hash(next_hashseq, HC_MATCHFINDER_HASH4_ORDER) as usize;
            cur_pos += 1;
            remaining -= 1;
            if remaining == 0 {
                break;
            }
        }
        next_hashes[0] = hash3 as u32;
        next_hashes[1] = hash4 as u32;
    }
}
