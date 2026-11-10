//! Lempel-Ziv match finding with a hash table of buckets: port of
//! `ht_matchfinder.h`, for the fastest compressor (level 1).
//!
//! A variant of the hash chains (`hc_matchfinder.rs`) for speed: each hash
//! bucket keeps the last two positions with its hash, in the table itself,
//! and matches are of four bytes or more.
//!
//! Differs from libdeflate: the next position's hash buckets are not
//! prefetched (`prefetchw`), which safe Rust cannot do; it changes nothing
//! but the speed.

use crate::deflate::libdeflate::common_defs::get_unaligned_le32;
use crate::deflate::libdeflate::matchfinder_common::{
    MATCHFINDER_WINDOW_SIZE, MfPos, lz_extend, lz_hash, matchfinder_init, matchfinder_rebase,
};

/// `HT_MATCHFINDER_HASH_ORDER`, `HT_MATCHFINDER_BUCKET_SIZE`.
const HT_MATCHFINDER_HASH_ORDER: u32 = 15;
const HT_MATCHFINDER_BUCKET_SIZE: usize = 2;

/// `HT_MATCHFINDER_MIN_MATCH_LEN`.
pub(crate) const HT_MATCHFINDER_MIN_MATCH_LEN: u32 = 4;
/// `HT_MATCHFINDER_REQUIRED_NBYTES`: the least `max_len` for
/// `ht_matchfinder_longest_match`.
pub(crate) const HT_MATCHFINDER_REQUIRED_NBYTES: u32 = 5;

const HASH_SIZE: usize = 1 << HT_MATCHFINDER_HASH_ORDER;

/// `struct ht_matchfinder`.
pub(crate) struct HtMatchfinder {
    hash_tab: [[MfPos; HT_MATCHFINDER_BUCKET_SIZE]; HASH_SIZE],
}

impl HtMatchfinder {
    /// A match finder on the heap, ready for `ht_matchfinder_init`.
    pub(crate) fn new() -> Box<HtMatchfinder> {
        Box::new(HtMatchfinder {
            hash_tab: [[0; HT_MATCHFINDER_BUCKET_SIZE]; HASH_SIZE],
        })
    }

    /// `ht_matchfinder_init`.
    pub(crate) fn init(&mut self) {
        matchfinder_init(self.hash_tab.as_flattened_mut());
    }

    /// `ht_matchfinder_slide_window`.
    fn slide_window(&mut self) {
        matchfinder_rebase(self.hash_tab.as_flattened_mut());
    }

    /// `ht_matchfinder_longest_match`, with `HT_MATCHFINDER_BUCKET_SIZE`
    /// 2: the longest match at `in_next`, of four bytes or more and at most
    /// `max_len`, which is `HT_MATCHFINDER_REQUIRED_NBYTES` or more.
    /// `next_hash` is the hash at `in_next`, and becomes the one at
    /// `in_next + 1`. Returns the match's length, or 0, and sets
    /// `offset_ret` to how far back it is.
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    pub(crate) fn longest_match(
        &mut self,
        data: &[u8],
        in_base_p: &mut usize,
        in_next: usize,
        max_len: u32,
        nice_len: u32,
        next_hash: &mut u32,
        offset_ret: &mut u32,
    ) -> u32 {
        let mut best_len = 0;
        let mut best_matchptr = in_next;
        let mut cur_pos = in_next - *in_base_p;

        if cur_pos == MATCHFINDER_WINDOW_SIZE {
            self.slide_window();
            *in_base_p += MATCHFINDER_WINDOW_SIZE;
            cur_pos = 0;
        }
        let in_base = *in_base_p;
        let cutoff = (cur_pos as i32 - MATCHFINDER_WINDOW_SIZE as i32) as MfPos;
        let at = |node: MfPos| in_base.wrapping_add_signed(node as isize);

        let hash = *next_hash as usize & (HASH_SIZE - 1);
        *next_hash = lz_hash(
            get_unaligned_le32(data, in_next + 1),
            HT_MATCHFINDER_HASH_ORDER,
        );
        let seq = get_unaligned_le32(data, in_next);

        // Hand-unrolled version for BUCKET_SIZE == 2. The logic here also
        // differs slightly in that it copies the first entry to the second
        // even if nice_len is reached on the first, as this can be slightly
        // faster.
        'out: {
            let bucket = &mut self.hash_tab[hash];
            let mut cur_node = bucket[0];
            bucket[0] = cur_pos as MfPos;
            if cur_node <= cutoff {
                break 'out;
            }
            let mut matchptr = at(cur_node);

            // The first entry goes to the second, whose entry is the next
            // to look at (`to_insert`).
            std::mem::swap(&mut cur_node, &mut bucket[1]);

            if get_unaligned_le32(data, matchptr) == seq {
                best_len = lz_extend(data, in_next, matchptr, 4, max_len);
                best_matchptr = matchptr;
                if cur_node <= cutoff || best_len >= nice_len {
                    break 'out;
                }
                matchptr = at(cur_node);
                let tail = (best_len - 3) as usize;
                if get_unaligned_le32(data, matchptr) == seq
                    && get_unaligned_le32(data, matchptr + tail)
                        == get_unaligned_le32(data, in_next + tail)
                {
                    let len = lz_extend(data, in_next, matchptr, 4, max_len);
                    if len > best_len {
                        best_len = len;
                        best_matchptr = matchptr;
                    }
                }
            } else {
                if cur_node <= cutoff {
                    break 'out;
                }
                matchptr = at(cur_node);
                if get_unaligned_le32(data, matchptr) == seq {
                    best_len = lz_extend(data, in_next, matchptr, 4, max_len);
                    best_matchptr = matchptr;
                }
            }
        }
        *offset_ret = (in_next - best_matchptr) as u32;
        best_len
    }

    /// `ht_matchfinder_skip_bytes`: advance the matchfinder by `count`
    /// bytes, which is not 0, without searching for matches.
    #[inline(always)]
    pub(crate) fn skip_bytes(
        &mut self,
        data: &[u8],
        in_base_p: &mut usize,
        mut in_next: usize,
        in_end: usize,
        count: u32,
        next_hash: &mut u32,
    ) {
        let mut cur_pos = (in_next - *in_base_p) as i32;
        let mut remaining = count;

        if count as usize + HT_MATCHFINDER_REQUIRED_NBYTES as usize > in_end - in_next {
            return;
        }

        // `cur_pos + count - 1 >= MATCHFINDER_WINDOW_SIZE`, count being 1 or more.
        if cur_pos as usize + count as usize > MATCHFINDER_WINDOW_SIZE {
            self.slide_window();
            *in_base_p += MATCHFINDER_WINDOW_SIZE;
            cur_pos -= MATCHFINDER_WINDOW_SIZE as i32;
        }

        let mut hash = *next_hash as usize & (HASH_SIZE - 1);
        loop {
            let bucket = &mut self.hash_tab[hash];
            bucket[1] = bucket[0];
            bucket[0] = cur_pos as MfPos;

            in_next += 1;
            hash = lz_hash(get_unaligned_le32(data, in_next), HT_MATCHFINDER_HASH_ORDER) as usize;
            cur_pos += 1;
            remaining -= 1;
            if remaining == 0 {
                break;
            }
        }
        *next_hash = hash as u32;
    }
}
