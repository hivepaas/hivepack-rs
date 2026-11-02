//! The LZ-based encoder: the sliding window and the match finders. Port of
//! `lz/lz_encoder.{h,c}`, `lz/lz_encoder_hash.h` and `lz/lz_encoder_mf.c`.
//!
//! Basic steps:
//!  1. Input gets copied into the dictionary.
//!  2. Data in dictionary gets run through the match finder byte by byte.
//!  3. The literals and matches are encoded using e.g. LZMA.
//!
//! The bytes that have been ran through the match finder, but not encoded
//! yet, are called 'read ahead'.

use crate::xz::common::{Action, NextCoder, Ret, bufcpy};
use crate::xz::filter::{FILTER_LZMA1, FILTER_LZMA1EXT, FILTER_LZMA2};
use crate::xz::lzma_common::{DICT_SIZE_MIN, LzmaOptions, MatchFinder};
use crate::xz::lzma_encoder::LzmaEncoder;
use crate::xz::lzma2_encoder::Lzma2Encoder;

/// `IS_ENC_DICT_SIZE_VALID`: for now, the dictionary size is limited to
/// 1.5 GiB.
pub(crate) fn is_enc_dict_size_valid(size: u32) -> bool {
    (DICT_SIZE_MIN..=(1 << 30) + (1 << 29)).contains(&size)
}

/// `lzma_match`: a length-distance pair found by the match finder.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Match {
    pub(crate) len: u32,
    pub(crate) dist: u32,
}

// lz_encoder_hash.h: the hash of the first bytes, with the CRC32 table.

/// `lzma_lz_hash_table`: the CRC32 table, as liblzma's tables generator
/// writes it, little endian so that the output doesn't depend on the
/// processor.
static HASH_TABLE: [u32; 256] = hash_table();

const fn hash_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut b = 0;
    while b < 256 {
        let mut r = b as u32;
        let mut j = 0;
        while j < 8 {
            r = if r & 1 != 0 {
                (r >> 1) ^ 0xEDB8_8320
            } else {
                r >> 1
            };
            j += 1;
        }
        table[b] = r;
        b += 1;
    }
    table
}
const HASH_2_SIZE: u32 = 1 << 10;
const HASH_3_SIZE: u32 = 1 << 16;
const HASH_2_MASK: u32 = HASH_2_SIZE - 1;
const HASH_3_MASK: u32 = HASH_3_SIZE - 1;
const FIX_3_HASH_SIZE: u32 = HASH_2_SIZE;
const FIX_4_HASH_SIZE: u32 = HASH_2_SIZE + HASH_3_SIZE;

/// Hash value to indicate unused element in the hash. Since we start the
/// positions from dict_size + 1, zero is always too far to qualify as
/// usable match position.
const EMPTY_HASH_VALUE: u32 = 0;

/// Normalization must be done when lzma_mf.offset + lzma_mf.read_pos
/// reaches MUST_NORMALIZE_POS.
const MUST_NORMALIZE_POS: u32 = u32::MAX;

/// `mf_get_hash_bytes`: how many bytes the match finder hashes in its
/// initial step. This is also the minimum nice_len value with the match
/// finder.
pub(crate) fn mf_get_hash_bytes(match_finder: MatchFinder) -> u32 {
    match_finder.0 & 0x0F
}

/// `lzma_memcmplen`: the length of the common prefix of `buf[a..]` and
/// `buf[b..]`, from `len` (already known to match) up to `limit`.
///
/// Differs from liblzma, without a difference to see: liblzma compares
/// words, reading up to LZMA_MEMCMPLEN_EXTRA bytes past the limit, which it
/// ignores; this compares eight bytes at a time within the limit.
#[inline(always)]
fn memcmplen(buf: &[u8], a: usize, b: usize, mut len: u32, limit: u32) -> u32 {
    let limit = limit as usize;
    let (x, y) = (&buf[a..a + limit], &buf[b..b + limit]);
    let mut i = len as usize;
    while i + 8 <= limit {
        let (Some(p), Some(q)) = (x[i..].first_chunk::<8>(), y[i..].first_chunk::<8>()) else {
            break;
        };
        let diff = u64::from_le_bytes(*p) ^ u64::from_le_bytes(*q);
        if diff != 0 {
            return (i + (diff.trailing_zeros() / 8) as usize) as u32;
        }
        i += 8;
    }
    while i < limit && x[i] == y[i] {
        i += 1;
    }
    len = i as u32;
    len
}

/// `lzma_lz_options` of the encoders.
#[derive(Clone, Debug, Default)]
pub(crate) struct LzEncOptions {
    /// Extra amount of data to keep available before the "actual"
    /// dictionary.
    pub(crate) before_size: u32,
    /// Size of the history buffer
    pub(crate) dict_size: u32,
    /// Extra amount of data to keep available after the "actual"
    /// dictionary.
    pub(crate) after_size: u32,
    /// Maximum length of a match that the LZ-based encoder can accept.
    /// This is used to extend matches of length nice_len to the maximum
    /// possible length.
    pub(crate) match_len_max: u32,
    /// Match finder will search matches up to this length. This must be
    /// less than or equal to match_len_max.
    pub(crate) nice_len: u32,
    /// Type of the match finder to use
    pub(crate) match_finder: MatchFinder,
    /// Maximum search depth
    pub(crate) depth: u32,
    /// Initial dictionary for the match finder to search.
    pub(crate) preset_dict: Option<Vec<u8>>,
}

/// `lzma_mf`: the history buffer and the match finder.
#[derive(Debug, Default)]
pub(crate) struct Mf {
    // In Window
    /// The buffer with data to be compressed.
    ///
    /// Differs from liblzma, without a difference to see: liblzma
    /// allocates it at its full size, uninitialised; its length here grows
    /// as data is written to it, up to `size`, and nothing is read
    /// past what was written.
    pub(crate) buffer: Vec<u8>,
    /// Total size of the allocated buffer (that is, including all the
    /// extra space)
    pub(crate) size: u32,
    /// Number of bytes that must be kept available in our input history.
    /// That is, once keep_size_before bytes have been processed,
    /// buffer[read_pos - keep_size_before] is the oldest byte that must
    /// be available for reading.
    pub(crate) keep_size_before: u32,
    /// Number of bytes that must be kept in buffer after read_pos. That
    /// is, read_pos <= write_pos - keep_size_after as long as action is
    /// LZMA_RUN; when action != LZMA_RUN, read_pos is allowed to reach
    /// write_pos so that the last bytes get encoded too.
    pub(crate) keep_size_after: u32,
    /// Match finders store locations of matches using 32-bit integers.
    /// To avoid adjusting several megabytes of integers every time the
    /// input window is moved with move_window, we only adjust the offset
    /// of the buffer. Thus, buffer[value_in_hash_table - offset] is the
    /// byte pointed by value_in_hash_table.
    pub(crate) offset: u32,
    /// buffer[read_pos] is the next byte to run through the match finder.
    /// This is incremented in the match finder once the byte has been
    /// processed.
    pub(crate) read_pos: u32,
    /// Number of bytes that have been ran through the match finder, but
    /// which haven't been encoded by the LZ-based encoder yet.
    pub(crate) read_ahead: u32,
    /// As long as read_pos is less than read_limit, there is enough input
    /// available in buffer for at least one encoding loop.
    ///
    /// Because of the stateful API, read_limit may and will get greater
    /// than read_pos quite often. This is taken into account when
    /// calculating the value for keep_size_after.
    pub(crate) read_limit: u32,
    /// buffer[write_pos] is the first byte that doesn't contain valid
    /// uncompressed data; that is, the next input byte will be copied to
    /// buffer[write_pos].
    pub(crate) write_pos: u32,
    /// Number of bytes not hashed before read_pos. This is needed to
    /// restart the match finder after LZMA_SYNC_FLUSH.
    pub(crate) pending: u32,

    // Match Finder
    /// The match finder: `find` and `skip`.
    match_finder: MatchFinder,
    hash: Vec<u32>,
    /// Differs from liblzma, without a difference to see: liblzma leaves
    /// it uninitialised; its length here grows with cyclic_pos, and the
    /// match finders read only what they wrote.
    son: Vec<u32>,
    cyclic_pos: u32,
    /// Must be dictionary size + 1.
    cyclic_size: u32,
    hash_mask: u32,
    /// Maximum number of loops in the match finder
    depth: u32,
    /// Maximum length of a match that the match finder will try to find.
    pub(crate) nice_len: u32,
    /// Maximum length of a match supported by the LZ-based encoder. If
    /// the longest match found by the match finder is nice_len,
    /// mf_find() tries to expand it up to match_len_max bytes.
    pub(crate) match_len_max: u32,
    /// When running out of input, binary tree match finders need to know
    /// if it is due to flushing or finishing. The action is used also by
    /// the LZ-based encoders themselves.
    pub(crate) action: Action,
    /// Number of elements in hash[]
    hash_count: u32,
    /// Number of elements in son[]
    sons_count: u32,
}

impl Mf {
    /// `mf_ptr`: the index of the first byte not ran through the match
    /// finder.
    #[inline(always)]
    pub(crate) fn ptr(&self) -> usize {
        self.read_pos as usize
    }

    /// `mf_avail`: the number of bytes that haven't been ran through the
    /// match finder yet.
    #[inline(always)]
    pub(crate) fn avail(&self) -> u32 {
        self.write_pos - self.read_pos
    }

    /// `mf_unencoded`: the number of bytes that haven't been encoded yet
    /// (some of these bytes may have been ran through the match finder
    /// though).
    #[inline(always)]
    pub(crate) fn unencoded(&self) -> u32 {
        self.write_pos - self.read_pos + self.read_ahead
    }

    /// `mf_skip`: skips the given number of bytes. This is used when a
    /// good match was found.
    #[inline(always)]
    pub(crate) fn skip(&mut self, amount: u32) {
        if amount != 0 {
            self.skip_raw(amount);
            self.read_ahead += amount;
        }
    }

    /// `mf_read`: copies at most `*left` bytes from the history buffer to
    /// `out`. This is needed by LZMA2 to encode uncompressed chunks.
    pub(crate) fn read(&self, out: &mut [u8], out_pos: &mut usize, left: &mut usize) {
        let out_avail = out.len() - *out_pos;
        let copy_size = out_avail.min(*left);
        let start = self.read_pos as usize - *left;
        out[*out_pos..*out_pos + copy_size].copy_from_slice(&self.buffer[start..start + copy_size]);
        *out_pos += copy_size;
        *left -= copy_size;
    }

    /// `lzma_mf_find`: finds matches starting from the current byte, into
    /// `matches`; the length of the longest match found, and the number
    /// of matches.
    pub(crate) fn find(&mut self, matches: &mut [Match]) -> (u32, u32) {
        // Call the match finder. It returns the number of length-distance
        // pairs found.
        let count = self.find_raw(matches);

        // Length of the longest match; assume that no matches were found
        // and thus the maximum length is zero.
        let mut len_best = 0;

        if count > 0 {
            // The last used element in the array contains the longest
            // match.
            len_best = matches[count as usize - 1].len;

            // If a match of maximum search length was found, try to
            // extend the match to maximum possible length.
            if len_best == self.nice_len {
                // The limit for the match length is either the maximum
                // match length supported by the LZ-based encoder or the
                // number of bytes left in the dictionary, whichever is
                // smaller.
                let limit = (self.avail() + 1).min(self.match_len_max);

                // The byte we just ran through the match finder, and the
                // beginning of the match. We need -1 here because the
                // match distances are zero based.
                let p1 = self.ptr() - 1;
                let p2 = p1 - matches[count as usize - 1].dist as usize - 1;

                len_best = memcmplen(&self.buffer, p1, p2, len_best, limit);
            }
        }

        // Finally update the read position to indicate that match finder
        // was run for this dictionary offset.
        self.read_ahead += 1;

        (len_best, count)
    }

    /// `mf->find`.
    fn find_raw(&mut self, matches: &mut [Match]) -> u32 {
        match self.match_finder {
            MatchFinder::HC3 => self.hc3_find(matches),
            MatchFinder::HC4 => self.hc4_find(matches),
            MatchFinder::BT2 => self.bt2_find(matches),
            MatchFinder::BT3 => self.bt3_find(matches),
            _ => self.bt4_find(matches),
        }
    }

    /// `mf->skip`.
    pub(crate) fn skip_raw(&mut self, amount: u32) {
        match self.match_finder {
            MatchFinder::HC3 => self.hc3_skip(amount),
            MatchFinder::HC4 => self.hc4_skip(amount),
            MatchFinder::BT2 => self.bt2_skip(amount),
            MatchFinder::BT3 => self.bt3_skip(amount),
            _ => self.bt4_skip(amount),
        }
    }

    /// `normalize`: drops the hash values that indicate distances greater
    /// than the dictionary size, and makes the others relative to a new
    /// offset, before the positions overflow.
    fn normalize(&mut self) {
        // In future we may not want to touch the lowest bits, because
        // there may be match finders that use larger resolution than one
        // byte.
        let subvalue = MUST_NORMALIZE_POS - self.cyclic_size;

        for value in self.hash.iter_mut().chain(self.son.iter_mut()) {
            // If the distance is greater than the dictionary size, we can
            // simply mark the hash element as empty.
            if *value <= subvalue {
                *value = EMPTY_HASH_VALUE;
            } else {
                *value -= subvalue;
            }
        }

        // Update offset to match the new locations. It wraps, as liblzma's
        // does: read_pos + offset stays the position.
        self.offset = self.offset.wrapping_sub(subvalue);
    }

    /// `move_pos`: marks the current byte as processed from point of view
    /// of the match finder.
    #[inline(always)]
    fn move_pos(&mut self) {
        self.cyclic_pos += 1;
        if self.cyclic_pos == self.cyclic_size {
            self.cyclic_pos = 0;
        }
        self.read_pos += 1;
        if self.read_pos.wrapping_add(self.offset) == u32::MAX {
            self.normalize();
        }
    }

    /// `move_pending`: when flushing, we cannot run the match finder
    /// unless there is nice_len bytes available in the dictionary.
    /// Instead, we skip running the match finder (indicating that no match
    /// was found), and count how many bytes we have ignored this way.
    ///
    /// When new data is given after the flushing was completed, the match
    /// finder is restarted by rewinding mf->read_pos backwards by
    /// mf->pending. Then the missed bytes are added to the hash using the
    /// match finder's skip function (with small amount of input, it may
    /// start using mf->pending again if flushing).
    ///
    /// Due to this rewinding, we don't touch cyclic_pos or test for
    /// normalization. It will be done when the match finder's skip
    /// function catches up after a flush.
    #[inline(always)]
    fn move_pending(&mut self) {
        self.read_pos += 1;
        self.pending += 1;
    }

    /// The `header` macro: the length limit, or None (after
    /// `move_pending`) if there is not enough input to run the match
    /// finder.
    #[inline(always)]
    fn header(&mut self, is_bt: bool, len_min: u32) -> Option<u32> {
        let mut len_limit = self.avail();
        if self.nice_len <= len_limit {
            len_limit = self.nice_len;
        } else if len_limit < len_min || (is_bt && self.action == Action::SyncFlush) {
            self.move_pending();
            return None;
        }
        Some(len_limit)
    }

    /// The position of the current byte: `pos` in liblzma.
    #[inline(always)]
    fn pos(&self) -> u32 {
        self.read_pos.wrapping_add(self.offset)
    }

    /// Makes `son` long enough to write the entries of `cyclic_pos`.
    #[inline(always)]
    fn son_grow(&mut self, entries: usize) {
        let need = (self.cyclic_pos as usize + 1) * entries;
        if self.son.len() < need {
            self.son.resize(need, EMPTY_HASH_VALUE);
        }
    }

    /// `hash_3_calc`: `(hash_2_value, hash_value)`.
    #[inline(always)]
    fn hash_3_calc(&self, cur: usize) -> (u32, u32) {
        let b = &self.buffer;
        let temp = HASH_TABLE[b[cur] as usize] ^ u32::from(b[cur + 1]);
        let hash_2_value = temp & HASH_2_MASK;
        let hash_value = (temp ^ (u32::from(b[cur + 2]) << 8)) & self.hash_mask;
        (hash_2_value, hash_value)
    }

    /// `hash_4_calc`: `(hash_2_value, hash_3_value, hash_value)`.
    #[inline(always)]
    fn hash_4_calc(&self, cur: usize) -> (u32, u32, u32) {
        let b = &self.buffer;
        let temp = HASH_TABLE[b[cur] as usize] ^ u32::from(b[cur + 1]);
        let hash_2_value = temp & HASH_2_MASK;
        let hash_3_value = (temp ^ (u32::from(b[cur + 2]) << 8)) & HASH_3_MASK;
        let hash_value =
            (temp ^ (u32::from(b[cur + 2]) << 8) ^ (HASH_TABLE[b[cur + 3] as usize] << 5))
                & self.hash_mask;
        (hash_2_value, hash_3_value, hash_value)
    }

    /// `hash_2_calc`.
    #[inline(always)]
    fn hash_2_calc(&self, cur: usize) -> u32 {
        u32::from(self.buffer[cur]) | (u32::from(self.buffer[cur + 1]) << 8)
    }

    // Hash Chain

    /// `hc_find_func`: the matches along the hash chain, after those in
    /// `matches[..count]`; the new count.
    #[allow(clippy::too_many_arguments)]
    fn hc_find_func(
        &mut self,
        len_limit: u32,
        pos: u32,
        cur: usize,
        mut cur_match: u32,
        matches: &mut [Match],
        mut count: u32,
        mut len_best: u32,
    ) -> u32 {
        let mut depth = self.depth;
        let cyclic_pos = self.cyclic_pos;
        let cyclic_size = self.cyclic_size;
        self.son_grow(1);
        self.son[cyclic_pos as usize] = cur_match;

        loop {
            let delta = pos.wrapping_sub(cur_match);
            if depth == 0 || delta >= cyclic_size {
                return count;
            }
            depth -= 1;

            let pb = cur - delta as usize;
            cur_match = self.son[cyclic_pos
                .wrapping_sub(delta)
                .wrapping_add(if delta > cyclic_pos { cyclic_size } else { 0 })
                as usize];

            let b = &self.buffer;
            if b[pb + len_best as usize] == b[cur + len_best as usize] && b[pb] == b[cur] {
                let len = memcmplen(b, pb, cur, 1, len_limit);

                if len_best < len {
                    len_best = len;
                    matches[count as usize] = Match {
                        len,
                        dist: delta - 1,
                    };
                    count += 1;

                    if len == len_limit {
                        return count;
                    }
                }
            }
        }
    }

    /// `hc_skip`.
    #[inline(always)]
    fn hc_skip_one(&mut self, cur_match: u32) {
        self.son_grow(1);
        self.son[self.cyclic_pos as usize] = cur_match;
        self.move_pos();
    }

    /// `lzma_mf_hc3_find`.
    fn hc3_find(&mut self, matches: &mut [Match]) -> u32 {
        let Some(len_limit) = self.header(false, 3) else {
            return 0;
        };
        let cur = self.ptr();
        let pos = self.pos();
        let mut matches_count = 0;

        let (hash_2_value, hash_value) = self.hash_3_calc(cur);

        let delta2 = pos.wrapping_sub(self.hash[hash_2_value as usize]);
        let cur_match = self.hash[(FIX_3_HASH_SIZE + hash_value) as usize];

        self.hash[hash_2_value as usize] = pos;
        self.hash[(FIX_3_HASH_SIZE + hash_value) as usize] = pos;

        let mut len_best = 2;

        if delta2 < self.cyclic_size && self.buffer[cur - delta2 as usize] == self.buffer[cur] {
            len_best = memcmplen(
                &self.buffer,
                cur - delta2 as usize,
                cur,
                len_best,
                len_limit,
            );

            matches[0] = Match {
                len: len_best,
                dist: delta2 - 1,
            };
            matches_count = 1;

            if len_best == len_limit {
                self.hc_skip_one(cur_match);
                return 1; // matches_count
            }
        }

        let count = self.hc_find_func(
            len_limit,
            pos,
            cur,
            cur_match,
            matches,
            matches_count,
            len_best,
        );
        self.move_pos();
        count
    }

    /// `lzma_mf_hc3_skip`.
    fn hc3_skip(&mut self, mut amount: u32) {
        loop {
            if self.avail() < 3 {
                self.move_pending();
            } else {
                let cur = self.ptr();
                let pos = self.pos();

                let (hash_2_value, hash_value) = self.hash_3_calc(cur);

                let cur_match = self.hash[(FIX_3_HASH_SIZE + hash_value) as usize];

                self.hash[hash_2_value as usize] = pos;
                self.hash[(FIX_3_HASH_SIZE + hash_value) as usize] = pos;

                self.hc_skip_one(cur_match);
            }
            amount -= 1;
            if amount == 0 {
                break;
            }
        }
    }

    /// `lzma_mf_hc4_find`.
    fn hc4_find(&mut self, matches: &mut [Match]) -> u32 {
        let Some(len_limit) = self.header(false, 4) else {
            return 0;
        };
        let cur = self.ptr();
        let pos = self.pos();
        let mut matches_count = 0;

        let (hash_2_value, hash_3_value, hash_value) = self.hash_4_calc(cur);

        let mut delta2 = pos.wrapping_sub(self.hash[hash_2_value as usize]);
        let delta3 = pos.wrapping_sub(self.hash[(FIX_3_HASH_SIZE + hash_3_value) as usize]);
        let cur_match = self.hash[(FIX_4_HASH_SIZE + hash_value) as usize];

        self.hash[hash_2_value as usize] = pos;
        self.hash[(FIX_3_HASH_SIZE + hash_3_value) as usize] = pos;
        self.hash[(FIX_4_HASH_SIZE + hash_value) as usize] = pos;

        let mut len_best = 1;

        if delta2 < self.cyclic_size && self.buffer[cur - delta2 as usize] == self.buffer[cur] {
            len_best = 2;
            matches[0] = Match {
                len: 2,
                dist: delta2 - 1,
            };
            matches_count = 1;
        }

        if delta2 != delta3
            && delta3 < self.cyclic_size
            && self.buffer[cur - delta3 as usize] == self.buffer[cur]
        {
            len_best = 3;
            matches[matches_count as usize].dist = delta3 - 1;
            matches_count += 1;
            delta2 = delta3;
        }

        if matches_count != 0 {
            len_best = memcmplen(
                &self.buffer,
                cur - delta2 as usize,
                cur,
                len_best,
                len_limit,
            );

            matches[matches_count as usize - 1].len = len_best;

            if len_best == len_limit {
                self.hc_skip_one(cur_match);
                return matches_count;
            }
        }

        if len_best < 3 {
            len_best = 3;
        }

        let count = self.hc_find_func(
            len_limit,
            pos,
            cur,
            cur_match,
            matches,
            matches_count,
            len_best,
        );
        self.move_pos();
        count
    }

    /// `lzma_mf_hc4_skip`.
    fn hc4_skip(&mut self, mut amount: u32) {
        loop {
            if self.avail() < 4 {
                self.move_pending();
            } else {
                let cur = self.ptr();
                let pos = self.pos();

                let (hash_2_value, hash_3_value, hash_value) = self.hash_4_calc(cur);

                let cur_match = self.hash[(FIX_4_HASH_SIZE + hash_value) as usize];

                self.hash[hash_2_value as usize] = pos;
                self.hash[(FIX_3_HASH_SIZE + hash_3_value) as usize] = pos;
                self.hash[(FIX_4_HASH_SIZE + hash_value) as usize] = pos;

                self.hc_skip_one(cur_match);
            }
            amount -= 1;
            if amount == 0 {
                break;
            }
        }
    }

    // Binary Tree

    /// `bt_find_func`: the matches along the binary tree, after those in
    /// `matches[..count]`, which it rebuilds; the new count. With
    /// `matches` empty, `bt_skip_func`: the tree only.
    #[allow(clippy::too_many_arguments)]
    fn bt_find_func(
        &mut self,
        len_limit: u32,
        pos: u32,
        cur: usize,
        mut cur_match: u32,
        mut matches: Option<&mut [Match]>,
        mut count: u32,
        mut len_best: u32,
    ) -> u32 {
        let mut depth = self.depth;
        let cyclic_pos = self.cyclic_pos;
        let cyclic_size = self.cyclic_size;
        self.son_grow(2);

        // ptr0 and ptr1 are indices into son.
        let mut ptr0 = ((cyclic_pos << 1) + 1) as usize;
        let mut ptr1 = (cyclic_pos << 1) as usize;

        let mut len0: u32 = 0;
        let mut len1: u32 = 0;

        loop {
            let delta = pos.wrapping_sub(cur_match);
            if depth == 0 || delta >= cyclic_size {
                self.son[ptr0] = EMPTY_HASH_VALUE;
                self.son[ptr1] = EMPTY_HASH_VALUE;
                return count;
            }
            depth -= 1;

            let pair = (cyclic_pos
                .wrapping_sub(delta)
                .wrapping_add(if delta > cyclic_pos { cyclic_size } else { 0 })
                << 1) as usize;
            let pb = cur - delta as usize;
            let mut len = len0.min(len1);

            if self.buffer[pb + len as usize] == self.buffer[cur + len as usize] {
                len = memcmplen(&self.buffer, pb, cur, len + 1, len_limit);

                if let Some(matches) = matches.as_deref_mut() {
                    if len_best < len {
                        len_best = len;
                        matches[count as usize] = Match {
                            len,
                            dist: delta - 1,
                        };
                        count += 1;

                        if len == len_limit {
                            self.son[ptr1] = self.son[pair];
                            self.son[ptr0] = self.son[pair + 1];
                            return count;
                        }
                    }
                } else if len == len_limit {
                    self.son[ptr1] = self.son[pair];
                    self.son[ptr0] = self.son[pair + 1];
                    return count;
                }
            }

            if self.buffer[pb + len as usize] < self.buffer[cur + len as usize] {
                self.son[ptr1] = cur_match;
                ptr1 = pair + 1;
                cur_match = self.son[ptr1];
                len1 = len;
            } else {
                self.son[ptr0] = cur_match;
                ptr0 = pair;
                cur_match = self.son[ptr0];
                len0 = len;
            }
        }
    }

    /// `bt_skip`.
    #[inline(always)]
    fn bt_skip_one(&mut self, len_limit: u32, pos: u32, cur: usize, cur_match: u32) {
        self.bt_find_func(len_limit, pos, cur, cur_match, None, 0, 0);
        self.move_pos();
    }

    /// `lzma_mf_bt2_find`.
    fn bt2_find(&mut self, matches: &mut [Match]) -> u32 {
        let Some(len_limit) = self.header(true, 2) else {
            return 0;
        };
        let cur = self.ptr();
        let pos = self.pos();

        let hash_value = self.hash_2_calc(cur);

        let cur_match = self.hash[hash_value as usize];
        self.hash[hash_value as usize] = pos;

        let count = self.bt_find_func(len_limit, pos, cur, cur_match, Some(matches), 0, 1);
        self.move_pos();
        count
    }

    /// `lzma_mf_bt2_skip`.
    fn bt2_skip(&mut self, mut amount: u32) {
        loop {
            if let Some(len_limit) = self.header(true, 2) {
                let cur = self.ptr();
                let pos = self.pos();

                let hash_value = self.hash_2_calc(cur);

                let cur_match = self.hash[hash_value as usize];
                self.hash[hash_value as usize] = pos;

                self.bt_skip_one(len_limit, pos, cur, cur_match);
            }
            amount -= 1;
            if amount == 0 {
                break;
            }
        }
    }

    /// `lzma_mf_bt3_find`.
    fn bt3_find(&mut self, matches: &mut [Match]) -> u32 {
        let Some(len_limit) = self.header(true, 3) else {
            return 0;
        };
        let cur = self.ptr();
        let pos = self.pos();
        let mut matches_count = 0;

        let (hash_2_value, hash_value) = self.hash_3_calc(cur);

        let delta2 = pos.wrapping_sub(self.hash[hash_2_value as usize]);
        let cur_match = self.hash[(FIX_3_HASH_SIZE + hash_value) as usize];

        self.hash[hash_2_value as usize] = pos;
        self.hash[(FIX_3_HASH_SIZE + hash_value) as usize] = pos;

        let mut len_best = 2;

        if delta2 < self.cyclic_size && self.buffer[cur - delta2 as usize] == self.buffer[cur] {
            len_best = memcmplen(
                &self.buffer,
                cur,
                cur - delta2 as usize,
                len_best,
                len_limit,
            );

            matches[0] = Match {
                len: len_best,
                dist: delta2 - 1,
            };
            matches_count = 1;

            if len_best == len_limit {
                self.bt_skip_one(len_limit, pos, cur, cur_match);
                return 1; // matches_count
            }
        }

        let count = self.bt_find_func(
            len_limit,
            pos,
            cur,
            cur_match,
            Some(matches),
            matches_count,
            len_best,
        );
        self.move_pos();
        count
    }

    /// `lzma_mf_bt3_skip`.
    fn bt3_skip(&mut self, mut amount: u32) {
        loop {
            if let Some(len_limit) = self.header(true, 3) {
                let cur = self.ptr();
                let pos = self.pos();

                let (hash_2_value, hash_value) = self.hash_3_calc(cur);

                let cur_match = self.hash[(FIX_3_HASH_SIZE + hash_value) as usize];

                self.hash[hash_2_value as usize] = pos;
                self.hash[(FIX_3_HASH_SIZE + hash_value) as usize] = pos;

                self.bt_skip_one(len_limit, pos, cur, cur_match);
            }
            amount -= 1;
            if amount == 0 {
                break;
            }
        }
    }

    /// `lzma_mf_bt4_find`.
    fn bt4_find(&mut self, matches: &mut [Match]) -> u32 {
        let Some(len_limit) = self.header(true, 4) else {
            return 0;
        };
        let cur = self.ptr();
        let pos = self.pos();
        let mut matches_count = 0;

        let (hash_2_value, hash_3_value, hash_value) = self.hash_4_calc(cur);

        let mut delta2 = pos.wrapping_sub(self.hash[hash_2_value as usize]);
        let delta3 = pos.wrapping_sub(self.hash[(FIX_3_HASH_SIZE + hash_3_value) as usize]);
        let cur_match = self.hash[(FIX_4_HASH_SIZE + hash_value) as usize];

        self.hash[hash_2_value as usize] = pos;
        self.hash[(FIX_3_HASH_SIZE + hash_3_value) as usize] = pos;
        self.hash[(FIX_4_HASH_SIZE + hash_value) as usize] = pos;

        let mut len_best = 1;

        if delta2 < self.cyclic_size && self.buffer[cur - delta2 as usize] == self.buffer[cur] {
            len_best = 2;
            matches[0] = Match {
                len: 2,
                dist: delta2 - 1,
            };
            matches_count = 1;
        }

        if delta2 != delta3
            && delta3 < self.cyclic_size
            && self.buffer[cur - delta3 as usize] == self.buffer[cur]
        {
            len_best = 3;
            matches[matches_count as usize].dist = delta3 - 1;
            matches_count += 1;
            delta2 = delta3;
        }

        if matches_count != 0 {
            len_best = memcmplen(
                &self.buffer,
                cur,
                cur - delta2 as usize,
                len_best,
                len_limit,
            );

            matches[matches_count as usize - 1].len = len_best;

            if len_best == len_limit {
                self.bt_skip_one(len_limit, pos, cur, cur_match);
                return matches_count;
            }
        }

        if len_best < 3 {
            len_best = 3;
        }

        let count = self.bt_find_func(
            len_limit,
            pos,
            cur,
            cur_match,
            Some(matches),
            matches_count,
            len_best,
        );
        self.move_pos();
        count
    }

    /// `lzma_mf_bt4_skip`.
    fn bt4_skip(&mut self, mut amount: u32) {
        loop {
            if let Some(len_limit) = self.header(true, 4) {
                let cur = self.ptr();
                let pos = self.pos();

                let (hash_2_value, hash_3_value, hash_value) = self.hash_4_calc(cur);

                let cur_match = self.hash[(FIX_4_HASH_SIZE + hash_value) as usize];

                self.hash[hash_2_value as usize] = pos;
                self.hash[(FIX_3_HASH_SIZE + hash_3_value) as usize] = pos;
                self.hash[(FIX_4_HASH_SIZE + hash_value) as usize] = pos;

                self.bt_skip_one(len_limit, pos, cur, cur_match);
            }
            amount -= 1;
            if amount == 0 {
                break;
            }
        }
    }

    /// `move_window`: moves the data in the input window to free space for
    /// new data.
    ///
    /// mf->buffer is a sliding input window, which keeps
    /// mf->keep_size_before bytes of input history available all the time.
    /// Now and then we need to "slide" the buffer to make space for the
    /// new data to the end of the buffer. At the same time, data older
    /// than keep_size_before is dropped.
    fn move_window(&mut self) {
        // Align the move to a multiple of 16 bytes. Some LZ-based encoders
        // like LZMA use the lowest bits of mf->read_pos to know the
        // alignment of the uncompressed data. We also get better speed for
        // memmove() with aligned buffers.
        let move_offset = (self.read_pos - self.keep_size_before) & !15;
        let move_size = (self.write_pos - move_offset) as usize;

        self.buffer
            .copy_within(move_offset as usize..move_offset as usize + move_size, 0);

        self.offset = self.offset.wrapping_add(move_offset);
        self.read_pos -= move_offset;
        self.read_limit -= move_offset;
        self.write_pos -= move_offset;
    }
}

/// `lz_encoder_prepare`: the sizes into `mf`; true if the options are
/// invalid.
fn lz_encoder_prepare(mf: &mut Mf, lz_options: &LzEncOptions) -> bool {
    let (old_size, old_hash_count, old_sons_count) = (mf.size, mf.hash_count, mf.sons_count);

    // For now, the dictionary size is limited to 1.5 GiB. This may grow in
    // the future if needed, but it needs a little more work than just
    // changing this check.
    if !is_enc_dict_size_valid(lz_options.dict_size)
        || lz_options.nice_len > lz_options.match_len_max
    {
        return true;
    }

    mf.keep_size_before = lz_options.before_size + lz_options.dict_size;
    mf.keep_size_after = lz_options.after_size + lz_options.match_len_max;

    // To avoid constant memmove()s, allocate some extra space. Since
    // memmove()s become more expensive when the size of the buffer
    // increases, we reserve more space when a large dictionary is used to
    // make the memmove() calls rarer.
    let mut reserve = lz_options.dict_size / 2;
    if reserve > 1 << 30 {
        reserve /= 2;
    }
    reserve +=
        (lz_options.before_size + lz_options.match_len_max + lz_options.after_size) / 2 + (1 << 19);

    mf.size = mf.keep_size_before + reserve + mf.keep_size_after;

    // Deallocate the old history buffer if it exists but has different
    // size than what is needed now.
    if old_size != mf.size {
        mf.buffer = Vec::new();
    }

    // Match finder options
    mf.match_len_max = lz_options.match_len_max;
    mf.nice_len = lz_options.nice_len;

    // cyclic_size has to stay smaller than 2 Gi.
    mf.cyclic_size = lz_options.dict_size + 1;

    // Validate the match finder ID.
    if !lz_options.match_finder.is_supported() {
        return true;
    }
    mf.match_finder = lz_options.match_finder;

    // Calculate the sizes of mf->hash and mf->son.
    //
    // NOTE: Since 5.3.5beta the LZMA encoder ensures that nice_len is big
    // enough for the selected match finder. This makes it easier for
    // applications as nice_len = 2 will always be accepted even though
    // the effective value can be slightly bigger.
    let hash_bytes = mf_get_hash_bytes(lz_options.match_finder);
    let is_bt = lz_options.match_finder.0 & 0x10 != 0;
    let mut hs: u32;

    if hash_bytes == 2 {
        hs = 0xFFFF;
    } else {
        // Round dictionary size up to the next 2^n - 1 so it can be used
        // as a hash mask.
        hs = lz_options.dict_size - 1;
        hs |= hs >> 1;
        hs |= hs >> 2;
        hs |= hs >> 4;
        hs |= hs >> 8;
        hs >>= 1;
        hs |= 0xFFFF;

        if hs > 1 << 24 {
            if hash_bytes == 3 {
                hs = (1 << 24) - 1;
            } else {
                hs >>= 1;
            }
        }
    }

    mf.hash_mask = hs;

    hs += 1;
    if hash_bytes > 2 {
        hs += HASH_2_SIZE;
    }
    if hash_bytes > 3 {
        hs += HASH_3_SIZE;
    }

    mf.hash_count = hs;
    mf.sons_count = mf.cyclic_size;
    if is_bt {
        mf.sons_count *= 2;
    }

    // Deallocate the old hash array if it exists and has different size
    // than what is needed now.
    if old_hash_count != mf.hash_count || old_sons_count != mf.sons_count {
        mf.hash = Vec::new();
        mf.son = Vec::new();
    }

    // Maximum number of match finder cycles
    mf.depth = lz_options.depth;
    if mf.depth == 0 {
        mf.depth = if is_bt {
            16 + mf.nice_len / 2
        } else {
            4 + mf.nice_len / 4
        };
    }

    false
}

/// `lz_encoder_init`: the buffers, and the preset dictionary; Err if the
/// memory cannot be had.
fn lz_encoder_init(mf: &mut Mf, lz_options: &LzEncOptions) -> Result<(), Ret> {
    // Allocate the history buffer: its memory is reserved here, as liblzma
    // allocates it. One that is kept starts empty again, as it grows as it
    // is written.
    if mf.buffer.capacity() == 0 {
        mf.buffer
            .try_reserve_exact(mf.size as usize)
            .map_err(|_| Ret::MemError)?;
    } else {
        mf.buffer.clear();
    }

    if mf.hash.is_empty() {
        // The binary trees are reserved as the buffer is.
        mf.son
            .try_reserve_exact(mf.sons_count as usize)
            .map_err(|_| Ret::MemError)?;

        // The hash table is asked of the allocator as zeroed memory, as
        // liblzma's lzma_alloc_zero() asks calloc(): a big one comes as
        // pages the system zeroes when they are first touched, so that a
        // short input does not pay for a big dictionary.
        //
        // Differs from liblzma: if that fails, the process aborts, where
        // liblzma returns LZMA_MEM_ERROR, as safe Rust has no zeroed
        // allocation that can fail. The table is at most 64 MiB (hs is
        // capped at 2^24), and the bigger buffers before it are reserved
        // with that check.
        mf.hash = vec![EMPTY_HASH_VALUE; mf.hash_count as usize];
    } else {
        mf.son.clear();
        mf.hash.fill(EMPTY_HASH_VALUE);
    }

    // Use cyclic_size as initial mf->offset. This allows avoiding a few
    // branches in the match finders. The downside is that match finder
    // needs to be normalized more often, which may hurt performance with
    // huge dictionaries.
    mf.offset = mf.cyclic_size;
    mf.read_pos = 0;
    mf.read_ahead = 0;
    mf.read_limit = 0;
    mf.write_pos = 0;
    mf.pending = 0;
    mf.cyclic_pos = 0;

    // Handle preset dictionary.
    if let Some(preset_dict) = &lz_options.preset_dict
        && !preset_dict.is_empty()
    {
        // If the preset dictionary is bigger than the actual dictionary,
        // use only the tail.
        let write_pos = preset_dict.len().min(mf.size as usize);
        mf.buffer
            .extend_from_slice(&preset_dict[preset_dict.len() - write_pos..]);
        mf.write_pos = write_pos as u32;
        mf.action = Action::SyncFlush;
        mf.skip_raw(mf.write_pos);
    }

    mf.action = Action::Run;
    Ok(())
}

/// `sizeof(lzma_coder)` of `lz_encoder.c` in liblzma on 64-bit systems,
/// which its memory usage counts.
const LZ_ENCODER_CODER_SIZE: u64 = 240;

/// More than the filters before an LZ encoder can hold back between calls:
/// a BCJ filter holds less than `2 * unfiltered_max` bytes (32 for IA-64),
/// delta none, and a chain has three of them at most.
const FILTERS_HELD_BACK: usize = 4096;

/// `lzma_lz_encoder_memusage`.
pub(crate) fn lz_encoder_memusage(lz_options: &LzEncOptions) -> u64 {
    let mut mf = Mf::default();

    // Setup the size information into mf.
    if lz_encoder_prepare(&mut mf, lz_options) {
        return u64::MAX;
    }

    // Calculate the memory usage.
    (u64::from(mf.hash_count) + u64::from(mf.sons_count)) * 4
        + u64::from(mf.size)
        + LZ_ENCODER_CODER_SIZE
}

/// `lzma_lz_encoder`: the LZ-based encoder, LZMA or LZMA2.
pub(crate) enum LzEnc {
    Lzma(Box<LzmaEncoder>),
    Lzma2(Box<Lzma2Encoder>),
}

impl LzEnc {
    /// `code`: encodes from `mf` to `out`.
    fn code(&mut self, mf: &mut Mf, out: &mut [u8], out_pos: &mut usize) -> Ret {
        match self {
            LzEnc::Lzma(lz) => lz.lzma_encode(mf, out, out_pos),
            LzEnc::Lzma2(lz) => lz.encode(mf, out, out_pos),
        }
    }
}

/// The `lzma_coder` of `lz_encoder.c`.
pub(crate) struct LzEncCoder {
    /// LZ-based encoder e.g. LZMA
    lz: LzEnc,
    /// History buffer and match finder
    mf: Mf,
    /// Next coder in the chain
    next: Option<Box<dyn NextCoder>>,
}

impl LzEncCoder {
    /// `lzma_lz_encoder_init`, after the `lz_init` that made `lz` and
    /// `lz_options`.
    pub(crate) fn new(lz: LzEnc, lz_options: &LzEncOptions) -> Result<LzEncCoder, Ret> {
        let mut mf = Mf::default();

        // Setup the size information into coder->mf.
        if lz_encoder_prepare(&mut mf, lz_options) {
            return Err(Ret::OptionsError);
        }

        // Allocate the buffers and do the rest of the initialization.
        lz_encoder_init(&mut mf, lz_options)?;

        Ok(LzEncCoder { lz, mf, next: None })
    }

    /// `lzma_lz_encoder_init` with this coder, whose memory is kept where
    /// the sizes are the same: it becomes the encoder of `id` with
    /// `options`, as liblzma's does when `lzma_next_coder_init()` has kept
    /// a coder of the same kind.
    pub(crate) fn reinit(&mut self, id: u64, options: &LzmaOptions) -> Result<(), Ret> {
        // Initialize the LZ-based encoder.
        let lz_options = match &mut self.lz {
            LzEnc::Lzma(lzma) => lzma.init(id, options)?,
            LzEnc::Lzma2(lzma2) => lzma2.init(options)?,
        };

        // Setup the size information into coder->mf and deallocate old
        // buffers if they have wrong size.
        if lz_encoder_prepare(&mut self.mf, &lz_options) {
            return Err(Ret::OptionsError);
        }

        // Allocate new buffers if needed, and do the rest of the
        // initialization.
        lz_encoder_init(&mut self.mf, &lz_options)
    }

    /// Whether this coder is of the kind `id` needs: liblzma's init
    /// functions are one for LZMA1 and LZMA1EXT, and another for LZMA2.
    pub(crate) fn is_kind_of(&self, id: u64) -> bool {
        match self.lz {
            LzEnc::Lzma(_) => id == FILTER_LZMA1 || id == FILTER_LZMA1EXT,
            LzEnc::Lzma2(_) => id == FILTER_LZMA2,
        }
    }

    /// The next filter in the chain, made after this one: the encoder
    /// reads its input from it.
    pub(crate) fn set_next(&mut self, next: Option<Box<dyn NextCoder>>) {
        self.next = next;
    }

    /// `fill_window`: tries to fill the input window (mf->buffer).
    ///
    /// This function must not be called once it has returned
    /// LZMA_STREAM_END.
    fn fill_window(&mut self, input: &[u8], in_pos: &mut usize, action: Action) -> Ret {
        let mf = &mut self.mf;

        // Move the sliding window if needed.
        if mf.read_pos >= mf.size - mf.keep_size_after {
            mf.move_window();
        }

        let mut write_pos = mf.write_pos as usize;
        let mut ret = match self.next.as_mut() {
            None => {
                // Not using a filter, simply memcpy() as much as possible.
                let want = (input.len() - *in_pos).min(mf.size as usize - write_pos);
                if mf.buffer.len() < write_pos + want {
                    mf.buffer.resize(write_pos + want, 0);
                }
                bufcpy(
                    input,
                    in_pos,
                    &mut mf.buffer[..write_pos + want],
                    &mut write_pos,
                );
                if action != Action::Run && *in_pos == input.len() {
                    Ret::StreamEnd
                } else {
                    Ret::Ok
                }
            }
            Some(next) => {
                // Differs from liblzma, without a difference to see:
                // liblzma gives the filters room to the end of the buffer.
                // They write at most the input left and what they held
                // back, so the buffer grows to that and a margin, as it
                // does without them.
                let want =
                    (input.len() - *in_pos + FILTERS_HELD_BACK).min(mf.size as usize - write_pos);
                if mf.buffer.len() < write_pos + want {
                    mf.buffer.resize(write_pos + want, 0);
                }
                next.code(
                    input,
                    in_pos,
                    &mut mf.buffer[..write_pos + want],
                    &mut write_pos,
                    action,
                )
            }
        };

        mf.write_pos = write_pos as u32;

        // If end of stream has been reached or flushing completed, we allow
        // the encoder to process all the input (that is, read_pos is
        // allowed to reach write_pos). Otherwise we keep keep_size_after
        // bytes available as prebuffer.
        if ret == Ret::StreamEnd {
            ret = Ret::Ok;
            mf.action = action;
            mf.read_limit = mf.write_pos;
        } else if mf.write_pos > mf.keep_size_after {
            // This needs to be done conditionally, because if we got only
            // little new input, there may be too little input to do any
            // encoding yet.
            mf.read_limit = mf.write_pos - mf.keep_size_after;
        }

        // Restart the match finder after finished LZMA_SYNC_FLUSH.
        if mf.pending > 0 && mf.read_pos < mf.read_limit {
            // Match finder may update coder->pending and expects it to
            // start from zero, so use a temporary variable.
            let pending = mf.pending;
            mf.pending = 0;

            // Rewind read_pos so that the match finder can hash the
            // pending bytes.
            mf.read_pos -= pending;

            // Call the skip function directly instead of using mf_skip(),
            // since we don't want to touch mf->read_ahead.
            mf.skip_raw(pending);
        }

        ret
    }
}

impl NextCoder for LzEncCoder {
    fn into_lz_encoder(self: Box<Self>) -> Option<Box<LzEncCoder>> {
        Some(self)
    }

    /// `lz_encode`.
    fn code(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        output: &mut [u8],
        out_pos: &mut usize,
        action: Action,
    ) -> Ret {
        while *out_pos < output.len() && (*in_pos < input.len() || action != Action::Run) {
            // Read more data to coder->mf.buffer if needed.
            if self.mf.action == Action::Run && self.mf.read_pos >= self.mf.read_limit {
                let ret = self.fill_window(input, in_pos, action);
                if ret != Ret::Ok {
                    return ret;
                }
            }

            // Encode
            let ret = self.lz.code(&mut self.mf, output, out_pos);
            if ret != Ret::Ok {
                // Setting this to LZMA_RUN for cases when we are flushing.
                // It doesn't matter when finishing or if an error
                // occurred.
                self.mf.action = Action::Run;
                return ret;
            }
        }

        Ret::Ok
    }
}
