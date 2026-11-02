//! Where to end a full block early, when its content changes: port of
//! `compress/zstd_preSplit.c`.

use crate::zstd::compress::hist::hist_add;

const THRESHOLD_PENALTY_RATE: u64 = 16;
const THRESHOLD_BASE: u64 = THRESHOLD_PENALTY_RATE - 2;
const THRESHOLD_PENALTY: i32 = 3;

const HASHLENGTH: usize = 2;
const HASHLOG_MAX: u32 = 10;
const HASHTABLESIZE: usize = 1 << HASHLOG_MAX;
const KNUTH: u32 = 0x9e37_79b9;

/// `hash2`: the hash of 2 bytes, or for a hash log of 8 just the first.
#[inline(always)]
fn hash2(src: &[u8], at: usize, hash_log: u32) -> usize {
    debug_assert!(hash_log >= 8);
    if hash_log == 8 {
        return usize::from(src[at]);
    }
    debug_assert!(hash_log <= HASHLOG_MAX);
    (u32::from(u16::from_le_bytes([src[at], src[at + 1]])).wrapping_mul(KNUTH) >> (32 - hash_log))
        as usize
}

/// `Fingerprint`: how often each hash occurred.
#[derive(Clone)]
struct Fingerprint {
    events: [u32; HASHTABLESIZE],
    nb_events: usize,
}

impl Fingerprint {
    fn new() -> Self {
        Fingerprint {
            events: [0; HASHTABLESIZE],
            nb_events: 0,
        }
    }

    /// `addEvents_generic`
    fn add_events(&mut self, src: &[u8], sampling_rate: usize, hash_log: u32) {
        let limit = src.len() - HASHLENGTH + 1;
        debug_assert!(src.len() >= HASHLENGTH);
        for n in (0..limit).step_by(sampling_rate) {
            self.events[hash2(src, n, hash_log)] += 1;
        }
        self.nb_events += limit / sampling_rate;
    }

    /// `recordFingerprint_generic`
    fn record(&mut self, src: &[u8], sampling_rate: usize, hash_log: u32) {
        self.events[..1 << hash_log].fill(0);
        self.nb_events = 0;
        self.add_events(src, sampling_rate, hash_log);
    }

    /// `mergeEvents`
    fn merge(&mut self, new: &Fingerprint) {
        for (acc, &n) in self.events.iter_mut().zip(&new.events) {
            *acc += n;
        }
        self.nb_events += new.nb_events;
    }
}

/// `fpDistance`
fn fp_distance(fp1: &Fingerprint, fp2: &Fingerprint, hash_log: u32) -> u64 {
    let mut distance: u64 = 0;
    for n in 0..1usize << hash_log {
        let d = i64::from(fp1.events[n]) * fp2.nb_events as i64
            - i64::from(fp2.events[n]) * fp1.nb_events as i64;
        distance = distance.wrapping_add(d.unsigned_abs());
    }
    distance
}

/// `compareFingerprints`: whether `new` is too different from `reference`.
fn compare_fingerprints(
    reference: &Fingerprint,
    new: &Fingerprint,
    penalty: i32,
    hash_log: u32,
) -> bool {
    debug_assert!(reference.nb_events > 0 && new.nb_events > 0);
    let p50 = reference.nb_events as u64 * new.nb_events as u64;
    let deviation = fp_distance(reference, new, hash_log);
    let threshold = p50 * (THRESHOLD_BASE + penalty as u64) / THRESHOLD_PENALTY_RATE;
    deviation >= threshold
}

/// `CHUNKSIZE`
const CHUNKSIZE: usize = 8 << 10;

/// `ZSTD_splitBlock_byChunks`: compares each 8 KB chunk with the ones
/// before, sampled at the level's rate; ends the block where one differs.
fn zstd_split_block_by_chunks(block: &[u8], level: usize) -> usize {
    // FP_RECORD(43), (11), (5), (1)
    const SAMPLING_RATES: [usize; 4] = [43, 11, 5, 1];
    const HASH_PARAMS: [u32; 4] = [8, 9, 10, 10];
    debug_assert!(level <= 3);
    let block_size = block.len();
    debug_assert!(block_size == 128 << 10);
    let (rate, hash_log) = (SAMPLING_RATES[level], HASH_PARAMS[level]);
    let mut past_events = Fingerprint::new();
    let mut new_events = Fingerprint::new();
    let mut penalty = THRESHOLD_PENALTY;

    past_events.record(&block[..CHUNKSIZE], rate, hash_log);
    let mut pos = CHUNKSIZE;
    while pos <= block_size - CHUNKSIZE {
        new_events.record(&block[pos..pos + CHUNKSIZE], rate, hash_log);
        if compare_fingerprints(&past_events, &new_events, penalty, hash_log) {
            return pos;
        }
        past_events.merge(&new_events);
        if penalty > 0 {
            penalty -= 1;
        }
        pos += CHUNKSIZE;
    }
    debug_assert!(pos == block_size);
    block_size
}

/// `ZSTD_splitBlock_fromBorders`: a very fast way: compares the bytes at
/// the start and the end of the block, then the middle with both, to end
/// the block at a quarter, half or three quarters, or not early.
fn zstd_split_block_from_borders(block: &[u8]) -> usize {
    const SEGMENT_SIZE: usize = 512;
    let block_size = block.len();
    debug_assert!(block_size == 128 << 10);
    // Only the 256 counts of bytes are used, of the 1024 of a fingerprint.
    let mut past_events = Fingerprint::new();
    let mut new_events = Fingerprint::new();
    let mut middle_events = Fingerprint::new();
    hist_add(&mut past_events.events[..256], &block[..SEGMENT_SIZE]);
    hist_add(
        &mut new_events.events[..256],
        &block[block_size - SEGMENT_SIZE..],
    );
    past_events.nb_events = SEGMENT_SIZE;
    new_events.nb_events = SEGMENT_SIZE;
    if !compare_fingerprints(&past_events, &new_events, 0, 8) {
        return block_size;
    }

    hist_add(
        &mut middle_events.events[..256],
        &block[block_size / 2 - SEGMENT_SIZE / 2..block_size / 2 + SEGMENT_SIZE / 2],
    );
    middle_events.nb_events = SEGMENT_SIZE;
    let dist_from_begin = fp_distance(&past_events, &middle_events, 8);
    let dist_from_end = fp_distance(&new_events, &middle_events, 8);
    let min_distance = (SEGMENT_SIZE * SEGMENT_SIZE / 3) as u64;
    if (dist_from_begin as i64 - dist_from_end as i64).unsigned_abs() < min_distance {
        return 64 << 10;
    }
    if dist_from_begin > dist_from_end {
        32 << 10
    } else {
        96 << 10
    }
}

/// `ZSTD_splitBlock`: where to end a full block of 128 KB, at `level` 0
/// (from its borders) to 4 (every chunk, fully sampled).
pub(crate) fn zstd_split_block(block: &[u8], level: usize) -> usize {
    debug_assert!(level <= 4);
    if level == 0 {
        return zstd_split_block_from_borders(block);
    }
    zstd_split_block_by_chunks(block, level - 1)
}
