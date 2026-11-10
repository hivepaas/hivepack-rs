//! A compressor for DEFLATE: port of `deflate_compress.c`.
//!
//! A whole buffer is compressed in one call into an output buffer, and the
//! call gives the compressed size, or 0 when it does not fit. The level
//! chooses the parser:
//!
//! - 0: uncompressed blocks only (`deflate_compress_none`);
//! - 1: greedy, with a hash table of two positions a bucket
//!   (`deflate_compress_fastest`, `ht_matchfinder.rs`);
//! - 2 to 4: greedy, with hash chains (`deflate_compress_greedy`,
//!   `hc_matchfinder.rs`);
//! - 5 to 7: lazy, and 8 and 9 lazy with two positions of look-ahead
//!   (`deflate_compress_lazy`, `deflate_compress_lazy2`);
//! - 10 to 12: near-optimal parsing, a minimum-cost path through the
//!   matches the binary trees find (`deflate_compress_near_optimal`,
//!   `bt_matchfinder.rs`), its symbol costs refined over several passes.
//!
//! Blocks end where the statistics of their literals and matches change
//! (`do_end_block_check`), and each is written as the cheapest of a block
//! with its own Huffman codes, the static codes or uncompressed blocks
//! (`deflate_flush_block`).
//!
//! The port is built as libdeflate's `SUPPORT_NEAR_OPTIMAL_PARSING`
//! default, 1, and with a 64-bit bit buffer, as on 64-bit machines; the
//! bits written are the same whatever the buffer's size.
//!
//! Differs from libdeflate: the input and output are slices and positions
//! in them are indices, where libdeflate has pointers. The union of parser
//! data in `struct libdeflate_compressor` is an enum, [`Parser`], and the
//! union of the precode and the full length codewords two fields
//! ([`Precode`], [`LengthCodes`]), never used at once.
//!
//! Not in libdeflate: [`Compressor::deflate_compress_part`] compresses a
//! buffer as a part of a stream that is not its last, its last block not
//! final and a sync marker after it, so that parts compressed apart, in
//! threads, are one stream (`deflate/mt.rs`). Only BFINAL changes, and only
//! in [`deflate_flush_block`] and [`deflate_compress_none`], where every
//! block is written; `deflate_compress` writes what it wrote before.

use crate::deflate::libdeflate::bt_matchfinder::{
    BT_MATCHFINDER_REQUIRED_NBYTES, BtMatchfinder, LzMatch,
};
use crate::deflate::libdeflate::common_defs::bsr32;
use crate::deflate::libdeflate::deflate_constants::{
    DEFLATE_BLOCKTYPE_DYNAMIC_HUFFMAN, DEFLATE_BLOCKTYPE_STATIC_HUFFMAN,
    DEFLATE_BLOCKTYPE_UNCOMPRESSED, DEFLATE_END_OF_BLOCK, DEFLATE_FIRST_LEN_SYM,
    DEFLATE_MAX_CODEWORD_LEN, DEFLATE_MAX_EXTRA_LENGTH_BITS, DEFLATE_MAX_EXTRA_OFFSET_BITS,
    DEFLATE_MAX_LITLEN_CODEWORD_LEN, DEFLATE_MAX_MATCH_LEN, DEFLATE_MAX_MATCH_OFFSET,
    DEFLATE_MAX_NUM_SYMS, DEFLATE_MAX_OFFSET_CODEWORD_LEN, DEFLATE_MAX_PRE_CODEWORD_LEN,
    DEFLATE_MIN_MATCH_LEN, DEFLATE_NUM_LITERALS, DEFLATE_NUM_LITLEN_SYMS, DEFLATE_NUM_OFFSET_SYMS,
    DEFLATE_NUM_PRECODE_SYMS,
};
use crate::deflate::libdeflate::hc_matchfinder::HcMatchfinder;
use crate::deflate::libdeflate::ht_matchfinder::{
    HT_MATCHFINDER_MIN_MATCH_LEN, HT_MATCHFINDER_REQUIRED_NBYTES, HtMatchfinder,
};
use crate::deflate::libdeflate::matchfinder_common::MATCHFINDER_WINDOW_SIZE;

/******************************************************************************/

// The parameters libdeflate lets a build change; the port has its defaults.

/// `MIN_BLOCK_LENGTH`: the minimum block length the compressor will use, in
/// uncompressed bytes, but for the final block, and for the last of a
/// series of uncompressed blocks. It is also about how far the block
/// before the last may go past the soft maximum so as not to leave a very
/// short last block.
const MIN_BLOCK_LENGTH: usize = 5000;

/// `SOFT_MAX_BLOCK_LENGTH`: for the greedy, lazy, lazy2 and near-optimal
/// compressors, the length the compressor tries to end blocks at; it may go
/// a little past it for a match that straddles it, or when the input ends
/// soon after.
const SOFT_MAX_BLOCK_LENGTH: usize = 300_000;

/// `SEQ_STORE_LENGTH`: for the greedy, lazy and lazy2 compressors, the
/// most matches a block holds; a block ends early when it is full.
const SEQ_STORE_LENGTH: usize = 50000;

/// `FAST_SOFT_MAX_BLOCK_LENGTH`: for `deflate_compress_fastest`, which
/// does not split blocks by their statistics, the length it ends them at.
const FAST_SOFT_MAX_BLOCK_LENGTH: usize = 65535;

/// `FAST_SEQ_STORE_LENGTH`: `SEQ_STORE_LENGTH` for
/// `deflate_compress_fastest`.
const FAST_SEQ_STORE_LENGTH: usize = 8192;

/// `MAX_LITLEN_CODEWORD_LEN`, `MAX_OFFSET_CODEWORD_LEN`,
/// `MAX_PRE_CODEWORD_LEN`: the longest codewords the compressor uses.
/// Literal/length codewords are limited to 14 bits, which costs almost
/// nothing and lets four literals be written at once.
const MAX_LITLEN_CODEWORD_LEN: u32 = 14;
const MAX_OFFSET_CODEWORD_LEN: u32 = DEFLATE_MAX_OFFSET_CODEWORD_LEN;
const MAX_PRE_CODEWORD_LEN: u32 = DEFLATE_MAX_PRE_CODEWORD_LEN;

/// `BIT_COST`: the near-optimal parser's costs are in 1/16 bits.
const BIT_COST: u32 = 16;

/// `LITERAL_NOSTAT_BITS`, `LENGTH_NOSTAT_BITS`, `OFFSET_NOSTAT_BITS`: the
/// bits assumed for a symbol the previous optimization pass did not use.
const LITERAL_NOSTAT_BITS: u32 = 13;
const LENGTH_NOSTAT_BITS: u32 = 13;
const OFFSET_NOSTAT_BITS: u32 = 10;

/// `MATCH_CACHE_LENGTH`: (slightly less than) the most matches the
/// near-optimal compressor caches per block.
const MATCH_CACHE_LENGTH: usize = SOFT_MAX_BLOCK_LENGTH * 5;

/// `MAX_MATCHES_PER_POS`: the most matches the binary trees find at a
/// position, one of each length.
const MAX_MATCHES_PER_POS: usize = (DEFLATE_MAX_MATCH_LEN - DEFLATE_MIN_MATCH_LEN + 1) as usize;

/// The entries of the match cache, `p.n.match_cache`: room past
/// `MATCH_CACHE_LENGTH` for the worst overflow before the block is ended.
const MATCH_CACHE_ROOM: usize =
    MATCH_CACHE_LENGTH + MAX_MATCHES_PER_POS + DEFLATE_MAX_MATCH_LEN as usize - 1;

/// `MAX_BLOCK_LENGTH`: the longest block: the final block, of up to
/// `SOFT_MAX_BLOCK_LENGTH + MIN_BLOCK_LENGTH - 1` bytes, or one that lazy2
/// ends with two literals and a longest match from
/// `SOFT_MAX_BLOCK_LENGTH - 1`.
const MAX_BLOCK_LENGTH: usize = {
    let a = SOFT_MAX_BLOCK_LENGTH + MIN_BLOCK_LENGTH - 1;
    let b = SOFT_MAX_BLOCK_LENGTH + 1 + DEFLATE_MAX_MATCH_LEN as usize;
    if a > b { a } else { b }
};

/// `check_buildtime_parameters`.
const _: () = {
    assert!(SOFT_MAX_BLOCK_LENGTH >= MIN_BLOCK_LENGTH);
    assert!(FAST_SOFT_MAX_BLOCK_LENGTH >= MIN_BLOCK_LENGTH);
    assert!(SEQ_STORE_LENGTH * DEFLATE_MIN_MATCH_LEN as usize >= MIN_BLOCK_LENGTH);
    assert!(FAST_SEQ_STORE_LENGTH * HT_MATCHFINDER_MIN_MATCH_LEN as usize >= MIN_BLOCK_LENGTH);
    assert!(MIN_BLOCK_LENGTH * MAX_MATCHES_PER_POS <= MATCH_CACHE_LENGTH);
    assert!(FAST_SOFT_MAX_BLOCK_LENGTH <= SOFT_MAX_BLOCK_LENGTH);
    assert!(
        SEQ_STORE_LENGTH * DEFLATE_MIN_MATCH_LEN as usize
            <= SOFT_MAX_BLOCK_LENGTH + MIN_BLOCK_LENGTH
    );
    assert!(
        FAST_SEQ_STORE_LENGTH * HT_MATCHFINDER_MIN_MATCH_LEN as usize
            <= FAST_SOFT_MAX_BLOCK_LENGTH + MIN_BLOCK_LENGTH
    );
    assert!(MAX_LITLEN_CODEWORD_LEN <= DEFLATE_MAX_LITLEN_CODEWORD_LEN);
    assert!(MAX_OFFSET_CODEWORD_LEN <= DEFLATE_MAX_OFFSET_CODEWORD_LEN);
    assert!(MAX_PRE_CODEWORD_LEN <= DEFLATE_MAX_PRE_CODEWORD_LEN);
    assert!((1usize << MAX_LITLEN_CODEWORD_LEN) >= DEFLATE_NUM_LITLEN_SYMS);
    assert!((1usize << MAX_OFFSET_CODEWORD_LEN) >= DEFLATE_NUM_OFFSET_SYMS);
    assert!((1usize << MAX_PRE_CODEWORD_LEN) >= DEFLATE_NUM_PRECODE_SYMS);
    // libdeflate_deflate_compress_bound() counts on it.
    assert!(2 * MIN_BLOCK_LENGTH <= u16::MAX as usize);
};

/******************************************************************************/

/// `deflate_length_slot_base`: length slot => length slot base value.
const DEFLATE_LENGTH_SLOT_BASE: [u32; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];

/// `deflate_extra_length_bits`: length slot => number of extra length bits.
const DEFLATE_EXTRA_LENGTH_BITS: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/// `deflate_offset_slot_base`: offset slot => offset slot base value.
const DEFLATE_OFFSET_SLOT_BASE: [u32; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];

/// `deflate_extra_offset_bits`: offset slot => number of extra offset bits.
const DEFLATE_EXTRA_OFFSET_BITS: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// `deflate_length_slot`: length => length slot.
#[rustfmt::skip]
const DEFLATE_LENGTH_SLOT: [u8; DEFLATE_MAX_MATCH_LEN as usize + 1] = [
    0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 12,
    12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15, 16, 16, 16, 16, 16,
    16, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17, 18, 18, 18, 18, 18, 18, 18,
    18, 19, 19, 19, 19, 19, 19, 19, 19, 20, 20, 20, 20, 20, 20, 20, 20, 20,
    20, 20, 20, 20, 20, 20, 20, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21,
    21, 21, 21, 21, 21, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22,
    22, 22, 22, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23,
    23, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 25, 25, 25,
    25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
    25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 26, 26, 26, 26, 26, 26, 26,
    26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
    26, 26, 26, 26, 26, 26, 26, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
    27, 27, 28,
];

/// `deflate_offset_slot`: `offset - 1 => offset_slot` for offset <= 256.
#[rustfmt::skip]
const DEFLATE_OFFSET_SLOT: [u8; 256] = [
    0, 1, 2, 3, 4, 4, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
    8, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
];

/// `deflate_precode_lens_permutation`: the order in which precode codeword
/// lengths are stored.
const DEFLATE_PRECODE_LENS_PERMUTATION: [u8; DEFLATE_NUM_PRECODE_SYMS] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// `deflate_extra_precode_bits`: precode symbol => number of extra bits.
const DEFLATE_EXTRA_PRECODE_BITS: [u8; DEFLATE_NUM_PRECODE_SYMS] =
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7];

/// Where the offset code's lengths start in [`DeflateCodes::lens`].
const LENS_OFFSET: usize = DEFLATE_NUM_LITLEN_SYMS;

/// `struct deflate_codes`: codewords and lengths for the DEFLATE Huffman
/// codes. A zero length means the symbol had zero frequency.
///
/// The lengths (`struct deflate_lens`) are one array, the literal/length
/// code's then the offset code's, as `deflate_precompute_huffman_header`
/// needs them.
#[derive(Clone)]
struct DeflateCodes {
    /// `codewords.litlen`.
    litlen: [u32; DEFLATE_NUM_LITLEN_SYMS],
    /// `codewords.offset`.
    offset: [u32; DEFLATE_NUM_OFFSET_SYMS],
    /// `lens.litlen`, then `lens.offset` from [`LENS_OFFSET`].
    lens: [u8; DEFLATE_NUM_LITLEN_SYMS + DEFLATE_NUM_OFFSET_SYMS],
}

impl DeflateCodes {
    const fn new() -> DeflateCodes {
        DeflateCodes {
            litlen: [0; DEFLATE_NUM_LITLEN_SYMS],
            offset: [0; DEFLATE_NUM_OFFSET_SYMS],
            lens: [0; DEFLATE_NUM_LITLEN_SYMS + DEFLATE_NUM_OFFSET_SYMS],
        }
    }
}

/// `struct deflate_freqs`: symbol frequency counters for the DEFLATE
/// Huffman codes.
#[derive(Clone)]
struct DeflateFreqs {
    litlen: [u32; DEFLATE_NUM_LITLEN_SYMS],
    offset: [u32; DEFLATE_NUM_OFFSET_SYMS],
}

/// `SEQ_LENGTH_SHIFT`, `SEQ_LITRUNLEN_MASK`.
const SEQ_LENGTH_SHIFT: u32 = 23;
const SEQ_LITRUNLEN_MASK: u32 = (1 << SEQ_LENGTH_SHIFT) - 1;

/// `struct deflate_sequence`: a run of literals followed by a match or the
/// end of the block, chosen by the parser before the block's codes are.
#[derive(Clone, Copy, Default)]
struct DeflateSequence {
    /// Bits 0..22: the number of literals in this run, which are read
    /// from the input. Bits 23..31: the length of the match which follows
    /// the literals, or 0 if this run is the last in the block.
    litrunlen_and_length: u32,
    /// The match's offset.
    offset: u16,
    /// The match's offset slot.
    offset_slot: u16,
}

/// `struct deflate_costs`: costs for the near-optimal parsing algorithm.
#[derive(Clone, Copy)]
struct DeflateCosts {
    /// The cost to output each possible literal.
    literal: [u32; DEFLATE_NUM_LITERALS],
    /// The cost to output each possible match length.
    length: [u32; DEFLATE_MAX_MATCH_LEN as usize + 1],
    /// The cost to output a match offset of each possible offset slot.
    offset_slot: [u32; DEFLATE_NUM_OFFSET_SYMS],
}

/// `OPTIMUM_OFFSET_SHIFT`, `OPTIMUM_LEN_MASK`.
const OPTIMUM_OFFSET_SHIFT: u32 = 9;
const OPTIMUM_LEN_MASK: u32 = (1 << OPTIMUM_OFFSET_SHIFT) - 1;

/// `struct deflate_optimum_node`: a position of the block, a node of the
/// graph of literal and match choices.
#[derive(Clone, Copy, Default)]
struct DeflateOptimumNode {
    /// The minimum cost to reach the end of the block from here.
    cost_to_end: u32,
    /// The literal or match that starts that path: the length in the low
    /// bits (1 for a literal), and the literal or the match's offset in
    /// the high bits.
    item: u32,
}

/// `NUM_LITERAL_OBSERVATION_TYPES`, `NUM_MATCH_OBSERVATION_TYPES`,
/// `NUM_OBSERVATION_TYPES`, `NUM_OBSERVATIONS_PER_BLOCK_CHECK`.
const NUM_LITERAL_OBSERVATION_TYPES: usize = 8;
const NUM_MATCH_OBSERVATION_TYPES: usize = 2;
const NUM_OBSERVATION_TYPES: usize = NUM_LITERAL_OBSERVATION_TYPES + NUM_MATCH_OBSERVATION_TYPES;
const NUM_OBSERVATIONS_PER_BLOCK_CHECK: u32 = 512;

/// `struct block_split_stats`.
#[derive(Clone, Default)]
struct BlockSplitStats {
    new_observations: [u32; NUM_OBSERVATION_TYPES],
    observations: [u32; NUM_OBSERVATION_TYPES],
    num_new_observations: u32,
    num_observations: u32,
}

/// `o.precode` of `struct libdeflate_compressor`: information about the
/// precode.
struct Precode {
    freqs: [u32; DEFLATE_NUM_PRECODE_SYMS],
    codewords: [u32; DEFLATE_NUM_PRECODE_SYMS],
    lens: [u8; DEFLATE_NUM_PRECODE_SYMS],
    items: [u32; DEFLATE_NUM_LITLEN_SYMS + DEFLATE_NUM_OFFSET_SYMS],
    num_litlen_syms: usize,
    num_offset_syms: usize,
    num_explicit_lens: usize,
    num_items: usize,
}

/// `o.length` of `struct libdeflate_compressor`: the "full" length
/// codewords, the litlen codeword with the extra bits after it.
struct LengthCodes {
    codewords: [u32; DEFLATE_MAX_MATCH_LEN as usize + 1],
    lens: [u8; DEFLATE_MAX_MATCH_LEN as usize + 1],
}

/// The parts of `struct libdeflate_compressor` that every compressor uses.
struct State {
    /// The compression level with which this compressor was created.
    compression_level: u32,
    /// Anything of this size or less we won't bother trying to compress.
    max_passthrough_size: usize,
    /// The maximum search depth: consider at most this many potential
    /// matches at each position.
    max_search_depth: u32,
    /// The "nice" match length: if a match of this length is found, choose
    /// it immediately without further consideration.
    nice_match_length: u32,
    /// Frequency counters for the current block.
    freqs: DeflateFreqs,
    /// Block split statistics for the current block.
    split_stats: BlockSplitStats,
    /// Dynamic Huffman codes for the current block.
    codes: DeflateCodes,
    /// The static Huffman codes defined by the DEFLATE format.
    static_codes: DeflateCodes,
    /// Temporary space for block flushing: `o.precode`.
    precode: Precode,
    /// `o.length`.
    length: LengthCodes,
    /// Not in libdeflate: whether the input's last block is the stream's
    /// last, with BFINAL set. False for [`Compressor::deflate_compress_part`].
    last: bool,
}

/// Data for greedy or lazy parsing: `p.g`.
struct Greedy {
    /// Hash chains matchfinder.
    hc_mf: Box<HcMatchfinder>,
    /// Matches and literals chosen for the current block.
    sequences: Vec<DeflateSequence>,
}

/// Data for fastest parsing: `p.f`.
struct Fastest {
    /// Hash table matchfinder.
    ht_mf: Box<HtMatchfinder>,
    /// Matches and literals chosen for the current block.
    sequences: Vec<DeflateSequence>,
}

/// Data for near-optimal parsing: `p.n`.
struct NearOptimal {
    /// Binary tree matchfinder.
    bt_mf: Box<BtMatchfinder>,
    /// Cached matches for the current block: for each position, the
    /// matches found there, by strictly increasing length, then an entry
    /// whose `length` is how many there are and whose `offset` is the
    /// literal at the position. Room past `MATCH_CACHE_LENGTH` takes the
    /// worst overflow before the block is ended.
    match_cache: Vec<LzMatch>,
    /// One node per position, and one for the end of the block, for the
    /// minimum-cost path.
    optimum_nodes: Vec<DeflateOptimumNode>,
    /// The current cost model being used.
    costs: DeflateCosts,
    /// Saved cost model.
    costs_saved: DeflateCosts,
    /// Match offset => offset slot, the full map.
    offset_slot_full: Vec<u8>,
    /// Literal/match statistics saved from previous block.
    prev_observations: [u32; NUM_OBSERVATION_TYPES],
    prev_num_observations: u32,
    /// Approximate match length frequencies based on a greedy parse,
    /// gathered during matchfinding, for the initial symbol costs.
    new_match_len_freqs: [u32; DEFLATE_MAX_MATCH_LEN as usize + 1],
    match_len_freqs: [u32; DEFLATE_MAX_MATCH_LEN as usize + 1],
    /// The maximum number of optimization passes per block.
    max_optim_passes: u32,
    /// Stop optimizing once a pass improves the cost by fewer bits.
    min_improvement_to_continue: u32,
    /// The bits a non-final pass's path must save for it to be used, when
    /// the final pass made the cost worse.
    min_bits_to_use_nonfinal_path: u32,
    /// The longest block whose best static Huffman block is looked for.
    max_len_to_optimize_static_block: u32,
}

/// `p` of `struct libdeflate_compressor`, with the compress() function
/// chosen at allocation time (`impl`).
enum Parser {
    /// Level 0: `max_passthrough_size` sends every input to
    /// `deflate_compress_none`.
    None,
    /// `deflate_compress_fastest`.
    Fastest(Fastest),
    /// `deflate_compress_greedy`.
    Greedy(Greedy),
    /// `deflate_compress_lazy`.
    Lazy(Greedy),
    /// `deflate_compress_lazy2`.
    Lazy2(Greedy),
    /// `deflate_compress_near_optimal`.
    NearOptimal(Box<NearOptimal>),
}

/// A DEFLATE compressor at one level, made by [`Compressor::new`]: port of
/// libdeflate's `struct libdeflate_compressor`.
///
/// It compresses a whole buffer at a time, raw DEFLATE, without the zlib or
/// gzip wrapper, with libdeflate 1.26's output, byte for byte. Levels 0 to
/// 12 are libdeflate's: 1 is the fastest, 6 the default, 9 the last before
/// the near-optimal parser of levels 10 to 12, which is slower and makes
/// smaller output.
///
/// ```
/// use hivepack::deflate::{Compressor, Inflate, InBuffer, OutBuffer, Flush, Status};
///
/// let data = b"one compressor, one call, one buffer, ".repeat(100);
/// let mut compressor = Compressor::new(12).expect("a level from 0 to 12");
/// let mut compressed = vec![0; compressor.deflate_compress_bound(data.len())];
/// let size = compressor.deflate_compress(&data, &mut compressed);
/// assert!(size > 0 && size < 100);
///
/// // Raw deflate, as hivepack's own Inflate reads it.
/// let mut inflate = Inflate::new(-15)?;
/// let mut out = vec![0; data.len()];
/// let mut output = OutBuffer::new(&mut out);
/// let status = inflate.inflate(&mut output, &mut InBuffer::new(&compressed[..size]), Flush::Finish)?;
/// assert_eq!(status, Status::StreamEnd);
/// assert_eq!(out, data);
/// # Ok::<(), hivepack::deflate::Error>(())
/// ```
pub struct Compressor {
    c: Box<State>,
    p: Parser,
}

/// `struct deflate_output_bitstream`: the state of sending bits to the
/// output, between blocks.
struct OutputBitstream {
    /// Bits that haven't yet been written to the output buffer.
    bitbuf: u64,
    /// Number of bits currently held in `bitbuf`: 0 to 7 between blocks.
    bitcount: u32,
    /// The index in the output at which the next byte should be written.
    next: usize,
    /// true if the output buffer ran out of space.
    overflow: bool,
}

/// `BITBUF_NBITS`: the capacity of the bit buffer, one less than its size,
/// so that `bitbuf >>= bitcount & !7` is defined.
const BITBUF_NBITS: u32 = 63;

/// `CAN_BUFFER`: whether `n` more bits always fit in the bit buffer after
/// a flush, which leaves up to 7.
const fn can_buffer(n: u32) -> bool {
    7 + n <= BITBUF_NBITS
}

/// `ADD_BITS`: add some bits to the bit buffer.
macro_rules! add_bits {
    ($bitbuf:ident, $bitcount:ident, $bits:expr, $n:expr) => {{
        $bitbuf |= ($bits as u64) << $bitcount;
        $bitcount += $n as u32;
    }};
}

/// `FLUSH_BITS`: write the whole bytes of the bit buffer to the output, a
/// word at once where there is room for a word, else a byte at a time.
/// `deflate_flush_block` checked before that the block fits.
macro_rules! flush_bits {
    ($out:ident, $out_next:ident, $out_fast_end:ident, $bitbuf:ident, $bitcount:ident) => {{
        if $out_next < $out_fast_end {
            // Flush a whole word (branchlessly).
            $out[$out_next..$out_next + 8].copy_from_slice(&$bitbuf.to_le_bytes());
            $bitbuf >>= $bitcount & !7;
            $out_next += ($bitcount >> 3) as usize;
            $bitcount &= 7;
        } else {
            // Flush a byte at a time.
            while $bitcount >= 8 {
                $out[$out_next] = $bitbuf as u8;
                $out_next += 1;
                $bitcount -= 8;
                $bitbuf >>= 8;
            }
        }
    }};
}

/// `heapify_subtree`: given the binary tree node `a[subtree_idx]` whose
/// children already satisfy the maxheap property, swap the node with its
/// greater child until it is greater than or equal to both of its
/// children. `a` uses 1-based indices: `a[i]` is `a1[i - 1]`.
fn heapify_subtree(a1: &mut [u32], length: usize, subtree_idx: usize) {
    let v = a1[subtree_idx - 1];
    let mut parent_idx = subtree_idx;
    loop {
        let mut child_idx = parent_idx * 2;
        if child_idx > length {
            break;
        }
        if child_idx < length && a1[child_idx] > a1[child_idx - 1] {
            child_idx += 1;
        }
        if v >= a1[child_idx - 1] {
            break;
        }
        a1[parent_idx - 1] = a1[child_idx - 1];
        parent_idx = child_idx;
    }
    a1[parent_idx - 1] = v;
}

/// `heapify_array`: rearrange `a` so that it satisfies the maxheap
/// property.
fn heapify_array(a1: &mut [u32], length: usize) {
    for subtree_idx in (1..=length / 2).rev() {
        heapify_subtree(a1, length, subtree_idx);
    }
}

/// `heap_sort`: sort the `length` numbers of `a`.
fn heap_sort(a: &mut [u32], mut length: usize) {
    heapify_array(a, length);
    while length >= 2 {
        a.swap(length - 1, 0);
        length -= 1;
        heapify_subtree(a, length, 1);
    }
}

/// `NUM_SYMBOL_BITS`, `SYMBOL_MASK`, `FREQ_MASK`.
const NUM_SYMBOL_BITS: u32 = 10;
const SYMBOL_MASK: u32 = (1 << NUM_SYMBOL_BITS) - 1;
const FREQ_MASK: u32 = !SYMBOL_MASK;

/// `sort_symbols`: the symbols of nonzero frequency, sorted by frequency
/// then symbol, written to `symout` as `sym | freq << NUM_SYMBOL_BITS`, the
/// lengths of the others set to 0. Returns how many there are.
fn sort_symbols(num_syms: usize, freqs: &[u32], lens: &mut [u8], symout: &mut [u32]) -> usize {
    let mut counters = [0u32; DEFLATE_MAX_NUM_SYMS];
    // We use heapsort, but with an added optimization. Since often most
    // symbol frequencies are low, we first do a count sort using a limited
    // number of counters. High frequencies are counted in the last counter,
    // and only they will be sorted with heapsort.
    let num_counters = num_syms;
    let counters = &mut counters[..num_counters];

    // Count the frequencies.
    for &freq in &freqs[..num_syms] {
        counters[(freq as usize).min(num_counters - 1)] += 1;
    }

    // Make the counters cumulative, ignoring the zero-th, which counted
    // symbols with zero frequency. As a side effect, this calculates the
    // number of symbols with nonzero frequency.
    let mut num_used_syms = 0;
    for counter in &mut counters[1..] {
        let count = *counter;
        *counter = num_used_syms;
        num_used_syms += count;
    }

    // Sort nonzero-frequency symbols using the counters. At the same time,
    // set the codeword lengths of zero-frequency symbols to 0.
    for sym in 0..num_syms {
        let freq = freqs[sym];
        if freq != 0 {
            let counter = &mut counters[(freq as usize).min(num_counters - 1)];
            symout[*counter as usize] = sym as u32 | (freq << NUM_SYMBOL_BITS);
            *counter += 1;
        } else {
            lens[sym] = 0;
        }
    }

    // Sort the symbols counted in the last counter.
    let start = counters[num_counters - 2] as usize;
    let end = counters[num_counters - 1] as usize;
    heap_sort(&mut symout[start..], end - start);

    num_used_syms as usize
}

/// `build_tree`: build a Huffman tree of the `sym_count` frequencies of
/// `a`, sorted, at least 2, keeping only its non-leaf nodes, in the first
/// `sym_count - 1` entries of `a`, each with its parent's index above
/// `NUM_SYMBOL_BITS`; `a[sym_count - 2]` is the root. The low bits of each
/// entry are kept as they are.
fn build_tree(a: &mut [u32], sym_count: usize) {
    let last_idx = sym_count - 1;
    // Index of the next lowest frequency leaf that still needs a parent.
    let mut i = 0;
    // Index of the next lowest frequency non-leaf that still needs a
    // parent, or 'e' if there is currently no such node.
    let mut b = 0;
    // Index of the next spot for a non-leaf (will overwrite a leaf).
    let mut e = 0;

    loop {
        // Select the next two lowest frequency nodes among the leaves A[i]
        // and non-leaves A[b], and create a new node A[e] to be their
        // parent.
        let new_freq;
        if i < last_idx && (b == e || (a[i + 1] & FREQ_MASK) <= (a[b] & FREQ_MASK)) {
            // Two leaves.
            new_freq = (a[i] & FREQ_MASK).wrapping_add(a[i + 1] & FREQ_MASK);
            i += 2;
        } else if b + 2 <= e && (i > last_idx || (a[b + 1] & FREQ_MASK) < (a[i] & FREQ_MASK)) {
            // Two non-leaves.
            new_freq = (a[b] & FREQ_MASK).wrapping_add(a[b + 1] & FREQ_MASK);
            a[b] = ((e as u32) << NUM_SYMBOL_BITS) | (a[b] & SYMBOL_MASK);
            a[b + 1] = ((e as u32) << NUM_SYMBOL_BITS) | (a[b + 1] & SYMBOL_MASK);
            b += 2;
        } else {
            // One leaf and one non-leaf.
            new_freq = (a[i] & FREQ_MASK).wrapping_add(a[b] & FREQ_MASK);
            a[b] = ((e as u32) << NUM_SYMBOL_BITS) | (a[b] & SYMBOL_MASK);
            i += 1;
            b += 1;
        }
        a[e] = new_freq | (a[e] & SYMBOL_MASK);
        // A binary tree with 'n' leaves has 'n - 1' non-leaves, so the tree
        // is complete once we've created 'n - 1' non-leaves.
        e += 1;
        if e >= last_idx {
            break;
        }
    }
}

/// `compute_length_counts`: from the tree `build_tree` made, rooted at
/// `a[root_idx]`, how many codewords have each length up to
/// `max_codeword_len`, longer ones given the longest length that has room.
fn compute_length_counts(
    a: &mut [u32],
    root_idx: usize,
    len_counts: &mut [u32; DEFLATE_MAX_CODEWORD_LEN + 1],
    max_codeword_len: u32,
) {
    let max_codeword_len = max_codeword_len as usize;
    len_counts[..=max_codeword_len].fill(0);
    len_counts[1] = 2;

    // Set the root node's depth to 0.
    a[root_idx] &= SYMBOL_MASK;

    for node in (0..root_idx).rev() {
        // Calculate the depth of this node.
        let parent = (a[node] >> NUM_SYMBOL_BITS) as usize;
        let parent_depth = a[parent] >> NUM_SYMBOL_BITS;
        let mut depth = (parent_depth + 1) as usize;

        // Set the depth of this node so that it is available when its
        // children (if any) are processed.
        a[node] = (a[node] & SYMBOL_MASK) | ((depth as u32) << NUM_SYMBOL_BITS);

        // If needed, decrease the length to meet the length-limited
        // constraint. This is not the optimal method for generating
        // length-limited Huffman codes! But it should be good enough.
        if depth >= max_codeword_len {
            depth = max_codeword_len;
            loop {
                depth -= 1;
                if len_counts[depth] != 0 {
                    break;
                }
            }
        }

        // Account for the fact that we have a non-leaf node at the current
        // depth.
        len_counts[depth] -= 1;
        len_counts[depth + 1] += 2;
    }
}

/// `reverse_codeword`: DEFLATE's codewords are bit-reversed. libdeflate
/// reverses with `rbit32` where the processor has it, else with a table;
/// both give the same codewords.
#[inline(always)]
fn reverse_codeword(codeword: u32, len: u8) -> u32 {
    codeword.reverse_bits() >> ((32 - u32::from(len)) & 31)
}

/// `gen_codewords`: the codewords of a canonical Huffman code, in `a`,
/// whose low bits hold the symbols sorted by frequency then symbol, from
/// how many codewords have each length.
fn gen_codewords(
    a: &mut [u32],
    lens: &mut [u8],
    len_counts: &[u32; DEFLATE_MAX_CODEWORD_LEN + 1],
    max_codeword_len: u32,
    num_syms: usize,
) {
    let mut next_codewords = [0u32; DEFLATE_MAX_CODEWORD_LEN + 1];

    // Given the number of codewords that will have each length, assign
    // codeword lengths to symbols. We do this by assigning the lengths in
    // decreasing order to the symbols sorted primarily by increasing
    // frequency and secondarily by increasing symbol value.
    let mut i = 0;
    for len in (1..=max_codeword_len as usize).rev() {
        for _ in 0..len_counts[len] {
            lens[(a[i] & SYMBOL_MASK) as usize] = len as u8;
            i += 1;
        }
    }

    // Generate the codewords themselves. We initialize the 'next_codewords'
    // array to provide the lexicographically first codeword of each length,
    // then assign codewords in symbol order. This produces a canonical
    // code.
    next_codewords[0] = 0;
    next_codewords[1] = 0;
    for len in 2..=max_codeword_len as usize {
        next_codewords[len] = (next_codewords[len - 1].wrapping_add(len_counts[len - 1])) << 1;
    }

    for sym in 0..num_syms {
        // DEFLATE requires bit-reversed codewords.
        let len = lens[sym];
        let next = &mut next_codewords[len as usize];
        a[sym] = reverse_codeword(*next, len);
        *next = next.wrapping_add(1);
    }
}

/// `deflate_make_huffman_code`: a length-limited canonical Huffman code for
/// `num_syms` symbols of frequencies `freqs`: the length of each symbol's
/// codeword in `lens` (0 for an unused symbol), at most
/// `max_codeword_len`, and the codeword in `codewords`.
///
/// When fewer than two symbols are used, two codewords of length 1 are
/// made, as zlib makes them: '0' for symbol 0, and '1' for the used symbol
/// if it is not symbol 0, else for symbol 1.
fn deflate_make_huffman_code(
    num_syms: usize,
    max_codeword_len: u32,
    freqs: &[u32],
    lens: &mut [u8],
    codewords: &mut [u32],
) {
    let a = codewords;
    const _: () = assert!(DEFLATE_MAX_NUM_SYMS <= 1 << NUM_SYMBOL_BITS);
    const _: () = assert!(MAX_BLOCK_LENGTH < (1 << (32 - NUM_SYMBOL_BITS)));

    // We begin by sorting the symbols primarily by frequency and
    // secondarily by symbol value. As an optimization, the array used for
    // this purpose ('A') shares storage with the space in which we will
    // eventually return the codewords.
    let num_used_syms = sort_symbols(num_syms, freqs, lens, a);

    // A complete Huffman code must contain at least 2 codewords.
    if num_used_syms < 2 {
        let sym = if num_used_syms != 0 {
            (a[0] & SYMBOL_MASK) as usize
        } else {
            0
        };
        let nonzero_idx = if sym != 0 { sym } else { 1 };

        a[0] = 0;
        lens[0] = 1;
        a[nonzero_idx] = 1;
        lens[nonzero_idx] = 1;
        return;
    }

    // Build a stripped-down version of the Huffman tree, sharing the array
    // 'A' with the symbol values. Then extract length counts from the tree
    // and use them to generate the final codewords.
    build_tree(a, num_used_syms);

    let mut len_counts = [0u32; DEFLATE_MAX_CODEWORD_LEN + 1];
    compute_length_counts(a, num_used_syms - 2, &mut len_counts, max_codeword_len);
    gen_codewords(a, lens, &len_counts, max_codeword_len, num_syms);
}

impl State {
    /// `deflate_reset_symbol_frequencies`: clear the Huffman symbol
    /// frequency counters, when starting a new DEFLATE block.
    fn deflate_reset_symbol_frequencies(&mut self) {
        self.freqs.litlen.fill(0);
        self.freqs.offset.fill(0);
    }
}

/// `deflate_make_huffman_codes`: the literal/length and offset codes for a
/// block, from the frequencies.
fn deflate_make_huffman_codes(freqs: &DeflateFreqs, codes: &mut DeflateCodes) {
    let (litlen_lens, offset_lens) = codes.lens.split_at_mut(LENS_OFFSET);
    deflate_make_huffman_code(
        DEFLATE_NUM_LITLEN_SYMS,
        MAX_LITLEN_CODEWORD_LEN,
        &freqs.litlen,
        litlen_lens,
        &mut codes.litlen,
    );
    deflate_make_huffman_code(
        DEFLATE_NUM_OFFSET_SYMS,
        MAX_OFFSET_CODEWORD_LEN,
        &freqs.offset,
        offset_lens,
        &mut codes.offset,
    );
}

/// `deflate_init_static_codes`: `c->static_codes`, made from the
/// frequencies that give the static code's lengths: `1 << (9 - len)`, as
/// libdeflate writes them.
#[allow(clippy::eq_op)]
fn deflate_init_static_codes(c: &mut State) {
    for (i, freq) in c.freqs.litlen.iter_mut().enumerate() {
        *freq = match i {
            0..144 => 1 << (9 - 8),
            144..256 => 1 << (9 - 9),
            256..280 => 1 << (9 - 7),
            _ => 1 << (9 - 8),
        };
    }
    c.freqs.offset.fill(1 << (5 - 5));
    deflate_make_huffman_codes(&c.freqs, &mut c.static_codes);
}

/// `deflate_get_offset_slot`: the offset slot of a match offset, from 1 to
/// 32768, with the small map: for offsets above 256, slots 16 to 29 are
/// slots 2 to 15 of an offset 128 times smaller.
#[inline(always)]
fn deflate_get_offset_slot(offset: u32) -> u32 {
    let n = 256u32.wrapping_sub(offset) >> 29;
    u32::from(DEFLATE_OFFSET_SLOT[((offset - 1) >> n) as usize & 255]) + (n << 1)
}

/// `deflate_compute_precode_items`: the items (precode symbols with their
/// extra bits above bit 5) that write the codeword lengths `lens`, and the
/// precode's frequencies. Returns how many items there are.
fn deflate_compute_precode_items(
    lens: &[u8],
    precode_freqs: &mut [u32; DEFLATE_NUM_PRECODE_SYMS],
    precode_items: &mut [u32],
) -> usize {
    let num_lens = lens.len();
    precode_freqs.fill(0);

    let mut itemptr = 0;
    let mut run_start = 0;
    loop {
        // Find the next run of codeword lengths.

        // len = the length being repeated
        let len = lens[run_start];

        // Extend the run.
        let mut run_end = run_start;
        loop {
            run_end += 1;
            if run_end == num_lens || len != lens[run_end] {
                break;
            }
        }

        if len == 0 {
            // Run of zeroes.

            // Symbol 18: RLE 11 to 138 zeroes at a time.
            while run_end - run_start >= 11 {
                let extra_bits = (run_end - run_start - 11).min(0x7F);
                precode_freqs[18] += 1;
                precode_items[itemptr] = 18 | ((extra_bits as u32) << 5);
                itemptr += 1;
                run_start += 11 + extra_bits;
            }

            // Symbol 17: RLE 3 to 10 zeroes at a time.
            if run_end - run_start >= 3 {
                let extra_bits = (run_end - run_start - 3).min(0x7);
                precode_freqs[17] += 1;
                precode_items[itemptr] = 17 | ((extra_bits as u32) << 5);
                itemptr += 1;
                run_start += 3 + extra_bits;
            }
        } else {
            // A run of nonzero lengths.

            // Symbol 16: RLE 3 to 6 of the previous length.
            if run_end - run_start >= 4 {
                precode_freqs[len as usize] += 1;
                precode_items[itemptr] = u32::from(len);
                itemptr += 1;
                run_start += 1;
                loop {
                    let extra_bits = (run_end - run_start - 3).min(0x3);
                    precode_freqs[16] += 1;
                    precode_items[itemptr] = 16 | ((extra_bits as u32) << 5);
                    itemptr += 1;
                    run_start += 3 + extra_bits;
                    if run_end - run_start < 3 {
                        break;
                    }
                }
            }
        }

        // Output any remaining lengths without RLE.
        while run_start != run_end {
            precode_freqs[len as usize] += 1;
            precode_items[itemptr] = u32::from(len);
            itemptr += 1;
            run_start += 1;
        }
        if run_start == num_lens {
            break;
        }
    }

    itemptr
}

/// `deflate_precompute_huffman_header`: precompute the information needed
/// to output dynamic Huffman codes: how many literal/length and offset
/// lengths are sent, the precode items that send them, and the precode.
fn deflate_precompute_huffman_header(c: &mut State) {
    let pre = &mut c.precode;
    let lens = &mut c.codes.lens;

    // Compute how many litlen and offset symbols are needed.
    pre.num_litlen_syms = DEFLATE_NUM_LITLEN_SYMS;
    while pre.num_litlen_syms > 257 && lens[pre.num_litlen_syms - 1] == 0 {
        pre.num_litlen_syms -= 1;
    }
    pre.num_offset_syms = DEFLATE_NUM_OFFSET_SYMS;
    while pre.num_offset_syms > 1 && lens[LENS_OFFSET + pre.num_offset_syms - 1] == 0 {
        pre.num_offset_syms -= 1;
    }

    // If we're not using the full set of literal/length codeword lengths,
    // then temporarily move the offset codeword lengths over so that the
    // literal/length and offset codeword lengths are contiguous.
    if pre.num_litlen_syms != DEFLATE_NUM_LITLEN_SYMS {
        lens.copy_within(
            LENS_OFFSET..LENS_OFFSET + pre.num_offset_syms,
            pre.num_litlen_syms,
        );
    }

    // Compute the "items" (RLE / literal tokens and extra bits) with which
    // the codeword lengths in the larger code will be output.
    pre.num_items = deflate_compute_precode_items(
        &lens[..pre.num_litlen_syms + pre.num_offset_syms],
        &mut pre.freqs,
        &mut pre.items,
    );

    // Build the precode.
    deflate_make_huffman_code(
        DEFLATE_NUM_PRECODE_SYMS,
        MAX_PRE_CODEWORD_LEN,
        &pre.freqs,
        &mut pre.lens,
        &mut pre.codewords,
    );

    // Count how many precode lengths we actually need to output.
    pre.num_explicit_lens = DEFLATE_NUM_PRECODE_SYMS;
    while pre.num_explicit_lens > 4
        && pre.lens[DEFLATE_PRECODE_LENS_PERMUTATION[pre.num_explicit_lens - 1] as usize] == 0
    {
        pre.num_explicit_lens -= 1;
    }

    // Restore the offset codeword lengths if needed.
    if pre.num_litlen_syms != DEFLATE_NUM_LITLEN_SYMS {
        lens.copy_within(
            pre.num_litlen_syms..pre.num_litlen_syms + pre.num_offset_syms,
            LENS_OFFSET,
        );
    }
}

/// `deflate_compute_full_len_codewords`: the "full" match length
/// codewords, the litlen codeword and the extra bits, for each length.
fn deflate_compute_full_len_codewords(length: &mut LengthCodes, codes: &DeflateCodes) {
    const _: () = assert!(MAX_LITLEN_CODEWORD_LEN + DEFLATE_MAX_EXTRA_LENGTH_BITS <= 32);
    for len in DEFLATE_MIN_MATCH_LEN as usize..=DEFLATE_MAX_MATCH_LEN as usize {
        let slot = DEFLATE_LENGTH_SLOT[len] as usize;
        let litlen_sym = DEFLATE_FIRST_LEN_SYM + slot;
        let extra_bits = len as u32 - DEFLATE_LENGTH_SLOT_BASE[slot];

        length.codewords[len] = codes.litlen[litlen_sym] | (extra_bits << codes.lens[litlen_sym]);
        length.lens[len] = codes.lens[litlen_sym] + DEFLATE_EXTRA_LENGTH_BITS[slot];
    }
}

/// What `deflate_flush_block` writes the literals and matches from: the
/// parser's sequences, or the near-optimal parser's minimum-cost path
/// (libdeflate's `sequences == NULL`), with its map of offset slots.
enum BlockItems<'a> {
    Sequences(&'a [DeflateSequence]),
    Path(&'a [DeflateOptimumNode], &'a [u8]),
}

/// `deflate_flush_block`: choose the best type of block (dynamic Huffman,
/// static Huffman or uncompressed), then output it. `c.freqs` and
/// `c.codes` must already be those of the block's literals, matches and
/// end-of-block symbol. If the block does not fit in the output, sets
/// `os.overflow` and writes nothing.
///
/// Differs from libdeflate: the input's last block (`is_final_block`) has
/// BFINAL set only if `c.last` says it ends the stream, so that
/// [`Compressor::deflate_compress_part`] can leave it for a part after. The
/// parsers, which all end their blocks here, then need no change, and
/// neither does the block's cost: BFINAL is one bit either way.
#[allow(clippy::too_many_arguments)]
fn deflate_flush_block(
    c: &mut State,
    os: &mut OutputBitstream,
    out: &mut [u8],
    input: &[u8],
    block_begin: usize,
    block_length: usize,
    items: BlockItems<'_>,
    is_final_block: bool,
) {
    let mut in_next = block_begin;
    let in_end = block_begin + block_length;
    let mut bitbuf = os.bitbuf;
    let mut bitcount = os.bitcount;
    let mut out_next = os.next;
    let out_end = out.len();
    let out_fast_end = out_end - (8 - 1).min(out_end - out_next);
    // The cost for each block type, in bits. Start with the cost of the
    // block header which is 3 bits.
    let mut dynamic_cost: u32 = 3;
    let mut static_cost: u32 = 3;
    let mut uncompressed_cost: u32 = 3;

    debug_assert!(block_length >= MIN_BLOCK_LENGTH || (is_final_block && block_length > 0));
    debug_assert!(block_length <= MAX_BLOCK_LENGTH);
    debug_assert!(bitcount <= 7);
    debug_assert!(!os.overflow);

    // Precompute the precode items and build the precode.
    deflate_precompute_huffman_header(c);

    // Account for the cost of encoding dynamic Huffman codes.
    let pre = &c.precode;
    dynamic_cost = dynamic_cost.wrapping_add(5 + 5 + 4 + (3 * pre.num_explicit_lens as u32));
    for sym in 0..DEFLATE_NUM_PRECODE_SYMS {
        let extra = u32::from(DEFLATE_EXTRA_PRECODE_BITS[sym]);
        dynamic_cost = dynamic_cost
            .wrapping_add(pre.freqs[sym].wrapping_mul(extra + u32::from(pre.lens[sym])));
    }

    // Account for the cost of encoding literals.
    for sym in 0..144 {
        let freq = c.freqs.litlen[sym];
        dynamic_cost = dynamic_cost.wrapping_add(freq.wrapping_mul(u32::from(c.codes.lens[sym])));
        static_cost = static_cost.wrapping_add(freq.wrapping_mul(8));
    }
    for sym in 144..256 {
        let freq = c.freqs.litlen[sym];
        dynamic_cost = dynamic_cost.wrapping_add(freq.wrapping_mul(u32::from(c.codes.lens[sym])));
        static_cost = static_cost.wrapping_add(freq.wrapping_mul(9));
    }

    // Account for the cost of encoding the end-of-block symbol.
    dynamic_cost = dynamic_cost.wrapping_add(u32::from(c.codes.lens[DEFLATE_END_OF_BLOCK]));
    static_cost = static_cost.wrapping_add(7);

    // Account for the cost of encoding lengths.
    for sym in DEFLATE_FIRST_LEN_SYM..DEFLATE_FIRST_LEN_SYM + DEFLATE_EXTRA_LENGTH_BITS.len() {
        let extra = u32::from(DEFLATE_EXTRA_LENGTH_BITS[sym - DEFLATE_FIRST_LEN_SYM]);
        let freq = c.freqs.litlen[sym];
        dynamic_cost =
            dynamic_cost.wrapping_add(freq.wrapping_mul(extra + u32::from(c.codes.lens[sym])));
        static_cost = static_cost
            .wrapping_add(freq.wrapping_mul(extra + u32::from(c.static_codes.lens[sym])));
    }

    // Account for the cost of encoding offsets.
    for sym in 0..DEFLATE_EXTRA_OFFSET_BITS.len() {
        let extra = u32::from(DEFLATE_EXTRA_OFFSET_BITS[sym]);
        let freq = c.freqs.offset[sym];
        dynamic_cost = dynamic_cost
            .wrapping_add(freq.wrapping_mul(extra + u32::from(c.codes.lens[LENS_OFFSET + sym])));
        static_cost = static_cost.wrapping_add(freq.wrapping_mul(extra + 5));
    }

    // Compute the cost of using uncompressed blocks.
    uncompressed_cost = uncompressed_cost.wrapping_add(
        ((bitcount + 3).wrapping_neg() & 7)
            + 32
            + (40 * (block_length.div_ceil(u16::MAX as usize) as u32 - 1))
            + (8 * block_length as u32),
    );

    // Choose and output the cheapest type of block. If there is a tie,
    // prefer uncompressed, then static, then dynamic.
    let best_cost = dynamic_cost.min(static_cost.min(uncompressed_cost));

    // If the block isn't going to fit, then stop early.
    if (u64::from(bitcount) + u64::from(best_cost)).div_ceil(8) > (out_end - out_next) as u64 {
        os.overflow = true;
        return;
    }
    // Else, now we know that the block fits, so no further bounds checks on
    // the output buffer are required until the next block.

    'out: {
        if best_cost == uncompressed_cost {
            // Uncompressed block(s). DEFLATE limits the length of
            // uncompressed blocks to UINT16_MAX bytes, so if the length of
            // the "block" we're flushing is over UINT16_MAX, we actually
            // output multiple blocks.
            loop {
                let mut bfinal = 0u8;
                let mut len = u16::MAX as usize;

                if in_end - in_next <= u16::MAX as usize {
                    bfinal = u8::from(is_final_block && c.last);
                    len = in_end - in_next;
                }
                // Output BFINAL (1 bit) and BTYPE (2 bits), then align to a
                // byte boundary.
                const _: () = assert!(DEFLATE_BLOCKTYPE_UNCOMPRESSED == 0);
                out[out_next] = (bfinal << bitcount) | bitbuf as u8;
                out_next += 1;
                if bitcount > 5 {
                    out[out_next] = 0;
                    out_next += 1;
                }
                bitbuf = 0;
                bitcount = 0;
                // Output LEN and NLEN, then the data itself.
                out[out_next..out_next + 2].copy_from_slice(&(len as u16).to_le_bytes());
                out_next += 2;
                out[out_next..out_next + 2].copy_from_slice(&(!(len as u16)).to_le_bytes());
                out_next += 2;
                out[out_next..out_next + len].copy_from_slice(&input[in_next..in_next + len]);
                out_next += len;
                in_next += len;
                if in_next == in_end {
                    break;
                }
            }
            // Done outputting uncompressed block(s).
            break 'out;
        }

        let codes;
        if best_cost == static_cost {
            // Static Huffman block.
            codes = &c.static_codes;
            add_bits!(bitbuf, bitcount, u64::from(is_final_block && c.last), 1);
            add_bits!(bitbuf, bitcount, DEFLATE_BLOCKTYPE_STATIC_HUFFMAN, 2);
            flush_bits!(out, out_next, out_fast_end, bitbuf, bitcount);
        } else {
            let pre = &c.precode;
            let num_explicit_lens = pre.num_explicit_lens;
            let num_precode_items = pre.num_items;

            // Dynamic Huffman block.
            codes = &c.codes;
            const _: () = assert!(can_buffer(1 + 2 + 5 + 5 + 4 + 3));
            add_bits!(bitbuf, bitcount, u64::from(is_final_block && c.last), 1);
            add_bits!(bitbuf, bitcount, DEFLATE_BLOCKTYPE_DYNAMIC_HUFFMAN, 2);
            add_bits!(bitbuf, bitcount, pre.num_litlen_syms - 257, 5);
            add_bits!(bitbuf, bitcount, pre.num_offset_syms - 1, 5);
            add_bits!(bitbuf, bitcount, num_explicit_lens - 4, 4);

            // Output the lengths of the codewords in the precode. A 64-bit
            // bitbuffer is just one bit too small to hold the maximum number
            // of precode lens, so to minimize flushes we merge one len with
            // the previous fields.
            const _: () = assert!(can_buffer(3 * (DEFLATE_NUM_PRECODE_SYMS as u32 - 1)));
            let precode_sym = DEFLATE_PRECODE_LENS_PERMUTATION[0] as usize;
            add_bits!(bitbuf, bitcount, pre.lens[precode_sym], 3);
            flush_bits!(out, out_next, out_fast_end, bitbuf, bitcount);
            // num_explicit_lens >= 4
            for &precode_sym in &DEFLATE_PRECODE_LENS_PERMUTATION[1..num_explicit_lens] {
                add_bits!(bitbuf, bitcount, pre.lens[precode_sym as usize], 3);
            }
            flush_bits!(out, out_next, out_fast_end, bitbuf, bitcount);

            // Output the lengths of the codewords in the litlen and offset
            // codes, encoded by the precode.
            const _: () = assert!(can_buffer(MAX_PRE_CODEWORD_LEN + 7));
            for &precode_item in &pre.items[..num_precode_items] {
                let precode_sym = (precode_item & 0x1F) as usize;
                add_bits!(
                    bitbuf,
                    bitcount,
                    pre.codewords[precode_sym],
                    pre.lens[precode_sym]
                );
                add_bits!(
                    bitbuf,
                    bitcount,
                    precode_item >> 5,
                    DEFLATE_EXTRA_PRECODE_BITS[precode_sym]
                );
                flush_bits!(out, out_next, out_fast_end, bitbuf, bitcount);
            }
        }

        // Output the literals and matches for a dynamic or static block.
        debug_assert!(bitcount <= 7);
        deflate_compute_full_len_codewords(&mut c.length, codes);
        let length_codes = &c.length;

        // `WRITE_MATCH`: write a match to the output buffer. Its parts fit
        // in the bit buffer together, so there is no flush between them.
        const _: () = assert!(can_buffer(
            MAX_LITLEN_CODEWORD_LEN
                + DEFLATE_MAX_EXTRA_LENGTH_BITS
                + MAX_OFFSET_CODEWORD_LEN
                + DEFLATE_MAX_EXTRA_OFFSET_BITS
        ));
        macro_rules! write_match {
            ($length:expr, $offset:expr, $offset_slot:expr) => {{
                let length = $length as usize;
                let offset = $offset as u32;
                let offset_slot = $offset_slot as usize;
                // Litlen symbol and extra length bits.
                add_bits!(
                    bitbuf,
                    bitcount,
                    length_codes.codewords[length],
                    length_codes.lens[length]
                );
                // Offset symbol.
                add_bits!(
                    bitbuf,
                    bitcount,
                    codes.offset[offset_slot],
                    codes.lens[LENS_OFFSET + offset_slot]
                );
                // Extra offset bits.
                add_bits!(
                    bitbuf,
                    bitcount,
                    offset - DEFLATE_OFFSET_SLOT_BASE[offset_slot],
                    DEFLATE_EXTRA_OFFSET_BITS[offset_slot]
                );
                flush_bits!(out, out_next, out_fast_end, bitbuf, bitcount);
            }};
        }

        match items {
            BlockItems::Path(nodes, offset_slot_full) => {
                // Output the literals and matches from the minimum-cost
                // path.
                let mut cur_node = 0;
                loop {
                    let item = nodes[cur_node].item;
                    let length = item & OPTIMUM_LEN_MASK;
                    let offset = item >> OPTIMUM_OFFSET_SHIFT;

                    if length == 1 {
                        // Literal.
                        let lit = offset as usize & 0xFF;
                        add_bits!(bitbuf, bitcount, codes.litlen[lit], codes.lens[lit]);
                        flush_bits!(out, out_next, out_fast_end, bitbuf, bitcount);
                    } else {
                        // Match.
                        write_match!(length, offset, offset_slot_full[offset as usize]);
                    }
                    cur_node += length as usize;
                    if cur_node == block_length {
                        break;
                    }
                }
            }
            BlockItems::Sequences(sequences) => {
                // Output the literals and matches from the sequences list.
                const _: () = assert!(can_buffer(4 * MAX_LITLEN_CODEWORD_LEN));
                for seq in sequences {
                    let mut litrunlen = (seq.litrunlen_and_length & SEQ_LITRUNLEN_MASK) as usize;
                    let length = seq.litrunlen_and_length >> SEQ_LENGTH_SHIFT;

                    // Output a run of literals.
                    let run = &input[in_next..in_next + litrunlen];
                    in_next += litrunlen;
                    let (quads, rest) = run.as_chunks::<4>();
                    for quad in quads {
                        for &lit in quad {
                            let lit = lit as usize;
                            add_bits!(bitbuf, bitcount, codes.litlen[lit], codes.lens[lit]);
                        }
                        flush_bits!(out, out_next, out_fast_end, bitbuf, bitcount);
                    }
                    litrunlen = rest.len();
                    if litrunlen != 0 {
                        for &lit in rest {
                            let lit = lit as usize;
                            add_bits!(bitbuf, bitcount, codes.litlen[lit], codes.lens[lit]);
                        }
                        flush_bits!(out, out_next, out_fast_end, bitbuf, bitcount);
                    }

                    if length == 0 {
                        // Last sequence?
                        debug_assert!(in_next == in_end);
                        break;
                    }

                    // Output a match.
                    write_match!(length, seq.offset, seq.offset_slot);
                    in_next += length as usize;
                }
            }
        }

        // Output the end-of-block symbol.
        debug_assert!(bitcount <= 7);
        add_bits!(
            bitbuf,
            bitcount,
            codes.litlen[DEFLATE_END_OF_BLOCK],
            codes.lens[DEFLATE_END_OF_BLOCK]
        );
        flush_bits!(out, out_next, out_fast_end, bitbuf, bitcount);
    }
    debug_assert!(bitcount <= 7);
    // The block cost was computed correctly: the bounds check above relies
    // on it, and so does libdeflate_deflate_compress_bound().
    debug_assert!(
        8 * (out_next - os.next) as u64 + u64::from(bitcount) - u64::from(os.bitcount)
            == u64::from(best_cost)
    );
    os.bitbuf = bitbuf;
    os.bitcount = bitcount;
    os.next = out_next;
}

/// `deflate_finish_block`: count the end-of-block symbol, make the
/// block's codes and write it.
#[allow(clippy::too_many_arguments)]
fn deflate_finish_block(
    c: &mut State,
    os: &mut OutputBitstream,
    out: &mut [u8],
    input: &[u8],
    block_begin: usize,
    block_length: usize,
    sequences: &[DeflateSequence],
    is_final_block: bool,
) {
    c.freqs.litlen[DEFLATE_END_OF_BLOCK] += 1;
    deflate_make_huffman_codes(&c.freqs, &mut c.codes);
    deflate_flush_block(
        c,
        os,
        out,
        input,
        block_begin,
        block_length,
        BlockItems::Sequences(sequences),
        is_final_block,
    );
}

/******************************************************************************/

// Block splitting algorithm. The problem is to decide when it is worthwhile
// to start a new block with new Huffman codes. As an approximation, we count
// symbols and after every N symbols, compare the expected distribution of
// symbols based on the previous data with the actual distribution. If they
// differ "by enough", then start a new block.
//
// As an optimization and heuristic, we don't distinguish between every
// symbol but rather we combine many symbols into a single "observation
// type". For literals we only look at the high bits and low bits, and for
// matches we only look at whether the match is long or not.
//
// For determining whether the probability distributions are "different
// enough" to start a new block, the simple heuristic of splitting when the
// sum of absolute differences exceeds a constant seems to be good enough. We
// also add a number proportional to the block length so that the algorithm
// is more likely to end long blocks than short blocks.

/// `init_block_split_stats`: initialize the block split statistics when
/// starting a new block.
fn init_block_split_stats(stats: &mut BlockSplitStats) {
    stats.new_observations.fill(0);
    stats.observations.fill(0);
    stats.num_new_observations = 0;
    stats.num_observations = 0;
}

/// `observe_literal`: literal observation. Heuristic: use the top 2 bits
/// and low 1 bits of the literal, for 8 possible literal observation types.
#[inline(always)]
fn observe_literal(stats: &mut BlockSplitStats, lit: u8) {
    stats.new_observations[usize::from(((lit >> 5) & 0x6) | (lit & 1))] += 1;
    stats.num_new_observations += 1;
}

/// `observe_match`: match observation. Heuristic: use one observation type
/// for "short match" and one observation type for "long match".
#[inline(always)]
fn observe_match(stats: &mut BlockSplitStats, length: u32) {
    stats.new_observations[NUM_LITERAL_OBSERVATION_TYPES + usize::from(length >= 9)] += 1;
    stats.num_new_observations += 1;
}

/// `merge_new_observations`.
fn merge_new_observations(stats: &mut BlockSplitStats) {
    for i in 0..NUM_OBSERVATION_TYPES {
        stats.observations[i] = stats.observations[i].wrapping_add(stats.new_observations[i]);
        stats.new_observations[i] = 0;
    }
    stats.num_observations = stats
        .num_observations
        .wrapping_add(stats.num_new_observations);
    stats.num_new_observations = 0;
}

/// `do_end_block_check`: whether the new observations differ enough from
/// the block's so far to end it; if not, they become the block's.
fn do_end_block_check(stats: &mut BlockSplitStats, block_length: u32) -> bool {
    if stats.num_observations > 0 {
        // Compute the sum of absolute differences of probabilities. To
        // avoid needing to use floating point arithmetic or do slow
        // divisions, we do all arithmetic with the probabilities multiplied
        // by num_observations * num_new_observations.
        let mut total_delta: u32 = 0;
        for i in 0..NUM_OBSERVATION_TYPES {
            let expected = stats.observations[i].wrapping_mul(stats.num_new_observations);
            let actual = stats.new_observations[i].wrapping_mul(stats.num_observations);
            let delta = actual.abs_diff(expected);
            total_delta = total_delta.wrapping_add(delta);
        }

        let num_items = stats
            .num_observations
            .wrapping_add(stats.num_new_observations);
        // Heuristic: the cutoff is when the sum of absolute differences of
        // probabilities becomes at least 200/512. As above, the probability
        // is multiplied by both num_new_observations and num_observations.
        // Be careful to avoid integer overflow.
        let mut cutoff = (stats.num_new_observations.wrapping_mul(200) / 512)
            .wrapping_mul(stats.num_observations);
        // Very short blocks have a lot of overhead for the Huffman codes,
        // so only use them if it clearly seems worthwhile. (This is an
        // additional penalty, which adds to the smaller penalty below which
        // scales more slowly.)
        if block_length < 10000 && num_items < 8192 {
            cutoff = cutoff
                .wrapping_add((u64::from(cutoff) * u64::from(8192 - num_items) / 8192) as u32);
        }

        // Ready to end the block?
        if total_delta.wrapping_add((block_length / 4096).wrapping_mul(stats.num_observations))
            >= cutoff
        {
            return true;
        }
    }
    merge_new_observations(stats);
    false
}

/// `ready_to_check_block`.
#[inline(always)]
fn ready_to_check_block(
    stats: &BlockSplitStats,
    in_block_begin: usize,
    in_next: usize,
    in_end: usize,
) -> bool {
    stats.num_new_observations >= NUM_OBSERVATIONS_PER_BLOCK_CHECK
        && in_next - in_block_begin >= MIN_BLOCK_LENGTH
        && in_end - in_next >= MIN_BLOCK_LENGTH
}

/// `should_end_block`.
#[inline(always)]
fn should_end_block(
    stats: &mut BlockSplitStats,
    in_block_begin: usize,
    in_next: usize,
    in_end: usize,
) -> bool {
    // Ready to try to end the block (again)?
    if !ready_to_check_block(stats, in_block_begin, in_next, in_end) {
        return false;
    }
    do_end_block_check(stats, (in_next - in_block_begin) as u32)
}

/******************************************************************************/

/// `deflate_begin_sequences`.
fn deflate_begin_sequences(c: &mut State, first_seq: &mut DeflateSequence) {
    c.deflate_reset_symbol_frequencies();
    first_seq.litrunlen_and_length = 0;
}

/// `deflate_choose_literal`.
#[inline(always)]
fn deflate_choose_literal(
    c: &mut State,
    literal: u8,
    gather_split_stats: bool,
    seq: &mut DeflateSequence,
) {
    c.freqs.litlen[literal as usize] += 1;
    if gather_split_stats {
        observe_literal(&mut c.split_stats, literal);
    }
    const _: () = assert!(MAX_BLOCK_LENGTH <= SEQ_LITRUNLEN_MASK as usize);
    seq.litrunlen_and_length += 1;
}

/// `deflate_choose_match`: the match ends the sequence `*seq_p` and the
/// next one begins.
#[inline(always)]
fn deflate_choose_match(
    c: &mut State,
    length: u32,
    offset: u32,
    gather_split_stats: bool,
    sequences: &mut [DeflateSequence],
    seq_p: &mut usize,
) {
    let length_slot = DEFLATE_LENGTH_SLOT[length as usize] as usize;
    let offset_slot = deflate_get_offset_slot(offset);

    c.freqs.litlen[DEFLATE_FIRST_LEN_SYM + length_slot] += 1;
    c.freqs.offset[offset_slot as usize & (DEFLATE_NUM_OFFSET_SYMS - 1)] += 1;
    if gather_split_stats {
        observe_match(&mut c.split_stats, length);
    }

    let seq = &mut sequences[*seq_p];
    seq.litrunlen_and_length |= length << SEQ_LENGTH_SHIFT;
    seq.offset = offset as u16;
    seq.offset_slot = offset_slot as u16;

    *seq_p += 1;
    sequences[*seq_p].litrunlen_and_length = 0;
}

/// `adjust_max_and_nice_len`: decrease the maximum and nice match lengths
/// if we're approaching the end of the input buffer.
#[inline(always)]
fn adjust_max_and_nice_len(max_len: &mut u32, nice_len: &mut u32, remaining: usize) {
    if remaining < DEFLATE_MAX_MATCH_LEN as usize {
        *max_len = remaining as u32;
        *nice_len = (*nice_len).min(*max_len);
    }
}

/// `choose_min_match_len`: the minimum match length for the greedy and
/// lazy parsers, from how many different literals the data has: few
/// literals are cheap, and short matches then not worth it.
fn choose_min_match_len(num_used_literals: u32, max_search_depth: u32) -> u32 {
    // map from num_used_literals to min_len
    #[rustfmt::skip]
    const MIN_LENS: [u8; 80] = [
        9, 9, 9, 9, 9, 9, 8, 8, 7, 7, 6, 6, 6, 6, 6, 6,
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 4, 4, 4,
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
        // The rest is implicitly 3.
    ];
    const _: () = assert!(DEFLATE_MIN_MATCH_LEN <= 3);
    const _: () = assert!(MIN_LENS.len() <= DEFLATE_NUM_LITERALS + 1);

    if num_used_literals as usize >= MIN_LENS.len() {
        return 3;
    }
    let mut min_len = u32::from(MIN_LENS[num_used_literals as usize]);
    // With a low max_search_depth, it may be too hard to find long matches.
    if max_search_depth < 16 {
        if max_search_depth < 5 {
            min_len = min_len.min(4);
        } else if max_search_depth < 10 {
            min_len = min_len.min(5);
        } else {
            min_len = min_len.min(7);
        }
    }
    min_len
}

/// `calculate_min_match_len`: `choose_min_match_len` from the literals in
/// the first 4 KiB of `data`; 3 for less than 512 bytes, where the static
/// code may well be best.
fn calculate_min_match_len(data: &[u8], data_len: usize, max_search_depth: u32) -> u32 {
    let mut used = [0u8; 256];
    let mut num_used_literals = 0u32;

    // For very short inputs, the static Huffman code has a good chance of
    // being best, in which case there is no reason to avoid short matches.
    if data_len < 512 {
        return DEFLATE_MIN_MATCH_LEN;
    }

    // For an initial approximation, scan the first 4 KiB of data. The
    // caller may use recalculate_min_match_len() to update min_len later.
    for &byte in &data[..data_len.min(4096)] {
        used[byte as usize] = 1;
    }
    for &u in &used {
        num_used_literals += u32::from(u);
    }
    choose_min_match_len(num_used_literals, max_search_depth)
}

/// `recalculate_min_match_len`: `choose_min_match_len` from the literals
/// the block used, ignoring those used very rarely.
fn recalculate_min_match_len(freqs: &DeflateFreqs, max_search_depth: u32) -> u32 {
    let mut literal_freq: u32 = 0;
    let mut num_used_literals = 0;

    for &freq in &freqs.litlen[..DEFLATE_NUM_LITERALS] {
        literal_freq = literal_freq.wrapping_add(freq);
    }

    let cutoff = literal_freq >> 10; // Ignore literals used very rarely.

    for &freq in &freqs.litlen[..DEFLATE_NUM_LITERALS] {
        if freq > cutoff {
            num_used_literals += 1;
        }
    }
    choose_min_match_len(num_used_literals, max_search_depth)
}

/// `choose_max_block_end`.
#[inline(always)]
fn choose_max_block_end(in_block_begin: usize, in_end: usize, soft_max_len: usize) -> usize {
    if in_end - in_block_begin < soft_max_len + MIN_BLOCK_LENGTH {
        return in_end;
    }
    in_block_begin + soft_max_len
}

/// `deflate_compress_none`: the level 0 "compressor", which always outputs
/// uncompressed blocks.
///
/// Differs from libdeflate: the last block has BFINAL set only if `last`
/// says it ends the stream, as [`deflate_flush_block`] does. Empty, and not
/// the last, the block it writes is a sync marker.
fn deflate_compress_none(input: &[u8], out: &mut [u8], last: bool) -> usize {
    let in_end = input.len();
    let out_end = out.len();
    let mut in_next = 0;
    let mut out_next = 0;

    // If the input is zero-length, we still must output a block in order
    // for the output to be a valid DEFLATE stream.
    if input.is_empty() {
        if out.len() < 5 {
            return 0;
        }
        // BFINAL and BTYPE, then LEN and NLEN.
        out[0] = u8::from(last) | (DEFLATE_BLOCKTYPE_UNCOMPRESSED << 1);
        out[1..5].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());
        return 5;
    }

    loop {
        let mut bfinal = 0;
        let mut len = u16::MAX as usize;

        if in_end - in_next <= u16::MAX as usize {
            bfinal = u8::from(last);
            len = in_end - in_next;
        }
        if out_end - out_next < 5 + len {
            return 0;
        }
        // Output BFINAL and BTYPE. The stream is already byte-aligned here,
        // so this step always requires outputting exactly 1 byte.
        out[out_next] = bfinal | (DEFLATE_BLOCKTYPE_UNCOMPRESSED << 1);
        out_next += 1;

        // Output LEN and NLEN, then the data itself.
        out[out_next..out_next + 2].copy_from_slice(&(len as u16).to_le_bytes());
        out_next += 2;
        out[out_next..out_next + 2].copy_from_slice(&(!(len as u16)).to_le_bytes());
        out_next += 2;
        out[out_next..out_next + len].copy_from_slice(&input[in_next..in_next + len]);
        out_next += len;
        in_next += len;
        if in_next == in_end {
            break;
        }
    }

    out_next
}

/// `deflate_compress_fastest`: a faster variant of
/// `deflate_compress_greedy`, with the `ht_matchfinder`, blocks of a fixed
/// length and no block splitting.
fn deflate_compress_fastest(
    c: &mut State,
    f: &mut Fastest,
    input: &[u8],
    os: &mut OutputBitstream,
    out: &mut [u8],
) {
    let mut in_next = 0;
    let in_end = input.len();
    let mut in_cur_base = in_next;
    let mut max_len = DEFLATE_MAX_MATCH_LEN;
    let mut nice_len = c.nice_match_length.min(max_len);
    let mut next_hash = 0;

    f.ht_mf.init();

    loop {
        // Starting a new DEFLATE block.
        let in_block_begin = in_next;
        let in_max_block_end = choose_max_block_end(in_next, in_end, FAST_SOFT_MAX_BLOCK_LENGTH);
        let sequences = &mut f.sequences;
        let mut seq = 0;

        deflate_begin_sequences(c, &mut sequences[seq]);

        loop {
            let mut offset = 0;
            let remaining = in_end - in_next;

            if remaining < DEFLATE_MAX_MATCH_LEN as usize {
                max_len = remaining as u32;
                if max_len < HT_MATCHFINDER_REQUIRED_NBYTES {
                    loop {
                        deflate_choose_literal(c, input[in_next], false, &mut sequences[seq]);
                        in_next += 1;
                        max_len -= 1;
                        if max_len == 0 {
                            break;
                        }
                    }
                    break;
                }
                nice_len = nice_len.min(max_len);
            }
            let length = f.ht_mf.longest_match(
                input,
                &mut in_cur_base,
                in_next,
                max_len,
                nice_len,
                &mut next_hash,
                &mut offset,
            );
            if length != 0 {
                // Match found.
                deflate_choose_match(c, length, offset, false, sequences, &mut seq);
                f.ht_mf.skip_bytes(
                    input,
                    &mut in_cur_base,
                    in_next + 1,
                    in_end,
                    length - 1,
                    &mut next_hash,
                );
                in_next += length as usize;
            } else {
                // No match found.
                deflate_choose_literal(c, input[in_next], false, &mut sequences[seq]);
                in_next += 1;
            }

            // Check if it's time to output another block.
            if !(in_next < in_max_block_end && seq < FAST_SEQ_STORE_LENGTH) {
                break;
            }
        }

        deflate_finish_block(
            c,
            os,
            out,
            input,
            in_block_begin,
            in_next - in_block_begin,
            &f.sequences,
            in_next == in_end,
        );
        if !(in_next != in_end && !os.overflow) {
            break;
        }
    }
}

/// `deflate_compress_greedy`: the "greedy" DEFLATE compressor. It always
/// chooses the longest match.
fn deflate_compress_greedy(
    c: &mut State,
    g: &mut Greedy,
    input: &[u8],
    os: &mut OutputBitstream,
    out: &mut [u8],
) {
    let mut in_next = 0;
    let in_end = input.len();
    let mut in_cur_base = in_next;
    let mut max_len = DEFLATE_MAX_MATCH_LEN;
    let mut nice_len = c.nice_match_length.min(max_len);
    let mut next_hashes = [0u32; 2];

    g.hc_mf.init();

    loop {
        // Starting a new DEFLATE block.
        let in_block_begin = in_next;
        let in_max_block_end = choose_max_block_end(in_next, in_end, SOFT_MAX_BLOCK_LENGTH);
        let sequences = &mut g.sequences;
        let mut seq = 0;

        init_block_split_stats(&mut c.split_stats);
        deflate_begin_sequences(c, &mut sequences[seq]);
        let min_len = calculate_min_match_len(
            &input[in_next..],
            in_max_block_end - in_next,
            c.max_search_depth,
        );
        loop {
            let mut offset = 0;

            adjust_max_and_nice_len(&mut max_len, &mut nice_len, in_end - in_next);
            let length = g.hc_mf.longest_match(
                input,
                &mut in_cur_base,
                in_next,
                min_len - 1,
                max_len,
                nice_len,
                c.max_search_depth,
                &mut next_hashes,
                &mut offset,
            );

            if length >= min_len && (length > DEFLATE_MIN_MATCH_LEN || offset <= 4096) {
                // Match found.
                deflate_choose_match(c, length, offset, true, sequences, &mut seq);
                g.hc_mf.skip_bytes(
                    input,
                    &mut in_cur_base,
                    in_next + 1,
                    in_end,
                    length - 1,
                    &mut next_hashes,
                );
                in_next += length as usize;
            } else {
                // No match found.
                deflate_choose_literal(c, input[in_next], true, &mut sequences[seq]);
                in_next += 1;
            }

            // Check if it's time to output another block.
            if !(in_next < in_max_block_end
                && seq < SEQ_STORE_LENGTH
                && !should_end_block(&mut c.split_stats, in_block_begin, in_next, in_end))
            {
                break;
            }
        }

        deflate_finish_block(
            c,
            os,
            out,
            input,
            in_block_begin,
            in_next - in_block_begin,
            &g.sequences,
            in_next == in_end,
        );
        if !(in_next != in_end && !os.overflow) {
            break;
        }
    }
}

/// `deflate_compress_lazy_generic`: before choosing a match, look for a
/// better one at the next position (and, if `LAZY2`, the one after), and
/// if there is one, output a literal (or two) instead.
fn deflate_compress_lazy_generic<const LAZY2: bool>(
    c: &mut State,
    g: &mut Greedy,
    input: &[u8],
    os: &mut OutputBitstream,
    out: &mut [u8],
) {
    let mut in_next = 0;
    let in_end = input.len();
    let mut in_cur_base = in_next;
    let mut max_len = DEFLATE_MAX_MATCH_LEN;
    let mut nice_len = c.nice_match_length.min(max_len);
    let mut next_hashes = [0u32; 2];

    g.hc_mf.init();

    loop {
        // Starting a new DEFLATE block.
        let in_block_begin = in_next;
        let in_max_block_end = choose_max_block_end(in_next, in_end, SOFT_MAX_BLOCK_LENGTH);
        let mut next_recalc_min_len = in_next + (in_end - in_next).min(10000);
        let sequences = &mut g.sequences;
        let mut seq = 0;

        init_block_split_stats(&mut c.split_stats);
        deflate_begin_sequences(c, &mut sequences[seq]);
        let mut min_len = calculate_min_match_len(
            &input[in_next..],
            in_max_block_end - in_next,
            c.max_search_depth,
        );
        loop {
            'next: {
                let mut cur_offset = 0;
                let mut next_offset = 0;

                // Recalculate the minimum match length if it hasn't been
                // done recently.
                if in_next >= next_recalc_min_len {
                    min_len = recalculate_min_match_len(&c.freqs, c.max_search_depth);
                    next_recalc_min_len +=
                        (in_end - next_recalc_min_len).min(in_next - in_block_begin);
                }

                // Find the longest match at the current position.
                adjust_max_and_nice_len(&mut max_len, &mut nice_len, in_end - in_next);
                let mut cur_len = g.hc_mf.longest_match(
                    input,
                    &mut in_cur_base,
                    in_next,
                    min_len - 1,
                    max_len,
                    nice_len,
                    c.max_search_depth,
                    &mut next_hashes,
                    &mut cur_offset,
                );
                if cur_len < min_len || (cur_len == DEFLATE_MIN_MATCH_LEN && cur_offset > 8192) {
                    // No match found. Choose a literal.
                    deflate_choose_literal(c, input[in_next], true, &mut sequences[seq]);
                    in_next += 1;
                    break 'next;
                }
                in_next += 1;

                // have_cur_match:
                loop {
                    // We have a match at the current position. If it's very
                    // long, choose it immediately.
                    if cur_len >= nice_len {
                        deflate_choose_match(c, cur_len, cur_offset, true, sequences, &mut seq);
                        g.hc_mf.skip_bytes(
                            input,
                            &mut in_cur_base,
                            in_next,
                            in_end,
                            cur_len - 1,
                            &mut next_hashes,
                        );
                        in_next += cur_len as usize - 1;
                        break 'next;
                    }

                    // Try to find a better match at the next position.
                    //
                    // Note: since we already have a match at the *current*
                    // position, we use only half the 'max_search_depth' when
                    // checking the *next* position. This is a useful
                    // trade-off because it's more worthwhile to use a
                    // greater search depth on the initial match.
                    adjust_max_and_nice_len(&mut max_len, &mut nice_len, in_end - in_next);
                    let mut next_len = g.hc_mf.longest_match(
                        input,
                        &mut in_cur_base,
                        in_next,
                        cur_len - 1,
                        max_len,
                        nice_len,
                        c.max_search_depth >> 1,
                        &mut next_hashes,
                        &mut next_offset,
                    );
                    in_next += 1;
                    if next_len >= cur_len
                        && 4 * (next_len - cur_len) as i32
                            + (bsr32(cur_offset) as i32 - bsr32(next_offset) as i32)
                            > 2
                    {
                        // Found a better match at the next position. Output
                        // a literal. Then the next match becomes the current
                        // match.
                        deflate_choose_literal(c, input[in_next - 2], true, &mut sequences[seq]);
                        cur_len = next_len;
                        cur_offset = next_offset;
                        continue;
                    }

                    if LAZY2 {
                        // In lazy2 mode, look ahead another position.
                        adjust_max_and_nice_len(&mut max_len, &mut nice_len, in_end - in_next);
                        next_len = g.hc_mf.longest_match(
                            input,
                            &mut in_cur_base,
                            in_next,
                            cur_len - 1,
                            max_len,
                            nice_len,
                            c.max_search_depth >> 2,
                            &mut next_hashes,
                            &mut next_offset,
                        );
                        in_next += 1;
                        if next_len >= cur_len
                            && 4 * (next_len - cur_len) as i32
                                + (bsr32(cur_offset) as i32 - bsr32(next_offset) as i32)
                                > 6
                        {
                            // There's a much better match two positions
                            // ahead, so use two literals.
                            deflate_choose_literal(
                                c,
                                input[in_next - 3],
                                true,
                                &mut sequences[seq],
                            );
                            deflate_choose_literal(
                                c,
                                input[in_next - 2],
                                true,
                                &mut sequences[seq],
                            );
                            cur_len = next_len;
                            cur_offset = next_offset;
                            continue;
                        }
                        // No better match at either of the next 2 positions.
                        // Output the current match.
                        deflate_choose_match(c, cur_len, cur_offset, true, sequences, &mut seq);
                        if cur_len > 3 {
                            g.hc_mf.skip_bytes(
                                input,
                                &mut in_cur_base,
                                in_next,
                                in_end,
                                cur_len - 3,
                                &mut next_hashes,
                            );
                            in_next += cur_len as usize - 3;
                        }
                    } else {
                        // No better match at the next position. Output the
                        // current match.
                        deflate_choose_match(c, cur_len, cur_offset, true, sequences, &mut seq);
                        g.hc_mf.skip_bytes(
                            input,
                            &mut in_cur_base,
                            in_next,
                            in_end,
                            cur_len - 2,
                            &mut next_hashes,
                        );
                        in_next += cur_len as usize - 2;
                    }
                    break;
                }
            }
            // Check if it's time to output another block.
            if !(in_next < in_max_block_end
                && seq < SEQ_STORE_LENGTH
                && !should_end_block(&mut c.split_stats, in_block_begin, in_next, in_end))
            {
                break;
            }
        }

        deflate_finish_block(
            c,
            os,
            out,
            input,
            in_block_begin,
            in_next - in_block_begin,
            &g.sequences,
            in_next == in_end,
        );
        if !(in_next != in_end && !os.overflow) {
            break;
        }
    }
}

/// `deflate_tally_item_list`: the frequencies of the Huffman symbols the
/// minimum-cost path takes, and the end-of-block symbol.
fn deflate_tally_item_list(c: &mut State, n: &NearOptimal, block_length: usize) {
    let mut cur_node = 0;
    loop {
        let item = n.optimum_nodes[cur_node].item;
        let length = item & OPTIMUM_LEN_MASK;
        let offset = item >> OPTIMUM_OFFSET_SHIFT;

        if length == 1 {
            // Literal.
            c.freqs.litlen[offset as usize & 0xFF] += 1;
        } else {
            // Match.
            c.freqs.litlen
                [DEFLATE_FIRST_LEN_SYM + DEFLATE_LENGTH_SLOT[length as usize] as usize] += 1;
            c.freqs.offset[n.offset_slot_full[offset as usize] as usize] += 1;
        }
        cur_node += length as usize;
        if cur_node == block_length {
            break;
        }
    }

    // Tally the end-of-block symbol.
    c.freqs.litlen[DEFLATE_END_OF_BLOCK] += 1;
}

/// `deflate_choose_all_literals`: the codes of a block of only literals.
fn deflate_choose_all_literals(c: &mut State, block: &[u8]) {
    c.deflate_reset_symbol_frequencies();
    for &byte in block {
        c.freqs.litlen[byte as usize] += 1;
    }
    c.freqs.litlen[DEFLATE_END_OF_BLOCK] += 1;

    deflate_make_huffman_codes(&c.freqs, &mut c.codes);
}

/// `deflate_compute_true_cost`: the exact cost, in bits, of the literals
/// and matches of `c.freqs` as a dynamic Huffman block, with the codes
/// already in `c.codes`.
fn deflate_compute_true_cost(c: &mut State) -> u32 {
    let mut cost: u32 = 0;

    deflate_precompute_huffman_header(c);

    c.codes.lens[c.precode.num_litlen_syms..DEFLATE_NUM_LITLEN_SYMS].fill(0);

    let pre = &c.precode;
    cost = cost.wrapping_add(5 + 5 + 4 + (3 * pre.num_explicit_lens as u32));
    for sym in 0..DEFLATE_NUM_PRECODE_SYMS {
        cost =
            cost.wrapping_add(pre.freqs[sym].wrapping_mul(
                u32::from(pre.lens[sym]) + u32::from(DEFLATE_EXTRA_PRECODE_BITS[sym]),
            ));
    }

    for sym in 0..DEFLATE_FIRST_LEN_SYM {
        cost = cost.wrapping_add(c.freqs.litlen[sym].wrapping_mul(u32::from(c.codes.lens[sym])));
    }

    for sym in DEFLATE_FIRST_LEN_SYM..DEFLATE_FIRST_LEN_SYM + DEFLATE_EXTRA_LENGTH_BITS.len() {
        cost = cost.wrapping_add(c.freqs.litlen[sym].wrapping_mul(
            u32::from(c.codes.lens[sym])
                + u32::from(DEFLATE_EXTRA_LENGTH_BITS[sym - DEFLATE_FIRST_LEN_SYM]),
        ));
    }

    for sym in 0..DEFLATE_EXTRA_OFFSET_BITS.len() {
        cost = cost.wrapping_add(c.freqs.offset[sym].wrapping_mul(
            u32::from(c.codes.lens[LENS_OFFSET + sym]) + u32::from(DEFLATE_EXTRA_OFFSET_BITS[sym]),
        ));
    }
    cost
}

/// `deflate_set_costs_from_codes`: the cost model from the codeword
/// lengths `lens`.
fn deflate_set_costs_from_codes(costs: &mut DeflateCosts, lens: &[u8; LENS_OFFSET + 32]) {
    // Literals.
    for i in 0..DEFLATE_NUM_LITERALS {
        let bits = if lens[i] != 0 {
            u32::from(lens[i])
        } else {
            LITERAL_NOSTAT_BITS
        };
        costs.literal[i] = bits * BIT_COST;
    }

    // Lengths.
    for i in DEFLATE_MIN_MATCH_LEN as usize..=DEFLATE_MAX_MATCH_LEN as usize {
        let length_slot = DEFLATE_LENGTH_SLOT[i] as usize;
        let litlen_sym = DEFLATE_FIRST_LEN_SYM + length_slot;
        let mut bits = if lens[litlen_sym] != 0 {
            u32::from(lens[litlen_sym])
        } else {
            LENGTH_NOSTAT_BITS
        };
        bits += u32::from(DEFLATE_EXTRA_LENGTH_BITS[length_slot]);
        costs.length[i] = bits * BIT_COST;
    }

    // Offset slots.
    for i in 0..DEFLATE_OFFSET_SLOT_BASE.len() {
        let len = lens[LENS_OFFSET + i];
        let mut bits = if len != 0 {
            u32::from(len)
        } else {
            OFFSET_NOSTAT_BITS
        };
        bits += u32::from(DEFLATE_EXTRA_OFFSET_BITS[i]);
        costs.offset_slot[i] = bits * BIT_COST;
    }
}

/// `default_litlen_costs`: the default cost of a literal and of a length
/// symbol, by the estimated match probability (0.25, 0.5, 0.75): a
/// literal's by the number of distinct literals used (0 to 256),
/// `int(-log2((1 - match_prob) / num_used_literals) * BIT_COST)`, and a
/// length symbol's, `int(-log2(match_prob/NUM_LEN_SLOTS) * BIT_COST)`.
/// libdeflate's `scripts/gen_default_litlen_costs.py` wrote the table.
struct DefaultLitlenCosts {
    used_lits_to_lit_cost: [u8; 257],
    len_sym_cost: u8,
}

#[rustfmt::skip]
static DEFAULT_LITLEN_COSTS: [DefaultLitlenCosts; 3] = [
    DefaultLitlenCosts { // match_prob = 0.25
        used_lits_to_lit_cost: [
            6, 6, 22, 32, 38, 43, 48, 51,
            54, 57, 59, 61, 64, 65, 67, 69,
            70, 72, 73, 74, 75, 76, 77, 79,
            80, 80, 81, 82, 83, 84, 85, 85,
            86, 87, 88, 88, 89, 89, 90, 91,
            91, 92, 92, 93, 93, 94, 95, 95,
            96, 96, 96, 97, 97, 98, 98, 99,
            99, 99, 100, 100, 101, 101, 101, 102,
            102, 102, 103, 103, 104, 104, 104, 105,
            105, 105, 105, 106, 106, 106, 107, 107,
            107, 108, 108, 108, 108, 109, 109, 109,
            109, 110, 110, 110, 111, 111, 111, 111,
            112, 112, 112, 112, 112, 113, 113, 113,
            113, 114, 114, 114, 114, 114, 115, 115,
            115, 115, 115, 116, 116, 116, 116, 116,
            117, 117, 117, 117, 117, 118, 118, 118,
            118, 118, 118, 119, 119, 119, 119, 119,
            120, 120, 120, 120, 120, 120, 121, 121,
            121, 121, 121, 121, 121, 122, 122, 122,
            122, 122, 122, 123, 123, 123, 123, 123,
            123, 123, 124, 124, 124, 124, 124, 124,
            124, 125, 125, 125, 125, 125, 125, 125,
            125, 126, 126, 126, 126, 126, 126, 126,
            127, 127, 127, 127, 127, 127, 127, 127,
            128, 128, 128, 128, 128, 128, 128, 128,
            128, 129, 129, 129, 129, 129, 129, 129,
            129, 129, 130, 130, 130, 130, 130, 130,
            130, 130, 130, 131, 131, 131, 131, 131,
            131, 131, 131, 131, 131, 132, 132, 132,
            132, 132, 132, 132, 132, 132, 132, 133,
            133, 133, 133, 133, 133, 133, 133, 133,
            133, 134, 134, 134, 134, 134, 134, 134,
            134,
        ],
        len_sym_cost: 109,
    },
    DefaultLitlenCosts { // match_prob = 0.5
        used_lits_to_lit_cost: [
            16, 16, 32, 41, 48, 53, 57, 60,
            64, 66, 69, 71, 73, 75, 76, 78,
            80, 81, 82, 83, 85, 86, 87, 88,
            89, 90, 91, 92, 92, 93, 94, 95,
            96, 96, 97, 98, 98, 99, 99, 100,
            101, 101, 102, 102, 103, 103, 104, 104,
            105, 105, 106, 106, 107, 107, 108, 108,
            108, 109, 109, 110, 110, 110, 111, 111,
            112, 112, 112, 113, 113, 113, 114, 114,
            114, 115, 115, 115, 115, 116, 116, 116,
            117, 117, 117, 118, 118, 118, 118, 119,
            119, 119, 119, 120, 120, 120, 120, 121,
            121, 121, 121, 122, 122, 122, 122, 122,
            123, 123, 123, 123, 124, 124, 124, 124,
            124, 125, 125, 125, 125, 125, 126, 126,
            126, 126, 126, 127, 127, 127, 127, 127,
            128, 128, 128, 128, 128, 128, 129, 129,
            129, 129, 129, 129, 130, 130, 130, 130,
            130, 130, 131, 131, 131, 131, 131, 131,
            131, 132, 132, 132, 132, 132, 132, 133,
            133, 133, 133, 133, 133, 133, 134, 134,
            134, 134, 134, 134, 134, 134, 135, 135,
            135, 135, 135, 135, 135, 135, 136, 136,
            136, 136, 136, 136, 136, 136, 137, 137,
            137, 137, 137, 137, 137, 137, 138, 138,
            138, 138, 138, 138, 138, 138, 138, 139,
            139, 139, 139, 139, 139, 139, 139, 139,
            140, 140, 140, 140, 140, 140, 140, 140,
            140, 141, 141, 141, 141, 141, 141, 141,
            141, 141, 141, 142, 142, 142, 142, 142,
            142, 142, 142, 142, 142, 142, 143, 143,
            143, 143, 143, 143, 143, 143, 143, 143,
            144,
        ],
        len_sym_cost: 93,
    },
    DefaultLitlenCosts { // match_prob = 0.75
        used_lits_to_lit_cost: [
            32, 32, 48, 57, 64, 69, 73, 76,
            80, 82, 85, 87, 89, 91, 92, 94,
            96, 97, 98, 99, 101, 102, 103, 104,
            105, 106, 107, 108, 108, 109, 110, 111,
            112, 112, 113, 114, 114, 115, 115, 116,
            117, 117, 118, 118, 119, 119, 120, 120,
            121, 121, 122, 122, 123, 123, 124, 124,
            124, 125, 125, 126, 126, 126, 127, 127,
            128, 128, 128, 129, 129, 129, 130, 130,
            130, 131, 131, 131, 131, 132, 132, 132,
            133, 133, 133, 134, 134, 134, 134, 135,
            135, 135, 135, 136, 136, 136, 136, 137,
            137, 137, 137, 138, 138, 138, 138, 138,
            139, 139, 139, 139, 140, 140, 140, 140,
            140, 141, 141, 141, 141, 141, 142, 142,
            142, 142, 142, 143, 143, 143, 143, 143,
            144, 144, 144, 144, 144, 144, 145, 145,
            145, 145, 145, 145, 146, 146, 146, 146,
            146, 146, 147, 147, 147, 147, 147, 147,
            147, 148, 148, 148, 148, 148, 148, 149,
            149, 149, 149, 149, 149, 149, 150, 150,
            150, 150, 150, 150, 150, 150, 151, 151,
            151, 151, 151, 151, 151, 151, 152, 152,
            152, 152, 152, 152, 152, 152, 153, 153,
            153, 153, 153, 153, 153, 153, 154, 154,
            154, 154, 154, 154, 154, 154, 154, 155,
            155, 155, 155, 155, 155, 155, 155, 155,
            156, 156, 156, 156, 156, 156, 156, 156,
            156, 157, 157, 157, 157, 157, 157, 157,
            157, 157, 157, 158, 158, 158, 158, 158,
            158, 158, 158, 158, 158, 158, 159, 159,
            159, 159, 159, 159, 159, 159, 159, 159,
            160,
        ],
        len_sym_cost: 84,
    },
];

/// `deflate_choose_default_litlen_costs`: the default costs of literal and
/// length symbols for a block, from the distinct literals it has and the
/// match frequency of a greedy parse. Returns `(lit_cost, len_sym_cost)`.
fn deflate_choose_default_litlen_costs(c: &mut State, n: &NearOptimal, block: &[u8]) -> (u32, u32) {
    let block_length = block.len() as u32;
    let mut num_used_literals = 0;
    let mut literal_freq = block_length;
    let mut match_freq: u32 = 0;

    // Calculate the number of distinct literals that exist in the data.
    c.freqs.litlen[..DEFLATE_NUM_LITERALS].fill(0);
    let cutoff = literal_freq >> 11; // Ignore literals used very rarely.
    for &byte in block {
        c.freqs.litlen[byte as usize] += 1;
    }
    for &freq in &c.freqs.litlen[..DEFLATE_NUM_LITERALS] {
        if freq > cutoff {
            num_used_literals += 1;
        }
    }
    if num_used_literals == 0 {
        num_used_literals = 1;
    }

    // Estimate the relative frequency of literals and matches in the
    // optimal parsing solution. We don't know the optimal solution, so this
    // can only be a very rough estimate. Therefore, we basically use the
    // match frequency from a greedy parse. We also apply the min_len
    // heuristic used by the greedy and lazy parsers, to avoid counting too
    // many matches when literals are cheaper than short matches.
    let min_len = choose_min_match_len(num_used_literals, c.max_search_depth) as usize;
    for i in min_len..n.match_len_freqs.len() {
        match_freq = match_freq.wrapping_add(n.match_len_freqs[i]);
        literal_freq = literal_freq.wrapping_sub((i as u32).wrapping_mul(n.match_len_freqs[i]));
    }
    if (literal_freq as i32) < 0 {
        // shouldn't happen
        literal_freq = 0;
    }

    let i = if match_freq > literal_freq {
        2 // many matches
    } else if match_freq.wrapping_mul(4) > literal_freq {
        1 // neutral
    } else {
        0 // few matches
    };

    const _: () = assert!(BIT_COST == 16);
    let costs = &DEFAULT_LITLEN_COSTS[i];
    (
        u32::from(costs.used_lits_to_lit_cost[num_used_literals as usize]),
        u32::from(costs.len_sym_cost),
    )
}

/// `deflate_default_length_cost`.
#[inline(always)]
fn deflate_default_length_cost(len: usize, len_sym_cost: u32) -> u32 {
    let slot = DEFLATE_LENGTH_SLOT[len] as usize;
    let num_extra_bits = u32::from(DEFLATE_EXTRA_LENGTH_BITS[slot]);
    len_sym_cost + (num_extra_bits * BIT_COST)
}

/// `deflate_default_offset_slot_cost`: all offset symbols assumed equally
/// probable, `int(-log2(1/30) * BIT_COST)`, and the extra bits.
#[inline(always)]
fn deflate_default_offset_slot_cost(slot: usize) -> u32 {
    let num_extra_bits = u32::from(DEFLATE_EXTRA_OFFSET_BITS[slot]);
    let offset_sym_cost = 4 * BIT_COST + (907 * BIT_COST) / 1000;
    offset_sym_cost + (num_extra_bits * BIT_COST)
}

/// `deflate_set_default_costs`: default symbol costs for the first block's
/// first optimization pass.
fn deflate_set_default_costs(costs: &mut DeflateCosts, lit_cost: u32, len_sym_cost: u32) {
    // Literals.
    costs.literal.fill(lit_cost);

    // Lengths.
    for i in DEFLATE_MIN_MATCH_LEN as usize..=DEFLATE_MAX_MATCH_LEN as usize {
        costs.length[i] = deflate_default_length_cost(i, len_sym_cost);
    }

    // Offset slots.
    for i in 0..DEFLATE_OFFSET_SLOT_BASE.len() {
        costs.offset_slot[i] = deflate_default_offset_slot_cost(i);
    }
}

/// `deflate_adjust_cost`: a cost mixed with the default, the more of the
/// default the more the block differs from the previous one.
#[inline(always)]
fn deflate_adjust_cost(cost_p: &mut u32, default_cost: u32, change_amount: u32) {
    *cost_p = match change_amount {
        // Block is very similar to previous; prefer previous costs.
        0 => (default_cost + 3 * *cost_p) / 4,
        1 => (default_cost + *cost_p) / 2,
        2 => (5 * default_cost + 3 * *cost_p) / 8,
        // Block differs greatly from previous; prefer default costs.
        _ => (3 * default_cost + *cost_p) / 4,
    };
}

/// `deflate_adjust_costs_impl`.
fn deflate_adjust_costs_impl(
    costs: &mut DeflateCosts,
    lit_cost: u32,
    len_sym_cost: u32,
    change_amount: u32,
) {
    // Literals.
    for cost in &mut costs.literal {
        deflate_adjust_cost(cost, lit_cost, change_amount);
    }

    // Lengths.
    for i in DEFLATE_MIN_MATCH_LEN as usize..=DEFLATE_MAX_MATCH_LEN as usize {
        deflate_adjust_cost(
            &mut costs.length[i],
            deflate_default_length_cost(i, len_sym_cost),
            change_amount,
        );
    }

    // Offset slots.
    for i in 0..DEFLATE_OFFSET_SLOT_BASE.len() {
        deflate_adjust_cost(
            &mut costs.offset_slot[i],
            deflate_default_offset_slot_cost(i),
            change_amount,
        );
    }
}

/// `deflate_adjust_costs`: adjust the costs when beginning a new block,
/// mixing the current costs, optimized for the previous block, with the
/// default ones, by how much the block's statistics differ from the
/// previous block's.
fn deflate_adjust_costs(c: &State, n: &mut NearOptimal, lit_cost: u32, len_sym_cost: u32) {
    let mut total_delta: u64 = 0;

    // Decide how different the current block is from the previous block,
    // using the block splitting statistics from the current and previous
    // blocks. The algorithm here is similar to the end-of-block check one,
    // but here we compare two entire blocks rather than a partial block with
    // a small extra part, and therefore we need 64-bit numbers in some
    // places.
    for i in 0..NUM_OBSERVATION_TYPES {
        let prev = u64::from(n.prev_observations[i]) * u64::from(c.split_stats.num_observations);
        let cur = u64::from(c.split_stats.observations[i]) * u64::from(n.prev_num_observations);
        total_delta = total_delta.wrapping_add(prev.abs_diff(cur));
    }
    let cutoff = (u64::from(n.prev_num_observations)
        .wrapping_mul(u64::from(c.split_stats.num_observations))
        .wrapping_mul(200))
        / 512;

    let costs = &mut n.costs;
    if total_delta > cutoff.wrapping_mul(3) {
        // Big change in the data; just use the default costs.
        deflate_set_default_costs(costs, lit_cost, len_sym_cost);
    } else if total_delta.wrapping_mul(4) > cutoff.wrapping_mul(9) {
        deflate_adjust_costs_impl(costs, lit_cost, len_sym_cost, 3);
    } else if total_delta.wrapping_mul(2) > cutoff.wrapping_mul(3) {
        deflate_adjust_costs_impl(costs, lit_cost, len_sym_cost, 2);
    } else if total_delta.wrapping_mul(2) > cutoff {
        deflate_adjust_costs_impl(costs, lit_cost, len_sym_cost, 1);
    } else {
        deflate_adjust_costs_impl(costs, lit_cost, len_sym_cost, 0);
    }
}

/// `deflate_set_initial_costs`.
fn deflate_set_initial_costs(
    c: &mut State,
    n: &mut NearOptimal,
    block: &[u8],
    is_first_block: bool,
) {
    let (lit_cost, len_sym_cost) = deflate_choose_default_litlen_costs(c, n, block);
    if is_first_block {
        deflate_set_default_costs(&mut n.costs, lit_cost, len_sym_cost);
    } else {
        deflate_adjust_costs(c, n, lit_cost, len_sym_cost);
    }
}

/// `deflate_find_min_cost_path`: the minimum-cost path from the start of
/// the block to its end, through the literals and the matches cached for
/// it (ending at `cache_ptr`), with the costs `n.costs`: worked out
/// backwards from the end, each node's cost to the end and the item that
/// starts its path. Then `c.freqs` and `c.codes` are those of the path.
fn deflate_find_min_cost_path(
    c: &mut State,
    n: &mut NearOptimal,
    block_length: usize,
    mut cache_ptr: usize,
) {
    let nodes = &mut n.optimum_nodes[..];
    let cache = &n.match_cache;
    let costs = &n.costs;
    let offset_slot_full = &n.offset_slot_full[..=DEFLATE_MAX_MATCH_OFFSET as usize];

    let mut cur_node = block_length;
    nodes[cur_node].cost_to_end = 0;
    loop {
        cur_node -= 1;
        cache_ptr -= 1;

        let num_matches = cache[cache_ptr].length as usize;
        let literal = cache[cache_ptr].offset as u32;

        // It's always possible to choose a literal.
        let mut best_cost_to_end =
            costs.literal[literal as usize & 0xFF].wrapping_add(nodes[cur_node + 1].cost_to_end);
        let mut best_item = (literal << OPTIMUM_OFFSET_SHIFT) | 1;

        // Also consider matches if there are any.
        if num_matches != 0 {
            // Consider each length from the minimum (DEFLATE_MIN_MATCH_LEN)
            // to the length of the longest match found at this position.
            // For each length, we consider only the smallest offset for
            // which that length is available. Although this is not
            // guaranteed to be optimal due to the possibility of a larger
            // offset costing less than a smaller offset to code, this is a
            // very useful heuristic.
            let matches = &cache[cache_ptr - num_matches..cache_ptr];
            let mut len = DEFLATE_MIN_MATCH_LEN as usize;
            for m in matches {
                let offset = m.offset as u32;
                let offset_slot = offset_slot_full[offset as usize] as usize;
                let offset_cost = costs.offset_slot[offset_slot & (DEFLATE_NUM_OFFSET_SYMS - 1)];
                let match_len = m.length as usize;
                let ahead = &nodes[cur_node..=cur_node + match_len];
                loop {
                    let cost_to_end = offset_cost
                        .wrapping_add(costs.length[len])
                        .wrapping_add(ahead[len].cost_to_end);
                    if cost_to_end < best_cost_to_end {
                        best_cost_to_end = cost_to_end;
                        best_item = len as u32 | (offset << OPTIMUM_OFFSET_SHIFT);
                    }
                    len += 1;
                    if len > match_len {
                        break;
                    }
                }
            }
            cache_ptr -= num_matches;
        }
        nodes[cur_node].cost_to_end = best_cost_to_end;
        nodes[cur_node].item = best_item;
        if cur_node == 0 {
            break;
        }
    }

    c.deflate_reset_symbol_frequencies();
    deflate_tally_item_list(c, n, block_length);
    deflate_make_huffman_codes(&c.freqs, &mut c.codes);
}

/// `deflate_optimize_and_flush_block`: choose the literals and matches of
/// the block, then output it. The minimum-cost path is found several times,
/// the first with default costs (mixed with the previous block's), the
/// others with the costs of the codes of the pass before. Using only
/// literals, and for small blocks the best path for the static codes, are
/// considered too. Returns whether only literals were best.
#[allow(clippy::too_many_arguments)]
fn deflate_optimize_and_flush_block(
    c: &mut State,
    n: &mut NearOptimal,
    os: &mut OutputBitstream,
    out: &mut [u8],
    input: &[u8],
    block_begin: usize,
    block_length: usize,
    cache_ptr: usize,
    is_first_block: bool,
    is_final_block: bool,
) -> bool {
    let block = &input[block_begin..block_begin + block_length];
    let mut num_passes_remaining = n.max_optim_passes;
    let mut best_true_cost = u32::MAX;
    let mut true_cost;
    let mut static_cost = u32::MAX;
    let mut only_literals = None;

    // On some data, using only literals (no matches) ends up being better
    // than what the iterative optimization algorithm produces. Therefore,
    // consider using only literals.
    deflate_choose_all_literals(c, block);
    let only_lits_cost = deflate_compute_true_cost(c);

    // Force the block to really end at the desired length, even if some
    // matches extend beyond it.
    let last = (block_length - 1 + DEFLATE_MAX_MATCH_LEN as usize).min(n.optimum_nodes.len() - 1);
    for node in &mut n.optimum_nodes[block_length..=last] {
        node.cost_to_end = 0x8000_0000;
    }

    // Sometimes a static Huffman block ends up being cheapest, particularly
    // if the block is small. So, if the block is sufficiently small, find
    // the optimal static block solution and remember its cost.
    if block_length <= n.max_len_to_optimize_static_block as usize {
        // Save c->p.n.costs temporarily.
        n.costs_saved = n.costs;

        deflate_set_costs_from_codes(&mut n.costs, &c.static_codes.lens);
        deflate_find_min_cost_path(c, n, block_length, cache_ptr);
        static_cost = n.optimum_nodes[0].cost_to_end / BIT_COST;
        static_cost = static_cost.wrapping_add(7); // for the end-of-block symbol

        // Restore c->p.n.costs.
        n.costs = n.costs_saved;
    }

    // Initialize c->p.n.costs with default costs.
    deflate_set_initial_costs(c, n, block, is_first_block);

    loop {
        // Find the minimum-cost path for this pass. Also set c->freqs and
        // c->codes to match the path.
        deflate_find_min_cost_path(c, n, block_length, cache_ptr);

        // Compute the exact cost of the block if the path were to be used.
        // Note that this differs from c->p.n.optimum_nodes[0].cost_to_end in
        // that true_cost uses the actual Huffman codes instead of
        // c->p.n.costs.
        true_cost = deflate_compute_true_cost(c);

        // If the cost didn't improve much from the previous pass, then doing
        // more passes probably won't be helpful, so stop early.
        if true_cost.wrapping_add(n.min_improvement_to_continue) > best_true_cost {
            break;
        }

        best_true_cost = true_cost;

        // Save the cost model that gave 'best_true_cost'.
        n.costs_saved = n.costs;

        // Update the cost model from the Huffman codes.
        deflate_set_costs_from_codes(&mut n.costs, &c.codes.lens);

        num_passes_remaining -= 1;
        if num_passes_remaining == 0 {
            break;
        }
    }

    let mut used_only_literals = false;
    if only_lits_cost.min(static_cost) < best_true_cost {
        if only_lits_cost < static_cost {
            // Using only literals ended up being best!
            deflate_choose_all_literals(c, block);
            deflate_set_costs_from_codes(&mut n.costs, &c.codes.lens);
            only_literals = Some(DeflateSequence {
                litrunlen_and_length: block_length as u32,
                offset: 0,
                offset_slot: 0,
            });
            used_only_literals = true;
        } else {
            // Static block ended up being best!
            deflate_set_costs_from_codes(&mut n.costs, &c.static_codes.lens);
            deflate_find_min_cost_path(c, n, block_length, cache_ptr);
        }
    } else if true_cost >= best_true_cost.wrapping_add(n.min_bits_to_use_nonfinal_path) {
        // The best solution was actually from a non-final optimization pass,
        // so recover and use the min-cost path from that pass.
        n.costs = n.costs_saved;
        deflate_find_min_cost_path(c, n, block_length, cache_ptr);
        deflate_set_costs_from_codes(&mut n.costs, &c.codes.lens);
    }
    let items = match &only_literals {
        Some(seq) => BlockItems::Sequences(std::slice::from_ref(seq)),
        None => BlockItems::Path(&n.optimum_nodes, &n.offset_slot_full),
    };
    deflate_flush_block(
        c,
        os,
        out,
        input,
        block_begin,
        block_length,
        items,
        is_final_block,
    );
    used_only_literals
}

/// `deflate_near_optimal_init_stats`.
fn deflate_near_optimal_init_stats(c: &mut State, n: &mut NearOptimal) {
    init_block_split_stats(&mut c.split_stats);
    n.new_match_len_freqs.fill(0);
    n.match_len_freqs.fill(0);
}

/// `deflate_near_optimal_merge_stats`.
fn deflate_near_optimal_merge_stats(c: &mut State, n: &mut NearOptimal) {
    merge_new_observations(&mut c.split_stats);
    for i in 0..n.match_len_freqs.len() {
        n.match_len_freqs[i] = n.match_len_freqs[i].wrapping_add(n.new_match_len_freqs[i]);
        n.new_match_len_freqs[i] = 0;
    }
}

/// `deflate_near_optimal_save_stats`: save some literal/match statistics
/// from the previous block so that `deflate_adjust_costs` will be able to
/// decide how much the current block differs from the previous one.
fn deflate_near_optimal_save_stats(c: &State, n: &mut NearOptimal) {
    n.prev_observations = c.split_stats.observations;
    n.prev_num_observations = c.split_stats.num_observations;
}

/// `deflate_near_optimal_clear_old_stats`.
fn deflate_near_optimal_clear_old_stats(c: &mut State, n: &mut NearOptimal) {
    c.split_stats.observations.fill(0);
    c.split_stats.num_observations = 0;
    n.match_len_freqs.fill(0);
}

/// `deflate_compress_near_optimal`: the "near-optimal" DEFLATE compressor.
/// It computes the optimal representation of each DEFLATE block using a
/// minimum-cost path search over the graph of possible match/literal
/// choices for that block, assuming a certain cost for each Huffman symbol.
///
/// For several reasons, the end result is not guaranteed to be optimal:
/// the choice of blocks, the heuristic limits on which matches are
/// considered, and symbol costs that are unknown until the symbols have
/// been chosen (so iterative optimization must be used).
fn deflate_compress_near_optimal(
    c: &mut State,
    n: &mut NearOptimal,
    input: &[u8],
    os: &mut OutputBitstream,
    out: &mut [u8],
) {
    let mut in_next = 0;
    let mut in_block_begin = in_next;
    let in_end = input.len();
    let mut in_cur_base = in_next;
    let mut in_next_slide = in_next + (in_end - in_next).min(MATCHFINDER_WINDOW_SIZE);
    let mut max_len = DEFLATE_MAX_MATCH_LEN;
    let mut nice_len = c.nice_match_length.min(max_len);
    let mut cache_ptr = 0;
    let mut next_hashes = [0u32; 2];
    let mut prev_block_used_only_literals = false;

    n.bt_mf.init();
    deflate_near_optimal_init_stats(c, n);

    loop {
        // Starting a new DEFLATE block.
        let in_max_block_end = choose_max_block_end(in_block_begin, in_end, SOFT_MAX_BLOCK_LENGTH);
        let mut prev_end_block_check = None;
        let mut change_detected = false;
        let mut next_observation = in_next;

        // Use the minimum match length heuristic to improve the
        // literal/match statistics gathered during matchfinding. However,
        // the actual near-optimal parse won't respect min_len, as it can
        // accurately assess the costs of different matches.
        //
        // If the "use only literals" strategy happened to be the best
        // strategy on the previous block, then probably the min_match_len
        // heuristic is still not aggressive enough for the data, so force
        // gathering literal stats only.
        let min_len = if prev_block_used_only_literals {
            DEFLATE_MAX_MATCH_LEN + 1
        } else {
            calculate_min_match_len(
                &input[in_block_begin..],
                in_max_block_end - in_block_begin,
                c.max_search_depth,
            )
        };

        // Find matches until we decide to end the block. We end the block
        // if any of the following is true:
        //
        // (1) Maximum block length has been reached
        // (2) Match catch may overflow.
        // (3) Block split heuristic says to split now.
        loop {
            let mut remaining = in_end - in_next;

            // Slide the window forward if needed.
            if in_next == in_next_slide {
                n.bt_mf.slide_window();
                in_cur_base = in_next;
                in_next_slide = in_next + remaining.min(MATCHFINDER_WINDOW_SIZE);
            }

            // Find matches with the current position using the binary tree
            // matchfinder and save them in match_cache.
            let matches = cache_ptr;
            let mut best_len = 0;
            adjust_max_and_nice_len(&mut max_len, &mut nice_len, remaining);
            if max_len >= BT_MATCHFINDER_REQUIRED_NBYTES {
                cache_ptr = n.bt_mf.get_matches(
                    input,
                    in_cur_base,
                    in_next - in_cur_base,
                    max_len,
                    nice_len,
                    c.max_search_depth,
                    &mut next_hashes,
                    &mut n.match_cache,
                    matches,
                );
                if cache_ptr > matches {
                    best_len = u32::from(n.match_cache[cache_ptr - 1].length);
                }
            }
            if in_next >= next_observation {
                if best_len >= min_len {
                    observe_match(&mut c.split_stats, best_len);
                    next_observation = in_next + best_len as usize;
                    n.new_match_len_freqs[best_len as usize] += 1;
                } else {
                    observe_literal(&mut c.split_stats, input[in_next]);
                    next_observation = in_next + 1;
                }
            }

            n.match_cache[cache_ptr] = LzMatch {
                length: (cache_ptr - matches) as u16,
                offset: u16::from(input[in_next]),
            };
            in_next += 1;
            cache_ptr += 1;

            // If there was a very long match found, don't cache any matches
            // for the bytes covered by that match. This avoids degenerate
            // behavior when compressing highly redundant data, where the
            // number of matches can be very large.
            //
            // This heuristic doesn't actually hurt the compression ratio
            // very much. If there's a long match, then the data must be
            // highly compressible, so it doesn't matter much what we do.
            if best_len >= DEFLATE_MIN_MATCH_LEN && best_len >= nice_len {
                best_len -= 1;
                loop {
                    remaining = in_end - in_next;
                    if in_next == in_next_slide {
                        n.bt_mf.slide_window();
                        in_cur_base = in_next;
                        in_next_slide = in_next + remaining.min(MATCHFINDER_WINDOW_SIZE);
                    }
                    adjust_max_and_nice_len(&mut max_len, &mut nice_len, remaining);
                    if max_len >= BT_MATCHFINDER_REQUIRED_NBYTES {
                        n.bt_mf.skip_byte(
                            input,
                            in_cur_base,
                            in_next - in_cur_base,
                            nice_len,
                            c.max_search_depth,
                            &mut next_hashes,
                        );
                    }
                    n.match_cache[cache_ptr] = LzMatch {
                        length: 0,
                        offset: u16::from(input[in_next]),
                    };
                    in_next += 1;
                    cache_ptr += 1;
                    best_len -= 1;
                    if best_len == 0 {
                        break;
                    }
                }
            }
            // Maximum block length or end of input reached?
            if in_next >= in_max_block_end {
                break;
            }
            // Match cache overflowed?
            if cache_ptr >= MATCH_CACHE_LENGTH {
                break;
            }
            // Not ready to try to end the block (again)?
            if !ready_to_check_block(&c.split_stats, in_block_begin, in_next, in_end) {
                continue;
            }
            // Check if it would be worthwhile to end the block.
            if do_end_block_check(&mut c.split_stats, (in_next - in_block_begin) as u32) {
                change_detected = true;
                break;
            }
            // Ending the block doesn't seem worthwhile here.
            deflate_near_optimal_merge_stats(c, n);
            prev_end_block_check = Some(in_next);
        }
        // All the matches for this block have been cached. Now choose the
        // precise end of the block and the sequence of items to output to
        // represent it, then flush the block.
        match prev_end_block_check {
            Some(in_block_end) if change_detected => {
                // The block is being ended because a recent chunk of data
                // differs from the rest of the block. We could end the
                // block at 'in_next' like the greedy and lazy compressors
                // do, but that's not ideal since it would include the
                // differing chunk in the block. The near-optimal compressor
                // has time to do a better job. Therefore, we rewind to just
                // before the chunk, and output a block that only goes up to
                // there.
                //
                // We then set things up to correctly start the next block,
                // considering that some work has already been done on it
                // (some matches found and stats gathered).
                let orig_cache_ptr = cache_ptr;
                let block_length = in_block_end - in_block_begin;
                let is_first = in_block_begin == 0;
                let is_final = false;
                let mut num_bytes_to_rewind = in_next - in_block_end;

                // Rewind the match cache.
                loop {
                    cache_ptr -= 1;
                    cache_ptr -= n.match_cache[cache_ptr].length as usize;
                    num_bytes_to_rewind -= 1;
                    if num_bytes_to_rewind == 0 {
                        break;
                    }
                }
                let cache_len_rewound = orig_cache_ptr - cache_ptr;

                prev_block_used_only_literals = deflate_optimize_and_flush_block(
                    c,
                    n,
                    os,
                    out,
                    input,
                    in_block_begin,
                    block_length,
                    cache_ptr,
                    is_first,
                    is_final,
                );
                n.match_cache
                    .copy_within(cache_ptr..cache_ptr + cache_len_rewound, 0);
                cache_ptr = cache_len_rewound;
                deflate_near_optimal_save_stats(c, n);
                // Clear the stats for the just-flushed block, leaving just
                // the stats for the beginning of the next block.
                deflate_near_optimal_clear_old_stats(c, n);
                in_block_begin = in_block_end;
            }
            _ => {
                // The block is being ended for a reason other than a
                // differing data chunk being detected. Don't rewind at all;
                // just end the block at the current position.
                let block_length = in_next - in_block_begin;
                let is_first = in_block_begin == 0;
                let is_final = in_next == in_end;

                deflate_near_optimal_merge_stats(c, n);
                prev_block_used_only_literals = deflate_optimize_and_flush_block(
                    c,
                    n,
                    os,
                    out,
                    input,
                    in_block_begin,
                    block_length,
                    cache_ptr,
                    is_first,
                    is_final,
                );
                cache_ptr = 0;
                deflate_near_optimal_save_stats(c, n);
                deflate_near_optimal_init_stats(c, n);
                in_block_begin = in_next;
            }
        }
        if !(in_next != in_end && !os.overflow) {
            break;
        }
    }
}

/// `deflate_init_offset_slot_full`: `p.n.offset_slot_full`, the offset
/// slot of each offset.
fn deflate_init_offset_slot_full(offset_slot_full: &mut [u8]) {
    for offset_slot in 0..DEFLATE_OFFSET_SLOT_BASE.len() {
        let offset = DEFLATE_OFFSET_SLOT_BASE[offset_slot] as usize;
        let offset_end = offset + (1 << DEFLATE_EXTRA_OFFSET_BITS[offset_slot]);
        offset_slot_full[offset..offset_end].fill(offset_slot as u8);
    }
}

impl NearOptimal {
    /// `p.n`, with the parameters of a level.
    fn new(
        max_optim_passes: u32,
        min_improvement_to_continue: u32,
        min_bits_to_use_nonfinal_path: u32,
        max_len_to_optimize_static_block: u32,
    ) -> Box<NearOptimal> {
        let costs = DeflateCosts {
            literal: [0; DEFLATE_NUM_LITERALS],
            length: [0; DEFLATE_MAX_MATCH_LEN as usize + 1],
            offset_slot: [0; DEFLATE_NUM_OFFSET_SYMS],
        };
        let mut n = Box::new(NearOptimal {
            bt_mf: BtMatchfinder::new(),
            match_cache: vec![LzMatch::default(); MATCH_CACHE_ROOM],
            optimum_nodes: vec![DeflateOptimumNode::default(); MAX_BLOCK_LENGTH + 1],
            costs,
            costs_saved: costs,
            offset_slot_full: vec![0; DEFLATE_MAX_MATCH_OFFSET as usize + 1],
            prev_observations: [0; NUM_OBSERVATION_TYPES],
            prev_num_observations: 0,
            new_match_len_freqs: [0; DEFLATE_MAX_MATCH_LEN as usize + 1],
            match_len_freqs: [0; DEFLATE_MAX_MATCH_LEN as usize + 1],
            max_optim_passes,
            min_improvement_to_continue,
            min_bits_to_use_nonfinal_path,
            max_len_to_optimize_static_block,
        });
        deflate_init_offset_slot_full(&mut n.offset_slot_full);
        n
    }
}

impl Greedy {
    fn new() -> Greedy {
        Greedy {
            hc_mf: HcMatchfinder::new(),
            sequences: vec![DeflateSequence::default(); SEQ_STORE_LENGTH + 1],
        }
    }
}

impl Compressor {
    /// A compressor at `compression_level`, from 0 (uncompressed blocks
    /// only) to 12, or -1 for the default, 6; `None` for any other level.
    ///
    /// Port of `libdeflate_alloc_compressor` (and of
    /// `libdeflate_alloc_compressor_ex`, without the options, which only
    /// choose the memory allocator). The memory taken is libdeflate's: about
    /// 0.2 MB at level 1, 0.7 MB at levels 2 to 9, 9 MB at levels 10 to 12.
    pub fn new(compression_level: i32) -> Option<Compressor> {
        // Note: For similarity with zlib's API, -1 is accepted as an alias
        // for the default compression level.
        let compression_level = if compression_level == -1 {
            6
        } else {
            compression_level
        };
        if !(0..=12).contains(&compression_level) {
            return None;
        }
        let compression_level = compression_level as u32;

        let mut c = Box::new(State {
            compression_level,
            // The higher the compression level, the more we should bother
            // trying to compress very small inputs.
            max_passthrough_size: 55 - (compression_level as usize * 4),
            max_search_depth: 0,
            nice_match_length: 0,
            freqs: DeflateFreqs {
                litlen: [0; DEFLATE_NUM_LITLEN_SYMS],
                offset: [0; DEFLATE_NUM_OFFSET_SYMS],
            },
            split_stats: BlockSplitStats::default(),
            codes: DeflateCodes::new(),
            static_codes: DeflateCodes::new(),
            precode: Precode {
                freqs: [0; DEFLATE_NUM_PRECODE_SYMS],
                codewords: [0; DEFLATE_NUM_PRECODE_SYMS],
                lens: [0; DEFLATE_NUM_PRECODE_SYMS],
                items: [0; DEFLATE_NUM_LITLEN_SYMS + DEFLATE_NUM_OFFSET_SYMS],
                num_litlen_syms: 0,
                num_offset_syms: 0,
                num_explicit_lens: 0,
                num_items: 0,
            },
            length: LengthCodes {
                codewords: [0; DEFLATE_MAX_MATCH_LEN as usize + 1],
                lens: [0; DEFLATE_MAX_MATCH_LEN as usize + 1],
            },
            last: true,
        });

        let (max_search_depth, nice_match_length, p) = match compression_level {
            0 => {
                c.max_passthrough_size = usize::MAX;
                (0, 0, Parser::None)
            }
            1 => (
                // max_search_depth is unused.
                0,
                32,
                Parser::Fastest(Fastest {
                    ht_mf: HtMatchfinder::new(),
                    sequences: vec![DeflateSequence::default(); FAST_SEQ_STORE_LENGTH + 1],
                }),
            ),
            2 => (6, 10, Parser::Greedy(Greedy::new())),
            3 => (12, 14, Parser::Greedy(Greedy::new())),
            4 => (16, 30, Parser::Greedy(Greedy::new())),
            5 => (16, 30, Parser::Lazy(Greedy::new())),
            6 => (35, 65, Parser::Lazy(Greedy::new())),
            7 => (100, 130, Parser::Lazy(Greedy::new())),
            8 => (300, DEFLATE_MAX_MATCH_LEN, Parser::Lazy2(Greedy::new())),
            9 => (600, DEFLATE_MAX_MATCH_LEN, Parser::Lazy2(Greedy::new())),
            10 => (35, 75, Parser::NearOptimal(NearOptimal::new(2, 32, 32, 0))),
            11 => (
                100,
                150,
                Parser::NearOptimal(NearOptimal::new(4, 16, 16, 1000)),
            ),
            _ => (
                300,
                DEFLATE_MAX_MATCH_LEN,
                Parser::NearOptimal(NearOptimal::new(10, 1, 1, 10000)),
            ),
        };
        c.max_search_depth = max_search_depth;
        c.nice_match_length = nice_match_length;

        deflate_init_static_codes(&mut c);

        Some(Compressor { c, p })
    }

    /// The level the compressor was made for, -1 given as 6: port of
    /// `libdeflate_get_compression_level`.
    pub fn compression_level(&self) -> u32 {
        self.c.compression_level
    }

    /// Compresses `input` into `output` as raw DEFLATE, and returns the
    /// compressed size, or 0 if it does not fit in `output`: port of
    /// `libdeflate_deflate_compress`.
    ///
    /// [`Compressor::deflate_compress_bound`] gives room that is always
    /// enough. With less, the output may still fit; when it does not, the
    /// bytes of `output` are left in no particular state, as libdeflate
    /// leaves them. Past the size returned, they may have been written to
    /// as well.
    pub fn deflate_compress(&mut self, input: &[u8], output: &mut [u8]) -> usize {
        self.compress(input, output, true)
    }

    /// Compresses `input` into `output` as a part of a raw DEFLATE stream
    /// that is not its last, and returns the compressed size, or 0 if it
    /// does not fit in `output`. Not in libdeflate.
    ///
    /// The part is what [`Compressor::deflate_compress`] writes, but for
    /// its last block, whose BFINAL is not set, and a sync marker after it,
    /// as zlib's `Z_SYNC_FLUSH` writes one: an empty uncompressed block, its
    /// 3 bits of header with zeros to the next byte, then `00 00 FF FF`. So
    /// the part ends on a byte, and parts one after the other, then what
    /// [`Compressor::deflate_compress`] writes, are one stream, as pigz
    /// joins its blocks. Each part is compressed alone: none refers to the
    /// input of the one before. An empty input's part is the sync marker
    /// alone.
    ///
    /// [`Compressor::deflate_compress_part_bound`] gives room that is
    /// always enough. With less, the output is left as
    /// [`Compressor::deflate_compress`] leaves it.
    pub fn deflate_compress_part(&mut self, input: &[u8], output: &mut [u8]) -> usize {
        self.compress(input, output, false)
    }

    /// `libdeflate_deflate_compress`, the input's last block ending the
    /// stream if `last`, else followed by a sync marker.
    fn compress(&mut self, input: &[u8], output: &mut [u8], last: bool) -> usize {
        let c = &mut *self.c;
        c.last = last;

        // For extremely short inputs, or for compression level 0, just
        // output uncompressed blocks.
        if input.len() <= c.max_passthrough_size {
            return compress_none(input, output, last);
        }

        // Initialize the output bitstream structure.
        let mut os = OutputBitstream {
            bitbuf: 0,
            bitcount: 0,
            next: 0,
            overflow: false,
        };

        // Call the actual compression function.
        match &mut self.p {
            Parser::None => return compress_none(input, output, last),
            Parser::Fastest(f) => deflate_compress_fastest(c, f, input, &mut os, output),
            Parser::Greedy(g) => deflate_compress_greedy(c, g, input, &mut os, output),
            Parser::Lazy(g) => {
                deflate_compress_lazy_generic::<false>(c, g, input, &mut os, output);
            }
            Parser::Lazy2(g) => {
                deflate_compress_lazy_generic::<true>(c, g, input, &mut os, output);
            }
            Parser::NearOptimal(n) => deflate_compress_near_optimal(c, n, input, &mut os, output),
        }

        // Return 0 if the output buffer is too small.
        if os.overflow {
            return 0;
        }
        if !last {
            return sync_marker(os, output);
        }

        // Write the final byte if needed. This can't overflow the output
        // buffer because deflate_flush_block() would have set the overflow
        // flag if there wasn't enough space remaining for the full final
        // block.
        debug_assert!(os.bitcount <= 7);
        if os.bitcount != 0 {
            output[os.next] = os.bitbuf as u8;
            os.next += 1;
        }

        // Return the compressed size in bytes.
        os.next
    }

    /// The most bytes [`Compressor::deflate_compress`] can write for
    /// `in_nbytes` bytes of input: port of
    /// `libdeflate_deflate_compress_bound`.
    ///
    /// The compressor never uses a compressed block where an uncompressed
    /// one would be smaller, so the worst case is uncompressed blocks, of
    /// at least `MIN_BLOCK_LENGTH` bytes but for the last, each with 5
    /// bytes more than its data.
    pub fn deflate_compress_bound(&self, in_nbytes: usize) -> usize {
        let max_blocks = in_nbytes.div_ceil(MIN_BLOCK_LENGTH).max(1);
        (5 * max_blocks) + in_nbytes
    }

    /// The most bytes [`Compressor::deflate_compress_part`] can write for
    /// `in_nbytes` bytes of input. Not in libdeflate.
    ///
    /// [`Compressor::deflate_compress_bound`], and 5 bytes for the sync
    /// marker: the blocks take at most that bound, in bits too, so with
    /// the marker's 3 bits they take one byte more at most, then its 4.
    pub fn deflate_compress_part_bound(&self, in_nbytes: usize) -> usize {
        Compressor::part_bound(in_nbytes)
    }

    /// [`Compressor::deflate_compress_part_bound`], which is the same at
    /// every level, without a compressor.
    pub(crate) fn part_bound(in_nbytes: usize) -> usize {
        let max_blocks = in_nbytes.div_ceil(MIN_BLOCK_LENGTH).max(1);
        (5 * max_blocks) + in_nbytes + 5
    }
}

/// `deflate_compress_none`, and a sync marker after it if not `last` but
/// for an empty input, whose block is one already. Not in libdeflate.
fn compress_none(input: &[u8], output: &mut [u8], last: bool) -> usize {
    let size = deflate_compress_none(input, output, last);
    if last || size == 0 || input.is_empty() {
        return size;
    }
    let os = OutputBitstream {
        bitbuf: 0,
        bitcount: 0,
        next: size,
        overflow: false,
    };
    sync_marker(os, output)
}

/// Ends a part with a sync marker after its last block, which is not
/// final: an empty uncompressed block, its header's 3 bits (BFINAL 0,
/// BTYPE 0) with zeros to the next byte, then LEN and NLEN, `00 00 FF FF`.
/// The size of the part, or 0 if the marker does not fit. Not in
/// libdeflate.
fn sync_marker(os: OutputBitstream, out: &mut [u8]) -> usize {
    debug_assert!(os.bitcount <= 7 && !os.overflow);
    // The bits left, the 3 bits of the header, and zeros to the byte.
    let bytes = (os.bitcount as usize + 3).div_ceil(8);
    let end = os.next + bytes + 4;
    if end > out.len() {
        return 0;
    }
    out[os.next..os.next + bytes].copy_from_slice(&os.bitbuf.to_le_bytes()[..bytes]);
    out[end - 4..end].copy_from_slice(&[0, 0, 0xFF, 0xFF]);
    end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_slots_are_the_bases() {
        for len in DEFLATE_MIN_MATCH_LEN..=DEFLATE_MAX_MATCH_LEN {
            let slot = DEFLATE_LENGTH_SLOT[len as usize] as usize;
            let base = DEFLATE_LENGTH_SLOT_BASE[slot];
            assert!(base <= len, "length {len}");
            if len != 258 {
                assert!(
                    len < base + (1 << DEFLATE_EXTRA_LENGTH_BITS[slot]),
                    "length {len}"
                );
            }
        }
    }

    #[test]
    fn offset_slots_are_the_bases() {
        let mut full = vec![0u8; DEFLATE_MAX_MATCH_OFFSET as usize + 1];
        deflate_init_offset_slot_full(&mut full);
        for offset in 1..=DEFLATE_MAX_MATCH_OFFSET {
            let slot = deflate_get_offset_slot(offset);
            assert_eq!(u32::from(full[offset as usize]), slot, "offset {offset}");
            let base = DEFLATE_OFFSET_SLOT_BASE[slot as usize];
            assert!(
                base <= offset && offset < base + (1 << DEFLATE_EXTRA_OFFSET_BITS[slot as usize])
            );
        }
    }

    #[test]
    fn static_codes_are_the_formats() {
        let Some(compressor) = Compressor::new(6) else {
            panic!("level 6");
        };
        let lens = &compressor.c.static_codes.lens;
        for sym in 0..288 {
            let want = match sym {
                0..144 => 8,
                144..256 => 9,
                256..280 => 7,
                _ => 8,
            };
            assert_eq!(lens[sym], want, "litlen {sym}");
        }
        assert!(lens[LENS_OFFSET..].iter().all(|&len| len == 5));
        // The first codeword of 7 bits, 256's, is 0000000; of 8 bits, 0's,
        // 00110000, reversed.
        assert_eq!(compressor.c.static_codes.litlen[256], 0);
        assert_eq!(compressor.c.static_codes.litlen[0], 0b0000_1100);
    }

    #[test]
    fn levels_out_of_range_are_refused() {
        assert!(Compressor::new(13).is_none());
        assert!(Compressor::new(-2).is_none());
        assert_eq!(Compressor::new(-1).map(|c| c.compression_level()), Some(6));
    }

    #[test]
    fn default_costs_are_increasing() {
        for costs in &DEFAULT_LITLEN_COSTS {
            assert!(
                costs.used_lits_to_lit_cost[1..]
                    .windows(2)
                    .all(|w| w[0] <= w[1])
            );
            assert_eq!(
                costs.used_lits_to_lit_cost[0],
                costs.used_lits_to_lit_cost[1]
            );
        }
    }
}
