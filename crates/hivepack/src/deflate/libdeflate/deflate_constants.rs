//! Constants of the DEFLATE format: port of `deflate_constants.h`.

/// `DEFLATE_BLOCKTYPE_UNCOMPRESSED`, `DEFLATE_BLOCKTYPE_STATIC_HUFFMAN`,
/// `DEFLATE_BLOCKTYPE_DYNAMIC_HUFFMAN`: the block types.
pub(crate) const DEFLATE_BLOCKTYPE_UNCOMPRESSED: u8 = 0;
pub(crate) const DEFLATE_BLOCKTYPE_STATIC_HUFFMAN: u64 = 1;
pub(crate) const DEFLATE_BLOCKTYPE_DYNAMIC_HUFFMAN: u64 = 2;

/// `DEFLATE_MIN_MATCH_LEN`, `DEFLATE_MAX_MATCH_LEN`: the shortest and
/// longest matches.
pub(crate) const DEFLATE_MIN_MATCH_LEN: u32 = 3;
pub(crate) const DEFLATE_MAX_MATCH_LEN: u32 = 258;

/// `DEFLATE_MAX_MATCH_OFFSET`: the farthest a match can be back.
pub(crate) const DEFLATE_MAX_MATCH_OFFSET: u32 = 32768;

/// `DEFLATE_WINDOW_ORDER`: log2 of `DEFLATE_MAX_MATCH_OFFSET`.
pub(crate) const DEFLATE_WINDOW_ORDER: u32 = 15;

/// The number of symbols in each Huffman code: `DEFLATE_NUM_PRECODE_SYMS`,
/// `DEFLATE_NUM_LITLEN_SYMS`, `DEFLATE_NUM_OFFSET_SYMS`, and the most of
/// them, `DEFLATE_MAX_NUM_SYMS`.
pub(crate) const DEFLATE_NUM_PRECODE_SYMS: usize = 19;
pub(crate) const DEFLATE_NUM_LITLEN_SYMS: usize = 288;
pub(crate) const DEFLATE_NUM_OFFSET_SYMS: usize = 32;
pub(crate) const DEFLATE_MAX_NUM_SYMS: usize = 288;

/// Division of symbols in the literal/length code:
/// `DEFLATE_NUM_LITERALS`, `DEFLATE_END_OF_BLOCK` and
/// `DEFLATE_FIRST_LEN_SYM`.
pub(crate) const DEFLATE_NUM_LITERALS: usize = 256;
pub(crate) const DEFLATE_END_OF_BLOCK: usize = 256;
pub(crate) const DEFLATE_FIRST_LEN_SYM: usize = 257;

/// The longest codeword of each code: `DEFLATE_MAX_PRE_CODEWORD_LEN`,
/// `DEFLATE_MAX_LITLEN_CODEWORD_LEN`, `DEFLATE_MAX_OFFSET_CODEWORD_LEN`
/// and `DEFLATE_MAX_CODEWORD_LEN`.
pub(crate) const DEFLATE_MAX_PRE_CODEWORD_LEN: u32 = 7;
pub(crate) const DEFLATE_MAX_LITLEN_CODEWORD_LEN: u32 = 15;
pub(crate) const DEFLATE_MAX_OFFSET_CODEWORD_LEN: u32 = 15;
pub(crate) const DEFLATE_MAX_CODEWORD_LEN: usize = 15;

/// `DEFLATE_MAX_EXTRA_LENGTH_BITS`, `DEFLATE_MAX_EXTRA_OFFSET_BITS`: the
/// most extra bits a length or an offset has.
pub(crate) const DEFLATE_MAX_EXTRA_LENGTH_BITS: u32 = 5;
pub(crate) const DEFLATE_MAX_EXTRA_OFFSET_BITS: u32 = 13;
