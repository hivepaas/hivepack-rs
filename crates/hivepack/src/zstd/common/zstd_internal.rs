//! Format constants and default tables: port of the parts of
//! `common/zstd_internal.h` (and of `zstd.h`) shared by the compressor and
//! the decompressor.

/// `ZSTD_MAGICNUMBER`
pub(crate) const ZSTD_MAGICNUMBER: u32 = 0xFD2F_B528;
/// `ZSTD_MAGIC_DICTIONARY`
pub(crate) const ZSTD_MAGIC_DICTIONARY: u32 = 0xEC30_A437;
/// `ZSTD_MAGIC_SKIPPABLE_START`: skippable frames use the 16 values from here.
pub(crate) const ZSTD_MAGIC_SKIPPABLE_START: u32 = 0x184D_2A50;
/// `ZSTD_MAGIC_SKIPPABLE_MASK`
pub(crate) const ZSTD_MAGIC_SKIPPABLE_MASK: u32 = 0xFFFF_FFF0;
/// `ZSTD_BLOCKSIZELOG_MAX`
pub(crate) const ZSTD_BLOCKSIZELOG_MAX: u32 = 17;
/// `ZSTD_BLOCKSIZE_MAX`
pub(crate) const ZSTD_BLOCKSIZE_MAX: usize = 1 << ZSTD_BLOCKSIZELOG_MAX;
/// `ZSTD_WINDOWLOG_ABSOLUTEMIN`
pub(crate) const ZSTD_WINDOWLOG_ABSOLUTEMIN: u32 = 10;
/// `ZSTD_FRAMEIDSIZE`: the size of the magic number.
pub(crate) const ZSTD_FRAMEIDSIZE: usize = 4;
/// `ZSTD_BLOCKHEADERSIZE`
pub(crate) const ZSTD_BLOCKHEADERSIZE: usize = 3;
/// `ZSTD_FRAMECHECKSUMSIZE`
pub(crate) const ZSTD_FRAMECHECKSUMSIZE: usize = 4;

/// `ZSTD_OPT_NUM`: how far ahead the optimal parser looks, at most.
pub(crate) const ZSTD_OPT_NUM: usize = 1 << 12;
/// `ZSTD_REP_NUM`: the number of repeat offsets.
pub(crate) const ZSTD_REP_NUM: usize = 3;
/// `repStartValue`
pub(crate) const REP_START_VALUE: [u32; ZSTD_REP_NUM] = [1, 4, 8];

/// `ZSTD_fcs_fieldSize`
pub(crate) const ZSTD_FCS_FIELD_SIZE: [usize; 4] = [0, 2, 4, 8];
/// `ZSTD_did_fieldSize`
pub(crate) const ZSTD_DID_FIELD_SIZE: [usize; 4] = [0, 1, 2, 4];

/// `blockType_e`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum BlockType {
    Raw = 0,
    Rle = 1,
    Compressed = 2,
    Reserved = 3,
}

/// `SymbolEncodingType_e`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SymbolEncodingType {
    Basic = 0,
    Rle = 1,
    Compressed = 2,
    Repeat = 3,
}

/// `MIN_SEQUENCES_SIZE`: `nbSeq == 0`.
pub(crate) const MIN_SEQUENCES_SIZE: usize = 1;
/// `MIN_CBLOCK_SIZE`: the smallest non-empty compressed block.
pub(crate) const MIN_CBLOCK_SIZE: usize = 1 /* litCSize */ + 1 /* RLE or RAW */;
/// `MIN_LITERALS_FOR_4_STREAMS`
pub(crate) const MIN_LITERALS_FOR_4_STREAMS: usize = 6;
/// `LONGNBSEQ`
pub(crate) const LONGNBSEQ: usize = 0x7F00;
/// `MINMATCH`
pub(crate) const MINMATCH: u32 = 3;
/// `Litbits`
pub(crate) const LITBITS: u32 = 8;
/// `LitHufLog`
pub(crate) const LIT_HUF_LOG: u32 = 11;
/// `MaxLit`
pub(crate) const MAX_LIT: u32 = (1 << LITBITS) - 1;
/// `MaxML`
pub(crate) const MAX_ML: u32 = 52;
/// `MaxLL`
pub(crate) const MAX_LL: u32 = 35;
/// `DefaultMaxOff`
pub(crate) const DEFAULT_MAX_OFF: u32 = 28;
/// `MaxOff`
pub(crate) const MAX_OFF: u32 = 31;
/// `MaxSeq`
pub(crate) const MAX_SEQ: u32 = if MAX_LL > MAX_ML { MAX_LL } else { MAX_ML };
/// `MLFSELog`
pub(crate) const ML_FSE_LOG: u32 = 9;
/// `LLFSELog`
pub(crate) const LL_FSE_LOG: u32 = 9;
/// `OffFSELog`
pub(crate) const OFF_FSE_LOG: u32 = 8;
/// `MaxFSELog`
pub(crate) const MAX_FSE_LOG: u32 = 9;
/// `MaxMLBits`
pub(crate) const MAX_ML_BITS: u32 = 16;
/// `MaxLLBits`
pub(crate) const MAX_LL_BITS: u32 = 16;
/// `ZSTD_MAX_HUF_HEADER_SIZE`: the header and up to 127 bytes of tree.
pub(crate) const ZSTD_MAX_HUF_HEADER_SIZE: usize = 128;
/// `ZSTD_MAX_FSE_HEADERS_SIZE`
pub(crate) const ZSTD_MAX_FSE_HEADERS_SIZE: usize =
    ((MAX_ML + 1) * ML_FSE_LOG + (MAX_LL + 1) * LL_FSE_LOG + (MAX_OFF + 1) * OFF_FSE_LOG)
        .div_ceil(8) as usize;

/// `LL_bits`
pub(crate) const LL_BITS: [u8; MAX_LL as usize + 1] = [
    0, 0, 0, 0, 0, 0, 0, 0, //
    0, 0, 0, 0, 0, 0, 0, 0, //
    1, 1, 1, 1, 2, 2, 3, 3, //
    4, 6, 7, 8, 9, 10, 11, 12, //
    13, 14, 15, 16,
];
/// `LL_defaultNorm`
pub(crate) const LL_DEFAULT_NORM: [i16; MAX_LL as usize + 1] = [
    4, 3, 2, 2, 2, 2, 2, 2, //
    2, 2, 2, 2, 2, 1, 1, 1, //
    2, 2, 2, 2, 2, 2, 2, 2, //
    2, 3, 2, 1, 1, 1, 1, 1, //
    -1, -1, -1, -1,
];
/// `LL_DEFAULTNORMLOG`
pub(crate) const LL_DEFAULT_NORM_LOG: u32 = 6;

/// `ML_bits`
pub(crate) const ML_BITS: [u8; MAX_ML as usize + 1] = [
    0, 0, 0, 0, 0, 0, 0, 0, //
    0, 0, 0, 0, 0, 0, 0, 0, //
    0, 0, 0, 0, 0, 0, 0, 0, //
    0, 0, 0, 0, 0, 0, 0, 0, //
    1, 1, 1, 1, 2, 2, 3, 3, //
    4, 4, 5, 7, 8, 9, 10, 11, //
    12, 13, 14, 15, 16,
];
/// `ML_defaultNorm`
pub(crate) const ML_DEFAULT_NORM: [i16; MAX_ML as usize + 1] = [
    1, 4, 3, 2, 2, 2, 2, 2, //
    2, 1, 1, 1, 1, 1, 1, 1, //
    1, 1, 1, 1, 1, 1, 1, 1, //
    1, 1, 1, 1, 1, 1, 1, 1, //
    1, 1, 1, 1, 1, 1, 1, 1, //
    1, 1, 1, 1, 1, 1, -1, -1, //
    -1, -1, -1, -1, -1,
];
/// `ML_DEFAULTNORMLOG`
pub(crate) const ML_DEFAULT_NORM_LOG: u32 = 6;

/// `OF_defaultNorm`
pub(crate) const OF_DEFAULT_NORM: [i16; DEFAULT_MAX_OFF as usize + 1] = [
    1, 1, 1, 1, 1, 1, 2, 2, //
    2, 1, 1, 1, 1, 1, 1, 1, //
    1, 1, 1, 1, 1, 1, 1, 1, //
    -1, -1, -1, -1, -1,
];
/// `OF_DEFAULTNORMLOG`
pub(crate) const OF_DEFAULT_NORM_LOG: u32 = 5;
