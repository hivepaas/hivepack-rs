//! The compression levels' parameters: port of `compress/clevels.h`.

use crate::zstd::compress::zstd_compress_internal::{CompressionParameters, Strategy};

/// `ZSTD_MAX_CLEVEL`
pub(crate) const ZSTD_MAX_CLEVEL: i32 = 22;

const fn p(
    window_log: u32,
    chain_log: u32,
    hash_log: u32,
    search_log: u32,
    min_match: u32,
    target_length: u32,
    strategy: Strategy,
) -> CompressionParameters {
    CompressionParameters {
        window_log,
        chain_log,
        hash_log,
        search_log,
        min_match,
        target_length,
        strategy,
    }
}

use Strategy::{Btlazy2, Btopt, Btultra, Btultra2, Dfast, Fast, Greedy, Lazy, Lazy2};

/// `ZSTD_defaultCParameters`: for each table (inputs over 256 KB or of
/// unknown size; up to 256 KB; up to 128 KB; up to 16 KB), the parameters
/// of each level, row 0 being the base for negative levels.
#[rustfmt::skip]
pub(crate) const ZSTD_DEFAULT_CPARAMETERS: [[CompressionParameters; ZSTD_MAX_CLEVEL as usize + 1]; 4] = [
    // SrcSize > 256 KB, or unknown
    [
        p(19, 12, 13, 1, 6, 1, Fast), // base for negative levels
        p(19, 13, 14, 1, 7, 0, Fast), // level  1
        p(20, 15, 16, 1, 6, 0, Fast), // level  2
        p(21, 16, 17, 1, 5, 0, Dfast), // level  3
        p(21, 18, 18, 1, 5, 0, Dfast), // level  4
        p(21, 18, 19, 3, 5, 2, Greedy), // level  5
        p(21, 18, 19, 3, 5, 4, Lazy), // level  6
        p(21, 19, 20, 4, 5, 8, Lazy), // level  7
        p(21, 19, 20, 4, 5, 16, Lazy2), // level  8
        p(22, 20, 21, 4, 5, 16, Lazy2), // level  9
        p(22, 21, 22, 5, 5, 16, Lazy2), // level 10
        p(22, 21, 22, 6, 5, 16, Lazy2), // level 11
        p(22, 22, 23, 6, 5, 32, Lazy2), // level 12
        p(22, 22, 22, 4, 5, 32, Btlazy2), // level 13
        p(22, 22, 23, 5, 5, 32, Btlazy2), // level 14
        p(22, 23, 23, 6, 5, 32, Btlazy2), // level 15
        p(22, 22, 22, 5, 5, 48, Btopt), // level 16
        p(23, 23, 22, 5, 4, 64, Btopt), // level 17
        p(23, 23, 22, 6, 3, 64, Btultra), // level 18
        p(23, 24, 22, 7, 3, 256, Btultra2), // level 19
        p(25, 25, 23, 7, 3, 256, Btultra2), // level 20
        p(26, 26, 24, 7, 3, 512, Btultra2), // level 21
        p(27, 27, 25, 9, 3, 999, Btultra2), // level 22
    ],
    // SrcSize <= 256 KB
    [
        p(18, 12, 13, 1, 5, 1, Fast), // base for negative levels
        p(18, 13, 14, 1, 6, 0, Fast), // level  1
        p(18, 14, 14, 1, 5, 0, Dfast), // level  2
        p(18, 16, 16, 1, 4, 0, Dfast), // level  3
        p(18, 16, 17, 3, 5, 2, Greedy), // level  4.
        p(18, 17, 18, 5, 5, 2, Greedy), // level  5.
        p(18, 18, 19, 3, 5, 4, Lazy), // level  6.
        p(18, 18, 19, 4, 4, 4, Lazy), // level  7
        p(18, 18, 19, 4, 4, 8, Lazy2), // level  8
        p(18, 18, 19, 5, 4, 8, Lazy2), // level  9
        p(18, 18, 19, 6, 4, 8, Lazy2), // level 10
        p(18, 18, 19, 5, 4, 12, Btlazy2), // level 11.
        p(18, 19, 19, 7, 4, 12, Btlazy2), // level 12.
        p(18, 18, 19, 4, 4, 16, Btopt), // level 13
        p(18, 18, 19, 4, 3, 32, Btopt), // level 14.
        p(18, 18, 19, 6, 3, 128, Btopt), // level 15.
        p(18, 19, 19, 6, 3, 128, Btultra), // level 16.
        p(18, 19, 19, 8, 3, 256, Btultra), // level 17.
        p(18, 19, 19, 6, 3, 128, Btultra2), // level 18.
        p(18, 19, 19, 8, 3, 256, Btultra2), // level 19.
        p(18, 19, 19, 10, 3, 512, Btultra2), // level 20.
        p(18, 19, 19, 12, 3, 512, Btultra2), // level 21.
        p(18, 19, 19, 13, 3, 999, Btultra2), // level 22.
    ],
    // SrcSize <= 128 KB
    [
        p(17, 12, 12, 1, 5, 1, Fast), // base for negative levels
        p(17, 12, 13, 1, 6, 0, Fast), // level  1
        p(17, 13, 15, 1, 5, 0, Fast), // level  2
        p(17, 15, 16, 2, 5, 0, Dfast), // level  3
        p(17, 17, 17, 2, 4, 0, Dfast), // level  4
        p(17, 16, 17, 3, 4, 2, Greedy), // level  5
        p(17, 16, 17, 3, 4, 4, Lazy), // level  6
        p(17, 16, 17, 3, 4, 8, Lazy2), // level  7
        p(17, 16, 17, 4, 4, 8, Lazy2), // level  8
        p(17, 16, 17, 5, 4, 8, Lazy2), // level  9
        p(17, 16, 17, 6, 4, 8, Lazy2), // level 10
        p(17, 17, 17, 5, 4, 8, Btlazy2), // level 11
        p(17, 18, 17, 7, 4, 12, Btlazy2), // level 12
        p(17, 18, 17, 3, 4, 12, Btopt), // level 13.
        p(17, 18, 17, 4, 3, 32, Btopt), // level 14.
        p(17, 18, 17, 6, 3, 256, Btopt), // level 15.
        p(17, 18, 17, 6, 3, 128, Btultra), // level 16.
        p(17, 18, 17, 8, 3, 256, Btultra), // level 17.
        p(17, 18, 17, 10, 3, 512, Btultra), // level 18.
        p(17, 18, 17, 5, 3, 256, Btultra2), // level 19.
        p(17, 18, 17, 7, 3, 512, Btultra2), // level 20.
        p(17, 18, 17, 9, 3, 512, Btultra2), // level 21.
        p(17, 18, 17, 11, 3, 999, Btultra2), // level 22.
    ],
    // SrcSize <= 16 KB
    [
        p(14, 12, 13, 1, 5, 1, Fast), // base for negative levels
        p(14, 14, 15, 1, 5, 0, Fast), // level  1
        p(14, 14, 15, 1, 4, 0, Fast), // level  2
        p(14, 14, 15, 2, 4, 0, Dfast), // level  3
        p(14, 14, 14, 4, 4, 2, Greedy), // level  4
        p(14, 14, 14, 3, 4, 4, Lazy), // level  5.
        p(14, 14, 14, 4, 4, 8, Lazy2), // level  6
        p(14, 14, 14, 6, 4, 8, Lazy2), // level  7
        p(14, 14, 14, 8, 4, 8, Lazy2), // level  8.
        p(14, 15, 14, 5, 4, 8, Btlazy2), // level  9.
        p(14, 15, 14, 9, 4, 8, Btlazy2), // level 10.
        p(14, 15, 14, 3, 4, 12, Btopt), // level 11.
        p(14, 15, 14, 4, 3, 24, Btopt), // level 12.
        p(14, 15, 14, 5, 3, 32, Btultra), // level 13.
        p(14, 15, 15, 6, 3, 64, Btultra), // level 14.
        p(14, 15, 15, 7, 3, 256, Btultra), // level 15.
        p(14, 15, 15, 5, 3, 48, Btultra2), // level 16.
        p(14, 15, 15, 6, 3, 128, Btultra2), // level 17.
        p(14, 15, 15, 7, 3, 256, Btultra2), // level 18.
        p(14, 15, 15, 8, 3, 256, Btultra2), // level 19.
        p(14, 15, 15, 8, 3, 512, Btultra2), // level 20.
        p(14, 15, 15, 9, 3, 512, Btultra2), // level 21.
        p(14, 15, 15, 10, 3, 999, Btultra2), // level 22.
    ],
];
