//! Port of `dictBuilder/zdict.c`, but the legacy trainer
//! (`ZDICT_trainFromBuffer_legacy`): a zstd dictionary's header and
//! entropy tables made from samples, for a content given
//! (`ZDICT_finalizeDictionary`, `ZDICT_addEntropyTablesFromBuffer`), the
//! statistics they come from (`ZDICT_analyzeEntropy`), the default trainer
//! (`ZDICT_trainFromBuffer`), and the helpers on dictionaries.
//!
//! A zstd dictionary is the magic number `ZSTD_MAGIC_DICTIONARY`, its ID,
//! the entropy tables of a block (literals, offset codes, match lengths,
//! literal lengths), three repeat offsets, then its content. The tables
//! come from the samples compressed as single blocks with the content as a
//! dictionary (`ZDICT_countEStats`).
//!
//! `ZDICT_isError` and `ZDICT_getErrorName` are [`Result`] and
//! [`ErrorCode::message`](crate::zstd::ErrorCode::message).

use crate::zstd::common::bits::highbit32;
use crate::zstd::common::error_private::{Error, ErrorCode, Result, error};
use crate::zstd::common::mem::{read_le32, write_le32};
use crate::zstd::common::xxhash::xxh64;
use crate::zstd::common::zstd_internal::{
    LL_FSE_LOG, MAX_LL, MAX_ML, MAX_OFF, ML_FSE_LOG, OFF_FSE_LOG, REP_START_VALUE,
    ZSTD_BLOCKSIZE_MAX, ZSTD_MAGIC_DICTIONARY, ZSTD_REP_NUM,
};
use crate::zstd::compress::fse_compress::{fse_normalize_count, fse_write_ncount};
use crate::zstd::compress::huf_compress::{
    HUF_CTABLE_SIZE, HufCTable, huf_build_ctable_wksp, huf_write_ctable_wksp,
};
use crate::zstd::compress::zstd_cdict::{CDict, zstd_load_c_entropy};
use crate::zstd::compress::zstd_compress::{
    CCtx, CParamMode, ZSTD_CLEVEL_DEFAULT, zstd_get_params_internal, zstd_seq_to_codes,
};
use crate::zstd::compress::zstd_compress_internal::{CompressedBlockState, CompressionParameters};
use crate::zstd::decompress::zstd_ddict::DictContentType;
use crate::zstd::dict_builder::check_samples;
use crate::zstd::dict_builder::fastcover::{
    FastCoverParams, optimize_train_from_buffer_fast_cover,
};

/// `ZDICT_DICTSIZE_MIN`: the smallest dictionary the trainers make, and
/// the smallest room [`finalize_dictionary`] takes.
pub(crate) const ZDICT_DICTSIZE_MIN: usize = 256;

/// `ZDICT_CONTENTSIZE_MIN`: the smallest content the legacy trainer keeps.
pub(crate) const ZDICT_CONTENTSIZE_MIN: usize = 128;

/// `MAXREPOFFSET`: the offsets counted as candidates for the repeat
/// offsets.
const MAXREPOFFSET: usize = 1024;

/// `OFFCODE_MAX`: the largest offset code of the dictionary's table, which
/// only the first block uses.
const OFFCODE_MAX: u32 = 30;

/// `HBUFFSIZE`: room for the header and entropy tables of
/// [`finalize_dictionary`], which they always fit.
const HBUFFSIZE: usize = 256;

/// `ZDICT_params_t`: the parameters every trainer takes for the header and
/// tables of its dictionary.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DictParams {
    /// The level the dictionary is made for: its tables are the statistics
    /// of blocks compressed at that level. 0 means the default level
    /// ([`default_c_level`](crate::zstd::default_c_level)).
    pub compression_level: i32,
    /// libzstd's notifications on stderr, from 0 (none) to 4 (debug).
    /// Taken and ignored: the port prints nothing. The optimizers give it
    /// back lowered by one, as libzstd does.
    pub notification_level: u32,
    /// The dictionary's ID; 0 for one made from a hash of the content,
    /// from 32768 to 2^31 - 1. The zstd format keeps the IDs up to 32767,
    /// and from 2^31, for a registry of public dictionaries.
    pub dict_id: u32,
}

/// `ZDICT_getDictID`: the ID of the zstd dictionary `dict`, or 0 when it
/// is not one (fewer than 8 bytes, or not the dictionary magic number).
/// The same as [`get_dict_id_from_dict`](crate::zstd::get_dict_id_from_dict).
pub fn get_dict_id(dict: &[u8]) -> u32 {
    if dict.len() < 8 {
        return 0;
    }
    if read_le32(dict, 0) != ZSTD_MAGIC_DICTIONARY {
        return 0;
    }
    read_le32(dict, 4)
}

/// `ZDICT_getDictHeaderSize`: the size of the zstd dictionary `dict`'s
/// header, its magic number, ID, entropy tables and repeat offsets: where
/// its content starts. Fails with [`ErrorCode::DictionaryCorrupted`] when
/// it is not a zstd dictionary, or one the encoder cannot load
/// (`ZSTD_loadCEntropy`).
pub fn get_dict_header_size(dict: &[u8]) -> Result<usize> {
    if dict.len() <= 8 || read_le32(dict, 0) != ZSTD_MAGIC_DICTIONARY {
        return error!(DictionaryCorrupted);
    }
    let mut bs = CompressedBlockState::new(0);
    bs.reset();
    zstd_load_c_entropy(&mut bs, dict)
}

/// `EStats_ress_t`: what the statistics are counted with: the content as a
/// `CDict`, a context, and room for a compressed block.
struct EStatsRess {
    dict: CDict,
    zc: CCtx,
    work_place: Vec<u8>,
}

/// The statistics `ZDICT_analyzeEntropy` gathers.
struct EStats {
    count_lit: [u32; 256],
    /// Up to `MaxOff`, where libzstd's array stops at `OFFCODE_MAX`: see
    /// [`zdict_count_e_stats`].
    offcode_count: [u32; MAX_OFF as usize + 1],
    matchlength_count: [u32; MAX_ML as usize + 1],
    litlength_count: [u32; MAX_LL as usize + 1],
    rep_offsets: [u32; MAXREPOFFSET],
}

/// `ZDICT_countEStats`: the statistics of `src`, compressed as one block
/// with the content as a dictionary (`ZSTD_compressBegin_usingCDict`, then
/// `ZSTD_compressBlock`), with `c_params`: its literals, the codes of its
/// sequences, and its first two offsets as candidates for the repeat
/// offsets. Only its first block's worth is compressed. A sample that
/// fails to compress, or does not compress (a block stored raw), counts
/// for nothing.
///
/// Differs from libzstd: libzstd's offset code counts stop at
/// `OFFCODE_MAX`, and an offset code of 31 (an offset past 2^31 - 4)
/// would be written past them; the port's has room for it. Only the codes
/// up to the dictionary's largest are read.
fn zdict_count_e_stats(
    esr: &mut EStatsRess,
    c_params: &CompressionParameters,
    stats: &mut EStats,
    src: &[u8],
) {
    let block_size_max = ZSTD_BLOCKSIZE_MAX.min(1usize << c_params.window_log);
    // Large samples: their first block only.
    let src = &src[..src.len().min(block_size_max)];
    let c_size = match esr
        .zc
        .compress_block_using_cdict(&mut esr.work_place, src, &esr.dict)
    {
        Ok(c_size) => c_size,
        // ZSTD_compressBegin_usingCDict or ZSTD_compressBlock failed: the
        // sample is left out.
        Err(_) => return,
    };
    if c_size == 0 {
        // Not compressible.
        return;
    }
    let seq_store = esr.zc.seq_store();

    // The literals.
    for &byte in seq_store.literals() {
        stats.count_lit[usize::from(byte)] = stats.count_lit[usize::from(byte)].wrapping_add(1);
    }

    // The sequences.
    let nb_seq = seq_store.sequences.len();
    let whole = seq_store.whole();
    zstd_seq_to_codes(&mut seq_store.view(&whole));
    for &code in &seq_store.of_code[..nb_seq] {
        let count = &mut stats.offcode_count[usize::from(code)];
        *count = count.wrapping_add(1);
    }
    for &code in &seq_store.ml_code[..nb_seq] {
        let count = &mut stats.matchlength_count[usize::from(code)];
        *count = count.wrapping_add(1);
    }
    for &code in &seq_store.ll_code[..nb_seq] {
        let count = &mut stats.litlength_count[usize::from(code)];
        *count = count.wrapping_add(1);
    }

    if nb_seq >= 2 {
        // The first two offsets: repeat codes (offBase 1 to 3) wrap around
        // to large values, which count as 0.
        let mut offset1 = seq_store.sequences[0]
            .off_base
            .wrapping_sub(ZSTD_REP_NUM as u32);
        let mut offset2 = seq_store.sequences[1]
            .off_base
            .wrapping_sub(ZSTD_REP_NUM as u32);
        if offset1 as usize >= MAXREPOFFSET {
            offset1 = 0;
        }
        if offset2 as usize >= MAXREPOFFSET {
            offset2 = 0;
        }
        let reps = &mut stats.rep_offsets;
        reps[offset1 as usize] = reps[offset1 as usize].wrapping_add(3);
        reps[offset2 as usize] = reps[offset2 as usize].wrapping_add(1);
    }
}

/// `ZDICT_totalSampleSize`
pub(crate) fn zdict_total_sample_size(sample_sizes: &[usize]) -> usize {
    sample_sizes
        .iter()
        .fold(0usize, |total, &size| total.wrapping_add(size))
}

/// `offsetCount_t`
#[derive(Clone, Copy, Default, Debug)]
struct OffsetCount {
    offset: u32,
    count: u32,
}

/// `ZDICT_insertSortCount`: `val` with `count` into the table of the most
/// frequent offsets, sorted by decreasing count, the last slot a scratch
/// one.
fn zdict_insert_sort_count(table: &mut [OffsetCount; ZSTD_REP_NUM + 1], val: u32, count: u32) {
    table[ZSTD_REP_NUM] = OffsetCount { offset: val, count };
    let mut u = ZSTD_REP_NUM;
    while u > 0 {
        if table[u - 1].count >= table[u].count {
            break;
        }
        table.swap(u - 1, u);
        u -= 1;
    }
}

/// `ZDICT_flatLit`: `count_lit` made a mostly flat distribution, yet one
/// that compresses, which `HUF_writeCTable` can describe.
fn zdict_flat_lit(count_lit: &mut [u32; 256]) {
    for count in &mut count_lit[1..] {
        *count = 2;
    }
    count_lit[0] = 4;
    count_lit[253] = 1;
    count_lit[254] = 1;
}

/// `ZDICT_analyzeEntropy`: the entropy tables of a dictionary of content
/// `dict` for `compression_level` (0 for the default), from the samples
/// compressed with it, written into `dst`: the Huffman table of the
/// literals, the FSE tables of the offset codes, match lengths and literal
/// lengths, then the three repeat offsets. Returns their size.
///
/// Every symbol gets a count of 1 to start with, so that it can be
/// described. Literals too flat or too regular for a Huffman table to save
/// anything take a made-up distribution. The repeat offsets are libzstd's
/// usual first ones: the most frequent offsets are counted, but not used,
/// as in libzstd.
///
/// Fails with `DictionaryCreationFailed` for a content of over 1 GB
/// (offsets past the largest code of the table), and as the table
/// functions fail, `DstSizeTooSmall` among them.
pub(crate) fn zdict_analyze_entropy(
    dst: &mut [u8],
    compression_level: i32,
    samples: &[u8],
    sample_sizes: &[usize],
    dict: &[u8],
    _notification_level: u32,
) -> Result<usize> {
    let mut stats = EStats {
        // Any character must be described.
        count_lit: [1; 256],
        offcode_count: [0; MAX_OFF as usize + 1],
        matchlength_count: [1; MAX_ML as usize + 1],
        litlength_count: [1; MAX_LL as usize + 1],
        rep_offsets: [0; MAXREPOFFSET],
    };
    let mut huf_table: HufCTable = [0; HUF_CTABLE_SIZE];
    let mut offcode_ncount = [0i16; OFFCODE_MAX as usize + 1];
    let mut matchlength_ncount = [0i16; MAX_ML as usize + 1];
    let mut litlength_ncount = [0i16; MAX_LL as usize + 1];
    let mut best_rep_offset = [OffsetCount::default(); ZSTD_REP_NUM + 1];
    // The offset code of the largest offset into the content and a block:
    // `(U32)(dictBufferSize + 128 KB)`, which a content of 4 GB wraps
    // around (to 0: no bit set, too large either way).
    let offcode_max = match (dict.len() as u64).wrapping_add(128 << 10) as u32 {
        0 => u32::MAX,
        reach => highbit32(reach),
    };
    let total_src_size = zdict_total_sample_size(sample_sizes);
    let average_sample_size = total_src_size / sample_sizes.len().max(1);

    if offcode_max > OFFCODE_MAX {
        // Too large a dictionary.
        return error!(DictionaryCreationFailed);
    }
    for count in &mut stats.offcode_count[..=offcode_max as usize] {
        *count = 1;
    }
    stats.rep_offsets[1] = 1;
    stats.rep_offsets[4] = 1;
    stats.rep_offsets[8] = 1;
    let compression_level = if compression_level == 0 {
        ZSTD_CLEVEL_DEFAULT
    } else {
        compression_level
    };
    // ZSTD_getParams: a size of 0 is unknown.
    let src_size_hint = match average_sample_size {
        0 => u64::MAX,
        size => size as u64,
    };
    let (c_params, _) = zstd_get_params_internal(
        compression_level,
        src_size_hint,
        dict.len(),
        CParamMode::Unknown,
    );

    // ZSTD_createCDict_advanced, as raw content (by reference in libzstd,
    // which only saves a copy), with the level's parameters for the samples.
    let mut esr = EStatsRess {
        dict: CDict::create_advanced(dict, DictContentType::RawContent, &c_params)
            .map_err(|_| Error::from(ErrorCode::MemoryAllocation))?,
        zc: CCtx::new(),
        work_place: crate::zstd::dict_builder::zeroed(ZSTD_BLOCKSIZE_MAX)?,
    };

    // The statistics of every sample.
    let mut pos = 0usize;
    for &size in sample_sizes {
        zdict_count_e_stats(&mut esr, &c_params, &mut stats, &samples[pos..pos + size]);
        pos += size;
    }
    drop(esr);

    // The literals first.
    let mut huff_log = 11;
    {
        let mut max_nb_bits =
            huf_build_ctable_wksp(&mut huf_table, &stats.count_lit, 255, huff_log)?;
        if max_nb_bits == 8 {
            // Not compressible, which HUF_writeCTable cannot describe: the
            // samples are noise, or too regular. A made-up distribution
            // instead, mostly flat, which compresses.
            zdict_flat_lit(&mut stats.count_lit);
            max_nb_bits = huf_build_ctable_wksp(&mut huf_table, &stats.count_lit, 255, huff_log)?;
            debug_assert!(max_nb_bits == 9);
        }
        huff_log = max_nb_bits;
    }

    // The most frequent first offsets: counted, but the result is not used
    // (libzstd does not judge their effect on the statistics yet).
    for offset in 1..MAXREPOFFSET as u32 {
        zdict_insert_sort_count(
            &mut best_rep_offset,
            offset,
            stats.rep_offsets[offset as usize],
        );
    }

    let total = stats.offcode_count[..=offcode_max as usize]
        .iter()
        .fold(0u32, |total, &count| total.wrapping_add(count));
    let off_log = fse_normalize_count(
        &mut offcode_ncount,
        OFF_FSE_LOG,
        &stats.offcode_count,
        total as usize,
        offcode_max,
        true,
    )?;

    let total = stats
        .matchlength_count
        .iter()
        .fold(0u32, |total, &count| total.wrapping_add(count));
    let ml_log = fse_normalize_count(
        &mut matchlength_ncount,
        ML_FSE_LOG,
        &stats.matchlength_count,
        total as usize,
        MAX_ML,
        true,
    )?;

    let total = stats
        .litlength_count
        .iter()
        .fold(0u32, |total, &count| total.wrapping_add(count));
    let ll_log = fse_normalize_count(
        &mut litlength_ncount,
        LL_FSE_LOG,
        &stats.litlength_count,
        total as usize,
        MAX_LL,
        true,
    )?;

    // The tables, into `dst`.
    let mut pos = 0;
    pos += huf_write_ctable_wksp(&mut dst[pos..], &huf_table, 255, huff_log)?;
    // The offset codes past the largest are 0, never read: their
    // normalized counts add up before them.
    pos += fse_write_ncount(&mut dst[pos..], &offcode_ncount, OFFCODE_MAX, off_log)?;
    pos += fse_write_ncount(&mut dst[pos..], &matchlength_ncount, MAX_ML, ml_log)?;
    pos += fse_write_ncount(&mut dst[pos..], &litlength_ncount, MAX_LL, ll_log)?;

    if dst.len() - pos < 12 {
        // No room for the repeat offsets.
        return error!(DstSizeTooSmall);
    }
    // libzstd's usual first repeat offsets, not the most frequent offsets
    // (`bestRepOffset`): their effect on the statistics is not judged.
    for (i, &rep) in REP_START_VALUE.iter().enumerate() {
        write_le32(dst, pos + 4 * i, rep);
    }
    Ok(pos + 12)
}

/// `ZDICT_maxRep`: the largest repeat offset.
fn zdict_max_rep(reps: &[u32; ZSTD_REP_NUM]) -> u32 {
    reps.iter().copied().fold(reps[0], u32::max)
}

/// The ID of a dictionary of `content`: `params.dict_id`, or, for 0, one
/// from its hash in the range a dictionary of no registry may take.
fn zdict_dict_id(content: &[u8], params: &DictParams) -> u32 {
    let random_id = xxh64(content, 0);
    let compliant_id = (random_id % ((1u64 << 31) - 32768)) as u32 + 32768;
    if params.dict_id != 0 {
        params.dict_id
    } else {
        compliant_id
    }
}

/// Where the content of [`zdict_finalize_dictionary`] is.
pub(crate) enum Content<'a> {
    /// A buffer of its own.
    Apart(&'a [u8]),
    /// The end of the dictionary's buffer, from this position, where the
    /// COVER trainers build it.
    Within(usize),
}

/// `ZDICT_finalizeDictionary`, with the content apart or within the
/// dictionary's buffer (libzstd's may overlap it anywhere): the header
/// (the magic number, the ID, the entropy tables of the first
/// `sample_sizes.len()` samples) into `dict`, then the content, cut to fit,
/// after zeros if it is shorter than the largest repeat offset.
pub(crate) fn zdict_finalize_dictionary(
    dict: &mut [u8],
    content: Content<'_>,
    samples: &[u8],
    sample_sizes: &[usize],
    params: DictParams,
) -> Result<usize> {
    let capacity = dict.len();
    let compression_level = if params.compression_level == 0 {
        ZSTD_CLEVEL_DEFAULT
    } else {
        params.compression_level
    };
    // The content must be at least as long as the largest repeat offset.
    let min_content_size = zdict_max_rep(&REP_START_VALUE) as usize;
    let mut header = [0u8; HBUFFSIZE];
    let mut dict_content_size;
    let h_size;
    {
        let content = match content {
            Content::Apart(content) => content,
            Content::Within(start) => &dict[start..],
        };
        dict_content_size = content.len();

        if capacity < dict_content_size {
            return error!(DstSizeTooSmall);
        }
        if capacity < ZDICT_DICTSIZE_MIN {
            return error!(DstSizeTooSmall);
        }

        // The dictionary header.
        write_le32(&mut header, 0, ZSTD_MAGIC_DICTIONARY);
        write_le32(&mut header, 4, zdict_dict_id(content, &params));

        // The entropy tables.
        let e_size = zdict_analyze_entropy(
            &mut header[8..],
            compression_level,
            samples,
            sample_sizes,
            content,
            params.notification_level,
        )?;
        h_size = 8 + e_size;
    }

    // The content cut, its start kept, if the whole does not fit.
    if h_size + dict_content_size > capacity {
        dict_content_size = capacity - h_size;
    }

    // Zeros before the content, if it is too short.
    let padding_size = if dict_content_size < min_content_size {
        if h_size + min_content_size > capacity {
            // No room for the largest repeat offset.
            return error!(DstSizeTooSmall);
        }
        min_content_size - dict_content_size
    } else {
        0
    };

    // The header, the padding, then the content: the best place in a
    // dictionary is its last byte. The content first, as it may lie where
    // the header goes.
    let dict_size = h_size + padding_size + dict_content_size;
    debug_assert!(dict_size <= capacity);
    let content_at = h_size + padding_size;
    match content {
        Content::Apart(content) => {
            dict[content_at..dict_size].copy_from_slice(&content[..dict_content_size]);
        }
        Content::Within(start) => {
            dict.copy_within(start..start + dict_content_size, content_at);
        }
    }
    dict[..h_size].copy_from_slice(&header[..h_size]);
    dict[h_size..content_at].fill(0);
    Ok(dict_size)
}

/// `ZDICT_finalizeDictionary`: the zstd dictionary of `content`, its header
/// made for the samples, into `dict`. Returns its size.
///
/// The header is the dictionary magic number, the ID (`params.dict_id`, or
/// one from a hash of the content), and the entropy tables of the samples
/// compressed with the content at `params.compression_level`, which should
/// be the level the dictionary will be used at. When the header and the
/// content do not fit `dict`, the content is cut: its start is kept. A
/// content shorter than 8 bytes, the largest first repeat offset, comes
/// after zeros.
///
/// `dict` must have room for 256 bytes (libzstd's `ZDICT_DICTSIZE_MIN`) and
/// for the content, or the call fails with [`ErrorCode::DstSizeTooSmall`].
/// It fails as libzstd does on some samples: too few, that do not
/// compress, all the same.
///
/// Differs from libzstd: the content cannot lie within `dict`, which safe
/// Rust's borrows forbid; libzstd allows it anywhere. The result would be
/// the same.
pub fn finalize_dictionary(
    dict: &mut [u8],
    content: &[u8],
    samples: &[u8],
    sample_sizes: &[usize],
    params: DictParams,
) -> Result<usize> {
    check_samples(samples, sample_sizes)?;
    zdict_finalize_dictionary(dict, Content::Apart(content), samples, sample_sizes, params)
}

/// `ZDICT_addEntropyTablesFromBuffer_advanced`: the zstd dictionary whose
/// content is the last `dict_content_size` bytes of `dict`: its header,
/// written at the start of `dict`, then the content moved right after it.
/// Returns its size, at most `dict.len()`.
///
/// The entropy tables are written first, then the magic number, then the
/// ID, which is a hash of the content as it is then: when the header runs
/// into the content (a content that nearly fills `dict`), the bytes it
/// wrote over are part of the hash, and of the dictionary, as in libzstd.
/// For the legacy trainer, which builds the content at the end of `dict`.
///
/// Differs from libzstd: libzstd writes before or past `dict` with a
/// buffer under 8 bytes or a content larger than it; the port fails with
/// `DstSizeTooSmall`.
pub(crate) fn zdict_add_entropy_tables_from_buffer_advanced(
    dict: &mut [u8],
    dict_content_size: usize,
    samples: &[u8],
    sample_sizes: &[usize],
    params: DictParams,
) -> Result<usize> {
    let capacity = dict.len();
    if capacity < 8 || dict_content_size > capacity {
        return error!(DstSizeTooSmall);
    }
    let compression_level = if params.compression_level == 0 {
        ZSTD_CLEVEL_DEFAULT
    } else {
        params.compression_level
    };
    let content_start = capacity - dict_content_size;
    let mut h_size = 8;

    // The entropy tables. The content is read in full before any is
    // written (libzstd's CDict references it until then).
    {
        let content = dict[content_start..].to_vec();
        let e_size = zdict_analyze_entropy(
            &mut dict[h_size..],
            compression_level,
            samples,
            sample_sizes,
            &content,
            params.notification_level,
        )?;
        h_size += e_size;
    }

    // The dictionary header, after the tables.
    write_le32(dict, 0, ZSTD_MAGIC_DICTIONARY);
    let dict_id = zdict_dict_id(&dict[content_start..], &params);
    write_le32(dict, 4, dict_id);

    if h_size + dict_content_size < capacity {
        dict.copy_within(content_start.., h_size);
    }
    Ok(capacity.min(h_size + dict_content_size))
}

/// `ZDICT_addEntropyTablesFromBuffer`: the zstd dictionary whose content
/// is the last `dict_content_size` bytes of `dict`, its header made for the
/// samples at the default level, with an ID from a hash of the content.
/// The header goes at the start of `dict`, the content right after it.
/// Returns the dictionary's size, at most `dict.len()`.
///
/// When the header runs into the content, it writes over the content's
/// first bytes, as in libzstd, which then hashes the content with them.
/// Deprecated in libzstd for [`finalize_dictionary`], which takes the
/// content apart and cuts it to fit. Fails with
/// [`ErrorCode::DstSizeTooSmall`] when the content is larger than `dict`
/// (where libzstd reads before it), or `dict` is under 8 bytes.
pub fn add_entropy_tables_from_buffer(
    dict: &mut [u8],
    dict_content_size: usize,
    samples: &[u8],
    sample_sizes: &[usize],
) -> Result<usize> {
    check_samples(samples, sample_sizes)?;
    zdict_add_entropy_tables_from_buffer_advanced(
        dict,
        dict_content_size,
        samples,
        sample_sizes,
        DictParams::default(),
    )
}

/// `ZDICT_trainFromBuffer`: a dictionary trained on the samples, into
/// `dict`. Returns its size, at most `dict.len()`.
///
/// The default trainer: the optimizer of the fast COVER trainer
/// ([`optimize_train_from_buffer_fast_cover`](crate::zstd::optimize_train_from_buffer_fast_cover)),
/// on one thread, with `d` = 8, `steps` = 4, `f` = 20 and `accel` = 1,
/// for the default level; a quarter of the samples, the last ones, test
/// the dictionaries it tries. About 100 KB of dictionary, from about 100
/// times as much of samples, is reasonable.
///
/// Training fails when there are not enough samples (at least 7), or
/// when most of them are too small (8 bytes at least), as in libzstd:
/// with [`ErrorCode::SrcSizeWrong`], or [`ErrorCode::DstSizeTooSmall`] for
/// room under 256 bytes. A dictionary would not help such samples anyway.
///
/// ```
/// # fn main() -> Result<(), hivepack::zstd::Error> {
/// let mut samples = Vec::new();
/// let mut sizes = Vec::new();
/// for i in 0..200 {
///     let sample = format!("{{\"id\": {i}, \"name\": \"user{}\", \"active\": {}}}", i * 7, i % 2 == 0);
///     samples.extend_from_slice(sample.as_bytes());
///     sizes.push(sample.len());
/// }
/// let mut dict = vec![0; 1024];
/// let size = hivepack::zstd::train_from_buffer(&mut dict, &samples, &sizes)?;
/// dict.truncate(size);
/// assert_ne!(hivepack::zstd::get_dict_id(&dict), 0);
///
/// // The dictionary at work.
/// let cdict = hivepack::zstd::CDict::new(&dict, 3)?;
/// let mut frame = vec![0; 1000];
/// let src = &samples[..sizes[0]];
/// let n = hivepack::zstd::CCtx::new().compress_using_cdict(&mut frame, src, &cdict)?;
/// let ddict = hivepack::zstd::DDict::new(&dict)?;
/// let mut out = vec![0; src.len()];
/// let back = hivepack::zstd::DCtx::new().decompress_using_ddict(&mut out, &frame[..n], &ddict)?;
/// assert_eq!(&out[..back], src);
/// # Ok(())
/// # }
/// ```
pub fn train_from_buffer(dict: &mut [u8], samples: &[u8], sample_sizes: &[usize]) -> Result<usize> {
    let mut params = FastCoverParams {
        d: 8,
        steps: 4,
        // The default level: no level is given.
        z_params: DictParams {
            compression_level: ZSTD_CLEVEL_DEFAULT,
            ..DictParams::default()
        },
        ..FastCoverParams::default()
    };
    optimize_train_from_buffer_fast_cover(dict, samples, sample_sizes, &mut params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_sort_count_keeps_the_largest_counts_in_order() {
        let mut table = [OffsetCount::default(); ZSTD_REP_NUM + 1];
        for (offset, count) in [(1, 5), (2, 9), (3, 5), (4, 1), (5, 7)] {
            zdict_insert_sort_count(&mut table, offset, count);
        }
        let kept: Vec<(u32, u32)> = table[..ZSTD_REP_NUM]
            .iter()
            .map(|t| (t.offset, t.count))
            .collect();
        // Ties keep the earlier offset first.
        assert_eq!(kept, [(2, 9), (5, 7), (1, 5)]);
    }

    #[test]
    fn dict_ids_and_header_sizes() {
        assert_eq!(get_dict_id(&[]), 0);
        assert_eq!(get_dict_id(&[0x37, 0xa4, 0x30, 0xec, 1, 2, 3]), 0);
        assert_eq!(
            get_dict_id(&[0x37, 0xa4, 0x30, 0xec, 1, 2, 3, 4]),
            0x0403_0201
        );
        assert_eq!(get_dict_id(&[0x28, 0xb5, 0x2f, 0xfd, 1, 2, 3, 4]), 0);
        let code = |r: Result<usize>| r.map_err(|e| e.code());
        assert_eq!(
            code(get_dict_header_size(&[0x37, 0xa4, 0x30, 0xec, 1, 2, 3, 4])),
            Err(ErrorCode::DictionaryCorrupted)
        );
        assert_eq!(
            code(get_dict_header_size(&[
                0x37, 0xa4, 0x30, 0xec, 1, 2, 3, 4, 0
            ])),
            Err(ErrorCode::DictionaryCorrupted)
        );
    }
}
