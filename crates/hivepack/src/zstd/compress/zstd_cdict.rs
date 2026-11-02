//! Compressing with a dictionary: port of the dictionary parts of
//! `compress/zstd_compress.c`. The `ZSTD_CDict`, a dictionary made ready
//! once for many frames; how a dictionary's content goes into a match
//! state's window and tables (`ZSTD_loadDictionaryContent`), and a zstd
//! dictionary's entropy tables into a block state (`ZSTD_loadCEntropy`);
//! and whether a frame attaches a `CDict` or copies it
//! (`ZSTD_shouldAttachDict`). The context's side is in `zstd_compress.rs`.
//!
//! A dictionary's content is in its own buffer, [`WindowBuffer::Dict`]: a
//! window over it is the segment before the input, the older segment once
//! the input comes, which the `extDict` block compressors search.

use crate::zstd::common::bits::highbit32;
use crate::zstd::common::entropy_common::fse_read_ncount;
use crate::zstd::common::error_private::{Error, ErrorCode, Result, error};
use crate::zstd::common::mem::read_le32;
use crate::zstd::common::zstd_internal::{
    LL_FSE_LOG, MAX_LL, MAX_ML, MAX_OFF, ML_FSE_LOG, OFF_FSE_LOG, ZSTD_MAGIC_DICTIONARY,
};
use crate::zstd::compress::fse_compress::fse_build_ctable_wksp;
use crate::zstd::compress::huf_compress::{HufRepeat, huf_read_ctable};
use crate::zstd::compress::zstd_compress::{
    CCtxParams, CParamMode, CParamOverrides, CParameter, ResetTarget, TableReset,
    ZSTD_CLEVEL_DEFAULT, ZSTD_CONTENTSIZE_UNKNOWN, set_cctx_parameter,
    zstd_get_cparams_from_cctx_params, zstd_get_cparams_internal, zstd_overflow_correct_if_needed,
    zstd_override_cparams, zstd_reset_match_state, zstd_resolve_row_match_finder_mode,
};
use crate::zstd::compress::zstd_compress_internal::{
    CompressedBlockState, CompressionParameters, DictAttachPref, FseRepeat, HASH_READ_SIZE,
    LdmState, MatchState, ParamSwitch, Strategy, WindowBuffer, ZSTD_CHUNKSIZE_MAX,
    ZSTD_CURRENT_MAX, ZSTD_HASHLOG_MIN, ZSTD_SHORT_CACHE_TAG_BITS, ZSTD_WINDOW_START_INDEX,
};
use crate::zstd::compress::zstd_double_fast::{
    zstd_fill_double_hash_table, zstd_fill_double_hash_table_for_cdict,
};
use crate::zstd::compress::zstd_fast::{zstd_fill_hash_table, zstd_fill_hash_table_for_cdict};
use crate::zstd::compress::zstd_lazy::{
    ZSTD_LAZY_DDSS_BUCKET_LOG, zstd_dedicated_dict_search_lazy_load_dictionary,
    zstd_insert_and_find_first_index, zstd_row_update,
};
use crate::zstd::compress::zstd_ldm::zstd_ldm_fill_hash_table;
use crate::zstd::compress::zstd_opt::zstd_update_tree;
use crate::zstd::decompress::zstd_ddict::DictContentType;

/// `ZSTD_CDict`: a dictionary made ready for compression, so that frames
/// using it start without the work of reading it: its entropy tables, and
/// its content in a match state's tables, for the parameters it was made
/// for. Give it to [`CCtx::ref_cdict`](crate::zstd::CCtx::ref_cdict) or
/// [`CCtx::compress_using_cdict`](crate::zstd::CCtx::compress_using_cdict).
///
/// Its parameters are a level's, for an input of unknown size, or those
/// given. A frame of a small input (or of unknown size) searches the
/// `CDict`'s tables where they are (it attaches the `CDict`); a larger one
/// copies them into its context; a large one, for a `CDict` made for a
/// level, reads its content again with parameters for the input. See
/// [`DictAttachPref`].
///
/// The content is always copied in (`ZSTD_dlm_byCopy`). A `CDict` does not
/// change once made: one can serve many contexts, behind an
/// [`Arc`](std::sync::Arc).
pub struct CDict {
    /// The whole dictionary, its header and tables included for a zstd
    /// dictionary (`dictContent`): the window of the match state is over
    /// it, from the content on ([`WindowBuffer::Dict`]).
    pub(crate) content: Box<[u8]>,
    /// How to read it, for a context that loads it again.
    pub(crate) content_type: DictContentType,
    /// Its match state: its parameters (`matchState.cParams`), its window
    /// over the content, and its tables, filled with every position
    /// (`ZSTD_dtlm_full`), their indices tagged for `fast` and `dfast`.
    pub(crate) match_state: MatchState,
    /// `cBlockState`: a zstd dictionary's entropy tables and repeat
    /// offsets, as the block before the frame's first.
    pub(crate) c_block_state: CompressedBlockState,
    pub(crate) dict_id: u32,
    /// The level it was made for, 0 (`ZSTD_NO_CLEVEL`) when made from
    /// parameters.
    pub(crate) compression_level: i32,
    /// Whether its tables are the row match finder's: resolved for its
    /// parameters.
    pub(crate) use_row_match_finder: ParamSwitch,
}

impl CDict {
    /// `ZSTD_createCDict`: `dict` made ready for frames at
    /// `compression_level` (0 for the default), read as a zstd dictionary
    /// if it starts with the dictionary magic number, as raw content
    /// otherwise.
    ///
    /// Its parameters are those of the level for an input of unknown size
    /// with a dictionary of this size. Fails as libzstd does (where it
    /// returns no `CDict`), with [`ErrorCode::DictionaryCorrupted`] for a
    /// zstd dictionary it cannot read.
    pub fn new(dict: &[u8], compression_level: i32) -> Result<CDict> {
        let c_params = zstd_get_cparams_internal(
            compression_level,
            ZSTD_CONTENTSIZE_UNKNOWN,
            dict.len(),
            CParamMode::CreateCDict,
        );
        let mut cdict = CDict::create_advanced(dict, DictContentType::Auto, &c_params)?;
        cdict.compression_level = if compression_level == 0 {
            ZSTD_CLEVEL_DEFAULT
        } else {
            compression_level
        };
        Ok(cdict)
    }

    /// `ZSTD_createCDict_advanced`, with the content copied in: `dict`,
    /// read as `content_type` says, made ready with `c_params` (but a
    /// target length of 0, which is the default level's), for no level.
    pub(crate) fn create_advanced(
        dict: &[u8],
        content_type: DictContentType,
        c_params: &CompressionParameters,
    ) -> Result<CDict> {
        // Parameters at level 0, with these compression parameters over
        // the level's.
        let (mut params, _) = CCtxParams::requested_default();
        params.compression_level = 0;
        let overrides = CParamOverrides::from(c_params);
        CDict::create_advanced2(dict, content_type, &params, &overrides)
    }

    /// `ZSTD_createCDict_advanced2`, with the content copied in: `dict`
    /// made ready with the parameters of a context that has `parameters`
    /// set (from the defaults, in order), read as `content_type` says.
    ///
    /// The compression parameters are those set over the level's for an
    /// input of unknown size (or of the size hint). It is made for no level
    /// (`ZSTD_NO_CLEVEL`): a frame referencing it takes the default level's
    /// parameters, under those it sets, sized for the input and the
    /// dictionary, and its tables are always the `CDict`'s, never loaded
    /// again for a large input. Fails as setting a parameter fails, or as
    /// reading the dictionary does:
    /// [`ErrorCode::DictionaryCorrupted`] for a zstd dictionary it cannot
    /// read, [`ErrorCode::DictionaryWrong`] for one that is not one with
    /// [`DictContentType::FullDict`].
    pub fn with_parameters(
        dict: &[u8],
        content_type: DictContentType,
        parameters: &[CParameter],
    ) -> Result<CDict> {
        // ZSTD_createCCtxParams, then ZSTD_CCtxParams_setParameter.
        let (mut params, mut overrides) = CCtxParams::requested_default();
        for &parameter in parameters {
            set_cctx_parameter(&mut params, &mut overrides, parameter)?;
        }
        CDict::create_advanced2(dict, content_type, &params, &overrides)
    }

    /// `ZSTD_createCDict_advanced2`, with the content copied in, for a
    /// context's parameters: `params` with `overrides`, the compression
    /// parameters set.
    pub(crate) fn create_advanced2(
        dict: &[u8],
        content_type: DictContentType,
        params: &CCtxParams,
        overrides: &CParamOverrides,
    ) -> Result<CDict> {
        let mut cctx_params = *params;
        // With ZSTD_c_enableDedicatedDictSearch, the level's parameters for
        // the dictionary alone with a larger hash table, under those set,
        // if they suit the dedicated search; otherwise as without it.
        let mut c_params = if cctx_params.enable_dedicated_dict_search {
            let mut c_params =
                zstd_dedicated_dict_search_get_cparams(cctx_params.compression_level, dict.len());
            zstd_override_cparams(&mut c_params, overrides);
            c_params
        } else {
            zstd_get_cparams_from_cctx_params(
                &cctx_params,
                overrides,
                ZSTD_CONTENTSIZE_UNKNOWN,
                dict.len(),
                CParamMode::CreateCDict,
            )
        };
        if !zstd_dedicated_dict_search_is_supported(&c_params) {
            // Back to the parameters without the dedicated search.
            cctx_params.enable_dedicated_dict_search = false;
            c_params = zstd_get_cparams_from_cctx_params(
                &cctx_params,
                overrides,
                ZSTD_CONTENTSIZE_UNKNOWN,
                dict.len(),
                CParamMode::CreateCDict,
            );
        }
        cctx_params.c_params = c_params;
        cctx_params.use_row_match_finder =
            zstd_resolve_row_match_finder_mode(cctx_params.use_row_match_finder, &c_params);

        // ZSTD_createCDict_advanced_internal, then ZSTD_initCDict_internal.
        let mut cdict = CDict {
            content: dict.into(),
            content_type,
            match_state: MatchState::new(c_params),
            c_block_state: CompressedBlockState::new(0),
            dict_id: 0,
            // Made from parameters (ZSTD_NO_CLEVEL).
            compression_level: 0,
            use_row_match_finder: cctx_params.use_row_match_finder,
        };
        // Before the reset, which then gives it a chain table whatever the
        // strategy.
        cdict.match_state.dedicated_dict_search = cctx_params.enable_dedicated_dict_search;
        // No dictionary yet.
        cdict.c_block_state.reset();
        zstd_reset_match_state(
            &mut cdict.match_state,
            &c_params,
            cctx_params.use_row_match_finder,
            TableReset::MakeClean,
            ResetTarget::CDict,
        );
        // Then the dictionary, if it has 8 bytes or more.
        cctx_params.compression_level = ZSTD_CLEVEL_DEFAULT;
        cctx_params.f_params.content_size_flag = true;
        cdict.dict_id = zstd_compress_insert_dictionary(
            &mut cdict.c_block_state,
            &mut cdict.match_state,
            None,
            &cctx_params,
            &cdict.content,
            content_type,
            DictTableLoadMethod::Full,
            TableFillPurpose::ForCDict,
        )?;
        Ok(cdict)
    }

    /// `ZSTD_getDictID_fromCDict`: the dictionary's ID, 0 for raw content
    /// (or a zstd dictionary made with the dictionary ID flag off).
    pub fn dict_id(&self) -> u32 {
        self.dict_id
    }

    /// The size of the dictionary given, its header included for a zstd
    /// dictionary (libzstd's `dictContentSize`).
    pub fn dict_size(&self) -> usize {
        self.content.len()
    }

    /// `ZSTD_getCParamsFromCDict`: the compression parameters it was made
    /// for.
    pub(crate) fn c_params(&self) -> &CompressionParameters {
        &self.match_state.c_params
    }

    /// The index after the content in its window (`cdictEnd`), and the
    /// length of the content there (`cdictLen`): 0 when nothing was loaded,
    /// for a dictionary of under 8 bytes.
    pub(crate) fn window_end_and_len(&self) -> (u32, u32) {
        let window = &self.match_state.window;
        let end = window.next_src as u32;
        (end, end - window.dict_limit)
    }
}

impl std::fmt::Debug for CDict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CDict")
            .field("dict_id", &self.dict_id)
            .field("dict_size", &self.content.len())
            .field("compression_level", &self.compression_level)
            .field("c_params", &self.match_state.c_params)
            .finish_non_exhaustive()
    }
}

/// `attachDictSizeCutoffs`: for each strategy, the input size up to which a
/// frame attaches a `CDict` rather than copy it: copying its tables costs
/// more than searching them where they are.
const ATTACH_DICT_SIZE_CUTOFFS: [u64; 10] = [
    8 << 10,  // unused
    8 << 10,  // fast
    16 << 10, // dfast
    32 << 10, // greedy
    32 << 10, // lazy
    32 << 10, // lazy2
    32 << 10, // btlazy2
    32 << 10, // btopt
    8 << 10,  // btultra
    8 << 10,  // btultra2
];

/// `ZSTD_shouldAttachDict`: whether a frame of `pledged_src_size` bytes
/// with `params` attaches `cdict` rather than copy it: always for a
/// dedicated dictionary search; otherwise for inputs up to the strategy's
/// cutoff or of unknown size, unless the preference says, and never with
/// `forceWindow` (`dictMatchState` does not keep to it).
pub(crate) fn zstd_should_attach_dict(
    cdict: &CDict,
    params: &CCtxParams,
    pledged_src_size: u64,
) -> bool {
    let cutoff = ATTACH_DICT_SIZE_CUTOFFS[cdict.match_state.c_params.strategy as usize];
    let dedicated_dict_search = cdict.match_state.dedicated_dict_search;
    dedicated_dict_search
        || ((pledged_src_size <= cutoff
            || pledged_src_size == ZSTD_CONTENTSIZE_UNKNOWN
            || params.attach_dict_pref == DictAttachPref::ForceAttach)
            && params.attach_dict_pref != DictAttachPref::ForceCopy
            && !params.force_window)
}

/// `ZSTD_dedicatedDictSearch_getCParams`: the parameters of a `CDict` with
/// the dedicated dictionary search, at `compression_level`: the level's
/// for an input of size 0 with a dictionary of `dict_size` bytes, with a
/// hash table `1 << ZSTD_LAZY_DDSS_BUCKET_LOG` times as large for `greedy`,
/// `lazy` and `lazy2`, its buckets.
///
/// Unlike a `CDict` without it, the size hint is not looked at, nor long
/// distance matching's window, and the parameters set over these are not
/// fitted to the dictionary again: libzstd does neither.
fn zstd_dedicated_dict_search_get_cparams(
    compression_level: i32,
    dict_size: usize,
) -> CompressionParameters {
    let mut c_params =
        zstd_get_cparams_internal(compression_level, 0, dict_size, CParamMode::CreateCDict);
    match c_params.strategy {
        Strategy::Greedy | Strategy::Lazy | Strategy::Lazy2 => {
            c_params.hash_log += ZSTD_LAZY_DDSS_BUCKET_LOG;
        }
        Strategy::Fast
        | Strategy::Dfast
        | Strategy::Btlazy2
        | Strategy::Btopt
        | Strategy::Btultra
        | Strategy::Btultra2 => {}
    }
    c_params
}

/// `ZSTD_dedicatedDictSearch_isSupported`: whether a `CDict` with
/// `c_params` can have the dedicated dictionary search: `greedy`, `lazy`
/// and `lazy2`, with a hash table larger than the chain table, which has
/// no more than `1 << 24` entries (their index takes 24 bits of a bucket's
/// last entry).
fn zstd_dedicated_dict_search_is_supported(c_params: &CompressionParameters) -> bool {
    c_params.strategy >= Strategy::Greedy
        && c_params.strategy <= Strategy::Lazy2
        && c_params.hash_log > c_params.chain_log
        && c_params.chain_log <= 24
}

/// `ZSTD_dedicatedDictSearch_revertCParams`: the parameters of a `CDict`
/// with the dedicated dictionary search without its larger hash table, for
/// the context that attaches it: its own tables would grow too otherwise.
pub(crate) fn zstd_dedicated_dict_search_revert_cparams(c_params: &mut CompressionParameters) {
    match c_params.strategy {
        Strategy::Greedy | Strategy::Lazy | Strategy::Lazy2 => {
            c_params.hash_log = c_params
                .hash_log
                .saturating_sub(ZSTD_LAZY_DDSS_BUCKET_LOG)
                .max(ZSTD_HASHLOG_MIN);
        }
        Strategy::Fast
        | Strategy::Dfast
        | Strategy::Btlazy2
        | Strategy::Btopt
        | Strategy::Btultra
        | Strategy::Btultra2 => {}
    }
}

/// `ZSTD_getCParamMode`: what the parameters of a frame with `cdict` (if
/// any) are for: the input only when it attaches the `CDict`, the input
/// and the dictionary otherwise.
pub(crate) fn zstd_get_cparam_mode(
    cdict: Option<&CDict>,
    params: &CCtxParams,
    pledged_src_size: u64,
) -> CParamMode {
    match cdict {
        Some(cdict) if zstd_should_attach_dict(cdict, params, pledged_src_size) => {
            CParamMode::AttachDict
        }
        _ => CParamMode::NoAttachDict,
    }
}

/// `ZSTD_CDictIndicesAreTagged`: whether a `CDict` with `c_params` keeps
/// tags in its hash tables' entries (see [`ZSTD_SHORT_CACHE_TAG_BITS`]),
/// which a context copying them takes out.
pub(crate) fn zstd_cdict_indices_are_tagged(c_params: &CompressionParameters) -> bool {
    matches!(c_params.strategy, Strategy::Fast | Strategy::Dfast)
}

/// `ZSTD_dictTableLoadMethod_e`: which positions of a dictionary go into
/// the hash tables of `fast` and `dfast`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum DictTableLoadMethod {
    /// Every third, as the block compressors fill them (`ZSTD_dtlm_fast`).
    Fast,
    /// The others too, where their entry is empty (`ZSTD_dtlm_full`).
    Full,
}

/// `ZSTD_tableFillPurpose_e`: whose tables a dictionary fills.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum TableFillPurpose {
    /// A `CDict`'s, whose `fast` and `dfast` tables hold tagged indices.
    ForCDict,
    /// A context's.
    ForCCtx,
}

/// `ZSTD_loadDictionaryContent`: `dict[start..end]`, the content, into the
/// match state's window, as the segment of `which` before the input
/// ([`WindowBuffer::Dict`], but for the jobs of multithreaded compression
/// after the first, whose input follows it in the same buffer), and its
/// positions into the tables; with `ldm`, into those of long distance
/// matching too, when the frame has it.
///
/// The content can be too large for the indices: only its end is loaded,
/// up to `ZSTD_CURRENT_MAX` bytes, or under 16 MB for a `CDict` with tagged
/// indices. And only the end of that goes into the tables, as much as they
/// can index.
#[allow(clippy::too_many_arguments)]
pub(crate) fn zstd_load_dictionary_content(
    ms: &mut MatchState,
    ldm: Option<&mut LdmState>,
    params: &CCtxParams,
    dict: &[u8],
    which: WindowBuffer,
    start: usize,
    end: usize,
    dtlm: DictTableLoadMethod,
    tfp: TableFillPurpose,
) -> Result<()> {
    let mut ip = start;
    let iend = end;
    let mut src_size = iend - ip;
    let load_ldm_dict = params.ldm_enable == ParamSwitch::Enable && ldm.is_some();

    // The match state has the parameters given.
    debug_assert!(params.c_params == ms.c_params);

    {
        // Large dictionaries cannot make the indices overflow: up to
        // exactly ZSTD_CURRENT_MAX, where the indices are lowered at once.
        let mut max_dict_size = ZSTD_CURRENT_MAX - ZSTD_WINDOW_START_INDEX;
        if zstd_cdict_indices_are_tagged(&params.c_params) && tfp == TableFillPurpose::ForCDict {
            // The short cache keeps tags in the low bits of a CDict's
            // entries: the indices must fit above them.
            let short_cache_max_dict_size =
                (1u32 << (32 - ZSTD_SHORT_CACHE_TAG_BITS)) - ZSTD_WINDOW_START_INDEX;
            max_dict_size = max_dict_size.min(short_cache_max_dict_size);
            debug_assert!(!load_ldm_dict);
        }
        // Too large: only its end.
        if src_size > max_dict_size as usize {
            ip = iend - max_dict_size as usize;
            src_size = max_dict_size as usize;
        }
    }

    if src_size > ZSTD_CHUNKSIZE_MAX as usize {
        // The window must be new for so large a dictionary: the port's
        // always is.
        debug_assert!(ms.window.is_empty());
    }
    ms.window.update(which, ip, src_size, false);

    if let Some(ldm) = ldm.filter(|_| load_ldm_dict) {
        // All of it into long distance matching's tables.
        ldm.window.update(which, ip, src_size, false);
        ldm.loaded_dict_end = if params.force_window {
            0
        } else {
            ldm.window.index(iend)
        };
        zstd_ldm_fill_hash_table(ldm, dict, ip, iend, &params.ldm);
    }

    {
        // Only the end the tables can index.
        let log = (params.c_params.hash_log + 3)
            .max(params.c_params.chain_log + 1)
            .min(31);
        let max_dict_size = 1usize << log;
        if src_size > max_dict_size {
            ip = iend - max_dict_size;
            src_size = max_dict_size;
        }
    }

    // With forceWindow, the content is part of the window, its matches
    // no farther than the window's size: no dictionary end.
    ms.next_to_update = ms.window.index(ip);
    ms.loaded_dict_end = if params.force_window {
        0
    } else {
        ms.window.index(iend)
    };
    ms.force_non_contiguous = params.deterministic_ref_prefix;
    if src_size == 0 {
        // Differs from libzstd: there the window, left as it was, makes
        // these indices from an unrelated pointer. A dictionary without
        // content is dropped at the first block, by ZSTD_checkDictValidity,
        // before anything reads them (the frame's window starts afresh:
        // that index is not its dictLimit, nor is 0); the port sets 0 at
        // once. The input's segment, never contiguous with what the window
        // has, sets nextToUpdate.
        ms.loaded_dict_end = 0;
    }

    if src_size <= HASH_READ_SIZE {
        return Ok(());
    }

    zstd_overflow_correct_if_needed(ms, params, ip, iend);

    match params.c_params.strategy {
        Strategy::Fast => match tfp {
            TableFillPurpose::ForCDict => {
                debug_assert!(dtlm == DictTableLoadMethod::Full);
                zstd_fill_hash_table_for_cdict(ms, dict, iend);
            }
            TableFillPurpose::ForCCtx => {
                debug_assert!(dtlm == DictTableLoadMethod::Fast);
                zstd_fill_hash_table(ms, dict, iend);
            }
        },
        Strategy::Dfast => match tfp {
            TableFillPurpose::ForCDict => {
                debug_assert!(dtlm == DictTableLoadMethod::Full);
                zstd_fill_double_hash_table_for_cdict(ms, dict, iend);
            }
            TableFillPurpose::ForCCtx => {
                debug_assert!(dtlm == DictTableLoadMethod::Fast);
                zstd_fill_double_hash_table(ms, dict, iend);
            }
        },
        Strategy::Greedy | Strategy::Lazy | Strategy::Lazy2 => {
            debug_assert!(src_size >= HASH_READ_SIZE);
            if ms.dedicated_dict_search {
                debug_assert!(!ms.chain_table.is_empty());
                zstd_dedicated_dict_search_lazy_load_dictionary(ms, dict, iend - HASH_READ_SIZE);
            } else {
                debug_assert!(params.use_row_match_finder != ParamSwitch::Auto);
                if params.use_row_match_finder == ParamSwitch::Enable {
                    ms.tag_table.fill(0);
                    zstd_row_update(ms, dict, iend - HASH_READ_SIZE);
                } else {
                    zstd_insert_and_find_first_index(ms, dict, iend - HASH_READ_SIZE);
                }
            }
        }
        Strategy::Btlazy2 | Strategy::Btopt | Strategy::Btultra | Strategy::Btultra2 => {
            // The dictionary's tree fully sorted.
            debug_assert!(src_size >= HASH_READ_SIZE);
            zstd_update_tree(ms, dict, iend - HASH_READ_SIZE, iend);
        }
    }

    ms.next_to_update = ms.window.index(iend);
    Ok(())
}

/// `ZSTD_dictNCountRepeat`: whether a dictionary's table of normalized
/// counts can be used for symbols up to `max_symbol_value` without a look
/// (every one has a count), or only after a check.
fn zstd_dict_ncount_repeat(
    normalized_counter: &[i16],
    dict_max_symbol_value: u32,
    max_symbol_value: u32,
) -> FseRepeat {
    if dict_max_symbol_value < max_symbol_value {
        return FseRepeat::Check;
    }
    if normalized_counter[..=max_symbol_value as usize].contains(&0) {
        return FseRepeat::Check;
    }
    FseRepeat::Valid
}

/// `ZSTD_loadCEntropy`: the entropy tables and repeat offsets of the zstd
/// dictionary `dict` into `bs`. Returns the size of its header, magic
/// number and ID included: where its content starts. Fails with
/// `DictionaryCorrupted` for a header it cannot read, or repeat offsets
/// that are 0 or past the content.
///
/// A table with a symbol of no code can only be used after a check
/// (`HUF_repeat_check`, `FSE_repeat_check`), as can one of offsets that does
/// not reach past the content and a block.
pub(crate) fn zstd_load_c_entropy(bs: &mut CompressedBlockState, dict: &[u8]) -> Result<usize> {
    let corrupted = |_: Error| Error::from(ErrorCode::DictionaryCorrupted);
    let mut offcode_ncount = [0i16; MAX_OFF as usize + 1];
    let mut offcode_max_value = MAX_OFF;
    let dict_end = dict.len();
    // Past the magic number and the dictionary's ID.
    let mut dict_ptr = 8;
    bs.entropy.huf.repeat_mode = HufRepeat::Check;

    {
        let mut max_symbol_value = 255;
        let mut has_zero_weights = true;
        let huf_header_size = huf_read_ctable(
            &mut bs.entropy.huf.ctable,
            &mut max_symbol_value,
            &dict[dict_ptr..],
            &mut has_zero_weights,
        );
        // Valid as it is only with every symbol.
        if !has_zero_weights && max_symbol_value == 255 {
            bs.entropy.huf.repeat_mode = HufRepeat::Valid;
        }
        dict_ptr += huf_header_size.map_err(corrupted)?;
    }

    {
        let mut offcode_log = 0;
        let offcode_header_size = fse_read_ncount(
            &mut offcode_ncount,
            &mut offcode_max_value,
            &mut offcode_log,
            &dict[dict_ptr..],
        )
        .map_err(corrupted)?;
        if offcode_log > OFF_FSE_LOG {
            return error!(DictionaryCorrupted);
        }
        // Every offset code, the ones the dictionary leaves out with a
        // count of 0, so that the table has nothing left from before.
        fse_build_ctable_wksp(
            &mut bs.entropy.fse.offcode_ctable,
            &offcode_ncount,
            MAX_OFF,
            offcode_log,
        )
        .map_err(corrupted)?;
        // Whether it can be used without a check depends on the content's
        // size, below.
        dict_ptr += offcode_header_size;
    }

    {
        let mut matchlength_ncount = [0i16; MAX_ML as usize + 1];
        let mut matchlength_max_value = MAX_ML;
        let mut matchlength_log = 0;
        let matchlength_header_size = fse_read_ncount(
            &mut matchlength_ncount,
            &mut matchlength_max_value,
            &mut matchlength_log,
            &dict[dict_ptr..],
        )
        .map_err(corrupted)?;
        if matchlength_log > ML_FSE_LOG {
            return error!(DictionaryCorrupted);
        }
        fse_build_ctable_wksp(
            &mut bs.entropy.fse.matchlength_ctable,
            &matchlength_ncount,
            matchlength_max_value,
            matchlength_log,
        )
        .map_err(corrupted)?;
        bs.entropy.fse.matchlength_repeat_mode =
            zstd_dict_ncount_repeat(&matchlength_ncount, matchlength_max_value, MAX_ML);
        dict_ptr += matchlength_header_size;
    }

    {
        let mut litlength_ncount = [0i16; MAX_LL as usize + 1];
        let mut litlength_max_value = MAX_LL;
        let mut litlength_log = 0;
        let litlength_header_size = fse_read_ncount(
            &mut litlength_ncount,
            &mut litlength_max_value,
            &mut litlength_log,
            &dict[dict_ptr..],
        )
        .map_err(corrupted)?;
        if litlength_log > LL_FSE_LOG {
            return error!(DictionaryCorrupted);
        }
        fse_build_ctable_wksp(
            &mut bs.entropy.fse.litlength_ctable,
            &litlength_ncount,
            litlength_max_value,
            litlength_log,
        )
        .map_err(corrupted)?;
        bs.entropy.fse.litlength_repeat_mode =
            zstd_dict_ncount_repeat(&litlength_ncount, litlength_max_value, MAX_LL);
        dict_ptr += litlength_header_size;
    }

    if dict_ptr + 12 > dict_end {
        return error!(DictionaryCorrupted);
    }
    bs.rep[0] = read_le32(dict, dict_ptr);
    bs.rep[1] = read_le32(dict, dict_ptr + 4);
    bs.rep[2] = read_le32(dict, dict_ptr + 8);
    dict_ptr += 12;

    {
        let dict_content_size = dict_end - dict_ptr;
        let mut offcode_max = MAX_OFF;
        if dict_content_size <= (u32::MAX - (128 << 10)) as usize {
            // The largest offset the table must reach: past the content,
            // and a block.
            let max_offset = dict_content_size as u32 + (128 << 10);
            // The smallest offset code that holds it.
            offcode_max = highbit32(max_offset);
        }
        // Valid as it is only with a code for every offset up to there.
        bs.entropy.fse.offcode_repeat_mode =
            zstd_dict_ncount_repeat(&offcode_ncount, offcode_max_value, offcode_max.min(MAX_OFF));

        // The repeat offsets are not 0, and within the content.
        for &rep in &bs.rep {
            if rep == 0 || rep as usize > dict_content_size {
                return error!(DictionaryCorrupted);
            }
        }
    }

    Ok(dict_ptr)
}

/// `ZSTD_loadZstdDictionary`: the zstd dictionary `dict`, its magic number
/// checked: its entropy tables into `bs`, its content into the match state.
/// Returns its ID, 0 with the dictionary ID flag off.
fn zstd_load_zstd_dictionary(
    bs: &mut CompressedBlockState,
    ms: &mut MatchState,
    params: &CCtxParams,
    dict: &[u8],
    dtlm: DictTableLoadMethod,
    tfp: TableFillPurpose,
) -> Result<u32> {
    debug_assert!(dict.len() >= 8);
    debug_assert!(read_le32(dict, 0) == ZSTD_MAGIC_DICTIONARY);

    let dict_id = if params.f_params.no_dict_id_flag {
        0
    } else {
        read_le32(dict, 4)
    };
    let e_size = zstd_load_c_entropy(bs, dict)?;
    // Without long distance matching, which only takes raw content.
    zstd_load_dictionary_content(
        ms,
        None,
        params,
        dict,
        WindowBuffer::Dict,
        e_size,
        dict.len(),
        dtlm,
        tfp,
    )?;
    Ok(dict_id)
}

/// `ZSTD_compress_insertDictionary`: `dict`, read as `content_type` says,
/// into the block state `bs` and the match state (with `ldm`, raw content
/// into long distance matching's tables too). Returns its ID: 0 for raw
/// content.
///
/// A dictionary of under 8 bytes is left out (or fails with
/// `DictionaryWrong` as [`DictContentType::FullDict`]), as is its block
/// state. One that is not a zstd dictionary fails the same way as
/// `FullDict`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn zstd_compress_insert_dictionary(
    bs: &mut CompressedBlockState,
    ms: &mut MatchState,
    ldm: Option<&mut LdmState>,
    params: &CCtxParams,
    dict: &[u8],
    content_type: DictContentType,
    dtlm: DictTableLoadMethod,
    tfp: TableFillPurpose,
) -> Result<u32> {
    if dict.len() < 8 {
        if content_type == DictContentType::FullDict {
            return error!(DictionaryWrong);
        }
        return Ok(0);
    }

    bs.reset();

    // Raw content, as asked.
    if content_type == DictContentType::RawContent {
        zstd_load_dictionary_content(
            ms,
            ldm,
            params,
            dict,
            WindowBuffer::Dict,
            0,
            dict.len(),
            dtlm,
            tfp,
        )?;
        return Ok(0);
    }

    if read_le32(dict, 0) != ZSTD_MAGIC_DICTIONARY {
        if content_type == DictContentType::Auto {
            // Raw content, as it is not a zstd dictionary.
            zstd_load_dictionary_content(
                ms,
                ldm,
                params,
                dict,
                WindowBuffer::Dict,
                0,
                dict.len(),
                dtlm,
                tfp,
            )?;
            return Ok(0);
        }
        return error!(DictionaryWrong);
    }

    // A zstd dictionary.
    zstd_load_zstd_dictionary(bs, ms, params, dict, dtlm, tfp)
}
