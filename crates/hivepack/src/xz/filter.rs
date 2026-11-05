//! Filters and filter chains: port of `common/filter_common.c`,
//! `common/filter_decoder.c`, `common/filter_encoder.c`,
//! `common/filter_flags_decoder.c` and `common/filter_flags_encoder.c`,
//! with the filter IDs and options of `api/lzma/lzma12.h`,
//! `api/lzma/bcj.h` and `api/lzma/delta.h`.

use crate::xz::common::{
    FILTER_RESERVED_START, MEMUSAGE_BASE, NextCoder, Ret, VLI_MAX, VLI_UNKNOWN,
};
use crate::xz::delta::{self, DeltaDecoder, DeltaEncoder};
use crate::xz::lz_decoder::{Lz, LzCoder};
use crate::xz::lz_encoder::{LzEnc, LzEncCoder};
use crate::xz::lzma_common::{LZMA1EXT_ALLOW_EOPM, LzmaOptions, is_lclppb_valid};
use crate::xz::lzma_decoder::{self, LzmaDecoder};
use crate::xz::lzma_encoder::{self, LzmaEncoder};
use crate::xz::lzma2_decoder::{self, Lzma2Decoder};
use crate::xz::lzma2_encoder::{self, Lzma2Encoder};
use crate::xz::simple::{self, SimpleCoder};
use crate::xz::vli;

/// `LZMA_FILTER_LZMA1`.
pub const FILTER_LZMA1: u64 = 0x4000_0000_0000_0001;
/// `LZMA_FILTER_LZMA1EXT`.
pub const FILTER_LZMA1EXT: u64 = 0x4000_0000_0000_0002;
/// `LZMA_FILTER_LZMA2`.
pub const FILTER_LZMA2: u64 = 0x21;
/// `LZMA_FILTER_DELTA`.
pub const FILTER_DELTA: u64 = 0x03;
/// `LZMA_FILTER_X86`: BCJ for x86 and x86-64.
pub const FILTER_X86: u64 = 0x04;
/// `LZMA_FILTER_POWERPC`: BCJ for big-endian PowerPC.
pub const FILTER_POWERPC: u64 = 0x05;
/// `LZMA_FILTER_IA64`: BCJ for IA-64 (Itanium).
pub const FILTER_IA64: u64 = 0x06;
/// `LZMA_FILTER_ARM`: BCJ for 32-bit ARM.
pub const FILTER_ARM: u64 = 0x07;
/// `LZMA_FILTER_ARMTHUMB`: BCJ for ARM-Thumb.
pub const FILTER_ARMTHUMB: u64 = 0x08;
/// `LZMA_FILTER_SPARC`: BCJ for SPARC.
pub const FILTER_SPARC: u64 = 0x09;
/// `LZMA_FILTER_ARM64`: BCJ for ARM64.
pub const FILTER_ARM64: u64 = 0x0A;
/// `LZMA_FILTER_RISCV`: BCJ for RISC-V.
pub const FILTER_RISCV: u64 = 0x0B;

/// `LZMA_FILTERS_MAX`.
pub const FILTERS_MAX: usize = 4;

/// `LZMA_DELTA_TYPE_BYTE`: the delta of bytes, the only type.
pub const DELTA_TYPE_BYTE: u32 = 0;
/// `LZMA_DELTA_DIST_MIN`.
pub const DELTA_DIST_MIN: u32 = 1;
/// `LZMA_DELTA_DIST_MAX`.
pub const DELTA_DIST_MAX: u32 = 256;

/// `lzma_options_delta`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeltaOptions {
    /// The type of delta, [`DELTA_TYPE_BYTE`].
    pub delta_type: u32,
    /// The distance, in bytes: from [`DELTA_DIST_MIN`] to
    /// [`DELTA_DIST_MAX`].
    pub dist: u32,
}

/// `lzma_options_bcj`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BcjOptions {
    /// The offset of the start of the data in the file, a multiple of the
    /// filter's alignment. No options is an offset of 0.
    pub start_offset: u32,
}

/// The options of a filter: `options` of `lzma_filter`, which points to
/// one of liblzma's options structures, as the Filter ID says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilterOptions {
    /// `lzma_options_lzma`, for LZMA1, LZMA1EXT and LZMA2.
    Lzma(LzmaOptions),
    /// `lzma_options_delta`, for delta.
    Delta(DeltaOptions),
    /// `lzma_options_bcj`, for the BCJ filters.
    Bcj(BcjOptions),
}

/// `lzma_filter`: a filter of a chain, its ID and its options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filter {
    /// The Filter ID, such as [`FILTER_LZMA2`].
    pub id: u64,
    /// The options, for the filters that have them.
    ///
    /// Differs from liblzma: options of the kind of another filter (which
    /// liblzma would read as its own) are refused, as no options are for
    /// LZMA, as invalid options are for delta and BCJ.
    pub options: Option<FilterOptions>,
}

impl Filter {
    /// LZMA2 with `options`.
    pub fn lzma2(options: LzmaOptions) -> Filter {
        Filter {
            id: FILTER_LZMA2,
            options: Some(FilterOptions::Lzma(options)),
        }
    }

    /// LZMA1 with `options`.
    pub fn lzma1(options: LzmaOptions) -> Filter {
        Filter {
            id: FILTER_LZMA1,
            options: Some(FilterOptions::Lzma(options)),
        }
    }

    /// Delta of bytes at a distance.
    pub fn delta(dist: u32) -> Filter {
        Filter {
            id: FILTER_DELTA,
            options: Some(FilterOptions::Delta(DeltaOptions {
                delta_type: DELTA_TYPE_BYTE,
                dist,
            })),
        }
    }

    /// A BCJ filter, such as [`FILTER_X86`], with a start offset.
    pub fn bcj(id: u64, start_offset: u32) -> Filter {
        Filter {
            id,
            options: Some(FilterOptions::Bcj(BcjOptions { start_offset })),
        }
    }

    /// The LZMA options, if these are.
    pub(crate) fn lzma_options(&self) -> Option<&LzmaOptions> {
        match &self.options {
            Some(FilterOptions::Lzma(options)) => Some(options),
            _ => None,
        }
    }
}

/// An entry of the `features` table of `filter_common.c`.
struct Feature {
    id: u64,
    /// true if it is OK to use this filter as non-last filter in the
    /// chain.
    non_last_ok: bool,
    /// true if it is OK to use this filter as the last filter in the
    /// chain.
    last_ok: bool,
    /// true if the filter may change the size of the data (that is, the
    /// amount of encoded output can be different than the amount of
    /// uncompressed input).
    changes_size: bool,
}

/// An LZMA filter's entry.
const fn lzma_feature(id: u64) -> Feature {
    Feature {
        id,
        non_last_ok: false,
        last_ok: true,
        changes_size: true,
    }
}

/// A delta or BCJ filter's entry.
const fn simple_feature(id: u64) -> Feature {
    Feature {
        id,
        non_last_ok: true,
        last_ok: false,
        changes_size: false,
    }
}

/// `features`.
const FEATURES: [Feature; 12] = [
    lzma_feature(FILTER_LZMA1),
    lzma_feature(FILTER_LZMA1EXT),
    lzma_feature(FILTER_LZMA2),
    simple_feature(FILTER_X86),
    simple_feature(FILTER_POWERPC),
    simple_feature(FILTER_IA64),
    simple_feature(FILTER_ARM),
    simple_feature(FILTER_ARMTHUMB),
    simple_feature(FILTER_ARM64),
    simple_feature(FILTER_SPARC),
    simple_feature(FILTER_RISCV),
    simple_feature(FILTER_DELTA),
];

/// `lzma_validate_chain`: the number of filters in a valid chain.
pub(crate) fn validate_chain(filters: &[Filter]) -> Result<usize, Ret> {
    // There must be at least one filter.
    if filters.is_empty() {
        return Err(Ret::ProgError);
    }

    // Number of non-last filters that may change the size of the data
    // significantly (that is, more than 1-2 % or so).
    let mut changes_size_count = 0;

    // True if it is OK to add a new filter after the current filter.
    let mut non_last_ok = true;

    // True if the last filter in the given chain is actually usable as the
    // last filter. Only filters that support embedding End of Payload
    // Marker can be used as the last filter in the chain.
    let mut last_ok = false;

    for filter in filters {
        // Look for the filter.
        let Some(feature) = FEATURES.iter().find(|f| f.id == filter.id) else {
            return Err(Ret::OptionsError);
        };

        // If the previous filter in the chain cannot be a non-last filter,
        // the chain is invalid.
        if !non_last_ok {
            return Err(Ret::OptionsError);
        }

        non_last_ok = feature.non_last_ok;
        last_ok = feature.last_ok;
        changes_size_count += usize::from(feature.changes_size);
    }

    // There must be 1-4 filters. The last filter must be usable as the last
    // filter in the chain. A maximum of three filters are allowed to change
    // the size of the data.
    if filters.len() > FILTERS_MAX || !last_ok || changes_size_count > 3 {
        return Err(Ret::OptionsError);
    }
    Ok(filters.len())
}

/// Whether a filter is one of the BCJ filters.
fn is_bcj(id: u64) -> bool {
    matches!(
        id,
        FILTER_X86
            | FILTER_POWERPC
            | FILTER_IA64
            | FILTER_ARM
            | FILTER_ARMTHUMB
            | FILTER_ARM64
            | FILTER_SPARC
            | FILTER_RISCV
    )
}

/// Whether the port has a coder of a filter: liblzma's decoders and
/// encoders are the same filters.
fn is_supported(id: u64) -> bool {
    matches!(
        id,
        FILTER_LZMA1 | FILTER_LZMA1EXT | FILTER_LZMA2 | FILTER_DELTA
    ) || is_bcj(id)
}

/// `lzma_filter_decoder_is_supported`.
pub fn decoder_is_supported(id: u64) -> bool {
    is_supported(id)
}

/// `lzma_filter_encoder_is_supported`.
pub fn encoder_is_supported(id: u64) -> bool {
    is_supported(id)
}

/// The options of an LZMA filter, or `LZMA_PROG_ERROR` as liblzma gives
/// for a filter without them.
fn lzma_options(filter: &Filter) -> Result<&LzmaOptions, Ret> {
    filter.lzma_options().ok_or(Ret::ProgError)
}

/// The start offset of a BCJ filter: 0 without options.
fn bcj_start_offset(filter: &Filter) -> Result<u32, Ret> {
    match &filter.options {
        None => Ok(0),
        Some(FilterOptions::Bcj(options)) => Ok(options.start_offset),
        Some(_) => Err(Ret::OptionsError),
    }
}

/// The options of a delta filter, if valid.
fn delta_options(filter: &Filter) -> Option<&DeltaOptions> {
    match &filter.options {
        Some(FilterOptions::Delta(options)) => Some(options),
        _ => None,
    }
}

/// `lzma_next_filter_init` of the decoders: the decoder of `filters[0]`,
/// reading from the decoders of the others, made after it as liblzma
/// makes them (so that an error of the first comes first).
pub(crate) fn filter_init(filters: &[Filter]) -> Result<Box<dyn NextCoder>, Ret> {
    let Some((filter, rest)) = filters.split_first() else {
        return Err(Ret::ProgError);
    };
    let next_init = |rest: &[Filter]| -> Result<Option<Box<dyn NextCoder>>, Ret> {
        if rest.is_empty() {
            Ok(None)
        } else {
            filter_init(rest).map(Some)
        }
    };
    match filter.id {
        FILTER_LZMA1 | FILTER_LZMA1EXT => {
            // `lzma_decoder_init`.
            let options = lzma_options(filter)?;
            if !is_lclppb_valid(options) {
                return Err(Ret::ProgError);
            }
            let mut uncomp_size = VLI_UNKNOWN;
            let mut allow_eopm = true;
            if filter.id == FILTER_LZMA1EXT {
                // Only one flag is supported.
                if options.ext_flags & !LZMA1EXT_ALLOW_EOPM != 0 {
                    return Err(Ret::OptionsError);
                }
                uncomp_size =
                    u64::from(options.ext_size_low) + (u64::from(options.ext_size_high) << 32);
                allow_eopm =
                    options.ext_flags & LZMA1EXT_ALLOW_EOPM != 0 || uncomp_size == VLI_UNKNOWN;
            }
            let (mut lzma, lz_options) = LzmaDecoder::create(options);
            lzma.reset(options);
            lzma.set_uncompressed(uncomp_size, allow_eopm);
            let mut coder = LzCoder::new(Lz::Lzma(Box::new(lzma)), &lz_options, None)?;
            coder.set_next(next_init(rest)?);
            Ok(Box::new(coder))
        }
        FILTER_LZMA2 => {
            let options = lzma_options(filter)?;
            let (lzma2, lz_options) = Lzma2Decoder::new(options);
            let mut coder = LzCoder::new(Lz::Lzma2(Box::new(lzma2)), &lz_options, None)?;
            coder.set_next(next_init(rest)?);
            Ok(Box::new(coder))
        }
        FILTER_DELTA => {
            let options = delta_options(filter).copied();
            let mut coder = DeltaDecoder::new(options)?;
            coder.set_next(next_init(rest)?);
            Ok(Box::new(coder))
        }
        id => {
            let mut coder = SimpleCoder::new(id, bcj_start_offset(filter)?, false)?;
            coder.set_next(next_init(rest)?);
            Ok(Box::new(coder))
        }
    }
}

/// `lzma_raw_decoder_init`: the chain of decoders for `filters`, the
/// first filter's decoder reading from the next one's.
pub(crate) fn raw_decoder_init(filters: &[Filter]) -> Result<Box<dyn NextCoder>, Ret> {
    let count = validate_chain(filters)?;

    // Every filter must have a decoder.
    for filter in &filters[..count] {
        if !decoder_is_supported(filter.id) {
            return Err(Ret::OptionsError);
        }
    }

    filter_init(&filters[..count])
}

/// `memusage` of the decoders' table, None for the filters without one.
fn filter_memusage(filter: &Filter) -> Option<u64> {
    match filter.id {
        FILTER_LZMA1 | FILTER_LZMA1EXT => Some(
            filter
                .lzma_options()
                .map_or(u64::MAX, lzma_decoder::decoder_memusage),
        ),
        FILTER_LZMA2 => Some(
            filter
                .lzma_options()
                .map_or(u64::MAX, lzma2_decoder::decoder_memusage),
        ),
        FILTER_DELTA => Some(delta::coder_memusage(delta_options(filter))),
        _ => None,
    }
}

/// `lzma_raw_coder_memusage`, for decoders and encoders: their memory,
/// filter by filter.
fn raw_coder_memusage(filters: &[Filter], memusage: impl Fn(&Filter) -> Option<u64>) -> u64 {
    // The chain has to have at least one filter.
    if validate_chain(filters).is_err() {
        return u64::MAX;
    }

    let mut total: u64 = 0;
    for filter in filters {
        if !is_supported(filter.id) {
            return u64::MAX; // Unsupported Filter ID
        }

        match memusage(filter) {
            // This filter doesn't have a function to calculate the memory
            // usage and validate the options. Such filters need only
            // little memory, so we use 1 KiB as a good estimate. They also
            // accept all possible options, so there's no need to worry
            // about lack of validation.
            None => total += 1024,
            // Invalid options
            Some(u64::MAX) => return u64::MAX,
            Some(usage) => total += usage,
        }
    }

    // Add some fixed amount of extra. It's to compensate memory usage of
    // Stream, Block etc. coders, malloc() overhead, stack etc.
    total + MEMUSAGE_BASE
}

/// `lzma_raw_decoder_memusage`: `u64::MAX` for an invalid chain.
pub fn raw_decoder_memusage(filters: &[Filter]) -> u64 {
    raw_coder_memusage(filters, filter_memusage)
}

/// `lzma_properties_decode`: the options of `id` from its properties.
pub(crate) fn properties_decode(id: u64, props: &[u8]) -> Result<Option<FilterOptions>, Ret> {
    match id {
        FILTER_LZMA1 | FILTER_LZMA1EXT => {
            lzma_decoder::props_decode(props).map(|o| Some(FilterOptions::Lzma(o)))
        }
        FILTER_LZMA2 => lzma2_decoder::props_decode(props).map(|o| Some(FilterOptions::Lzma(o))),
        FILTER_DELTA => delta::props_decode(props).map(|o| Some(FilterOptions::Delta(o))),
        id if is_bcj(id) => simple::props_decode(props).map(|o| o.map(FilterOptions::Bcj)),
        _ => Err(Ret::OptionsError),
    }
}

/// `lzma_filter_flags_decode`: a filter of a Block Header.
pub(crate) fn filter_flags_decode(input: &[u8], in_pos: &mut usize) -> Result<Filter, Ret> {
    // Filter ID
    let mut id = 0;
    match vli::decode_single(&mut id, input, in_pos) {
        Ret::Ok => {}
        ret => return Err(ret),
    }
    if id >= FILTER_RESERVED_START {
        return Err(Ret::DataError);
    }

    // Size of Properties
    let mut props_size = 0;
    match vli::decode_single(&mut props_size, input, in_pos) {
        Ret::Ok => {}
        ret => return Err(ret),
    }

    // Filter Properties
    if ((input.len() - *in_pos) as u64) < props_size {
        return Err(Ret::DataError);
    }
    let props = &input[*in_pos..*in_pos + props_size as usize];
    let options = properties_decode(id, props);
    *in_pos += props_size as usize;
    Ok(Filter {
        id,
        options: options?,
    })
}

// filter_encoder.c

/// `lzma_next_filter_init` of the encoders, whose chain liblzma reverses:
/// the encoder of the last filter of `filters`, reading from the encoders
/// of the ones before it, made after it as liblzma makes them (so that an
/// error of the last comes first).
fn encoder_filter_init(filters: &[Filter]) -> Result<Box<dyn NextCoder>, Ret> {
    let Some((filter, rest)) = filters.split_last() else {
        return Err(Ret::ProgError);
    };
    let next_init = |rest: &[Filter]| -> Result<Option<Box<dyn NextCoder>>, Ret> {
        if rest.is_empty() {
            Ok(None)
        } else {
            encoder_filter_init(rest).map(Some)
        }
    };
    match filter.id {
        // lzma_encoder_init() and lzma2_encoder_init().
        FILTER_LZMA1 | FILTER_LZMA1EXT | FILTER_LZMA2 => {
            let (lz, lz_options) = if filter.id == FILTER_LZMA2 {
                let (lzma2, lz_options) = Lzma2Encoder::new(lzma_options(filter)?)?;
                (LzEnc::Lzma2(Box::new(lzma2)), lz_options)
            } else {
                let (lzma, lz_options) = LzmaEncoder::create(filter.id, lzma_options(filter)?)?;
                (LzEnc::Lzma(Box::new(lzma)), lz_options)
            };
            let mut coder = LzEncCoder::new(lz, &lz_options)?;
            coder.set_next(next_init(rest)?);
            Ok(Box::new(coder))
        }
        FILTER_DELTA => {
            let options = delta_options(filter).copied();
            let mut coder = DeltaEncoder::new(options)?;
            coder.set_next(next_init(rest)?);
            Ok(Box::new(coder))
        }
        id => {
            let mut coder = SimpleCoder::new(id, bcj_start_offset(filter)?, true)?;
            coder.set_next(next_init(rest)?);
            Ok(Box::new(coder))
        }
    }
}

/// `lzma_raw_encoder_init`: the encoders of a filter chain.
///
/// liblzma reverses the chain for its encoders: the last filter (LZMA) is
/// the first coder, which reads from the one before it, and so on to the
/// first filter, which reads the input.
pub(crate) fn raw_encoder_init(filters: &[Filter]) -> Result<Box<dyn NextCoder>, Ret> {
    raw_encoder_reinit(filters, None)
}

/// `lzma_raw_encoder_init` with the coder of an earlier call: an LZ encoder
/// of the kind the chain needs keeps its memory, as liblzma's does when
/// `lzma_next_coder_init()` finds a coder of the same kind.
pub(crate) fn raw_encoder_reinit(
    filters: &[Filter],
    old: Option<Box<dyn NextCoder>>,
) -> Result<Box<dyn NextCoder>, Ret> {
    // Do some basic validation and get the number of filters.
    let count = validate_chain(filters)?;

    for filter in &filters[..count] {
        if !encoder_is_supported(filter.id) {
            return Err(Ret::OptionsError);
        }
    }

    if let (Some((filter, rest)), Some(mut coder)) = (
        filters[..count].split_last(),
        old.and_then(NextCoder::into_lz_encoder),
    ) && coder.is_kind_of(filter.id)
    {
        coder.reinit(filter.id, lzma_options(filter)?)?;
        coder.set_next(if rest.is_empty() {
            None
        } else {
            Some(encoder_filter_init(rest)?)
        });
        return Ok(coder);
    }

    encoder_filter_init(&filters[..count])
}

/// Not in liblzma: the encoder of a filter that cannot end a chain, a branch
/// converter or delta, on its own, its output the filtered data. 7z's writer
/// runs it before LZMA2's blocks, which threads compress apart: it keeps state
/// from one block to the next, as it does in a chain.
#[cfg(feature = "sevenz")]
pub(crate) fn filter_encoder_alone(filter: &Filter) -> Result<Box<dyn NextCoder>, Ret> {
    if matches!(filter.id, FILTER_LZMA1 | FILTER_LZMA1EXT | FILTER_LZMA2)
        || !encoder_is_supported(filter.id)
    {
        return Err(Ret::OptionsError);
    }
    encoder_filter_init(core::slice::from_ref(filter))
}

/// The `memusage` of an encoder in `encoders[]`, None for the filters
/// without one.
fn encoder_memusage(filter: &Filter) -> Option<u64> {
    // liblzma reads the LZMA options without checking for NULL.
    match filter.id {
        FILTER_LZMA1 | FILTER_LZMA1EXT => Some(
            filter
                .lzma_options()
                .map_or(u64::MAX, lzma_encoder::encoder_memusage),
        ),
        FILTER_LZMA2 => Some(
            filter
                .lzma_options()
                .map_or(u64::MAX, lzma2_encoder::lzma2_encoder_memusage),
        ),
        FILTER_DELTA => Some(delta::coder_memusage(delta_options(filter))),
        _ => None,
    }
}

/// `lzma_raw_encoder_memusage`: the memory the encoders of a chain need,
/// or u64::MAX if the chain is invalid or not supported.
pub fn raw_encoder_memusage(filters: &[Filter]) -> u64 {
    raw_coder_memusage(filters, encoder_memusage)
}

/// `lzma_mt_block_size`: the Block size of the threaded encoder for a
/// chain, the largest its filters ask for, u64::MAX if none does or a
/// filter is not supported.
///
/// Differs from liblzma: LZMA2 without its options gives u64::MAX, where
/// liblzma reads through the null pointer.
pub(crate) fn mt_block_size(filters: &[Filter]) -> u64 {
    let mut max = 0;

    for filter in filters {
        if !encoder_is_supported(filter.id) {
            return u64::MAX;
        }

        // Only LZMA2 has a block_size function.
        if filter.id == FILTER_LZMA2 {
            let size = match filter.lzma_options() {
                Some(options) => lzma2_encoder::lzma2_block_size(options),
                None => u64::MAX,
            };
            if size > max {
                max = size;
            }
        }
    }

    if max == 0 { u64::MAX } else { max }
}

/// `lzma_properties_size`.
pub(crate) fn properties_size(filter: &Filter) -> Result<u32, Ret> {
    match filter.id {
        FILTER_LZMA1 | FILTER_LZMA1EXT => Ok(5),
        FILTER_LZMA2 | FILTER_DELTA => Ok(1),
        // `lzma_simple_props_size`.
        id if is_bcj(id) => Ok(match &filter.options {
            Some(FilterOptions::Bcj(options)) if options.start_offset != 0 => 4,
            _ => 0,
        }),
        // Unknown filter - if the Filter ID is a proper VLI, return
        // LZMA_OPTIONS_ERROR instead of LZMA_PROG_ERROR, because it's
        // possible that we just don't have support compiled in for the
        // requested filter.
        id if id <= VLI_MAX => Err(Ret::OptionsError),
        _ => Err(Ret::ProgError),
    }
}

/// `lzma_properties_encode`.
pub(crate) fn properties_encode(filter: &Filter, props: &mut [u8]) -> Ret {
    match filter.id {
        FILTER_LZMA1 | FILTER_LZMA1EXT => match filter.lzma_options() {
            Some(options) => lzma_encoder::props_encode(options, props),
            None => Ret::ProgError,
        },
        FILTER_LZMA2 => match filter.lzma_options() {
            Some(options) => lzma2_encoder::lzma2_props_encode(options, props),
            None => Ret::ProgError,
        },
        FILTER_DELTA => delta::props_encode(delta_options(filter), props),
        id if is_bcj(id) => {
            if let Some(FilterOptions::Bcj(options)) = &filter.options {
                simple::props_encode(options, props);
            }
            Ret::Ok
        }
        _ => Ret::ProgError,
    }
}

// filter_flags_encoder.c

/// `lzma_filter_flags_size`.
pub(crate) fn filter_flags_size(filter: &Filter) -> Result<u32, Ret> {
    if filter.id >= FILTER_RESERVED_START {
        return Err(Ret::ProgError);
    }

    let size = properties_size(filter)?;
    Ok(size + vli::size(filter.id) + vli::size(u64::from(size)))
}

/// `lzma_filter_flags_encode`.
pub(crate) fn filter_flags_encode(filter: &Filter, out: &mut [u8], out_pos: &mut usize) -> Ret {
    // Filter ID
    if filter.id >= FILTER_RESERVED_START {
        return Ret::ProgError;
    }

    let ret = vli::encode_single(filter.id, out, out_pos);
    if ret != Ret::Ok {
        return ret;
    }

    // Size of Properties
    let props_size = match properties_size(filter) {
        Ok(size) => size,
        Err(ret) => return ret,
    };
    let ret = vli::encode_single(u64::from(props_size), out, out_pos);
    if ret != Ret::Ok {
        return ret;
    }

    // Filter Properties
    if out.len() - *out_pos < props_size as usize {
        return Ret::ProgError;
    }

    let ret = properties_encode(filter, &mut out[*out_pos..]);
    if ret != Ret::Ok {
        return ret;
    }

    *out_pos += props_size as usize;

    Ret::Ok
}

/// `lzma_filters_copy`: a copy of the chain, or LZMA_OPTIONS_ERROR for more
/// than four filters, or options of a filter this build does not know.
pub(crate) fn filters_copy(filters: &[Filter]) -> Result<Vec<Filter>, Ret> {
    for (i, filter) in filters.iter().enumerate() {
        if i == FILTERS_MAX {
            return Err(Ret::OptionsError);
        }

        if filter.options.is_some() && !FEATURES.iter().any(|f| f.id == filter.id) {
            return Err(Ret::OptionsError);
        }
    }
    Ok(filters.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xz::common::Action;
    use crate::xz::lzma_common::{MatchFinder, Mode};

    /// `data` to its end through `coder`, in calls of `room` bytes of output.
    fn encode(coder: &mut dyn NextCoder, data: &[u8], room: usize) -> Vec<u8> {
        let mut out = vec![0; data.len() * 2 + 1024];
        let (mut in_pos, mut out_pos) = (0, 0);
        loop {
            let end = (out_pos + room).min(out.len());
            let ret = coder.code(
                data,
                &mut in_pos,
                &mut out[..end],
                &mut out_pos,
                Action::Finish,
            );
            if ret == Ret::StreamEnd {
                out.truncate(out_pos);
                return out;
            }
            assert_eq!(ret, Ret::Ok);
        }
    }

    /// Chains of each kind of LZ encoder that differ in what the encoders
    /// keep: the mode, the match finder, the sizes of the buffers, lc, lp
    /// and pb, a preset dictionary, and the filters before.
    fn chains() -> Vec<Vec<Filter>> {
        let options = |preset| LzmaOptions::preset(preset).unwrap_or_default();
        let normal = LzmaOptions {
            dict_size: 1 << 20,
            ..options(6)
        };
        let small = LzmaOptions {
            dict_size: 4096,
            lc: 1,
            lp: 2,
            pb: 1,
            mode: Mode::NORMAL,
            mf: MatchFinder::BT2,
            ..options(1)
        };
        let dictionary = LzmaOptions {
            preset_dict: Some((0..1000u32).map(|i| (i % 7) as u8).collect()),
            ..options(2)
        };
        let ext = Filter {
            id: FILTER_LZMA1EXT,
            options: Some(FilterOptions::Lzma(LzmaOptions {
                ext_flags: LZMA1EXT_ALLOW_EOPM,
                ..options(3)
            })),
        };
        vec![
            vec![Filter::lzma2(options(0))],
            vec![Filter::lzma2(normal.clone())],
            vec![Filter::lzma2(small.clone())],
            vec![Filter::lzma2(dictionary.clone())],
            vec![Filter::lzma1(options(1))],
            vec![Filter::lzma1(normal)],
            vec![Filter::lzma1(dictionary)],
            vec![ext],
            vec![Filter::delta(4), Filter::lzma2(options(0))],
            vec![
                Filter::bcj(FILTER_X86, 16),
                Filter::delta(2),
                Filter::lzma1(small),
            ],
        ]
    }

    /// An encoder made again, as liblzma makes one for the next Block,
    /// writes what a new one writes: whatever it was before, and whether it
    /// had finished, was left in the middle of its input, or was left one
    /// byte before its end, when flushing.
    #[test]
    fn an_encoder_made_again_writes_what_a_new_one_writes() {
        let mut data = Vec::new();
        for i in 0..30_000u32 {
            data.push((i.wrapping_mul(2_654_435_761) >> (24 + i % 5)) as u8);
        }

        let chains = chains();
        for before in &chains {
            let whole = encode(raw_encoder_init(before).unwrap().as_mut(), &data, 1 << 20);
            for after in &chains {
                let mut new = raw_encoder_init(after).unwrap();
                let want = encode(new.as_mut(), &data, 1000);

                // Where the encoder before is left: how much output it gets.
                for (action, room) in [
                    (Action::Finish, whole.len()),
                    (Action::Run, 100),
                    (Action::Finish, whole.len() - 1),
                ] {
                    let mut old = raw_encoder_init(before).unwrap();
                    let mut out = vec![0; room];
                    let (mut in_pos, mut out_pos) = (0, 0);
                    let ret = old.code(&data, &mut in_pos, &mut out, &mut out_pos, action);
                    assert!(ret == Ret::Ok || ret == Ret::StreamEnd);

                    let mut again = raw_encoder_reinit(after, Some(old)).unwrap();
                    assert!(
                        encode(again.as_mut(), &data, 777) == want,
                        "{before:?} left at {room} bytes, then {after:?}",
                    );
                }
            }
        }
    }
}
