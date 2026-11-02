//! Port of the parts of `compress/zstd_compress.c` about sequences given
//! from outside the match finder: frames compressed from the caller's
//! sequences (`ZSTD_compressSequences`, `ZSTD_compressSequencesAndLiterals`),
//! blocks whose sequences come from a sequence producer of the caller's
//! (`ZSTD_registerSequenceProducer`, and its part of `ZSTD_buildSeqStore`),
//! and the sequences a frame would have (`ZSTD_generateSequences`, with the
//! sequence collector). A module of its own for its size, as a part of
//! `zstd_compress.rs`, whose context it works on.
//!
//! libzstd trusts the sequences it is given unless told to check them
//! (`ZSTD_c_validateSequences`), and some that make no sense lead it to
//! read or write out of its buffers. The port follows libzstd's arithmetic
//! on them, lengths that wrap around included, so that every frame libzstd
//! writes, sensible or not, the port writes too; where libzstd would go
//! out of its buffers, the port fails with `ExternalSequencesInvalid`
//! instead (each place is marked).

use super::{
    CCtx, CParameterKind, ZSTD_BLOCKSIZE_MAX_MIN, ZSTD_MINMATCH_MIN, offbase_is_repcode,
    zstd_compress_bound, zstd_entropy_compress_seq_store, zstd_entropy_compress_seq_store_internal,
    zstd_is_rle, zstd_rle_compress_block,
};
use crate::zstd::common::error_private::{Result, error};
use crate::zstd::common::mem::write_le32;
use crate::zstd::common::zstd_internal::{
    BlockType, MIN_CBLOCK_SIZE, MINMATCH, ZSTD_BLOCKHEADERSIZE, ZSTD_REP_NUM,
};
use crate::zstd::compress::zstd_compress_internal::{
    FseRepeat, LongLengthType, ParamSwitch, SeqDef, SeqStoreView,
    zstd_literals_compression_is_disabled, zstd_no_compress_block, zstd_update_rep,
};
use crate::zstd::compress::zstdmt_compress::ZSTDMT_JOBSIZE_MIN;
use std::sync::Mutex;

/// `ZSTD_Sequence`: a sequence as the caller gives it to
/// [`CCtx::compress_sequences`], or gets it from
/// [`CCtx::generate_sequences`]: `lit_length` literals, then a match of
/// `match_length` bytes, `offset` back.
///
/// A sequence whose offset and match length are both 0 is a block
/// delimiter: it ends a block, its `lit_length` the block's last literals
/// (possibly 0).
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Debug)]
pub struct Sequence {
    /// How far back the match starts, 1 for the byte just before (not the
    /// offset code of the format); 0 in a block delimiter.
    pub offset: u32,
    /// The literals before the match.
    pub lit_length: u32,
    /// The length of the match; 0 in a block delimiter.
    pub match_length: u32,
    /// Which repeat offset `offset` is, 1 to 3, as the format counts them
    /// (with a literal length of 0: the second, the third, and the first
    /// less one), or 0 for none. [`CCtx::generate_sequences`] sets it;
    /// [`CCtx::compress_sequences`] does not read it, and works the repeat
    /// offsets out itself (see [`CParameter::RepcodeResolution`]).
    ///
    /// [`CParameter::RepcodeResolution`]: super::CParameter::RepcodeResolution
    pub rep: u32,
}

/// `ZSTD_SequenceFormat_e`: whether sequences given come with block
/// delimiters ([`CParameter::BlockDelimiters`]).
///
/// [`CParameter::BlockDelimiters`]: super::CParameter::BlockDelimiters
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum SequenceFormat {
    /// `ZSTD_sf_noBlockDelimiters`, the default: just sequences, without
    /// delimiters. The context cuts the frame into blocks itself, splitting
    /// a sequence where a block ends in it; input past the sequences is
    /// literals.
    #[default]
    NoBlockDelimiters = 0,
    /// `ZSTD_sf_explicitBlockDelimiters`: each block's sequences, then a
    /// delimiter (offset 0, match length 0) with the block's last
    /// literals.
    ExplicitBlockDelimiters = 1,
}

/// `ZSTD_SEQUENCE_PRODUCER_ERROR`: what a [`SequenceProducer`] returns when
/// it cannot give a block's sequences. Any value greater than the room it
/// was given is taken as an error too.
pub const SEQUENCE_PRODUCER_ERROR: usize = usize::MAX;

/// `ZSTD_sequenceProducer_F`: a match finder of the caller's, which gives
/// the sequences of each block of the frames a context compresses, in
/// place of the context's own (see [`CCtx::register_sequence_producer`]).
///
/// Closures with the arguments of [`SequenceProducer::produce_sequences`]
/// are producers.
pub trait SequenceProducer: Send {
    /// The sequences of the block `src` into `out_seqs`, and how many: a
    /// valid parse of `src`, whose lengths add up to `src.len()`, every
    /// match of 3 bytes or more but maybe the last's, which may be a block
    /// delimiter (offset 0, match length 0) with the last literals. When
    /// the last sequence is not a delimiter, the context adds one, of no
    /// literals. Offsets reach back no farther than the start of `src` and
    /// `window_size`.
    ///
    /// `dict` is a dictionary to find matches in too; libzstd 1.5.7
    /// passes none, and neither does the port. `compression_level` is the
    /// frame's level.
    ///
    /// Return [`SEQUENCE_PRODUCER_ERROR`] (or any number larger than
    /// `out_seqs.len()`) when the block cannot be done, or 0 for a block
    /// that is not empty: the context then fails the frame with
    /// [`ErrorCode::SequenceProducerFailed`](crate::zstd::ErrorCode::SequenceProducerFailed),
    /// or compresses that block itself if
    /// [`CParameter::EnableSeqProducerFallback`](super::CParameter::EnableSeqProducerFallback)
    /// is on. A parse that is not valid is not detected, unless
    /// [`CParameter::ValidateSequences`](super::CParameter::ValidateSequences)
    /// is on, and makes a frame that does not decode to the input.
    fn produce_sequences(
        &mut self,
        out_seqs: &mut [Sequence],
        src: &[u8],
        dict: &[u8],
        compression_level: i32,
        window_size: usize,
    ) -> usize;
}

impl<F> SequenceProducer for F
where
    F: FnMut(&mut [Sequence], &[u8], &[u8], i32, usize) -> usize + Send,
{
    fn produce_sequences(
        &mut self,
        out_seqs: &mut [Sequence],
        src: &[u8],
        dict: &[u8],
        compression_level: i32,
        window_size: usize,
    ) -> usize {
        self(out_seqs, src, dict, compression_level, window_size)
    }
}

/// `ZSTD_sequenceBound`: the most sequences an input of `src_size` bytes
/// can have, block delimiters included: the room
/// [`CCtx::generate_sequences`] can need.
pub fn sequence_bound(src_size: usize) -> usize {
    let max_nb_seq = (src_size / ZSTD_MINMATCH_MIN as usize) + 1;
    let max_nb_delims = (src_size / ZSTD_BLOCKSIZE_MAX_MIN as usize) + 1;
    max_nb_seq + max_nb_delims
}

/// `ZSTD_mergeBlockDelimiters`: `sequences` without their block
/// delimiters, the literals of each added to the next sequence's (those of
/// the last are dropped), moved to the front. Returns how many are left:
/// sequences for [`SequenceFormat::NoBlockDelimiters`]. The ones after are
/// left as they were.
pub fn merge_block_delimiters(sequences: &mut [Sequence]) -> usize {
    let seqs_size = sequences.len();
    let mut out = 0;
    for i in 0..seqs_size {
        if sequences[i].offset == 0 && sequences[i].match_length == 0 {
            if i != seqs_size - 1 {
                sequences[i + 1].lit_length = sequences[i + 1]
                    .lit_length
                    .wrapping_add(sequences[i].lit_length);
            }
        } else {
            sequences[out] = sequences[i];
            out += 1;
        }
    }
    out
}

/// `ZSTD_resolveExternalRepcodeSearch`: whether to look for repeat offsets
/// in the sequences given; for `Auto`, from level 10 on.
pub(crate) fn zstd_resolve_external_repcode_search(
    value: ParamSwitch,
    c_level: i32,
) -> ParamSwitch {
    if value != ParamSwitch::Auto {
        return value;
    }
    if c_level < 10 {
        ParamSwitch::Disable
    } else {
        ParamSwitch::Enable
    }
}

// ---------------------------------------------------------------------------
// The sequence collector

/// `SeqCollector`: the sequences of the blocks of a frame, gathered for
/// [`CCtx::generate_sequences`].
///
/// Differs from libzstd: the sequences go into a buffer of the context's,
/// copied out to the caller's array at the end, where libzstd writes them
/// there as they come; the array then holds the same, on failure too. And
/// libzstd keeps on gathering sequences into that array in the frames the
/// context compresses after `ZSTD_generateSequences`, which it does not
/// turn off; the port gathers them only within it.
pub(crate) struct SeqCollector {
    /// The sequences so far: `seqIndex` of them.
    pub(crate) seqs: Vec<Sequence>,
    /// `maxSequences`: the room in the caller's array.
    pub(crate) max_sequences: usize,
}

/// `ZSTD_copyBlockSequences`: the sequences of a block (or a partition of
/// it), `in_seqs` with `nb_in_literals` literals and the long length the
/// store marks, as [`Sequence`]s, with their offsets and repeat codes as
/// the repeat offsets `prev_repcodes` before them make them; then a block
/// delimiter with the last literals. Fails with `DstSizeTooSmall`, adding
/// none, when they do not all fit.
pub(crate) fn copy_block_sequences(
    collector: &mut SeqCollector,
    in_seqs: &[SeqDef],
    nb_in_literals: usize,
    long_length_type: LongLengthType,
    long_length_pos: u32,
    prev_repcodes: &[u32; ZSTD_REP_NUM],
) -> Result<()> {
    let nb_in_sequences = in_seqs.len();
    let nb_out_sequences = nb_in_sequences + 1;
    let seq_index = collector.seqs.len();
    debug_assert!(seq_index <= collector.max_sequences);
    // Room for every sequence and the delimiter.
    if nb_out_sequences > collector.max_sequences - seq_index {
        return error!(DstSizeTooSmall);
    }

    let mut repcodes = *prev_repcodes;
    let mut nb_out_literals: usize = 0;
    for (i, in_seq) in in_seqs.iter().enumerate() {
        let mut out = Sequence {
            offset: 0,
            lit_length: u32::from(in_seq.lit_length),
            match_length: u32::from(in_seq.ml_base) + MINMATCH,
            rep: 0,
        };
        // The one length of 64 KB or more a block can have: with MINMATCH
        // added to every match length, and blocks of 128 KB at most.
        if i == long_length_pos as usize {
            match long_length_type {
                LongLengthType::LiteralLength => out.lit_length += 0x10000,
                LongLengthType::MatchLength => out.match_length += 0x10000,
                LongLengthType::None => {}
            }
        }
        // The offset, of a repeat code too.
        let raw_offset = if offbase_is_repcode(in_seq.off_base) {
            let repcode = in_seq.off_base;
            out.rep = repcode;
            if out.lit_length != 0 {
                repcodes[repcode as usize - 1]
            } else if repcode == 3 {
                repcodes[0].wrapping_sub(1)
            } else {
                repcodes[repcode as usize]
            }
        } else {
            in_seq.off_base.wrapping_sub(ZSTD_REP_NUM as u32)
        };
        out.offset = raw_offset;
        // The repeat offsets after the sequence, its literal length 0 by
        // its 16 bits, as libzstd tells.
        zstd_update_rep(&mut repcodes, in_seq.off_base, in_seq.lit_length == 0);
        nb_out_literals = nb_out_literals.wrapping_add(out.lit_length as usize);
        collector.seqs.push(out);
    }
    // The last literals as a delimiter, (0, 0, 0) when there are none.
    let last_ll_size = nb_in_literals.wrapping_sub(nb_out_literals);
    collector.seqs.push(Sequence {
        offset: 0,
        lit_length: last_ll_size as u32,
        match_length: 0,
        // Not set by libzstd, which leaves what the caller's array has
        // there: see CCtx::generate_sequences.
        rep: 0,
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// The sequence producer

/// `ZSTD_postProcessSequenceProducerResult`: `nb_external_seqs`, what the
/// producer returned for a block of `src_size` bytes, checked for an error;
/// and a block delimiter added if the producer did not end with one.
/// Returns how many sequences there are then.
fn post_process_sequence_producer_result(
    out_seqs: &mut [Sequence],
    nb_external_seqs: usize,
    src_size: usize,
) -> Result<usize> {
    let out_seqs_capacity = out_seqs.len();
    // An error code, as the producer returns it.
    if nb_external_seqs > out_seqs_capacity {
        return error!(SequenceProducerFailed);
    }
    // No sequences for a block that is not empty.
    if nb_external_seqs == 0 && src_size > 0 {
        return error!(SequenceProducerFailed);
    }
    if src_size == 0 {
        out_seqs[0] = Sequence::default();
        return Ok(1);
    }
    let last_seq = out_seqs[nb_external_seqs - 1];
    // Already a block delimiter.
    if last_seq.offset == 0 && last_seq.match_length == 0 {
        return Ok(nb_external_seqs);
    }
    // No room for one: only a parse that is not valid needs as many
    // sequences as ZSTD_sequenceBound allows.
    if nb_external_seqs == out_seqs_capacity {
        return error!(SequenceProducerFailed);
    }
    out_seqs[nb_external_seqs] = Sequence::default();
    Ok(nb_external_seqs + 1)
}

/// `ZSTD_fastSequenceLengthSum`: the literal and match lengths of
/// `seq_buf`, all of them, delimiters included.
fn fast_sequence_length_sum(seq_buf: &[Sequence]) -> usize {
    let mut match_len_sum: usize = 0;
    let mut lit_len_sum: usize = 0;
    for seq in seq_buf {
        lit_len_sum = lit_len_sum.wrapping_add(seq.lit_length as usize);
        match_len_sum = match_len_sum.wrapping_add(seq.match_length as usize);
    }
    lit_len_sum.wrapping_add(match_len_sum)
}

// ---------------------------------------------------------------------------
// Sequences into a block's store

/// `ZSTD_validateSequence`: whether the sequence of offset base `off_base`
/// (as `ZSTD_storeSeq` takes it) and match length `match_length`, ending
/// `pos_in_src` bytes into the frame, is valid: its offset within the
/// window, or within the frame so far and the dictionary while that is no
/// larger than the window; its match no shorter than the shortest match
/// (3 bytes with a sequence producer).
#[allow(clippy::too_many_arguments)]
fn validate_sequence(
    off_base: u32,
    match_length: u32,
    min_match: u32,
    pos_in_src: usize,
    window_log: u32,
    dict_size: usize,
    use_sequence_producer: bool,
) -> Result<()> {
    let window_size = 1u64 << window_log;
    // As long as the frame so far is no larger than the window, offsets may
    // reach into the dictionary, past the window even; after that, no
    // farther than the window.
    let offset_bound = if pos_in_src as u64 > window_size {
        window_size
    } else {
        pos_in_src as u64 + dict_size as u64
    };
    let match_len_lower_bound = if min_match == 3 || use_sequence_producer {
        3
    } else {
        4
    };
    // OFFSET_TO_OFFBASE(offsetBound)
    if u64::from(off_base) > offset_bound + ZSTD_REP_NUM as u64 {
        // Offset too large.
        return error!(ExternalSequencesInvalid);
    }
    if match_length < match_len_lower_bound {
        // Match length too small for the shortest match.
        return error!(ExternalSequencesInvalid);
    }
    Ok(())
}

/// `ZSTD_finalizeOffBase`: the offset base of the offset `raw_offset`: a
/// repeat code if it is one of the repeat offsets `rep`, as the format
/// counts them with a literal length of 0 (`ll0`) or not;
/// `OFFSET_TO_OFFBASE` otherwise.
fn finalize_off_base(raw_offset: u32, rep: &[u32; ZSTD_REP_NUM], ll0: bool) -> u32 {
    let ll0 = u32::from(ll0);
    if ll0 == 0 && raw_offset == rep[0] {
        1
    } else if raw_offset == rep[1] {
        2 - ll0
    } else if raw_offset == rep[2] {
        3 - ll0
    } else if ll0 != 0 && raw_offset == rep[0].wrapping_sub(1) {
        3
    } else {
        // OFFSET_TO_OFFBASE, which wraps around for the largest offsets.
        raw_offset.wrapping_add(ZSTD_REP_NUM as u32)
    }
}

/// An offset base `OFFSET_TO_OFFBASE` made of an offset given, checked.
///
/// Differs from libzstd: an offset of 2^32 − 3 wraps around to an offset
/// base of 0, which is neither an offset nor a repeat code; libzstd goes on
/// with it, reading past its repeat offsets and its tables (its offset
/// code is the high bit of 0). The port fails with
/// `ExternalSequencesInvalid`. The two offsets above it wrap around to
/// repeat codes, which libzstd and the port both take as such.
fn checked_off_base(off_base: u32) -> Result<u32> {
    if off_base == 0 {
        return error!(ExternalSequencesInvalid);
    }
    Ok(off_base)
}

/// `ZSTD_SequencePosition`: how far the blocks of a frame have taken the
/// caller's sequences.
///
/// Differs from libzstd: the index is a `usize`, libzstd's a `U32`; they
/// differ only past 2^32 sequences.
#[derive(Clone, Copy, Default, Debug)]
struct SequencePosition {
    /// `idx`: the sequence where the next block starts.
    idx: usize,
    /// `posInSequence`: how far into that sequence, from the start of its
    /// literals, when a block ended in it.
    pos_in_sequence: u32,
    /// `posInSrc`: how far into the input, counted when the sequences are
    /// checked.
    pos_in_src: usize,
}

/// `blockSize_explicitDelimiter`: the size of the next block, the lengths
/// of its sequences up to its delimiter and that one's literals. Fails
/// without a delimiter, or with a sequence of offset 0 and a match.
fn block_size_explicit_delimiter(in_seqs: &[Sequence], seq_pos: SequencePosition) -> Result<usize> {
    let mut end = false;
    let mut block_size: usize = 0;
    let mut spos = seq_pos.idx;
    debug_assert!(spos <= in_seqs.len());
    while spos < in_seqs.len() {
        let seq = in_seqs[spos];
        end = seq.offset == 0;
        // libzstd adds the two lengths as `U32`, which can wrap around.
        block_size =
            block_size.wrapping_add(seq.lit_length.wrapping_add(seq.match_length) as usize);
        if end {
            if seq.match_length != 0 {
                // A delimiter has neither an offset nor a match.
                return error!(ExternalSequencesInvalid);
            }
            break;
        }
        spos += 1;
    }
    if !end {
        // No block delimiter before the end of the sequences.
        return error!(ExternalSequencesInvalid);
    }
    Ok(block_size)
}

/// `determine_blockSize`: the size of the next block, at most `block_size`
/// and `remaining`: without delimiters, as much as that; with them, the
/// next block's, which fails if larger.
fn determine_block_size(
    mode: SequenceFormat,
    block_size: usize,
    remaining: usize,
    in_seqs: &[Sequence],
    seq_pos: SequencePosition,
) -> Result<usize> {
    if mode == SequenceFormat::NoBlockDelimiters {
        // A target: the sequences may end the block a little before.
        return Ok(remaining.min(block_size));
    }
    let explicit_block_size = block_size_explicit_delimiter(in_seqs, seq_pos)?;
    if explicit_block_size > block_size {
        // The sequences make a block larger than the largest.
        return error!(ExternalSequencesInvalid);
    }
    if explicit_block_size > remaining {
        // The sequences make a frame longer than the input.
        return error!(ExternalSequencesInvalid);
    }
    Ok(explicit_block_size)
}

/// `BlockSummary`: a block of the sequences given with their literals
/// apart.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BlockSummary {
    /// `nbSequences`: its sequences, its delimiter included.
    pub(crate) nb_sequences: usize,
    /// `blockSize`: the bytes they make.
    pub(crate) block_size: usize,
    /// `litSize`: their literals.
    pub(crate) lit_size: usize,
}

/// `ZSTD_get1BlockSummary`: the next block of `seqs`, up to the first
/// sequence with a match length of 0, its delimiter. Fails without one.
///
/// libzstd has a version with AVX2, built for processors that have it
/// (`-mavx2`), which sums the lengths in 32 bits; the port follows the
/// other, which sums them in a `size_t`. They differ only for sums past
/// 2^32.
pub(crate) fn get1_block_summary(seqs: &[Sequence]) -> Result<BlockSummary> {
    let mut total_match_size: usize = 0;
    let mut lit_size: usize = 0;
    let mut n = 0;
    while n < seqs.len() {
        total_match_size = total_match_size.wrapping_add(seqs[n].match_length as usize);
        lit_size = lit_size.wrapping_add(seqs[n].lit_length as usize);
        if seqs[n].match_length == 0 {
            // The end of the block (its offset is not checked).
            break;
        }
        n += 1;
    }
    if n == seqs.len() {
        // No end of block.
        return error!(ExternalSequencesInvalid);
    }
    Ok(BlockSummary {
        nb_sequences: n + 1,
        block_size: lit_size.wrapping_add(total_match_size),
        lit_size,
    })
}

/// `convertSequences_noRepcodes`: `in_seqs` into the store's sequences, as
/// offsets, never repeat codes. Returns where the long length is: 0 for
/// none, its position plus 1 for a match length, plus 1 and the number of
/// sequences for a literal length (of several, the last's).
fn convert_sequences_no_repcodes(
    dst_seqs: &mut Vec<SeqDef>,
    in_seqs: &[Sequence],
) -> Result<usize> {
    let nb_sequences = in_seqs.len();
    let mut long_len = 0;
    for (n, seq) in in_seqs.iter().enumerate() {
        dst_seqs.push(SeqDef {
            off_base: checked_off_base(seq.offset.wrapping_add(ZSTD_REP_NUM as u32))?,
            lit_length: seq.lit_length as u16,
            ml_base: seq.match_length.wrapping_sub(MINMATCH) as u16,
        });
        // A length over 65535.
        if seq.match_length > 65535 + MINMATCH {
            long_len = n + 1;
        }
        if seq.lit_length > 65535 {
            long_len = n + nb_sequences + 1;
        }
    }
    Ok(long_len)
}

impl CCtx {
    /// `ZSTD_registerSequenceProducer`: `producer` gives the sequences of
    /// each block of the frames the context compresses after, in place of
    /// its own match finder; `None` for none, the default. It stays until
    /// another is registered, or the parameters are reset.
    ///
    /// It serves the frames of [`CCtx::compress2`] and
    /// [`CCtx::compress_stream2`] (and of [`CCtx::generate_sequences`]),
    /// not those of [`CCtx::compress`] and the other one-call functions,
    /// which do not take the parameters set. Each block is given apart,
    /// without the input before it nor the dictionary: the producer's
    /// matches are within the block (the dictionary is still the frame's,
    /// for the decoder, and for the blocks the producer fails on when the
    /// context compresses them itself, see
    /// [`CParameter::EnableSeqProducerFallback`]). Blocks too small to
    /// compress, under 7 bytes, are not given.
    ///
    /// The frames of a producer that fails with long distance matching
    /// ([`CParameter::EnableLongDistanceMatching`]) at their first block,
    /// and with workers ([`CParameter::NbWorkers`]) as they start, with
    /// [`ErrorCode::ParameterCombinationUnsupported`]: long distance
    /// matching turns itself on for windows of 128 MB or more with the
    /// strongest strategies, unless turned off.
    ///
    /// Registered while a frame is streamed, it serves from the next frame:
    /// that frame goes on with the one it started with, as in libzstd.
    ///
    /// A flaw of libzstd 1.5.7, which the port keeps to write the same
    /// frames: with the fallback and the resolution of repeat codes on
    /// ([`CParameter::RepcodeResolution`]), a block the context compresses
    /// itself with the strategies up to `btlazy2`, whose block compressors
    /// keep only two repeat offsets up to date, leaves a third that the
    /// decoder does not have. A sequence of the producer's next block whose
    /// offset is that one is then written as a repeat code the decoder takes
    /// for another offset, and the frame does not decode to the input. With
    /// the fallback, turn the resolution off, or use the strategies from
    /// `btopt` up.
    ///
    /// [`CParameter::EnableSeqProducerFallback`]: super::CParameter::EnableSeqProducerFallback
    /// [`CParameter::RepcodeResolution`]: super::CParameter::RepcodeResolution
    /// [`CParameter::EnableLongDistanceMatching`]: super::CParameter::EnableLongDistanceMatching
    /// [`CParameter::NbWorkers`]: super::CParameter::NbWorkers
    /// [`ErrorCode::ParameterCombinationUnsupported`]: crate::zstd::ErrorCode::ParameterCombinationUnsupported
    pub fn register_sequence_producer(&mut self, producer: Option<Box<dyn SequenceProducer>>) {
        self.requested_params.ext_seq_prod = producer.is_some();
        let producer = producer.map(Mutex::new);
        if self.stream_stage == super::StreamStage::Init {
            self.seq_producer = producer;
            self.pending_seq_producer = None;
        } else {
            self.pending_seq_producer = Some(producer);
        }
    }

    /// The sequence producer registered while the last frame was streamed,
    /// for the frame about to start (whose parameters, those requested,
    /// already say whether there is one).
    pub(super) fn commit_pending_seq_producer(&mut self) {
        if let Some(producer) = self.pending_seq_producer.take() {
            self.seq_producer = producer;
        }
    }

    /// The sequence producer's part of `ZSTD_buildSeqStore`: the sequences
    /// of the block `src` from the producer, checked, into the store.
    /// Returns `false` when it fails and the context is to compress the
    /// block itself (`ZSTD_c_enableSeqProducerFallback`); its failure
    /// otherwise.
    pub(super) fn build_seq_store_with_producer(&mut self, src: &[u8]) -> Result<bool> {
        let window_size = 1usize << self.applied_params.c_params.window_log;
        let compression_level = self.applied_params.compression_level;
        let nb_external_seqs = match &mut self.seq_producer {
            Some(producer) => {
                // Never locked: see `seq_producer`.
                let producer = match producer.get_mut() {
                    Ok(producer) => producer,
                    Err(poisoned) => poisoned.into_inner(),
                };
                // The dictionary: none, as in libzstd 1.5.7.
                producer.produce_sequences(
                    &mut self.ext_seq_buf,
                    src,
                    &[],
                    compression_level,
                    window_size,
                )
            }
            // The parameters say there is one only when there is.
            None => SEQUENCE_PRODUCER_ERROR,
        };
        match post_process_sequence_producer_result(
            &mut self.ext_seq_buf,
            nb_external_seqs,
            src.len(),
        ) {
            Ok(nb_post_processed_seqs) => {
                let seq_len_sum =
                    fast_sequence_length_sum(&self.ext_seq_buf[..nb_post_processed_seqs]);
                if seq_len_sum > src.len() {
                    // The sequences make too large a block.
                    return error!(ExternalSequencesInvalid);
                }
                let ext_seqs = std::mem::take(&mut self.ext_seq_buf);
                let mut seq_pos = SequencePosition::default();
                let result = self.transfer_sequences_w_block_delim(
                    &mut seq_pos,
                    &ext_seqs[..nb_post_processed_seqs],
                    src,
                    self.applied_params.search_for_external_repcodes,
                );
                self.ext_seq_buf = ext_seqs;
                result?;
                Ok(true)
            }
            // The producer failed: the frame too, unless falling back.
            Err(error) if !self.applied_params.enable_match_finder_fallback => Err(error),
            Err(_) => Ok(false),
        }
    }

    /// The size of the frame's dictionary, which offsets may reach into:
    /// the `CDict`'s, the loaded dictionary's or the prefix's.
    ///
    /// As in libzstd, a prefix never counts: the frame's start
    /// (`ZSTD_CCtx_init_compressStream2`) has used it up already.
    fn sequences_dict_size(&self) -> usize {
        if let Some(cdict) = &self.cdict {
            cdict.dict_size()
        } else if let Some((prefix, _)) = &self.prefix_dict {
            prefix.len()
        } else {
            0
        }
    }

    /// `ZSTD_transferSequences_wBlockDelim`: the sequences from `seq_pos`
    /// up to the next block delimiter into the store, as the block `src`,
    /// whose size their lengths and the delimiter's literals must add up
    /// to; their offsets as repeat codes where they can be, unless
    /// `external_rep_search` is off. Returns the block's size.
    fn transfer_sequences_w_block_delim(
        &mut self,
        seq_pos: &mut SequencePosition,
        in_seqs: &[Sequence],
        src: &[u8],
        external_rep_search: ParamSwitch,
    ) -> Result<usize> {
        let block_size = src.len();
        let start_idx = seq_pos.idx;
        let mut idx = seq_pos.idx;
        let iend = block_size;
        let mut ip = 0usize;
        // libzstd's `U32`.
        let dict_size = self.sequences_dict_size() as u32 as usize;
        let params = self.applied_params;
        let mut updated_repcodes = self.prev_cblock.rep;
        while idx < in_seqs.len() && (in_seqs[idx].match_length != 0 || in_seqs[idx].offset != 0) {
            let lit_length = in_seqs[idx].lit_length;
            let match_length = in_seqs[idx].match_length;
            let off_base = if external_rep_search == ParamSwitch::Disable {
                checked_off_base(in_seqs[idx].offset.wrapping_add(ZSTD_REP_NUM as u32))?
            } else {
                let ll0 = lit_length == 0;
                let off_base = checked_off_base(finalize_off_base(
                    in_seqs[idx].offset,
                    &updated_repcodes,
                    ll0,
                ))?;
                zstd_update_rep(&mut updated_repcodes, off_base, ll0);
                off_base
            };

            if params.validate_sequences {
                seq_pos.pos_in_src = seq_pos
                    .pos_in_src
                    .wrapping_add(lit_length.wrapping_add(match_length) as usize);
                validate_sequence(
                    off_base,
                    match_length,
                    params.c_params.min_match,
                    seq_pos.pos_in_src,
                    params.c_params.window_log,
                    dict_size,
                    params.ext_seq_prod,
                )?;
            }
            if idx - seq_pos.idx >= self.seq_store.max_nb_seq {
                // More sequences than the store holds: a shortest match of
                // 3 makes room for more.
                return error!(ExternalSequencesInvalid);
            }
            // Differs from libzstd: lengths whose sum wraps around 2^32 can
            // put the literals past the block, which libzstd reads; the port
            // fails. Only such lengths do: the block's size is their sum.
            if ip
                .checked_add(lit_length as usize)
                .is_none_or(|lit_end| lit_end > iend)
            {
                return error!(ExternalSequencesInvalid);
            }
            self.seq_store
                .store_external_seq(src, ip, lit_length, off_base, match_length);
            ip = ip.wrapping_add(match_length.wrapping_add(lit_length) as usize);
            idx += 1;
        }
        if idx == in_seqs.len() {
            // No block delimiter.
            return error!(ExternalSequencesInvalid);
        }

        // Without looking for repeat codes, the repeat offsets now: the
        // last three offsets.
        debug_assert!(idx >= start_idx);
        if external_rep_search == ParamSwitch::Disable && idx != start_idx {
            let rep = &mut updated_repcodes;
            // The last sequence before the delimiter.
            let last_seq_idx = idx - 1;
            if last_seq_idx >= start_idx + 2 {
                rep[2] = in_seqs[last_seq_idx - 2].offset;
                rep[1] = in_seqs[last_seq_idx - 1].offset;
                rep[0] = in_seqs[last_seq_idx].offset;
            } else if last_seq_idx == start_idx + 1 {
                rep[2] = rep[0];
                rep[1] = in_seqs[last_seq_idx - 1].offset;
                rep[0] = in_seqs[last_seq_idx].offset;
            } else {
                debug_assert!(last_seq_idx == start_idx);
                rep[2] = rep[1];
                rep[1] = rep[0];
                rep[0] = in_seqs[last_seq_idx].offset;
            }
        }
        self.next_cblock.rep = updated_repcodes;

        let last_lit_length = in_seqs[idx].lit_length;
        if last_lit_length != 0 {
            // The same as above, for the delimiter's literals.
            if ip
                .checked_add(last_lit_length as usize)
                .is_none_or(|lit_end| lit_end > iend)
            {
                return error!(ExternalSequencesInvalid);
            }
            self.seq_store
                .store_last_literals(src, ip, last_lit_length as usize);
            ip += last_lit_length as usize;
            seq_pos.pos_in_src = seq_pos.pos_in_src.wrapping_add(last_lit_length as usize);
        }
        if ip != iend {
            // The block's size does not agree with its delimiter.
            return error!(ExternalSequencesInvalid);
        }
        seq_pos.idx = idx + 1;
        Ok(block_size)
    }

    /// `ZSTD_transferSequences_noDelim`: the sequences from `seq_pos` that
    /// make the block `src`, into the store, the one it ends in split there,
    /// as offsets made repeat codes where they can be (repeat codes are
    /// always looked for here). The block may end a little earlier, not to
    /// split a match into one shorter than the shortest match. Returns the
    /// block's size then.
    ///
    /// libzstd's `U32` arithmetic, which wraps around, is kept.
    fn transfer_sequences_no_delim(
        &mut self,
        seq_pos: &mut SequencePosition,
        in_seqs: &[Sequence],
        src: &[u8],
    ) -> Result<usize> {
        let block_size = src.len();
        let mut idx = seq_pos.idx;
        let mut start_pos_in_sequence = seq_pos.pos_in_sequence;
        let mut end_pos_in_sequence = seq_pos.pos_in_sequence.wrapping_add(block_size as u32);
        let dict_size = self.sequences_dict_size();
        let mut ip = 0usize;
        let mut iend = block_size;
        let params = self.applied_params;
        let min_match = params.c_params.min_match;
        let mut updated_repcodes = self.prev_cblock.rep;
        let mut bytes_adjustment: u32 = 0;
        let mut final_match_split = false;

        while end_pos_in_sequence != 0 && idx < in_seqs.len() && !final_match_split {
            let curr_seq = in_seqs[idx];
            let mut lit_length = curr_seq.lit_length;
            let mut match_length = curr_seq.match_length;
            let raw_offset = curr_seq.offset;
            let curr_seq_length = curr_seq.lit_length.wrapping_add(curr_seq.match_length);

            // The sequence, cut to where the block ends.
            if end_pos_in_sequence >= curr_seq_length {
                if start_pos_in_sequence >= lit_length {
                    start_pos_in_sequence -= lit_length;
                    lit_length = 0;
                    match_length = match_length.wrapping_sub(start_pos_in_sequence);
                } else {
                    lit_length -= start_pos_in_sequence;
                }
                // On to the next sequence.
                end_pos_in_sequence -= curr_seq_length;
                start_pos_in_sequence = 0;
            } else {
                // The last sequence, which the block ends in: split it.
                if end_pos_in_sequence > lit_length {
                    lit_length = lit_length.saturating_sub(start_pos_in_sequence);
                    let mut first_half_match_length = end_pos_in_sequence
                        .wrapping_sub(start_pos_in_sequence)
                        .wrapping_sub(lit_length);
                    if match_length as usize > block_size && first_half_match_length >= min_match {
                        // A match longer than the block is split.
                        let second_half_match_length = curr_seq
                            .match_length
                            .wrapping_add(curr_seq.lit_length)
                            .wrapping_sub(end_pos_in_sequence);
                        if second_half_match_length < min_match {
                            // The block ends a little earlier, for the
                            // second half to be a whole match.
                            end_pos_in_sequence = end_pos_in_sequence
                                .wrapping_sub(min_match - second_half_match_length);
                            bytes_adjustment = min_match - second_half_match_length;
                            first_half_match_length =
                                first_half_match_length.wrapping_sub(bytes_adjustment);
                        }
                        match_length = first_half_match_length;
                        // Stop after storing it, the position in the
                        // sequence kept.
                        final_match_split = true;
                    } else {
                        // The block ends before the match instead, not to
                        // split it (or into one too short): with the last
                        // literals.
                        bytes_adjustment = end_pos_in_sequence.wrapping_sub(curr_seq.lit_length);
                        end_pos_in_sequence = curr_seq.lit_length;
                        break;
                    }
                } else {
                    // The block ends in the literals: with the last literals.
                    break;
                }
            }

            // The offset, as a repeat code if it is one.
            let ll0 = lit_length == 0;
            let off_base = checked_off_base(finalize_off_base(raw_offset, &updated_repcodes, ll0))?;
            zstd_update_rep(&mut updated_repcodes, off_base, ll0);

            if params.validate_sequences {
                seq_pos.pos_in_src = seq_pos
                    .pos_in_src
                    .wrapping_add(lit_length.wrapping_add(match_length) as usize);
                validate_sequence(
                    off_base,
                    match_length,
                    min_match,
                    seq_pos.pos_in_src,
                    params.c_params.window_log,
                    dict_size,
                    params.ext_seq_prod,
                )?;
            }
            if idx - seq_pos.idx >= self.seq_store.max_nb_seq {
                // More sequences than the store holds.
                return error!(ExternalSequencesInvalid);
            }
            // Differs from libzstd: as in transfer_sequences_w_block_delim,
            // lengths whose sum wraps around 2^32 can put the literals past
            // the block, which libzstd reads; the port fails.
            if ip
                .checked_add(lit_length as usize)
                .is_none_or(|lit_end| lit_end > iend)
            {
                return error!(ExternalSequencesInvalid);
            }
            self.seq_store
                .store_external_seq(src, ip, lit_length, off_base, match_length);
            ip = ip.wrapping_add(match_length.wrapping_add(lit_length) as usize);
            if !final_match_split {
                // The next sequence.
                idx += 1;
            }
        }
        // (libzstd asserts that the block ends within the sequence at
        // `idx`, which lengths that wrap around 2^32 break.)
        seq_pos.idx = idx;
        seq_pos.pos_in_sequence = end_pos_in_sequence;
        self.next_cblock.rep = updated_repcodes;

        // Differs from libzstd: sequences that reach past the input can make
        // the block end before its start, or before the sequences stored
        // end, which libzstd goes on with, copying from before its input
        // or 4 GB of literals; the port fails. Sequences within the input
        // never do.
        let Some(adjusted_end) = iend.checked_sub(bytes_adjustment as usize) else {
            return error!(ExternalSequencesInvalid);
        };
        iend = adjusted_end;
        if ip > iend {
            return error!(ExternalSequencesInvalid);
        }
        if ip != iend {
            // The last literals.
            let last_ll_size = iend - ip;
            self.seq_store.store_last_literals(src, ip, last_ll_size);
            seq_pos.pos_in_src = seq_pos.pos_in_src.wrapping_add(last_ll_size);
        }
        Ok(iend)
    }

    /// `ZSTD_compressSequences_internal`: the blocks of the frame, from the
    /// sequences given and the input `src`, into `dst`, their headers
    /// included. Returns their size.
    fn compress_sequences_internal(
        &mut self,
        dst: &mut [u8],
        in_seqs: &[Sequence],
        src: &[u8],
    ) -> Result<usize> {
        let mut c_size = 0;
        let mut remaining = src.len();
        let mut seq_pos = SequencePosition::default();
        let mut ip = 0;
        let mut op = 0;
        let mode = self.applied_params.block_delimiters;

        // An empty frame: one empty raw block, the last.
        if remaining == 0 {
            let c_block_header24 = 1 /* last block */ + ((BlockType::Raw as u32) << 1);
            if dst.len() < 4 {
                // No room for the empty block's header (4 bytes are
                // written, as libzstd writes them).
                return error!(DstSizeTooSmall);
            }
            write_le32(dst, op, c_block_header24);
            op += ZSTD_BLOCKHEADERSIZE;
            c_size += ZSTD_BLOCKHEADERSIZE;
        }

        while remaining != 0 {
            let block_size =
                determine_block_size(mode, self.block_size_max, remaining, in_seqs, seq_pos)?;
            // Found before the sequences, which may end the block earlier.
            let last_block = block_size == remaining;
            debug_assert!(block_size <= remaining);
            self.seq_store.reset();

            let block = &src[ip..ip + block_size];
            let block_size = match mode {
                SequenceFormat::ExplicitBlockDelimiters => self.transfer_sequences_w_block_delim(
                    &mut seq_pos,
                    in_seqs,
                    block,
                    self.applied_params.search_for_external_repcodes,
                )?,
                SequenceFormat::NoBlockDelimiters => {
                    self.transfer_sequences_no_delim(&mut seq_pos, in_seqs, block)?
                }
            };
            let block = &src[ip..ip + block_size];

            // Blocks too small to compress are stored raw.
            if block_size < MIN_CBLOCK_SIZE + ZSTD_BLOCKHEADERSIZE + 1 + 1 {
                let c_block_size = zstd_no_compress_block(&mut dst[op..], block, last_block)?;
                c_size += c_block_size;
                ip += block_size;
                op += c_block_size;
                remaining -= block_size;
                // The block after still counts as the first.
                continue;
            }

            if dst.len() - op < ZSTD_BLOCKHEADERSIZE {
                // No room for the next block's header.
                return error!(DstSizeTooSmall);
            }
            let params = &self.applied_params;
            let disable = zstd_literals_compression_is_disabled(
                params.literal_compression_mode,
                params.c_params.strategy,
                params.c_params.target_length,
            );
            let mut compressed_seqs_size = zstd_entropy_compress_seq_store(
                &mut self.seq_store,
                &self.prev_cblock.entropy,
                &mut self.next_cblock.entropy,
                params.c_params.strategy,
                disable,
                &mut dst[op + ZSTD_BLOCKHEADERSIZE..],
                block_size,
                false,
            )?;

            // The first block is never RLE, though it may qualify: the
            // command line of zstd 1.4.3 and earlier reports that not all
            // input was consumed. ZSTD_maybeRLE: few sequences, few
            // literals.
            if !self.is_first_block
                && self.seq_store.sequences.len() < 4
                && self.seq_store.literals().len() < 10
                && zstd_is_rle(block)
            {
                compressed_seqs_size = 1;
            }

            let c_block_size = match compressed_seqs_size {
                0 => zstd_no_compress_block(&mut dst[op..], block, last_block)?,
                1 => zstd_rle_compress_block(&mut dst[op..], block[0], block_size, last_block)?,
                _ => {
                    // The block's tables and repeat offsets for the next.
                    self.confirm_repcodes_and_entropy_tables();
                    if self.prev_cblock.entropy.fse.offcode_repeat_mode == FseRepeat::Valid {
                        self.prev_cblock.entropy.fse.offcode_repeat_mode = FseRepeat::Check;
                    }
                    let c_block_header = u32::from(last_block)
                        + ((BlockType::Compressed as u32) << 1)
                        + ((compressed_seqs_size as u32) << 3);
                    dst[op..op + 3].copy_from_slice(&c_block_header.to_le_bytes()[..3]);
                    ZSTD_BLOCKHEADERSIZE + compressed_seqs_size
                }
            };

            c_size += c_block_size;
            if last_block {
                break;
            }
            ip += block_size;
            op += c_block_size;
            remaining -= block_size;
            self.is_first_block = false;
        }
        Ok(c_size)
    }

    /// Differs from libzstd: with workers ([`CParameter::NbWorkers`]) for
    /// an input over 512 KB, libzstd starts the frame on its workers, then
    /// compresses the sequences with the context's own state, which the
    /// frame never set up (the last frame's, or none): it fails, or reads
    /// and writes out of its buffers. The port fails with
    /// `ParameterCombinationUnsupported`, after what libzstd fails for
    /// first, the dictionary loaded made a `CDict`, and with the prefix
    /// used up, as libzstd uses it.
    ///
    /// [`CParameter::NbWorkers`]: super::CParameter::NbWorkers
    fn refuse_sequences_with_workers(&mut self, src_size: usize) -> Result<()> {
        if self.requested_params.nb_workers > 0 && src_size > ZSTDMT_JOBSIZE_MIN {
            self.init_local_dict()?;
            self.prefix_dict = None;
            return error!(ParameterCombinationUnsupported);
        }
        Ok(())
    }

    /// `ZSTD_compressSequences`: `src` as one frame, from the sequences
    /// `in_seqs` the caller found in it, into `dst`. Returns the frame's
    /// size.
    ///
    /// The frame has the parameters set, as with [`CCtx::compress2`], and
    /// the dictionary loaded or referenced, or the prefix, which offsets
    /// may reach into (checked, a prefix does not count, as in libzstd);
    /// the level decides how the sequences and literals are entropy-coded.
    /// How the sequences make blocks is [`CParameter::BlockDelimiters`]'s;
    /// input past the sequences is literals. Unless checked
    /// ([`CParameter::ValidateSequences`]: offsets within the window and
    /// the dictionary, matches no shorter than [`CParameter::MinMatch`]),
    /// the sequences are trusted, and with offsets past the input so far
    /// (or the window), or matches under 3 bytes, the frame does not decode
    /// to `src`. They fail with [`ErrorCode::ExternalSequencesInvalid`]
    /// when they cannot make the blocks: without a block delimiter where
    /// one is expected, with blocks larger than the largest
    /// ([`CParameter::MaxBlockSize`], and the window) or past the input,
    /// with more sequences in a block than it can hold (a third of its size
    /// with a shortest match of 3, a quarter otherwise), and checked, when
    /// they are not valid. Blocks that do not compress are stored raw, or
    /// RLE.
    ///
    /// The frame ends the frame being streamed, if any; after it, as in
    /// libzstd, the context is still in a frame for
    /// [`CCtx::set_parameter`] (which fails with
    /// [`ErrorCode::StageWrong`] for most parameters) until it is reset
    /// ([`CCtx::reset`]) or [`CCtx::compress2`] starts another.
    ///
    /// Differs from libzstd: with less room than the largest frame header,
    /// 18 bytes, libzstd writes before `dst`; the port fails with
    /// [`ErrorCode::DstSizeTooSmall`]. And with workers for an input over
    /// 512 KB, libzstd fails or goes out of its buffers; the port fails
    /// with [`ErrorCode::ParameterCombinationUnsupported`].
    ///
    /// [`CParameter::BlockDelimiters`]: super::CParameter::BlockDelimiters
    /// [`CParameter::ValidateSequences`]: super::CParameter::ValidateSequences
    /// [`CParameter::MinMatch`]: super::CParameter::MinMatch
    /// [`CParameter::MaxBlockSize`]: super::CParameter::MaxBlockSize
    /// [`ErrorCode::ExternalSequencesInvalid`]: crate::zstd::ErrorCode::ExternalSequencesInvalid
    /// [`ErrorCode::StageWrong`]: crate::zstd::ErrorCode::StageWrong
    /// [`ErrorCode::DstSizeTooSmall`]: crate::zstd::ErrorCode::DstSizeTooSmall
    /// [`ErrorCode::ParameterCombinationUnsupported`]: crate::zstd::ErrorCode::ParameterCombinationUnsupported
    pub fn compress_sequences(
        &mut self,
        dst: &mut [u8],
        in_seqs: &[Sequence],
        src: &[u8],
    ) -> Result<usize> {
        self.refuse_sequences_with_workers(src.len())?;
        // The transparent initialization stage, as ZSTD_compressStream2's.
        self.init_compress_stream2(super::EndDirective::End, src.len())?;

        // The frame header.
        let frame_header_size =
            Self::write_frame_header(dst, &self.applied_params, src.len() as u64, self.dict_id)?;
        let mut op = frame_header_size;
        if self.applied_params.f_params.checksum_flag && !src.is_empty() {
            self.xxh_state.update(src);
        }

        // The blocks.
        let c_blocks_size = self.compress_sequences_internal(&mut dst[op..], in_seqs, src)?;
        op += c_blocks_size;

        // The checksum, if asked for.
        if self.applied_params.f_params.checksum_flag {
            let checksum = self.xxh_state.digest() as u32;
            if dst.len() - op < 4 {
                // No room for the checksum.
                return error!(DstSizeTooSmall);
            }
            write_le32(dst, op, checksum);
            op += 4;
        }
        Ok(op)
    }

    /// `ZSTD_convertBlockSequences`: the sequences of a block, `in_seqs`,
    /// its delimiter last, into the store, without their literals: as
    /// offsets, or as repeat codes where they can be if
    /// `repcode_resolution`. The lengths are not checked.
    pub(crate) fn convert_block_sequences(
        &mut self,
        in_seqs: &[Sequence],
        repcode_resolution: bool,
    ) -> Result<()> {
        let nb_sequences = in_seqs.len();
        if nb_sequences >= self.seq_store.max_nb_seq {
            // More sequences than the store holds.
            return error!(ExternalSequencesInvalid);
        }
        let mut updated_repcodes = self.prev_cblock.rep;
        debug_assert!(nb_sequences >= 1);
        let real_sequences = &in_seqs[..nb_sequences - 1];

        if !repcode_resolution {
            let long_len =
                convert_sequences_no_repcodes(&mut self.seq_store.sequences, real_sequences)?;
            if long_len != 0 {
                let store = &mut self.seq_store;
                if long_len < nb_sequences {
                    store.long_length_type = LongLengthType::MatchLength;
                    store.long_length_pos = (long_len - 1) as u32;
                } else {
                    store.long_length_type = LongLengthType::LiteralLength;
                    store.long_length_pos = (long_len - (nb_sequences - 1) - 1) as u32;
                }
            }
        } else {
            for seq in real_sequences {
                let ll0 = seq.lit_length == 0;
                let off_base =
                    checked_off_base(finalize_off_base(seq.offset, &updated_repcodes, ll0))?;
                self.seq_store
                    .push_external_seq(seq.lit_length, off_base, seq.match_length);
                zstd_update_rep(&mut updated_repcodes, off_base, ll0);
            }
        }

        // Without looking for repeat codes, the repeat offsets now: the
        // last three offsets.
        if !repcode_resolution && nb_sequences > 1 {
            let rep = &mut updated_repcodes;
            if nb_sequences >= 4 {
                // The last sequence before the delimiter.
                let last_seq_idx = nb_sequences - 2;
                rep[2] = in_seqs[last_seq_idx - 2].offset;
                rep[1] = in_seqs[last_seq_idx - 1].offset;
                rep[0] = in_seqs[last_seq_idx].offset;
            } else if nb_sequences == 3 {
                rep[2] = rep[0];
                rep[1] = in_seqs[0].offset;
                rep[0] = in_seqs[1].offset;
            } else {
                debug_assert!(nb_sequences == 2);
                rep[2] = rep[1];
                rep[1] = rep[0];
                rep[0] = in_seqs[0].offset;
            }
        }
        self.next_cblock.rep = updated_repcodes;
        Ok(())
    }

    /// `ZSTD_compressSequencesAndLiterals_internal`: the blocks of the frame,
    /// from the sequences given and their `literals`, all of them, into
    /// `dst`, their headers included. Returns their size.
    fn compress_sequences_and_literals_internal(
        &mut self,
        dst: &mut [u8],
        in_seqs: &[Sequence],
        literals: &[u8],
        src_size: usize,
    ) -> Result<usize> {
        let mut remaining = src_size;
        let mut c_size = 0;
        let mut op = 0;
        let mut in_seqs = in_seqs;
        let mut literals = literals;
        let repcode_resolution =
            self.applied_params.search_for_external_repcodes == ParamSwitch::Enable;
        debug_assert!(self.applied_params.search_for_external_repcodes != ParamSwitch::Auto);

        if in_seqs.is_empty() {
            // At least one block delimiter is needed.
            return error!(ExternalSequencesInvalid);
        }

        // An empty frame: one empty raw block, the last. The blocks are then
        // still compressed, as in libzstd: the frame fails, as a block of
        // no bytes holds no sequences, or for a size that is not 0.
        if in_seqs.len() == 1 && in_seqs[0].lit_length == 0 {
            let c_block_header24 = 1 /* last block */ + ((BlockType::Raw as u32) << 1);
            if dst.len() < 3 {
                // No room for the empty block's header.
                return error!(DstSizeTooSmall);
            }
            dst[..3].copy_from_slice(&c_block_header24.to_le_bytes()[..3]);
            op += ZSTD_BLOCKHEADERSIZE;
            c_size += ZSTD_BLOCKHEADERSIZE;
        }

        while !in_seqs.is_empty() {
            let block = get1_block_summary(in_seqs)?;
            let last_block = block.nb_sequences == in_seqs.len();
            debug_assert!(block.nb_sequences <= in_seqs.len());
            if block.lit_size > literals.len() {
                // The sequences need more literals than given.
                return error!(ExternalSequencesInvalid);
            }
            self.seq_store.reset();
            self.convert_block_sequences(&in_seqs[..block.nb_sequences], repcode_resolution)?;
            in_seqs = &in_seqs[block.nb_sequences..];
            remaining = remaining.wrapping_sub(block.block_size);

            // A block too small to compress is still compressed: without
            // the input, it cannot be stored raw.
            if dst.len() - op < ZSTD_BLOCKHEADERSIZE {
                // No room for the next block's header.
                return error!(DstSizeTooSmall);
            }
            let params = &self.applied_params;
            let store = &mut self.seq_store;
            let nb_seq = store.sequences.len();
            for codes in [&mut store.ll_code, &mut store.ml_code, &mut store.of_code] {
                codes.resize(nb_seq, 0);
            }
            let mut seqs = SeqStoreView {
                sequences: &store.sequences,
                literals: &literals[..block.lit_size],
                ll_code: &mut store.ll_code[..nb_seq],
                ml_code: &mut store.ml_code[..nb_seq],
                of_code: &mut store.of_code[..nb_seq],
                long_length_type: store.long_length_type,
                long_length_pos: store.long_length_pos,
            };
            let mut compressed_seqs_size = zstd_entropy_compress_seq_store_internal(
                &mut dst[op + ZSTD_BLOCKHEADERSIZE..],
                &mut seqs,
                &self.prev_cblock.entropy,
                &mut self.next_cblock.entropy,
                params.c_params.strategy,
                zstd_literals_compression_is_disabled(
                    params.literal_compression_mode,
                    params.c_params.strategy,
                    params.c_params.target_length,
                ),
                false,
            )?;
            // The format forbids compressed blocks larger than the largest
            // block.
            if compressed_seqs_size > self.block_size_max {
                compressed_seqs_size = 0;
            }
            literals = &literals[block.lit_size..];

            if compressed_seqs_size == 0 {
                // Without the input, a raw block cannot be written.
                return error!(CannotProduceUncompressedBlock);
            }
            // Never RLE, which would need the input too.
            debug_assert!(compressed_seqs_size > 1);
            self.confirm_repcodes_and_entropy_tables();
            if self.prev_cblock.entropy.fse.offcode_repeat_mode == FseRepeat::Valid {
                self.prev_cblock.entropy.fse.offcode_repeat_mode = FseRepeat::Check;
            }
            let c_block_header = u32::from(last_block)
                + ((BlockType::Compressed as u32) << 1)
                + ((compressed_seqs_size as u32) << 3);
            dst[op..op + 3].copy_from_slice(&c_block_header.to_le_bytes()[..3]);
            let c_block_size = ZSTD_BLOCKHEADERSIZE + compressed_seqs_size;

            c_size += c_block_size;
            op += c_block_size;
            self.is_first_block = false;
            if last_block {
                debug_assert!(in_seqs.is_empty());
                break;
            }
        }

        if !literals.is_empty() {
            // The literals must all be used.
            return error!(ExternalSequencesInvalid);
        }
        if remaining != 0 {
            // The sequences must make exactly `src_size` bytes.
            return error!(ExternalSequencesInvalid);
        }
        Ok(c_size)
    }

    /// `ZSTD_compressSequencesAndLiterals`: a frame of `decompressed_size`
    /// bytes, from its sequences `in_seqs` and its literals, all of them
    /// one after the other, into `dst`, without the input itself: quicker
    /// than [`CCtx::compress_sequences`] when the literals are at hand.
    /// Returns the frame's size.
    ///
    /// Only with explicit block delimiters
    /// ([`CParameter::BlockDelimiters`]; otherwise it fails with
    /// [`ErrorCode::FrameParameterUnsupported`]), without checking them
    /// ([`CParameter::ValidateSequences`] fails with
    /// [`ErrorCode::ParameterUnsupported`]) and without a checksum
    /// ([`ErrorCode::FrameParameterUnsupported`] again). Each block must
    /// compress: one that would be stored raw fails with
    /// [`ErrorCode::CannotProduceUncompressedBlock`], as do RLE blocks,
    /// which are not detected. The literals must be exactly those of the
    /// sequences, and the sequences make exactly `decompressed_size` bytes
    /// (or it fails with [`ErrorCode::ExternalSequencesInvalid`]). As
    /// with [`CCtx::compress_sequences`], after it the context is still in
    /// a frame for [`CCtx::set_parameter`].
    ///
    /// Differs from libzstd: libzstd also takes the capacity of the
    /// literals' buffer, which must be at least their size, as it may read
    /// past them; the port reads within the slice. Room for less than the
    /// largest frame header, 18 bytes, and workers for over 512 KB, fail as
    /// for [`CCtx::compress_sequences`].
    ///
    /// [`CParameter::BlockDelimiters`]: super::CParameter::BlockDelimiters
    /// [`CParameter::ValidateSequences`]: super::CParameter::ValidateSequences
    /// [`ErrorCode::FrameParameterUnsupported`]: crate::zstd::ErrorCode::FrameParameterUnsupported
    /// [`ErrorCode::ParameterUnsupported`]: crate::zstd::ErrorCode::ParameterUnsupported
    /// [`ErrorCode::CannotProduceUncompressedBlock`]: crate::zstd::ErrorCode::CannotProduceUncompressedBlock
    /// [`ErrorCode::ExternalSequencesInvalid`]: crate::zstd::ErrorCode::ExternalSequencesInvalid
    pub fn compress_sequences_and_literals(
        &mut self,
        dst: &mut [u8],
        in_seqs: &[Sequence],
        literals: &[u8],
        decompressed_size: usize,
    ) -> Result<usize> {
        self.refuse_sequences_with_workers(decompressed_size)?;
        // The transparent initialization stage, as ZSTD_compressStream2's.
        self.init_compress_stream2(super::EndDirective::End, decompressed_size)?;
        let params = &self.applied_params;
        if params.block_delimiters == SequenceFormat::NoBlockDelimiters {
            // Only with explicit block delimiters.
            return error!(FrameParameterUnsupported);
        }
        if params.validate_sequences {
            // The sequences cannot be checked.
            return error!(ParameterUnsupported);
        }
        if params.f_params.checksum_flag {
            // Nor the checksum computed, without the input.
            return error!(FrameParameterUnsupported);
        }

        // The frame header.
        let frame_header_size = Self::write_frame_header(
            dst,
            &self.applied_params,
            decompressed_size as u64,
            self.dict_id,
        )?;
        let op = frame_header_size;

        // The blocks.
        let c_blocks_size = self.compress_sequences_and_literals_internal(
            &mut dst[op..],
            in_seqs,
            literals,
            decompressed_size,
        )?;
        Ok(op + c_blocks_size)
    }

    /// `ZSTD_generateSequences`: the sequences the context finds in `src`,
    /// compressing it as [`CCtx::compress2`] would, into `out_seqs`.
    /// Returns how many there are.
    ///
    /// Each block's sequences end with a block delimiter (offset 0, match
    /// length 0) with its last literals, (0, 0, 0) when there are none; the
    /// block splitter after the sequences
    /// ([`CParameter::SplitAfterSequences`]) ends each partition with one.
    /// [`Sequence::rep`] says which repeat offset each offset is; a
    /// delimiter's is left as `out_seqs` had it. [`sequence_bound`] gives
    /// room enough; with less, it fails with
    /// [`ErrorCode::DstSizeTooSmall`], the sequences of the blocks before
    /// in `out_seqs`. Fails with [`ErrorCode::ParameterUnsupported`] with
    /// a target size for compressed blocks
    /// ([`CParameter::TargetCBlockSize`]) or workers, and with [`ErrorCode::SequenceProducerFailed`] when a block
    /// is too small to have sequences (under 7 bytes, the last of an input
    /// that ends with one included).
    ///
    /// Deprecated in libzstd 1.5.7, for debugging only: libzstd says it
    /// will remove it, for `ZSTD_extractSequences`.
    ///
    /// [`CParameter::SplitAfterSequences`]: super::CParameter::SplitAfterSequences
    /// [`CParameter::TargetCBlockSize`]: super::CParameter::TargetCBlockSize
    /// [`ErrorCode::DstSizeTooSmall`]: crate::zstd::ErrorCode::DstSizeTooSmall
    /// [`ErrorCode::ParameterUnsupported`]: crate::zstd::ErrorCode::ParameterUnsupported
    /// [`ErrorCode::SequenceProducerFailed`]: crate::zstd::ErrorCode::SequenceProducerFailed
    #[deprecated(
        note = "for debugging only, as in libzstd 1.5.7, which will replace it with ZSTD_extractSequences"
    )]
    pub fn generate_sequences(&mut self, out_seqs: &mut [Sequence], src: &[u8]) -> Result<usize> {
        let Ok(dst_capacity) = zstd_compress_bound(src.len()) else {
            // libzstd allocates the bound: that fails.
            return error!(MemoryAllocation);
        };
        if self.get_parameter(CParameterKind::TargetCBlockSize) != 0 {
            // Not with a target size for compressed blocks.
            return error!(ParameterUnsupported);
        }
        if self.get_parameter(CParameterKind::NbWorkers) != 0 {
            // Not with workers.
            return error!(ParameterUnsupported);
        }
        let mut dst = Vec::new();
        if dst.try_reserve_exact(dst_capacity).is_err() {
            return error!(MemoryAllocation);
        }
        dst.resize(dst_capacity, 0);

        self.seq_collector = Some(SeqCollector {
            seqs: Vec::new(),
            max_sequences: out_seqs.len(),
        });
        let result = self.compress2(&mut dst, src);
        let collected = self
            .seq_collector
            .take()
            .map(|collector| collector.seqs)
            .unwrap_or_default();
        // Into the caller's array, delimiters keeping its `rep` as libzstd
        // leaves it.
        for (out, seq) in out_seqs.iter_mut().zip(&collected) {
            let rep = if seq.match_length == 0 {
                out.rep
            } else {
                seq.rep
            };
            *out = Sequence { rep, ..*seq };
        }
        result?;
        Ok(collected.len())
    }
}
