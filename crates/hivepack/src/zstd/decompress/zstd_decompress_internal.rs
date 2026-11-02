//! The decoder's types and constants: port of
//! `decompress/zstd_decompress_internal.h`.
//!
//! `ZSTD_DCtx` holds pointers into buffers it does not own: the previous
//! output (`prefixStart`, `virtualStart`, `dictEnd`) and the literals
//! (`litPtr`, `litBuffer`, `litBufferEnd`), which may be in the output, in its
//! own extra buffer, or in the input. The port keeps indices instead, with a
//! tag saying which buffer each one is in, and passes the buffers to the
//! functions that use them.

use std::sync::Arc;

use crate::zstd::common::fse_decompress::FseBuildDTableWksp;
use crate::zstd::common::xxhash::Xxh64State;
use crate::zstd::common::zstd_internal::{
    BlockType, LL_FSE_LOG, MAX_LL, MAX_ML, MAX_OFF, ML_FSE_LOG, OFF_FSE_LOG, REP_START_VALUE,
    ZSTD_REP_NUM,
};
use crate::zstd::decompress::huf_decompress::{HufDTable, HufDecompressWksp};
use crate::zstd::decompress::zstd_ddict::DDict;
use crate::zstd::decompress::zstd_decompress::FRAMEHEADER_SIZE_MAX;

/// `LL_base`
pub(crate) const LL_BASE: [u32; MAX_LL as usize + 1] = [
    0, 1, 2, 3, 4, 5, 6, 7, //
    8, 9, 10, 11, 12, 13, 14, 15, //
    16, 18, 20, 22, 24, 28, 32, 40, //
    48, 64, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, //
    0x2000, 0x4000, 0x8000, 0x10000,
];

/// `OF_base`
pub(crate) const OF_BASE: [u32; MAX_OFF as usize + 1] = [
    0, 1, 1, 5, 0xD, 0x1D, 0x3D, 0x7D, //
    0xFD, 0x1FD, 0x3FD, 0x7FD, 0xFFD, 0x1FFD, 0x3FFD, 0x7FFD, //
    0xFFFD, 0x1FFFD, 0x3FFFD, 0x7FFFD, 0xFFFFD, 0x1FFFFD, 0x3FFFFD, 0x7FFFFD, //
    0xFFFFFD, 0x1FFFFFD, 0x3FFFFFD, 0x7FFFFFD, 0xFFFFFFD, 0x1FFFFFFD, 0x3FFFFFFD, 0x7FFFFFFD,
];

/// `OF_bits`
pub(crate) const OF_BITS: [u8; MAX_OFF as usize + 1] = [
    0, 1, 2, 3, 4, 5, 6, 7, //
    8, 9, 10, 11, 12, 13, 14, 15, //
    16, 17, 18, 19, 20, 21, 22, 23, //
    24, 25, 26, 27, 28, 29, 30, 31,
];

/// `ML_base`
pub(crate) const ML_BASE: [u32; MAX_ML as usize + 1] = [
    3, 4, 5, 6, 7, 8, 9, 10, //
    11, 12, 13, 14, 15, 16, 17, 18, //
    19, 20, 21, 22, 23, 24, 25, 26, //
    27, 28, 29, 30, 31, 32, 33, 34, //
    35, 37, 39, 41, 43, 47, 51, 59, //
    67, 83, 99, 0x83, 0x103, 0x203, 0x403, 0x803, //
    0x1003, 0x2003, 0x4003, 0x8003, 0x10003,
];

/// `ZSTD_seqSymbol`: one cell of a sequence decoding table.
///
/// The four fields are packed in one `u64`, in libzstd's layout: the
/// decoder then reads a cell in one load, as libzstd does on 64-bit
/// machines, rather than one per field.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SeqSymbol(u64);

impl SeqSymbol {
    /// `nextState`
    #[inline(always)]
    pub(crate) const fn next_state(self) -> u16 {
        self.0 as u16
    }

    /// `nbAdditionalBits`
    #[inline(always)]
    pub(crate) const fn nb_additional_bits(self) -> u8 {
        (self.0 >> 16) as u8
    }

    /// `nbBits`
    #[inline(always)]
    pub(crate) const fn nb_bits(self) -> u8 {
        (self.0 >> 24) as u8
    }

    /// `baseValue`
    #[inline(always)]
    pub(crate) const fn base_value(self) -> u32 {
        (self.0 >> 32) as u32
    }
}

impl std::fmt::Debug for SeqSymbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeqSymbol")
            .field("next_state", &self.next_state())
            .field("nb_additional_bits", &self.nb_additional_bits())
            .field("nb_bits", &self.nb_bits())
            .field("base_value", &self.base_value())
            .finish()
    }
}

/// A cell, in the order libzstd writes them in its tables.
pub(crate) const fn sym(
    next_state: u16,
    nb_additional_bits: u8,
    nb_bits: u8,
    base_value: u32,
) -> SeqSymbol {
    SeqSymbol(
        next_state as u64
            | (nb_additional_bits as u64) << 16
            | (nb_bits as u64) << 24
            | (base_value as u64) << 32,
    )
}

/// A sequence decoding table of up to `N` cells, with its header
/// (`ZSTD_seqSymbol_header`).
#[derive(Clone)]
pub(crate) struct SeqDTable<const N: usize> {
    pub(crate) fast_mode: bool,
    pub(crate) table_log: u32,
    pub(crate) cells: [SeqSymbol; N],
}

impl<const N: usize> Default for SeqDTable<N> {
    fn default() -> Self {
        SeqDTable {
            fast_mode: false,
            table_log: 0,
            cells: [SeqSymbol::default(); N],
        }
    }
}

/// The literal-length table: `SEQSYMBOL_TABLE_SIZE(LLFSELog)` less the header.
pub(crate) const LL_TABLE_CELLS: usize = 1 << LL_FSE_LOG;
/// The offset table.
pub(crate) const OF_TABLE_CELLS: usize = 1 << OFF_FSE_LOG;
/// The match-length table.
pub(crate) const ML_TABLE_CELLS: usize = 1 << ML_FSE_LOG;

/// `ZSTD_entropyDTables_t`
pub(crate) struct EntropyDTables {
    pub(crate) ll_table: SeqDTable<LL_TABLE_CELLS>,
    pub(crate) of_table: SeqDTable<OF_TABLE_CELLS>,
    pub(crate) ml_table: SeqDTable<ML_TABLE_CELLS>,
    pub(crate) huf_table: HufDTable,
    pub(crate) rep: [u32; ZSTD_REP_NUM],
    pub(crate) workspace: FseBuildDTableWksp,
}

/// `ZSTD_HUFFDTABLE_CAPACITY_LOG`
pub(crate) const ZSTD_HUFFDTABLE_CAPACITY_LOG: u32 = 12;

impl Default for EntropyDTables {
    fn default() -> Self {
        EntropyDTables {
            ll_table: SeqDTable::default(),
            of_table: SeqDTable::default(),
            ml_table: SeqDTable::default(),
            huf_table: HufDTable::new(ZSTD_HUFFDTABLE_CAPACITY_LOG),
            rep: REP_START_VALUE,
            workspace: FseBuildDTableWksp::default(),
        }
    }
}

/// Which table one of libzstd's `LLTptr`, `OFTptr`, `MLTptr` or `HUFptr`
/// points to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum TableRef {
    /// The predefined table for the default distribution.
    Default,
    /// The context's own table, in `entropy`.
    Own,
    /// The table of the dictionary in use (a `ZSTD_DDict`), which the
    /// caller passes along.
    Dict,
}

/// `ZSTD_DECODER_INTERNAL_BUFFER`
pub(crate) const ZSTD_DECODER_INTERNAL_BUFFER: usize = 1 << 16;
/// `ZSTD_LBMIN`
const ZSTD_LBMIN: usize = 64;
/// `ZSTD_LBMAX`
const ZSTD_LBMAX: usize = 128 << 10;
/// `ZSTD_LITBUFFEREXTRASIZE`: the extra buffer that holds literals when the
/// output has no room for them.
pub(crate) const ZSTD_LITBUFFEREXTRASIZE: usize = if ZSTD_DECODER_INTERNAL_BUFFER < ZSTD_LBMIN {
    ZSTD_LBMIN
} else if ZSTD_DECODER_INTERNAL_BUFFER > ZSTD_LBMAX {
    ZSTD_LBMAX
} else {
    ZSTD_DECODER_INTERNAL_BUFFER
};

/// `WILDCOPY_OVERLENGTH`: how far libzstd's copies may run past their end.
/// The port copies exact lengths, but keeps the margins libzstd keeps, since
/// they decide where literals go and which checks apply.
pub(crate) const WILDCOPY_OVERLENGTH: usize = 32;

/// `ZSTD_litLocation_e`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum LitLocation {
    /// Entirely in the extra buffer (or, for stored literals, in the input).
    NotInDst,
    /// Entirely in the output, after where this block's output ends.
    InDst,
    /// Split between the end of this block's output and the extra buffer.
    Split,
}

/// The buffer a literal position is in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum LitBuf {
    /// The output.
    Out,
    /// `litExtraBuffer`.
    Extra,
    /// The block's input: stored literals referenced where they are.
    Src,
}

/// A position in one of the literal buffers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct LitPos {
    pub(crate) buf: LitBuf,
    pub(crate) pos: usize,
}

impl LitPos {
    pub(crate) const fn new(buf: LitBuf, pos: usize) -> Self {
        LitPos { buf, pos }
    }
}

/// The older segment of the window, libzstd's "extDict": the dictionary's
/// content, or output from before a discontinuity. libzstd describes it by
/// `virtualStart` and `dictEnd`; its length is `prefixStart - virtualStart`.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ExtDict<'a> {
    None,
    /// A buffer of its own.
    Separate(&'a [u8]),
    /// Earlier output in the buffer the block is decoded into, from `start`
    /// to `end`: when streaming, libzstd goes back to the start of its
    /// output buffer, and what was decoded before stays in the window. The
    /// block's own output can write over it, as in libzstd, where both are
    /// the same memory.
    InOut {
        start: usize,
        end: usize,
    },
}

impl ExtDict<'_> {
    pub(crate) fn len(&self) -> usize {
        match self {
            ExtDict::None => 0,
            ExtDict::Separate(content) => content.len(),
            ExtDict::InOut { start, end } => end - start,
        }
    }
}

/// A segment of the window while streaming, as libzstd's pointers give it:
/// `prefixStart` to `previousDstEnd` for the current one, `virtualStart`
/// and `dictEnd` for the older one. The port keeps which buffer each
/// segment is in, and positions in it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Segment {
    /// libzstd's NULL pointers, or an older segment of no length.
    None,
    /// The content of the dictionary the frame uses.
    Dict,
    /// `start..end` in the output buffer: the context's own (`outBuff`), or
    /// the caller's with [`DParameter::StableOutBuffer`](crate::zstd::DParameter::StableOutBuffer);
    /// for [`DCtx::decompress_continue`](crate::zstd::DCtx::decompress_continue),
    /// the copy of the window in [`Bufferless`].
    Out { start: usize, end: usize },
}

/// The window of a frame decoded with
/// [`DCtx::decompress_continue`](crate::zstd::DCtx::decompress_continue).
/// libzstd's is the caller's earlier output, where it lies, which the
/// caller must keep; safe Rust cannot read it there at the next call, so
/// the port keeps a copy: the older segment, then the current one, from
/// the start of `window` (the stream's [`Segment::Out`] positions), and
/// the last call's address, to tell where segments end as libzstd does.
#[derive(Default)]
pub(crate) struct Bufferless {
    /// The frame was begun with `ZSTD_decompressBegin` or its variants.
    pub(crate) begun: bool,
    /// The copy of the window, its first `end` bytes; room after them for
    /// the next block.
    pub(crate) window: Vec<u8>,
    pub(crate) end: usize,
    /// `previousDstEnd`, in the caller's memory: where its output ended,
    /// or the dictionary's content; 0 for libzstd's NULL.
    pub(crate) caller_end: usize,
}

/// `ZSTD_dStage`: what [`DCtx::decompress_stream`](crate::zstd::DCtx::decompress_stream)
/// reads next within a frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum DStage {
    GetFrameHeaderSize,
    DecodeFrameHeader,
    DecodeBlockHeader,
    DecompressBlock,
    DecompressLastBlock,
    CheckChecksum,
    DecodeSkippableHeader,
    SkipFrame,
}

/// `ZSTD_nextInputType_e`: what [`DCtx::decompress_continue`](crate::zstd::DCtx::decompress_continue)
/// reads next ([`DCtx::next_input_type`](crate::zstd::DCtx::next_input_type)).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NextInputType {
    /// The frame header, or the start of a skippable frame's.
    FrameHeader,
    /// A block header.
    BlockHeader,
    /// A block's content, which is not the last block.
    Block,
    /// The last block's content.
    LastBlock,
    /// The frame's checksum.
    Checksum,
    /// The rest of a skippable frame's header, or its content.
    SkippableFrame,
}

/// `ZSTD_dStreamStage`: where [`DCtx::decompress_stream`](crate::zstd::DCtx::decompress_stream)
/// is between calls.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum DStreamStage {
    Init,
    LoadHeader,
    Read,
    Load,
    Flush,
}

/// The output buffer a streaming call was given, as libzstd's
/// `expectedOutBuffer` keeps it: where it is, its size, and the position.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) struct OutBufferId {
    pub(crate) address: usize,
    pub(crate) size: usize,
    pub(crate) pos: usize,
}

/// `ZSTD_format_e`: whether frames start with the magic number.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Format {
    /// The zstd frame format, with the magic number (`ZSTD_f_zstd1`).
    #[default]
    Zstd1,
    /// Frames without the 4-byte magic number (`ZSTD_f_zstd1_magicless`).
    Zstd1Magicless,
}

/// `ZSTD_FrameType_e`
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum FrameType {
    /// A zstd frame.
    #[default]
    Frame,
    /// A skippable frame, whose content decoders skip.
    Skippable,
}

/// `ZSTD_CONTENTSIZE_UNKNOWN`: the frame header does not give its content
/// size.
pub const CONTENTSIZE_UNKNOWN: u64 = u64::MAX;

/// `ZSTD_FrameHeader`: what a frame header says.
///
/// As in libzstd, an unknown content size is [`CONTENTSIZE_UNKNOWN`]; a
/// header that stores that value itself means the same.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct FrameHeader {
    /// The size of the frame's content, or [`CONTENTSIZE_UNKNOWN`]. For a
    /// skippable frame: the size of its content.
    pub frame_content_size: u64,
    /// The window the frame needs. 0 for a skippable frame.
    pub window_size: u64,
    /// The largest block: the window size, at most 128 KiB.
    pub block_size_max: u32,
    pub frame_type: FrameType,
    /// The size of the header, in bytes.
    pub header_size: u32,
    /// The dictionary the frame needs, 0 for none. For a skippable frame:
    /// the magic number's variant, 0 to 15.
    pub dict_id: u32,
    /// Whether the frame ends with a checksum of its content.
    pub checksum_flag: bool,
}

impl FrameHeader {
    /// The content size, when the header gives it.
    pub fn content_size(&self) -> Option<u64> {
        (self.frame_content_size != CONTENTSIZE_UNKNOWN).then_some(self.frame_content_size)
    }
}

/// `ZSTD_dictUses_e`: for how long the context uses its dictionary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum DictUses {
    /// Until told otherwise.
    Indefinitely,
    /// Not at all (any dictionary is dropped).
    DontUse,
    /// For the next frame only.
    Once,
}

/// `ZSTD_DDictHashSet`: the dictionaries referenced with
/// [`DParameter::RefMultipleDDicts`](crate::zstd::DParameter::RefMultipleDDicts)
/// on, by dictionary ID, in an open-addressing table.
#[derive(Debug)]
pub(crate) struct DDictHashSet {
    /// `ddictPtrTable`; its length (`ddictPtrTableSize`) is a power of 2.
    pub(crate) table: Vec<Option<Arc<DDict>>>,
    /// `ddictPtrCount`
    pub(crate) count: usize,
}

/// `ZSTD_DCtx`, which is also libzstd's `ZSTD_DStream`: a decompression
/// context, reused across frames.
///
/// Create one with [`DCtx::new`] and keep it: it holds tables and buffers
/// that would otherwise be set up for every call. It decodes whole frames
/// in one call ([`DCtx::decompress`]), or streams them in pieces of any
/// size ([`DCtx::decompress_stream`]).
pub struct DCtx {
    pub(crate) ll_tptr: TableRef,
    pub(crate) ml_tptr: TableRef,
    pub(crate) of_tptr: TableRef,
    pub(crate) huf_ptr: TableRef,
    pub(crate) entropy: Box<EntropyDTables>,
    /// `workspace`: for building Huffman tables.
    pub(crate) workspace: Box<HufDecompressWksp>,
    pub(crate) lit_entropy: bool,
    pub(crate) fse_entropy: bool,
    pub(crate) lit_ptr: LitPos,
    pub(crate) lit_size: usize,
    pub(crate) is_frame_decompression: bool,
    pub(crate) ddict_is_cold: bool,
    /// `disableHufAsm`: has no effect in the port, which has no assembly.
    pub(crate) disable_huf_asm: bool,
    pub(crate) lit_buffer: LitPos,
    pub(crate) lit_buffer_end: LitPos,
    pub(crate) lit_buffer_location: LitLocation,
    pub(crate) lit_extra_buffer: Box<[u8]>,

    // The frame.
    pub(crate) f_params: FrameHeader,
    pub(crate) processed_c_size: u64,
    pub(crate) decoded_size: u64,
    pub(crate) validate_checksum: bool,
    pub(crate) xxh_state: Xxh64State,

    // Parameters.
    pub(crate) format: Format,
    pub(crate) max_window_size: usize,
    /// `outBufferMode == ZSTD_bm_stable` (streaming).
    pub(crate) stable_out_buffer: bool,
    pub(crate) force_ignore_checksum: bool,
    pub(crate) ref_multiple_ddicts: bool,
    pub(crate) max_block_size_param: u32,

    // The dictionary.
    pub(crate) dict_id: u32,
    pub(crate) ddict: Option<Arc<DDict>>,
    pub(crate) dict_uses: DictUses,
    pub(crate) ddict_set: Option<DDictHashSet>,

    /// libzstd's `dictEnd` and `previousDstEnd`, as addresses. The port
    /// keeps the window as slices, but libzstd compares these pointers to
    /// tell whether a dictionary is still in the processor's cache
    /// (`ddictIsCold`), which picks the sequence loop, so the port tracks
    /// them too. They are never dereferenced.
    pub(crate) dict_end: usize,
    pub(crate) previous_dst_end: usize,

    // Streaming: the frame, read piece by piece (ZSTD_decompressContinue).
    /// `expected`: how much input the stage needs.
    pub(crate) expected: usize,
    pub(crate) stage: DStage,
    /// `bType`
    pub(crate) b_type: BlockType,
    pub(crate) rle_size: u32,
    pub(crate) header_size: usize,
    pub(crate) header_buffer: [u8; FRAMEHEADER_SIZE_MAX],
    /// The window, as `prefixStart` to `previousDstEnd`.
    pub(crate) stream_prefix: Segment,
    /// The older segment of the window, as `virtualStart` and `dictEnd`.
    pub(crate) stream_ext: Segment,
    /// The dictionary the frame being streamed uses: libzstd points into
    /// it, so the port keeps it alive until the next frame.
    pub(crate) frame_ddict: Option<Arc<DDict>>,
    /// The window of a frame decoded without the streaming buffers.
    pub(crate) bufferless: Bufferless,

    // Streaming: the buffers (ZSTD_decompressStream).
    pub(crate) stream_stage: DStreamStage,
    /// `inBuff`, whose length is `inBuffSize`: a block, gathered when the
    /// input comes in smaller pieces.
    pub(crate) in_buff: Vec<u8>,
    pub(crate) in_pos: usize,
    /// `outBuff`, whose length is `outBuffSize`: the window and the block
    /// being decoded, when the output buffer is not stable.
    pub(crate) out_buff: Vec<u8>,
    pub(crate) out_start: usize,
    pub(crate) out_end: usize,
    /// `lhSize`: how much of the frame header is in `header_buffer`.
    pub(crate) lh_size: usize,
    pub(crate) hostage_byte: bool,
    pub(crate) no_forward_progress: u32,
    pub(crate) expected_out_buffer: OutBufferId,
    pub(crate) oversized_duration: usize,
}

/// `ZSTD_WINDOWLOG_LIMIT_DEFAULT`
pub(crate) const ZSTD_WINDOWLOG_LIMIT_DEFAULT: u32 = 27;
/// `ZSTD_MAXWINDOWSIZE_DEFAULT`
pub(crate) const ZSTD_MAXWINDOWSIZE_DEFAULT: usize = (1 << ZSTD_WINDOWLOG_LIMIT_DEFAULT) + 1;

impl DCtx {
    /// `ZSTD_createDCtx`
    pub fn new() -> Self {
        DCtx {
            ll_tptr: TableRef::Own,
            ml_tptr: TableRef::Own,
            of_tptr: TableRef::Own,
            huf_ptr: TableRef::Own,
            entropy: Box::default(),
            workspace: Box::default(),
            lit_entropy: false,
            fse_entropy: false,
            lit_ptr: LitPos::new(LitBuf::Extra, 0),
            lit_size: 0,
            // ZSTD_initDCtx_internal
            is_frame_decompression: true,
            ddict_is_cold: false,
            disable_huf_asm: false,
            lit_buffer: LitPos::new(LitBuf::Extra, 0),
            lit_buffer_end: LitPos::new(LitBuf::Extra, 0),
            lit_buffer_location: LitLocation::NotInDst,
            lit_extra_buffer: vec![0; ZSTD_LITBUFFEREXTRASIZE + WILDCOPY_OVERLENGTH]
                .into_boxed_slice(),
            f_params: FrameHeader::default(),
            processed_c_size: 0,
            decoded_size: 0,
            validate_checksum: false,
            xxh_state: Xxh64State::new(0),
            format: Format::Zstd1,
            max_window_size: ZSTD_MAXWINDOWSIZE_DEFAULT,
            stable_out_buffer: false,
            force_ignore_checksum: false,
            ref_multiple_ddicts: false,
            max_block_size_param: 0,
            dict_id: 0,
            ddict: None,
            dict_uses: DictUses::DontUse,
            ddict_set: None,
            dict_end: 0,
            previous_dst_end: 0,
            expected: 0,
            stage: DStage::GetFrameHeaderSize,
            b_type: BlockType::Reserved,
            rle_size: 0,
            header_size: 0,
            header_buffer: [0; FRAMEHEADER_SIZE_MAX],
            stream_prefix: Segment::None,
            stream_ext: Segment::None,
            frame_ddict: None,
            bufferless: Bufferless::default(),
            stream_stage: DStreamStage::Init,
            in_buff: Vec::new(),
            in_pos: 0,
            out_buff: Vec::new(),
            out_start: 0,
            out_end: 0,
            lh_size: 0,
            hostage_byte: false,
            no_forward_progress: 0,
            expected_out_buffer: OutBufferId::default(),
            oversized_duration: 0,
        }
    }

    /// The entropy part of `ZSTD_decompressBegin`: no tables from earlier
    /// blocks, and the starting repeat offsets.
    pub(crate) fn reset_entropy(&mut self) {
        // libzstd sets only the descriptor; the cells are rebuilt before use.
        self.entropy.huf_table.desc = HufDTable::new_desc(ZSTD_HUFFDTABLE_CAPACITY_LOG);
        self.lit_entropy = false;
        self.fse_entropy = false;
        self.entropy.rep = REP_START_VALUE;
        self.ll_tptr = TableRef::Own;
        self.ml_tptr = TableRef::Own;
        self.of_tptr = TableRef::Own;
        self.huf_ptr = TableRef::Own;
    }
}

impl Default for DCtx {
    fn default() -> Self {
        DCtx::new()
    }
}

impl std::fmt::Debug for DCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DCtx")
            .field("format", &self.format)
            .field("max_window_size", &self.max_window_size)
            .field("dict_id", &self.dict_id)
            .finish_non_exhaustive()
    }
}
