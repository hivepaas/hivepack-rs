//! The LZ4 frame format (`.lz4` files): `lz4frame.c`'s decoding half and
//! what it shares with the encoder.

use core::fmt;

use crate::lz4::lz4::{self, DecodeError, DictDirective, KB};
use crate::lz4::xxhash::{Xxh32, xxh32};

/*-************************************
 *  Constants
 **************************************/

/// `LZ4F_VERSION`.
pub const VERSION: u32 = 100;

/// `LZ4F_MAGICNUMBER`.
pub const MAGICNUMBER: u32 = 0x184D_2204;
/// `LZ4F_MAGIC_SKIPPABLE_START`: skippable frames have magic numbers from
/// this to this + 15.
pub const MAGIC_SKIPPABLE_START: u32 = 0x184D_2A50;
/// `LZ4F_MIN_SIZE_TO_KNOW_HEADER_LENGTH`.
pub const MIN_SIZE_TO_KNOW_HEADER_LENGTH: usize = 5;
/// `LZ4F_HEADER_SIZE_MIN`.
pub const HEADER_SIZE_MIN: usize = 7;
/// `LZ4F_HEADER_SIZE_MAX`.
pub const HEADER_SIZE_MAX: usize = 19;
/// `LZ4F_BLOCK_HEADER_SIZE`: a block's size, and its compressed flag.
pub const BLOCK_HEADER_SIZE: usize = 4;
/// `LZ4F_BLOCK_CHECKSUM_SIZE`.
pub const BLOCK_CHECKSUM_SIZE: usize = 4;
/// `LZ4F_CONTENT_CHECKSUM_SIZE`.
pub const CONTENT_CHECKSUM_SIZE: usize = 4;

const MIN_FH_SIZE: usize = HEADER_SIZE_MIN;
const MAX_FH_SIZE: usize = HEADER_SIZE_MAX;
const BH_SIZE: usize = BLOCK_HEADER_SIZE;
const BF_SIZE: usize = BLOCK_CHECKSUM_SIZE;

const BLOCKUNCOMPRESSED_FLAG: u32 = 0x8000_0000;

const GB: usize = 1 << 30;

fn read_le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn read_le64(bytes: &[u8], at: usize) -> u64 {
    let mut word = [0; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(word)
}

/*-************************************
 *  Error management
 **************************************/

/// `LZ4F_errorCodes`, with the same numbers.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum Error {
    Generic = 1,
    MaxBlockSizeInvalid = 2,
    BlockModeInvalid = 3,
    ParameterInvalid = 4,
    CompressionLevelInvalid = 5,
    HeaderVersionWrong = 6,
    BlockChecksumInvalid = 7,
    ReservedFlagSet = 8,
    AllocationFailed = 9,
    SrcSizeTooLarge = 10,
    DstMaxSizeTooSmall = 11,
    FrameHeaderIncomplete = 12,
    FrameTypeUnknown = 13,
    FrameSizeWrong = 14,
    SrcPtrWrong = 15,
    DecompressionFailed = 16,
    HeaderChecksumInvalid = 17,
    ContentChecksumInvalid = 18,
    FrameDecodingAlreadyStarted = 19,
    CompressionStateUninitialized = 20,
    ParameterNull = 21,
    IoWrite = 22,
    IoRead = 23,
}

impl Error {
    /// The error's number in `LZ4F_errorCodes`. liblz4 returns it negated,
    /// as a `size_t`.
    pub fn number(self) -> u32 {
        self as u32
    }

    /// `LZ4F_getErrorName()`: `"ERROR_frameType_unknown"` and so on.
    pub fn name(self) -> &'static str {
        match self {
            Error::Generic => "ERROR_GENERIC",
            Error::MaxBlockSizeInvalid => "ERROR_maxBlockSize_invalid",
            Error::BlockModeInvalid => "ERROR_blockMode_invalid",
            Error::ParameterInvalid => "ERROR_parameter_invalid",
            Error::CompressionLevelInvalid => "ERROR_compressionLevel_invalid",
            Error::HeaderVersionWrong => "ERROR_headerVersion_wrong",
            Error::BlockChecksumInvalid => "ERROR_blockChecksum_invalid",
            Error::ReservedFlagSet => "ERROR_reservedFlag_set",
            Error::AllocationFailed => "ERROR_allocation_failed",
            Error::SrcSizeTooLarge => "ERROR_srcSize_tooLarge",
            Error::DstMaxSizeTooSmall => "ERROR_dstMaxSize_tooSmall",
            Error::FrameHeaderIncomplete => "ERROR_frameHeader_incomplete",
            Error::FrameTypeUnknown => "ERROR_frameType_unknown",
            Error::FrameSizeWrong => "ERROR_frameSize_wrong",
            Error::SrcPtrWrong => "ERROR_srcPtr_wrong",
            Error::DecompressionFailed => "ERROR_decompressionFailed",
            Error::HeaderChecksumInvalid => "ERROR_headerChecksum_invalid",
            Error::ContentChecksumInvalid => "ERROR_contentChecksum_invalid",
            Error::FrameDecodingAlreadyStarted => "ERROR_frameDecoding_alreadyStarted",
            Error::CompressionStateUninitialized => "ERROR_compressionState_uninitialized",
            Error::ParameterNull => "ERROR_parameter_null",
            Error::IoWrite => "ERROR_io_write",
            Error::IoRead => "ERROR_io_read",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl core::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

/// `LZ4F_getVersion()`.
pub fn get_version() -> u32 {
    VERSION
}

/*-************************************
 *  Frame parameters
 **************************************/

/// `LZ4F_blockSizeID_t`: the largest block of a frame.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub enum BlockSizeId {
    /// `LZ4F_default`: 64 KB.
    #[default]
    Default = 0,
    Max64Kb = 4,
    Max256Kb = 5,
    Max1Mb = 6,
    Max4Mb = 7,
}

impl BlockSizeId {
    /// The ID a frame header gives, 4 to 7.
    fn from_header(id: u32) -> Self {
        match id {
            4 => BlockSizeId::Max64Kb,
            5 => BlockSizeId::Max256Kb,
            6 => BlockSizeId::Max1Mb,
            _ => BlockSizeId::Max4Mb,
        }
    }
}

/// `LZ4F_getBlockSize()`: the size of the largest block, in bytes.
pub fn get_block_size(block_size_id: BlockSizeId) -> usize {
    match block_size_id {
        BlockSizeId::Default | BlockSizeId::Max64Kb => 64 * KB,
        BlockSizeId::Max256Kb => 256 * KB,
        BlockSizeId::Max1Mb => 1024 * KB,
        BlockSizeId::Max4Mb => 4096 * KB,
    }
}

/// `LZ4F_blockMode_t`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub enum BlockMode {
    /// `LZ4F_blockLinked`: each block can refer to the 64 KB before it.
    #[default]
    Linked = 0,
    /// `LZ4F_blockIndependent`.
    Independent = 1,
}

/// `LZ4F_frameType_t`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub enum FrameType {
    /// `LZ4F_frame`.
    #[default]
    Frame = 0,
    /// `LZ4F_skippableFrame`.
    SkippableFrame = 1,
}

/// `LZ4F_frameInfo_t`: what a frame header says.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct FrameInfo {
    /// `blockSizeID`.
    pub block_size_id: BlockSizeId,
    /// `blockMode`.
    pub block_mode: BlockMode,
    /// `contentChecksumFlag`: a checksum of the content ends the frame.
    pub content_checksum: bool,
    /// `frameType`.
    pub frame_type: FrameType,
    /// `contentSize`: the size of the content, 0 when unknown. For a
    /// skippable frame, the size of its data.
    pub content_size: u64,
    /// `dictID`: the dictionary's ID, 0 when there is none.
    pub dict_id: u32,
    /// `blockChecksumFlag`: each block has a checksum.
    pub block_checksum: bool,
}

/// `LZ4F_decompressOptions_t`.
///
/// Differs from liblz4: there is no `stableDst`, the promise that the
/// output stays where it was between calls. The context keeps the history
/// it needs in its own buffer at the end of each call, as liblz4 does
/// without the promise.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct DecompressOptions {
    /// `skipChecksums`: no content checksum and no checksum of the
    /// uncompressed blocks is computed or checked, for the rest of the
    /// frame once set. The checksums of the compressed blocks still are,
    /// as liblz4 checks them.
    pub skip_checksums: bool,
}

/// The input of a call: `src[pos..]` is what may be read.
#[derive(Debug)]
pub struct InBuffer<'a> {
    pub src: &'a [u8],
    /// How much of `src` has been read. Each call moves it forward.
    pub pos: usize,
}

impl<'a> InBuffer<'a> {
    /// All of `src`, from its start.
    pub fn new(src: &'a [u8]) -> Self {
        InBuffer { src, pos: 0 }
    }
}

/// The output of a call: `dst[pos..]` is the space it may write.
#[derive(Debug)]
pub struct OutBuffer<'a> {
    pub dst: &'a mut [u8],
    /// How much of `dst` has been written. Each call moves it forward.
    pub pos: usize,
}

impl<'a> OutBuffer<'a> {
    /// All of `dst`, from its start.
    pub fn new(dst: &'a mut [u8]) -> Self {
        OutBuffer { dst, pos: 0 }
    }
}

/// `LZ4F_headerChecksum`.
fn header_checksum(header: &[u8]) -> u8 {
    (xxh32(header, 0) >> 8) as u8
}

/*-***************************************************
 *   Frame Decompression
 *****************************************************/

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum DStage {
    GetFrameHeader = 0,
    StoreFrameHeader,
    Init,
    GetBlockHeader,
    StoreBlockHeader,
    CopyDirect,
    GetBlockChecksum,
    GetCBlock,
    StoreCBlock,
    FlushOut,
    GetSuffix,
    StoreSuffix,
    GetSFrameSize,
    StoreSFrameSize,
    SkipSkippable,
}

/// Where `dctx->dict` points.
///
/// Differs from liblz4: a pointer becomes the buffer it is in, and the
/// position in it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DictAt {
    /// `NULL`.
    Null,
    /// The start of the dictionary of `LZ4F_decompress_usingDict`, which
    /// the context keeps a copy of.
    User,
    /// `tmpOutBuffer`.
    Tmp,
    /// This position in the output of the call.
    Dst(usize),
    /// A position in the output of an earlier call: the history is never
    /// read from there, as it is moved into `tmpOutBuffer` at the end of
    /// each call while blocks may follow.
    Gone,
}

/// The history a block is decoded with: the arguments of
/// `LZ4_decompress_safe_usingDict` after the output.
enum BlockDict<'a> {
    /// No dictionary, or an empty one.
    None,
    /// The `n` bytes before the output, in its buffer.
    Prefix(usize),
    /// A dictionary apart from the output.
    Ext(&'a [u8]),
}

/// `LZ4_decompress_safe_usingDict`, with the dictionary as `BlockDict`.
fn decompress_using_dict(
    src: &[u8],
    out: &mut [u8],
    start: usize,
    dict: BlockDict<'_>,
) -> core::result::Result<usize, DecodeError> {
    match dict {
        BlockDict::None | BlockDict::Prefix(0) => {
            lz4::decompress_generic(src, out, start, false, DictDirective::NoDict, start, &[])
        }
        BlockDict::Ext([]) => {
            lz4::decompress_generic(src, out, start, false, DictDirective::NoDict, start, &[])
        }
        BlockDict::Prefix(size) if size >= 64 * KB - 1 => lz4::decompress_generic(
            src,
            out,
            start,
            false,
            DictDirective::WithPrefix64k,
            start - size.min(64 * KB),
            &[],
        ),
        BlockDict::Prefix(size) => lz4::decompress_generic(
            src,
            out,
            start,
            false,
            DictDirective::NoDict,
            start - size,
            &[],
        ),
        BlockDict::Ext(dict) => lz4::decompress_generic(
            src,
            out,
            start,
            false,
            DictDirective::UsingExtDict,
            start,
            dict,
        ),
    }
}

/// Where the compressed block being decoded is.
#[derive(Clone, Copy)]
enum SelectedIn {
    /// In the input of the call, from this position.
    Src(usize),
    /// In `tmpIn`.
    TmpIn,
    /// In `header`, from this position.
    Header(usize),
}

/// `LZ4F_dctx`: decompresses frames, in as many calls as the input and
/// output need.
///
/// Differs from liblz4: after an error, every call returns it again until
/// [`DecompressionContext::reset`], where liblz4 says the context is not
/// resumable and its state undefined.
#[derive(Clone, Debug)]
pub struct DecompressionContext {
    frame_info: FrameInfo,
    version: u32,
    d_stage: DStage,
    frame_remaining_size: u64,
    max_block_size: usize,
    max_buffer_size: usize,
    tmp_in: Vec<u8>,
    tmp_in_size: usize,
    tmp_in_target: usize,
    tmp_out_buffer: Vec<u8>,
    dict: DictAt,
    dict_size: usize,
    /// The dictionary given to `decompress_using_dict` (`DictAt::User`).
    user_dict: Vec<u8>,
    /// `tmpOut`, as a position in `tmp_out_buffer`.
    tmp_out: usize,
    tmp_out_size: usize,
    tmp_out_start: usize,
    xxh: Xxh32,
    block_checksum: Xxh32,
    skip_checksum: bool,
    header: [u8; HEADER_SIZE_MAX],
    error: Option<Error>,
}

impl Default for DecompressionContext {
    fn default() -> Self {
        DecompressionContext::new()
    }
}

impl DecompressionContext {
    /// `LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION)`.
    pub fn new() -> Self {
        DecompressionContext {
            frame_info: FrameInfo::default(),
            version: VERSION,
            d_stage: DStage::GetFrameHeader,
            frame_remaining_size: 0,
            max_block_size: 0,
            max_buffer_size: 0,
            tmp_in: Vec::new(),
            tmp_in_size: 0,
            tmp_in_target: 0,
            tmp_out_buffer: Vec::new(),
            dict: DictAt::Null,
            dict_size: 0,
            user_dict: Vec::new(),
            tmp_out: 0,
            tmp_out_size: 0,
            tmp_out_start: 0,
            xxh: Xxh32::new(0),
            block_checksum: Xxh32::new(0),
            skip_checksum: false,
            header: [0; HEADER_SIZE_MAX],
            error: None,
        }
    }

    /// The version the context was made for, [`VERSION`].
    pub fn version(&self) -> u32 {
        self.version
    }

    /// `LZ4F_resetDecompressionContext`: ready for a new frame, whatever
    /// state it was in, an error included. The buffers are kept.
    pub fn reset(&mut self) {
        self.d_stage = DStage::GetFrameHeader;
        self.dict = DictAt::Null;
        self.dict_size = 0;
        self.skip_checksum = false;
        self.frame_remaining_size = 0;
        self.error = None;
    }

    /// `LZ4F_decodeHeader`: `src` is the start of a frame, `from_header`
    /// whether it is `dctx->header`. Returns the bytes read of it.
    fn decode_header(&mut self, src: &[u8], from_header: bool) -> Result<usize> {
        let src_size = src.len();
        // The frame header must be decoded to get the frame info.
        if src_size < MIN_FH_SIZE {
            return Err(Error::FrameHeaderIncomplete);
        }
        self.frame_info = FrameInfo::default();

        // Special case: skippable frames.
        if read_le32(src, 0) & 0xFFFF_FFF0 == MAGIC_SKIPPABLE_START {
            self.frame_info.frame_type = FrameType::SkippableFrame;
            if from_header {
                self.tmp_in_size = src_size;
                self.tmp_in_target = 8;
                self.d_stage = DStage::StoreSFrameSize;
                return Ok(src_size);
            }
            self.d_stage = DStage::GetSFrameSize;
            return Ok(4);
        }

        // Control the magic number.
        if read_le32(src, 0) != MAGICNUMBER {
            return Err(Error::FrameTypeUnknown);
        }
        self.frame_info.frame_type = FrameType::Frame;

        // Flags.
        let flg = u32::from(src[4]);
        let version = (flg >> 6) & 0x03;
        let block_checksum_flag = (flg >> 4) & 1;
        let block_mode = (flg >> 5) & 1;
        let content_size_flag = (flg >> 3) & 1;
        let content_checksum_flag = (flg >> 2) & 1;
        let dict_id_flag = flg & 1;
        // Validate.
        if (flg >> 1) & 1 != 0 {
            // Reserved bit.
            return Err(Error::ReservedFlagSet);
        }
        if version != 1 {
            // The version number: the only supported value.
            return Err(Error::HeaderVersionWrong);
        }

        // Frame header size.
        let frame_header_size = MIN_FH_SIZE
            + if content_size_flag != 0 { 8 } else { 0 }
            + if dict_id_flag != 0 { 4 } else { 0 };

        if src_size < frame_header_size {
            // Not enough input to fully decode the frame header.
            if !from_header {
                self.header[..src_size].copy_from_slice(src);
            }
            self.tmp_in_size = src_size;
            self.tmp_in_target = frame_header_size;
            self.d_stage = DStage::StoreFrameHeader;
            return Ok(src_size);
        }

        let bd = u32::from(src[5]);
        let block_size_id = (bd >> 4) & 0x07;
        // Validate.
        if (bd >> 7) & 1 != 0 {
            // Reserved bit.
            return Err(Error::ReservedFlagSet);
        }
        if block_size_id < 4 {
            // 4-7 are the only supported values for the time being.
            return Err(Error::MaxBlockSizeInvalid);
        }
        if bd & 0x0F != 0 {
            // Reserved bits.
            return Err(Error::ReservedFlagSet);
        }

        // Check the header.
        let hc = header_checksum(&src[4..frame_header_size - 1]);
        if hc != src[frame_header_size - 1] {
            return Err(Error::HeaderChecksumInvalid);
        }

        // Save.
        self.frame_info.block_mode = if block_mode != 0 {
            BlockMode::Independent
        } else {
            BlockMode::Linked
        };
        self.frame_info.block_checksum = block_checksum_flag != 0;
        self.frame_info.content_checksum = content_checksum_flag != 0;
        self.frame_info.block_size_id = BlockSizeId::from_header(block_size_id);
        self.max_block_size = get_block_size(self.frame_info.block_size_id);
        if content_size_flag != 0 {
            self.frame_info.content_size = read_le64(src, 6);
            self.frame_remaining_size = self.frame_info.content_size;
        }
        if dict_id_flag != 0 {
            self.frame_info.dict_id = read_le32(src, frame_header_size - 5);
        }

        self.d_stage = DStage::Init;
        Ok(frame_header_size)
    }

    /// `LZ4F_getFrameInfo`: the frame's parameters, and a hint of the input
    /// the next call wants.
    ///
    /// Before decoding has started, the frame header must be all in the
    /// input, and is read from it (the position moves past it): decoding
    /// goes on from there. After, nothing is read; once the header is half
    /// read, it is [`Error::FrameDecodingAlreadyStarted`].
    pub fn get_frame_info(&mut self, input: &mut InBuffer<'_>) -> Result<(FrameInfo, usize)> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if self.d_stage > DStage::StoreFrameHeader {
            // The frame info is already decoded. The hint is what
            // LZ4F_decompress gives with no input and no output.
            let info = self.frame_info;
            let hint = self
                .decompress_impl(None, &[], DecompressOptions::default())
                .map(|(_, _, hint)| hint)?;
            return Ok((info, hint));
        }
        if self.d_stage == DStage::StoreFrameHeader {
            // Frame decoding already started, in the middle of the header.
            return Err(Error::FrameDecodingAlreadyStarted);
        }
        let src = input.src.get(input.pos..).unwrap_or_default();
        let h_size = header_size(src)?;
        if src.len() < h_size {
            return Err(Error::FrameHeaderIncomplete);
        }
        let read = self.decode_header(&src[..h_size], false)?;
        input.pos += read;
        // The hint: a block header.
        Ok((self.frame_info, BH_SIZE))
    }

    /// `LZ4F_updateDict`: the `dst_size` bytes just written at `dst_ptr` in
    /// `dst` join the history (linked blocks only).
    fn update_dict(&mut self, dst: &[u8], dst_ptr: usize, dst_size: usize, within_tmp: bool) {
        if self.dict_size == 0 {
            // Will lead to prefix mode.
            self.dict = DictAt::Dst(dst_ptr);
        }

        if let DictAt::Dst(start) = self.dict
            && start + self.dict_size == dst_ptr
        {
            // Prefix mode: everything within the output.
            self.dict_size += dst_size;
            return;
        }

        if dst_ptr + dst_size >= 64 * KB {
            // The history in the output is large enough to become the
            // dictionary.
            self.dict = DictAt::Dst(0);
            self.dict_size = dst_ptr + dst_size;
            return;
        }

        // The output does not hold the whole useful history (64 KB), so it
        // must be saved within tmpOutBuffer.
        debug_assert!(dst_size < 64 * KB);

        if within_tmp && self.dict == DictAt::Tmp {
            // Continue the history within tmpOutBuffer: what was written is
            // what follows the dictionary there, so it just extends it.
            debug_assert_eq!(self.dict_size, self.tmp_out + self.tmp_out_start);
            self.dict_size += dst_size;
            return;
        }

        if within_tmp {
            // Copy the relevant part of the dictionary in front of tmpOut,
            // within tmpOutBuffer.
            let preserve_size = self.tmp_out;
            let mut copy_size = (64 * KB).saturating_sub(self.tmp_out_size);
            copy_size = copy_size.min(preserve_size);
            // liblz4 points before the output when the block was flushed in
            // earlier calls too, and then copies nothing.
            let old_dict_end = self.dict_size.wrapping_sub(self.tmp_out_start);
            self.copy_dict_into_tmp(
                dst,
                old_dict_end.wrapping_sub(copy_size),
                preserve_size - copy_size,
                copy_size,
            );
            self.dict = DictAt::Tmp;
            self.dict_size = preserve_size + self.tmp_out_start + dst_size;
            return;
        }

        if self.dict == DictAt::Tmp {
            // Copy the output into tmp to complete the dictionary.
            if self.dict_size + dst_size > self.max_buffer_size {
                // The tmp buffer is not large enough.
                let preserve_size = 64 * KB - dst_size;
                let from = self.dict_size - preserve_size;
                self.tmp_out_buffer
                    .copy_within(from..from + preserve_size, 0);
                self.dict_size = preserve_size;
            }
            let at = self.dict_size;
            self.tmp_out_buffer[at..at + dst_size]
                .copy_from_slice(&dst[dst_ptr..dst_ptr + dst_size]);
            self.dict_size += dst_size;
            return;
        }

        // Join the dictionary and the output into tmp.
        let preserve_size = (64 * KB - dst_size).min(self.dict_size);
        self.copy_dict_into_tmp(dst, self.dict_size - preserve_size, 0, preserve_size);
        self.tmp_out_buffer[preserve_size..preserve_size + dst_size]
            .copy_from_slice(&dst[dst_ptr..dst_ptr + dst_size]);
        self.dict = DictAt::Tmp;
        self.dict_size = preserve_size + dst_size;
    }

    /// `memcpy(tmpOutBuffer + to, dict + from, len)`, from a dictionary
    /// that is not in tmpOutBuffer itself (or is, before `to`).
    fn copy_dict_into_tmp(&mut self, dst: &[u8], from: usize, to: usize, len: usize) {
        if len == 0 {
            return;
        }
        match self.dict {
            DictAt::User => {
                self.tmp_out_buffer[to..to + len].copy_from_slice(&self.user_dict[from..from + len])
            }
            DictAt::Dst(start) => {
                self.tmp_out_buffer[to..to + len]
                    .copy_from_slice(&dst[start + from..start + from + len]);
            }
            DictAt::Tmp => self.tmp_out_buffer.copy_within(from..from + len, to),
            // An empty history: nothing to copy.
            DictAt::Null | DictAt::Gone => debug_assert_eq!(len, 0),
        }
    }

    /// `LZ4F_decompress`: decodes what it can of the input into the
    /// output, moving their positions past what it read and wrote, and
    /// returns a hint of the input the next call wants: the rest of the
    /// current block and the header of the next. 0 means the frame is
    /// complete, and the context is ready for another.
    ///
    /// After an error, nothing has been read or written, as liblz4 says
    /// (though the output may hold bytes of blocks the call decoded).
    pub fn decompress(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
        options: DecompressOptions,
    ) -> Result<usize> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let src = input.src.get(input.pos..).unwrap_or_default();
        let dst = output.dst.get_mut(output.pos..).unwrap_or_default();
        let (read, written, hint) = self.decompress_impl(Some(dst), src, options)?;
        input.pos += read;
        output.pos += written;
        Ok(hint)
    }

    /// `LZ4F_decompress_usingDict`: as [`decompress`](Self::decompress),
    /// with `dict` as the history of the frame's first block (and of each
    /// block, when they are independent). It is taken until the frame's
    /// header is read; the context keeps a copy.
    pub fn decompress_using_dict(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
        dict: &[u8],
        options: DecompressOptions,
    ) -> Result<usize> {
        if self.error.is_none() && self.d_stage <= DStage::Init {
            self.user_dict.clear();
            if self.user_dict.try_reserve_exact(dict.len()).is_err() {
                return Err(Error::AllocationFailed);
            }
            self.user_dict.extend_from_slice(dict);
            self.dict = DictAt::User;
            self.dict_size = dict.len();
        }
        self.decompress(output, input, options)
    }

    /// The history a block is decoded with: where it is, and its start and
    /// size there, with liblz4's limit of 1 GB on `dictSize`.
    fn block_dict(&self) -> (DictAt, usize, usize) {
        let mut start = 0;
        let mut size = self.dict_size;
        if self.dict != DictAt::Null && size > GB {
            // Overflow control: liblz4's dictSize is an int, avoid
            // truncation and sign issues.
            start = size - 64 * KB;
            size = 64 * KB;
        }
        (self.dict, start, size)
    }

    fn decompress_impl(
        &mut self,
        mut dst: Option<&mut [u8]>,
        src: &[u8],
        options: DecompressOptions,
    ) -> Result<(usize, usize, usize)> {
        let result = self.decompress_stages(&mut dst, src, options);
        if let Err(error) = result {
            self.error = Some(error);
        }
        result
    }

    fn decompress_stages(
        &mut self,
        dst: &mut Option<&mut [u8]>,
        src: &[u8],
        options: DecompressOptions,
    ) -> Result<(usize, usize, usize)> {
        let src_end = src.len();
        let mut src_ptr = 0usize;
        let dst_end = dst.as_ref().map_or(0, |dst| dst.len());
        let mut dst_ptr = 0usize;
        let mut selected_in = SelectedIn::Src(0);
        let mut do_another_stage = true;
        let mut next_src_size_hint = 1;

        // Once set, disabled for the remainder of the frame.
        self.skip_checksum |= options.skip_checksums;

        // Behaves as a state machine.
        while do_another_stage {
            match self.d_stage {
                DStage::GetFrameHeader => {
                    if src_end - src_ptr >= MAX_FH_SIZE {
                        // Enough to decode: shortcut. Updates the stage.
                        let h_size = self.decode_header(&src[src_ptr..], false)?;
                        src_ptr += h_size;
                        continue;
                    }
                    self.tmp_in_size = 0;
                    if src_end == src_ptr {
                        // 0-size input.
                        return Ok((0, 0, MIN_FH_SIZE));
                    }
                    // The minimum size to decode the header.
                    self.tmp_in_target = MIN_FH_SIZE;
                    self.d_stage = DStage::StoreFrameHeader;
                    // Fall through.
                }

                DStage::StoreFrameHeader => {
                    let size_to_copy =
                        (self.tmp_in_target - self.tmp_in_size).min(src_end - src_ptr);
                    self.header[self.tmp_in_size..self.tmp_in_size + size_to_copy]
                        .copy_from_slice(&src[src_ptr..src_ptr + size_to_copy]);
                    self.tmp_in_size += size_to_copy;
                    src_ptr += size_to_copy;
                    if self.tmp_in_size < self.tmp_in_target {
                        // The rest of the header, and the next block's.
                        next_src_size_hint = (self.tmp_in_target - self.tmp_in_size) + BH_SIZE;
                        // Not enough input: ask for more.
                        do_another_stage = false;
                        continue;
                    }
                    // Updates the stage.
                    let header = self.header;
                    self.decode_header(&header[..self.tmp_in_target], true)?;
                }

                DStage::Init => {
                    if self.frame_info.content_checksum {
                        self.xxh.reset(0);
                    }
                    // Internal buffers allocation.
                    let buffer_needed = self.max_block_size
                        + if self.frame_info.block_mode == BlockMode::Linked {
                            128 * KB
                        } else {
                            0
                        };
                    if buffer_needed > self.max_buffer_size {
                        // The tmp buffers are too small. The allocation
                        // will be tried again on the next entry.
                        self.max_buffer_size = 0;
                        if !reallocate(&mut self.tmp_in, self.max_block_size + BF_SIZE)
                            || !reallocate(&mut self.tmp_out_buffer, buffer_needed)
                        {
                            return Err(Error::AllocationFailed);
                        }
                        self.max_buffer_size = buffer_needed;
                    }
                    self.tmp_in_size = 0;
                    self.tmp_in_target = 0;
                    self.tmp_out = 0;
                    self.tmp_out_start = 0;
                    self.tmp_out_size = 0;

                    self.d_stage = DStage::GetBlockHeader;
                    // Fall through.
                }

                DStage::GetBlockHeader | DStage::StoreBlockHeader => {
                    if self.d_stage == DStage::GetBlockHeader {
                        if src_end - src_ptr >= BH_SIZE {
                            selected_in = SelectedIn::Src(src_ptr);
                            src_ptr += BH_SIZE;
                        } else {
                            // Not enough input to read the cBlockSize field.
                            self.tmp_in_size = 0;
                            self.d_stage = DStage::StoreBlockHeader;
                        }
                    }

                    if self.d_stage == DStage::StoreBlockHeader {
                        let remaining_input = src_end - src_ptr;
                        let wanted_data = BH_SIZE - self.tmp_in_size;
                        let size_to_copy = wanted_data.min(remaining_input);
                        self.tmp_in[self.tmp_in_size..self.tmp_in_size + size_to_copy]
                            .copy_from_slice(&src[src_ptr..src_ptr + size_to_copy]);
                        src_ptr += size_to_copy;
                        self.tmp_in_size += size_to_copy;

                        if self.tmp_in_size < BH_SIZE {
                            // Not enough input for cBlockSize.
                            next_src_size_hint = BH_SIZE - self.tmp_in_size;
                            do_another_stage = false;
                            continue;
                        }
                        selected_in = SelectedIn::TmpIn;
                    }

                    // Decode the block header.
                    let block_header = match selected_in {
                        SelectedIn::Src(at) => read_le32(src, at),
                        SelectedIn::TmpIn | SelectedIn::Header(_) => read_le32(&self.tmp_in, 0),
                    };
                    let next_c_block_size = (block_header & 0x7FFF_FFFF) as usize;
                    let crc_size = if self.frame_info.block_checksum {
                        BF_SIZE
                    } else {
                        0
                    };
                    if block_header == 0 {
                        // The frame's end: no more blocks.
                        self.d_stage = DStage::GetSuffix;
                        continue;
                    }
                    if next_c_block_size > self.max_block_size {
                        return Err(Error::MaxBlockSizeInvalid);
                    }
                    if block_header & BLOCKUNCOMPRESSED_FLAG != 0 {
                        // The next block is uncompressed.
                        self.tmp_in_target = next_c_block_size;
                        if self.frame_info.block_checksum {
                            self.block_checksum.reset(0);
                        }
                        self.d_stage = DStage::CopyDirect;
                        continue;
                    }
                    // The next block is a compressed block.
                    self.tmp_in_target = next_c_block_size + crc_size;
                    self.d_stage = DStage::GetCBlock;
                    if dst_ptr == dst_end || src_ptr == src_end {
                        next_src_size_hint = BH_SIZE + next_c_block_size + crc_size;
                        do_another_stage = false;
                    }
                }

                DStage::CopyDirect => {
                    // An uncompressed block.
                    let size_to_copy;
                    if let Some(out) = dst.as_deref_mut() {
                        let min_buff_size = (src_end - src_ptr).min(dst_end - dst_ptr);
                        size_to_copy = self.tmp_in_target.min(min_buff_size);
                        out[dst_ptr..dst_ptr + size_to_copy]
                            .copy_from_slice(&src[src_ptr..src_ptr + size_to_copy]);
                        if !self.skip_checksum {
                            if self.frame_info.block_checksum {
                                self.block_checksum
                                    .update(&src[src_ptr..src_ptr + size_to_copy]);
                            }
                            if self.frame_info.content_checksum {
                                self.xxh.update(&src[src_ptr..src_ptr + size_to_copy]);
                            }
                        }
                        if self.frame_info.content_size != 0 {
                            self.frame_remaining_size =
                                self.frame_remaining_size.wrapping_sub(size_to_copy as u64);
                        }

                        // History management (linked blocks only).
                        if self.frame_info.block_mode == BlockMode::Linked {
                            self.update_dict(out, dst_ptr, size_to_copy, false);
                        }
                        src_ptr += size_to_copy;
                        dst_ptr += size_to_copy;
                    } else {
                        size_to_copy = 0;
                    }
                    if size_to_copy == self.tmp_in_target {
                        // All done.
                        if self.frame_info.block_checksum {
                            self.tmp_in_size = 0;
                            self.d_stage = DStage::GetBlockChecksum;
                        } else {
                            // A new block.
                            self.d_stage = DStage::GetBlockHeader;
                        }
                        continue;
                    }
                    // More to copy.
                    self.tmp_in_target -= size_to_copy;
                    next_src_size_hint = self.tmp_in_target
                        + if self.frame_info.block_checksum {
                            BF_SIZE
                        } else {
                            0
                        }
                        + BH_SIZE;
                    do_another_stage = false;
                }

                DStage::GetBlockChecksum => {
                    // The checksum of the uncompressed block just copied.
                    let crc_src;
                    if src_end - src_ptr >= 4 && self.tmp_in_size == 0 {
                        crc_src = read_le32(src, src_ptr);
                        src_ptr += 4;
                    } else {
                        let still_to_copy = 4 - self.tmp_in_size;
                        let size_to_copy = still_to_copy.min(src_end - src_ptr);
                        self.header[self.tmp_in_size..self.tmp_in_size + size_to_copy]
                            .copy_from_slice(&src[src_ptr..src_ptr + size_to_copy]);
                        self.tmp_in_size += size_to_copy;
                        src_ptr += size_to_copy;
                        if self.tmp_in_size < 4 {
                            // All input consumed.
                            do_another_stage = false;
                            continue;
                        }
                        crc_src = read_le32(&self.header, 0);
                    }
                    if !self.skip_checksum {
                        let calc_crc = self.block_checksum.digest();
                        if crc_src != calc_crc {
                            return Err(Error::BlockChecksumInvalid);
                        }
                    }
                    // A new block.
                    self.d_stage = DStage::GetBlockHeader;
                }

                DStage::GetCBlock | DStage::StoreCBlock => {
                    if self.d_stage == DStage::GetCBlock {
                        if src_end - src_ptr < self.tmp_in_target {
                            self.tmp_in_size = 0;
                            self.d_stage = DStage::StoreCBlock;
                            continue;
                        }
                        // The input is large enough to read the full block
                        // directly.
                        selected_in = SelectedIn::Src(src_ptr);
                        src_ptr += self.tmp_in_target;
                    } else {
                        let wanted_data = self.tmp_in_target - self.tmp_in_size;
                        let input_left = src_end - src_ptr;
                        let size_to_copy = wanted_data.min(input_left);
                        self.tmp_in[self.tmp_in_size..self.tmp_in_size + size_to_copy]
                            .copy_from_slice(&src[src_ptr..src_ptr + size_to_copy]);
                        self.tmp_in_size += size_to_copy;
                        src_ptr += size_to_copy;
                        if self.tmp_in_size < self.tmp_in_target {
                            // Need more input.
                            next_src_size_hint = (self.tmp_in_target - self.tmp_in_size)
                                + if self.frame_info.block_checksum {
                                    BF_SIZE
                                } else {
                                    0
                                }
                                + BH_SIZE;
                            do_another_stage = false;
                            continue;
                        }
                        selected_in = SelectedIn::TmpIn;
                    }

                    // At this stage, the input is large enough to decode a
                    // block. First, decode and control the block checksum
                    // if it exists.
                    if self.frame_info.block_checksum {
                        debug_assert!(self.tmp_in_target >= 4);
                        self.tmp_in_target -= 4;
                        let block = self.selected(selected_in, src);
                        let read_block_crc = read_le32(block, self.tmp_in_target);
                        let calc_block_crc = xxh32(&block[..self.tmp_in_target], 0);
                        if read_block_crc != calc_block_crc {
                            return Err(Error::BlockChecksumInvalid);
                        }
                    }

                    // Decode directly into the output if there is enough
                    // room, unless the dictionary is stored in tmpOut: then
                    // it's faster to decode within tmpOut, to benefit from
                    // the prefix speedup.
                    let dict_before_tmp_out =
                        self.dict == DictAt::Tmp && self.dict_size == self.tmp_out;
                    if let Some(out) = dst.as_deref_mut()
                        && dst_end - dst_ptr >= self.max_block_size
                        && !dict_before_tmp_out
                    {
                        let decoded_size = self.decode_into_dst(selected_in, src, out, dst_ptr)?;
                        if self.frame_info.content_checksum && !self.skip_checksum {
                            self.xxh.update(&out[dst_ptr..dst_ptr + decoded_size]);
                        }
                        if self.frame_info.content_size != 0 {
                            self.frame_remaining_size =
                                self.frame_remaining_size.wrapping_sub(decoded_size as u64);
                        }

                        // Dictionary management.
                        if self.frame_info.block_mode == BlockMode::Linked {
                            self.update_dict(out, dst_ptr, decoded_size, false);
                        }

                        dst_ptr += decoded_size;
                        // The end of the block: get another one.
                        self.d_stage = DStage::GetBlockHeader;
                        continue;
                    }

                    // Not enough room in the output: decode into tmpOut.

                    // Manage the dictionary.
                    if self.frame_info.block_mode == BlockMode::Linked {
                        if self.dict == DictAt::Tmp {
                            // Truncate the dictionary to 64 KB if too big.
                            if self.dict_size > 128 * KB {
                                let from = self.dict_size - 64 * KB;
                                self.tmp_out_buffer.copy_within(from..from + 64 * KB, 0);
                                self.dict_size = 64 * KB;
                            }
                            self.tmp_out = self.dict_size;
                        } else {
                            // The dictionary is not within tmpOut.
                            let reserved_dict_space = self.dict_size.min(64 * KB);
                            self.tmp_out = reserved_dict_space;
                        }
                    }

                    // Decode the block into tmpOut.
                    let decoded_size = self.decode_into_tmp(selected_in, src, dst.as_deref())?;
                    if self.frame_info.content_checksum && !self.skip_checksum {
                        self.xxh.update(
                            &self.tmp_out_buffer[self.tmp_out..self.tmp_out + decoded_size],
                        );
                    }
                    if self.frame_info.content_size != 0 {
                        self.frame_remaining_size =
                            self.frame_remaining_size.wrapping_sub(decoded_size as u64);
                    }
                    self.tmp_out_size = decoded_size;
                    self.tmp_out_start = 0;
                    self.d_stage = DStage::FlushOut;
                    // Fall through.
                }

                DStage::FlushOut => {
                    // Flush the decoded data from tmpOut to the output.
                    if let Some(out) = dst.as_deref_mut() {
                        let size_to_copy =
                            (self.tmp_out_size - self.tmp_out_start).min(dst_end - dst_ptr);
                        let from = self.tmp_out + self.tmp_out_start;
                        out[dst_ptr..dst_ptr + size_to_copy]
                            .copy_from_slice(&self.tmp_out_buffer[from..from + size_to_copy]);

                        // Dictionary management.
                        if self.frame_info.block_mode == BlockMode::Linked {
                            self.update_dict(out, dst_ptr, size_to_copy, true);
                        }

                        self.tmp_out_start += size_to_copy;
                        dst_ptr += size_to_copy;
                    }
                    if self.tmp_out_start == self.tmp_out_size {
                        // All flushed: get the next block.
                        self.d_stage = DStage::GetBlockHeader;
                        continue;
                    }
                    // Could not flush everything: stop there, and just ask
                    // for a block header.
                    do_another_stage = false;
                    next_src_size_hint = BH_SIZE;
                }

                DStage::GetSuffix | DStage::StoreSuffix => {
                    if self.d_stage == DStage::GetSuffix {
                        if self.frame_remaining_size != 0 {
                            // An incorrect frame size was decoded.
                            return Err(Error::FrameSizeWrong);
                        }
                        if !self.frame_info.content_checksum {
                            // No checksum: the frame is complete.
                            next_src_size_hint = 0;
                            self.reset();
                            do_another_stage = false;
                            continue;
                        }
                        if src_end - src_ptr < 4 {
                            // Not enough for the entire checksum.
                            self.tmp_in_size = 0;
                            self.d_stage = DStage::StoreSuffix;
                        } else {
                            selected_in = SelectedIn::Src(src_ptr);
                            src_ptr += 4;
                        }
                    }

                    if self.d_stage == DStage::StoreSuffix {
                        let remaining_input = src_end - src_ptr;
                        let wanted_data = 4 - self.tmp_in_size;
                        let size_to_copy = wanted_data.min(remaining_input);
                        self.tmp_in[self.tmp_in_size..self.tmp_in_size + size_to_copy]
                            .copy_from_slice(&src[src_ptr..src_ptr + size_to_copy]);
                        src_ptr += size_to_copy;
                        self.tmp_in_size += size_to_copy;
                        if self.tmp_in_size < 4 {
                            // Not enough input to read the complete suffix.
                            next_src_size_hint = 4 - self.tmp_in_size;
                            do_another_stage = false;
                            continue;
                        }
                        selected_in = SelectedIn::TmpIn;
                    }

                    // dstage_checkSuffix: no direct entry.
                    if !self.skip_checksum {
                        let read_crc = read_le32(self.selected(selected_in, src), 0);
                        let result_crc = self.xxh.digest();
                        if read_crc != result_crc {
                            return Err(Error::ContentChecksumInvalid);
                        }
                    }
                    next_src_size_hint = 0;
                    self.reset();
                    do_another_stage = false;
                }

                DStage::GetSFrameSize | DStage::StoreSFrameSize => {
                    if self.d_stage == DStage::GetSFrameSize {
                        if src_end - src_ptr >= 4 {
                            selected_in = SelectedIn::Src(src_ptr);
                            src_ptr += 4;
                        } else {
                            // Not enough input to read the size field.
                            self.tmp_in_size = 4;
                            self.tmp_in_target = 8;
                            self.d_stage = DStage::StoreSFrameSize;
                        }
                    }

                    if self.d_stage == DStage::StoreSFrameSize {
                        let size_to_copy =
                            (self.tmp_in_target - self.tmp_in_size).min(src_end - src_ptr);
                        self.header[self.tmp_in_size..self.tmp_in_size + size_to_copy]
                            .copy_from_slice(&src[src_ptr..src_ptr + size_to_copy]);
                        src_ptr += size_to_copy;
                        self.tmp_in_size += size_to_copy;
                        if self.tmp_in_size < self.tmp_in_target {
                            // Not enough input to get the full size: wait
                            // for more.
                            next_src_size_hint = self.tmp_in_target - self.tmp_in_size;
                            do_another_stage = false;
                            continue;
                        }
                        selected_in = SelectedIn::Header(4);
                    }

                    // dstage_decodeSFrameSize: no direct entry.
                    let s_frame_size = read_le32(self.selected(selected_in, src), 0) as usize;
                    self.frame_info.content_size = s_frame_size as u64;
                    self.tmp_in_target = s_frame_size;
                    self.d_stage = DStage::SkipSkippable;
                }

                DStage::SkipSkippable => {
                    let skip_size = self.tmp_in_target.min(src_end - src_ptr);
                    src_ptr += skip_size;
                    self.tmp_in_target -= skip_size;
                    do_another_stage = false;
                    next_src_size_hint = self.tmp_in_target;
                    if next_src_size_hint == 0 {
                        // The frame is fully skipped: ready for a new one.
                        self.reset();
                    }
                }
            }
        }

        // Preserve the history within tmpOut whenever necessary: the next
        // block will use up to 64 KB of the ones before, if the dictionary
        // exists and is not already within tmp, and the stage is one of
        // [init ... getSuffix[. liblz4 does not when the caller promises
        // that the output stays (stableDst), which the port does not take.
        if self.frame_info.block_mode == BlockMode::Linked
            && self.dict != DictAt::Tmp
            && self.dict != DictAt::Null
            && self.d_stage >= DStage::Init
            && self.d_stage < DStage::GetSuffix
        {
            let out = dst.as_deref().unwrap_or_default();
            if self.d_stage == DStage::FlushOut {
                let preserve_size = self.tmp_out;
                let mut copy_size = (64 * KB).saturating_sub(self.tmp_out_size);
                copy_size = copy_size.min(preserve_size);
                // liblz4 points before the output when the block was flushed in
                // earlier calls too, and then copies nothing.
                let old_dict_end = self.dict_size.wrapping_sub(self.tmp_out_start);
                self.copy_dict_into_tmp(
                    out,
                    old_dict_end.wrapping_sub(copy_size),
                    preserve_size - copy_size,
                    copy_size,
                );
                self.dict = DictAt::Tmp;
                self.dict_size = preserve_size + self.tmp_out_start;
            } else {
                let new_dict_size = self.dict_size.min(64 * KB);
                self.copy_dict_into_tmp(out, self.dict_size - new_dict_size, 0, new_dict_size);
                self.dict = DictAt::Tmp;
                self.dict_size = new_dict_size;
                self.tmp_out = new_dict_size;
            }
        }
        if let DictAt::Dst(_) = self.dict {
            // The output is the caller's again: liblz4's pointer would
            // dangle, and is not read before the frame ends.
            self.dict = DictAt::Gone;
        }

        Ok((src_ptr, dst_ptr, next_src_size_hint))
    }

    /// `selectedIn`: the block header, compressed block or checksum being
    /// read.
    fn selected<'a>(&'a self, selected_in: SelectedIn, src: &'a [u8]) -> &'a [u8] {
        match selected_in {
            SelectedIn::Src(at) => &src[at..],
            SelectedIn::TmpIn => &self.tmp_in,
            SelectedIn::Header(at) => &self.header[at..],
        }
    }

    /// The compressed block, `tmpInTarget` bytes.
    fn compressed<'a>(
        selected_in: SelectedIn,
        src: &'a [u8],
        tmp_in: &'a [u8],
        size: usize,
    ) -> &'a [u8] {
        match selected_in {
            SelectedIn::Src(at) => &src[at..at + size],
            SelectedIn::TmpIn | SelectedIn::Header(_) => &tmp_in[..size],
        }
    }

    /// The block decoded directly into the output at `dst_ptr`, with up to
    /// `maxBlockSize` bytes of room.
    fn decode_into_dst(
        &self,
        selected_in: SelectedIn,
        src: &[u8],
        out: &mut [u8],
        dst_ptr: usize,
    ) -> Result<usize> {
        let block = Self::compressed(selected_in, src, &self.tmp_in, self.tmp_in_target);
        let (dict, start, size) = self.block_dict();
        let end = dst_ptr + self.max_block_size;
        let decoded = match dict {
            DictAt::Null | DictAt::Gone => {
                decompress_using_dict(block, &mut out[..end], dst_ptr, BlockDict::None)
            }
            DictAt::User => decompress_using_dict(
                block,
                &mut out[..end],
                dst_ptr,
                BlockDict::Ext(&self.user_dict[start..start + size]),
            ),
            DictAt::Tmp => decompress_using_dict(
                block,
                &mut out[..end],
                dst_ptr,
                BlockDict::Ext(&self.tmp_out_buffer[start..start + size]),
            ),
            DictAt::Dst(at) => {
                let from = at + start;
                if from + size == dst_ptr {
                    decompress_using_dict(block, &mut out[..end], dst_ptr, BlockDict::Prefix(size))
                } else {
                    // A dictionary earlier in the output, apart from it.
                    let (before, after) = out.split_at_mut(dst_ptr);
                    decompress_using_dict(
                        block,
                        &mut after[..self.max_block_size],
                        0,
                        BlockDict::Ext(&before[from..from + size]),
                    )
                }
            }
        };
        decoded.map_err(|_| Error::DecompressionFailed)
    }

    /// The block decoded into tmpOut, with `maxBlockSize` bytes of room.
    fn decode_into_tmp(
        &mut self,
        selected_in: SelectedIn,
        src: &[u8],
        out: Option<&[u8]>,
    ) -> Result<usize> {
        let block = Self::compressed(selected_in, src, &self.tmp_in, self.tmp_in_target);
        let (dict, start, size) = self.block_dict();
        let tmp_out = self.tmp_out;
        let end = tmp_out + self.max_block_size;
        let decoded = match dict {
            DictAt::Null | DictAt::Gone => decompress_using_dict(
                block,
                &mut self.tmp_out_buffer[..end],
                tmp_out,
                BlockDict::None,
            ),
            DictAt::User => decompress_using_dict(
                block,
                &mut self.tmp_out_buffer[..end],
                tmp_out,
                BlockDict::Ext(&self.user_dict[start..start + size]),
            ),
            DictAt::Dst(at) => {
                let out = out.unwrap_or_default();
                decompress_using_dict(
                    block,
                    &mut self.tmp_out_buffer[..end],
                    tmp_out,
                    BlockDict::Ext(&out[at + start..at + start + size]),
                )
            }
            DictAt::Tmp => {
                if start + size == tmp_out {
                    decompress_using_dict(
                        block,
                        &mut self.tmp_out_buffer[..end],
                        tmp_out,
                        BlockDict::Prefix(size),
                    )
                } else {
                    // A dictionary earlier in tmpOutBuffer, apart from
                    // tmpOut.
                    let (before, after) = self.tmp_out_buffer.split_at_mut(tmp_out);
                    decompress_using_dict(
                        block,
                        &mut after[..self.max_block_size],
                        0,
                        BlockDict::Ext(&before[start..start + size]),
                    )
                }
            }
        };
        decoded.map_err(|_| Error::DecompressionFailed)
    }
}

/// A buffer of `size` bytes in place of `buffer`, or `false` if it cannot
/// be allocated (`LZ4F_malloc` returning `NULL`).
fn reallocate(buffer: &mut Vec<u8>, size: usize) -> bool {
    *buffer = Vec::new();
    if buffer.try_reserve_exact(size).is_err() {
        return false;
    }
    buffer.resize(size, 0);
    true
}

/// `LZ4F_headerSize`: the size of the frame header that starts `src`,
/// which must hold at least its first 5 bytes.
pub fn header_size(src: &[u8]) -> Result<usize> {
    // The minimal size to determine the header size.
    if src.len() < MIN_SIZE_TO_KNOW_HEADER_LENGTH {
        return Err(Error::FrameHeaderIncomplete);
    }

    // Special case: skippable frames.
    if read_le32(src, 0) & 0xFFFF_FFF0 == MAGIC_SKIPPABLE_START {
        return Ok(8);
    }

    // Control the magic number.
    if read_le32(src, 0) != MAGICNUMBER {
        return Err(Error::FrameTypeUnknown);
    }

    // Frame header size.
    let flg = src[4];
    let content_size_flag = (flg >> 3) & 1;
    let dict_id_flag = flg & 1;
    Ok(MIN_FH_SIZE
        + if content_size_flag != 0 { 8 } else { 0 }
        + if dict_id_flag != 0 { 4 } else { 0 })
}
