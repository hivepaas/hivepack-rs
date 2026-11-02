//! Decoding frames: port of `decompress/zstd_decompress.c`, in one call
//! ([`DCtx::decompress`]) or streaming ([`DCtx::decompress_stream`]).
//!
//! libzstd decodes into a caller's buffer that may overlap the input
//! ("in-place" decompression). The port takes an output slice and an input
//! slice, which cannot overlap, so that case does not arise.
//!
//! libzstd's bufferless streaming functions (`ZSTD_decompressBegin`,
//! `ZSTD_decompressContinue` and the ones around them) keep the caller's
//! earlier output buffers as the window, between calls. Safe Rust cannot
//! hold on to them, so the port keeps those functions for
//! [`DCtx::decompress_stream`], which passes them its own buffer (or the
//! caller's stable one), and does not offer them on their own.

use std::sync::Arc;

use crate::zstd::common::entropy_common::fse_read_ncount;
use crate::zstd::common::error_private::{Error, ErrorCode, Result, error};
use crate::zstd::common::mem::{read_le16, read_le32, read_le64};
use crate::zstd::common::xxhash::{Xxh64State, xxh64};
use crate::zstd::common::zstd_internal::{
    BlockType, LL_BITS, LL_FSE_LOG, MAX_LL, MAX_ML, MAX_OFF, ML_BITS, ML_FSE_LOG, OFF_FSE_LOG,
    ZSTD_BLOCKHEADERSIZE, ZSTD_BLOCKSIZE_MAX, ZSTD_DID_FIELD_SIZE, ZSTD_FCS_FIELD_SIZE,
    ZSTD_FRAMEIDSIZE, ZSTD_MAGIC_DICTIONARY, ZSTD_MAGIC_SKIPPABLE_MASK, ZSTD_MAGIC_SKIPPABLE_START,
    ZSTD_MAGICNUMBER, ZSTD_WINDOWLOG_ABSOLUTEMIN,
};
use crate::zstd::decompress::huf_decompress::{HufReadDTableX2Workspace, huf_read_dtable_x2_wksp};
use crate::zstd::decompress::zstd_ddict::{DDict, DictContentType};
use crate::zstd::decompress::zstd_decompress_block::{
    BlockOut, BlockProperties, build_fse_table, decompress_block_internal, get_c_block_size,
};
use crate::zstd::decompress::zstd_decompress_internal::{
    CONTENTSIZE_UNKNOWN, DCtx, DDictHashSet, DStage, DStreamStage, DictUses, EntropyDTables,
    ExtDict, Format, FrameHeader, FrameType, LL_BASE, ML_BASE, NextInputType, OF_BASE, OF_BITS,
    OutBufferId, Segment, TableRef, WILDCOPY_OVERLENGTH, ZSTD_MAXWINDOWSIZE_DEFAULT,
    ZSTD_WINDOWLOG_LIMIT_DEFAULT,
};

/// `ZSTD_SKIPPABLEHEADERSIZE`
pub const SKIPPABLE_HEADER_SIZE: usize = 8;

/// How often [`DCtx::decompress_continue`] dropped the oldest part of its
/// copy of the window, so that the tests can check they reach it.
#[cfg(test)]
pub(crate) static BUFFERLESS_TRIMS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
/// `ZSTD_WINDOWLOG_MAX` for a 64-bit machine. libzstd lowers it to 30 on
/// 32-bit machines; the port keeps 31 everywhere.
pub const WINDOWLOG_MAX: u32 = 31;
/// `ZSTD_BLOCKSIZE_MAX_MIN`: the smallest maximum block size allowed.
pub const BLOCKSIZE_MAX_MIN: u32 = 1 << 10;
/// `ZSTD_FRAMEHEADERSIZE_MAX`
pub const FRAMEHEADER_SIZE_MAX: usize = 18;

/// `ZSTD_FRAMEHEADERSIZE_PREFIX`: what it takes to know the header's size.
const fn frame_header_size_prefix(format: Format) -> usize {
    match format {
        Format::Zstd1 => 5,
        Format::Zstd1Magicless => 1,
    }
}

/// `ZSTD_FRAMEHEADERSIZE_MIN`
const fn frame_header_size_min(format: Format) -> usize {
    match format {
        Format::Zstd1 => 6,
        Format::Zstd1Magicless => 2,
    }
}

/// `ZSTD_startingInputLength`
const fn starting_input_length(format: Format) -> usize {
    frame_header_size_prefix(format)
}

/// The address of a position in a buffer: what libzstd compares its
/// pointers against. Never dereferenced.
fn address(buffer: &[u8], pos: usize) -> usize {
    (buffer.as_ptr() as usize).wrapping_add(pos)
}

// ---------------------------------------------------------------------------
// The DDict hash set
// ---------------------------------------------------------------------------

/// `DDICT_HASHSET_MAX_LOAD_FACTOR_COUNT_MULT` and `_SIZE_MULT`: the table
/// grows once `count * 4 / size * 3` is not 0, that is from a quarter full
/// (the integer division makes it so, not the 0.75 libzstd describes).
const DDICT_HASHSET_MAX_LOAD_FACTOR_COUNT_MULT: usize = 4;
const DDICT_HASHSET_MAX_LOAD_FACTOR_SIZE_MULT: usize = 3;
const DDICT_HASHSET_TABLE_BASE_SIZE: usize = 64;
const DDICT_HASHSET_RESIZE_FACTOR: usize = 2;

impl DDictHashSet {
    /// `ZSTD_createDDictHashSet`
    pub(crate) fn new() -> DDictHashSet {
        DDictHashSet {
            table: vec![None; DDICT_HASHSET_TABLE_BASE_SIZE],
            count: 0,
        }
    }

    /// `ZSTD_DDictHashSet_getIndex`: where the search for `dict_id` starts.
    ///
    /// Differs from libzstd: the ID is hashed as little-endian bytes.
    /// libzstd hashes them in the machine's order, so on big-endian
    /// machines its IDs land in other slots.
    fn get_index(&self, dict_id: u32) -> usize {
        let hash = xxh64(&dict_id.to_le_bytes(), 0);
        (hash & (self.table.len() as u64 - 1)) as usize
    }

    /// `ZSTD_DDictHashSet_emplaceDDict`: adds `ddict` without growing the
    /// table, replacing one of the same ID.
    ///
    /// Differs from libzstd: the search wraps from the last slot to the
    /// first, as libzstd's development branch does since commit c6f91a4.
    /// libzstd 1.5.7 steps from the last slot to one past the table.
    fn emplace(&mut self, ddict: Arc<DDict>) -> Result<()> {
        let dict_id = ddict.dict_id;
        let mut idx = self.get_index(dict_id);
        let idx_range_mask = self.table.len() - 1;
        if self.count == self.table.len() {
            // The set is full.
            return error!(Generic);
        }
        while let Some(entry) = &self.table[idx] {
            if entry.dict_id == dict_id {
                self.table[idx] = Some(ddict);
                return Ok(());
            }
            idx = (idx + 1) & idx_range_mask;
        }
        self.table[idx] = Some(ddict);
        self.count += 1;
        Ok(())
    }

    /// `ZSTD_DDictHashSet_expand`: doubles the table and places every
    /// DDict again.
    fn expand(&mut self) -> Result<()> {
        let new_table_size = self.table.len() * DDICT_HASHSET_RESIZE_FACTOR;
        let old_table = std::mem::replace(&mut self.table, vec![None; new_table_size]);
        self.count = 0;
        for ddict in old_table.into_iter().flatten() {
            self.emplace(ddict)?;
        }
        Ok(())
    }

    /// `ZSTD_DDictHashSet_getDDict`: the DDict of ID `dict_id`, if any.
    ///
    /// As in libzstd, the search stops at the first DDict of ID 0, taken
    /// for an empty slot: a raw-content DDict found there is what comes
    /// back, whatever ID was asked for. The search wraps around as in
    /// [`DDictHashSet::emplace`].
    pub(crate) fn get(&self, dict_id: u32) -> Option<&Arc<DDict>> {
        let mut idx = self.get_index(dict_id);
        let idx_range_mask = self.table.len() - 1;
        loop {
            let curr_dict_id = self.table[idx].as_ref().map_or(0, |ddict| ddict.dict_id);
            if curr_dict_id == dict_id || curr_dict_id == 0 {
                break;
            }
            idx = (idx + 1) & idx_range_mask;
        }
        self.table[idx].as_ref()
    }

    /// `ZSTD_DDictHashSet_addDDict`: adds `ddict`, growing the table first
    /// if it is loaded enough.
    pub(crate) fn add(&mut self, ddict: Arc<DDict>) -> Result<()> {
        if self.count * DDICT_HASHSET_MAX_LOAD_FACTOR_COUNT_MULT / self.table.len()
            * DDICT_HASHSET_MAX_LOAD_FACTOR_SIZE_MULT
            != 0
        {
            self.expand()?;
        }
        self.emplace(ddict)
    }
}

// ---------------------------------------------------------------------------
// Frame headers
// ---------------------------------------------------------------------------

/// `ZSTD_isFrame`: whether `buffer` starts with a frame's magic number,
/// skippable or not (legacy frames are not supported).
pub fn is_frame(buffer: &[u8]) -> bool {
    if buffer.len() < ZSTD_FRAMEIDSIZE {
        return false;
    }
    let magic = read_le32(buffer, 0);
    magic == ZSTD_MAGICNUMBER || (magic & ZSTD_MAGIC_SKIPPABLE_MASK) == ZSTD_MAGIC_SKIPPABLE_START
}

/// `ZSTD_isSkippableFrame`
pub fn is_skippable_frame(buffer: &[u8]) -> bool {
    buffer.len() >= ZSTD_FRAMEIDSIZE
        && (read_le32(buffer, 0) & ZSTD_MAGIC_SKIPPABLE_MASK) == ZSTD_MAGIC_SKIPPABLE_START
}

/// `ZSTD_frameHeaderSize_internal`
fn frame_header_size_internal(src: &[u8], format: Format) -> Result<usize> {
    let min_input_size = starting_input_length(format);
    if src.len() < min_input_size {
        return error!(SrcSizeWrong);
    }
    let fhd = src[min_input_size - 1];
    let dict_id = usize::from(fhd & 3);
    let single_segment = (fhd >> 5) & 1 != 0;
    let fcs_id = usize::from(fhd >> 6);
    Ok(min_input_size
        + usize::from(!single_segment)
        + ZSTD_DID_FIELD_SIZE[dict_id]
        + ZSTD_FCS_FIELD_SIZE[fcs_id]
        + usize::from(single_segment && fcs_id == 0))
}

/// `ZSTD_frameHeaderSize`: the size of the frame header at the start of
/// `src`, which needs 5 bytes.
pub fn frame_header_size(src: &[u8]) -> Result<usize> {
    frame_header_size_internal(src, Format::Zstd1)
}

/// What [`get_frame_header`] found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FrameHeaderState {
    /// The whole header.
    Complete(FrameHeader),
    /// The input stops before the header ends: this many bytes are needed.
    NeedsInput(usize),
}

/// `ZSTD_getFrameHeader_advanced`
pub fn get_frame_header_advanced(src: &[u8], format: Format) -> Result<FrameHeaderState> {
    let mut zfh = FrameHeader::default();
    match get_frame_header_into(&mut zfh, src, format)? {
        0 => Ok(FrameHeaderState::Complete(zfh)),
        needed => Ok(FrameHeaderState::NeedsInput(needed)),
    }
}

/// `ZSTD_getFrameHeader_advanced` as libzstd has it: fills `zfh` and
/// returns 0 once the header is complete, or else the input size it needs.
///
/// As in libzstd, `zfh` is cleared as soon as `src` holds
/// `ZSTD_startingInputLength` bytes, before the header is known to be
/// complete or valid, and left alone before that. The streaming decoder
/// looks up the frame's dictionary from `zfh` whatever this returns.
pub(crate) fn get_frame_header_into(
    zfh: &mut FrameHeader,
    src: &[u8],
    format: Format,
) -> Result<usize> {
    let ip = src;
    let src_size = src.len();
    let min_input_size = starting_input_length(format);

    if src_size < min_input_size {
        if src_size > 0 && format != Format::Zstd1Magicless {
            // Check that what there is could be a supported magic number,
            // to fail early if it cannot.
            let to_copy = src_size.min(4);
            let mut hbuf = ZSTD_MAGICNUMBER.to_le_bytes();
            hbuf[..to_copy].copy_from_slice(&src[..to_copy]);
            if u32::from_le_bytes(hbuf) != ZSTD_MAGICNUMBER {
                // Not a zstd frame: maybe a skippable one.
                let mut hbuf = ZSTD_MAGIC_SKIPPABLE_START.to_le_bytes();
                hbuf[..to_copy].copy_from_slice(&src[..to_copy]);
                if (u32::from_le_bytes(hbuf) & ZSTD_MAGIC_SKIPPABLE_MASK)
                    != ZSTD_MAGIC_SKIPPABLE_START
                {
                    return error!(PrefixUnknown);
                }
            }
        }
        return Ok(min_input_size);
    }

    *zfh = FrameHeader::default();
    if format != Format::Zstd1Magicless && read_le32(src, 0) != ZSTD_MAGICNUMBER {
        if (read_le32(src, 0) & ZSTD_MAGIC_SKIPPABLE_MASK) == ZSTD_MAGIC_SKIPPABLE_START {
            // A skippable frame.
            if src_size < SKIPPABLE_HEADER_SIZE {
                // The magic number and the frame length.
                return Ok(SKIPPABLE_HEADER_SIZE);
            }
            zfh.frame_type = FrameType::Skippable;
            zfh.dict_id = read_le32(src, 0) - ZSTD_MAGIC_SKIPPABLE_START;
            zfh.header_size = SKIPPABLE_HEADER_SIZE as u32;
            zfh.frame_content_size = u64::from(read_le32(src, ZSTD_FRAMEIDSIZE));
            return Ok(0);
        }
        return error!(PrefixUnknown);
    }

    // Enough input to read the whole header?
    let fh_size = frame_header_size_internal(src, format)?;
    if src_size < fh_size {
        return Ok(fh_size);
    }
    zfh.header_size = fh_size as u32;

    let fhd_byte = ip[min_input_size - 1];
    let mut pos = min_input_size;
    let dict_id_size_code = fhd_byte & 3;
    let checksum_flag = (fhd_byte >> 2) & 1 != 0;
    let single_segment = (fhd_byte >> 5) & 1 != 0;
    let fcs_id = fhd_byte >> 6;
    let mut window_size: u64 = 0;
    let mut dict_id: u32 = 0;
    let mut frame_content_size = CONTENTSIZE_UNKNOWN;
    if fhd_byte & 0x08 != 0 {
        // Reserved bits, which must be zero.
        return error!(FrameParameterUnsupported);
    }

    if !single_segment {
        let wl_byte = ip[pos];
        pos += 1;
        let window_log = u32::from(wl_byte >> 3) + ZSTD_WINDOWLOG_ABSOLUTEMIN;
        if window_log > WINDOWLOG_MAX {
            return error!(FrameParameterWindowTooLarge);
        }
        window_size = 1u64 << window_log;
        window_size += (window_size >> 3) * u64::from(wl_byte & 7);
    }
    match dict_id_size_code {
        0 => {}
        1 => {
            dict_id = u32::from(ip[pos]);
            pos += 1;
        }
        2 => {
            dict_id = u32::from(read_le16(ip, pos));
            pos += 2;
        }
        _ => {
            dict_id = read_le32(ip, pos);
            pos += 4;
        }
    }
    match fcs_id {
        0 => {
            if single_segment {
                frame_content_size = u64::from(ip[pos]);
            }
        }
        1 => frame_content_size = u64::from(read_le16(ip, pos)) + 256,
        2 => frame_content_size = u64::from(read_le32(ip, pos)),
        _ => frame_content_size = read_le64(ip, pos),
    }
    if single_segment {
        window_size = frame_content_size;
    }

    zfh.frame_type = FrameType::Frame;
    zfh.frame_content_size = frame_content_size;
    zfh.window_size = window_size;
    zfh.block_size_max = window_size.min(ZSTD_BLOCKSIZE_MAX as u64) as u32;
    zfh.dict_id = dict_id;
    zfh.checksum_flag = checksum_flag;
    Ok(0)
}

/// `ZSTD_getFrameHeader`: reads the frame header at the start of `src`.
/// It does not consume input, only reads it.
pub fn get_frame_header(src: &[u8]) -> Result<FrameHeaderState> {
    get_frame_header_advanced(src, Format::Zstd1)
}

/// The result of [`get_frame_content_size`] and [`find_decompressed_size`]:
/// libzstd's `ZSTD_CONTENTSIZE_UNKNOWN` and `ZSTD_CONTENTSIZE_ERROR`, or a
/// size.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ContentSize {
    Known(u64),
    /// The frame does not say.
    Unknown,
    /// Not a frame, or too short to tell.
    Error,
}

impl ContentSize {
    /// How libzstd returns it: the size, or one of its two special values.
    fn from_raw(size: u64) -> ContentSize {
        match size {
            CONTENTSIZE_UNKNOWN => ContentSize::Unknown,
            CONTENTSIZE_ERROR => ContentSize::Error,
            size => ContentSize::Known(size),
        }
    }
}

/// `ZSTD_CONTENTSIZE_ERROR`
const CONTENTSIZE_ERROR: u64 = u64::MAX - 1;

/// `ZSTD_getFrameContentSize` as libzstd returns it.
fn get_frame_content_size_raw(src: &[u8]) -> u64 {
    match get_frame_header(src) {
        Ok(FrameHeaderState::Complete(zfh)) if zfh.frame_type == FrameType::Skippable => 0,
        Ok(FrameHeaderState::Complete(zfh)) => zfh.frame_content_size,
        _ => CONTENTSIZE_ERROR,
    }
}

/// `ZSTD_getFrameContentSize`: the content size of the frame at the start
/// of `src`, as its header gives it.
pub fn get_frame_content_size(src: &[u8]) -> ContentSize {
    ContentSize::from_raw(get_frame_content_size_raw(src))
}

/// `readSkippableFrameSize`
fn read_skippable_frame_size(src: &[u8]) -> Result<usize> {
    if src.len() < SKIPPABLE_HEADER_SIZE {
        return error!(SrcSizeWrong);
    }
    let size_u32 = read_le32(src, ZSTD_FRAMEIDSIZE);
    if size_u32.wrapping_add(SKIPPABLE_HEADER_SIZE as u32) < size_u32 {
        return error!(FrameParameterUnsupported);
    }
    let skippable_size = SKIPPABLE_HEADER_SIZE + size_u32 as usize;
    if skippable_size > src.len() {
        return error!(SrcSizeWrong);
    }
    Ok(skippable_size)
}

/// `ZSTD_readSkippableFrame`: copies the content of the skippable frame at
/// the start of `src` to `dst`. Returns its size, and the magic number's
/// variant (0 to 15).
pub fn read_skippable_frame(dst: &mut [u8], src: &[u8]) -> Result<(usize, u32)> {
    if src.len() < SKIPPABLE_HEADER_SIZE {
        return error!(SrcSizeWrong);
    }
    let magic_number = read_le32(src, 0);
    let skippable_frame_size = read_skippable_frame_size(src);
    // libzstd checks the frame size after the magic number, whatever the
    // size's error.
    if !is_skippable_frame(src) {
        return error!(FrameParameterUnsupported);
    }
    let skippable_frame_size = match skippable_frame_size {
        Ok(size) => size,
        // libzstd subtracts the header size from the error code and goes on;
        // the only error left possible here is a size past the input.
        Err(_) => return error!(SrcSizeWrong),
    };
    let skippable_content_size = skippable_frame_size - SKIPPABLE_HEADER_SIZE;
    if skippable_content_size > dst.len() {
        return error!(DstSizeTooSmall);
    }
    dst[..skippable_content_size]
        .copy_from_slice(&src[SKIPPABLE_HEADER_SIZE..skippable_frame_size]);
    Ok((
        skippable_content_size,
        magic_number - ZSTD_MAGIC_SKIPPABLE_START,
    ))
}

/// `ZSTD_findDecompressedSize`: the total content size of the frames in
/// `src`, which must hold whole frames and nothing else.
pub fn find_decompressed_size(src: &[u8]) -> ContentSize {
    let mut src = src;
    let mut total_dst_size: u64 = 0;

    while src.len() >= starting_input_length(Format::Zstd1) {
        let magic_number = read_le32(src, 0);

        if (magic_number & ZSTD_MAGIC_SKIPPABLE_MASK) == ZSTD_MAGIC_SKIPPABLE_START {
            let Ok(skippable_size) = read_skippable_frame_size(src) else {
                return ContentSize::Error;
            };
            src = &src[skippable_size..];
            continue;
        }

        let fcs = get_frame_content_size_raw(src);
        if fcs >= CONTENTSIZE_ERROR {
            return ContentSize::from_raw(fcs);
        }
        let Some(total) = total_dst_size.checked_add(fcs) else {
            return ContentSize::Error;
        };
        total_dst_size = total;

        // Skip to the next frame.
        let Ok(frame_src_size) = find_frame_compressed_size(src) else {
            return ContentSize::Error;
        };
        src = &src[frame_src_size..];
    }

    if !src.is_empty() {
        return ContentSize::Error;
    }
    ContentSize::Known(total_dst_size)
}

/// `ZSTD_frameSizeInfo`
struct FrameSizeInfo {
    nb_blocks: usize,
    compressed_size: usize,
    decompressed_bound: u64,
}

/// `ZSTD_findFrameSizeInfo`: walks the frame at the start of `src`.
fn find_frame_size_info(src: &[u8], format: Format) -> Result<FrameSizeInfo> {
    if format == Format::Zstd1
        && src.len() >= SKIPPABLE_HEADER_SIZE
        && (read_le32(src, 0) & ZSTD_MAGIC_SKIPPABLE_MASK) == ZSTD_MAGIC_SKIPPABLE_START
    {
        return Ok(FrameSizeInfo {
            nb_blocks: 0,
            compressed_size: read_skippable_frame_size(src)?,
            decompressed_bound: 0,
        });
    }

    let mut ip = 0usize;
    let mut remaining_size = src.len();
    let mut nb_blocks = 0usize;

    // The frame header.
    let zfh = match get_frame_header_advanced(src, format)? {
        FrameHeaderState::Complete(zfh) => zfh,
        FrameHeaderState::NeedsInput(_) => return error!(SrcSizeWrong),
    };
    ip += zfh.header_size as usize;
    remaining_size -= zfh.header_size as usize;

    // Each block.
    loop {
        let mut block_properties = BlockProperties {
            block_type: BlockType::Raw,
            last_block: false,
            orig_size: 0,
        };
        let c_block_size = get_c_block_size(&src[ip..], &mut block_properties)?;
        if ZSTD_BLOCKHEADERSIZE + c_block_size > remaining_size {
            return error!(SrcSizeWrong);
        }
        ip += ZSTD_BLOCKHEADERSIZE + c_block_size;
        remaining_size -= ZSTD_BLOCKHEADERSIZE + c_block_size;
        nb_blocks += 1;
        if block_properties.last_block {
            break;
        }
    }

    // The checksum.
    if zfh.checksum_flag {
        if remaining_size < 4 {
            return error!(SrcSizeWrong);
        }
        ip += 4;
    }

    let decompressed_bound = if zfh.frame_content_size != CONTENTSIZE_UNKNOWN {
        zfh.frame_content_size
    } else {
        (nb_blocks as u64).wrapping_mul(u64::from(zfh.block_size_max))
    };
    Ok(FrameSizeInfo {
        nb_blocks,
        compressed_size: ip,
        decompressed_bound,
    })
}

/// `ZSTD_findFrameCompressedSize`: the size of the frame (or skippable
/// frame) at the start of `src`.
pub fn find_frame_compressed_size(src: &[u8]) -> Result<usize> {
    find_frame_size_info(src, Format::Zstd1).map(|info| info.compressed_size)
}

/// `ZSTD_decompressBound`: an upper bound on what the frames in `src`
/// decode to, `None` if they are not valid.
pub fn decompress_bound(src: &[u8]) -> Option<u64> {
    let mut src = src;
    let mut bound: u64 = 0;
    while !src.is_empty() {
        let info = find_frame_size_info(src, Format::Zstd1).ok()?;
        if info.decompressed_bound == CONTENTSIZE_ERROR {
            return None;
        }
        src = &src[info.compressed_size..];
        bound = bound.wrapping_add(info.decompressed_bound);
    }
    Some(bound)
}

/// `ZSTD_getDictID_fromDict`: the ID of a zstd dictionary, 0 for raw
/// content.
pub fn get_dict_id_from_dict(dict: &[u8]) -> u32 {
    if dict.len() < 8 || read_le32(dict, 0) != ZSTD_MAGIC_DICTIONARY {
        return 0;
    }
    read_le32(dict, ZSTD_FRAMEIDSIZE)
}

/// `ZSTD_getDictID_fromFrame`: the ID of the dictionary the frame needs, 0
/// if it needs none, does not say, or cannot be read.
pub fn get_dict_id_from_frame(src: &[u8]) -> u32 {
    match get_frame_header(src) {
        Ok(FrameHeaderState::Complete(zfh)) => zfh.dict_id,
        Ok(FrameHeaderState::NeedsInput(_)) => 0,
        Err(_) => 0,
    }
}

// ---------------------------------------------------------------------------
// Dictionaries
// ---------------------------------------------------------------------------

/// `ZSTD_loadDEntropy`: reads the entropy tables of the zstd dictionary
/// `dict`. Returns the size of that part.
pub(crate) fn load_d_entropy(entropy: &mut EntropyDTables, dict: &[u8]) -> Result<usize> {
    let dict_end = dict.len();
    if dict.len() <= 8 {
        return error!(DictionaryCorrupted);
    }
    debug_assert!(read_le32(dict, 0) == ZSTD_MAGIC_DICTIONARY);
    // Skip the header: magic number and ID.
    let mut dict_ptr = 8usize;

    {
        // libzstd uses the FSE tables as the workspace here.
        let mut workspace = Box::new(HufReadDTableX2Workspace::default());
        let Ok(h_size) =
            huf_read_dtable_x2_wksp(&mut entropy.huf_table, &dict[dict_ptr..], &mut workspace)
        else {
            return error!(DictionaryCorrupted);
        };
        dict_ptr += h_size;
    }

    {
        let mut offcode_ncount = [0i16; MAX_OFF as usize + 1];
        let mut offcode_max_value = MAX_OFF;
        let mut offcode_log = 0;
        let Ok(offcode_header_size) = fse_read_ncount(
            &mut offcode_ncount,
            &mut offcode_max_value,
            &mut offcode_log,
            &dict[dict_ptr..],
        ) else {
            return error!(DictionaryCorrupted);
        };
        if offcode_max_value > MAX_OFF || offcode_log > OFF_FSE_LOG {
            return error!(DictionaryCorrupted);
        }
        build_fse_table(
            &mut entropy.of_table,
            &offcode_ncount,
            offcode_max_value,
            &OF_BASE,
            &OF_BITS,
            offcode_log,
            &mut entropy.workspace,
        );
        dict_ptr += offcode_header_size;
    }

    {
        let mut matchlength_ncount = [0i16; MAX_ML as usize + 1];
        let mut matchlength_max_value = MAX_ML;
        let mut matchlength_log = 0;
        let Ok(matchlength_header_size) = fse_read_ncount(
            &mut matchlength_ncount,
            &mut matchlength_max_value,
            &mut matchlength_log,
            &dict[dict_ptr..],
        ) else {
            return error!(DictionaryCorrupted);
        };
        if matchlength_max_value > MAX_ML || matchlength_log > ML_FSE_LOG {
            return error!(DictionaryCorrupted);
        }
        build_fse_table(
            &mut entropy.ml_table,
            &matchlength_ncount,
            matchlength_max_value,
            &ML_BASE,
            &ML_BITS,
            matchlength_log,
            &mut entropy.workspace,
        );
        dict_ptr += matchlength_header_size;
    }

    {
        let mut litlength_ncount = [0i16; MAX_LL as usize + 1];
        let mut litlength_max_value = MAX_LL;
        let mut litlength_log = 0;
        let Ok(litlength_header_size) = fse_read_ncount(
            &mut litlength_ncount,
            &mut litlength_max_value,
            &mut litlength_log,
            &dict[dict_ptr..],
        ) else {
            return error!(DictionaryCorrupted);
        };
        if litlength_max_value > MAX_LL || litlength_log > LL_FSE_LOG {
            return error!(DictionaryCorrupted);
        }
        build_fse_table(
            &mut entropy.ll_table,
            &litlength_ncount,
            litlength_max_value,
            &LL_BASE,
            &LL_BITS,
            litlength_log,
            &mut entropy.workspace,
        );
        dict_ptr += litlength_header_size;
    }

    if dict_ptr + 12 > dict_end {
        return error!(DictionaryCorrupted);
    }
    let dict_content_size = dict_end - (dict_ptr + 12);
    for i in 0..3 {
        let rep = read_le32(dict, dict_ptr);
        dict_ptr += 4;
        if rep == 0 || rep as usize > dict_content_size {
            return error!(DictionaryCorrupted);
        }
        entropy.rep[i] = rep;
    }

    Ok(dict_ptr)
}

/// The window a frame starts with, besides its own output: the content of
/// the dictionary in use, and its tables when it has some.
#[derive(Clone, Copy)]
struct FrameDict<'d> {
    content: ExtDict<'d>,
    entropy: Option<&'d EntropyDTables>,
}

impl FrameDict<'_> {
    const NONE: FrameDict<'static> = FrameDict {
        content: ExtDict::None,
        entropy: None,
    };
}

impl DCtx {
    /// `ZSTD_decompressBegin`: gets ready for a new frame.
    fn decompress_begin_internal(&mut self) {
        self.expected = starting_input_length(self.format);
        self.stage = DStage::GetFrameHeaderSize;
        self.processed_c_size = 0;
        self.decoded_size = 0;
        self.previous_dst_end = 0;
        self.dict_end = 0;
        self.stream_prefix = Segment::None;
        self.stream_ext = Segment::None;
        self.frame_ddict = None;
        self.reset_entropy();
        self.dict_id = 0;
        self.b_type = BlockType::Reserved;
        self.is_frame_decompression = true;
        // The bufferless window, kept allocated.
        self.bufferless.begun = false;
        self.bufferless.end = 0;
        self.bufferless.caller_end = 0;
    }

    /// `ZSTD_refDictContent`, for the pointer bookkeeping: the window will
    /// be `content`.
    fn ref_dict_content(&mut self, content: &[u8]) {
        self.dict_end = self.previous_dst_end;
        self.previous_dst_end = address(content, content.len());
    }

    /// `ZSTD_decompress_insertDictionary`: loads `dict`'s tables, if it is a
    /// zstd dictionary, and returns its content.
    fn insert_dictionary<'d>(&mut self, dict: &'d [u8]) -> Result<&'d [u8]> {
        if dict.len() < 8 || read_le32(dict, 0) != ZSTD_MAGIC_DICTIONARY {
            // Raw content.
            self.ref_dict_content(dict);
            return Ok(dict);
        }
        self.dict_id = read_le32(dict, ZSTD_FRAMEIDSIZE);

        // The entropy tables.
        let Ok(e_size) = load_d_entropy(&mut self.entropy, dict) else {
            return error!(DictionaryCorrupted);
        };
        let content = &dict[e_size..];
        self.lit_entropy = true;
        self.fse_entropy = true;

        // The rest is content.
        self.ref_dict_content(content);
        Ok(content)
    }

    /// `ZSTD_decompressBegin_usingDict`
    fn frame_begin_using_dict<'d>(&mut self, dict: Option<&'d [u8]>) -> Result<FrameDict<'d>> {
        self.decompress_begin_internal();
        let Some(dict) = dict.filter(|d| !d.is_empty()) else {
            return Ok(FrameDict::NONE);
        };
        match self.insert_dictionary(dict) {
            Ok(content) => Ok(FrameDict {
                content: ExtDict::Separate(content),
                entropy: None,
            }),
            Err(_) => error!(DictionaryCorrupted),
        }
    }

    /// `ZSTD_decompressBegin_usingDDict`
    fn frame_begin_using_ddict<'d>(&mut self, ddict: Option<&'d DDict>) -> FrameDict<'d> {
        if let Some(ddict) = ddict {
            // A dictionary other than the one just used is presumably not in
            // the processor's cache: the first block then prefetches.
            self.ddict_is_cold = self.dict_end != address(&ddict.content, ddict.content.len());
        }
        self.decompress_begin_internal();
        match ddict {
            // A missing DDict means no dictionary.
            None => FrameDict::NONE,
            Some(ddict) => {
                self.copy_ddict_parameters(ddict);
                FrameDict {
                    content: ExtDict::Separate(&ddict.content),
                    entropy: ddict.entropy_present.then_some(&*ddict.entropy),
                }
            }
        }
    }

    /// `ZSTD_copyDDictParameters`
    fn copy_ddict_parameters(&mut self, ddict: &DDict) {
        self.dict_id = ddict.dict_id;
        // prefixStart and virtualStart at the content's start.
        self.stream_prefix = Segment::Dict;
        self.stream_ext = Segment::None;
        self.dict_end = address(&ddict.content, ddict.content.len());
        self.previous_dst_end = self.dict_end;
        if ddict.entropy_present {
            self.lit_entropy = true;
            self.fse_entropy = true;
            self.ll_tptr = TableRef::Dict;
            self.ml_tptr = TableRef::Dict;
            self.of_tptr = TableRef::Dict;
            self.huf_ptr = TableRef::Dict;
            self.entropy.rep = ddict.entropy.rep;
        } else {
            self.lit_entropy = false;
            self.fse_entropy = false;
        }
    }

    /// `ZSTD_checkContinuity`, for the pointer bookkeeping: a frame's output
    /// never continues the previous segment, which becomes the older one.
    fn check_continuity(&mut self, dst: &[u8], pos: usize, dst_size: usize) {
        let dst_address = address(dst, pos);
        if dst_address != self.previous_dst_end && dst_size > 0 {
            self.dict_end = self.previous_dst_end;
            self.previous_dst_end = dst_address;
        }
    }

    /// `ZSTD_DCtx_selectFrameDDict`: with several dictionaries referenced,
    /// switches to the one the frame names.
    ///
    /// As in libzstd, when called for a one-call decompression this changes
    /// the dictionary later frames use, not the one already set up for this
    /// frame.
    ///
    /// Differs from libzstd: libzstd frees a dictionary loaded with
    /// `ZSTD_DCtx_loadDictionary` (or a prefix) here, while this frame and
    /// the rest of the call still read it: a use-after-free in 1.5.7, still
    /// in its development branch in October 2026. The port keeps it alive,
    /// and decodes as libzstd would if the freed memory were intact.
    fn select_frame_ddict(&mut self) {
        if self.ddict.is_some()
            && let Some(frame_ddict) = self
                .ddict_set
                .as_ref()
                .and_then(|set| set.get(self.f_params.dict_id))
        {
            let frame_ddict = frame_ddict.clone();
            self.clear_dict();
            self.dict_id = self.f_params.dict_id;
            self.ddict = Some(frame_ddict);
            self.dict_uses = DictUses::Indefinitely;
        }
    }

    /// `ZSTD_decodeFrameHeader`: reads the header, whose size is known.
    fn decode_frame_header(&mut self, src: &[u8]) -> Result<()> {
        if get_frame_header_into(&mut self.f_params, src, self.format)? > 0 {
            return error!(SrcSizeWrong);
        }

        // With several dictionaries, use the one the frame names.
        if self.ref_multiple_ddicts && self.ddict_set.is_some() {
            self.select_frame_ddict();
        }

        if self.f_params.dict_id != 0 && self.dict_id != self.f_params.dict_id {
            return error!(DictionaryWrong);
        }
        self.validate_checksum = self.f_params.checksum_flag && !self.force_ignore_checksum;
        if self.validate_checksum {
            self.xxh_state = Xxh64State::new(0);
        }
        self.processed_c_size += src.len() as u64;
        Ok(())
    }

    /// `ZSTD_decompressFrame`: decodes the frame at the start of `src` to
    /// `dst[op_start..]`. Returns the size it decoded to and the size of the
    /// frame.
    fn decompress_frame(
        &mut self,
        dst: &mut [u8],
        op_start: usize,
        src: &[u8],
        dict: FrameDict<'_>,
    ) -> Result<(usize, usize)> {
        let mut ip = 0usize;
        let oend = dst.len();
        let mut op = op_start;
        let mut remaining_src_size = src.len();

        if remaining_src_size < frame_header_size_min(self.format) + ZSTD_BLOCKHEADERSIZE {
            return error!(SrcSizeWrong);
        }

        // The frame header.
        {
            let frame_header_size = frame_header_size_internal(
                &src[..frame_header_size_prefix(self.format)],
                self.format,
            )?;
            if remaining_src_size < frame_header_size + ZSTD_BLOCKHEADERSIZE {
                return error!(SrcSizeWrong);
            }
            self.decode_frame_header(&src[..frame_header_size])?;
            ip += frame_header_size;
            remaining_src_size -= frame_header_size;
        }

        // A smaller maximum block size, if set.
        if self.max_block_size_param != 0 {
            self.f_params.block_size_max =
                self.f_params.block_size_max.min(self.max_block_size_param);
        }

        // Each block.
        loop {
            let mut block_properties = BlockProperties {
                block_type: BlockType::Raw,
                last_block: false,
                orig_size: 0,
            };
            let c_block_size =
                get_c_block_size(&src[ip..ip + remaining_src_size], &mut block_properties)?;

            ip += ZSTD_BLOCKHEADERSIZE;
            remaining_src_size -= ZSTD_BLOCKHEADERSIZE;
            if c_block_size > remaining_src_size {
                return error!(SrcSizeWrong);
            }
            let block = &src[ip..ip + c_block_size];

            let decoded_size = match block_properties.block_type {
                BlockType::Compressed => {
                    debug_assert!(self.is_frame_decompression);
                    let mut bo = BlockOut {
                        out: &mut *dst,
                        dst: op,
                        dst_capacity: oend - op,
                        prefix_start: op_start,
                        ext: dict.content,
                        dict: dict.entropy,
                    };
                    decompress_block_internal(self, &mut bo, block, false)?
                }
                BlockType::Raw => {
                    // ZSTD_copyRawBlock
                    if c_block_size > oend - op {
                        return error!(DstSizeTooSmall);
                    }
                    dst[op..op + c_block_size].copy_from_slice(block);
                    c_block_size
                }
                BlockType::Rle => {
                    // ZSTD_setRleBlock
                    let regen_size = block_properties.orig_size as usize;
                    if regen_size > oend - op {
                        return error!(DstSizeTooSmall);
                    }
                    dst[op..op + regen_size].fill(block[0]);
                    regen_size
                }
                BlockType::Reserved => return error!(CorruptionDetected),
            };
            if self.validate_checksum {
                self.xxh_state.update(&dst[op..op + decoded_size]);
            }
            op += decoded_size;
            ip += c_block_size;
            remaining_src_size -= c_block_size;
            if block_properties.last_block {
                break;
            }
        }

        if self.f_params.frame_content_size != CONTENTSIZE_UNKNOWN
            && (op - op_start) as u64 != self.f_params.frame_content_size
        {
            return error!(CorruptionDetected);
        }
        if self.f_params.checksum_flag {
            // The frame content checksum.
            if remaining_src_size < 4 {
                return error!(ChecksumWrong);
            }
            if !self.force_ignore_checksum {
                let check_calc = self.xxh_state.digest() as u32;
                let check_read = read_le32(src, ip);
                if check_read != check_calc {
                    return error!(ChecksumWrong);
                }
            }
            ip += 4;
        }
        Ok((op - op_start, ip))
    }

    /// `ZSTD_decompressMultiFrame`: decodes every frame in `src`, with `dict`
    /// or `ddict` (not both).
    fn decompress_multi_frame(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        dict: Option<&[u8]>,
        ddict: Option<&DDict>,
    ) -> Result<usize> {
        let mut src_pos = 0usize;
        let mut op = 0usize;
        let mut more_than_1_frame = false;
        debug_assert!(dict.is_none() || ddict.is_none());

        while src.len() - src_pos >= starting_input_length(self.format) {
            let frame_src = &src[src_pos..];
            if self.format == Format::Zstd1 && frame_src.len() >= 4 {
                let magic_number = read_le32(frame_src, 0);
                if (magic_number & ZSTD_MAGIC_SKIPPABLE_MASK) == ZSTD_MAGIC_SKIPPABLE_START {
                    // A skippable frame: skip it.
                    let skippable_size = read_skippable_frame_size(frame_src)?;
                    src_pos += skippable_size;
                    continue;
                }
            }

            let frame_dict = if ddict.is_some() {
                self.frame_begin_using_ddict(ddict)
            } else {
                // With no dictionary too.
                self.frame_begin_using_dict(dict)?
            };
            self.check_continuity(dst, op, dst.len() - op);

            match self.decompress_frame(dst, op, frame_src, frame_dict) {
                Err(error) if error.code() == ErrorCode::PrefixUnknown && more_than_1_frame => {
                    // After a frame, bytes that are not a frame more likely
                    // mean the input size is wrong.
                    return error!(SrcSizeWrong);
                }
                Err(error) => return Err(error),
                Ok((decoded, consumed)) => {
                    op += decoded;
                    src_pos += consumed;
                }
            }
            more_than_1_frame = true;
        }

        if src_pos != src.len() {
            // Input left over.
            return error!(SrcSizeWrong);
        }
        Ok(op)
    }

    /// `ZSTD_getDDict`: the dictionary for the next frame.
    fn get_ddict(&mut self) -> Option<Arc<DDict>> {
        match self.dict_uses {
            DictUses::DontUse => {
                self.clear_dict();
                None
            }
            DictUses::Indefinitely => self.ddict.clone(),
            DictUses::Once => {
                self.dict_uses = DictUses::DontUse;
                self.ddict.clone()
            }
        }
    }

    /// `ZSTD_clearDict`
    fn clear_dict(&mut self) {
        self.ddict = None;
        self.dict_uses = DictUses::DontUse;
    }

    /// `ZSTD_decompressDCtx`: decodes the frames in `src` to `dst`, with the
    /// dictionary loaded or referenced, if any. Returns the size decoded.
    ///
    /// `src` must hold whole frames (and skippable frames), and nothing else.
    pub fn decompress(&mut self, dst: &mut [u8], src: &[u8]) -> Result<usize> {
        let ddict = self.get_ddict();
        self.decompress_multi_frame(dst, src, None, ddict.as_deref())
    }

    /// `ZSTD_decompress_usingDict`: decodes with `dict`, a zstd dictionary
    /// or raw content, read anew for each frame.
    pub fn decompress_using_dict(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        dict: &[u8],
    ) -> Result<usize> {
        self.decompress_multi_frame(dst, src, Some(dict), None)
    }

    /// `ZSTD_decompress_usingDDict`: decodes with a dictionary prepared
    /// once.
    pub fn decompress_using_ddict(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        ddict: &DDict,
    ) -> Result<usize> {
        self.decompress_multi_frame(dst, src, None, Some(ddict))
    }

    /// `ZSTD_DCtx_loadDictionary_advanced`, by copy: the dictionary for the
    /// frames that follow.
    pub fn load_dictionary_advanced(
        &mut self,
        dict: &[u8],
        content_type: DictContentType,
    ) -> Result<()> {
        if self.stream_stage != DStreamStage::Init {
            return error!(StageWrong);
        }
        self.clear_dict();
        if !dict.is_empty() {
            // libzstd reports any failure here as an allocation failure.
            let Ok(ddict) = DDict::with_content_type(dict, content_type) else {
                return error!(MemoryAllocation);
            };
            self.ddict = Some(Arc::new(ddict));
            self.dict_uses = DictUses::Indefinitely;
        }
        Ok(())
    }

    /// `ZSTD_DCtx_loadDictionary`: the dictionary for the frames that
    /// follow, copied in. An empty one means none.
    pub fn load_dictionary(&mut self, dict: &[u8]) -> Result<()> {
        self.load_dictionary_advanced(dict, DictContentType::Auto)
    }

    /// `ZSTD_DCtx_refPrefix`: raw content to use as the window for the next
    /// frame only. libzstd references it; the port copies it.
    pub fn ref_prefix(&mut self, prefix: &[u8]) -> Result<()> {
        self.load_dictionary_advanced(prefix, DictContentType::RawContent)?;
        self.dict_uses = DictUses::Once;
        Ok(())
    }

    /// `ZSTD_DCtx_refDDict`: the dictionary for the frames that follow, or
    /// none. With [`DParameter::RefMultipleDDicts`] on, each one referenced
    /// is kept, and a frame uses the one it names.
    pub fn ref_ddict(&mut self, ddict: Option<Arc<DDict>>) -> Result<()> {
        if self.stream_stage != DStreamStage::Init {
            return error!(StageWrong);
        }
        self.clear_dict();
        if let Some(ddict) = ddict {
            self.ddict = Some(ddict.clone());
            self.dict_uses = DictUses::Indefinitely;
            if self.ref_multiple_ddicts {
                self.ddict_set
                    .get_or_insert_with(DDictHashSet::new)
                    .add(ddict)?;
            }
        }
        Ok(())
    }

    /// `ZSTD_DCtx_setMaxWindowSize`: the largest window the context accepts
    /// when streaming.
    pub fn set_max_window_size(&mut self, max_window_size: usize) -> Result<()> {
        let min = 1usize << ZSTD_WINDOWLOG_ABSOLUTEMIN;
        let max = 1usize << WINDOWLOG_MAX;
        if self.stream_stage != DStreamStage::Init {
            return error!(StageWrong);
        }
        if max_window_size < min || max_window_size > max {
            return error!(ParameterOutOfBound);
        }
        self.max_window_size = max_window_size;
        Ok(())
    }

    /// `ZSTD_DCtx_setParameter`
    pub fn set_parameter(&mut self, parameter: DParameter) -> Result<()> {
        if self.stream_stage != DStreamStage::Init {
            return error!(StageWrong);
        }
        match parameter {
            DParameter::WindowLogMax(value) => {
                let value = if value == 0 {
                    ZSTD_WINDOWLOG_LIMIT_DEFAULT
                } else {
                    value
                };
                if !(ZSTD_WINDOWLOG_ABSOLUTEMIN..=WINDOWLOG_MAX).contains(&value) {
                    return error!(ParameterOutOfBound);
                }
                self.max_window_size = 1 << value;
            }
            DParameter::Format(format) => self.format = format,
            DParameter::StableOutBuffer(stable) => self.stable_out_buffer = stable,
            DParameter::ForceIgnoreChecksum(ignore) => self.force_ignore_checksum = ignore,
            DParameter::RefMultipleDDicts(multiple) => self.ref_multiple_ddicts = multiple,
            DParameter::DisableHuffmanAssembly(disable) => self.disable_huf_asm = disable,
            DParameter::MaxBlockSize(value) => {
                if value != 0 && !(BLOCKSIZE_MAX_MIN..=ZSTD_BLOCKSIZE_MAX as u32).contains(&value) {
                    return error!(ParameterOutOfBound);
                }
                self.max_block_size_param = value;
            }
        }
        Ok(())
    }

    /// `ZSTD_DCtx_getParameter`, as libzstd's integer value.
    pub fn get_parameter(&self, parameter: DParameterKind) -> i32 {
        match parameter {
            DParameterKind::WindowLogMax => {
                (usize::BITS - 1 - self.max_window_size.leading_zeros()) as i32
            }
            DParameterKind::Format => match self.format {
                Format::Zstd1 => 0,
                Format::Zstd1Magicless => 1,
            },
            DParameterKind::StableOutBuffer => i32::from(self.stable_out_buffer),
            DParameterKind::ForceIgnoreChecksum => i32::from(self.force_ignore_checksum),
            DParameterKind::RefMultipleDDicts => i32::from(self.ref_multiple_ddicts),
            DParameterKind::DisableHuffmanAssembly => i32::from(self.disable_huf_asm),
            DParameterKind::MaxBlockSize => self.max_block_size_param as i32,
        }
    }

    /// `ZSTD_DCtx_reset`
    pub fn reset(&mut self, reset: ResetDirective) -> Result<()> {
        if matches!(
            reset,
            ResetDirective::SessionOnly | ResetDirective::SessionAndParameters
        ) {
            self.stream_stage = DStreamStage::Init;
            self.no_forward_progress = 0;
            self.is_frame_decompression = true;
        }
        if matches!(
            reset,
            ResetDirective::Parameters | ResetDirective::SessionAndParameters
        ) {
            if self.stream_stage != DStreamStage::Init {
                return error!(StageWrong);
            }
            self.clear_dict();
            // ZSTD_DCtx_resetParameters
            self.format = Format::Zstd1;
            self.max_window_size = ZSTD_MAXWINDOWSIZE_DEFAULT;
            self.stable_out_buffer = false;
            self.force_ignore_checksum = false;
            self.ref_multiple_ddicts = false;
            self.disable_huf_asm = false;
            self.max_block_size_param = 0;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Streaming
// ---------------------------------------------------------------------------

/// `ZSTD_NO_FORWARD_PROGRESS_MAX`: how many calls in a row may neither read
/// nor write before [`DCtx::decompress_stream`] fails.
const ZSTD_NO_FORWARD_PROGRESS_MAX: u32 = 16;
/// `ZSTD_WORKSPACETOOLARGE_FACTOR`: buffers this many times larger than a
/// frame needs are too large...
const ZSTD_WORKSPACETOOLARGE_FACTOR: usize = 3;
/// `ZSTD_WORKSPACETOOLARGE_MAXDURATION`: ...for this many frames in a row,
/// after which they shrink.
const ZSTD_WORKSPACETOOLARGE_MAXDURATION: usize = 128;

/// `ZSTD_inBuffer`: input for [`DCtx::decompress_stream`], read from `pos`
/// on.
#[derive(Clone, Copy, Debug)]
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

/// `ZSTD_outBuffer`: where [`DCtx::decompress_stream`] writes, from `pos`
/// on.
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

impl OutBufferId {
    fn of(output: &OutBuffer<'_>) -> OutBufferId {
        OutBufferId {
            address: output.dst.as_ptr() as usize,
            size: output.dst.len(),
            pos: output.pos,
        }
    }
}

/// `ZSTD_DStreamInSize`: the input size that suits
/// [`DCtx::decompress_stream`] best, a whole block with its header.
pub const fn dstream_in_size() -> usize {
    ZSTD_BLOCKSIZE_MAX + ZSTD_BLOCKHEADERSIZE
}

/// `ZSTD_DStreamOutSize`: an output size that holds any block, so that
/// each call can flush one.
pub const fn dstream_out_size() -> usize {
    ZSTD_BLOCKSIZE_MAX
}

/// `ZSTD_decodingBufferSize_internal`
fn decoding_buffer_size_internal(
    window_size: u64,
    frame_content_size: u64,
    block_size_max: usize,
) -> Result<usize> {
    let block_size = (window_size.min(ZSTD_BLOCKSIZE_MAX as u64) as usize).min(block_size_max);
    // A block and WILDCOPY_OVERLENGTH bytes past the window, so that a
    // block ending there can start again at the buffer's start and still
    // keep a whole window; and another block, so that split literals at the
    // end of a block do not overwrite the older part of the window.
    let needed_rb_size = window_size
        .wrapping_add(block_size as u64 * 2)
        .wrapping_add(WILDCOPY_OVERLENGTH as u64 * 2);
    let needed_size = frame_content_size.min(needed_rb_size);
    match usize::try_from(needed_size) {
        Ok(min_rb_size) => Ok(min_rb_size),
        Err(_) => error!(FrameParameterWindowTooLarge),
    }
}

/// `ZSTD_decodingBufferSize_min`: the buffer [`DCtx::decompress_stream`]
/// keeps for a frame with this window and content size (unless the output
/// buffer is stable).
pub fn decoding_buffer_size_min(window_size: u64, frame_content_size: u64) -> Result<usize> {
    decoding_buffer_size_internal(window_size, frame_content_size, ZSTD_BLOCKSIZE_MAX)
}

impl DCtx {
    /// `ZSTD_nextSrcSizeToDecompressWithInputSize`: the input the stage
    /// needs. A stored block can be taken in pieces, as much as there is.
    fn next_src_size_to_decompress_with_input_size(&self, input_size: usize) -> usize {
        if !matches!(
            self.stage,
            DStage::DecompressBlock | DStage::DecompressLastBlock
        ) {
            return self.expected;
        }
        if self.b_type != BlockType::Raw {
            return self.expected;
        }
        input_size.min(self.expected).max(1)
    }

    /// `ZSTD_isSkipFrame`
    fn is_skip_frame(&self) -> bool {
        self.stage == DStage::SkipFrame
    }

    /// `ZSTD_checkContinuity`, while streaming: output written anywhere but
    /// where the previous output ended starts a new segment of the window,
    /// and the current one becomes the older one.
    ///
    /// The addresses libzstd compares are tracked for `ddictIsCold`; the
    /// window itself is decided on positions in `out`, the buffer of the
    /// whole frame. The two agree, unless another buffer happens to end
    /// right where `out` starts.
    fn check_continuity_stream(&mut self, out: &[u8], dst: usize, dst_size: usize) {
        if dst_size == 0 {
            return;
        }
        let dst_address = address(out, dst);
        if dst_address != self.previous_dst_end {
            self.dict_end = self.previous_dst_end;
            self.previous_dst_end = dst_address;
        }
        if !matches!(self.stream_prefix, Segment::Out { end, .. } if end == dst) {
            self.stream_ext = self.stream_prefix;
            self.stream_prefix = Segment::Out {
                start: dst,
                end: dst,
            };
        }
    }

    /// The compressed block of `ZSTD_decompressContinue`: decodes `src` to
    /// `out[dst..]`, with the window as the stream left it.
    fn decompress_stream_block(
        &mut self,
        out: &mut [u8],
        dst: usize,
        dst_capacity: usize,
        src: &[u8],
    ) -> Result<usize> {
        let ddict = self.frame_ddict.clone();
        let ext = match self.stream_ext {
            Segment::None => ExtDict::None,
            Segment::Dict => ddict
                .as_deref()
                .map_or(ExtDict::None, |ddict| ExtDict::Separate(&ddict.content)),
            Segment::Out { start, end } => ExtDict::InOut { start, end },
        };
        let prefix_start = match self.stream_prefix {
            Segment::Out { start, .. } => start,
            // Only before any output, when there is no room for any.
            Segment::None | Segment::Dict => dst,
        };
        let mut bo = BlockOut {
            out,
            dst,
            dst_capacity,
            prefix_start,
            ext,
            dict: ddict
                .as_deref()
                .filter(|ddict| ddict.entropy_present)
                .map(|ddict| &*ddict.entropy),
        };
        decompress_block_internal(self, &mut bo, src, true)
    }

    /// `ZSTD_decompressContinue`, as the streaming decoder calls it: decodes
    /// `src`, exactly the input the stage expects, to
    /// `out[dst..dst + dst_capacity]`. Returns the size decoded.
    ///
    /// `src_size` is the size of `src`, except for the content of a
    /// skippable frame, which libzstd counts without reading it: the
    /// streaming decoder does not keep it, and passes no bytes.
    fn decompress_continue_internal(
        &mut self,
        out: &mut [u8],
        dst: usize,
        dst_capacity: usize,
        src: &[u8],
        src_size: usize,
    ) -> Result<usize> {
        debug_assert!(src.len() == src_size || self.is_skip_frame());
        if src_size != self.next_src_size_to_decompress_with_input_size(src_size) {
            return error!(SrcSizeWrong);
        }
        self.check_continuity_stream(out, dst, dst_capacity);

        self.processed_c_size += src_size as u64;

        match self.stage {
            DStage::GetFrameHeaderSize => {
                // A skippable frame? The stream decoder reads headers on its
                // own, so only a frame begun by the one-call functions ends
                // up here.
                if self.format == Format::Zstd1
                    && src.len() >= ZSTD_FRAMEIDSIZE
                    && (read_le32(src, 0) & ZSTD_MAGIC_SKIPPABLE_MASK) == ZSTD_MAGIC_SKIPPABLE_START
                {
                    self.header_buffer[..src.len()].copy_from_slice(src);
                    // What is left of the skippable frame header.
                    self.expected = SKIPPABLE_HEADER_SIZE - src.len();
                    self.stage = DStage::DecodeSkippableHeader;
                    return Ok(0);
                }
                self.header_size = frame_header_size_internal(src, self.format)?;
                self.header_buffer[..src.len()].copy_from_slice(src);
                self.expected = self.header_size - src.len();
                self.stage = DStage::DecodeFrameHeader;
                Ok(0)
            }

            DStage::DecodeFrameHeader => {
                self.header_buffer[self.header_size - src.len()..self.header_size]
                    .copy_from_slice(src);
                let header = self.header_buffer;
                self.decode_frame_header(&header[..self.header_size])?;
                self.expected = ZSTD_BLOCKHEADERSIZE;
                self.stage = DStage::DecodeBlockHeader;
                Ok(0)
            }

            DStage::DecodeBlockHeader => {
                let mut bp = BlockProperties {
                    block_type: BlockType::Raw,
                    last_block: false,
                    orig_size: 0,
                };
                let c_block_size = get_c_block_size(src, &mut bp)?;
                if c_block_size > self.f_params.block_size_max as usize {
                    // Larger than the frame allows.
                    return error!(CorruptionDetected);
                }
                self.expected = c_block_size;
                self.b_type = bp.block_type;
                self.rle_size = bp.orig_size;
                if c_block_size != 0 {
                    self.stage = if bp.last_block {
                        DStage::DecompressLastBlock
                    } else {
                        DStage::DecompressBlock
                    };
                    return Ok(0);
                }
                // An empty block. As in libzstd, an empty last block ends the
                // frame without checking its content size.
                if bp.last_block {
                    if self.f_params.checksum_flag {
                        self.expected = 4;
                        self.stage = DStage::CheckChecksum;
                    } else {
                        // The end of the frame.
                        self.expected = 0;
                        self.stage = DStage::GetFrameHeaderSize;
                    }
                } else {
                    // On to the next block header.
                    self.expected = ZSTD_BLOCKHEADERSIZE;
                    self.stage = DStage::DecodeBlockHeader;
                }
                Ok(0)
            }

            DStage::DecompressBlock | DStage::DecompressLastBlock => {
                let r_size = match self.b_type {
                    BlockType::Compressed => {
                        debug_assert!(self.is_frame_decompression);
                        let r_size = self.decompress_stream_block(out, dst, dst_capacity, src);
                        // A compressed block comes whole. As in libzstd, this
                        // holds after an error too.
                        self.expected = 0;
                        r_size?
                    }
                    BlockType::Raw => {
                        // ZSTD_copyRawBlock
                        debug_assert!(src.len() <= self.expected);
                        if src.len() > dst_capacity {
                            return error!(DstSizeTooSmall);
                        }
                        out[dst..dst + src.len()].copy_from_slice(src);
                        self.expected -= src.len();
                        src.len()
                    }
                    BlockType::Rle => {
                        // ZSTD_setRleBlock
                        let regen_size = self.rle_size as usize;
                        self.expected = 0;
                        if regen_size > dst_capacity {
                            return error!(DstSizeTooSmall);
                        }
                        out[dst..dst + regen_size].fill(src[0]);
                        regen_size
                    }
                    BlockType::Reserved => return error!(CorruptionDetected),
                };
                if r_size > self.f_params.block_size_max as usize {
                    // Decoded to more than the frame allows.
                    return error!(CorruptionDetected);
                }
                self.decoded_size += r_size as u64;
                if self.validate_checksum {
                    self.xxh_state.update(&out[dst..dst + r_size]);
                }
                self.previous_dst_end = address(out, dst + r_size);
                if let Segment::Out { end, .. } = &mut self.stream_prefix
                    && *end == dst
                {
                    *end = dst + r_size;
                }

                // Stay on this stage until the stored block is all in.
                if self.expected > 0 {
                    return Ok(r_size);
                }

                if self.stage == DStage::DecompressLastBlock {
                    // The end of the frame.
                    if self.f_params.frame_content_size != CONTENTSIZE_UNKNOWN
                        && self.decoded_size != self.f_params.frame_content_size
                    {
                        return error!(CorruptionDetected);
                    }
                    if self.f_params.checksum_flag {
                        // Then the frame's checksum.
                        self.expected = 4;
                        self.stage = DStage::CheckChecksum;
                    } else {
                        self.expected = 0;
                        self.stage = DStage::GetFrameHeaderSize;
                    }
                } else {
                    self.stage = DStage::DecodeBlockHeader;
                    self.expected = ZSTD_BLOCKHEADERSIZE;
                }
                Ok(r_size)
            }

            DStage::CheckChecksum => {
                if self.validate_checksum {
                    let h32 = self.xxh_state.digest() as u32;
                    let check32 = read_le32(src, 0);
                    if check32 != h32 {
                        return error!(ChecksumWrong);
                    }
                }
                self.expected = 0;
                self.stage = DStage::GetFrameHeaderSize;
                Ok(0)
            }

            DStage::DecodeSkippableHeader => {
                debug_assert!(src.len() <= SKIPPABLE_HEADER_SIZE);
                self.header_buffer[SKIPPABLE_HEADER_SIZE - src.len()..SKIPPABLE_HEADER_SIZE]
                    .copy_from_slice(src);
                // The content's size, which can be far larger than any buffer.
                self.expected = read_le32(&self.header_buffer, ZSTD_FRAMEIDSIZE) as usize;
                self.stage = DStage::SkipFrame;
                Ok(0)
            }

            DStage::SkipFrame => {
                self.expected = 0;
                self.stage = DStage::GetFrameHeaderSize;
                Ok(0)
            }
        }
    }

    /// `ZSTD_decompressBegin`: starts a frame for
    /// [`DCtx::decompress_continue`], without a dictionary.
    pub fn decompress_begin(&mut self) {
        self.decompress_begin_internal();
        self.bufferless.begun = true;
    }

    /// `ZSTD_decompressBegin_usingDict`: starts a frame for
    /// [`DCtx::decompress_continue`] with `dict`: a zstd dictionary, or raw
    /// content (one without the dictionary magic number, or under 8
    /// bytes). An empty one means none. Fails with
    /// [`ErrorCode::DictionaryCorrupted`] for a zstd dictionary whose
    /// tables cannot be read.
    ///
    /// libzstd references the dictionary; the port copies it. Where it lies
    /// still counts: output that starts right where `dict` ends in memory
    /// continues its content, as in libzstd.
    pub fn decompress_begin_using_dict(&mut self, dict: &[u8]) -> Result<()> {
        self.decompress_begin();
        if dict.is_empty() {
            return Ok(());
        }
        // The tables into the context's own, as libzstd loads them; the
        // content after them, which is all the window has of it, copied.
        let Ok(content) = self.insert_dictionary(dict) else {
            return error!(DictionaryCorrupted);
        };
        let content = DDict::with_content_type(content, DictContentType::RawContent)?;
        self.frame_ddict = Some(Arc::new(content));
        // prefixStart and virtualStart at the content's start.
        self.stream_prefix = Segment::Dict;
        self.stream_ext = Segment::None;
        self.bufferless.caller_end = address(dict, dict.len());
        Ok(())
    }

    /// `ZSTD_decompressBegin_usingDDict`: starts a frame for
    /// [`DCtx::decompress_continue`] with `ddict`.
    pub fn decompress_begin_using_ddict(&mut self, ddict: Arc<DDict>) {
        // As in ZSTD_decompressBegin_usingDDict: a dictionary other than the
        // one just used is presumably not in the processor's cache.
        let content_end = address(&ddict.content, ddict.content.len());
        self.ddict_is_cold = self.dict_end != content_end;
        self.decompress_begin();
        self.copy_ddict_parameters(&ddict);
        self.frame_ddict = Some(ddict);
        self.bufferless.caller_end = content_end;
    }

    /// `ZSTD_nextSrcSizeToDecompress`: how many bytes the next call of
    /// [`DCtx::decompress_continue`] takes: exactly that many, or, in a
    /// stored block, from 1 byte up to that many. 0 once the frame is
    /// decoded.
    pub fn next_src_size_to_decompress(&self) -> usize {
        self.expected
    }

    /// `ZSTD_nextInputType`: what the next call of
    /// [`DCtx::decompress_continue`] reads.
    pub fn next_input_type(&self) -> NextInputType {
        match self.stage {
            DStage::GetFrameHeaderSize | DStage::DecodeFrameHeader => NextInputType::FrameHeader,
            DStage::DecodeBlockHeader => NextInputType::BlockHeader,
            DStage::DecompressBlock => NextInputType::Block,
            DStage::DecompressLastBlock => NextInputType::LastBlock,
            DStage::CheckChecksum => NextInputType::Checksum,
            DStage::DecodeSkippableHeader | DStage::SkipFrame => NextInputType::SkippableFrame,
        }
    }

    /// `ZSTD_decompressContinue`: decodes `src`, the next piece of the frame
    /// begun with [`DCtx::decompress_begin`] (or its variants), of the size
    /// [`DCtx::next_src_size_to_decompress`] gives, into `dst`. Returns how
    /// much it wrote there: 0 for a header or a checksum, and for each
    /// piece of a skippable frame, whose content it skips. The frame is
    /// decoded when [`DCtx::next_src_size_to_decompress`] gives 0; begin
    /// again for the next.
    ///
    /// Wrong sizes fail with [`ErrorCode::SrcSizeWrong`], room too small
    /// for a block with [`ErrorCode::DstSizeTooSmall`], and a context that
    /// was not begun so, or that was used since for other decompression,
    /// with [`ErrorCode::StageWrong`] (where libzstd reads whatever state
    /// it holds). After an error, begin again.
    ///
    /// The window, as in libzstd, is the output since the last call whose
    /// `dst` did not start where the previous one's output ended in memory,
    /// and the one segment before it: output decoded each time into a new
    /// buffer has only the last call's before it, where a frame's matches
    /// may reach further back and fail with
    /// [`ErrorCode::CorruptionDetected`]. A round buffer of
    /// [`decoding_buffer_size_min`] bytes, written from its start again
    /// when what is left of it is less than a block, keeps the window.
    ///
    /// Differs from libzstd: libzstd reads the window in the caller's
    /// memory; the port keeps a copy of it, of at least the frame's window
    /// size and a block, and decodes each block there before copying it to
    /// `dst`. A damaged frame whose matches reach further back than its
    /// window, or into output the caller has written over since, decodes
    /// differently, or fails with [`ErrorCode::CorruptionDetected`] where
    /// libzstd reads that memory. A damaged compressed block that decodes
    /// to more than the frame's block size fails with
    /// [`ErrorCode::CorruptionDetected`]; libzstd, given more room than
    /// that, may decode on to the end of `dst` first and fail with
    /// [`ErrorCode::DstSizeTooSmall`].
    pub fn decompress_continue(&mut self, dst: &mut [u8], src: &[u8]) -> Result<usize> {
        if !self.bufferless.begun {
            return error!(StageWrong);
        }
        if src.len() != self.next_src_size_to_decompress_with_input_size(src.len()) {
            return error!(SrcSizeWrong);
        }
        // ZSTD_checkContinuity, on the caller's addresses.
        let at = address(dst, 0);
        if !dst.is_empty() {
            if at != self.bufferless.caller_end {
                self.bufferless_new_segment();
                self.bufferless.caller_end = at;
            } else if self.stream_prefix == Segment::Dict
                && let Some(ddict) = &self.frame_ddict
            {
                // The output follows the dictionary's content in memory:
                // one segment.
                let content = &ddict.content;
                let window = &mut self.bufferless.window;
                if window.len() < content.len() {
                    window.resize(content.len(), 0);
                }
                window[..content.len()].copy_from_slice(content);
                self.bufferless.end = content.len();
                self.stream_prefix = Segment::Out {
                    start: 0,
                    end: content.len(),
                };
                self.stream_ext = Segment::None;
            }
        }

        // The room the piece can write, in the copy of the window: a block
        // at most, or what a stored or RLE block says.
        let in_block = matches!(
            self.stage,
            DStage::DecompressBlock | DStage::DecompressLastBlock
        );
        let compressed = in_block && self.b_type == BlockType::Compressed;
        let room = if !in_block {
            0
        } else {
            match self.b_type {
                BlockType::Compressed => self.f_params.block_size_max as usize,
                BlockType::Rle => self.rle_size as usize,
                BlockType::Raw | BlockType::Reserved => src.len(),
            }
            .min(dst.len())
        };
        let end = self.bufferless.end;
        let mut window = std::mem::take(&mut self.bufferless.window);
        if window.len() < end + room {
            window.resize(end + room, 0);
        }
        let result =
            self.decompress_continue_internal(&mut window[..end + room], end, room, src, src.len());
        let result = match result {
            Ok(size) => {
                dst[..size].copy_from_slice(&window[end..end + size]);
                if in_block {
                    self.bufferless.end = end + size;
                    self.bufferless.caller_end = at.wrapping_add(size);
                }
                Ok(size)
            }
            // libzstd decodes on into the larger room; past the block size,
            // the block is damaged.
            Err(error)
                if compressed && error.code() == ErrorCode::DstSizeTooSmall && dst.len() > room =>
            {
                error!(CorruptionDetected)
            }
            Err(error) => Err(error),
        };
        self.bufferless.window = window;
        if in_block {
            self.bufferless_trim();
        }
        result
    }

    /// `ZSTD_checkContinuity`, for [`DCtx::decompress_continue`]: output
    /// elsewhere than where the last ended starts a new segment of the
    /// window, and the current one becomes the older one.
    fn bufferless_new_segment(&mut self) {
        match self.stream_prefix {
            Segment::Out { start, end } => {
                // The older segment before it is gone.
                self.bufferless.window.copy_within(start..end, 0);
                let len = end - start;
                self.stream_ext = Segment::Out { start: 0, end: len };
                self.stream_prefix = Segment::Out {
                    start: len,
                    end: len,
                };
                self.bufferless.end = len;
            }
            older => {
                // The dictionary's content, or nothing.
                self.stream_ext = older;
                self.stream_prefix = Segment::Out { start: 0, end: 0 };
                self.bufferless.end = 0;
            }
        }
    }

    /// Drops the oldest part of the copy of the window, beyond the frame's
    /// window size and a block, once it holds twice that (and at least
    /// 1 MB).
    fn bufferless_trim(&mut self) {
        let keep = usize::try_from(self.f_params.window_size)
            .unwrap_or(usize::MAX)
            .saturating_add(self.f_params.block_size_max as usize);
        let end = self.bufferless.end;
        if end <= keep.saturating_mul(2).max(1 << 20) {
            return;
        }
        let drop = end - keep;
        #[cfg(test)]
        BUFFERLESS_TRIMS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.bufferless.window.copy_within(drop..end, 0);
        self.bufferless.end = keep;
        let shift = |segment: Segment| match segment {
            Segment::Out { end, .. } if end <= drop => Segment::None,
            Segment::Out { start, end } => Segment::Out {
                start: start.saturating_sub(drop),
                end: end - drop,
            },
            other => other,
        };
        self.stream_ext = shift(self.stream_ext);
        self.stream_prefix = shift(self.stream_prefix);
    }

    /// `ZSTD_DCtx_updateOversizedDuration`: counts the frames in a row for
    /// which the buffers are much larger than needed.
    fn update_oversized_duration(
        &mut self,
        needed_in_buff_size: usize,
        needed_out_buff_size: usize,
    ) {
        // ZSTD_DCtx_isOverflow
        let held = self.in_buff.len().wrapping_add(self.out_buff.len());
        let needed = needed_in_buff_size.wrapping_add(needed_out_buff_size);
        if held >= needed.wrapping_mul(ZSTD_WORKSPACETOOLARGE_FACTOR) {
            self.oversized_duration += 1;
        } else {
            self.oversized_duration = 0;
        }
    }

    /// `ZSTD_checkOutBuffer`: with a stable output buffer, each call of a
    /// frame must get the buffer the previous call left, at the same
    /// position.
    fn check_out_buffer(&self, output: &OutBuffer<'_>) -> Result<()> {
        if !self.stable_out_buffer {
            return Ok(());
        }
        // Any buffer can start a frame.
        if self.stream_stage == DStreamStage::Init {
            return Ok(());
        }
        if self.expected_out_buffer == OutBufferId::of(output) {
            return Ok(());
        }
        error!(DstBufferWrong)
    }

    /// `ZSTD_decompressContinueStream`: decodes `src` (see
    /// [`DCtx::decompress_continue`] for `src_size`) into the context's
    /// buffer, or straight into `dst[*op..oend]` when the output buffer is
    /// stable, and moves on to the stage that follows.
    fn decompress_continue_stream(
        &mut self,
        dst: &mut [u8],
        op: &mut usize,
        oend: usize,
        src: &[u8],
        src_size: usize,
    ) -> Result<()> {
        let is_skip_frame = self.is_skip_frame();
        if !self.stable_out_buffer {
            let dst_size = if is_skip_frame {
                0
            } else {
                self.out_buff.len() - self.out_start
            };
            let mut out_buff = std::mem::take(&mut self.out_buff);
            let decoded_size = self.decompress_continue_internal(
                &mut out_buff,
                self.out_start,
                dst_size,
                src,
                src_size,
            );
            self.out_buff = out_buff;
            let decoded_size = decoded_size?;
            if decoded_size == 0 && !is_skip_frame {
                self.stream_stage = DStreamStage::Read;
            } else {
                self.out_end = self.out_start + decoded_size;
                self.stream_stage = DStreamStage::Flush;
            }
        } else {
            // Straight into the output buffer.
            let dst_size = if is_skip_frame { 0 } else { oend - *op };
            let decoded_size =
                self.decompress_continue_internal(dst, *op, dst_size, src, src_size)?;
            *op += decoded_size;
            // Nothing to flush.
            self.stream_stage = DStreamStage::Read;
        }
        Ok(())
    }

    /// `ZSTD_decompressStream`: decodes as much of `input` to `output` as
    /// both allow, frame after frame, and moves their positions forward.
    ///
    /// Returns 0 when a frame is decoded and all of it flushed, at the end
    /// of that frame: the next call starts the next frame. Otherwise, a
    /// hint at how much input the next step needs (the rest of a block, and
    /// the next block's header), which the caller can ignore. Call again
    /// with more input, or more room in `output`: some output may still be
    /// held back, even when all the input is read.
    ///
    /// Unless [`DParameter::StableOutBuffer`] is set, the context keeps a
    /// window of output of its own, as large as the frame's window plus
    /// two blocks (at most the frame's content size), so `output` can be of
    /// any size, and a different buffer at each call.
    ///
    /// After an error the context is in no state to go on: reset it with
    /// [`DCtx::reset`] before the next frame.
    ///
    /// Differs from libzstd: when the call fails, `input.pos` and
    /// `output.pos` are left as they were. libzstd leaves them too, but
    /// for one error, about the first bytes of a header, where it marks
    /// the input as read.
    pub fn decompress_stream(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
    ) -> Result<usize> {
        let (in_pos, out_pos) = (input.pos, output.pos);
        let result = self.decompress_stream_internal(output, input);
        if result.is_err() {
            input.pos = in_pos;
            output.pos = out_pos;
        }
        result
    }

    /// `ZSTD_decompressStream`, leaving the positions where libzstd leaves
    /// them when it fails.
    pub(crate) fn decompress_stream_internal(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
    ) -> Result<usize> {
        let src = input.src;
        let istart = input.pos;
        let iend = src.len();
        let mut ip = istart;
        let ostart = output.pos;
        let oend = output.dst.len();
        let mut op = ostart;
        let mut some_more_work = true;

        if input.pos > input.src.len() {
            return error!(SrcSizeWrong);
        }
        if output.pos > output.dst.len() {
            return error!(DstSizeTooSmall);
        }
        self.check_out_buffer(output)?;

        while some_more_work {
            match self.stream_stage {
                DStreamStage::Init => {
                    // A transparent reset.
                    self.stream_stage = DStreamStage::LoadHeader;
                    self.lh_size = 0;
                    self.in_pos = 0;
                    self.out_start = 0;
                    self.out_end = 0;
                    self.hostage_byte = false;
                    self.expected_out_buffer = OutBufferId::of(output);
                }

                DStreamStage::LoadHeader => {
                    let header = self.header_buffer;
                    let h_size = get_frame_header_into(
                        &mut self.f_params,
                        &header[..self.lh_size],
                        self.format,
                    );
                    if self.ref_multiple_ddicts && self.ddict_set.is_some() {
                        self.select_frame_ddict();
                    }
                    let h_size = h_size?;
                    if h_size != 0 {
                        // More input needed (h_size > lh_size).
                        let to_load = h_size - self.lh_size;
                        let remaining_input = iend - ip;
                        if to_load > remaining_input {
                            // Not enough for the whole header.
                            if remaining_input > 0 {
                                self.header_buffer[self.lh_size..self.lh_size + remaining_input]
                                    .copy_from_slice(&src[ip..iend]);
                                self.lh_size += remaining_input;
                            }
                            input.pos = input.src.len();
                            // Check the first few bytes.
                            let header = self.header_buffer;
                            get_frame_header_into(
                                &mut self.f_params,
                                &header[..self.lh_size],
                                self.format,
                            )?;
                            // The rest of the header, and the next block's.
                            return Ok(frame_header_size_min(self.format).max(h_size)
                                - self.lh_size
                                + ZSTD_BLOCKHEADERSIZE);
                        }
                        self.header_buffer[self.lh_size..h_size]
                            .copy_from_slice(&src[ip..ip + to_load]);
                        self.lh_size = h_size;
                        ip += to_load;
                        continue;
                    }

                    // The whole frame in one call, when the input holds it
                    // and the output has room for it.
                    if self.f_params.frame_content_size != CONTENTSIZE_UNKNOWN
                        && self.f_params.frame_type != FrameType::Skippable
                        && (oend - op) as u64 >= self.f_params.frame_content_size
                    {
                        // As in libzstd, from where this call's input starts.
                        if let Ok(info) = find_frame_size_info(&src[istart..iend], self.format)
                            && info.compressed_size <= iend - istart
                        {
                            let c_size = info.compressed_size;
                            let ddict = self.get_ddict();
                            let decompressed_size = self.decompress_multi_frame(
                                &mut output.dst[op..oend],
                                &src[istart..istart + c_size],
                                None,
                                ddict.as_deref(),
                            )?;
                            ip = istart + c_size;
                            op += decompressed_size;
                            self.expected = 0;
                            self.stream_stage = DStreamStage::Init;
                            some_more_work = false;
                            continue;
                        }
                    }

                    // A stable output buffer must hold the whole frame.
                    if self.stable_out_buffer
                        && self.f_params.frame_type != FrameType::Skippable
                        && self.f_params.frame_content_size != CONTENTSIZE_UNKNOWN
                        && ((oend - op) as u64) < self.f_params.frame_content_size
                    {
                        return error!(DstSizeTooSmall);
                    }

                    // Take in the header (see DStage::DecodeFrameHeader).
                    let ddict = self.get_ddict();
                    self.frame_begin_using_ddict(ddict.as_deref());
                    self.frame_ddict = ddict;

                    if self.format == Format::Zstd1
                        && (read_le32(&self.header_buffer, 0) & ZSTD_MAGIC_SKIPPABLE_MASK)
                            == ZSTD_MAGIC_SKIPPABLE_START
                    {
                        // A skippable frame.
                        self.expected = read_le32(&self.header_buffer, ZSTD_FRAMEIDSIZE) as usize;
                        self.stage = DStage::SkipFrame;
                    } else {
                        let header = self.header_buffer;
                        self.decode_frame_header(&header[..self.lh_size])?;
                        self.expected = ZSTD_BLOCKHEADERSIZE;
                        self.stage = DStage::DecodeBlockHeader;
                    }

                    // Bound the memory used.
                    self.f_params.window_size = self
                        .f_params
                        .window_size
                        .max(1 << ZSTD_WINDOWLOG_ABSOLUTEMIN);
                    if self.f_params.window_size > self.max_window_size as u64 {
                        return error!(FrameParameterWindowTooLarge);
                    }
                    if self.max_block_size_param != 0 {
                        self.f_params.block_size_max =
                            self.f_params.block_size_max.min(self.max_block_size_param);
                    }

                    // Buffers as large as the frame needs.
                    let needed_in_buff_size = (self.f_params.block_size_max as usize).max(4);
                    let needed_out_buff_size = if self.stable_out_buffer {
                        0
                    } else {
                        decoding_buffer_size_internal(
                            self.f_params.window_size,
                            self.f_params.frame_content_size,
                            self.f_params.block_size_max as usize,
                        )?
                    };
                    self.update_oversized_duration(needed_in_buff_size, needed_out_buff_size);
                    let too_small = self.in_buff.len() < needed_in_buff_size
                        || self.out_buff.len() < needed_out_buff_size;
                    let too_large = self.oversized_duration >= ZSTD_WORKSPACETOOLARGE_MAXDURATION;
                    if too_small || too_large {
                        // The old buffers go first, as in libzstd.
                        self.in_buff = Vec::new();
                        self.out_buff = Vec::new();
                        self.in_buff = vec![0; needed_in_buff_size];
                        self.out_buff = vec![0; needed_out_buff_size];
                    }
                    self.stream_stage = DStreamStage::Read;
                }

                DStreamStage::Read => {
                    let needed_in_size =
                        self.next_src_size_to_decompress_with_input_size(iend - ip);
                    if needed_in_size == 0 {
                        // The end of the frame.
                        self.stream_stage = DStreamStage::Init;
                        some_more_work = false;
                        continue;
                    }
                    if iend - ip >= needed_in_size {
                        // Straight from the input.
                        self.decompress_continue_stream(
                            output.dst,
                            &mut op,
                            oend,
                            &src[ip..ip + needed_in_size],
                            needed_in_size,
                        )?;
                        ip += needed_in_size;
                        continue;
                    }
                    if ip == iend {
                        // No more input.
                        some_more_work = false;
                        continue;
                    }
                    self.stream_stage = DStreamStage::Load;
                }

                DStreamStage::Load => {
                    let needed_in_size = self.expected;
                    // The part not loaded yet. libzstd's size_t wraps around
                    // if a one-call decompression ran in the middle of a
                    // stream; the check below then fails.
                    let to_load = needed_in_size.wrapping_sub(self.in_pos);
                    let is_skip_frame = self.is_skip_frame();
                    let loaded_size = to_load.min(iend - ip);
                    if !is_skip_frame {
                        if self.in_pos > self.in_buff.len()
                            || to_load > self.in_buff.len() - self.in_pos
                        {
                            // Should never happen.
                            return error!(CorruptionDetected);
                        }
                        self.in_buff[self.in_pos..self.in_pos + loaded_size]
                            .copy_from_slice(&src[ip..ip + loaded_size]);
                    }
                    ip += loaded_size;
                    self.in_pos += loaded_size;
                    if loaded_size < to_load {
                        // Not enough input: wait for more.
                        some_more_work = false;
                        continue;
                    }

                    // Decode what is loaded.
                    self.in_pos = 0;
                    let in_buff = std::mem::take(&mut self.in_buff);
                    let loaded: &[u8] = if is_skip_frame {
                        &[]
                    } else {
                        &in_buff[..needed_in_size]
                    };
                    let result = self.decompress_continue_stream(
                        output.dst,
                        &mut op,
                        oend,
                        loaded,
                        needed_in_size,
                    );
                    self.in_buff = in_buff;
                    result?;
                }

                DStreamStage::Flush => {
                    let to_flush_size = self.out_end - self.out_start;
                    let flushed_size = to_flush_size.min(oend - op);
                    output.dst[op..op + flushed_size].copy_from_slice(
                        &self.out_buff[self.out_start..self.out_start + flushed_size],
                    );
                    op += flushed_size;
                    self.out_start += flushed_size;
                    if flushed_size == to_flush_size {
                        // All flushed.
                        self.stream_stage = DStreamStage::Read;
                        if (self.out_buff.len() as u64) < self.f_params.frame_content_size
                            && self.out_start + self.f_params.block_size_max as usize
                                > self.out_buff.len()
                        {
                            // Too near the end for another block: start
                            // filling the buffer from its start again.
                            self.out_start = 0;
                            self.out_end = 0;
                        }
                        continue;
                    }
                    // The output is full.
                    some_more_work = false;
                }
            }
        }

        // The result.
        input.pos = ip;
        output.pos = op;

        // What a stable output buffer must be at the next call.
        self.expected_out_buffer = OutBufferId::of(output);

        if ip == istart && op == ostart {
            // No progress.
            self.no_forward_progress += 1;
            if self.no_forward_progress >= ZSTD_NO_FORWARD_PROGRESS_MAX {
                if op == oend {
                    return error!(NoForwardProgressDestFull);
                }
                if ip == iend {
                    return error!(NoForwardProgressInputEmpty);
                }
            }
        } else {
            self.no_forward_progress = 0;
        }

        let mut next_src_size_hint = self.expected;
        if next_src_size_hint == 0 {
            // The frame is decoded.
            if self.out_end == self.out_start {
                // And all of it flushed.
                if self.hostage_byte {
                    if input.pos >= input.src.len() {
                        // The hostage byte is not there to release.
                        self.stream_stage = DStreamStage::Read;
                        return Ok(1);
                    }
                    // Release it.
                    input.pos += 1;
                }
                return Ok(0);
            }
            if !self.hostage_byte {
                // Output is left to flush: keep the frame's last input byte
                // back until it is, so that the caller calls again. The
                // call that ended the frame read it, so there is one.
                input.pos = input.pos.saturating_sub(1);
                self.hostage_byte = true;
            }
            return Ok(1);
        }
        // Ask for the next block's header too.
        if self.stage == DStage::DecompressBlock {
            next_src_size_hint += ZSTD_BLOCKHEADERSIZE;
        }
        // Less what is already loaded.
        Ok(next_src_size_hint.wrapping_sub(self.in_pos))
    }

    /// `ZSTD_decompressStream_simpleArgs`: [`DCtx::decompress_stream`] with
    /// the buffers and positions as separate arguments.
    pub fn decompress_stream_simple_args(
        &mut self,
        dst: &mut [u8],
        dst_pos: &mut usize,
        src: &[u8],
        src_pos: &mut usize,
    ) -> Result<usize> {
        let mut output = OutBuffer { dst, pos: *dst_pos };
        let mut input = InBuffer { src, pos: *src_pos };
        let result = self.decompress_stream(&mut output, &mut input);
        *dst_pos = output.pos;
        *src_pos = input.pos;
        result
    }

    /// `ZSTD_initDStream`: abandons any frame being streamed and drops the
    /// dictionary. Returns the input size the first call needs at least.
    pub fn init_dstream(&mut self) -> Result<usize> {
        self.reset(ResetDirective::SessionOnly)?;
        self.ref_ddict(None)?;
        Ok(starting_input_length(self.format))
    }
}

/// `ZSTD_dParameter`, with its value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DParameter {
    /// The largest window to accept when streaming, as a power of 2; 0 for
    /// the default, 27 (128 MiB). One-call decompression is bounded by its
    /// output instead.
    WindowLogMax(u32),
    /// Frames with or without the magic number.
    Format(Format),
    /// When streaming, the output buffer stays the same between calls: the
    /// decoder then writes straight into it and keeps no window of its own.
    /// Each call of a frame must get the same buffer, at the position the
    /// previous call left (or fails with
    /// [`ErrorCode::DstBufferWrong`]), and the buffer must hold the whole
    /// frame.
    StableOutBuffer(bool),
    /// Do not check checksums.
    ForceIgnoreChecksum(bool),
    /// Keep every dictionary referenced with [`DCtx::ref_ddict`], and use
    /// the one each frame names.
    RefMultipleDDicts(bool),
    /// libzstd's switch for its assembly Huffman loop. The port has none; it
    /// is accepted and changes nothing.
    DisableHuffmanAssembly(bool),
    /// A smaller maximum block size, 1 KiB to 128 KiB; 0 for none.
    MaxBlockSize(u32),
}

/// A `ZSTD_dParameter`, for [`DCtx::get_parameter`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DParameterKind {
    WindowLogMax,
    Format,
    StableOutBuffer,
    ForceIgnoreChecksum,
    RefMultipleDDicts,
    DisableHuffmanAssembly,
    MaxBlockSize,
}

/// `ZSTD_ResetDirective`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResetDirective {
    /// Abandon the current frame; keep the parameters and dictionary.
    SessionOnly,
    /// Reset the parameters and drop the dictionary.
    Parameters,
    SessionAndParameters,
}

/// `ZSTD_decompress`: decodes the frames in `src` to `dst`, which must be
/// large enough for all of them. Returns the size decoded.
///
/// [`find_decompressed_size`] or [`get_frame_content_size`] tell how large,
/// when the frames say. Each call sets up a new context; reuse a [`DCtx`]
/// to avoid that.
pub fn decompress(dst: &mut [u8], src: &[u8]) -> Result<usize> {
    DCtx::new().decompress(dst, src)
}

impl From<Error> for std::io::Error {
    fn from(error: Error) -> Self {
        std::io::Error::other(error)
    }
}

#[cfg(test)]
mod bufferless_tests {
    //! [`DCtx::decompress_continue`] into one buffer, for a frame longer
    //! than twice its window and 1 MB: its copy of the window drops the
    //! oldest part, and stays bounded. The oracle's buffer is too small for
    //! this; with libzstd's own buffers, nothing there depends on it.

    use super::*;
    use crate::zstd::{CCtx, CParameter};

    #[test]
    fn the_copy_of_the_window_stays_bounded() {
        let mut rng = crate::zstd::oracle::Rng::new(0xB0FF);
        let data = rng.lz_data(1_300_000);
        let mut cctx = CCtx::new();
        for parameter in [
            CParameter::CompressionLevel(3),
            CParameter::WindowLog(15),
            CParameter::ChecksumFlag(true),
        ] {
            cctx.set_parameter(parameter).expect("a parameter");
        }
        let mut frame = vec![0u8; crate::zstd::compress_bound(data.len()).expect("a bound")];
        let size = cctx.compress2(&mut frame, &data).expect("compressed");
        frame.truncate(size);

        let trims = BUFFERLESS_TRIMS.load(std::sync::atomic::Ordering::Relaxed);
        let mut dctx = DCtx::new();
        dctx.decompress_begin();
        let mut out = vec![0u8; data.len()];
        let (mut ip, mut op) = (0, 0);
        let mut largest = 0;
        loop {
            let next = dctx.next_src_size_to_decompress();
            if next == 0 {
                break;
            }
            op += dctx
                .decompress_continue(&mut out[op..], &frame[ip..ip + next])
                .expect("decoded");
            ip += next;
            largest = largest.max(dctx.bufferless.window.len());
        }
        assert_eq!((ip, op), (frame.len(), data.len()));
        assert!(out == data, "the output differs");
        assert!(BUFFERLESS_TRIMS.load(std::sync::atomic::Ordering::Relaxed) > trims);
        // 1 MB, and the room for a block of 32 KB.
        assert!(
            largest <= (1 << 20) + (1 << 15),
            "a copy of {largest} bytes"
        );
    }
}
