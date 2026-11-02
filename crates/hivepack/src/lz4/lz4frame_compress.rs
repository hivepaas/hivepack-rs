//! The LZ4 frame format: `lz4frame.c`'s compression half.
//!
//! Differs from liblz4: liblz4's streams refer to the history of linked
//! blocks by pointer; the port finds it by where it is (`Loc`): in the
//! context's buffer (`tmpBuff`), in the input of the current call, in the
//! dictionary given to `compress_begin_using_dict` (of which the context
//! keeps a copy of the last 64 KB), or in a `CDict`. At the end of each call
//! that compressed from its input, the history is copied into the context's
//! buffer (`LZ4F_localSaveDict`), as liblz4 does unless the caller promises
//! the input stays (`stableSrc`), which the port takes only within
//! `compress_frame`, where no call follows. A dictionary and an input that
//! follow each other in memory are taken as apart.

use std::sync::Arc;

use crate::lz4::lz4::KB;
use crate::lz4::lz4_compress::{History, Input, LoadDictMode, StreamState};
use crate::lz4::lz4frame::{
    BLOCK_CHECKSUM_SIZE, BLOCK_HEADER_SIZE, BlockMode, BlockSizeId, Error, FrameInfo,
    HEADER_SIZE_MAX, MAGICNUMBER, Result, get_block_size,
};
use crate::lz4::lz4hc::{
    self, CLEVEL_DEFAULT, CLEVEL_MAX, CLEVEL_MIN, DictCtx, HcState, Limit, Moved,
};
use crate::lz4::xxhash::{Xxh32, xxh32};

const BH_SIZE: usize = BLOCK_HEADER_SIZE;
const BF_SIZE: usize = BLOCK_CHECKSUM_SIZE;
const MAX_FH_SIZE: usize = HEADER_SIZE_MAX;
const BLOCKUNCOMPRESSED_FLAG: u32 = 0x8000_0000;
const MB: usize = 1 << 20;

/// `LZ4F_preferences_t`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct Preferences {
    /// `frameInfo`: the frame's parameters. `frame_type` is not used.
    pub frame_info: FrameInfo,
    /// `compressionLevel`: below 2 (0 is the default), `LZ4_compress_fast`,
    /// a negative level `-n` with an acceleration of `n + 1`; 2 to 12, high
    /// compression (more than 12 is 12).
    pub compression_level: i32,
    /// `autoFlush`: every call compresses all it is given, rather than
    /// keeping what does not fill a block for the next.
    pub auto_flush: bool,
    /// `favorDecSpeed`: at levels 10 to 12, matches that decompress faster.
    pub favor_dec_speed: bool,
}

/// `LZ4F_compressionLevel_max()`.
pub fn compression_level_max() -> i32 {
    CLEVEL_MAX
}

fn write_le32(dst: &mut [u8], at: usize, value: u32) {
    dst[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// `LZ4F_optimalBSID`: the smallest block size up to `requested` that holds
/// `src_size` bytes.
fn optimal_bsid(requested: BlockSizeId, src_size: usize) -> BlockSizeId {
    let mut max_block_size = 64 * KB;
    for proposed in [
        BlockSizeId::Max64Kb,
        BlockSizeId::Max256Kb,
        BlockSizeId::Max1Mb,
        BlockSizeId::Max4Mb,
    ] {
        if requested as u32 <= proposed as u32 {
            break;
        }
        if src_size <= max_block_size {
            return proposed;
        }
        max_block_size <<= 2;
    }
    requested
}

/// `LZ4F_compressBound_internal`.
fn compress_bound_internal(
    src_size: usize,
    prefs: Option<&Preferences>,
    already_buffered: usize,
) -> usize {
    // The worst case.
    let null = Preferences {
        frame_info: FrameInfo {
            content_checksum: true,
            block_checksum: true,
            ..FrameInfo::default()
        },
        ..Preferences::default()
    };
    let prefs = prefs.unwrap_or(&null);
    let flush = prefs.auto_flush || src_size == 0;
    let block_size = get_block_size(prefs.frame_info.block_size_id);
    let max_buffered = block_size - 1;
    let buffered_size = already_buffered.min(max_buffered);
    let max_src_size = src_size.saturating_add(buffered_size);
    let nb_full_blocks = max_src_size / block_size;
    let partial_block_size = max_src_size & (block_size - 1);
    let last_block_size = if flush { partial_block_size } else { 0 };
    let nb_blocks = nb_full_blocks + usize::from(last_block_size > 0);

    let block_crc_size = BF_SIZE * usize::from(prefs.frame_info.block_checksum);
    let frame_end = BH_SIZE + usize::from(prefs.frame_info.content_checksum) * BF_SIZE;

    ((BH_SIZE + block_crc_size) * nb_blocks)
        .saturating_add(block_size.saturating_mul(nb_full_blocks))
        .saturating_add(last_block_size + frame_end)
}

/// `LZ4F_compressFrameBound`: room enough for the frame `compress_frame`
/// makes of `src_size` bytes.
pub fn compress_frame_bound(src_size: usize, prefs: Option<&Preferences>) -> usize {
    let mut prefs = prefs.copied().unwrap_or_default();
    prefs.auto_flush = true;
    MAX_FH_SIZE.saturating_add(compress_bound_internal(src_size, Some(&prefs), 0))
}

/// `LZ4F_compressBound`: room enough for what `compress_update` writes of
/// `src_size` bytes, whatever the context keeps, and for `compress_end`
/// (with `src_size` 0). Without preferences, for the worst ones.
pub fn compress_bound(src_size: usize, prefs: Option<&Preferences>) -> usize {
    match prefs {
        Some(p) if p.auto_flush => compress_bound_internal(src_size, prefs, 0),
        _ => compress_bound_internal(src_size, prefs, usize::MAX),
    }
}

/// `LZ4F_CDict`: a dictionary digested once, for the frames compressed with
/// it, which can share it between threads.
#[derive(Clone, Debug)]
pub struct CDict {
    /// The fast state the dictionary's last 64 KB are loaded into
    /// (`LZ4_loadDictSlow`), and them.
    fast: Arc<(StreamState, Vec<u8>)>,
    /// The high-compression state they are loaded into, at the default
    /// level, and them.
    hc: DictCtx,
}

impl CDict {
    /// `LZ4F_createCDict`: `dict`, of which the last 64 KB are used.
    pub fn new(dict: &[u8]) -> Self {
        let content = dict[dict.len() - dict.len().min(64 * KB)..].to_vec();
        let mut fast = StreamState::default();
        fast.init();
        fast.load_dict(&content, LoadDictMode::Slow);
        let mut hc = HcState::default();
        hc.init_stream();
        // Which level will be used is not known: the state is made for
        // the most common high-compression mode.
        hc.set_compression_level(CLEVEL_DEFAULT);
        hc.load_dict(&content);
        CDict {
            fast: Arc::new((fast, content.clone())),
            hc: Arc::new((hc, content)),
        }
    }
}

/// Where a history ends.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Loc {
    /// In the context's buffer.
    Tmp(usize),
    /// In the input of the current call.
    Src(usize),
    /// In the dictionary of `compress_begin_using_dict`.
    User(usize),
    /// In the content of the context's `CDict`.
    CDict(usize),
}

/// The buffers a history can be in.
#[derive(Clone, Copy)]
struct Bufs<'a> {
    tmp: &'a [u8],
    src: &'a [u8],
    user: &'a [u8],
    cdict: &'a [u8],
}

impl<'a> Bufs<'a> {
    /// The buffer a history ending at `loc` is in, and where it ends there
    /// (nothing for `NULL`).
    fn at(&self, loc: Option<Loc>) -> (&'a [u8], usize) {
        match loc {
            Some(Loc::Tmp(end)) => (self.tmp, end),
            Some(Loc::Src(end)) => (self.src, end),
            Some(Loc::User(end)) => (self.user, end),
            Some(Loc::CDict(end)) => (self.cdict, end),
            None => (&[], 0),
        }
    }

    /// The `size` bytes of a history ending at `loc`.
    fn ending(&self, loc: Option<Loc>, size: usize) -> &'a [u8] {
        if size == 0 {
            return &[];
        }
        let (buf, end) = self.at(loc);
        &buf[end - size..end]
    }
}

/// The fast state of a frame (`LZ4_stream_t`), and where its history is.
#[derive(Clone, Debug)]
struct FastCtx {
    state: StreamState,
    /// Where the history, the state's `dictSize` bytes, ends.
    dict_end: Option<Loc>,
    dict_ctx: Option<Arc<(StreamState, Vec<u8>)>>,
}

/// The high-compression state of a frame (`LZ4_streamHC_t`), and where its
/// prefix and external dictionary are.
#[derive(Clone, Debug)]
struct HcCtx {
    state: HcState,
    /// Where the prefix (`end`) ends.
    prefix_end: Option<Loc>,
    /// Where the external dictionary ends.
    ext_end: Option<Loc>,
    dict_ctx: Option<DictCtx>,
}

#[derive(Clone, Debug)]
enum Lz4Ctx {
    Fast(Box<FastCtx>),
    Hc(Box<HcCtx>),
}

impl Lz4Ctx {
    /// `LZ4_initStream`.
    fn new_fast() -> Self {
        let mut state = StreamState::default();
        state.init();
        Lz4Ctx::Fast(Box::new(FastCtx {
            state,
            dict_end: None,
            dict_ctx: None,
        }))
    }

    /// `LZ4_initStreamHC`.
    fn new_hc() -> Self {
        let mut state = HcState::default();
        state.init_stream();
        Lz4Ctx::Hc(Box::new(HcCtx {
            state,
            prefix_end: None,
            ext_end: None,
            dict_ctx: None,
        }))
    }

    /// `ctxTypeID`: 1 for the fast state, 2 for high compression.
    fn type_id(&self) -> u8 {
        match self {
            Lz4Ctx::Fast(_) => 1,
            Lz4Ctx::Hc(_) => 2,
        }
    }

    /// `LZ4F_initStream`: the state prepared for a stream of blocks (a
    /// frame of linked blocks, or each independent block), reset and with
    /// the dictionary attached.
    fn init_stream(&mut self, cdict: Option<&Arc<CDict>>, level: i32, block_mode: BlockMode) {
        match self {
            Lz4Ctx::Fast(f) => {
                if cdict.is_some() || block_mode == BlockMode::Linked {
                    // In these cases, LZ4_compress_fast_continue() is
                    // called, which needs an already reset context.
                    // Otherwise, a one-shot function is called, which
                    // resets the state itself, knowing the table type it
                    // needs.
                    f.state.reset_fast();
                    f.dict_end = None;
                    f.dict_ctx = None;
                    if let Some(cd) = cdict
                        && f.state.attach(&cd.fast.0)
                    {
                        f.dict_ctx = Some(cd.fast.clone());
                    }
                }
            }
            Lz4Ctx::Hc(h) => {
                h.state.reset_fast(level);
                h.prefix_end = None;
                h.dict_ctx = cdict.map(|cd| cd.hc.clone());
            }
        }
    }
}

/// `LZ4F_BlockCompressMode_e`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
enum BlockCompress {
    #[default]
    Compressed,
    Uncompressed,
}

/// `LZ4F_lastBlockStatus`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LastBlock {
    NotDone,
    FromTmpBuffer,
    FromSrcBuffer,
}

/// A block's bytes, in the context's buffer or in the input.
#[derive(Clone, Copy)]
struct Block {
    in_src: bool,
    pos: usize,
    len: usize,
}

impl Block {
    fn loc(&self, at: usize) -> Loc {
        if self.in_src {
            Loc::Src(at)
        } else {
            Loc::Tmp(at)
        }
    }
}

/// `LZ4F_cctx`: compresses frames, the header, the blocks and the end, in
/// as many calls as the input comes in.
#[derive(Clone, Debug)]
pub struct CompressionContext {
    prefs: Preferences,
    version: u32,
    c_stage: u32,
    cdict: Option<Arc<CDict>>,
    max_block_size: usize,
    max_buffer_size: usize,
    tmp_buff: Vec<u8>,
    /// `tmpIn`, as a position in `tmp_buff`.
    tmp_in: usize,
    tmp_in_size: usize,
    total_in_size: u64,
    xxh: Xxh32,
    lz4_ctx: Option<Lz4Ctx>,
    /// `lz4CtxAlloc`: the type of the largest state allocated.
    lz4_ctx_alloc: u8,
    block_compress_mode: BlockCompress,
    /// The last 64 KB of the dictionary of `compress_begin_using_dict`,
    /// which liblz4 refers to where the caller keeps it.
    user_dict: Vec<u8>,
}

impl Default for CompressionContext {
    fn default() -> Self {
        CompressionContext::new()
    }
}

impl CompressionContext {
    /// `LZ4F_createCompressionContext(&cctx, LZ4F_VERSION)`.
    pub fn new() -> Self {
        CompressionContext {
            prefs: Preferences::default(),
            version: crate::lz4::lz4frame::VERSION,
            c_stage: 0,
            cdict: None,
            max_block_size: 0,
            max_buffer_size: 0,
            tmp_buff: Vec::new(),
            tmp_in: 0,
            tmp_in_size: 0,
            total_in_size: 0,
            xxh: Xxh32::new(0),
            lz4_ctx: None,
            lz4_ctx_alloc: 0,
            block_compress_mode: BlockCompress::Compressed,
            user_dict: Vec::new(),
        }
    }

    /// The version the context was made for, `LZ4F_VERSION`.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// `LZ4F_compressBegin_internal`: the frame header written into `dst`,
    /// and the context ready for the frame's blocks. Returns the header's
    /// size.
    fn begin_internal(
        &mut self,
        dst: &mut [u8],
        dict: Option<&[u8]>,
        cdict: Option<&Arc<CDict>>,
        prefs: Option<&Preferences>,
    ) -> Result<usize> {
        if dst.len() < MAX_FH_SIZE {
            return Err(Error::DstMaxSizeTooSmall);
        }
        let prefs = prefs.copied().unwrap_or_default();
        self.prefs = prefs;
        let fast = prefs.compression_level < CLEVEL_MIN;

        // Context management.
        let ctx_type_id = if fast { 1 } else { 2 };
        if self.lz4_ctx_alloc < ctx_type_id {
            // Not enough space allocated.
            self.lz4_ctx = Some(if fast {
                Lz4Ctx::new_fast()
            } else {
                Lz4Ctx::new_hc()
            });
            self.lz4_ctx_alloc = ctx_type_id;
        } else if self.lz4_ctx.as_ref().map(Lz4Ctx::type_id) != Some(ctx_type_id) {
            // A large enough state is allocated, but it is reset to the
            // right type.
            self.lz4_ctx = Some(if fast {
                Lz4Ctx::new_fast()
            } else {
                let mut ctx = Lz4Ctx::new_hc();
                if let Lz4Ctx::Hc(h) = &mut ctx {
                    h.state.set_compression_level(prefs.compression_level);
                }
                ctx
            });
        }

        // Buffer management.
        if self.prefs.frame_info.block_size_id == BlockSizeId::Default {
            self.prefs.frame_info.block_size_id = BlockSizeId::Max64Kb;
        }
        self.max_block_size = get_block_size(self.prefs.frame_info.block_size_id);
        let linked = self.prefs.frame_info.block_mode == BlockMode::Linked;
        let required_buff_size = if prefs.auto_flush {
            // Only the past data up to the window size is needed.
            if linked { 64 * KB } else { 0 }
        } else {
            self.max_block_size + if linked { 128 * KB } else { 0 }
        };
        if self.max_buffer_size < required_buff_size {
            self.max_buffer_size = 0;
            self.tmp_buff = Vec::new();
            if self.tmp_buff.try_reserve_exact(required_buff_size).is_err() {
                return Err(Error::AllocationFailed);
            }
            self.tmp_buff.resize(required_buff_size, 0);
            self.max_buffer_size = required_buff_size;
        }
        self.tmp_in = 0;
        self.tmp_in_size = 0;
        self.xxh.reset(0);

        // Context init.
        self.cdict = cdict.cloned();
        let level = self.prefs.compression_level;
        let Some(ctx) = self.lz4_ctx.as_mut() else {
            return Err(Error::AllocationFailed);
        };
        if linked {
            // Only for linked blocks: independent ones are prepared at each
            // block.
            ctx.init_stream(cdict, level, BlockMode::Linked);
        }
        if let Lz4Ctx::Hc(h) = ctx {
            h.state.favor_decompression_speed(prefs.favor_dec_speed);
        }
        if let Some(dict) = dict {
            if dict.len() > i32::MAX as usize {
                return Err(Error::ParameterInvalid);
            }
            self.user_dict.clear();
            self.user_dict
                .extend_from_slice(&dict[dict.len() - dict.len().min(64 * KB)..]);
            let end = Some(Loc::User(self.user_dict.len()));
            match ctx {
                Lz4Ctx::Fast(f) => {
                    f.state.load_dict(&self.user_dict, LoadDictMode::Fast);
                    f.dict_end = end;
                    f.dict_ctx = None;
                }
                Lz4Ctx::Hc(h) => {
                    h.state.load_dict(&self.user_dict);
                    h.prefix_end = end;
                    h.dict_ctx = None;
                }
            }
        }

        // Write the frame header: the magic number.
        write_le32(dst, 0, MAGICNUMBER);
        let header_start = 4;
        let mut at = header_start;
        let fi = &self.prefs.frame_info;
        // The FLG byte.
        dst[at] = (1 << 6) // Version '01'
            + ((fi.block_mode as u8 & 1) << 5)
            + (u8::from(fi.block_checksum) << 4)
            + (u8::from(fi.content_size > 0) << 3)
            + (u8::from(fi.content_checksum) << 2)
            + u8::from(fi.dict_id > 0);
        // The BD byte.
        dst[at + 1] = (fi.block_size_id as u8 & 7) << 4;
        at += 2;
        // The optional content size.
        if fi.content_size != 0 {
            dst[at..at + 8].copy_from_slice(&fi.content_size.to_le_bytes());
            at += 8;
            self.total_in_size = 0;
        }
        // The optional dictionary ID.
        if fi.dict_id != 0 {
            write_le32(dst, at, fi.dict_id);
            at += 4;
        }
        // The header checksum.
        dst[at] = (xxh32(&dst[header_start..at], 0) >> 8) as u8;
        at += 1;

        // The header is written: the blocks come next.
        self.c_stage = 1;
        Ok(at)
    }

    /// `LZ4F_compressBegin`: the frame header written into `dst` (which
    /// must hold 19 bytes), and the context ready for the frame's blocks.
    /// Returns the header's size.
    pub fn compress_begin(&mut self, dst: &mut [u8], prefs: Option<&Preferences>) -> Result<usize> {
        self.begin_internal(dst, None, None, prefs)
    }

    /// `LZ4F_compressBegin_usingDict`: as `compress_begin`, with `dict` (its
    /// last 64 KB) as the history of the first block. As in liblz4, only of
    /// the first block, and only if the blocks are linked: with independent
    /// blocks, it is not used.
    pub fn compress_begin_using_dict(
        &mut self,
        dst: &mut [u8],
        dict: &[u8],
        prefs: Option<&Preferences>,
    ) -> Result<usize> {
        self.begin_internal(dst, Some(dict), None, prefs)
    }

    /// `LZ4F_compressBegin_usingCDict`: as `compress_begin`, with `cdict` as
    /// the history of the first block, and of each one if the blocks are
    /// independent.
    pub fn compress_begin_using_cdict(
        &mut self,
        dst: &mut [u8],
        cdict: &Arc<CDict>,
        prefs: Option<&Preferences>,
    ) -> Result<usize> {
        self.begin_internal(dst, None, Some(cdict), prefs)
    }

    /// The compression function `LZ4F_selectCompression` chooses, on
    /// `block`: returns the compressed size, or 0 if it does not fit in
    /// `dst`.
    fn compress_block(
        &mut self,
        src: &[u8],
        block: Block,
        dst: &mut [u8],
        mode: BlockCompress,
    ) -> usize {
        if mode == BlockCompress::Uncompressed {
            // LZ4F_doNotCompressBlock.
            return 0;
        }
        let level = self.prefs.compression_level;
        let linked = self.prefs.frame_info.block_mode == BlockMode::Linked;
        let cdict = self.cdict.as_ref();
        let Some(ctx) = self.lz4_ctx.as_mut() else {
            return 0;
        };
        if !linked {
            ctx.init_stream(cdict, level, BlockMode::Independent);
        }
        let bufs = Bufs {
            tmp: &self.tmp_buff,
            src,
            user: &self.user_dict,
            cdict: cdict.map_or(&[][..], |cd| &cd.hc.1),
        };
        let buf = if block.in_src { src } else { bufs.tmp };
        let block_start = Some(block.loc(block.pos));
        let block_end = Some(block.loc(block.pos + block.len));
        match ctx {
            Lz4Ctx::Fast(f) => {
                let acceleration = if level < 0 {
                    level.saturating_neg().saturating_add(1)
                } else {
                    1
                };
                if !linked && cdict.is_none() {
                    // LZ4F_compressBlock.
                    return f.state.compress_fast_ext_state_fast_reset(
                        &buf[block.pos..block.pos + block.len],
                        dst,
                        acceleration,
                    );
                }
                // LZ4_compress_fast_continue.
                let dict_size = f.state.dict_size();
                let input = Input {
                    buf,
                    src: block.pos,
                    len: block.len,
                    dict: &[],
                };
                let history = if dict_size > 0 && f.dict_end == block_start {
                    History::Prefix
                } else {
                    History::Ext(bufs.ending(f.dict_end, dict_size))
                };
                let result = f.state.compress_fast_continue(
                    &input,
                    history,
                    dst,
                    acceleration,
                    &mut f.dict_ctx,
                );
                // The history ends with the block, whether it was a
                // prefix, or it is the block.
                f.dict_end = block_end;
                result
            }
            Lz4Ctx::Hc(h) => {
                if !linked && cdict.is_none() {
                    // LZ4F_compressBlockHC.
                    return h.state.compress_ext_state_fast_reset(
                        &buf[block.pos..block.pos + block.len],
                        dst,
                        level,
                    );
                }
                // LZ4_compress_HC_continue.
                let limit = if dst.len() < crate::lz4::lz4::compress_bound(block.len) {
                    Limit::LimitedOutput
                } else {
                    Limit::NotLimited
                };
                let follows = h.prefix_end == block_start;
                let (prefix, prefix_end) = bufs.at(h.prefix_end);
                let ext = bufs.ending(h.ext_end, h.state.ext_size());
                let mut src_size = block.len;
                let (result, moved) = lz4hc::continue_located(
                    &mut h.state,
                    &mut h.dict_ctx,
                    buf,
                    block.pos,
                    follows,
                    prefix,
                    prefix_end,
                    ext,
                    dst,
                    &mut src_size,
                    limit,
                );
                match moved {
                    Moved::Nothing => {}
                    Moved::PrefixToExt => h.ext_end = h.prefix_end,
                    Moved::DictCtxToExt => h.ext_end = Some(Loc::CDict(bufs.cdict.len())),
                }
                h.prefix_end = block_end;
                result
            }
        }
    }

    /// `LZ4F_makeBlock`: `block` compressed into `dst` at `at`, with its
    /// header and checksum, or stored as it is if that is not smaller.
    /// Returns the bytes written.
    fn make_block(
        &mut self,
        src: &[u8],
        block: Block,
        dst: &mut [u8],
        at: usize,
        mode: BlockCompress,
    ) -> usize {
        let data = at + BH_SIZE;
        let capacity = block.len.saturating_sub(1);
        let mut c_size = self.compress_block(src, block, &mut dst[data..data + capacity], mode);
        if c_size == 0 || c_size >= block.len {
            c_size = block.len;
            write_le32(dst, at, c_size as u32 | BLOCKUNCOMPRESSED_FLAG);
            let bytes = if block.in_src { src } else { &self.tmp_buff };
            dst[data..data + c_size].copy_from_slice(&bytes[block.pos..block.pos + block.len]);
        } else {
            write_le32(dst, at, c_size as u32);
        }
        let crc = self.prefs.frame_info.block_checksum;
        if crc {
            // The checksum of the compressed data.
            let crc32 = xxh32(&dst[data..data + c_size], 0);
            write_le32(dst, data + c_size, crc32);
        }
        BH_SIZE + c_size + usize::from(crc) * BF_SIZE
    }

    /// `LZ4F_localSaveDict`: the history (up to 64 KB) saved at the start of
    /// the context's buffer. Returns its size.
    fn local_save_dict(&mut self, src: &[u8]) -> usize {
        let cdict = self.cdict.as_ref().map_or(&[][..], |cd| &cd.hc.1[..]);
        let Some(ctx) = self.lz4_ctx.as_mut() else {
            return 0;
        };
        let (end, size) = match ctx {
            Lz4Ctx::Fast(f) => {
                // LZ4_saveDict(stream, tmpBuff, 64 KB).
                let end = f.dict_end;
                let size = f.state.save_dict(64 * KB);
                f.dict_end = Some(Loc::Tmp(size));
                (end, size)
            }
            Lz4Ctx::Hc(h) => {
                // LZ4_saveDictHC(stream, tmpBuff, 64 KB).
                let end = h.prefix_end;
                let size = h.state.save_dict(64 * KB);
                h.prefix_end = Some(Loc::Tmp(size));
                (end, size)
            }
        };
        if size > 0 {
            // memmove(tmpBuff, dictEnd - size, size).
            match end {
                Some(Loc::Tmp(end)) => self.tmp_buff.copy_within(end - size..end, 0),
                _ => {
                    let bufs = Bufs {
                        tmp: &[],
                        src,
                        user: &self.user_dict,
                        cdict,
                    };
                    self.tmp_buff[..size].copy_from_slice(bufs.ending(end, size));
                }
            }
        }
        size
    }

    /// `LZ4F_compressUpdateImpl`; `stable_src` is `stableSrc`.
    fn update_impl(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        stable_src: bool,
        block_compression: BlockCompress,
    ) -> Result<usize> {
        let block_size = self.max_block_size;
        let src_size = src.len();
        let mut src_ptr = 0;
        let mut dst_ptr = 0;
        let mut last_block = LastBlock::NotDone;

        if self.c_stage != 1 {
            // The state must be initialised and waiting for the next block.
            return Err(Error::CompressionStateUninitialized);
        }
        let linked = self.prefs.frame_info.block_mode == BlockMode::Linked;
        if block_compression == BlockCompress::Uncompressed && linked {
            return Err(Error::BlockModeInvalid);
        }
        let switch = self.block_compress_mode != block_compression;
        let bound = if switch && self.tmp_in_size > 0 {
            // The block flushed first, then the input alone.
            (self.tmp_in_size + BH_SIZE + BF_SIZE).saturating_add(compress_bound_internal(
                src_size,
                Some(&self.prefs),
                0,
            ))
        } else {
            compress_bound_internal(src_size, Some(&self.prefs), self.tmp_in_size)
        };
        if dst.len() < bound {
            return Err(Error::DstMaxSizeTooSmall);
        }
        if block_compression == BlockCompress::Uncompressed && dst.len() < src_size {
            return Err(Error::DstMaxSizeTooSmall);
        }

        // Flush the block being written, to go on with the new block
        // compression.
        if switch {
            dst_ptr += self.flush(dst)?;
            self.block_compress_mode = block_compression;
        }

        // Complete the tmp buffer.
        if self.tmp_in_size > 0 {
            // Some data is already within the tmp buffer.
            let size_to_copy = block_size - self.tmp_in_size;
            let at = self.tmp_in + self.tmp_in_size;
            if size_to_copy > src_size {
                // Add src to the tmpIn buffer.
                self.tmp_buff[at..at + src_size].copy_from_slice(src);
                src_ptr = src_size;
                self.tmp_in_size += src_size;
            } else {
                // Complete the tmpIn block, then compress it.
                last_block = LastBlock::FromTmpBuffer;
                self.tmp_buff[at..at + size_to_copy].copy_from_slice(&src[..size_to_copy]);
                src_ptr += size_to_copy;

                let block = Block {
                    in_src: false,
                    pos: self.tmp_in,
                    len: block_size,
                };
                dst_ptr += self.make_block(src, block, dst, dst_ptr, block_compression);
                if linked {
                    self.tmp_in += block_size;
                }
                self.tmp_in_size = 0;
            }
        }

        while src_size - src_ptr >= block_size {
            // Compress full blocks.
            last_block = LastBlock::FromSrcBuffer;
            let block = Block {
                in_src: true,
                pos: src_ptr,
                len: block_size,
            };
            dst_ptr += self.make_block(src, block, dst, dst_ptr, block_compression);
            src_ptr += block_size;
        }

        if self.prefs.auto_flush && src_ptr < src_size {
            // autoFlush: the remaining input (less than a block) is
            // compressed.
            last_block = LastBlock::FromSrcBuffer;
            let block = Block {
                in_src: true,
                pos: src_ptr,
                len: src_size - src_ptr,
            };
            dst_ptr += self.make_block(src, block, dst, dst_ptr, block_compression);
            src_ptr = src_size;
        }

        // Preserve the dictionary within tmpBuff whenever necessary.
        if linked && last_block == LastBlock::FromSrcBuffer {
            // Linked blocks are only meant to be compressed (see
            // uncompressed_update).
            if stable_src {
                // The input is stable: the history stays in it.
                self.tmp_in = 0;
            } else {
                let real_dict_size = self.local_save_dict(src);
                self.tmp_in = real_dict_size;
            }
        }

        // Keep tmpIn within limits: without autoFlush, there may be data
        // left within the buffer, and not enough room for the next block.
        if !self.prefs.auto_flush && self.tmp_in + block_size > self.max_buffer_size {
            // Only 64 KB are kept within the buffer, which ensures there is
            // room for the next block. This happens only after a block from
            // the buffer.
            let real_dict_size = self.local_save_dict(src);
            self.tmp_in = real_dict_size;
        }

        // Some input left, less than a block.
        if src_ptr < src_size {
            // Fill the tmp buffer.
            let size_to_copy = src_size - src_ptr;
            let at = self.tmp_in;
            self.tmp_buff[at..at + size_to_copy].copy_from_slice(&src[src_ptr..]);
            self.tmp_in_size = size_to_copy;
        }

        if self.prefs.frame_info.content_checksum {
            self.xxh.update(src);
        }

        self.total_in_size = self.total_in_size.wrapping_add(src_size as u64);
        Ok(dst_ptr)
    }

    /// `LZ4F_compressUpdate`: `src` compressed into `dst`, but for what
    /// does not fill a block, which the context keeps for the next call
    /// (unless `auto_flush`). `dst` must hold `compress_bound(src.len(),
    /// prefs)` bytes, and after `uncompressed_update` left some input in
    /// the context, the block it is flushed into too (see there). Returns
    /// the bytes written, which can be 0.
    ///
    /// After an error, the context must begin a new frame before it is used
    /// again.
    pub fn compress_update(&mut self, dst: &mut [u8], src: &[u8]) -> Result<usize> {
        self.update_impl(dst, src, false, BlockCompress::Compressed)
    }

    /// `LZ4F_uncompressedUpdate`: as `compress_update`, with the blocks
    /// stored as they are. For independent blocks only.
    ///
    /// Differs from liblz4: with linked blocks, liblz4 makes frames that do
    /// not decompress to their input (its compressor does not see the
    /// stored blocks the decompressor refers to); the port returns
    /// `Error::BlockModeInvalid`. And when what the context keeps from the
    /// other kind of call is flushed first, `compress_bound` does not count
    /// that block: liblz4 writes past the end of `dst` (fixed after 1.10.0);
    /// the port returns `Error::DstMaxSizeTooSmall` unless `dst` holds it
    /// too, up to a block and 8 bytes more.
    pub fn uncompressed_update(&mut self, dst: &mut [u8], src: &[u8]) -> Result<usize> {
        self.update_impl(dst, src, false, BlockCompress::Uncompressed)
    }

    /// `LZ4F_flush`: what the context keeps compressed into a block now.
    /// Returns the bytes written, 0 if there was nothing.
    pub fn flush(&mut self, dst: &mut [u8]) -> Result<usize> {
        if self.tmp_in_size == 0 {
            // Nothing to flush.
            return Ok(0);
        }
        if self.c_stage != 1 {
            return Err(Error::CompressionStateUninitialized);
        }
        if dst.len() < self.tmp_in_size + BH_SIZE + BF_SIZE {
            return Err(Error::DstMaxSizeTooSmall);
        }

        // Compress the tmp buffer.
        let block = Block {
            in_src: false,
            pos: self.tmp_in,
            len: self.tmp_in_size,
        };
        let mode = self.block_compress_mode;
        let written = self.make_block(&[], block, dst, 0, mode);

        if self.prefs.frame_info.block_mode == BlockMode::Linked {
            self.tmp_in += self.tmp_in_size;
        }
        self.tmp_in_size = 0;

        // Keep tmpIn within limits (necessarily linked blocks).
        if self.tmp_in + self.max_block_size > self.max_buffer_size {
            let real_dict_size = self.local_save_dict(&[]);
            self.tmp_in = real_dict_size;
        }
        Ok(written)
    }

    /// `LZ4F_compressEnd`: what the context keeps compressed, then the end
    /// mark and the content checksum. Returns the bytes written (4 at
    /// least). The context can then begin another frame.
    pub fn compress_end(&mut self, dst: &mut [u8]) -> Result<usize> {
        let flush_size = self.flush(dst)?;
        let mut at = flush_size;
        let capacity = dst.len() - flush_size;

        if capacity < 4 {
            return Err(Error::DstMaxSizeTooSmall);
        }
        // The end mark.
        write_le32(dst, at, 0);
        at += 4;

        if self.prefs.frame_info.content_checksum {
            let xxh = self.xxh.digest();
            if capacity < 8 {
                return Err(Error::DstMaxSizeTooSmall);
            }
            // The content checksum.
            write_le32(dst, at, xxh);
            at += 4;
        }

        // The context can be used again.
        self.c_stage = 0;

        let content_size = self.prefs.frame_info.content_size;
        if content_size != 0 && content_size != self.total_in_size {
            return Err(Error::FrameSizeWrong);
        }
        Ok(at)
    }

    /// `LZ4F_compressFrame_usingCDict`: `src` compressed into one frame in
    /// `dst`, with `cdict` (or no dictionary). `dst` must hold
    /// `compress_frame_bound(src.len(), prefs)` bytes. Returns the frame's
    /// size.
    pub fn compress_frame_using_cdict(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        cdict: Option<&Arc<CDict>>,
        prefs: Option<&Preferences>,
    ) -> Result<usize> {
        let mut prefs = prefs.copied().unwrap_or_default();
        if prefs.frame_info.content_size != 0 {
            // The content size corrected, if one is asked for.
            prefs.frame_info.content_size = src.len() as u64;
        }
        prefs.frame_info.block_size_id = optimal_bsid(prefs.frame_info.block_size_id, src.len());
        prefs.auto_flush = true;
        if src.len() <= get_block_size(prefs.frame_info.block_size_id) {
            // Only one block: no need for links between blocks.
            prefs.frame_info.block_mode = BlockMode::Independent;
        }

        if dst.len() < compress_frame_bound(src.len(), Some(&prefs)) {
            return Err(Error::DstMaxSizeTooSmall);
        }

        let header_size = self.begin_internal(dst, None, cdict, Some(&prefs))?;
        let mut at = header_size;
        at += self.update_impl(&mut dst[at..], src, true, BlockCompress::Compressed)?;
        at += self.compress_end(&mut dst[at..])?;
        Ok(at)
    }
}

/// `LZ4F_compressFrame`: `src` compressed into one frame in `dst`, which
/// must hold `compress_frame_bound(src.len(), prefs)` bytes. Returns the
/// frame's size.
pub fn compress_frame(dst: &mut [u8], src: &[u8], prefs: Option<&Preferences>) -> Result<usize> {
    let mut cctx = CompressionContext::new();
    // As liblz4: so that no buffer is allocated, which works because the
    // frame is flushed at each call and the input is stable.
    cctx.max_buffer_size = 5 * MB;
    if prefs.is_none_or(|p| p.compression_level < CLEVEL_MIN) {
        cctx.lz4_ctx = Some(Lz4Ctx::new_fast());
        cctx.lz4_ctx_alloc = 1;
    }
    cctx.compress_frame_using_cdict(dst, src, None, prefs)
}
