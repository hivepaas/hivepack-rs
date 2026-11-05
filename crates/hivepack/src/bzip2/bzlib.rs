//! Library top-level functions: port of `bzlib.c` without the file I/O
//! functions (`BZ2_bzReadOpen` and the others, and `BZ2_bzopen`), with
//! the public parts of `bzlib.h`.
//!
//! libbzip2 returns an `int`: `BZ_OK` to `BZ_STREAM_END` on success, a
//! negative code on failure. The port returns `Result<Status, Error>`
//! instead, with the same codes. A `bz_stream`'s `next_in`, `avail_in`,
//! `next_out` and `avail_out` are an [`InBuffer`] and an [`OutBuffer`],
//! and its totals belong to the [`Compress`] or [`Decompress`].

use core::fmt;

use crate::bzip2::compress::EState;
use crate::bzip2::crctable::update_crc;
use crate::bzip2::decompress::{DState, decompress, index_into_f};
use crate::bzip2::private::*;

/// The input of a call: `src[pos..]` is what may be read
/// (`next_in`/`avail_in`).
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

/// The output of a call: `dst[pos..]` is the space it may write
/// (`next_out`/`avail_out`).
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

/// The `action` argument of `BZ2_bzCompress()`, with the same numbers.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Action {
    /// `BZ_RUN`: compress what is given, writing out finished blocks.
    Run = 0,
    /// `BZ_FLUSH`: end the current block once the input given is read,
    /// and write it all out.
    Flush = 1,
    /// `BZ_FINISH`: end the stream once the input given is read.
    Finish = 2,
}

/// Success: libbzip2's return codes from `BZ_OK` to `BZ_STREAM_END`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Status {
    /// `BZ_OK`: the decompressor made what progress it could, and the
    /// stream goes on.
    Ok,
    /// `BZ_RUN_OK`: the compressor made progress with [`Action::Run`], or
    /// finished a flush.
    RunOk,
    /// `BZ_FLUSH_OK`: a flush is under way; call again with
    /// [`Action::Flush`] and more output space.
    FlushOk,
    /// `BZ_FINISH_OK`: the end of the stream is under way; call again with
    /// [`Action::Finish`] and more output space.
    FinishOk,
    /// `BZ_STREAM_END`: the end of the stream, all of it written, its CRCs
    /// verified when decompressing.
    StreamEnd,
}

impl Status {
    /// The number libbzip2 gives this result.
    pub fn number(self) -> i32 {
        match self {
            Status::Ok => BZ_OK,
            Status::RunOk => BZ_RUN_OK,
            Status::FlushOk => BZ_FLUSH_OK,
            Status::FinishOk => BZ_FINISH_OK,
            Status::StreamEnd => BZ_STREAM_END,
        }
    }
}

/// libbzip2's negative return codes, with the same numbers.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum Error {
    /// `BZ_SEQUENCE_ERROR`: a call in the wrong order, such as a flush
    /// whose input changed before it ended, or a call after the end of
    /// the stream.
    Sequence = -1,
    /// `BZ_PARAM_ERROR`: a parameter out of range, or a compressor call
    /// with [`Action::Run`] that could do nothing.
    Param = -2,
    /// `BZ_MEM_ERROR`: not enough memory.
    Mem = -3,
    /// `BZ_DATA_ERROR`: the compressed data is damaged, or a CRC does not
    /// match.
    Data = -4,
    /// `BZ_DATA_ERROR_MAGIC`: the data does not start as a bzip2 stream.
    DataMagic = -5,
    /// `BZ_IO_ERROR`, from the file functions, which the port does not
    /// have.
    Io = -6,
    /// `BZ_UNEXPECTED_EOF`: [`buff_to_buff_decompress`] reached the end of
    /// its input before the end of the stream.
    UnexpectedEof = -7,
    /// `BZ_OUTBUFF_FULL`: the output of [`buff_to_buff_compress`] or
    /// [`buff_to_buff_decompress`] did not fit.
    OutbuffFull = -8,
    /// `BZ_CONFIG_ERROR`, for a C compiler whose types have the wrong
    /// sizes, which the port never returns.
    Config = -9,
}

impl Error {
    /// The number libbzip2 gives this error.
    pub fn number(self) -> i32 {
        self as i32
    }

    /// The name `BZ2_bzerror()` gives this error, such as
    /// `"DATA_ERROR_MAGIC"`.
    ///
    /// Port of `bzerrorstrings` in `bzlib.c`.
    pub fn message(self) -> &'static str {
        match self {
            Error::Sequence => "SEQUENCE_ERROR",
            Error::Param => "PARAM_ERROR",
            Error::Mem => "MEM_ERROR",
            Error::Data => "DATA_ERROR",
            Error::DataMagic => "DATA_ERROR_MAGIC",
            Error::Io => "IO_ERROR",
            Error::UnexpectedEof => "UNEXPECTED_EOF",
            Error::OutbuffFull => "OUTBUFF_FULL",
            Error::Config => "CONFIG_ERROR",
        }
    }

    fn from_number(code: i32) -> Error {
        match code {
            BZ_SEQUENCE_ERROR => Error::Sequence,
            BZ_PARAM_ERROR => Error::Param,
            BZ_MEM_ERROR => Error::Mem,
            BZ_DATA_ERROR => Error::Data,
            BZ_DATA_ERROR_MAGIC => Error::DataMagic,
            -6 => Error::Io,
            -7 => Error::UnexpectedEof,
            -8 => Error::OutbuffFull,
            _ => Error::Config,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl core::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

/// libbzip2's return code as the port returns it.
fn result(ret: i32) -> Result<Status> {
    match ret {
        BZ_OK => Ok(Status::Ok),
        BZ_RUN_OK => Ok(Status::RunOk),
        BZ_FLUSH_OK => Ok(Status::FlushOk),
        BZ_FINISH_OK => Ok(Status::FinishOk),
        BZ_STREAM_END => Ok(Status::StreamEnd),
        _ => Err(Error::from_number(ret)),
    }
}

/// `BZ2_bzlibVersion()`: `"1.0.8, 13-Jul-2019"`, the release the port
/// follows.
pub fn version() -> &'static str {
    BZ_VERSION
}

/// A compressor: a `bz_stream` set up by `BZ2_bzCompressInit`.
///
/// Its output is libbzip2's, byte for byte, with the same block size and
/// work factor, whatever pieces the input and output come in.
pub struct Compress {
    s: Box<EState>,
}

impl Compress {
    /// `BZ2_bzCompressInit(strm, blockSize100k, 0, workFactor)`: blocks of
    /// `block_size_100k` × 100,000 bytes, from 1 to 9, and a work factor
    /// from 0 to 250, 0 meaning the default, 30: how hard the main sorting
    /// algorithm tries on repetitive data before it gives way to the
    /// slower but steadier fallback. The output is the same with every
    /// work factor.
    ///
    /// Differs from libbzip2: there is no verbosity, as the port prints
    /// nothing.
    pub fn new(block_size_100k: i32, work_factor: i32) -> Result<Compress> {
        if !(1..=9).contains(&block_size_100k) || !(0..=250).contains(&work_factor) {
            return Err(Error::Param);
        }
        let work_factor = if work_factor == 0 { 30 } else { work_factor };
        let s = EState::new(block_size_100k, work_factor).ok_or(Error::Mem)?;
        Ok(Compress { s })
    }

    /// `BZ2_bzCompress`: reads what it can of `input`, and writes what it
    /// can to `output`, for `action`.
    ///
    /// As in libbzip2, [`Action::Run`] fails with [`Error::Param`] when it
    /// can neither read nor write. Once a flush or the end of the stream is
    /// asked for, every call until it is done must ask for it again, with
    /// the input that was left ([`Error::Sequence`] otherwise).
    ///
    /// Differs from libbzip2: there are no null pointers to check, but a
    /// buffer whose `pos` is past its end fails with [`Error::Param`].
    pub fn compress(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
        action: Action,
    ) -> Result<Status> {
        if output.pos > output.dst.len() || input.pos > input.src.len() {
            return Err(Error::Param);
        }
        result(self.s.compress(output, input, action))
    }

    /// `total_in`: the bytes read so far.
    pub fn total_in(&self) -> u64 {
        self.s.total_in
    }

    /// `total_out`: the bytes written so far.
    pub fn total_out(&self) -> u64 {
        self.s.total_out
    }
}

impl fmt::Debug for Compress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Compress")
            .field("total_in", &self.s.total_in)
            .field("total_out", &self.s.total_out)
            .finish_non_exhaustive()
    }
}

/// A decompressor: a `bz_stream` set up by `BZ2_bzDecompressInit`, for one
/// stream.
pub struct Decompress {
    s: Box<DState>,
    /// The error a call returned, which every later call returns again.
    failed: Option<Error>,
}

impl Decompress {
    /// `BZ2_bzDecompressInit(strm, 0, small)`: with `small`, the
    /// decompressor uses about 2.5 bytes for each byte of a block instead
    /// of 4, at about half the speed.
    ///
    /// Differs from libbzip2: there is no verbosity, as the port prints
    /// nothing, and `small` is a `bool`, so nothing can be out of range.
    pub fn new(small: bool) -> Decompress {
        Decompress {
            s: DState::new(small),
            failed: None,
        }
    }

    /// `BZ2_bzDecompress`: reads what it can of `input`, and writes what it
    /// can to `output`. It returns [`Status::StreamEnd`] once the stream's
    /// end is read and all of it written; any input after that is left
    /// unread, and later calls fail with [`Error::Sequence`].
    ///
    /// Differs from libbzip2: after an error, every later call returns it
    /// again. libbzip2's manual allows only `BZ2_bzDecompressEnd` after an
    /// error, and calling `BZ2_bzDecompress` anyway goes on from wherever
    /// it stopped, in ways that can read out of bounds. Also, there are no
    /// null pointers to check, but a buffer whose `pos` is past its end
    /// fails with [`Error::Param`].
    pub fn decompress(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
    ) -> Result<Status> {
        if output.pos > output.dst.len() || input.pos > input.src.len() {
            return Err(Error::Param);
        }
        if let Some(error) = self.failed {
            return Err(error);
        }
        let ret = bz_decompress(&mut self.s, output, input);
        if matches!(ret, BZ_MEM_ERROR | BZ_DATA_ERROR | BZ_DATA_ERROR_MAGIC) {
            self.failed = Some(Error::from_number(ret));
        }
        result(ret)
    }

    /// `total_in`: the bytes read so far.
    pub fn total_in(&self) -> u64 {
        self.s.total_in
    }

    /// `total_out`: the bytes written so far.
    pub fn total_out(&self) -> u64 {
        self.s.total_out
    }
}

impl fmt::Debug for Decompress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decompress")
            .field("total_in", &self.s.total_in)
            .field("total_out", &self.s.total_out)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

/// A vector with room for `n` items, or `None` where the memory is not
/// there, as `BZALLOC` returns `NULL`.
fn reserved<T>(n: usize) -> Option<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).ok()?;
    Some(v)
}

/// The bytes a [`Compress`] of blocks of `block_size_100k` × 100,000 bytes
/// takes: what [`EState::new`] reserves, and the state itself. Not
/// libbzip2's: [`CompressMt`](crate::bzip2::CompressMt) counts its threads'
/// memory with it.
pub(crate) fn compress_memory(block_size_100k: i32) -> u64 {
    let n = 100_000 * u64::from(block_size_100k.clamp(1, 9).unsigned_abs());
    let overshoot = u64::from(BZ_N_OVERSHOOT.unsigned_abs());
    // ptr and eclass, block, quadrant, mtfv, ftab and zbits, as below.
    let vectors = 4 * n * 2 + (n + overshoot) + 2 * (n + overshoot) + 2 * n + 4 * 65537;
    let zbits = n / 8 * 17 + 32768;
    vectors + zbits + size_of::<EState>() as u64
}

/// The most bytes a [`Decompress`] that is not small takes: a `u32` for
/// each byte of the largest block, and the state. Not libbzip2's: the
/// threads of `hivepack::open` count their memory with it.
#[cfg(feature = "open")]
pub(crate) fn decompress_memory() -> u64 {
    4 * 900_000 + size_of::<DState>() as u64
}

impl EState {
    /// The state `BZ2_bzCompressInit` sets up, with its parameters
    /// checked, or `None` without the memory.
    fn new(block_size_100k: i32, work_factor: i32) -> Option<Box<EState>> {
        let n = 100000 * block_size_100k as usize;
        let overshoot = BZ_N_OVERSHOOT as usize;
        // Where libbzip2 writes the compressed block, after the block in
        // arr2, there is room for 3 bytes and more for each byte of the
        // block; a block takes at most 17 bits for each, and a few
        // kilobytes of tables.
        let zbits = n / 8 * 17 + 32768;
        let mut ftab = reserved(65537)?;
        ftab.resize(65537, 0);
        let mut s = Box::new(EState {
            mode: BZ_M_RUNNING,
            state: BZ_S_INPUT,
            avail_in_expect: 0,
            ptr: reserved(n)?,
            block: reserved(n + overshoot)?,
            quadrant: reserved(n + overshoot)?,
            eclass: reserved(n)?,
            ftab,
            orig_ptr: 0,
            mtfv: reserved(n)?,
            zbits: reserved(zbits)?,
            work_factor,
            state_in_ch: 0,
            state_in_len: 0,
            nblock: 0,
            nblock_max: 100000 * block_size_100k - 19,
            state_out_pos: 0,
            n_in_use: 0,
            in_use: [false; 256],
            unseq_to_seq: [0; 256],
            bs_buff: 0,
            bs_live: 0,
            block_crc: 0,
            combined_crc: 0,
            block_no: 0,
            block_size_100k,
            n_mtf: 0,
            mtf_freq: [0; BZ_MAX_ALPHA_SIZE],
            selector: [0; BZ_MAX_SELECTORS],
            selector_mtf: [0; BZ_MAX_SELECTORS],
            len: [[0; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS],
            code: [[0; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS],
            rfreq: [[0; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS],
            len_pack: [[0; 4]; BZ_MAX_ALPHA_SIZE],
            total_in: 0,
            total_out: 0,
        });
        s.init_rl();
        s.prepare_new_block();
        Some(s)
    }

    /// `prepare_new_block`.
    fn prepare_new_block(&mut self) {
        self.nblock = 0;
        self.block.clear();
        self.zbits.clear();
        self.state_out_pos = 0;
        self.block_crc = crate::bzip2::crctable::CRC_INIT;
        self.in_use = [false; 256];
        self.block_no += 1;
    }

    /// `init_RL`.
    fn init_rl(&mut self) {
        self.state_in_ch = 256;
        self.state_in_len = 0;
    }

    /// `isempty_RL`.
    fn isempty_rl(&self) -> bool {
        !(self.state_in_ch < 256 && self.state_in_len > 0)
    }

    /// `add_pair_to_block`: the run held in `state_in_ch` and
    /// `state_in_len` added to the block, runs of 4 and more as 4 bytes
    /// and a count.
    fn add_pair_to_block(&mut self) {
        let ch = self.state_in_ch as u8;
        for _ in 0..self.state_in_len {
            self.block_crc = update_crc(self.block_crc, ch);
        }
        self.in_use[self.state_in_ch as usize] = true;
        match self.state_in_len {
            1 => self.block.push(ch),
            2 => self.block.extend_from_slice(&[ch, ch]),
            3 => self.block.extend_from_slice(&[ch, ch, ch]),
            _ => {
                self.in_use[(self.state_in_len - 4) as usize] = true;
                self.block
                    .extend_from_slice(&[ch, ch, ch, ch, (self.state_in_len - 4) as u8]);
            }
        }
        self.nblock = self.block.len() as i32;
    }

    /// `flush_RL`.
    fn flush_rl(&mut self) {
        if self.state_in_ch < 256 {
            self.add_pair_to_block();
        }
        self.init_rl();
    }

    /// `ADD_CHAR_TO_BLOCK`.
    #[inline(always)]
    fn add_char_to_block(&mut self, zchh0: u8) {
        let zchh = u32::from(zchh0);
        // Fast track the common case.
        if zchh != self.state_in_ch && self.state_in_len == 1 {
            let ch = self.state_in_ch as u8;
            self.block_crc = update_crc(self.block_crc, ch);
            self.in_use[self.state_in_ch as usize] = true;
            self.block.push(ch);
            self.nblock += 1;
            self.state_in_ch = zchh;
        } else if zchh != self.state_in_ch || self.state_in_len == 255 {
            // General, uncommon cases.
            if self.state_in_ch < 256 {
                self.add_pair_to_block();
            }
            self.state_in_ch = zchh;
            self.state_in_len = 1;
        } else {
            self.state_in_len += 1;
        }
    }

    /// `copy_input_until_stop`: true iff it read anything.
    fn copy_input_until_stop(&mut self, input: &mut InBuffer<'_>) -> bool {
        let mut progress_in = false;

        if self.mode == BZ_M_RUNNING {
            // Fast track the common case.
            loop {
                // Block full?
                if self.nblock >= self.nblock_max {
                    break;
                }
                // No input?
                if input.pos == input.src.len() {
                    break;
                }
                progress_in = true;
                self.add_char_to_block(input.src[input.pos]);
                input.pos += 1;
                self.total_in += 1;
            }
        } else {
            // General, uncommon case.
            loop {
                // Block full?
                if self.nblock >= self.nblock_max {
                    break;
                }
                // No input?
                if input.pos == input.src.len() {
                    break;
                }
                // Flush/finish end?
                if self.avail_in_expect == 0 {
                    break;
                }
                progress_in = true;
                self.add_char_to_block(input.src[input.pos]);
                input.pos += 1;
                self.total_in += 1;
                self.avail_in_expect -= 1;
            }
        }
        progress_in
    }

    /// `copy_output_until_stop`: true iff it wrote anything.
    fn copy_output_until_stop(&mut self, output: &mut OutBuffer<'_>) -> bool {
        // No output space, or block done?
        let n = (output.dst.len() - output.pos).min(self.zbits.len() - self.state_out_pos);
        output.dst[output.pos..output.pos + n]
            .copy_from_slice(&self.zbits[self.state_out_pos..self.state_out_pos + n]);
        self.state_out_pos += n;
        output.pos += n;
        self.total_out += n as u64;
        n > 0
    }

    /// `handle_compress`: true iff it read or wrote anything.
    fn handle_compress(&mut self, output: &mut OutBuffer<'_>, input: &mut InBuffer<'_>) -> bool {
        let mut progress_in = false;
        let mut progress_out = false;

        loop {
            if self.state == BZ_S_OUTPUT {
                progress_out |= self.copy_output_until_stop(output);
                if self.state_out_pos < self.zbits.len() {
                    break;
                }
                if self.mode == BZ_M_FINISHING && self.avail_in_expect == 0 && self.isempty_rl() {
                    break;
                }
                self.prepare_new_block();
                self.state = BZ_S_INPUT;
                if self.mode == BZ_M_FLUSHING && self.avail_in_expect == 0 && self.isempty_rl() {
                    break;
                }
            }

            if self.state == BZ_S_INPUT {
                progress_in |= self.copy_input_until_stop(input);
                if self.mode != BZ_M_RUNNING && self.avail_in_expect == 0 {
                    self.flush_rl();
                    self.compress_block(self.mode == BZ_M_FINISHING);
                    self.state = BZ_S_OUTPUT;
                } else if self.nblock >= self.nblock_max {
                    self.compress_block(false);
                    self.state = BZ_S_OUTPUT;
                } else if input.pos == input.src.len() {
                    break;
                }
            }
        }

        progress_in || progress_out
    }

    /// `BZ2_bzCompress`, after the checks of its arguments.
    fn compress(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
        action: Action,
    ) -> i32 {
        loop {
            // preswitch:
            match self.mode {
                BZ_M_IDLE => return BZ_SEQUENCE_ERROR,

                BZ_M_RUNNING => match action {
                    Action::Run => {
                        let progress = self.handle_compress(output, input);
                        return if progress { BZ_RUN_OK } else { BZ_PARAM_ERROR };
                    }
                    Action::Flush => {
                        self.avail_in_expect = input.src.len() - input.pos;
                        self.mode = BZ_M_FLUSHING;
                    }
                    Action::Finish => {
                        self.avail_in_expect = input.src.len() - input.pos;
                        self.mode = BZ_M_FINISHING;
                    }
                },

                BZ_M_FLUSHING => {
                    if action != Action::Flush {
                        return BZ_SEQUENCE_ERROR;
                    }
                    if self.avail_in_expect != input.src.len() - input.pos {
                        return BZ_SEQUENCE_ERROR;
                    }
                    self.handle_compress(output, input);
                    if self.avail_in_expect > 0
                        || !self.isempty_rl()
                        || self.state_out_pos < self.zbits.len()
                    {
                        return BZ_FLUSH_OK;
                    }
                    self.mode = BZ_M_RUNNING;
                    return BZ_RUN_OK;
                }

                _ => {
                    // BZ_M_FINISHING.
                    if action != Action::Finish {
                        return BZ_SEQUENCE_ERROR;
                    }
                    if self.avail_in_expect != input.src.len() - input.pos {
                        return BZ_SEQUENCE_ERROR;
                    }
                    let progress = self.handle_compress(output, input);
                    if !progress {
                        return BZ_SEQUENCE_ERROR;
                    }
                    if self.avail_in_expect > 0
                        || !self.isempty_rl()
                        || self.state_out_pos < self.zbits.len()
                    {
                        return BZ_FINISH_OK;
                    }
                    self.mode = BZ_M_IDLE;
                    return BZ_STREAM_END;
                }
            }
        }
    }
}

/// `unRLE_obuf_to_output_FAST`: writes the block out, undoing the first
/// run-length coding, with the fast decompressor's `tt`. True iff data
/// corruption is discovered.
fn unrle_obuf_to_output_fast(s: &mut DState, output: &mut OutBuffer<'_>) -> bool {
    let limit = 100000 * s.block_size_100k as u32;

    if s.block_randomised {
        // `BZ_GET_FAST`.
        macro_rules! get_fast {
            () => {{
                // c_tPos is unsigned, hence test < 0 is pointless.
                if s.t_pos >= limit {
                    return true;
                }
                s.t_pos = s.tt[s.t_pos as usize];
                let cccc = (s.t_pos & 0xff) as u8;
                s.t_pos >>= 8;
                cccc
            }};
        }

        loop {
            // Try to finish existing run.
            loop {
                if output.pos == output.dst.len() {
                    return false;
                }
                if s.state_out_len == 0 {
                    break;
                }
                output.dst[output.pos] = s.state_out_ch;
                s.calculated_block_crc = update_crc(s.calculated_block_crc, s.state_out_ch);
                s.state_out_len -= 1;
                output.pos += 1;
                s.total_out += 1;
            }

            // Can a new run be started?
            if s.nblock_used == s.save.nblock + 1 {
                return false;
            }

            // Only caused by corrupt data stream?
            if s.nblock_used > s.save.nblock + 1 {
                return true;
            }

            s.state_out_len = 1;
            s.state_out_ch = s.k0;
            let mut k1 = get_fast!();
            k1 ^= s.rand.update_mask();
            s.nblock_used += 1;
            if s.nblock_used == s.save.nblock + 1 {
                continue;
            }
            if k1 != s.k0 {
                s.k0 = k1;
                continue;
            }

            s.state_out_len = 2;
            let mut k1 = get_fast!();
            k1 ^= s.rand.update_mask();
            s.nblock_used += 1;
            if s.nblock_used == s.save.nblock + 1 {
                continue;
            }
            if k1 != s.k0 {
                s.k0 = k1;
                continue;
            }

            s.state_out_len = 3;
            let mut k1 = get_fast!();
            k1 ^= s.rand.update_mask();
            s.nblock_used += 1;
            if s.nblock_used == s.save.nblock + 1 {
                continue;
            }
            if k1 != s.k0 {
                s.k0 = k1;
                continue;
            }

            let mut k1 = get_fast!();
            k1 ^= s.rand.update_mask();
            s.nblock_used += 1;
            s.state_out_len = i32::from(k1) + 4;
            s.k0 = get_fast!();
            s.k0 ^= s.rand.update_mask();
            s.nblock_used += 1;
        }
    }

    // Restore.
    let mut c_calculated_block_crc = s.calculated_block_crc;
    let mut c_state_out_ch = s.state_out_ch;
    let mut c_state_out_len = s.state_out_len;
    let mut c_nblock_used = s.nblock_used;
    let mut c_k0 = s.k0;
    let c_tt = &s.tt;
    let mut c_t_pos = s.t_pos;
    let dst = &mut *output.dst;
    let mut cs_next_out = output.pos;
    // End restore.

    let s_save_nblock_pp = s.save.nblock + 1;

    // `BZ_GET_FAST_C`. On a return, the bytes written by this call are not
    // counted in `output.pos`, as libbzip2 leaves `next_out` and
    // `avail_out` as they were.
    macro_rules! get_fast_c {
        () => {{
            // c_tPos is unsigned, hence test < 0 is pointless.
            if c_t_pos >= limit {
                return true;
            }
            c_t_pos = c_tt[c_t_pos as usize];
            let cccc = (c_t_pos & 0xff) as u8;
            c_t_pos >>= 8;
            cccc
        }};
    }

    // Set where libbzip2 jumps to `s_state_out_len_eq_one`: one byte of
    // the run is left to write.
    let mut eq_one = false;
    'return_notr: loop {
        // Try to finish existing run.
        if eq_one || c_state_out_len > 0 {
            if !eq_one {
                loop {
                    if cs_next_out == dst.len() {
                        break 'return_notr;
                    }
                    if c_state_out_len == 1 {
                        break;
                    }
                    dst[cs_next_out] = c_state_out_ch;
                    c_calculated_block_crc = update_crc(c_calculated_block_crc, c_state_out_ch);
                    c_state_out_len -= 1;
                    cs_next_out += 1;
                }
            }
            // s_state_out_len_eq_one:
            eq_one = false;
            if cs_next_out == dst.len() {
                c_state_out_len = 1;
                break 'return_notr;
            }
            dst[cs_next_out] = c_state_out_ch;
            c_calculated_block_crc = update_crc(c_calculated_block_crc, c_state_out_ch);
            cs_next_out += 1;
        }
        // Only caused by corrupt data stream?
        if c_nblock_used > s_save_nblock_pp {
            return true;
        }

        // Can a new run be started?
        if c_nblock_used == s_save_nblock_pp {
            c_state_out_len = 0;
            break 'return_notr;
        }
        c_state_out_ch = c_k0;
        let k1 = get_fast_c!();
        c_nblock_used += 1;
        if k1 != c_k0 {
            c_k0 = k1;
            eq_one = true;
            continue;
        }
        if c_nblock_used == s_save_nblock_pp {
            eq_one = true;
            continue;
        }

        c_state_out_len = 2;
        let k1 = get_fast_c!();
        c_nblock_used += 1;
        if c_nblock_used == s_save_nblock_pp {
            continue;
        }
        if k1 != c_k0 {
            c_k0 = k1;
            continue;
        }

        c_state_out_len = 3;
        let k1 = get_fast_c!();
        c_nblock_used += 1;
        if c_nblock_used == s_save_nblock_pp {
            continue;
        }
        if k1 != c_k0 {
            c_k0 = k1;
            continue;
        }

        let k1 = get_fast_c!();
        c_nblock_used += 1;
        c_state_out_len = i32::from(k1) + 4;
        c_k0 = get_fast_c!();
        c_nblock_used += 1;
    }

    // return_notr:
    s.total_out += (cs_next_out - output.pos) as u64;

    // Save.
    s.calculated_block_crc = c_calculated_block_crc;
    s.state_out_ch = c_state_out_ch;
    s.state_out_len = c_state_out_len;
    s.nblock_used = c_nblock_used;
    s.k0 = c_k0;
    s.t_pos = c_t_pos;
    output.pos = cs_next_out;
    // End save.
    false
}

/// `unRLE_obuf_to_output_SMALL`: as [`unrle_obuf_to_output_fast`], with
/// the small decompressor's `ll16` and `ll4`.
fn unrle_obuf_to_output_small(s: &mut DState, output: &mut OutBuffer<'_>) -> bool {
    let limit = 100000 * s.block_size_100k as u32;

    // `BZ_GET_SMALL`.
    macro_rules! get_small {
        () => {{
            // c_tPos is unsigned, hence test < 0 is pointless.
            if s.t_pos >= limit {
                return true;
            }
            let cccc = index_into_f(s.t_pos as i32, &s.cftab) as u8;
            s.t_pos = s.get_ll(s.t_pos as usize);
            cccc
        }};
    }
    // The mask of a randomised block, or nothing.
    let randomised = s.block_randomised;
    macro_rules! mask {
        () => {
            if randomised { s.rand.update_mask() } else { 0 }
        };
    }

    loop {
        // Try to finish existing run.
        loop {
            if output.pos == output.dst.len() {
                return false;
            }
            if s.state_out_len == 0 {
                break;
            }
            output.dst[output.pos] = s.state_out_ch;
            s.calculated_block_crc = update_crc(s.calculated_block_crc, s.state_out_ch);
            s.state_out_len -= 1;
            output.pos += 1;
            s.total_out += 1;
        }

        // Can a new run be started?
        if s.nblock_used == s.save.nblock + 1 {
            return false;
        }

        // Only caused by corrupt data stream?
        if s.nblock_used > s.save.nblock + 1 {
            return true;
        }

        s.state_out_len = 1;
        s.state_out_ch = s.k0;
        let mut k1 = get_small!();
        k1 ^= mask!();
        s.nblock_used += 1;
        if s.nblock_used == s.save.nblock + 1 {
            continue;
        }
        if k1 != s.k0 {
            s.k0 = k1;
            continue;
        }

        s.state_out_len = 2;
        let mut k1 = get_small!();
        k1 ^= mask!();
        s.nblock_used += 1;
        if s.nblock_used == s.save.nblock + 1 {
            continue;
        }
        if k1 != s.k0 {
            s.k0 = k1;
            continue;
        }

        s.state_out_len = 3;
        let mut k1 = get_small!();
        k1 ^= mask!();
        s.nblock_used += 1;
        if s.nblock_used == s.save.nblock + 1 {
            continue;
        }
        if k1 != s.k0 {
            s.k0 = k1;
            continue;
        }

        let mut k1 = get_small!();
        k1 ^= mask!();
        s.nblock_used += 1;
        s.state_out_len = i32::from(k1) + 4;
        s.k0 = get_small!();
        s.k0 ^= mask!();
        s.nblock_used += 1;
    }
}

/// `BZ2_bzDecompress`, after the checks of its arguments.
fn bz_decompress(s: &mut DState, output: &mut OutBuffer<'_>, input: &mut InBuffer<'_>) -> i32 {
    loop {
        if s.state == BZ_X_IDLE {
            return BZ_SEQUENCE_ERROR;
        }
        if s.state == BZ_X_OUTPUT {
            let corrupt = if s.small_decompress {
                unrle_obuf_to_output_small(s, output)
            } else {
                unrle_obuf_to_output_fast(s, output)
            };
            if corrupt {
                return BZ_DATA_ERROR;
            }
            if s.nblock_used == s.save.nblock + 1 && s.state_out_len == 0 {
                s.calculated_block_crc = !s.calculated_block_crc;
                if s.calculated_block_crc != s.stored_block_crc {
                    return BZ_DATA_ERROR;
                }
                s.calculated_combined_crc = s.calculated_combined_crc.rotate_left(1);
                s.calculated_combined_crc ^= s.calculated_block_crc;
                s.state = BZ_X_BLKHDR_1;
            } else {
                return BZ_OK;
            }
        }
        if s.state >= BZ_X_MAGIC_1 {
            let r = decompress(s, input);
            if r == BZ_STREAM_END {
                if s.calculated_combined_crc != s.stored_combined_crc {
                    return BZ_DATA_ERROR;
                }
                return r;
            }
            // Differs from libbzip2, for what never happens: where
            // BZ2_decompress fails after setting BZ_X_OUTPUT (see
            // decompress.rs), this returns its error at once.
            if r < 0 || s.state != BZ_X_OUTPUT {
                return r;
            }
        }
    }
}

/// `BZ2_bzBuffToBuffCompress`: `source` compressed into `dest`, in one
/// call. It returns the length of the stream, or [`Error::OutbuffFull`]
/// if it did not fit.
pub fn buff_to_buff_compress(
    dest: &mut [u8],
    source: &[u8],
    block_size_100k: i32,
    work_factor: i32,
) -> Result<usize> {
    let mut strm = Compress::new(block_size_100k, work_factor)?;
    let mut output = OutBuffer::new(dest);
    let mut input = InBuffer::new(source);
    match strm.compress(&mut output, &mut input, Action::Finish)? {
        Status::StreamEnd => Ok(output.pos),
        Status::FinishOk => Err(Error::OutbuffFull),
        // BZ2_bzCompress with BZ_FINISH returns nothing else on success.
        _ => Err(Error::Sequence),
    }
}

/// `BZ2_bzBuffToBuffDecompress`: the stream at the start of `source`
/// decompressed into `dest`, in one call. It returns the length of the
/// output, [`Error::OutbuffFull`] if it did not fit, or
/// [`Error::UnexpectedEof`] if `source` ends before the stream does.
pub fn buff_to_buff_decompress(dest: &mut [u8], source: &[u8], small: bool) -> Result<usize> {
    let mut strm = Decompress::new(small);
    let mut output = OutBuffer::new(dest);
    let mut input = InBuffer::new(source);
    match strm.decompress(&mut output, &mut input)? {
        Status::StreamEnd => Ok(output.pos),
        _ => {
            if output.pos < output.dst.len() {
                Err(Error::UnexpectedEof)
            } else {
                Err(Error::OutbuffFull)
            }
        }
    }
}
