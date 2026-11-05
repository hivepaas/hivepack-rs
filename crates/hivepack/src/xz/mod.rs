//! .xz and .lzma compression, and .xz, .lzma and .lz decompression, in safe
//! Rust, ported from the official library, liblzma of
//! [XZ Utils](https://tukaani.org/xz/) 5.8.4.
//!
//! A [`Stream`] codes as an `lzma_stream` does, with the coder it was made
//! with. The decoders: `.xz` ([`Stream::stream_decoder`]), the same in threads
//! ([`Stream::stream_decoder_mt`]), `.lzma`
//! ([`Stream::alone_decoder`]), `.lz` ([`Stream::lzip_decoder`]), any of
//! them by their first byte ([`Stream::auto_decoder`]), or raw LZMA1 and
//! LZMA2 ([`Stream::raw_decoder`]). The encoders: `.xz` of a preset
//! ([`Stream::easy_encoder`]) or of a filter chain
//! ([`Stream::stream_encoder`]), the same in threads
//! ([`Stream::stream_encoder_mt`]), `.lzma` ([`Stream::alone_encoder`]), or
//! raw ([`Stream::raw_encoder`]); and in one call, [`easy_buffer_encode`],
//! [`stream_buffer_encode`] and [`raw_buffer_encode`]. Each call gives
//! liblzma's result and reads and writes what liblzma reads and writes: the
//! encoders write liblzma's bytes. The rules the port follows, and how it
//! is checked, are in the repository: `docs/xz.md` and `docs/safety.md`.
//!
//! ```
//! # fn main() -> Result<(), hivepack::xz::Error> {
//! use hivepack::xz::{Action, InBuffer, OutBuffer, Status, Stream};
//!
//! // "hello\n" in an .xz Stream with a CRC64, as liblzma writes it.
//! let xz = [
//!     0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46,
//!     0x02, 0xc0, 0x0a, 0x06, 0x21, 0x01, 0x16, 0x00, 0xe2, 0x86, 0x15, 0xc0,
//!     0x01, 0x00, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x0a, 0x00, 0x00, 0x00,
//!     0xa5, 0x60, 0x97, 0xf1, 0x94, 0xf6, 0xfd, 0xe0, 0x00, 0x01, 0x1e, 0x06,
//!     0xc1, 0x2f, 0xa4, 0x1d, 0x1f, 0xb6, 0xf3, 0x7d, 0x01, 0x00, 0x00, 0x00,
//!     0x00, 0x04, 0x59, 0x5a,
//! ];
//! let mut stream = Stream::stream_decoder(u64::MAX, 0)?;
//! let mut out = [0; 16];
//! let mut output = OutBuffer::new(&mut out);
//! let status = stream.code(&mut output, &mut InBuffer::new(&xz), Action::Finish)?;
//! assert_eq!(status, Status::StreamEnd);
//! let written = output.pos;
//! assert_eq!(&out[..written], b"hello\n");
//! # Ok(())
//! # }
//! ```
//!
//! Encoding, in one call:
//!
//! ```
//! # fn main() -> Result<(), hivepack::xz::Error> {
//! use hivepack::xz::{Check, PRESET_DEFAULT, easy_buffer_encode, stream_buffer_bound};
//!
//! let data = b"hello\n";
//! let mut xz = vec![0; stream_buffer_bound(data.len())];
//! let mut len = 0;
//! easy_buffer_encode(PRESET_DEFAULT, Check::CRC64, data, &mut xz, &mut len)?;
//! xz.truncate(len);
//! // The Stream liblzma writes, byte for byte.
//! assert_eq!(&xz[..6], b"\xfd7zXZ\0");
//! assert_eq!(len, 64);
//! # Ok(())
//! # }
//! ```
//!
//! A filter chain ends with LZMA1 or LZMA2, and may have up to three
//! delta ([`Filter::delta`]) and BCJ ([`Filter::bcj`]) filters before it,
//! which help executables and tables of numbers compress:
//!
//! ```
//! # fn main() -> Result<(), hivepack::xz::Error> {
//! use hivepack::xz::{
//!     Action, Check, FILTER_X86, Filter, InBuffer, LzmaOptions, OutBuffer, Stream,
//!     stream_buffer_bound, stream_buffer_encode,
//! };
//!
//! // x86 calls to a function at 0x1000, from all over.
//! let mut code = Vec::new();
//! for at in (0..4000u32).step_by(5) {
//!     code.push(0xe8);
//!     code.extend_from_slice(&0x1000u32.wrapping_sub(at + 5).to_le_bytes());
//! }
//! let filters = [Filter::bcj(FILTER_X86, 0), Filter::lzma2(LzmaOptions::preset(6).unwrap())];
//! let mut xz = vec![0; stream_buffer_bound(code.len())];
//! let mut len = 0;
//! stream_buffer_encode(&filters, Check::CRC64, &code, &mut xz, &mut len)?;
//!
//! let mut stream = Stream::stream_decoder(u64::MAX, 0)?;
//! let mut out = vec![0; code.len()];
//! stream.code(&mut OutBuffer::new(&mut out), &mut InBuffer::new(&xz[..len]), Action::Finish)?;
//! assert_eq!(out, code);
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
// Loops keep liblzma's indices, so the port reads side by side with the C.
#![allow(clippy::needless_range_loop)]

mod alone_decoder;
mod alone_encoder;
mod auto_decoder;
mod block;
mod check;
mod common;
mod delta;
mod filter;
mod index_hash;
mod lz_decoder;
mod lz_encoder;
mod lzip_decoder;
mod lzma2_decoder;
mod lzma2_encoder;
mod lzma_common;
mod lzma_decoder;
mod lzma_encoder;
mod outqueue;
mod range_decoder;
mod range_encoder;
mod simple;
mod stream_decoder;
mod stream_decoder_mt;
mod stream_encoder;
mod stream_encoder_mt;
mod stream_flags;
mod vli;

use core::fmt;

pub use check::{CHECK_ID_MAX, Check};
pub use common::{
    Action, CONCATENATED, FAIL_FAST, IGNORE_CHECK, TELL_ANY_CHECK, TELL_NO_CHECK,
    TELL_UNSUPPORTED_CHECK,
};
pub use filter::{
    BcjOptions, DELTA_DIST_MAX, DELTA_DIST_MIN, DELTA_TYPE_BYTE, DeltaOptions, FILTER_ARM,
    FILTER_ARM64, FILTER_ARMTHUMB, FILTER_DELTA, FILTER_IA64, FILTER_LZMA1, FILTER_LZMA1EXT,
    FILTER_LZMA2, FILTER_POWERPC, FILTER_RISCV, FILTER_SPARC, FILTER_X86, FILTERS_MAX, Filter,
    FilterOptions, decoder_is_supported, encoder_is_supported, raw_decoder_memusage,
    raw_encoder_memusage,
};
pub use lzma_common::{
    DICT_SIZE_DEFAULT, DICT_SIZE_MIN, LC_DEFAULT, LCLP_MAX, LP_DEFAULT, LZMA1EXT_ALLOW_EOPM,
    LzmaOptions, MatchFinder, Mode, PB_DEFAULT, PB_MAX, PRESET_DEFAULT, PRESET_EXTREME,
    PRESET_LEVEL_MASK,
};
pub use simple::{
    bcj_arm64_decode, bcj_arm64_encode, bcj_riscv_decode, bcj_riscv_encode, bcj_x86_decode,
    bcj_x86_encode,
};
pub use stream_encoder_mt::MtOptions;

use common::{Internal, Ret};

/// The XZ Utils release this crate follows.
pub const UPSTREAM_VERSION: &str = "5.8.4";

/// `lzma_version_number()`: `LZMA_VERSION` of the release the port
/// follows, 50080042 for 5.8.4 stable.
pub fn version_number() -> u32 {
    50_080_042
}

/// `lzma_version_string()`.
pub fn version_string() -> &'static str {
    "5.8.4"
}

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

/// Success, or something to know: liblzma's return codes that are not
/// errors, with the same numbers.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Status {
    /// `LZMA_OK`: progress was made, and the stream goes on.
    Ok,
    /// `LZMA_STREAM_END`: the end of the stream.
    StreamEnd,
    /// `LZMA_NO_CHECK`: the Stream has no integrity check
    /// ([`TELL_NO_CHECK`]). Decoding can go on.
    NoCheck,
    /// `LZMA_UNSUPPORTED_CHECK`: the Stream's integrity check cannot be
    /// computed ([`TELL_UNSUPPORTED_CHECK`]). Decoding can go on.
    UnsupportedCheck,
    /// `LZMA_GET_CHECK`: [`Stream::get_check`] can now tell the Stream's
    /// integrity check ([`TELL_ANY_CHECK`]). Decoding can go on.
    GetCheck,
}

impl Status {
    /// The number liblzma gives this result.
    pub fn number(self) -> i32 {
        match self {
            Status::Ok => 0,
            Status::StreamEnd => 1,
            Status::NoCheck => 2,
            Status::UnsupportedCheck => 3,
            Status::GetCheck => 4,
        }
    }
}

/// liblzma's error codes, with the same numbers.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum Error {
    /// `LZMA_UNSUPPORTED_CHECK` where it is an error: an encoder cannot be
    /// made with an integrity check this build cannot compute. (From
    /// [`Stream::code`] it is [`Status::UnsupportedCheck`].)
    UnsupportedCheck = 3,
    /// `LZMA_MEM_ERROR`: not enough memory.
    Mem = 5,
    /// `LZMA_MEMLIMIT_ERROR`: the memory usage limit was reached. Not
    /// fatal: decoding goes on once [`Stream::memlimit_set`] raises it.
    Memlimit = 6,
    /// `LZMA_FORMAT_ERROR`: the input is not in the format of the decoder.
    Format = 7,
    /// `LZMA_OPTIONS_ERROR`: an option or a feature is not supported.
    Options = 8,
    /// `LZMA_DATA_ERROR`: the data is corrupt.
    Data = 9,
    /// `LZMA_BUF_ERROR`: no progress was possible, twice in a row.
    Buf = 10,
    /// `LZMA_PROG_ERROR`: the calls were not as liblzma allows.
    Prog = 11,
}

impl Error {
    /// The number liblzma gives this error.
    pub fn number(self) -> i32 {
        self as i32
    }

    /// A short description of the error.
    pub fn message(self) -> &'static str {
        match self {
            Error::UnsupportedCheck => "unsupported type of integrity check",
            Error::Mem => "cannot allocate memory",
            Error::Memlimit => "memory usage limit reached",
            Error::Format => "file format not recognized",
            Error::Options => "unsupported options",
            Error::Data => "compressed data is corrupt",
            Error::Buf => "unexpected end of input",
            Error::Prog => "programming error",
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

/// liblzma's return code as the port returns it.
fn result(ret: Ret) -> Result<Status> {
    match ret {
        Ret::Ok => Ok(Status::Ok),
        Ret::StreamEnd => Ok(Status::StreamEnd),
        Ret::NoCheck => Ok(Status::NoCheck),
        Ret::UnsupportedCheck => Ok(Status::UnsupportedCheck),
        Ret::GetCheck => Ok(Status::GetCheck),
        Ret::MemError => Err(Error::Mem),
        Ret::MemlimitError => Err(Error::Memlimit),
        Ret::FormatError => Err(Error::Format),
        Ret::OptionsError => Err(Error::Options),
        Ret::DataError => Err(Error::Data),
        Ret::BufError => Err(Error::Buf),
        Ret::ProgError => Err(Error::Prog),
        // lzma_code returns it as LZMA_OK.
        Ret::TimedOut => Ok(Status::Ok),
    }
}

/// An error code where initialization failed.
fn init_error(ret: Ret) -> Error {
    match result(ret) {
        Err(e) => e,
        Ok(Status::UnsupportedCheck) => Error::UnsupportedCheck,
        Ok(_) => Error::Prog,
    }
}

/// An `lzma_stream` with its decoder, made by one of liblzma's
/// initialization functions.
pub struct Stream {
    internal: Internal,
}

// A stream can be moved to another thread.
const _: fn() = || {
    fn send<T: Send>() {}
    send::<Stream>();
};

impl Stream {
    fn new(next: Box<dyn common::NextCoder>) -> Stream {
        Stream::with_actions(next, &[Action::Run, Action::Finish])
    }

    fn with_actions(next: Box<dyn common::NextCoder>, actions: &[Action]) -> Stream {
        Stream {
            internal: Internal::new(next, actions),
        }
    }

    /// `lzma_easy_encoder`: a .xz encoder of a preset, 0 to 9 with
    /// [`PRESET_EXTREME`] or not, with an integrity check.
    pub fn easy_encoder(preset: u32, check: Check) -> Result<Stream> {
        let filters = easy_preset(preset).ok_or(Error::Options)?;
        Stream::stream_encoder(&filters, check)
    }

    /// `lzma_stream_encoder`: a .xz encoder of a filter chain, with an
    /// integrity check. It takes all the actions: [`Action::SyncFlush`]
    /// makes all the input so far decodable, [`Action::FullFlush`] and
    /// [`Action::FullBarrier`] end the Block too.
    pub fn stream_encoder(filters: &[Filter], check: Check) -> Result<Stream> {
        let encoder = stream_encoder::StreamEncoder::new(filters, check).map_err(init_error)?;
        Ok(Stream::with_actions(
            Box::new(encoder),
            &[
                Action::Run,
                Action::SyncFlush,
                Action::FullFlush,
                Action::FullBarrier,
                Action::Finish,
            ],
        ))
    }

    /// `lzma_stream_decoder_mt`: a .xz decoder that decodes Blocks in up to
    /// `options.threads` threads, as far as their sizes are in their headers
    /// (as the threaded encoder writes them) and `options.memlimit_threading`
    /// allows, and the others without threads. It takes [`Action::Run`] and
    /// [`Action::Finish`]. With [`FAIL_FAST`], an error is returned as soon
    /// as it is found, else after all the output before it.
    pub fn stream_decoder_mt(options: &MtOptions) -> Result<Stream> {
        let decoder = stream_decoder_mt::StreamDecoderMt::new(options).map_err(init_error)?;
        Ok(Stream::with_actions(
            Box::new(decoder),
            &[Action::Run, Action::Finish],
        ))
    }

    /// `lzma_stream_encoder_mt`: a .xz encoder that compresses Blocks of
    /// `options.block_size` bytes in up to `options.threads` threads, and
    /// writes the Blocks' sizes in their headers (which the single-threaded
    /// encoder does not). It takes [`Action::Run`], [`Action::FullFlush`],
    /// [`Action::FullBarrier`] and [`Action::Finish`]; with a timeout,
    /// [`Stream::code`] may return before it has used all the input or
    /// filled the output.
    pub fn stream_encoder_mt(options: &MtOptions) -> Result<Stream> {
        let encoder = stream_encoder_mt::StreamEncoderMt::new(options).map_err(init_error)?;
        Ok(Stream::with_actions(
            Box::new(encoder),
            &[
                Action::Run,
                Action::FullFlush,
                Action::FullBarrier,
                Action::Finish,
            ],
        ))
    }

    /// `lzma_alone_encoder`: a .lzma encoder. The header gives the size
    /// as unknown, and the data ends with the end of payload marker.
    pub fn alone_encoder(options: &LzmaOptions) -> Result<Stream> {
        let encoder = alone_encoder::AloneEncoder::new(options).map_err(init_error)?;
        Ok(Stream::new(Box::new(encoder)))
    }

    /// `lzma_raw_encoder`: an encoder of the raw data of a filter chain.
    /// LZMA2 takes [`Action::SyncFlush`]; LZMA1 does not.
    pub fn raw_encoder(filters: &[Filter]) -> Result<Stream> {
        let next = filter::raw_encoder_init(filters).map_err(init_error)?;
        Ok(Stream::with_actions(
            next,
            &[Action::Run, Action::SyncFlush, Action::Finish],
        ))
    }

    /// [`Stream::raw_encoder`] with what this one keeps: an encoder of the same
    /// kind goes on with its memory, as liblzma's does when `lzma_raw_encoder`
    /// gets the same `lzma_stream` again, and writes what a new one would. This
    /// one is used up, finished or not.
    pub fn raw_encoder_again(self, filters: &[Filter]) -> Result<Stream> {
        let next =
            filter::raw_encoder_reinit(filters, Some(self.internal.next)).map_err(init_error)?;
        Ok(Stream::with_actions(
            next,
            &[Action::Run, Action::SyncFlush, Action::Finish],
        ))
    }

    /// Not in liblzma: the encoder of a branch converter or the delta filter
    /// alone, which gives the filtered data, for what compresses it apart.
    #[cfg(feature = "sevenz")]
    pub(crate) fn filter_encoder(filter: &Filter) -> Result<Stream> {
        let next = filter::filter_encoder_alone(filter).map_err(init_error)?;
        Ok(Stream::new(next))
    }

    /// `lzma_stream_decoder`: a .xz decoder, with a memory usage limit and
    /// the flags [`TELL_NO_CHECK`], [`TELL_UNSUPPORTED_CHECK`],
    /// [`TELL_ANY_CHECK`], [`IGNORE_CHECK`], [`CONCATENATED`] and
    /// [`FAIL_FAST`] (which only the multithreaded decoder uses).
    pub fn stream_decoder(memlimit: u64, flags: u32) -> Result<Stream> {
        let decoder = stream_decoder::StreamDecoder::new(memlimit, flags).map_err(init_error)?;
        Ok(Stream::new(Box::new(decoder)))
    }

    /// `lzma_alone_decoder`: a .lzma decoder, with a memory usage limit.
    pub fn alone_decoder(memlimit: u64) -> Result<Stream> {
        Ok(Stream::new(Box::new(alone_decoder::AloneDecoder::new(
            memlimit, false,
        ))))
    }

    /// `lzma_lzip_decoder`: a .lz decoder, with a memory usage limit and
    /// the flags of [`Stream::stream_decoder`].
    pub fn lzip_decoder(memlimit: u64, flags: u32) -> Result<Stream> {
        let decoder = lzip_decoder::LzipDecoder::new(memlimit, flags).map_err(init_error)?;
        Ok(Stream::new(Box::new(decoder)))
    }

    /// `lzma_auto_decoder`: a decoder of .xz, .lzma or .lz, whichever the
    /// first byte says.
    pub fn auto_decoder(memlimit: u64, flags: u32) -> Result<Stream> {
        let decoder = auto_decoder::AutoDecoder::new(memlimit, flags).map_err(init_error)?;
        Ok(Stream::new(Box::new(decoder)))
    }

    /// `lzma_raw_decoder`: a decoder of the raw data of a filter chain.
    pub fn raw_decoder(filters: &[Filter]) -> Result<Stream> {
        let next = filter::raw_decoder_init(filters).map_err(init_error)?;
        Ok(Stream::new(next))
    }

    /// `lzma_code`: reads what it can of `input` and writes what it can to
    /// `output`.
    ///
    /// Differs from liblzma: there are no null pointers to check, nor
    /// reserved members, but a buffer whose `pos` is past its end fails
    /// with [`Error::Prog`].
    pub fn code(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
        action: Action,
    ) -> Result<Status> {
        if output.pos > output.dst.len() || input.pos > input.src.len() {
            return Err(Error::Prog);
        }
        result(self.internal.code(
            input.src,
            &mut input.pos,
            output.dst,
            &mut output.pos,
            action,
        ))
    }

    /// `lzma_get_check`: the integrity check of the Stream, once its header
    /// is decoded; `Check::NONE` where the decoder cannot tell.
    pub fn get_check(&self) -> Check {
        self.internal.get_check()
    }

    /// `lzma_memusage`: the memory the decoder needs now, as liblzma
    /// counts it; 0 where it cannot tell.
    pub fn memusage(&mut self) -> u64 {
        self.internal.memconfig_get().0
    }

    /// `lzma_memlimit_get`: the memory usage limit; 0 where the decoder has
    /// none.
    pub fn memlimit_get(&mut self) -> u64 {
        self.internal.memconfig_get().1
    }

    /// `lzma_memlimit_set`: a new memory usage limit (0 counts as 1).
    pub fn memlimit_set(&mut self, new_memlimit: u64) -> Result<()> {
        result(self.internal.memlimit_set(new_memlimit)).map(|_| ())
    }

    /// `lzma_get_progress`: the input read and output written so far.
    pub fn get_progress(&self) -> (u64, u64) {
        self.internal.get_progress()
    }

    /// `total_in`: the bytes read so far.
    pub fn total_in(&self) -> u64 {
        self.internal.total_in
    }

    /// `total_out`: the bytes written so far.
    pub fn total_out(&self) -> u64 {
        self.internal.total_out
    }
}

impl fmt::Debug for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stream")
            .field("total_in", &self.internal.total_in)
            .field("total_out", &self.internal.total_out)
            .finish_non_exhaustive()
    }
}

/// `lzma_easy_preset`: the filter chain of a preset, LZMA2 alone.
pub(crate) fn easy_preset(preset: u32) -> Option<Vec<Filter>> {
    Some(vec![Filter::lzma2(LzmaOptions::preset(preset)?)])
}

/// `lzma_stream_encoder_mt_memusage`: the memory the threaded encoder
/// needs, or u64::MAX if the options are invalid.
pub fn stream_encoder_mt_memusage(options: &MtOptions) -> u64 {
    stream_encoder_mt::stream_encoder_mt_memusage(options)
}

/// `lzma_cputhreads`: the number of hardware threads, or 0 if it cannot
/// be told.
pub fn cputhreads() -> u32 {
    std::thread::available_parallelism().map_or(0, |n| u32::try_from(n.get()).unwrap_or(u32::MAX))
}

/// `lzma_easy_encoder_memusage`: the memory the encoder of a preset needs,
/// or u32::MAX for an invalid preset, as liblzma returns.
pub fn easy_encoder_memusage(preset: u32) -> u64 {
    match easy_preset(preset) {
        Some(filters) => raw_encoder_memusage(&filters),
        None => u64::from(u32::MAX),
    }
}

/// `lzma_easy_decoder_memusage`: the memory the decoder of what a preset
/// encodes needs, or u32::MAX for an invalid preset.
pub fn easy_decoder_memusage(preset: u32) -> u64 {
    match easy_preset(preset) {
        Some(filters) => raw_decoder_memusage(&filters),
        None => u64::from(u32::MAX),
    }
}

/// The result of a single-call encoder.
fn buffer_result(ret: Ret) -> Result<()> {
    match ret {
        Ret::Ok => Ok(()),
        ret => Err(init_error(ret)),
    }
}

/// `lzma_easy_buffer_encode`: `input` as a .xz Stream of a preset, in one
/// call, written to `output[*out_pos..]`; `*out_pos` moves past it on
/// success.
pub fn easy_buffer_encode(
    preset: u32,
    check: Check,
    input: &[u8],
    output: &mut [u8],
    out_pos: &mut usize,
) -> Result<()> {
    let filters = easy_preset(preset).ok_or(Error::Options)?;
    stream_buffer_encode(&filters, check, input, output, out_pos)
}

/// `lzma_stream_buffer_encode`: `input` as a .xz Stream of a filter chain,
/// in one call, as [`easy_buffer_encode`] writes it. Empty input makes a
/// Stream without Blocks; data that does not compress is stored in
/// LZMA2's uncompressed chunks.
pub fn stream_buffer_encode(
    filters: &[Filter],
    check: Check,
    input: &[u8],
    output: &mut [u8],
    out_pos: &mut usize,
) -> Result<()> {
    buffer_result(stream_encoder::stream_buffer_encode(
        filters, check, input, output, out_pos,
    ))
}

/// `lzma_stream_buffer_bound`: the most output [`stream_buffer_encode`]
/// can need for `uncompressed_size` bytes, or 0 if too large.
pub fn stream_buffer_bound(uncompressed_size: usize) -> usize {
    stream_encoder::stream_buffer_bound(uncompressed_size)
}

/// `lzma_raw_buffer_encode`: `input` as the raw data of a filter chain, in
/// one call; on failure `*out_pos` is left as it was.
pub fn raw_buffer_encode(
    filters: &[Filter],
    input: &[u8],
    output: &mut [u8],
    out_pos: &mut usize,
) -> Result<()> {
    if *out_pos > output.len() {
        return Err(Error::Prog);
    }

    let mut next = filter::raw_encoder_init(filters).map_err(init_error)?;

    // Do the actual encoding with LZMA_FINISH.
    let out_start = *out_pos;
    let mut in_pos = 0;
    let mut ret = next.code(input, &mut in_pos, output, out_pos, Action::Finish);

    if ret == Ret::StreamEnd {
        ret = Ret::Ok;
    } else {
        if ret == Ret::Ok {
            // Output buffer was too small.
            ret = Ret::BufError;
        }

        // Restore the output position.
        *out_pos = out_start;
    }

    buffer_result(ret)
}
