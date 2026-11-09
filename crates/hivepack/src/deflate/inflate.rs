//! Decompression: port of `inflate.{h,c}`.
//!
//! `inflate()` is a state machine: each call goes as far as the input and
//! the output space allow, keeps where it stopped in [`InflateState`], and
//! goes on from there on the next call. The modes, their order and the
//! transitions between them are zlib's:
//!
//! ```text
//! Process header:
//!     HEAD -> (gzip) or (zlib) or (raw)
//!     (gzip) -> FLAGS -> TIME -> OS -> EXLEN -> EXTRA -> NAME -> COMMENT ->
//!               HCRC -> TYPE
//!     (zlib) -> DICTID or TYPE
//!     DICTID -> DICT -> TYPE
//!     (raw) -> TYPEDO
//! Read deflate blocks:
//!         TYPE -> TYPEDO -> STORED or TABLE or LEN_ or CHECK
//!         STORED -> COPY_ -> COPY -> TYPE
//!         TABLE -> LENLENS -> CODELENS -> LEN_
//!         LEN_ -> LEN
//! Read deflate codes in fixed or dynamic block:
//!             LEN -> LENEXT or LIT or TYPE
//!             LENEXT -> DIST -> DISTEXT -> MATCH -> LEN
//!             LIT -> LEN
//! Process trailer:
//!     CHECK -> LENGTH -> DONE
//! ```
//!
//! Differs from zlib: the stream (`z_stream`) and its state are one value,
//! [`Inflate`], whose input and output are given to each call as an
//! [`InBuffer`] and an [`OutBuffer`]. A call cannot be made on a stream that
//! was never initialised or already ended, so the checks zlib makes for
//! that (`inflateStateCheck`) are left out, as are the custom allocators.

use crate::deflate::adler32::{ADLER32_INIT, adler32};
use crate::deflate::crc32::crc32;
use crate::deflate::inffast::inflate_fast;
use crate::deflate::inffixed::{DISTFIX, LENFIX};
use crate::deflate::inftrees::{Code, CodeType, ENOUGH, ENOUGH_LENS, inflate_fixed, inflate_table};

/// How many entries [`InflateState::fast_table`] gives: a power of two at
/// least `ENOUGH_LENS`, the most entries a table and its sub-tables take.
pub(crate) const TABLE_SPAN: usize = 1024;

/// The size of `codes`: `ENOUGH` would do, but with `TABLE_SPAN` entries
/// from the start of the distance table, which starts at most
/// `ENOUGH_LENS` entries in, every table has `TABLE_SPAN` entries.
const CODES_SIZE: usize = ENOUGH_LENS + TABLE_SPAN;
const _: () = assert!(CODES_SIZE >= ENOUGH);

/// `table` at the start of `TABLE_SPAN` entries, the rest invalid codes.
const fn span<const N: usize>(table: &[Code; N]) -> [Code; TABLE_SPAN] {
    let mut span = [Code::new(64, 1, 0); TABLE_SPAN];
    let mut i = 0;
    while i < N {
        span[i] = table[i];
        i += 1;
    }
    span
}

static LENFIX_SPAN: [Code; TABLE_SPAN] = span(&LENFIX);
static DISTFIX_SPAN: [Code; TABLE_SPAN] = span(&DISTFIX);

use crate::deflate::zutil::{
    DEF_WBITS, Error, ErrorCode, Flush, Result, Status, Z_BUF_ERROR, Z_DATA_ERROR, Z_DEFLATED,
    Z_OK, Z_STREAM_END, result, zswap32,
};

/// `inflate_mode`: where inflate() stopped, in the order of zlib's, which
/// the code compares.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum Mode {
    /// waiting for magic header
    Head = 16180,
    /// waiting for method and flags (gzip)
    Flags,
    /// waiting for modification time (gzip)
    Time,
    /// waiting for extra flags and operating system (gzip)
    Os,
    /// waiting for extra length (gzip)
    ExLen,
    /// waiting for extra bytes (gzip)
    Extra,
    /// waiting for end of file name (gzip)
    Name,
    /// waiting for end of comment (gzip)
    Comment,
    /// waiting for header crc (gzip)
    HCrc,
    /// waiting for dictionary check value
    DictId,
    /// waiting for inflateSetDictionary() call
    Dict,
    /// waiting for type bits, including last-flag bit
    Type,
    /// same, but skip check to exit inflate on new block
    TypeDo,
    /// waiting for stored size (length and complement)
    Stored,
    /// same as COPY below, but only first time in
    Copy_,
    /// waiting for input or output to copy stored block
    Copy,
    /// waiting for dynamic block table lengths
    Table,
    /// waiting for code length code lengths
    LenLens,
    /// waiting for length/lit and distance code lengths
    CodeLens,
    /// same as LEN below, but only first time in
    Len_,
    /// waiting for length/lit/eob code
    Len,
    /// waiting for length extra bits
    LenExt,
    /// waiting for distance code
    Dist,
    /// waiting for distance extra bits
    DistExt,
    /// waiting for output space to copy string
    Match,
    /// waiting for output space to write literal
    Lit,
    /// waiting for 32-bit check value
    Check,
    /// waiting for 32-bit length (gzip)
    Length,
    /// finished check, done -- remain here until reset
    Done,
    /// got a data error -- remain here until reset
    Bad,
    /// got an inflate() memory error -- remain here until reset
    Mem,
    /// looking for synchronization bytes to restart inflate()
    Sync,
}

/// Which table a code pointer of `inflate_state` points to.
///
/// Differs from zlib: an index into `codes`, or one of the fixed tables,
/// instead of a pointer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Table {
    LenFix,
    DistFix,
    Codes(usize),
}

/// What a gzip header said, as `inflateGetHeader` asks inflate() to fill
/// it in: `gz_header` in `zlib.h`.
///
/// The extra field, name and comment are kept only if a buffer for them is
/// given, and only as much of them as fits: the buffer's length is zlib's
/// `extra_max`, `name_max` or `comm_max`. The name and comment keep their
/// terminating zero when it fits. When the header has no such field,
/// inflate() sets the buffer to `None`.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct GzHeader {
    /// true if compressed data believed to be text
    pub text: i32,
    /// modification time
    pub time: u64,
    /// extra flags
    pub xflags: i32,
    /// operating system
    pub os: i32,
    /// the extra field, or `None` if none
    pub extra: Option<Vec<u8>>,
    /// extra field length (valid if `extra` is not `None`)
    pub extra_len: u32,
    /// the zero-terminated file name, or `None`
    pub name: Option<Vec<u8>>,
    /// the zero-terminated comment, or `None`
    pub comment: Option<Vec<u8>>,
    /// true if there was a header crc
    pub hcrc: i32,
    /// 1 when done reading the gzip header, -1 if the stream turned out to
    /// be zlib, 0 before
    pub done: i32,
}

impl GzHeader {
    /// A header to fill in, keeping up to `extra_max`, `name_max` and
    /// `comm_max` bytes of the extra field, name and comment. A maximum of
    /// zero keeps none.
    pub fn new(extra_max: usize, name_max: usize, comm_max: usize) -> GzHeader {
        let buffer = |max: usize| (max > 0).then(|| vec![0; max]);
        GzHeader {
            extra: buffer(extra_max),
            name: buffer(name_max),
            comment: buffer(comm_max),
            ..GzHeader::default()
        }
    }
}

/// Where inflate() reads from: `next_in` and `avail_in` of `z_stream`.
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

/// Where inflate() writes, from `pos` on: `next_out` and `avail_out` of
/// `z_stream`.
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

/// The state maintained between inflate() calls: `inflate_state` in
/// `inflate.h`, about 7K bytes without the sliding window, which is up to
/// 32K bytes.
#[derive(Clone)]
pub(crate) struct InflateState {
    /// current inflate mode
    pub mode: Mode,
    /// true if processing last block
    pub last: bool,
    /// bit 0 true for zlib, bit 1 true for gzip, bit 2 true to validate
    /// check value
    pub wrap: i32,
    /// true if dictionary provided
    pub havedict: bool,
    /// gzip header method and flags, 0 if zlib, or -1 if raw or no header
    /// yet
    pub flags: i32,
    /// zlib header max distance (INFLATE_STRICT)
    pub dmax: u32,
    /// protected copy of check value
    pub check: u32,
    /// protected copy of output count
    pub total: u64,
    /// where to save gzip header information
    pub head: Option<GzHeader>,
    // sliding window
    /// log base 2 of requested window size
    pub wbits: u32,
    /// window size or zero if not using window
    pub wsize: usize,
    /// valid bytes in the window
    pub whave: usize,
    /// window write index
    pub wnext: usize,
    /// allocated sliding window, if needed (empty if not)
    pub window: Vec<u8>,
    // bit accumulator
    /// input bit accumulator
    pub hold: u64,
    /// number of bits in hold
    pub bits: u32,
    // for string and stored block copying
    /// literal or length of data to copy
    pub length: u32,
    /// distance back to copy string from
    pub offset: u32,
    // for table and code decoding
    /// extra bits needed
    pub extra: u32,
    // fixed and dynamic code tables
    /// starting table for length/literal codes
    pub lencode: Table,
    /// starting table for distance codes
    pub distcode: Table,
    /// index bits for lencode
    pub lenbits: u32,
    /// index bits for distcode
    pub distbits: u32,
    // dynamic table building
    /// number of code length code lengths
    pub ncode: u32,
    /// number of length code lengths
    pub nlen: u32,
    /// number of distance code lengths
    pub ndist: u32,
    /// number of code lengths in lens[]
    pub have: u32,
    /// next available space in codes[]
    pub next: usize,
    /// temporary storage for code lengths
    pub lens: [u16; 320],
    /// work area for code table building
    pub work: [u16; 288],
    /// space for code tables
    ///
    /// Differs from zlib: longer than `ENOUGH` (see `CODES_SIZE`).
    pub codes: [Code; CODES_SIZE],
    /// if false, allow invalid distance too far
    pub sane: bool,
    /// bits back of last unprocessed length/lit
    pub back: i32,
    /// initial length of match
    pub was: u32,
}

impl InflateState {
    /// The table that a code pointer points to.
    #[inline(always)]
    pub(crate) fn table(&self, table: Table) -> &[Code] {
        match table {
            Table::LenFix => &LENFIX,
            Table::DistFix => &DISTFIX,
            Table::Codes(start) => &self.codes[start..],
        }
    }

    /// The same table as an array of `TABLE_SPAN` entries, for
    /// inflate_fast(): every index into a table is below `ENOUGH_LENS`, so
    /// masking it with `TABLE_SPAN - 1` changes nothing, and lets the
    /// compiler leave out the bounds check.
    #[inline(always)]
    pub(crate) fn fast_table(&self, table: Table) -> &[Code; TABLE_SPAN] {
        match table {
            Table::LenFix => &LENFIX_SPAN,
            Table::DistFix => &DISTFIX_SPAN,
            // The distance table starts at most ENOUGH_LENS entries in, so
            // there is always a full span; the fixed table is never used.
            Table::Codes(start) => self.codes[start..].first_chunk().unwrap_or(&LENFIX_SPAN),
        }
    }

    /// Updates the window with the last `wsize` (normally 32K) bytes of
    /// `end[..]`'s last `copy` bytes, written before returning. If the
    /// window does not exist yet, creates it. This is only called when a
    /// window is already in use, or when output has been written during
    /// this inflate call, but the end of the deflate stream has not been
    /// reached yet. It is also called to create a window for dictionary
    /// data when a dictionary is loaded. Returns true when the window
    /// cannot be allocated.
    ///
    /// Providing output buffers larger than 32K to inflate() should
    /// provide a speed advantage, since only the last 32K of output is
    /// copied to the sliding window upon return from inflate(), and since
    /// all distances after the first 32K of output will fall in the output
    /// data, making match copies simpler and faster.
    ///
    /// Port of `updatewindow`, `inflate.c`.
    fn updatewindow(&mut self, end: &[u8], mut copy: usize) -> bool {
        // if it hasn't been done already, allocate space for the window
        if self.window.is_empty() {
            let size = 1usize << self.wbits;
            if self.window.try_reserve_exact(size).is_err() {
                return true;
            }
            self.window.resize(size, 0);
        }

        // if window not in use yet, initialize
        if self.wsize == 0 {
            self.wsize = 1 << self.wbits;
            self.wnext = 0;
            self.whave = 0;
        }

        // copy state->wsize or less output bytes into the circular window
        let end_pos = end.len();
        if copy >= self.wsize {
            let wsize = self.wsize;
            self.window[..wsize].copy_from_slice(&end[end_pos - wsize..]);
            self.wnext = 0;
            self.whave = self.wsize;
        } else {
            let dist = (self.wsize - self.wnext).min(copy);
            let wnext = self.wnext;
            self.window[wnext..wnext + dist]
                .copy_from_slice(&end[end_pos - copy..end_pos - copy + dist]);
            copy -= dist;
            if copy != 0 {
                self.window[..copy].copy_from_slice(&end[end_pos - copy..]);
                self.wnext = copy;
                self.whave = self.wsize;
            } else {
                self.wnext += dist;
                if self.wnext == self.wsize {
                    self.wnext = 0;
                }
                if self.whave < self.wsize {
                    self.whave += dist;
                }
            }
        }
        false
    }
}

/// A decompression stream: `z_stream` with its `inflate_state`.
///
/// ```
/// # fn main() -> Result<(), hivepack::deflate::Error> {
/// use hivepack::deflate::{Flush, InBuffer, Inflate, OutBuffer, Status};
///
/// // "hello", deflated with a zlib header.
/// let stream = [0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x06, 0x2c, 0x02, 0x15];
/// let mut inflate = Inflate::new(15)?;
/// let mut out = [0; 16];
/// let mut output = OutBuffer::new(&mut out);
/// let status = inflate.inflate(&mut output, &mut InBuffer::new(&stream), Flush::Finish)?;
/// assert_eq!(status, Status::StreamEnd);
/// let written = output.pos;
/// assert_eq!(&out[..written], b"hello");
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Inflate {
    /// total number of input bytes read so far
    total_in: u64,
    /// total number of bytes output so far
    total_out: u64,
    /// last error message, `None` if no error
    msg: Option<&'static str>,
    /// best guess about the data type: the bits of the bit buffer, and
    /// whether at the end of a block (see [`Inflate::data_type`])
    data_type: i32,
    /// Adler-32 or CRC-32 value of the uncompressed data
    adler: u32,
    state: Box<InflateState>,
}

impl Inflate {
    /// A stream that decompresses with a window of 2^`window_bits` bytes:
    ///
    /// - 8 to 15: a zlib stream; 0 takes the window size from its header;
    /// - −8 to −15: a raw deflate stream, with no header or trailer;
    /// - 16 more (24 to 31): a gzip stream;
    /// - 32 more (40 to 47): either, told apart by the header.
    ///
    /// Fails with `ErrorCode::Stream` for any other value.
    ///
    /// Port of `inflateInit2_`, `inflate.c`.
    pub fn new(window_bits: i32) -> Result<Inflate> {
        let mut strm = Inflate::alloc();
        strm.reset2(window_bits)?;
        Ok(strm)
    }

    /// The stream and its state, zeroed, as `inflateInit2_` allocates them.
    fn alloc() -> Inflate {
        let state = InflateState {
            mode: Mode::Head, // to pass state test in inflateReset2()
            last: false,
            wrap: 0,
            havedict: false,
            flags: 0,
            dmax: 0,
            check: 0,
            total: 0,
            head: None,
            wbits: 0,
            wsize: 0,
            whave: 0,
            wnext: 0,
            window: Vec::new(),
            hold: 0,
            bits: 0,
            length: 0,
            offset: 0,
            extra: 0,
            lencode: Table::Codes(0),
            distcode: Table::Codes(0),
            lenbits: 0,
            distbits: 0,
            ncode: 0,
            nlen: 0,
            ndist: 0,
            have: 0,
            next: 0,
            lens: [0; 320],
            work: [0; 288],
            codes: [Code::default(); CODES_SIZE],
            sane: false,
            back: 0,
            was: 0,
        };
        Inflate {
            total_in: 0,
            total_out: 0,
            msg: None,
            data_type: 0,
            adler: 0,
            state: Box::new(state),
        }
    }

    /// A zlib stream with the largest window: `inflateInit`.
    pub fn new_default() -> Inflate {
        let mut strm = Inflate::alloc();
        // DEF_WBITS is valid, so this cannot fail.
        let _ = strm.reset2(DEF_WBITS);
        strm
    }

    /// Resets the stream for a new one, keeping the window that was
    /// allocated.
    ///
    /// Port of `inflateResetKeep`, `inflate.c`.
    pub fn reset_keep(&mut self) {
        let state = &mut *self.state;
        self.total_in = 0;
        self.total_out = 0;
        state.total = 0;
        self.msg = None;
        self.data_type = 0;
        if state.wrap != 0 {
            // to support ill-conceived Java test suite
            self.adler = (state.wrap & 1) as u32;
        }
        state.mode = Mode::Head;
        state.last = false;
        state.havedict = false;
        state.flags = -1;
        state.dmax = 32768;
        state.head = None;
        state.hold = 0;
        state.bits = 0;
        state.lencode = Table::Codes(0);
        state.distcode = Table::Codes(0);
        state.next = 0;
        state.sane = true;
        state.back = -1;
    }

    /// Resets the stream for a new one with the same parameters.
    ///
    /// Port of `inflateReset`, `inflate.c`.
    pub fn reset(&mut self) {
        let state = &mut *self.state;
        state.wsize = 0;
        state.whave = 0;
        state.wnext = 0;
        self.reset_keep();
    }

    /// Resets the stream for a new one, with a new `window_bits` (see
    /// [`Inflate::new`]).
    ///
    /// Port of `inflateReset2`, `inflate.c`.
    pub fn reset2(&mut self, mut window_bits: i32) -> Result<()> {
        let wrap;

        // extract wrap request from windowBits parameter
        if window_bits < 0 {
            if window_bits < -15 {
                return Err(Error::stream());
            }
            wrap = 0;
            window_bits = -window_bits;
        } else {
            wrap = (window_bits >> 4) + 5;
            if window_bits < 48 {
                window_bits &= 15;
            }
        }

        // set number of window bits, free window if different
        if window_bits != 0 && !(8..=15).contains(&window_bits) {
            return Err(Error::stream());
        }
        let state = &mut *self.state;
        if !state.window.is_empty() && state.wbits != window_bits as u32 {
            state.window = Vec::new();
        }

        // update state and reset the rest of it
        state.wrap = wrap;
        state.wbits = window_bits as u32;
        self.reset();
        Ok(())
    }

    /// Inserts `bits` bits of `value` into the bit buffer, as if they came
    /// before the input. A negative `bits` empties the bit buffer instead.
    ///
    /// Port of `inflatePrime`, `inflate.c`.
    pub fn prime(&mut self, bits: i32, mut value: i32) -> Result<()> {
        if bits == 0 {
            return Ok(());
        }
        let state = &mut *self.state;
        if bits < 0 {
            state.hold = 0;
            state.bits = 0;
            return Ok(());
        }
        if bits > 16 || state.bits + bits as u32 > 32 {
            return Err(Error::stream());
        }
        value &= ((1i64 << bits) - 1) as i32;
        state.hold = state.hold.wrapping_add((value as i64 as u64) << state.bits);
        state.bits += bits as u32;
        Ok(())
    }

    /// Decompresses as much as `input` and the space in `output` allow,
    /// and moves their positions past what was read and written.
    ///
    /// Returns `Status::StreamEnd` at the end of the stream (once its check
    /// value is verified), `Status::NeedDict` when the stream needs a
    /// dictionary ([`Inflate::set_dictionary`]), and `Status::Ok` otherwise.
    /// `ErrorCode::Buf` means that no progress was possible, or, with
    /// `Flush::Finish`, that the stream has not ended; it is not fatal.
    /// `ErrorCode::Data` means that the input is not a valid stream, and
    /// [`Error::msg`] says why.
    ///
    /// Differs from zlib: up to 15 bytes of `output` past what it wrote may
    /// be written over, as zlib-ng's inflate() does, where zlib writes none:
    /// a match is copied in whole pieces where there is room for them.
    ///
    /// Port of `inflate`, `inflate.c`.
    pub fn inflate(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
        flush: Flush,
    ) -> Result<Status> {
        // Differs from zlib: there are no null pointers to check, but the
        // positions may be past the buffers' ends.
        if output.pos > output.dst.len() || input.pos > input.src.len() {
            return Err(Error::stream());
        }
        let Inflate {
            total_in,
            total_out,
            msg,
            data_type,
            adler,
            state,
        } = self;
        let state = &mut **state;

        // permutation of code lengths
        const ORDER: [u16; 19] = [
            16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
        ];

        if state.mode == Mode::Type {
            state.mode = Mode::TypeDo; // skip check
        }

        // LOAD()
        let src = input.src;
        let dst = &mut *output.dst;
        let mut next = input.pos; // next input
        let mut have = src.len() - next; // available input
        let mut put = output.pos; // next output
        let mut left = dst.len() - put; // available output
        let mut hold = state.hold; // bit buffer
        let mut bits = state.bits; // bits in bit buffer

        let mut in_ = have; // save starting available input
        let mut out = left; // save starting available output
        let mut ret = Z_OK; // return code

        // Get a byte of input into the bit accumulator, or return from
        // inflate() if there is no input available.
        macro_rules! pullbyte {
            ($leave:lifetime) => {{
                if have == 0 {
                    break $leave;
                }
                have -= 1;
                hold += u64::from(src[next]) << bits;
                next += 1;
                bits += 8;
            }};
        }
        // Assure that there are at least n bits in the bit accumulator. If
        // there is not enough available input to do that, then return from
        // inflate().
        macro_rules! needbits {
            ($leave:lifetime, $n:expr) => {{
                while bits < ($n) as u32 {
                    pullbyte!($leave);
                }
            }};
        }
        // Return the low n bits of the bit accumulator (n < 16)
        macro_rules! bits {
            ($n:expr) => {
                ((hold as u32) & ((1u32 << ($n)) - 1))
            };
        }
        // Remove n bits from the bit accumulator
        macro_rules! dropbits {
            ($n:expr) => {{
                let n = ($n) as u32;
                hold >>= n;
                bits -= n;
            }};
        }
        // Clear the input bit accumulator
        macro_rules! initbits {
            () => {{
                hold = 0;
                bits = 0;
            }};
        }
        // Remove zero to seven bits as needed to go to a byte boundary
        macro_rules! bytebits {
            () => {{
                hold >>= bits & 7;
                bits -= bits & 7;
            }};
        }
        // check function to use adler32() for zlib or crc32() for gzip
        macro_rules! update_check {
            ($check:expr, $buf:expr) => {
                if state.flags != 0 {
                    crc32($check, $buf)
                } else {
                    adler32($check, $buf)
                }
            };
        }
        // check macros for header crc
        macro_rules! crc2 {
            ($word:expr) => {{
                let word = $word;
                state.check = crc32(state.check, &[word as u8, (word >> 8) as u8]);
            }};
        }
        macro_rules! crc4 {
            ($word:expr) => {{
                let word = $word;
                state.check = crc32(
                    state.check,
                    &[
                        word as u8,
                        (word >> 8) as u8,
                        (word >> 16) as u8,
                        (word >> 24) as u8,
                    ],
                );
            }};
        }
        macro_rules! bad {
            ($msg:expr) => {{
                *msg = Some($msg);
                state.mode = Mode::Bad;
            }};
        }

        // Each pass of the loop runs the case of the current mode. Where
        // zlib falls through to the next case, the port sets the next mode
        // and goes round again; where zlib breaks out of the switch, the
        // port goes round again too.
        'inf_leave: loop {
            match state.mode {
                Mode::Head => {
                    if state.wrap == 0 {
                        state.mode = Mode::TypeDo;
                        continue;
                    }
                    needbits!('inf_leave, 16);
                    if (state.wrap & 2) != 0 && hold == 0x8b1f {
                        // gzip header
                        if state.wbits == 0 {
                            state.wbits = 15;
                        }
                        state.check = crc32(0, &[]);
                        crc2!(hold);
                        initbits!();
                        state.mode = Mode::Flags;
                        continue;
                    }
                    if let Some(head) = &mut state.head {
                        head.done = -1;
                    }
                    // check if zlib header allowed
                    if (state.wrap & 1) == 0 || ((u64::from(bits!(8)) << 8) + (hold >> 8)) % 31 != 0
                    {
                        bad!("incorrect header check");
                        continue;
                    }
                    if bits!(4) != Z_DEFLATED {
                        bad!("unknown compression method");
                        continue;
                    }
                    dropbits!(4);
                    let len = bits!(4) + 8;
                    if state.wbits == 0 {
                        state.wbits = len;
                    }
                    if len > 15 || len > state.wbits {
                        bad!("invalid window size");
                        continue;
                    }
                    state.dmax = 1 << len;
                    state.flags = 0; // indicate zlib header
                    state.check = ADLER32_INIT;
                    *adler = state.check;
                    state.mode = if hold & 0x200 != 0 {
                        Mode::DictId
                    } else {
                        Mode::Type
                    };
                    initbits!();
                }
                Mode::Flags => {
                    needbits!('inf_leave, 16);
                    state.flags = hold as i32;
                    if (state.flags & 0xff) as u32 != Z_DEFLATED {
                        bad!("unknown compression method");
                        continue;
                    }
                    if state.flags & 0xe000 != 0 {
                        bad!("unknown header flags set");
                        continue;
                    }
                    if let Some(head) = &mut state.head {
                        head.text = ((hold >> 8) & 1) as i32;
                    }
                    if (state.flags & 0x0200) != 0 && (state.wrap & 4) != 0 {
                        crc2!(hold);
                    }
                    initbits!();
                    state.mode = Mode::Time;
                }
                Mode::Time => {
                    needbits!('inf_leave, 32);
                    if let Some(head) = &mut state.head {
                        head.time = hold;
                    }
                    if (state.flags & 0x0200) != 0 && (state.wrap & 4) != 0 {
                        crc4!(hold);
                    }
                    initbits!();
                    state.mode = Mode::Os;
                }
                Mode::Os => {
                    needbits!('inf_leave, 16);
                    if let Some(head) = &mut state.head {
                        head.xflags = (hold & 0xff) as i32;
                        head.os = (hold >> 8) as i32;
                    }
                    if (state.flags & 0x0200) != 0 && (state.wrap & 4) != 0 {
                        crc2!(hold);
                    }
                    initbits!();
                    state.mode = Mode::ExLen;
                }
                Mode::ExLen => {
                    if state.flags & 0x0400 != 0 {
                        needbits!('inf_leave, 16);
                        state.length = hold as u32;
                        if let Some(head) = &mut state.head {
                            head.extra_len = hold as u32;
                        }
                        if (state.flags & 0x0200) != 0 && (state.wrap & 4) != 0 {
                            crc2!(hold);
                        }
                        initbits!();
                    } else if let Some(head) = &mut state.head {
                        head.extra = None;
                    }
                    state.mode = Mode::Extra;
                }
                Mode::Extra => {
                    if state.flags & 0x0400 != 0 {
                        let copy = (state.length as usize).min(have);
                        if copy != 0 {
                            if let Some(head) = &mut state.head
                                && let Some(extra) = &mut head.extra
                            {
                                let len = head.extra_len.wrapping_sub(state.length) as usize;
                                let extra_max = extra.len();
                                if len < extra_max {
                                    let n = if len + copy > extra_max {
                                        extra_max - len
                                    } else {
                                        copy
                                    };
                                    extra[len..len + n].copy_from_slice(&src[next..next + n]);
                                }
                            }
                            if (state.flags & 0x0200) != 0 && (state.wrap & 4) != 0 {
                                state.check = crc32(state.check, &src[next..next + copy]);
                            }
                            have -= copy;
                            next += copy;
                            state.length -= copy as u32;
                        }
                        if state.length != 0 {
                            break 'inf_leave;
                        }
                    }
                    state.length = 0;
                    state.mode = Mode::Name;
                }
                Mode::Name | Mode::Comment => {
                    // The file name and the comment are read alike.
                    let is_name = state.mode == Mode::Name;
                    let flag = if is_name { 0x0800 } else { 0x1000 };
                    if state.flags & flag != 0 {
                        if have == 0 {
                            break 'inf_leave;
                        }
                        let mut copy = 0;
                        let mut len;
                        loop {
                            len = src[next + copy];
                            copy += 1;
                            if let Some(head) = &mut state.head {
                                let buffer = if is_name {
                                    &mut head.name
                                } else {
                                    &mut head.comment
                                };
                                if let Some(buffer) = buffer
                                    && (state.length as usize) < buffer.len()
                                {
                                    buffer[state.length as usize] = len;
                                    state.length += 1;
                                }
                            }
                            if !(len != 0 && copy < have) {
                                break;
                            }
                        }
                        if (state.flags & 0x0200) != 0 && (state.wrap & 4) != 0 {
                            state.check = crc32(state.check, &src[next..next + copy]);
                        }
                        have -= copy;
                        next += copy;
                        if len != 0 {
                            break 'inf_leave;
                        }
                    } else if let Some(head) = &mut state.head {
                        if is_name {
                            head.name = None;
                        } else {
                            head.comment = None;
                        }
                    }
                    if is_name {
                        state.length = 0;
                        state.mode = Mode::Comment;
                    } else {
                        state.mode = Mode::HCrc;
                    }
                }
                Mode::HCrc => {
                    if state.flags & 0x0200 != 0 {
                        needbits!('inf_leave, 16);
                        if (state.wrap & 4) != 0 && hold != u64::from(state.check & 0xffff) {
                            bad!("header crc mismatch");
                            continue;
                        }
                        initbits!();
                    }
                    if let Some(head) = &mut state.head {
                        head.hcrc = (state.flags >> 9) & 1;
                        head.done = 1;
                    }
                    state.check = crc32(0, &[]);
                    *adler = state.check;
                    state.mode = Mode::Type;
                }
                Mode::DictId => {
                    needbits!('inf_leave, 32);
                    state.check = zswap32(hold);
                    *adler = state.check;
                    initbits!();
                    state.mode = Mode::Dict;
                }
                Mode::Dict => {
                    if !state.havedict {
                        // RESTORE()
                        output.pos = put;
                        input.pos = next;
                        state.hold = hold;
                        state.bits = bits;
                        return Ok(Status::NeedDict);
                    }
                    state.check = ADLER32_INIT;
                    *adler = state.check;
                    state.mode = Mode::Type;
                }
                Mode::Type | Mode::TypeDo => {
                    // TYPE falls through to TYPEDO without changing the
                    // mode, so that a call that runs out of input there
                    // still leaves the stream at TYPE.
                    if state.mode == Mode::Type && (flush == Flush::Block || flush == Flush::Trees)
                    {
                        break 'inf_leave;
                    }
                    if state.last {
                        bytebits!();
                        state.mode = Mode::Check;
                        continue;
                    }
                    needbits!('inf_leave, 3);
                    state.last = bits!(1) != 0;
                    dropbits!(1);
                    match bits!(2) {
                        0 => {
                            // stored block
                            state.mode = Mode::Stored;
                        }
                        1 => {
                            // fixed block
                            inflate_fixed(state);
                            state.mode = Mode::Len_; // decode codes
                            if flush == Flush::Trees {
                                dropbits!(2);
                                break 'inf_leave;
                            }
                        }
                        2 => {
                            // dynamic block
                            state.mode = Mode::Table;
                        }
                        _ => bad!("invalid block type"),
                    }
                    dropbits!(2);
                }
                Mode::Stored => {
                    bytebits!(); // go to byte boundary
                    needbits!('inf_leave, 32);
                    if (hold & 0xffff) != ((hold >> 16) ^ 0xffff) {
                        bad!("invalid stored block lengths");
                        continue;
                    }
                    state.length = (hold as u32) & 0xffff;
                    initbits!();
                    state.mode = Mode::Copy_;
                    if flush == Flush::Trees {
                        break 'inf_leave;
                    }
                }
                Mode::Copy_ => {
                    state.mode = Mode::Copy;
                }
                Mode::Copy => {
                    let mut copy = state.length as usize;
                    if copy != 0 {
                        copy = copy.min(have).min(left);
                        if copy == 0 {
                            break 'inf_leave;
                        }
                        dst[put..put + copy].copy_from_slice(&src[next..next + copy]);
                        have -= copy;
                        next += copy;
                        left -= copy;
                        put += copy;
                        state.length -= copy as u32;
                        continue;
                    }
                    state.mode = Mode::Type;
                }
                Mode::Table => {
                    needbits!('inf_leave, 14);
                    state.nlen = bits!(5) + 257;
                    dropbits!(5);
                    state.ndist = bits!(5) + 1;
                    dropbits!(5);
                    state.ncode = bits!(4) + 4;
                    dropbits!(4);
                    if state.nlen > 286 || state.ndist > 30 {
                        bad!("too many length or distance symbols");
                        continue;
                    }
                    state.have = 0;
                    state.mode = Mode::LenLens;
                }
                Mode::LenLens => {
                    while state.have < state.ncode {
                        needbits!('inf_leave, 3);
                        state.lens[ORDER[state.have as usize] as usize] = bits!(3) as u16;
                        state.have += 1;
                        dropbits!(3);
                    }
                    while state.have < 19 {
                        state.lens[ORDER[state.have as usize] as usize] = 0;
                        state.have += 1;
                    }
                    state.next = 0;
                    state.lencode = Table::Codes(0);
                    state.distcode = Table::Codes(0);
                    state.lenbits = 7;
                    let InflateState {
                        lens,
                        codes,
                        next: next_code,
                        lenbits,
                        work,
                        ..
                    } = state;
                    let r =
                        inflate_table(CodeType::Codes, lens, 19, codes, next_code, lenbits, work);
                    if r != 0 {
                        bad!("invalid code lengths set");
                        continue;
                    }
                    state.have = 0;
                    state.mode = Mode::CodeLens;
                }
                Mode::CodeLens => {
                    'lens: while state.have < state.nlen + state.ndist {
                        let mut here;
                        loop {
                            here = state.codes[bits!(state.lenbits) as usize];
                            if u32::from(here.bits) <= bits {
                                break;
                            }
                            pullbyte!('inf_leave);
                        }
                        if here.val < 16 {
                            dropbits!(here.bits);
                            state.lens[state.have as usize] = here.val;
                            state.have += 1;
                        } else {
                            let len;
                            let mut copy;
                            if here.val == 16 {
                                needbits!('inf_leave, here.bits + 2);
                                dropbits!(here.bits);
                                if state.have == 0 {
                                    bad!("invalid bit length repeat");
                                    break 'lens;
                                }
                                len = state.lens[state.have as usize - 1];
                                copy = 3 + bits!(2);
                                dropbits!(2);
                            } else if here.val == 17 {
                                needbits!('inf_leave, here.bits + 3);
                                dropbits!(here.bits);
                                len = 0;
                                copy = 3 + bits!(3);
                                dropbits!(3);
                            } else {
                                needbits!('inf_leave, here.bits + 7);
                                dropbits!(here.bits);
                                len = 0;
                                copy = 11 + bits!(7);
                                dropbits!(7);
                            }
                            if state.have + copy > state.nlen + state.ndist {
                                bad!("invalid bit length repeat");
                                break 'lens;
                            }
                            while copy != 0 {
                                copy -= 1;
                                state.lens[state.have as usize] = len;
                                state.have += 1;
                            }
                        }
                    }

                    // handle error breaks in while
                    if state.mode == Mode::Bad {
                        continue;
                    }

                    // check for end-of-block code (better have one)
                    if state.lens[256] == 0 {
                        bad!("invalid code -- missing end-of-block");
                        continue;
                    }

                    // build code tables -- note: do not change the lenbits
                    // or distbits values here (9 and 6) without reading the
                    // comments in inftrees.h concerning the ENOUGH
                    // constants, which depend on those values
                    state.next = 0;
                    state.lencode = Table::Codes(0);
                    state.lenbits = 9;
                    let nlen = state.nlen as usize;
                    let ndist = state.ndist as usize;
                    let InflateState {
                        lens,
                        codes,
                        next: next_code,
                        lenbits,
                        work,
                        ..
                    } = state;
                    let r = inflate_table(
                        CodeType::Lens,
                        &lens[..],
                        nlen,
                        codes,
                        next_code,
                        lenbits,
                        work,
                    );
                    if r != 0 {
                        bad!("invalid literal/lengths set");
                        continue;
                    }
                    state.distcode = Table::Codes(state.next);
                    state.distbits = 6;
                    let InflateState {
                        lens,
                        codes,
                        next: next_code,
                        distbits,
                        work,
                        ..
                    } = state;
                    let r = inflate_table(
                        CodeType::Dists,
                        &lens[nlen..],
                        ndist,
                        codes,
                        next_code,
                        distbits,
                        work,
                    );
                    if r != 0 {
                        bad!("invalid distances set");
                        continue;
                    }
                    state.mode = Mode::Len_;
                    if flush == Flush::Trees {
                        break 'inf_leave;
                    }
                }
                Mode::Len_ => {
                    state.mode = Mode::Len;
                }
                Mode::Len => {
                    if have >= 6 && left >= 258 {
                        // RESTORE()
                        state.hold = hold;
                        state.bits = bits;
                        inflate_fast(state, src, &mut next, dst, &mut put, out, msg);
                        // LOAD()
                        have = src.len() - next;
                        left = dst.len() - put;
                        hold = state.hold;
                        bits = state.bits;
                        if state.mode == Mode::Type {
                            state.back = -1;
                        }
                        continue;
                    }
                    state.back = 0;
                    let lencode = state.lencode;
                    let mut here;
                    loop {
                        here = state.table(lencode)[bits!(state.lenbits) as usize];
                        if u32::from(here.bits) <= bits {
                            break;
                        }
                        pullbyte!('inf_leave);
                    }
                    if here.op != 0 && (here.op & 0xf0) == 0 {
                        let last = here;
                        loop {
                            let index = usize::from(last.val)
                                + (bits!(u32::from(last.bits) + u32::from(last.op)) >> last.bits)
                                    as usize;
                            here = state.table(lencode)[index];
                            if u32::from(last.bits) + u32::from(here.bits) <= bits {
                                break;
                            }
                            pullbyte!('inf_leave);
                        }
                        dropbits!(last.bits);
                        state.back += i32::from(last.bits);
                    }
                    dropbits!(here.bits);
                    state.back += i32::from(here.bits);
                    state.length = u32::from(here.val);
                    if here.op == 0 {
                        state.mode = Mode::Lit;
                        continue;
                    }
                    if here.op & 32 != 0 {
                        state.back = -1;
                        state.mode = Mode::Type;
                        continue;
                    }
                    if here.op & 64 != 0 {
                        bad!("invalid literal/length code");
                        continue;
                    }
                    state.extra = u32::from(here.op) & 15;
                    state.mode = Mode::LenExt;
                }
                Mode::LenExt => {
                    if state.extra != 0 {
                        needbits!('inf_leave, state.extra);
                        state.length += bits!(state.extra);
                        dropbits!(state.extra);
                        state.back += state.extra as i32;
                    }
                    state.was = state.length;
                    state.mode = Mode::Dist;
                }
                Mode::Dist => {
                    let distcode = state.distcode;
                    let mut here;
                    loop {
                        here = state.table(distcode)[bits!(state.distbits) as usize];
                        if u32::from(here.bits) <= bits {
                            break;
                        }
                        pullbyte!('inf_leave);
                    }
                    if (here.op & 0xf0) == 0 {
                        let last = here;
                        loop {
                            let index = usize::from(last.val)
                                + (bits!(u32::from(last.bits) + u32::from(last.op)) >> last.bits)
                                    as usize;
                            here = state.table(distcode)[index];
                            if u32::from(last.bits) + u32::from(here.bits) <= bits {
                                break;
                            }
                            pullbyte!('inf_leave);
                        }
                        dropbits!(last.bits);
                        state.back += i32::from(last.bits);
                    }
                    dropbits!(here.bits);
                    state.back += i32::from(here.bits);
                    if here.op & 64 != 0 {
                        bad!("invalid distance code");
                        continue;
                    }
                    state.offset = u32::from(here.val);
                    state.extra = u32::from(here.op) & 15;
                    state.mode = Mode::DistExt;
                }
                Mode::DistExt => {
                    if state.extra != 0 {
                        needbits!('inf_leave, state.extra);
                        state.offset += bits!(state.extra);
                        dropbits!(state.extra);
                        state.back += state.extra as i32;
                    }
                    state.mode = Mode::Match;
                }
                Mode::Match => {
                    if left == 0 {
                        break 'inf_leave;
                    }
                    let mut copy = out - left;
                    let offset = state.offset as usize;
                    if offset > copy {
                        // copy from window
                        copy = offset - copy;
                        if copy > state.whave && state.sane {
                            bad!("invalid distance too far back");
                            continue;
                        }
                        let from = if copy > state.wnext {
                            copy -= state.wnext;
                            state.wsize - copy
                        } else {
                            state.wnext - copy
                        };
                        copy = copy.min(state.length as usize).min(left);
                        left -= copy;
                        state.length -= copy as u32;
                        dst[put..put + copy].copy_from_slice(&state.window[from..from + copy]);
                        put += copy;
                    } else {
                        // copy from output
                        let from = put - offset;
                        copy = (state.length as usize).min(left);
                        left -= copy;
                        state.length -= copy as u32;
                        for i in 0..copy {
                            dst[put + i] = dst[from + i];
                        }
                        put += copy;
                    }
                    if state.length == 0 {
                        state.mode = Mode::Len;
                    }
                }
                Mode::Lit => {
                    if left == 0 {
                        break 'inf_leave;
                    }
                    dst[put] = state.length as u8;
                    put += 1;
                    left -= 1;
                    state.mode = Mode::Len;
                }
                Mode::Check => {
                    if state.wrap != 0 {
                        needbits!('inf_leave, 32);
                        out -= left;
                        *total_out += out as u64;
                        state.total += out as u64;
                        if (state.wrap & 4) != 0 && out != 0 {
                            state.check = update_check!(state.check, &dst[put - out..put]);
                            *adler = state.check;
                        }
                        out = left;
                        let trailer = if state.flags != 0 {
                            hold
                        } else {
                            u64::from(zswap32(hold))
                        };
                        if (state.wrap & 4) != 0 && trailer != u64::from(state.check) {
                            bad!("incorrect data check");
                            continue;
                        }
                        initbits!();
                    }
                    state.mode = Mode::Length;
                }
                Mode::Length => {
                    if state.wrap != 0 && state.flags != 0 {
                        needbits!('inf_leave, 32);
                        if (state.wrap & 4) != 0 && hold != (state.total & 0xffff_ffff) {
                            bad!("incorrect length check");
                            continue;
                        }
                        initbits!();
                    }
                    state.mode = Mode::Done;
                }
                Mode::Done => {
                    ret = Z_STREAM_END;
                    break 'inf_leave;
                }
                Mode::Bad => {
                    ret = Z_DATA_ERROR;
                    break 'inf_leave;
                }
                Mode::Mem => {
                    return Err(Error::new(ErrorCode::Mem, *msg));
                }
                Mode::Sync => {
                    return Err(Error::new(ErrorCode::Stream, *msg));
                }
            }
        }

        // Return from inflate(), updating the total counts and the check
        // value. If there was no progress during the inflate() call, return
        // a buffer error. Call updatewindow() to create and/or update the
        // window state. Note: a memory error from inflate() is
        // non-recoverable.

        // inf_leave: RESTORE()
        output.pos = put;
        input.pos = next;
        state.hold = hold;
        state.bits = bits;
        if (state.wsize != 0
            || (out != left
                && state.mode < Mode::Bad
                && (state.mode < Mode::Check || flush != Flush::Finish)))
            && state.updatewindow(&dst[..put], out - left)
        {
            state.mode = Mode::Mem;
            return Err(Error::new(ErrorCode::Mem, *msg));
        }
        in_ -= have;
        out -= left;
        *total_in += in_ as u64;
        *total_out += out as u64;
        state.total += out as u64;
        if (state.wrap & 4) != 0 && out != 0 {
            state.check = update_check!(state.check, &dst[put - out..put]);
            *adler = state.check;
        }
        *data_type = state.bits as i32
            + if state.last { 64 } else { 0 }
            + if state.mode == Mode::Type { 128 } else { 0 }
            + if state.mode == Mode::Len_ || state.mode == Mode::Copy_ {
                256
            } else {
                0
            };
        if ((in_ == 0 && out == 0) || flush == Flush::Finish) && ret == Z_OK {
            ret = Z_BUF_ERROR;
        }
        result(ret, *msg)
    }

    /// Copies the window, the dictionary for what follows, to the start of
    /// `dictionary` if given, and returns its length (up to 32 KiB).
    ///
    /// Port of `inflateGetDictionary`, `inflate.c`.
    pub fn get_dictionary(&self, dictionary: Option<&mut [u8]>) -> usize {
        let state = &*self.state;
        // copy dictionary
        if state.whave != 0
            && let Some(dictionary) = dictionary
        {
            let first = state.whave - state.wnext;
            dictionary[..first].copy_from_slice(&state.window[state.wnext..state.whave]);
            dictionary[first..first + state.wnext].copy_from_slice(&state.window[..state.wnext]);
        }
        state.whave
    }

    /// Sets the dictionary: after `Status::NeedDict` for a zlib stream (and
    /// then it must be the one [`Inflate::adler`] names, or the call fails
    /// with `ErrorCode::Data`), or at any time for a raw stream.
    ///
    /// Port of `inflateSetDictionary`, `inflate.c`.
    pub fn set_dictionary(&mut self, dictionary: &[u8]) -> Result<()> {
        let state = &mut *self.state;
        if state.wrap != 0 && state.mode != Mode::Dict {
            return Err(Error::stream());
        }

        // check for correct dictionary identifier
        if state.mode == Mode::Dict {
            let dictid = adler32(ADLER32_INIT, dictionary);
            if dictid != state.check {
                return Err(Error::new(ErrorCode::Data, None));
            }
        }

        // copy dictionary to window using updatewindow(), which will amend
        // the existing dictionary if appropriate
        if state.updatewindow(dictionary, dictionary.len()) {
            state.mode = Mode::Mem;
            return Err(Error::new(ErrorCode::Mem, None));
        }
        state.havedict = true;
        Ok(())
    }

    /// Asks inflate() to fill in `head` from the gzip header, if the
    /// stream has one; [`Inflate::header`] then returns it. Fails with
    /// `ErrorCode::Stream` unless the stream may be gzip.
    ///
    /// Port of `inflateGetHeader`, `inflate.c`.
    pub fn get_header(&mut self, mut head: GzHeader) -> Result<()> {
        let state = &mut *self.state;
        if (state.wrap & 2) == 0 {
            return Err(Error::stream());
        }

        // save header structure
        head.done = 0;
        state.head = Some(head);
        Ok(())
    }

    /// The header [`Inflate::get_header`] asked for, as far as inflate()
    /// has filled it in.
    pub fn header(&self) -> Option<&GzHeader> {
        self.state.head.as_ref()
    }

    /// Skips input up to the next full flush point (the four bytes 0, 0,
    /// 0xff, 0xff of an empty stored block) and readies the stream to
    /// decompress from there, without a check value.
    ///
    /// Returns `ErrorCode::Buf` if there is no input, and `ErrorCode::Data`
    /// if none was found in the input, which is then all read; calling
    /// again with more input goes on with the search.
    ///
    /// Port of `inflateSync`, `inflate.c`.
    pub fn sync(&mut self, input: &mut InBuffer<'_>) -> Result<()> {
        if input.pos > input.src.len() {
            return Err(Error::stream());
        }
        let avail_in = input.src.len() - input.pos;
        let state = &mut *self.state;
        if avail_in == 0 && state.bits < 8 {
            return Err(Error::new(ErrorCode::Buf, self.msg));
        }

        // if first time, start search in bit buffer
        if state.mode != Mode::Sync {
            state.mode = Mode::Sync;
            state.hold >>= state.bits & 7;
            state.bits -= state.bits & 7;
            let mut buf = [0u8; 4]; // to restore bit buffer to byte string
            let mut len = 0;
            while state.bits >= 8 {
                buf[len] = state.hold as u8;
                len += 1;
                state.hold >>= 8;
                state.bits -= 8;
            }
            state.have = 0;
            syncsearch(&mut state.have, &buf[..len]);
        }

        // search available input
        let len = syncsearch(&mut state.have, &input.src[input.pos..]);
        input.pos += len;
        self.total_in += len as u64;

        // return no joy or set up to restart inflate() on a new block
        if state.have != 4 {
            return Err(Error::new(ErrorCode::Data, self.msg));
        }
        if state.flags == -1 {
            state.wrap = 0; // if no header yet, treat as raw
        } else {
            state.wrap &= !4; // no point in computing a check value now
        }
        let flags = state.flags;
        let (total_in, total_out) = (self.total_in, self.total_out);
        self.reset();
        self.total_in = total_in;
        self.total_out = total_out;
        let state = &mut *self.state;
        state.flags = flags;
        state.mode = Mode::Type;
        Ok(())
    }

    /// Whether inflate() is at the end of a block made by a sync or full
    /// flush, waiting for the lengths of the empty stored block after it.
    ///
    /// Port of `inflateSyncPoint`, `inflate.c`.
    pub fn sync_point(&self) -> bool {
        self.state.mode == Mode::Stored && self.state.bits == 0
    }

    /// zlib built without `INFLATE_ALLOW_INVALID_DISTANCE_TOOFAR_ARRR`, as
    /// it is by default, refuses to undermine its checks: this always fails
    /// with `ErrorCode::Data`.
    ///
    /// Port of `inflateUndermine`, `inflate.c`.
    pub fn undermine(&mut self, _subvert: bool) -> Result<()> {
        self.state.sane = true;
        Err(Error::new(ErrorCode::Data, None))
    }

    /// Whether to check the stream's check value (on by default for zlib
    /// and gzip streams).
    ///
    /// Port of `inflateValidate`, `inflate.c`.
    pub fn validate(&mut self, check: bool) {
        let state = &mut *self.state;
        if check && state.wrap != 0 {
            state.wrap |= 4;
        } else {
            state.wrap &= !4;
        }
    }

    /// Where the stream is, for random access: the number of bits back
    /// from the last input byte read to the start of the current code, in
    /// the upper bits, and in the lower 16 bits the bytes of a stored block
    /// or a match still to copy. −1 in the upper bits means at the start of
    /// a block.
    ///
    /// Port of `inflateMark`, `inflate.c`.
    pub fn mark(&self) -> i64 {
        let state = &*self.state;
        let low = match state.mode {
            Mode::Copy => state.length,
            Mode::Match => state.was - state.length,
            _ => 0,
        };
        (i64::from(state.back) << 16) + i64::from(low)
    }

    /// The number of entries of the code tables the current block's codes
    /// use.
    ///
    /// Port of `inflateCodesUsed`, `inflate.c`.
    pub fn codes_used(&self) -> u64 {
        self.state.next as u64
    }

    /// The number of input bytes read so far: `total_in`.
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// The number of bytes written so far: `total_out`.
    pub fn total_out(&self) -> u64 {
        self.total_out
    }

    /// The Adler-32 (zlib) or CRC-32 (gzip) of the output so far, or the
    /// Adler-32 of the dictionary a zlib stream needs: `adler`.
    pub fn adler(&self) -> u32 {
        self.adler
    }

    /// `data_type` after inflate(): the number of unused bits in the last
    /// byte read, plus 64 in the last block, 128 at the end of a block (or
    /// the header), and 256 just after the header of a stored, fixed or
    /// dynamic block.
    pub fn data_type(&self) -> i32 {
        self.data_type
    }

    /// The message of the last error, if any: `msg`.
    pub fn msg(&self) -> Option<&'static str> {
        self.msg
    }
}

impl Default for Inflate {
    fn default() -> Inflate {
        Inflate::new_default()
    }
}

/// Searches `buf` for the pattern 0, 0, 0xff, 0xff. When called, `*have`
/// is the number of pattern bytes found in order so far, in 0..3. On
/// return `*have` is updated to the new state. If on return `*have` equals
/// four, then the pattern was found and the return value is how many bytes
/// were read including the last byte of the pattern. If `*have` is less
/// than four, then the pattern has not been found yet and the return value
/// is `buf.len()`. Then `syncsearch()` can be called again with more data
/// and the `*have` state. `*have` is initialized to zero for the first
/// call.
///
/// Port of `syncsearch`, `inflate.c`.
fn syncsearch(have: &mut u32, buf: &[u8]) -> usize {
    let mut got = *have;
    let mut next = 0;
    while next < buf.len() && got < 4 {
        if u32::from(buf[next]) == if got < 2 { 0 } else { 0xff } {
            got += 1;
        } else if buf[next] != 0 {
            got = 0;
        } else {
            got = 4 - got;
        }
        next += 1;
    }
    *have = got;
    next
}
