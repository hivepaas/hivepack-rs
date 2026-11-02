//! Deflate64 decompression with a call-back interface: port of
//! `contrib/infback9/infback9.{h,c}` and `inflate9.h`.
//!
//! Deflate64 is PKWare's undocumented deflate64 compression method, method
//! 9 in ZIP archives: deflate with a 64K window, a length code (285) with
//! 16 extra bits, and two more distance codes. zlib has no compressor for
//! it; `contrib/infback9` decodes it, with the call-back interface of
//! `inflateBack`: [`InflateBack9::inflate_back9`] asks a [`BackIn`] for input
//! when it runs out, and gives its output to a [`BackOut`] a window (64K)
//! at a time, and once more at the end.

use crate::deflate::inffix9::{DISTFIX9, LENFIX9};
use crate::deflate::inftree9::{ENOUGH9, inflate_table9};
use crate::deflate::inftrees::{Code, CodeType};
use crate::deflate::zutil::{Error, ErrorCode, Result, Status};

/// `WSIZE`: the window, which is the output buffer too.
const WSIZE: usize = 65536;

/// Where [`InflateBack9::inflate_back9`] reads its input from: `in_func`.
pub trait BackIn {
    /// More input: the next bytes, or none when there are no more (or
    /// reading failed), as zlib's `in()` returning zero.
    fn input(&mut self) -> &[u8];
}

/// Where [`InflateBack9::inflate_back9`] writes its output: `out_func`.
pub trait BackOut {
    /// Takes the next output: a full window (64K) while decoding, and what
    /// is left at the end. Returns true if writing it failed, as zlib's
    /// `out()` returning non-zero; decoding then stops.
    fn output(&mut self, data: &[u8]) -> bool;
}

/// What [`InflateBack9::inflate_back9`] returned: zlib's return code, with
/// `strm->next_in` and `strm->avail_in`, the input left unused.
#[derive(Debug)]
pub struct Back9 {
    /// `Status::StreamEnd` at the end of the stream; `ErrorCode::Buf` if
    /// the input or the output failed, and `ErrorCode::Data` if the stream
    /// is not valid ([`Error::msg`] says why).
    pub result: Result<Status>,
    /// The bytes not used at the end of the last input: of `initial`, or of
    /// what [`BackIn::input`] last returned. `None` if `input()` gave none,
    /// zlib's `strm->next_in` set to null.
    pub unused: Option<usize>,
}

/// `inflate_mode` of `inflate9.h`: where inflateBack9() is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    /// waiting for type bits, including last-flag bit
    Type,
    /// waiting for stored size (length and complement)
    Stored,
    /// waiting for dynamic block table lengths
    Table,
    /// waiting for length/lit code
    Len,
    /// finished check, done
    Done,
    /// got a data error
    Bad,
}

/// The state maintained between calls: `inflate_state` of `inflate9.h`,
/// about 7K bytes.
#[derive(Clone)]
struct State9 {
    /// number of code length code lengths
    ncode: u32,
    /// number of length code lengths
    nlen: u32,
    /// number of distance code lengths
    ndist: u32,
    /// number of code lengths in lens[]
    have: u32,
    /// next available space in codes[]
    next: usize,
    /// temporary storage for code lengths
    lens: [u16; 320],
    /// work area for code table building
    work: [u16; 288],
    /// space for code tables
    codes: [Code; ENOUGH9],
}

/// Which table a code pointer points to: the fixed ones, or an index into
/// `codes`.
#[derive(Clone, Copy)]
enum Table {
    LenFix,
    DistFix,
    Codes(usize),
}

/// A Deflate64 decoder: the state of `inflateBack9`, and its 64K window.
///
/// ```
/// use hivepack::deflate::{BackIn, BackOut, InflateBack9, Status};
///
/// // A stored block holding "hi", the last.
/// let stream = [0x01, 0x02, 0x00, 0xfd, 0xff, b'h', b'i'];
/// struct Nothing;
/// impl BackIn for Nothing {
///     fn input(&mut self) -> &[u8] {
///         &[]
///     }
/// }
/// struct Collect(Vec<u8>);
/// impl BackOut for Collect {
///     fn output(&mut self, data: &[u8]) -> bool {
///         self.0.extend_from_slice(data);
///         false
///     }
/// }
/// let mut out = Collect(Vec::new());
/// let back = InflateBack9::new().inflate_back9(&stream, &mut Nothing, &mut out);
/// assert_eq!(back.result, Ok(Status::StreamEnd));
/// assert_eq!(out.0, b"hi");
/// ```
#[derive(Clone)]
pub struct InflateBack9 {
    state: Box<State9>,
    window: Box<[u8; WSIZE]>,
    msg: Option<&'static str>,
}

impl Default for InflateBack9 {
    fn default() -> InflateBack9 {
        InflateBack9::new()
    }
}

impl InflateBack9 {
    /// A decoder, with its own window.
    ///
    /// Port of `inflateBack9Init_`, `infback9.c`. Differs from zlib: the
    /// decoder allocates its 64K window, which zlib's caller gives it.
    pub fn new() -> InflateBack9 {
        InflateBack9 {
            state: Box::new(State9 {
                ncode: 0,
                nlen: 0,
                ndist: 0,
                have: 0,
                next: 0,
                lens: [0; 320],
                work: [0; 288],
                codes: [Code::default(); ENOUGH9],
            }),
            window: Box::new([0; WSIZE]),
            msg: None,
        }
    }

    /// The message of the last error, if any: `strm->msg`.
    pub fn msg(&self) -> Option<&'static str> {
        self.msg
    }

    /// Decodes a whole Deflate64 stream: starts with the bytes of
    /// `initial` (zlib's `strm->next_in`), asks `input` for more when they
    /// run out, and gives `output` the decoded bytes.
    ///
    /// Port of `inflateBack9`, `infback9.c`. Differs from zlib: `in()` and
    /// `out()` are traits, and the unused input comes with the result
    /// rather than in `strm`.
    pub fn inflate_back9(
        &mut self,
        initial: &[u8],
        input: &mut dyn BackIn,
        output: &mut dyn BackOut,
    ) -> Back9 {
        let InflateBack9 { state, window, msg } = self;
        let state = &mut **state;

        // permutation of code lengths
        const ORDER: [u16; 19] = [
            16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
        ];

        // Reset the state
        *msg = None;
        let mut mode = Mode::Type;
        let mut lastblock = false; // true if processing last block
        let mut wrap = false; // true if the window has wrapped
        let mut next: &[u8] = initial; // next input, and what is left of it
        let mut in_failed = false; // in() gave nothing: next_in is null
        let mut hold: u64 = 0; // bit buffer
        let mut bits: u32 = 0; // bits in bit buffer
        let mut put: usize = 0; // next output
        let mut left: usize = WSIZE; // available output
        let mut lencode = Table::Codes(0); // starting table for length/literal codes
        let mut distcode = Table::Codes(0); // starting table for distance codes
        let mut lenbits: u32 = 0; // index bits for lencode
        let mut distbits: u32 = 0; // index bits for distcode
        let mut length: usize; // literal or length of data to copy

        const Z_STREAM_END: i32 = 1;
        const Z_DATA_ERROR: i32 = -3;
        const Z_BUF_ERROR: i32 = -5;

        let table = |codes: &[Code; ENOUGH9], t: Table, i: usize| -> Code {
            match t {
                Table::LenFix => LENFIX9[i],
                Table::DistFix => DISTFIX9[i],
                Table::Codes(start) => codes[start + i],
            }
        };

        // Assure that some input is available. If input is requested, but
        // denied, then return a Z_BUF_ERROR from inflateBack().
        macro_rules! pull {
            ($leave:lifetime) => {{
                if next.is_empty() {
                    next = input.input();
                    if next.is_empty() {
                        in_failed = true;
                        break $leave Z_BUF_ERROR;
                    }
                }
            }};
        }
        // Get a byte of input into the bit accumulator, or return from
        // inflateBack() with an error if there is no input available.
        macro_rules! pullbyte {
            ($leave:lifetime) => {{
                pull!($leave);
                hold += u64::from(next[0]) << bits;
                next = &next[1..];
                bits += 8;
            }};
        }
        // Assure that there are at least n bits in the bit accumulator. If
        // there is not enough available input to do that, then return from
        // inflateBack() with an error.
        macro_rules! needbits {
            ($leave:lifetime, $n:expr) => {{
                while bits < ($n) as u32 {
                    pullbyte!($leave);
                }
            }};
        }
        // Return the low n bits of the bit accumulator (n <= 16)
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
        // Assure that some output space is available, by writing out the
        // window if it's full. If the write fails, return from
        // inflateBack() with a Z_BUF_ERROR.
        macro_rules! room {
            ($leave:lifetime) => {{
                if left == 0 {
                    put = 0;
                    left = WSIZE;
                    wrap = true;
                    if output.output(&window[..left]) {
                        break $leave Z_BUF_ERROR;
                    }
                }
            }};
        }
        macro_rules! bad {
            ($msg:expr) => {{
                *msg = Some($msg);
                mode = Mode::Bad;
            }};
        }

        // Inflate until end of block marked as last
        let ret: i32 = 'inf_leave: loop {
            match mode {
                Mode::Type => {
                    // determine and dispatch block type
                    if lastblock {
                        bytebits!();
                        mode = Mode::Done;
                        continue;
                    }
                    needbits!('inf_leave, 3);
                    lastblock = bits!(1) != 0;
                    dropbits!(1);
                    match bits!(2) {
                        0 => mode = Mode::Stored, // stored block
                        1 => {
                            // fixed block
                            lencode = Table::LenFix;
                            lenbits = 9;
                            distcode = Table::DistFix;
                            distbits = 5;
                            mode = Mode::Len; // decode codes
                        }
                        2 => mode = Mode::Table, // dynamic block
                        _ => bad!("invalid block type"),
                    }
                    dropbits!(2);
                }
                Mode::Stored => {
                    // get and verify stored block length
                    bytebits!(); // go to byte boundary
                    needbits!('inf_leave, 32);
                    if (hold & 0xffff) != ((hold >> 16) ^ 0xffff) {
                        bad!("invalid stored block lengths");
                        continue;
                    }
                    length = (hold & 0xffff) as usize;
                    initbits!();

                    // copy stored block from input to output
                    while length != 0 {
                        pull!('inf_leave);
                        room!('inf_leave);
                        let copy = length.min(next.len()).min(left);
                        window[put..put + copy].copy_from_slice(&next[..copy]);
                        next = &next[copy..];
                        left -= copy;
                        put += copy;
                        length -= copy;
                    }
                    mode = Mode::Type;
                }
                Mode::Table => {
                    // get dynamic table entries descriptor
                    needbits!('inf_leave, 14);
                    state.nlen = bits!(5) + 257;
                    dropbits!(5);
                    state.ndist = bits!(5) + 1;
                    dropbits!(5);
                    state.ncode = bits!(4) + 4;
                    dropbits!(4);
                    if state.nlen > 286 {
                        bad!("too many length symbols");
                        continue;
                    }

                    // get code length code lengths (not a typo)
                    state.have = 0;
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
                    lencode = Table::Codes(0);
                    lenbits = 7;
                    let State9 {
                        lens,
                        codes,
                        next: next_code,
                        work,
                        ..
                    } = &mut *state;
                    let t = inflate_table9(
                        CodeType::Codes,
                        &lens[..],
                        19,
                        &mut codes[..],
                        next_code,
                        &mut lenbits,
                        &mut work[..],
                    );
                    if t != 0 {
                        bad!("invalid code lengths set");
                        continue;
                    }

                    // get length and distance code code lengths
                    state.have = 0;
                    'lens: while state.have < state.nlen + state.ndist {
                        let mut here;
                        loop {
                            here = table(&state.codes, lencode, bits!(lenbits) as usize);
                            if u32::from(here.bits) <= bits {
                                break;
                            }
                            pullbyte!('inf_leave);
                        }
                        if here.val < 16 {
                            needbits!('inf_leave, here.bits);
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
                    if mode == Mode::Bad {
                        continue;
                    }

                    // check for end-of-block code (better have one)
                    if state.lens[256] == 0 {
                        bad!("invalid code -- missing end-of-block");
                        continue;
                    }

                    // build code tables -- note: do not change the lenbits or
                    // distbits values here (9 and 6) without reading the
                    // comments in inftree9.h concerning the ENOUGH constants,
                    // which depend on those values
                    state.next = 0;
                    lencode = Table::Codes(0);
                    lenbits = 9;
                    let nlen = state.nlen as usize;
                    let ndist = state.ndist as usize;
                    let State9 {
                        lens,
                        codes,
                        next: next_code,
                        work,
                        ..
                    } = &mut *state;
                    let t = inflate_table9(
                        CodeType::Lens,
                        &lens[..],
                        nlen,
                        &mut codes[..],
                        next_code,
                        &mut lenbits,
                        &mut work[..],
                    );
                    if t != 0 {
                        bad!("invalid literal/lengths set");
                        continue;
                    }
                    distcode = Table::Codes(state.next);
                    distbits = 6;
                    let State9 {
                        lens,
                        codes,
                        next: next_code,
                        work,
                        ..
                    } = &mut *state;
                    let t = inflate_table9(
                        CodeType::Dists,
                        &lens[nlen..],
                        ndist,
                        &mut codes[..],
                        next_code,
                        &mut distbits,
                        &mut work[..],
                    );
                    if t != 0 {
                        bad!("invalid distances set");
                        continue;
                    }
                    mode = Mode::Len;
                }
                Mode::Len => {
                    // The tables of this block, looked up once for all its
                    // codes.
                    let lcode: &[Code] = match lencode {
                        Table::LenFix => &LENFIX9,
                        Table::DistFix => &DISTFIX9,
                        Table::Codes(start) => &state.codes[start..],
                    };
                    let dcode: &[Code] = match distcode {
                        Table::LenFix => &LENFIX9,
                        Table::DistFix => &DISTFIX9,
                        Table::Codes(start) => &state.codes[start..],
                    };
                    'codes: loop {
                        // get a literal, length, or end-of-block code
                        let mut here;
                        loop {
                            here = lcode[bits!(lenbits) as usize];
                            if u32::from(here.bits) <= bits {
                                break;
                            }
                            pullbyte!('inf_leave);
                        }
                        if here.op != 0 && (here.op & 0xf0) == 0 {
                            let last = here;
                            loop {
                                let index = usize::from(last.val)
                                    + (bits!(u32::from(last.bits) + u32::from(last.op))
                                        >> last.bits)
                                        as usize;
                                here = lcode[index];
                                if u32::from(last.bits) + u32::from(here.bits) <= bits {
                                    break;
                                }
                                pullbyte!('inf_leave);
                            }
                            dropbits!(last.bits);
                        }
                        dropbits!(here.bits);
                        length = usize::from(here.val);

                        // process literal
                        if here.op == 0 {
                            room!('inf_leave);
                            window[put & (WSIZE - 1)] = length as u8;
                            put += 1;
                            left -= 1;
                            continue 'codes;
                        }

                        // process end of block
                        if here.op & 32 != 0 {
                            mode = Mode::Type;
                            break 'codes;
                        }

                        // invalid code
                        if here.op & 64 != 0 {
                            bad!("invalid literal/length code");
                            break 'codes;
                        }

                        // length code -- get extra bits, if any
                        let extra = u32::from(here.op) & 31;
                        if extra != 0 {
                            needbits!('inf_leave, extra);
                            length += bits!(extra) as usize;
                            dropbits!(extra);
                        }

                        // get distance code
                        loop {
                            here = dcode[bits!(distbits) as usize];
                            if u32::from(here.bits) <= bits {
                                break;
                            }
                            pullbyte!('inf_leave);
                        }
                        if (here.op & 0xf0) == 0 {
                            let last = here;
                            loop {
                                let index = usize::from(last.val)
                                    + (bits!(u32::from(last.bits) + u32::from(last.op))
                                        >> last.bits)
                                        as usize;
                                here = dcode[index];
                                if u32::from(last.bits) + u32::from(here.bits) <= bits {
                                    break;
                                }
                                pullbyte!('inf_leave);
                            }
                            dropbits!(last.bits);
                        }
                        dropbits!(here.bits);
                        if here.op & 64 != 0 {
                            bad!("invalid distance code");
                            break 'codes;
                        }
                        let mut offset = usize::from(here.val);

                        // get distance extra bits, if any
                        let extra = u32::from(here.op) & 15;
                        if extra != 0 {
                            needbits!('inf_leave, extra);
                            offset += bits!(extra) as usize;
                            dropbits!(extra);
                        }
                        if offset > WSIZE - if wrap { 0 } else { left } {
                            bad!("invalid distance too far back");
                            break 'codes;
                        }

                        // copy match from window to output
                        loop {
                            room!('inf_leave);
                            let mut copy = WSIZE - offset;
                            let from;
                            if copy < left {
                                from = put + copy;
                                copy = left - copy;
                            } else {
                                from = put - offset;
                                copy = left;
                            }
                            copy = copy.min(length);
                            length -= copy;
                            left -= copy;
                            // A copy from ahead of the output, or from far
                            // enough back, is the byte loop's copy at once.
                            if from >= put || from + copy <= put {
                                window.copy_within(from..from + copy, put);
                            } else {
                                for i in 0..copy {
                                    window[put + i] = window[from + i];
                                }
                            }
                            put += copy;
                            if length == 0 {
                                break;
                            }
                        }
                    }
                }
                Mode::Done => {
                    // inflate stream terminated properly -- write leftover
                    // output
                    if left < WSIZE && output.output(&window[..WSIZE - left]) {
                        break 'inf_leave Z_BUF_ERROR;
                    }
                    break 'inf_leave Z_STREAM_END;
                }
                Mode::Bad => {
                    break 'inf_leave Z_DATA_ERROR;
                }
            }
        };

        // Return unused input
        let unused = if in_failed { None } else { Some(next.len()) };
        let result = match ret {
            Z_STREAM_END => Ok(Status::StreamEnd),
            Z_DATA_ERROR => Err(Error::new(ErrorCode::Data, *msg)),
            _ => Err(Error::new(ErrorCode::Buf, *msg)),
        };
        Back9 { result, unused }
    }
}
