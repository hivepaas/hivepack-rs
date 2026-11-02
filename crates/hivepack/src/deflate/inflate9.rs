//! Deflate64 decompression that stops when the input or the output runs out
//! and goes on at the next call, as [`Inflate`](crate::deflate::Inflate) does.
//!
//! zlib decodes Deflate64 only in `contrib/infback9`, which takes the whole
//! stream through call-backs ([`InflateBack9`](crate::deflate::InflateBack9)). A ZIP
//! reader pulls an entry's data a piece at a time, so this decoder is
//! hivepack's own: the structure of `inflate.c`, a mode for each place where
//! the input or the output can run out, its sliding window (here 64K) and
//! its copies from the output or the window; with the decoding of
//! `infback9.c`: the Deflate64 tables of `inftree9.c`, length code 285 with
//! 16 extra bits, distance codes 30 and 31, and its messages. There is no
//! fast loop, as `infback9.c` has none. `tests/deflate64.rs` checks that it
//! decodes every stream as `infback9.c` does.

use crate::deflate::inffix9::{DISTFIX9, LENFIX9};
use crate::deflate::inflate::{InBuffer, OutBuffer};
use crate::deflate::inftree9::{ENOUGH9, inflate_table9};
use crate::deflate::inftrees::{Code, CodeType};
use crate::deflate::zutil::{Error, ErrorCode, Result, Status};

/// The window: 64K, the most a Deflate64 distance reaches back.
const WSIZE: usize = 65536;

/// Where the decoder is: the modes of `inflate.c` a raw stream goes
/// through.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    /// waiting for type bits, including last-flag bit
    Type,
    /// waiting for stored size (length and complement)
    Stored,
    /// waiting for input or output to copy stored block
    Copy,
    /// waiting for dynamic block table lengths
    Table,
    /// waiting for code length code lengths
    LenLens,
    /// waiting for length/lit and distance code lengths
    CodeLens,
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
    /// the stream ended -- remain here until reset
    Done,
    /// got a data error -- remain here until reset
    Bad,
}

/// Which table a code pointer points to.
#[derive(Clone, Copy)]
enum Table {
    LenFix,
    DistFix,
    Codes(usize),
}

/// The state kept between calls, as `inflate_state` keeps it.
struct State {
    mode: Mode,
    /// true if processing last block
    last: bool,
    /// bit buffer
    hold: u64,
    /// bits in bit buffer
    bits: u32,
    /// literal or length of data to copy
    length: u32,
    /// distance back to copy string from
    offset: u32,
    /// extra bits needed
    extra: u32,
    lencode: Table,
    distcode: Table,
    lenbits: u32,
    distbits: u32,
    ncode: u32,
    nlen: u32,
    ndist: u32,
    have: u32,
    next: usize,
    lens: [u16; 320],
    work: [u16; 288],
    codes: [Code; ENOUGH9],
    /// valid bytes in the window
    whave: usize,
    /// window write index
    wnext: usize,
    window: Box<[u8; WSIZE]>,
}

impl State {
    fn table(&self, table: Table) -> &[Code] {
        match table {
            Table::LenFix => &LENFIX9,
            Table::DistFix => &DISTFIX9,
            Table::Codes(start) => &self.codes[start..],
        }
    }

    /// Keeps the last 64K bytes of output in the window: `updatewindow` of
    /// `inflate.c`, with `end` the output, of which the last `copy` bytes
    /// are new.
    fn updatewindow(&mut self, end: &[u8], mut copy: usize) {
        let end_pos = end.len();
        if copy >= WSIZE {
            self.window.copy_from_slice(&end[end_pos - WSIZE..]);
            self.wnext = 0;
            self.whave = WSIZE;
        } else {
            let dist = (WSIZE - self.wnext).min(copy);
            let wnext = self.wnext;
            self.window[wnext..wnext + dist]
                .copy_from_slice(&end[end_pos - copy..end_pos - copy + dist]);
            copy -= dist;
            if copy != 0 {
                self.window[..copy].copy_from_slice(&end[end_pos - copy..]);
                self.wnext = copy;
                self.whave = WSIZE;
            } else {
                self.wnext += dist;
                if self.wnext == WSIZE {
                    self.wnext = 0;
                }
                if self.whave < WSIZE {
                    self.whave += dist;
                }
            }
        }
    }
}

/// A Deflate64 decoder, a raw stream with no header or trailer, as in a
/// ZIP archive (method 9).
///
/// ```
/// use hivepack::deflate::{InBuffer, Inflate9, OutBuffer, Status};
///
/// // A stored block holding "hi", the last.
/// let stream = [0x01, 0x02, 0x00, 0xfd, 0xff, b'h', b'i'];
/// let mut out = [0; 8];
/// let mut output = OutBuffer::new(&mut out);
/// let status = Inflate9::new().inflate(&mut output, &mut InBuffer::new(&stream));
/// assert_eq!(status, Ok(Status::StreamEnd));
/// assert_eq!(output.pos, 2);
/// ```
pub struct Inflate9 {
    state: Box<State>,
    msg: Option<&'static str>,
    total_in: u64,
    total_out: u64,
}

impl Default for Inflate9 {
    fn default() -> Inflate9 {
        Inflate9::new()
    }
}

impl Inflate9 {
    /// A decoder at the start of a stream.
    pub fn new() -> Inflate9 {
        Inflate9 {
            state: Box::new(State {
                mode: Mode::Type,
                last: false,
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
                codes: [Code::default(); ENOUGH9],
                whave: 0,
                wnext: 0,
                window: Box::new([0; WSIZE]),
            }),
            msg: None,
            total_in: 0,
            total_out: 0,
        }
    }

    /// Starts a new stream, keeping the memory: `inflateReset`.
    pub fn reset(&mut self) {
        let state = &mut *self.state;
        state.mode = Mode::Type;
        state.last = false;
        state.hold = 0;
        state.bits = 0;
        state.whave = 0;
        state.wnext = 0;
        state.lencode = Table::Codes(0);
        state.distcode = Table::Codes(0);
        state.next = 0;
        self.msg = None;
        self.total_in = 0;
        self.total_out = 0;
    }

    /// The message of the last error, if any: `strm->msg`.
    pub fn msg(&self) -> Option<&'static str> {
        self.msg
    }

    /// The input read so far.
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// The output written so far.
    pub fn total_out(&self) -> u64 {
        self.total_out
    }

    /// Decompresses as much as `input` and the space in `output` allow,
    /// and moves their positions past what was read and written.
    ///
    /// Returns `Status::StreamEnd` at the end of the stream and `Status::Ok`
    /// otherwise. `ErrorCode::Buf` means that no progress was possible, for
    /// want of input or output space; it is not fatal. `ErrorCode::Data`
    /// means that the input is not a valid stream, and [`Inflate9::msg`]
    /// says why, in the words of `infback9.c`. Input is read a byte at a
    /// time as it is needed, so at the end of the stream what is left of
    /// `input` is what follows the stream.
    pub fn inflate(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
    ) -> Result<Status> {
        if output.pos > output.dst.len() || input.pos > input.src.len() {
            return Err(Error::new(ErrorCode::Stream, None));
        }
        let Inflate9 {
            state,
            msg,
            total_in,
            total_out,
        } = self;
        let state = &mut **state;

        // permutation of code lengths
        const ORDER: [u16; 19] = [
            16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
        ];

        // LOAD()
        let src = input.src;
        let dst = &mut *output.dst;
        let start = output.pos; // where this call's output starts
        let mut next = input.pos; // next input
        let mut have = src.len() - next; // available input
        let mut put = output.pos; // next output
        let mut left = dst.len() - put; // available output
        let mut hold = state.hold; // bit buffer
        let mut bits = state.bits; // bits in bit buffer

        let in_ = have; // save starting available input
        let out = left; // save starting available output
        let mut ret = Ok(Status::Ok);

        // Get a byte of input into the bit accumulator, or return if there
        // is no input available.
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
        // Assure that there are at least n bits in the bit accumulator.
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
        macro_rules! bad {
            ($msg:expr) => {{
                *msg = Some($msg);
                state.mode = Mode::Bad;
            }};
        }

        'inf_leave: loop {
            match state.mode {
                Mode::Type => {
                    if state.last {
                        bytebits!();
                        state.mode = Mode::Done;
                        continue;
                    }
                    needbits!('inf_leave, 3);
                    state.last = bits!(1) != 0;
                    dropbits!(1);
                    match bits!(2) {
                        0 => state.mode = Mode::Stored, // stored block
                        1 => {
                            // fixed block
                            state.lencode = Table::LenFix;
                            state.lenbits = 9;
                            state.distcode = Table::DistFix;
                            state.distbits = 5;
                            state.mode = Mode::Len; // decode codes
                        }
                        2 => state.mode = Mode::Table, // dynamic block
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
                    // Deflate64 has 32 distance codes: only the lengths are
                    // checked, as in infback9.c.
                    if state.nlen > 286 {
                        bad!("too many length symbols");
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
                    state.lenbits = 7;
                    let State {
                        lens,
                        codes,
                        next: next_code,
                        lenbits,
                        work,
                        ..
                    } = state;
                    if inflate_table9(
                        CodeType::Codes,
                        &lens[..],
                        19,
                        &mut codes[..],
                        next_code,
                        lenbits,
                        &mut work[..],
                    ) != 0
                    {
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

                    // build code tables, with the index bits of infback9.c
                    state.next = 0;
                    state.lencode = Table::Codes(0);
                    state.lenbits = 9;
                    let nlen = state.nlen as usize;
                    let ndist = state.ndist as usize;
                    let State {
                        lens,
                        codes,
                        next: next_code,
                        lenbits,
                        work,
                        ..
                    } = state;
                    if inflate_table9(
                        CodeType::Lens,
                        &lens[..],
                        nlen,
                        &mut codes[..],
                        next_code,
                        lenbits,
                        &mut work[..],
                    ) != 0
                    {
                        bad!("invalid literal/lengths set");
                        continue;
                    }
                    state.distcode = Table::Codes(state.next);
                    state.distbits = 6;
                    let State {
                        lens,
                        codes,
                        next: next_code,
                        distbits,
                        work,
                        ..
                    } = state;
                    if inflate_table9(
                        CodeType::Dists,
                        &lens[nlen..],
                        ndist,
                        &mut codes[..],
                        next_code,
                        distbits,
                        &mut work[..],
                    ) != 0
                    {
                        bad!("invalid distances set");
                        continue;
                    }
                    state.mode = Mode::Len;
                }
                Mode::Len => {
                    // Literals are written here while there is room, without
                    // going through Mode::Lit; a length, the end of the
                    // block or an error leaves the loop. The block's table is
                    // looked up once.
                    let lcode: &[Code] = match state.lencode {
                        Table::LenFix => &LENFIX9,
                        Table::DistFix => &DISTFIX9,
                        Table::Codes(start) => &state.codes[start..],
                    };
                    let lenbits = state.lenbits;
                    loop {
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

                        // process literal
                        if here.op == 0 {
                            if left == 0 {
                                state.length = u32::from(here.val);
                                state.mode = Mode::Lit;
                                break;
                            }
                            dst[put] = here.val as u8;
                            put += 1;
                            left -= 1;
                            continue;
                        }
                        state.length = u32::from(here.val);
                        // process end of block
                        if here.op & 32 != 0 {
                            state.mode = Mode::Type;
                            break;
                        }
                        // invalid code
                        if here.op & 64 != 0 {
                            bad!("invalid literal/length code");
                            break;
                        }
                        // length code: up to 16 extra bits, for code 285
                        state.extra = u32::from(here.op) & 31;
                        state.mode = Mode::LenExt;
                        break;
                    }
                }
                Mode::LenExt => {
                    if state.extra != 0 {
                        needbits!('inf_leave, state.extra);
                        state.length += bits!(state.extra);
                        dropbits!(state.extra);
                    }
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
                    }
                    dropbits!(here.bits);
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
                    }
                    // infback9.c's check, written as inflate.c's: no further
                    // back than the output so far, up to the window.
                    if state.offset as usize > (put - start) + state.whave {
                        bad!("invalid distance too far back");
                        continue;
                    }
                    state.mode = Mode::Match;
                }
                Mode::Match => {
                    if left == 0 {
                        break 'inf_leave;
                    }
                    let mut copy = put - start;
                    let offset = state.offset as usize;
                    if offset > copy {
                        // copy from window
                        copy = offset - copy;
                        let from = if copy > state.wnext {
                            copy -= state.wnext;
                            WSIZE - copy
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
                        if from + copy <= put {
                            dst.copy_within(from..from + copy, put);
                        } else {
                            for i in 0..copy {
                                dst[put + i] = dst[from + i];
                            }
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
                Mode::Done => {
                    ret = Ok(Status::StreamEnd);
                    break 'inf_leave;
                }
                Mode::Bad => {
                    ret = Err(Error::new(ErrorCode::Data, *msg));
                    break 'inf_leave;
                }
            }
        }

        // RESTORE(), and the window kept for the next call.
        output.pos = put;
        input.pos = next;
        state.hold = hold;
        state.bits = bits;
        if out != left {
            state.updatewindow(&dst[..put], out - left);
        }
        *total_in += (in_ - have) as u64;
        *total_out += (out - left) as u64;
        if in_ == have && out == left && ret == Ok(Status::Ok) {
            ret = Err(Error::new(ErrorCode::Buf, *msg));
        }
        ret
    }
}
