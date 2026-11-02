//! The fast decoding loop: port of `inffast.{h,c}`.

use crate::deflate::inflate::{InflateState, Mode, TABLE_SPAN};

/// Decodes literal, length and distance codes and writes literals and match
/// bytes until either not enough input or output is available, an
/// end-of-block is encountered, or a data error is encountered. When large
/// enough input and output buffers are supplied to inflate(), for example,
/// a 16K input buffer and a 64K output buffer, more than 95% of the
/// inflate execution time is spent in this routine.
///
/// Entry assumptions:
/// - `state.mode` is `Len`;
/// - at least 6 bytes of input are left at `*next_in`;
/// - at least 258 bytes of output space are left at `*next_out`;
/// - `start` is the output space inflate() had when it was called, so that
///   the output written in this call starts at `*next_out - (start -
///   left)`;
/// - `state.bits < 8`.
///
/// On return, `state.mode` is one of `Len` (not enough input or output),
/// `Type` (end of block) or `Bad` (with `*msg` set). The bytes of the bit
/// buffer that were not used are given back to the input.
///
/// Port of `inflate_fast`, `inffast.c` (without `INFLATE_STRICT` and
/// `INFLATE_ALLOW_INVALID_DISTANCE_TOOFAR_ARRR`, as zlib is built by
/// default). Differs from zlib:
/// - positions are indices into `input`, `output` and the window rather
///   than pointers;
/// - the bit buffer is refilled once per code, with eight bytes read at
///   once (fewer at the end of the input), to 56 bits or more, which is
///   enough for a length, a distance and their extra bits (at most 48).
///   zlib pulls two bytes at a time, when it has fewer than 15 bits. The
///   bits are the same: those past `bits` in `hold` are always either zero
///   or the next bits of the input, so they can be or-ed again, and the
///   bytes not used are given back at the end, as zlib gives back its own.
///   zlib's loop stops when fewer than six bytes are left past those it
///   has pulled, which depends on when it pulled them; but then it gives
///   back the bytes it did not use, and inflate() calls it again at once if
///   six or more are left, with nothing else changed. So zlib decodes a
///   code here exactly when six bytes or more are left past the bytes
///   already used, and the port's loop goes on under that same test.
pub(crate) fn inflate_fast(
    state: &mut InflateState,
    input: &[u8],
    next_in: &mut usize,
    output: &mut [u8],
    next_out: &mut usize,
    start: usize,
    msg: &mut Option<&'static str>,
) {
    // copy state to local variables
    let mut inp = *next_in; // local strm->next_in
    let last = input.len() - 6; // have enough input while the bytes used reach no further
    let mut out = *next_out; // local strm->next_out
    let beg = out - (start - (output.len() - out)); // inflate()'s initial strm->next_out
    let end = out + (output.len() - out - 257); // while out < end, enough space available
    let wsize = state.wsize; // window size or zero if not using window
    let whave = state.whave; // valid bytes in the window
    let wnext = state.wnext; // window write index
    let mut hold = state.hold; // local strm->hold
    let mut bits = state.bits; // local strm->bits
    let lmask = (1u64 << state.lenbits) - 1; // mask for first level of length codes
    let dmask = (1u64 << state.distbits) - 1; // mask for first level of distance codes
    let sane = state.sane;
    let mut mode = None; // the mode to leave in, when not Len

    {
        let window = &state.window[..];
        // Differs from zlib: every index into these is masked with
        // `TABLE_SPAN - 1`, which changes none (see `fast_table`), so that
        // the compiler leaves out the bounds checks.
        let lcode = state.fast_table(state.lencode); // local strm->lencode
        let dcode = state.fast_table(state.distcode); // local strm->distcode
        const SPAN: usize = TABLE_SPAN - 1;

        // decode literals and length/distances until end-of-block or not
        // enough input data or output space
        'outer: loop {
            // refill to 56 bits or more
            if inp + 8 <= input.len() {
                hold |= read_word(input, inp) << bits;
                inp += ((63 - bits) >> 3) as usize;
                bits |= 56;
            } else {
                refill_end(input, &mut inp, &mut hold, &mut bits);
            }
            let mut here = lcode[(hold & lmask) as usize & SPAN];
            // dolen:
            loop {
                let op = u32::from(here.bits);
                hold >>= op;
                bits -= op;
                let mut op = u32::from(here.op);
                if op == 0 {
                    // literal
                    output[out] = here.val as u8;
                    out += 1;
                } else if op & 16 != 0 {
                    // length base
                    let mut len = u32::from(here.val);
                    op &= 15; // number of extra bits
                    if op != 0 {
                        len += (hold as u32) & ((1u32 << op) - 1);
                        hold >>= op;
                        bits -= op;
                    }
                    here = dcode[(hold & dmask) as usize & SPAN];
                    // dodist:
                    loop {
                        let op = u32::from(here.bits);
                        hold >>= op;
                        bits -= op;
                        let mut op = u32::from(here.op);
                        if op & 16 != 0 {
                            // distance base
                            let mut dist = u32::from(here.val);
                            op &= 15; // number of extra bits
                            dist += (hold as u32) & ((1u32 << op) - 1);
                            hold >>= op;
                            bits -= op;
                            let dist = dist as usize;
                            let mut len = len as usize;
                            let op = out - beg; // max distance in output
                            if dist > op {
                                // see if copy from window
                                let mut op = dist - op; // distance back in window
                                if op > whave && sane {
                                    *msg = Some("invalid distance too far back");
                                    mode = Some(Mode::Bad);
                                    break 'outer;
                                }
                                // Where the rest of the copy comes from: the
                                // window at `from`, or the output if
                                // `from_window` is false.
                                let mut from;
                                let mut from_window = true;
                                if wnext == 0 {
                                    // very common case
                                    from = wsize - op;
                                    if op < len {
                                        // some from window
                                        len -= op;
                                        output[out..out + op]
                                            .copy_from_slice(&window[from..from + op]);
                                        out += op;
                                        from = out - dist; // rest from output
                                        from_window = false;
                                    }
                                } else if wnext < op {
                                    // wrap around window
                                    from = wsize + wnext - op;
                                    op -= wnext;
                                    if op < len {
                                        // some from end of window
                                        len -= op;
                                        output[out..out + op]
                                            .copy_from_slice(&window[from..from + op]);
                                        out += op;
                                        from = 0;
                                        if wnext < len {
                                            // some from start of window
                                            let op = wnext;
                                            len -= op;
                                            output[out..out + op].copy_from_slice(&window[..op]);
                                            out += op;
                                            from = out - dist; // rest from output
                                            from_window = false;
                                        }
                                    }
                                } else {
                                    // contiguous in window
                                    from = wnext - op;
                                    if op < len {
                                        // some from window
                                        len -= op;
                                        output[out..out + op]
                                            .copy_from_slice(&window[from..from + op]);
                                        out += op;
                                        from = out - dist; // rest from output
                                        from_window = false;
                                    }
                                }
                                if from_window {
                                    output[out..out + len]
                                        .copy_from_slice(&window[from..from + len]);
                                    out += len;
                                } else {
                                    copy_from_output(output, &mut out, from, len);
                                }
                            } else {
                                // copy direct from output
                                let from = out - dist;
                                copy_from_output(output, &mut out, from, len);
                            }
                        } else if op & 64 == 0 {
                            // 2nd level distance code
                            let index =
                                usize::from(here.val) + (hold & ((1u64 << op) - 1)) as usize;
                            here = dcode[index & SPAN];
                            continue;
                        } else {
                            *msg = Some("invalid distance code");
                            mode = Some(Mode::Bad);
                            break 'outer;
                        }
                        break;
                    }
                } else if op & 64 == 0 {
                    // 2nd level length code
                    let index = usize::from(here.val) + (hold & ((1u64 << op) - 1)) as usize;
                    here = lcode[index & SPAN];
                    continue;
                } else if op & 32 != 0 {
                    // end-of-block
                    mode = Some(Mode::Type);
                    break 'outer;
                } else {
                    *msg = Some("invalid literal/length code");
                    mode = Some(Mode::Bad);
                    break 'outer;
                }
                break;
            }
            // the bytes used so far end at inp - bits / 8
            if !(inp - (bits >> 3) as usize <= last && out < end) {
                break;
            }
        }
    }

    // return unused bytes (on entry, bits < 8, so in won't go too far back)
    let len = bits >> 3;
    inp -= len as usize;
    bits -= len << 3;
    hold &= (1u64 << bits) - 1;

    // update state and return
    *next_in = inp;
    *next_out = out;
    state.hold = hold;
    state.bits = bits;
    if let Some(mode) = mode {
        state.mode = mode;
    }
}

/// The refill at the end of the input, where fewer than eight bytes are
/// left: those there are, the rest zeros. zlib's test of the input left
/// keeps six bytes for each code, so they are enough.
#[cold]
fn refill_end(input: &[u8], inp: &mut usize, hold: &mut u64, bits: &mut u32) {
    let left = input.len() - *inp;
    let mut word = [0; 8];
    word[..left].copy_from_slice(&input[*inp..]);
    *hold |= u64::from_le_bytes(word) << *bits;
    let take = (((63 - *bits) >> 3) as usize).min(left);
    *inp += take;
    *bits += 8 * take as u32;
}

/// Eight bytes of input from `pos`, the first the lowest.
#[inline(always)]
fn read_word(input: &[u8], pos: usize) -> u64 {
    let mut word = [0; 8];
    word.copy_from_slice(&input[pos..pos + 8]);
    u64::from_le_bytes(word)
}

/// Copies `len` bytes (at least three) from `from`, earlier in `output`, to
/// `*out`, so that the copy repeats when they overlap.
///
/// Differs from zlib: zlib copies three bytes per loop. When the bytes are
/// at least eight back, the port copies eight at a time, each piece read
/// before it is written, and a run of one byte (one back) it fills, which
/// give the same bytes.
#[inline(always)]
fn copy_from_output(output: &mut [u8], out: &mut usize, from: usize, len: usize) {
    let dst = *out;
    let mut i = 0;
    if dst - from == 1 {
        // A run of one byte.
        let byte = output[from];
        output[dst..dst + len].fill(byte);
        i = len;
    } else if dst - from >= 8 {
        while i + 8 <= len {
            let mut piece = [0; 8];
            piece.copy_from_slice(&output[from + i..from + i + 8]);
            output[dst + i..dst + i + 8].copy_from_slice(&piece);
            i += 8;
        }
    }
    while i < len {
        output[dst + i] = output[from + i];
        i += 1;
    }
    *out += len;
}
