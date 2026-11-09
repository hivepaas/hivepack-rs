//! The fast decoding loop: port of `inffast.{h,c}`.

use std::sync::OnceLock;

use crate::deflate::inflate::{FastKind, InflateState, Mode};
use crate::deflate::inftrees::{
    Code, CodeType, DIST_ROOT, ENOUGH_DISTS_FAST, ENOUGH_LENS_FAST, LEN_ROOT, build_table,
};

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
/// - `state.bits < 8`, zlib says; inflate() may leave a whole byte there,
///   which the port's loop takes as it takes the rest.
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
/// - the codes are decoded from tables of their own ([`FastTables`]), made
///   from zlib's for each block, which a dynamic block builds with roots of
///   11 and 8 bits: each entry a word that says all of what it is. What is
///   decoded, the bits each code takes, where the loop stops and its errors
///   are those of zlib's tables. inflate() calls the loop only where there
///   are such tables, as there always are for a block of codes.
pub(crate) fn inflate_fast(
    state: &mut InflateState,
    input: &[u8],
    next_in: &mut usize,
    output: &mut [u8],
    next_out: &mut usize,
    start: usize,
    msg: &mut Option<&'static str>,
) {
    match state.fast_kind {
        FastKind::Own => {
            if let Some(tables) = state.fast.take() {
                inflate_fast_packed(state, input, next_in, output, next_out, start, msg, &tables);
                state.fast = Some(tables);
            }
        }
        FastKind::Fixed => {
            if let Some(tables) = fixed_tables() {
                inflate_fast_packed(state, input, next_in, output, next_out, start, msg, tables);
            }
        }
        // inflate() does not call it then.
        FastKind::None => {}
    }
}

/// The masks of the roots of [`FastTables::len`] and [`FastTables::dist`],
/// `LEN_ROOT` and `DIST_ROOT` bits.
const LEN_ROOT_MASK: usize = (1 << LEN_ROOT) - 1;
const DIST_ROOT_MASK: usize = (1 << DIST_ROOT) - 1;
/// The tables' sizes, powers of two past the most they take, which every
/// index is masked to, so that the compiler leaves out the bounds checks.
const LEN_SPAN: usize = 4096;
const DIST_SPAN: usize = 512;
const _: () = assert!(LEN_SPAN >= ENOUGH_LENS_FAST && DIST_SPAN >= ENOUGH_DISTS_FAST);

/// What an entry of [`FastTables`] is: a literal, a link to a sub-table,
/// the end of the block, or an invalid code; a length or distance base is
/// none of them.
const LITERAL: u32 = 1 << 15;
const SUBTABLE: u32 = 1 << 14;
const END: u32 = 1 << 13;
const INVALID: u32 = 1 << 12;

/// The fast loop's tables of a block's codes: zlib's, built with roots of 11
/// and 8 bits where zlib's are of 9 and 6, so that fewer codes take a
/// sub-table, each entry made a word that says all of what it is, so that
/// the loop decodes a code with one load and one test.
///
/// An entry's bits 0 to 7 are the bits the code takes, its extra bits with
/// it; bits 8 to 11 the code's own length, which the extra bits come after
/// (for a link, the sub-table's index bits); bits 12 to 15 what it is
/// ([`LITERAL`], [`SUBTABLE`], [`END`], [`INVALID`], or none for a base);
/// bits 16 to 31 its value: the literal, the base, or the sub-table's
/// start. A sub-table is indexed by the bits after the root's, which a link
/// does not take: its entries take the whole code.
///
/// zlib's checks of the code are those of its own tables, and so is what
/// each code takes, invalid ones too: these are made from them.
#[derive(Clone)]
pub(crate) struct FastTables {
    len: [u32; LEN_SPAN],
    dist: [u32; DIST_SPAN],
}

impl FastTables {
    pub(crate) fn boxed() -> Box<FastTables> {
        Box::new(FastTables {
            len: [0; LEN_SPAN],
            dist: [0; DIST_SPAN],
        })
    }

    /// The tables made from zlib's: `lens`, the literal/length table and its
    /// sub-tables, with a root of `len_bits`, and `dists`, the distance
    /// table, of `dist_bits`. `false` where a root is larger than this has
    /// room for, which zlib's never are.
    pub(crate) fn make(
        &mut self,
        lens: &[Code],
        len_bits: u32,
        dists: &[Code],
        dist_bits: u32,
    ) -> bool {
        made_from(lens, len_bits, LEN_ROOT, &mut self.len)
            && made_from(dists, dist_bits, DIST_ROOT, &mut self.dist)
    }
}

/// `codes`, zlib's table and its sub-tables with a root of `bits`, made into
/// `out`, whose root is `root` bits. Where `bits` is less, as where the
/// code's longest is shorter than `root`, zlib's table has no sub-table: its
/// entries are repeated, as each index's low bits find the same entry.
fn made_from(codes: &[Code], bits: u32, root: u32, out: &mut [u32]) -> bool {
    let full = 1usize << root;
    if bits > root || codes.len() > out.len() || codes.len() < 1 << bits {
        return false;
    }
    if bits < root {
        let low = (1usize << bits) - 1;
        for (i, entry) in out[..full].iter_mut().enumerate() {
            *entry = packed(codes[i & low], 0);
        }
    } else {
        for (entry, &code) in out[..full].iter_mut().zip(&codes[..full]) {
            *entry = packed(code, 0);
        }
        for (entry, &code) in out[full..codes.len()].iter_mut().zip(&codes[full..]) {
            *entry = packed(code, root);
        }
    }
    true
}

/// zlib's entry `code` as a word of [`FastTables`]; `under` the root's bits
/// for an entry of a sub-table, whose `bits` are those past them, 0 for the
/// root's.
fn packed(code: Code, under: u32) -> u32 {
    let op = u32::from(code.op);
    let length = u32::from(code.bits) + under;
    let value = u32::from(code.val) << 16;
    if op == 0 {
        LITERAL | value | length
    } else if op & 16 != 0 {
        // A base, its extra bits after the code.
        value | (length << 8) | (length + (op & 15))
    } else if op & 64 == 0 {
        // A link: `op` index bits, the sub-table at `val`.
        SUBTABLE | value | (op << 8)
    } else if op & 32 != 0 {
        END | length
    } else {
        INVALID | length
    }
}

/// The tables of the fixed codes (`inffixed.h`'s, built again with roots of
/// 11 and 8 bits), made once.
fn fixed_tables() -> Option<&'static FastTables> {
    static FIXED: OnceLock<Option<Box<FastTables>>> = OnceLock::new();
    FIXED
        .get_or_init(|| {
            let mut lens = [0u16; 320];
            lens[..144].fill(8);
            lens[144..256].fill(9);
            lens[256..280].fill(7);
            lens[280..288].fill(8);
            lens[288..].fill(5);
            let mut work = [0u16; 288];
            let mut codes = vec![Code::new(0, 0, 0); ENOUGH_LENS_FAST + ENOUGH_DISTS_FAST];
            let mut next = 0;
            let mut len_bits = LEN_ROOT;
            let lens_built = build_table(
                CodeType::Lens,
                &lens[..288],
                288,
                &mut codes,
                &mut next,
                &mut len_bits,
                &mut work,
                ENOUGH_LENS_FAST,
                ENOUGH_DISTS_FAST,
            );
            let dist_start = next;
            let mut dist_bits = DIST_ROOT;
            let dists_built = build_table(
                CodeType::Dists,
                &lens[288..],
                32,
                &mut codes,
                &mut next,
                &mut dist_bits,
                &mut work,
                ENOUGH_LENS_FAST,
                ENOUGH_DISTS_FAST,
            );
            let mut tables = FastTables::boxed();
            let made = lens_built == 0
                && dists_built == 0
                && tables.make(
                    &codes[..dist_start],
                    len_bits,
                    &codes[dist_start..next],
                    dist_bits,
                );
            made.then_some(tables)
        })
        .as_deref()
}

/// The entry of the sub-table that `link` points to, in `table`, for the
/// bits of `hold` after the root's `root`.
#[inline(always)]
fn sub_index(link: u32, hold: u64, root: u32) -> usize {
    let index_bits = (link >> 8) & 0xF;
    (link >> 16) as usize + ((hold >> root) as usize & ((1usize << index_bits) - 1))
}

/// The value of a base entry `entry`, its extra bits read from `hold`.
#[inline(always)]
fn based(entry: u32, hold: u64) -> u32 {
    let taken = entry & 0xFF;
    let code = (entry >> 8) & 0xF;
    (entry >> 16) + (((hold as u32) & ((1u32 << taken) - 1)) >> code)
}

/// [`inflate_fast`] with [`FastTables`]: zlib's loop, each code decoded
/// from its word.
#[allow(clippy::too_many_arguments)]
fn inflate_fast_packed(
    state: &mut InflateState,
    input: &[u8],
    next_in: &mut usize,
    output: &mut [u8],
    next_out: &mut usize,
    start: usize,
    msg: &mut Option<&'static str>,
    tables: &FastTables,
) {
    let mut inp = *next_in;
    let last = input.len() - 6;
    let mut out = *next_out;
    let beg = out - (start - (output.len() - out));
    let end = out + (output.len() - out - 257);
    let mut hold = state.hold;
    let mut bits = state.bits;
    let mut mode = None;

    {
        // What a match that reaches into the window takes, read only then.
        let window = Window {
            bytes: &state.window[..],
            wsize: state.wsize,
            whave: state.whave,
            wnext: state.wnext,
            sane: state.sane,
        };
        let len_table = &tables.len;
        let dist_table = &tables.dist;
        loop {
            if inp + 8 <= input.len() {
                hold |= read_word(input, inp) << bits;
                inp += ((63 - bits) >> 3) as usize;
                bits |= 56;
            } else {
                refill_end(input, &mut inp, &mut hold, &mut bits);
            }
            // Room for two more literals after this code, decoded without
            // going round: each is decoded where zlib decodes it, in its
            // fast loop, as past three codes' bits (33 at most, literals of
            // the root) the loop's test still holds with six bytes more left,
            // and so it does with two bytes more of output space. (Added to
            // `last` rather than taken from `inp`: inflate() may call the
            // loop with a byte in the bit buffer, so right after a refill
            // `inp` may be less than the bytes it holds.)
            let room = inp + 6 <= last + (bits >> 3) as usize && out + 2 < end;
            let mut entry = len_table[hold as usize & LEN_ROOT_MASK];
            if entry & SUBTABLE != 0 {
                entry = len_table[sub_index(entry, hold, LEN_ROOT) & (LEN_SPAN - 1)];
            }
            // The code taken, whatever it is, its extra bits read from
            // `used`, the bits before it.
            let used = hold;
            let taken = entry & 0xFF;
            hold >>= taken;
            bits -= taken;
            if entry & LITERAL != 0 {
                output[out] = (entry >> 16) as u8;
                out += 1;
                if room {
                    // Up to two more, while they are literals of the root,
                    // from the bits the refill left: 48 or more, of which a
                    // literal of a sub-table takes 15 and two of the root
                    // 22.
                    let next = len_table[hold as usize & LEN_ROOT_MASK];
                    if next & LITERAL != 0 {
                        let taken = next & 0xFF;
                        hold >>= taken;
                        bits -= taken;
                        output[out] = (next >> 16) as u8;
                        out += 1;
                        let next = len_table[hold as usize & LEN_ROOT_MASK];
                        if next & LITERAL != 0 {
                            let taken = next & 0xFF;
                            hold >>= taken;
                            bits -= taken;
                            output[out] = (next >> 16) as u8;
                            out += 1;
                        }
                    }
                }
            } else if entry & (END | INVALID) == 0 {
                let len = based(entry, used) as usize;
                let mut entry = dist_table[hold as usize & DIST_ROOT_MASK];
                if entry & SUBTABLE != 0 {
                    entry = dist_table[sub_index(entry, hold, DIST_ROOT) & (DIST_SPAN - 1)];
                }
                let used = hold;
                let taken = entry & 0xFF;
                hold >>= taken;
                bits -= taken;
                if entry & INVALID != 0 {
                    *msg = Some("invalid distance code");
                    mode = Some(Mode::Bad);
                    break;
                }
                let dist = based(entry, used) as usize;
                if dist <= out - beg {
                    // copy direct from output
                    let from = out - dist;
                    copy_from_output(output, &mut out, from, len);
                } else {
                    match window.copy(output, out, beg, dist, len) {
                        Some(after) => out = after,
                        None => {
                            *msg = Some("invalid distance too far back");
                            mode = Some(Mode::Bad);
                            break;
                        }
                    }
                }
            } else if entry & END != 0 {
                mode = Some(Mode::Type);
                break;
            } else {
                *msg = Some("invalid literal/length code");
                mode = Some(Mode::Bad);
                break;
            }
            if !(inp - (bits >> 3) as usize <= last && out < end) {
                break;
            }
        }
    }

    let len = bits >> 3;
    inp -= len as usize;
    bits -= len << 3;
    hold &= (1u64 << bits) - 1;

    *next_in = inp;
    *next_out = out;
    state.hold = hold;
    state.bits = bits;
    if let Some(mode) = mode {
        state.mode = mode;
    }
}

/// The window and what says how much of it is there, as inflate_fast()
/// reads them for a match that starts before the output inflate() was given.
struct Window<'a> {
    bytes: &'a [u8],
    wsize: usize,
    whave: usize,
    wnext: usize,
    sane: bool,
}

impl Window<'_> {
    /// The copy of a match of `len` bytes from `dist` back to `out`, which
    /// starts before `beg`, the output inflate() was given: from the window,
    /// then the output, as zlib's loop copies it; where the output is then.
    /// `None` where it starts further back than the window holds, and
    /// `sane`. Not inlined, so that the loop keeps none of this in its
    /// registers; and `out` given and given back, not borrowed, so that the
    /// loop keeps its own in one.
    #[inline(never)]
    fn copy(
        &self,
        output: &mut [u8],
        out: usize,
        beg: usize,
        dist: usize,
        len: usize,
    ) -> Option<usize> {
        let mut at = out;
        let out = &mut at;
        let Window {
            bytes: window,
            wsize,
            whave,
            wnext,
            sane,
        } = *self;
        let mut len = len;
        // see if copy from window
        let mut op = dist - (*out - beg); // distance back in window
        if op > whave && sane {
            return None;
        }
        let mut from;
        let mut from_window = true;
        if wnext == 0 {
            // very common case
            from = wsize - op;
            if op < len {
                // some from window
                len -= op;
                output[*out..*out + op].copy_from_slice(&window[from..from + op]);
                *out += op;
                from = *out - dist; // rest from output
                from_window = false;
            }
        } else if wnext < op {
            // wrap around window
            from = wsize + wnext - op;
            op -= wnext;
            if op < len {
                // some from end of window
                len -= op;
                output[*out..*out + op].copy_from_slice(&window[from..from + op]);
                *out += op;
                from = 0;
                if wnext < len {
                    // some from start of window
                    let op = wnext;
                    len -= op;
                    output[*out..*out + op].copy_from_slice(&window[..op]);
                    *out += op;
                    from = *out - dist; // rest from output
                    from_window = false;
                }
            }
        } else {
            // contiguous in window
            from = wnext - op;
            if op < len {
                // some from window
                len -= op;
                output[*out..*out + op].copy_from_slice(&window[from..from + op]);
                *out += op;
                from = *out - dist; // rest from output
                from_window = false;
            }
        }
        if from_window {
            output[*out..*out + len].copy_from_slice(&window[from..from + len]);
            *out += len;
        } else {
            copy_from_output(output, out, from, len);
        }
        Some(at)
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
/// at least eight back, the port copies eight at a time, sixteen when they
/// are sixteen back, each piece read before it is written; a run of one
/// byte (one back) it fills, which give the same bytes. Where `output` has
/// room for a whole piece past the copy, the last piece is copied whole, as
/// zlib-ng copies: what it writes past the copy is in the output's space,
/// and nothing reads it before the output's next bytes, or the next call's,
/// write over it.
#[inline(always)]
fn copy_from_output(output: &mut [u8], out: &mut usize, from: usize, len: usize) {
    let dst = *out;
    let dist = dst - from;
    if dist >= 16 && dst + len + 16 <= output.len() {
        let mut i = 0;
        while i < len {
            let at = dst + i;
            let mut piece = [0; 16];
            piece.copy_from_slice(&output[at - dist..at - dist + 16]);
            output[at..at + 16].copy_from_slice(&piece);
            i += 16;
        }
        *out += len;
        return;
    }
    if dist >= 8 && dst + len + 8 <= output.len() {
        let mut i = 0;
        while i < len {
            let at = dst + i;
            let mut piece = [0; 8];
            piece.copy_from_slice(&output[at - dist..at - dist + 8]);
            output[at..at + 8].copy_from_slice(&piece);
            i += 8;
        }
        *out += len;
        return;
    }
    let mut i = 0;
    if dist == 1 {
        // A run of one byte.
        let byte = output[from];
        output[dst..dst + len].fill(byte);
        i = len;
    } else if dist >= 8 {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every distance up to 40 and length from 3 to 258, with no room to a
    /// little past the copy: the bytes written are those of a copy a byte
    /// at a time, and none past the output's end is reached.
    #[test]
    fn copies_are_those_of_one_byte_at_a_time() {
        for dist in 1..=40 {
            for len in 3..=258 {
                for room in [0, 1, 7, 8, 15, 16, 17, 40] {
                    let size = 64 + len + room;
                    let start: Vec<u8> = (0..size).map(|i| (i * 7 + 3) as u8).collect();
                    let dst = 64;
                    let mut expected = start.clone();
                    for i in 0..len {
                        expected[dst + i] = expected[dst - dist + i];
                    }
                    let mut output = start.clone();
                    let mut out = dst;
                    copy_from_output(&mut output, &mut out, dst - dist, len);
                    assert_eq!(out, dst + len);
                    assert_eq!(
                        output[..dst + len],
                        expected[..dst + len],
                        "{dist} back, {len} long, {room} past"
                    );
                }
            }
        }
    }
}
