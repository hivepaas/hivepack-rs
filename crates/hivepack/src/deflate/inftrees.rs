//! Building the decoding tables of a Huffman code: port of `inftrees.{h,c}`.

use crate::deflate::inflate::{InflateState, Table};

/// A table entry: `code` in `inftrees.h`.
///
/// `op` says what the entry is:
/// - `00000000`: a literal;
/// - `0000tttt`: a link to a sub-table, `tttt != 0` its number of index
///   bits;
/// - `0001eeee`: a length or distance, `eeee` its number of extra bits;
/// - `01100000`: end of block;
/// - `01000000`: an invalid code.
///
/// `bits` is the number of bits in this code or part of the code to drop,
/// and `val` the literal, the base length or distance, or the offset from
/// the current table to the next table.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct Code {
    pub op: u8,
    pub bits: u8,
    pub val: u16,
}

impl Code {
    pub(crate) const fn new(op: u8, bits: u8, val: u16) -> Code {
        Code { op, bits, val }
    }
}

/// `ENOUGH_LENS`, `ENOUGH_DISTS`, `ENOUGH`: the most table entries a
/// literal/length code (with a root table of 9 bits) and a distance code (6
/// bits) can need, found by zlib's `examples/enough.c`.
pub(crate) const ENOUGH_LENS: usize = 852;
pub(crate) const ENOUGH_DISTS: usize = 592;
pub(crate) const ENOUGH: usize = ENOUGH_LENS + ENOUGH_DISTS;

/// `MAXBITS`: the longest code.
const MAXBITS: usize = 15;

/// `codetype`: what a code decodes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum CodeType {
    Codes,
    Lens,
    Dists,
}

/// Length codes 257..285 base.
static LBASE: [u16; 31] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258, 0, 0,
];
/// Length codes 257..285 extra.
static LEXT: [u16; 31] = [
    16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18, 19, 19, 19, 19, 20, 20, 20, 20,
    21, 21, 21, 21, 16, 199, 75,
];
/// Distance codes 0..29 base.
static DBASE: [u16; 32] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 0, 0,
];
/// Distance codes 0..29 extra.
static DEXT: [u16; 32] = [
    16, 16, 16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 21, 21, 22, 22, 23, 23, 24, 24, 25, 25, 26, 26,
    27, 27, 28, 28, 29, 29, 64, 64,
];

/// Builds the tables to decode the canonical Huffman code whose lengths are
/// `lens[0..codes]`, at `table[*next..]`, whose indices are
/// `0..2^bits`. `work` is a work area of at least `codes` entries.
///
/// Returns 0 on success, -1 for an invalid code, and +1 when `ENOUGH` is
/// not enough. On success `*next` is moved past the entries used, and
/// `*bits` is the root table's actual index bits, which differ from the
/// request if it is greater than the longest code or less than the
/// shortest.
///
/// Port of `inflate_table`, `inftrees.c`. Differs from zlib: the table is
/// an index into `table` rather than a pointer.
pub(crate) fn inflate_table(
    ty: CodeType,
    lens: &[u16],
    codes: usize,
    table: &mut [Code],
    next: &mut usize,
    bits: &mut u32,
    work: &mut [u16],
) -> i32 {
    // number of codes of each length
    let mut count = [0u16; MAXBITS + 1];
    // offsets in table for each length
    let mut offs = [0u16; MAXBITS + 1];

    // accumulate lengths for codes (assumes lens[] all in 0..MAXBITS)
    for &len in &lens[..codes] {
        count[len as usize] += 1;
    }

    // bound code lengths, force root to be within code lengths
    let mut root = *bits;
    let mut max = MAXBITS as u32;
    while max >= 1 {
        if count[max as usize] != 0 {
            break;
        }
        max -= 1;
    }
    if root > max {
        root = max;
    }
    if max == 0 {
        // no symbols to code at all
        let here = Code::new(64, 1, 0); // invalid code marker
        // make a table to force an error
        table[*next] = here;
        table[*next + 1] = here;
        *next += 2;
        *bits = 1;
        return 0; // no symbols, but wait for decoding to report error
    }
    let mut min = 1;
    while min < max {
        if count[min as usize] != 0 {
            break;
        }
        min += 1;
    }
    if root < min {
        root = min;
    }

    // check for an over-subscribed or incomplete set of lengths
    let mut left: i32 = 1;
    for len in 1..=MAXBITS {
        left <<= 1;
        left -= i32::from(count[len]);
        if left < 0 {
            return -1; // over-subscribed
        }
    }
    if left > 0 && (ty == CodeType::Codes || max != 1) {
        return -1; // incomplete set
    }

    // generate offsets into symbol table for each length for sorting
    offs[1] = 0;
    for len in 1..MAXBITS {
        offs[len + 1] = offs[len] + count[len];
    }

    // sort symbols by length, by symbol order within each length
    for sym in 0..codes {
        if lens[sym] != 0 {
            let len = lens[sym] as usize;
            work[offs[len] as usize] = sym as u16;
            offs[len] += 1;
        }
    }

    // set up for code type
    let (base, extra, matched): (&[u16], &[u16], u32) = match ty {
        CodeType::Codes => (&[], &[], 20),
        CodeType::Lens => (&LBASE, &LEXT, 257),
        CodeType::Dists => (&DBASE, &DEXT, 0),
    };

    // initialize state for loop
    let start = *next; // where *table points
    let mut huff: u32 = 0; // starting code
    let mut sym: usize = 0; // starting code symbol
    let mut len = min; // starting code length
    let mut next_table = start; // current table to fill in
    let mut curr = root; // current table index bits
    let mut drop: u32 = 0; // current bits to drop from code for index
    let mut low: u32 = u32::MAX; // trigger new sub-table when len > root
    let mut used: u32 = 1 << root; // use root table entries
    let mask = used - 1; // mask for comparing low

    // check available table space
    if (ty == CodeType::Lens && used as usize > ENOUGH_LENS)
        || (ty == CodeType::Dists && used as usize > ENOUGH_DISTS)
    {
        return 1;
    }

    // process all codes and make table entries
    loop {
        // create table entry
        let symbol = u32::from(work[sym]);
        let here = if symbol + 1 < matched {
            Code::new(0, (len - drop) as u8, symbol as u16)
        } else if symbol >= matched {
            let i = (symbol - matched) as usize;
            Code::new(extra[i] as u8, (len - drop) as u8, base[i])
        } else {
            Code::new(32 + 64, (len - drop) as u8, 0) // end of block
        };

        // replicate for those indices with low len bits equal to huff
        let incr = 1u32 << (len - drop);
        let mut fill = 1u32 << curr;
        min = fill; // save offset to next table
        loop {
            fill -= incr;
            table[next_table + ((huff >> drop) + fill) as usize] = here;
            if fill == 0 {
                break;
            }
        }

        // backwards increment the len-bit code huff
        let mut incr = 1u32 << (len - 1);
        while huff & incr != 0 {
            incr >>= 1;
        }
        if incr != 0 {
            huff &= incr - 1;
            huff += incr;
        } else {
            huff = 0;
        }

        // go to next symbol, update count, len
        sym += 1;
        count[len as usize] -= 1;
        if count[len as usize] == 0 {
            if len == max {
                break;
            }
            len = u32::from(lens[work[sym] as usize]);
        }

        // create new sub-table if needed
        if len > root && (huff & mask) != low {
            // if first time, transition to sub-tables
            if drop == 0 {
                drop = root;
            }

            // increment past last table
            next_table += min as usize; // here min is 1 << curr

            // determine length of next table
            curr = len - drop;
            let mut left: i32 = 1 << curr;
            while curr + drop < max {
                left -= i32::from(count[(curr + drop) as usize]);
                if left <= 0 {
                    break;
                }
                curr += 1;
                left <<= 1;
            }

            // check for enough space
            used += 1 << curr;
            if (ty == CodeType::Lens && used as usize > ENOUGH_LENS)
                || (ty == CodeType::Dists && used as usize > ENOUGH_DISTS)
            {
                return 1;
            }

            // point entry in root table to sub-table
            low = huff & mask;
            table[start + low as usize] =
                Code::new(curr as u8, root as u8, (next_table - start) as u16);
        }
    }

    // fill in remaining table entry if code is incomplete (guaranteed to
    // have at most one remaining entry, since if the code is incomplete,
    // the maximum code length that was allowed to get this far is one bit)
    if huff != 0 {
        table[next_table + huff as usize] = Code::new(64, (len - drop) as u8, 0);
    }

    // set return parameters
    *next += used as usize;
    *bits = root;
    0
}

/// Sets `state` to decode a fixed-code block, with the tables from
/// `inffixed.h`.
///
/// Port of `inflate_fixed`, `inftrees.c` (without `BUILDFIXED`, as zlib is
/// built by default).
pub(crate) fn inflate_fixed(state: &mut InflateState) {
    state.lencode = Table::LenFix;
    state.lenbits = 9;
    state.distcode = Table::DistFix;
    state.distbits = 5;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deflate::inffixed::{DISTFIX, LENFIX};

    /// zlib's `makefixed()` builds `inffixed.h` with `inflate_table`: the
    /// port's must build the same tables.
    #[test]
    fn builds_the_fixed_tables() {
        let mut lens = [0u16; 288];
        let mut work = [0u16; 288];
        for (sym, len) in lens.iter_mut().enumerate() {
            *len = match sym {
                0..144 => 8,
                144..256 => 9,
                256..280 => 7,
                _ => 8,
            };
        }
        let mut table = [Code::default(); 544];
        let mut next = 0;
        let mut bits = 9;
        assert_eq!(
            inflate_table(
                CodeType::Lens,
                &lens,
                288,
                &mut table,
                &mut next,
                &mut bits,
                &mut work
            ),
            0
        );
        assert_eq!((next, bits), (512, 9));
        for (low, (built, fixed)) in table[..512].iter().zip(LENFIX.iter()).enumerate() {
            // makefixed() writes 64 for the invalid codes 286 and 287.
            let op = if low & 127 == 99 { 64 } else { built.op };
            assert_eq!(
                Code::new(op, built.bits, built.val),
                *fixed,
                "lenfix[{low}]"
            );
        }

        let lens = [5u16; 32];
        let dist = next;
        let mut bits = 5;
        assert_eq!(
            inflate_table(
                CodeType::Dists,
                &lens,
                32,
                &mut table,
                &mut next,
                &mut bits,
                &mut work
            ),
            0
        );
        assert_eq!((next, bits), (544, 5));
        assert_eq!(&table[dist..dist + 32], &DISTFIX[..]);
    }

    /// From zlib's `test/infcover.c`, `cover_trees`: tables that do not fit
    /// in `ENOUGH_DISTS`, which zlib's own callers never ask for.
    #[test]
    fn not_enough() {
        let mut lens = [0u16; 16];
        let mut work = [0u16; 16];
        for (bits, len) in lens.iter_mut().enumerate().take(15) {
            *len = bits as u16 + 1;
        }
        lens[15] = 15;
        for request in [15, 1] {
            let mut table = [Code::default(); ENOUGH_DISTS];
            let mut next = 0;
            let mut bits = request;
            let ret = inflate_table(
                CodeType::Dists,
                &lens,
                16,
                &mut table,
                &mut next,
                &mut bits,
                &mut work,
            );
            assert_eq!(ret, 1);
        }
    }
}
