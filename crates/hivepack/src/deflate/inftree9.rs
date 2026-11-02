//! Building the decoding tables of a Deflate64 Huffman code: port of
//! `contrib/infback9/inftree9.{h,c}`.
//!
//! Deflate64 is PKWare's deflate with a 64K window: length code 285 has 16
//! extra bits on a base of 3, instead of meaning 258, and distance codes 30
//! and 31 reach 65536 back. The table entries are those of `inftrees`, but
//! a length or distance is `100eeeee` in `op`, as 16 extra bits need five.
//! This table builder is an older version of zlib's `inflate_table`, kept
//! as it is in `contrib/infback9`: a code with no symbols is an error, and
//! an incomplete code is filled in by a loop of its own.

use crate::deflate::inftrees::{Code, CodeType};

/// `ENOUGH_LENS`, `ENOUGH_DISTS`, `ENOUGH` of `inftree9.h`: "enough 286 9
/// 15" and "enough 32 6 15".
pub(crate) const ENOUGH_LENS9: usize = 852;
pub(crate) const ENOUGH_DISTS9: usize = 594;
pub(crate) const ENOUGH9: usize = ENOUGH_LENS9 + ENOUGH_DISTS9;

/// `MAXBITS`: the longest code.
const MAXBITS: usize = 15;

/// Length codes 257..285 base.
static LBASE: [u16; 31] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 3, 0, 0,
];
/// Length codes 257..285 extra.
static LEXT: [u16; 31] = [
    128, 128, 128, 128, 128, 128, 128, 128, 129, 129, 129, 129, 130, 130, 130, 130, 131, 131, 131,
    131, 132, 132, 132, 132, 133, 133, 133, 133, 144, 199, 75,
];
/// Distance codes 0..31 base.
static DBASE: [u16; 32] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153,
];
/// Distance codes 0..31 extra.
static DEXT: [u16; 32] = [
    128, 128, 128, 128, 129, 129, 130, 130, 131, 131, 132, 132, 133, 133, 134, 134, 135, 135, 136,
    136, 137, 137, 138, 138, 139, 139, 140, 140, 141, 141, 142, 142,
];

/// Builds the tables to decode the canonical Huffman code whose lengths are
/// `lens[0..codes]`, at `table[*next..]`, whose indices are `0..2^bits`.
/// `work` is a work area of at least `codes` entries.
///
/// Returns 0 on success, -1 for an invalid code (including one with no
/// symbols), and +1 when `ENOUGH` is not enough. On success `*next` is
/// moved past the entries used, and `*bits` is the root table's actual
/// index bits.
///
/// Port of `inflate_table9`, `contrib/infback9/inftree9.c`. Differs from
/// zlib: the table is an index into `table` rather than a pointer.
pub(crate) fn inflate_table9(
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
        return -1; // no codes!
    }
    let mut min = 1;
    while min <= MAXBITS as u32 {
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

    // set up for code type: symbols below `end` are literals, above it
    // lengths or distances, at it the end of block
    let end: i32 = match ty {
        CodeType::Codes => 19,
        CodeType::Lens => 256,
        CodeType::Dists => -1,
    };
    let entry = |symbol: usize| -> (u8, u16) {
        match ty {
            CodeType::Codes => (0, 0), // dummy value--not used
            CodeType::Lens => (LEXT[symbol - 257] as u8, LBASE[symbol - 257]),
            CodeType::Dists => (DEXT[symbol] as u8, DBASE[symbol]),
        }
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
    if (ty == CodeType::Lens && used as usize >= ENOUGH_LENS9)
        || (ty == CodeType::Dists && used as usize >= ENOUGH_DISTS9)
    {
        return 1;
    }

    // process all codes and make table entries
    loop {
        // create table entry
        let symbol = work[sym] as usize;
        let here = if (symbol as i32) < end {
            Code::new(0, (len - drop) as u8, symbol as u16)
        } else if (symbol as i32) > end {
            let (op, val) = entry(symbol);
            Code::new(op, (len - drop) as u8, val)
        } else {
            Code::new(32 + 64, (len - drop) as u8, 0) // end of block
        };

        // replicate for those indices with low len bits equal to huff
        let incr = 1u32 << (len - drop);
        let mut fill = 1u32 << curr;
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
            next_table += 1 << curr;

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
            if (ty == CodeType::Lens && used as usize >= ENOUGH_LENS9)
                || (ty == CodeType::Dists && used as usize >= ENOUGH_DISTS9)
            {
                return 1;
            }

            // point entry in root table to sub-table
            low = huff & mask;
            table[start + low as usize] =
                Code::new(curr as u8, root as u8, (next_table - start) as u16);
        }
    }

    // Fill in rest of table for incomplete codes. This loop is similar to
    // the loop above in incrementing huff for table indices. It is assumed
    // that len is equal to curr + drop, so there is no loop needed to
    // increment through high index bits. When the current sub-table is
    // filled, the loop drops back to the root table to fill in any
    // remaining entries there.
    let mut here = Code::new(64, (len - drop) as u8, 0); // invalid code marker
    while huff != 0 {
        // when done with sub-table, drop back to root table
        if drop != 0 && (huff & mask) != low {
            drop = 0;
            len = root;
            next_table = start;
            here.bits = len as u8;
        }

        // put invalid code marker in table
        table[next_table + (huff >> drop) as usize] = here;

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
    }

    // set return parameters
    *next += used as usize;
    *bits = root;
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deflate::inffix9::{DISTFIX9, LENFIX9};

    /// zlib's `makefixed9()` builds `inffix9.h` with `inflate_table9`: the
    /// port's must build the same tables. `inffix9.h` was made with an older
    /// `lext`, whose entries for the two symbols past 285 were 65 and 77,
    /// now 199 and 75: either way the four entries of 286 and 287 are
    /// invalid codes (`op & 64`), which decode the same.
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
        let ret = inflate_table9(
            CodeType::Lens,
            &lens,
            288,
            &mut table,
            &mut next,
            &mut bits,
            &mut work,
        );
        assert_eq!((ret, next, bits), (0, 512, 9));
        let mut invalid = 0;
        for (built, fixed) in table[..512].iter().zip(&LENFIX9) {
            if built != fixed {
                assert!(
                    built.op & 64 != 0 && fixed.op & 64 != 0,
                    "{built:?} {fixed:?}"
                );
                assert_eq!((built.bits, built.val), (fixed.bits, fixed.val));
                invalid += 1;
            }
        }
        assert_eq!(invalid, 4);

        let lens = [5u16; 32];
        let dist = next;
        let mut bits = 5;
        let ret = inflate_table9(
            CodeType::Dists,
            &lens,
            32,
            &mut table,
            &mut next,
            &mut bits,
            &mut work,
        );
        assert_eq!((ret, next, bits), (0, 544, 5));
        assert_eq!(&table[dist..dist + 32], &DISTFIX9[..]);
    }
}
