//! XPRESS with Huffman coding, as a WIM's chunks are compressed with it.
//!
//! Microsoft's *[MS-XCA]: Xpress Compression Algorithm* (v20240423) is the
//! specification, published under its Open Specification Promise, and
//! §2.2.4 gives the decompression algorithm as pseudocode. This follows
//! it. Nothing here is a port: wimlib's decompressor is GPL-3.0-or-later
//! and was not read — it is built by `scripts/testdata.py` and run as a
//! program to write the archives the tests read back.
//!
//! The shape of it: a block begins with **256 bytes holding 512 four-bit
//! code lengths**, one for each symbol of the alphabet, and from those the
//! canonical Huffman codes are rebuilt. A symbol under 256 is that byte. A
//! symbol at or above it is a match, and the symbol itself carries both how
//! long the match is and how many bits of its distance follow:
//!
//! ```text
//! HuffmanSymbol = 256 + min(Length - 3, 15) + 16 * GetHighBit(Distance)
//! ```
//!
//! so `(symbol - 256) % 16` is the length, `/ 16` the number of distance
//! bits ([MS-XCA] §2.1.4.1). A length of 15 means 18 or more, and the rest
//! is in bytes taken from the stream itself rather than from the bits.

use super::error::Error;

/// How many symbols the alphabet has: 256 literals and 256 matches.
const SYMBOLS: usize = 512;

/// The longest Huffman code, which is what four bits can say.
const MOST_BITS: u32 = 15;

/// How long the table of code lengths is: two four-bit lengths a byte.
const TABLE: usize = SYMBOLS / 2;

/// How much one block holds at most ([MS-XCA] §2.2.4, `BlockEnd`).
const BLOCK: usize = 65536;

/// The shortest match, which the symbol's length is counted from.
const MIN_MATCH: usize = 3;

/// A canonical Huffman decoder, as [MS-XCA] §2.2.4 builds one: every
/// 15-bit prefix maps to the symbol whose code begins it, so a symbol is
/// one lookup and its code length says how many bits it took.
///
/// The specification says an implementation "MAY use this simple
/// table-based method, but SHOULD use a faster method". This is the simple
/// one, kept across the chunks of a resource so that the 64 KiB of it is
/// taken once rather than for each 32 KiB chunk.
pub(crate) struct Decoder {
    /// 2^15 entries, each the symbol a prefix decodes to.
    prefixes: Vec<u16>,
    lengths: [u8; SYMBOLS],
}

impl Decoder {
    pub(crate) fn new() -> Decoder {
        Decoder {
            prefixes: vec![0; 1 << MOST_BITS],
            lengths: [0; SYMBOLS],
        }
    }

    /// The codes of one block, from its 256 bytes of code lengths.
    ///
    /// A table that does not fill the prefixes exactly is not a canonical
    /// Huffman code, and the block is not read: the specification says so
    /// both ways round — more entries than 2^15 and fewer are each
    /// "compressed data is not valid".
    fn build(&mut self, table: &[u8]) -> Result<(), Error> {
        for (i, byte) in table.iter().enumerate() {
            // The length of an even symbol is the low four bits, of an odd
            // one the high four ([MS-XCA] §2.1.4.3).
            self.lengths[i * 2] = byte & 0x0F;
            self.lengths[i * 2 + 1] = byte >> 4;
        }
        let mut at = 0usize;
        for bits in 1..=MOST_BITS {
            let each = 1usize << (MOST_BITS - bits);
            for (symbol, &length) in self.lengths.iter().enumerate() {
                if u32::from(length) != bits {
                    continue;
                }
                let end = at.checked_add(each).ok_or(Error::Xpress)?;
                if end > self.prefixes.len() {
                    return Err(Error::Xpress);
                }
                self.prefixes[at..end].fill(symbol as u16);
                at = end;
            }
        }
        if at != self.prefixes.len() {
            return Err(Error::Xpress);
        }
        Ok(())
    }
}

/// The bits and bytes of a block, read as [MS-XCA] §2.2.4 reads them: a
/// 32-bit register holding at least the next 16 bits, filled 16 bits at a
/// time from little-endian halfwords.
///
/// The bytes a long match length is written in are **not** in the bits:
/// they are the halfwords the register has not reached yet, taken from the
/// stream in passing. That is why the two live in one reader.
struct Bits<'a> {
    src: &'a [u8],
    at: usize,
    /// The bits, the next one at the top.
    window: u32,
    /// How many of the low 16 bits of `window` are still to be read, which
    /// goes negative exactly when another halfword is due.
    spare: i32,
}

impl<'a> Bits<'a> {
    /// The reader of a block whose code lengths are already taken.
    fn new(src: &'a [u8]) -> Result<Bits<'a>, Error> {
        let mut bits = Bits {
            src,
            at: TABLE,
            window: 0,
            spare: 16,
        };
        let first = bits.halfword()?;
        let second = bits.halfword()?;
        bits.window = (u32::from(first) << 16) | u32::from(second);
        Ok(bits)
    }

    /// The next little-endian halfword, which is where both the bits and a
    /// long length's bytes come from.
    fn halfword(&mut self) -> Result<u16, Error> {
        let end = self.at.checked_add(2).ok_or(Error::Xpress)?;
        if end > self.src.len() {
            return Err(Error::Xpress);
        }
        let word = u16::from_le_bytes([self.src[self.at], self.src[self.at + 1]]);
        self.at = end;
        Ok(word)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        let byte = *self.src.get(self.at).ok_or(Error::Xpress)?;
        self.at += 1;
        Ok(byte)
    }

    /// The next 15 bits, without taking them.
    fn peek(&self) -> usize {
        (self.window >> (32 - MOST_BITS)) as usize
    }

    /// `take` bits gone, and another halfword in where one is due.
    fn take(&mut self, take: u32) -> Result<(), Error> {
        // A code of no bits is no code: a symbol the block never uses has
        // a length of zero, and reaching one means the table and the bits
        // disagree.
        if take == 0 || take > MOST_BITS {
            return Err(Error::Xpress);
        }
        self.window <<= take;
        self.spare -= take as i32;
        if self.spare < 0 {
            let word = self.halfword()?;
            self.window |= u32::from(word) << (-self.spare);
            self.spare += 16;
        }
        Ok(())
    }
}

/// `src` decompressed into `out`, which is as long as the chunk holds.
///
/// One chunk is one block. A block holds 65536 bytes at most ([MS-XCA]
/// §2.2.4), and a WIM compresses XPRESS in chunks of 32768, so a block
/// boundary never falls inside a chunk; a chunk longer than a block is
/// refused rather than read as though the table at its start covered all
/// of it.
///
/// `out` is filled whole or this fails: a chunk says how long it is, and
/// bits that stop early are a chunk that was cut short.
pub(crate) fn decompress(decoder: &mut Decoder, src: &[u8], out: &mut [u8]) -> Result<(), Error> {
    if out.len() > BLOCK {
        return Err(Error::Xpress);
    }
    if src.len() < TABLE {
        return Err(Error::Xpress);
    }
    decoder.build(&src[..TABLE])?;
    let mut bits = Bits::new(src)?;
    let mut written = 0usize;
    while written < out.len() {
        let symbol = decoder.prefixes[bits.peek()] as usize;
        bits.take(u32::from(decoder.lengths[symbol]))?;
        if symbol < 256 {
            out[written] = symbol as u8;
            written += 1;
            continue;
        }
        // A match: the symbol says how long it is and how many bits of
        // its distance follow ([MS-XCA] §2.1.4.1). Symbol 256 is the end
        // marker where the output is already whole and the input read,
        // which cannot be here because the output is not whole; the
        // specification's own pseudocode then takes it as this match of
        // three bytes at a distance of one, which fails below for being
        // of bytes before the chunk.
        let match_symbol = symbol - 256;
        let mut match_length = match_symbol % 16;
        let offset_bits = (match_symbol / 16) as u32;
        if match_length == 15 {
            // Longer than 17, and the rest is in bytes rather than bits.
            match_length = usize::from(bits.byte()?);
            if match_length == 255 {
                match_length = usize::from(bits.halfword()?);
                // The specification's own encoder writes a halfword of
                // zero and then a 32-bit length for 65536 and over, while
                // its decoder refuses what is under 15 instead of reading
                // one. A block holds 65536 bytes, so no length that large
                // fits in one, and the reader keeps the decoder's rule.
                if match_length < 15 {
                    return Err(Error::Xpress);
                }
                match_length -= 15;
            }
            match_length += 15;
        }
        match_length += MIN_MATCH;

        // The distance's low bits, with the high one the symbol carried.
        // The specification's pseudocode shifts by `32 - MatchOffsetBitLength`
        // and does not say what no bits does; a distance of 1 has no low
        // bits, so none are read.
        let mut offset = 1usize << offset_bits;
        if offset_bits > 0 {
            offset += (bits.window >> (32 - offset_bits)) as usize;
            bits.take(offset_bits)?;
        }
        if offset > written {
            // Of bytes before the chunk, which a chunk cannot reach: each
            // one is compressed on its own.
            return Err(Error::Xpress);
        }
        if match_length > out.len() - written {
            // Longer than the chunk says it holds.
            return Err(Error::Xpress);
        }
        // One byte at a time: a match may be longer than its own distance,
        // which is how a run of one byte is written ([MS-XCA] §2.2.4).
        for _ in 0..match_length {
            out[written] = out[written - offset];
            written += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bits as [MS-XCA] writes them: most significant first, in
    /// little-endian halfwords.
    struct Writer {
        words: Vec<u8>,
        acc: u32,
        bits: u32,
    }

    impl Writer {
        fn new() -> Writer {
            Writer {
                words: Vec::new(),
                acc: 0,
                bits: 0,
            }
        }

        fn put(&mut self, value: u32, width: u32) {
            self.acc = (self.acc << width) | value;
            self.bits += width;
            while self.bits >= 16 {
                let word = (self.acc >> (self.bits - 16)) as u16;
                self.words.extend_from_slice(&word.to_le_bytes());
                self.bits -= 16;
                self.acc &= (1u32 << self.bits).wrapping_sub(1);
            }
        }

        /// The halfwords, the last one padded, and two of zeroes after it
        /// so that a reader filling ahead never runs past the end.
        fn finish(mut self) -> Vec<u8> {
            if self.bits > 0 {
                self.put(0, 16 - self.bits);
            }
            self.words.extend_from_slice(&[0, 0, 0, 0]);
            self.words
        }
    }

    /// Code lengths of nine bits for every symbol, which fills the
    /// prefixes exactly: 512 symbols of 2^(15-9) entries each is 2^15. The
    /// code of a symbol is then the symbol itself in nine bits, since
    /// canonical codes go by length and then by symbol.
    fn all_nine() -> [u8; SYMBOLS] {
        [9u8; SYMBOLS]
    }

    /// A block: the 256 bytes of code lengths, then the bits.
    fn block(lengths: &[u8; SYMBOLS], bits: Writer) -> Vec<u8> {
        let mut out = Vec::with_capacity(TABLE);
        for pair in lengths.as_chunks::<2>().0 {
            out.push((pair[1] << 4) | (pair[0] & 0x0F));
        }
        out.extend_from_slice(&bits.finish());
        out
    }

    fn decode(src: &[u8], len: usize) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; len];
        decompress(&mut Decoder::new(), src, &mut out)?;
        Ok(out)
    }

    #[test]
    fn literals_come_out_as_themselves() {
        let mut bits = Writer::new();
        for byte in b"hello" {
            bits.put(u32::from(*byte), 9);
        }
        let src = block(&all_nine(), bits);
        assert_eq!(decode(&src, 5).unwrap(), b"hello");
    }

    /// A match of three bytes at a distance of one, which is how a run of
    /// one byte is written: the symbol carries both, and no bits follow.
    #[test]
    fn a_match_copies_what_came_before_it() {
        let mut bits = Writer::new();
        bits.put(u32::from(b'a'), 9);
        // 256 + (length - 3) + 16 * high bit of the distance.
        bits.put(256, 9);
        let src = block(&all_nine(), bits);
        assert_eq!(decode(&src, 4).unwrap(), b"aaaa");
    }

    /// A distance of more than one: the symbol says how many of its bits
    /// follow, and those are the bits under the highest one.
    #[test]
    fn a_distance_takes_its_bits_from_the_stream() {
        let mut bits = Writer::new();
        bits.put(u32::from(b'a'), 9);
        bits.put(u32::from(b'b'), 9);
        // Length 3, one bit of distance: distance = 2 + that bit.
        bits.put(256 + 16, 9);
        bits.put(0, 1);
        let src = block(&all_nine(), bits);
        assert_eq!(decode(&src, 5).unwrap(), b"ababa");
    }

    /// A length of 15 in the symbol means 18 or more, and the rest is a
    /// byte taken from the stream rather than from the bits.
    #[test]
    fn a_long_match_takes_its_length_from_a_byte() {
        let mut bits = Writer::new();
        bits.put(u32::from(b'a'), 9);
        bits.put(256 + 15, 9);
        let mut src = block(&all_nine(), bits);
        // The byte goes where a reader taking halfwords has got to, which
        // [MS-XCA] §2.1.4.3 says is what makes the extra bytes "the next
        // bytes that the decompression function will read". Counted: two
        // halfwords are taken before the first symbol, and the second
        // symbol's nine bits take the spare below zero, so a third is
        // taken as well. Six bytes in, then.
        // 20 - 18 = 2, so this is a match of 20 bytes.
        src.insert(TABLE + 6, 2);
        assert_eq!(decode(&src, 21).unwrap(), b"a".repeat(21));
    }

    #[test]
    fn a_match_of_bytes_before_the_chunk_is_refused() {
        let mut bits = Writer::new();
        bits.put(256, 9);
        let src = block(&all_nine(), bits);
        assert!(matches!(decode(&src, 4), Err(Error::Xpress)));
    }

    #[test]
    fn a_match_past_the_chunk_is_refused() {
        let mut bits = Writer::new();
        bits.put(u32::from(b'a'), 9);
        bits.put(256, 9);
        let src = block(&all_nine(), bits);
        assert!(matches!(decode(&src, 2), Err(Error::Xpress)));
    }

    /// Lengths that leave the prefixes short of 2^15, or past it, are not a
    /// canonical Huffman code: [MS-XCA] §2.2.4 makes each an error.
    #[test]
    fn a_table_that_is_not_a_canonical_code_is_refused() {
        let mut bits = Writer::new();
        bits.put(0, 9);
        // Every symbol unused: nothing fills the prefixes.
        let src = block(&[0u8; SYMBOLS], Writer::new());
        assert!(matches!(decode(&src, 1), Err(Error::Xpress)));
        // Every symbol one bit: two codes' worth of room for 512 symbols.
        let src = block(&[1u8; SYMBOLS], bits);
        assert!(matches!(decode(&src, 1), Err(Error::Xpress)));
    }

    #[test]
    fn bits_that_run_out_before_the_chunk_is_whole_are_refused() {
        let mut bits = Writer::new();
        bits.put(u32::from(b'a'), 9);
        let mut src = block(&all_nine(), bits);
        src.truncate(TABLE + 2);
        assert!(matches!(decode(&src, 100), Err(Error::Xpress)));
    }

    /// A block holds 65536 bytes, so a chunk longer than one is refused
    /// rather than read as though the table at its start covered it all.
    #[test]
    fn a_chunk_longer_than_a_block_is_refused() {
        let src = block(&all_nine(), Writer::new());
        assert!(matches!(decode(&src, BLOCK + 1), Err(Error::Xpress)));
    }

    #[test]
    fn a_chunk_with_no_table_is_refused() {
        assert!(matches!(decode(&[0u8; 10], 1), Err(Error::Xpress)));
    }
}
