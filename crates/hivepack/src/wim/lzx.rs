//! LZX, which is what a Windows disc's `install.wim` is compressed with.
//!
//! Microsoft's *[MS-PATCH]: LZX DELTA Compression and Decompression* is the
//! specification, published under its Open Specification Promise, and its
//! §2.7 gives the decoding of a match or a literal as pseudocode. It was
//! read from Microsoft's own Open Specifications pages, where each section
//! carries the date it was last revised; the newest of the ones that
//! matter here is §2.6.3, revised 2025-05-20, which is also the one the
//! specification contradicts itself in. LZXD is
//! LZX with delta compression added: a WIM gives the decoder no reference
//! data, so §2.1.3 never arises and what is left is LZX itself. Nothing
//! here is a port: wimlib's decompressor is GPL-3.0-or-later and was not
//! read — it is built by `scripts/testdata.py` and run as a program to
//! write the archives the tests read back.
//!
//! The shape of it. A chunk holds one or more **blocks**, each with its own
//! Huffman trees, and a block holds literals and matches. The **main tree**
//! has 256 symbols for the literal bytes and eight more for each position
//! slot (§2.4); a match's symbol says both how long the match is, through a
//! length header of [0, 7], and roughly how far back it reaches, through a
//! position slot whose **base position** and **footer bits** (§2.6.2) the
//! window decides. The **length tree** holds the rest of a length over
//! eight, the **aligned offset tree** the low three bits of an offset in an
//! aligned offset block, and a **pretree** the path lengths of the others,
//! which are written as the difference from the lengths of the block before
//! (§2.5). Three **repeated offsets** stand for the offsets of the last
//! three matches (§2.1.4).
//!
//! **A WIM does four things the specification does not**, and no
//! specification of the WIM variant is published, so these were measured
//! against archives `wimlib-imagex` wrote, the same way `chunks` measured
//! the table of chunks:
//!
//! 1. There is **no 16-bit chunk-size prefix** (§2.2.1). A WIM's own table
//!    of chunks already says how long each is.
//! 2. There is **no E8 header bit** (§2.2.2), and yet x86 call
//!    translation is always on. The stream begins at the block type, so
//!    nothing in it says whether the calls were rewritten; every chunk is
//!    undone with an `E8_file_size` of **12000000** and a `chunk_offset`
//!    of **zero**, since a chunk is translated on its own as it is
//!    compressed on its own. Measured against a file of nothing but `E8`
//!    calls over three chunks, with displacements on each side of every
//!    edge of the rule — 0, 1, 1000, 11999999, 12000000, -1, -2^31 — of
//!    which that one reading gives back all 70000 bytes and no other
//!    reading gives even 95% of them: a cumulative `chunk_offset` misses
//!    3892 bytes and a file size of 10000000 misses 6938. A **stored**
//!    chunk is not translated — its bytes are the file's own — which a
//!    resource whose first chunk compresses and whose second does not
//!    says.
//! 3. There is **no Extra Length field** (§2.6.6). That field is LZXD's
//!    own, for the matches of up to 32768 bytes §2.1.5 gives; a WIM's LZX
//!    is the older format, whose longest match is the 257 the length tree
//!    reaches. Reading the field where it is not there is what a WIM shows
//!    plainest: a match of 257 bytes is taken as one of 427, which over
//!    text that repeats every 44 bytes still copies the right bytes, and
//!    the nine bits it swallows only come out as rubbish a line later.
//! 4. The **Block Size field is not 24 bits** (§2.3.1.2). One bit after the
//!    block type says the block holds 32768 bytes; where it does not, a
//!    field follows that is 16 bits for a window of 32768 or less and 24
//!    bits for a larger one. What was measured, in archives of chunk 32768
//!    and of chunk 65536:
//!
//! ```text
//! chunk 32768, block 32768:  001 1              verbatim, 32768
//! chunk 32768, block  4896:  001 0 0x1320       verbatim, 4896    (16 bits)
//! chunk 32768, block 17600:  001 0 0x44c0       verbatim, 17600   (16 bits)
//! chunk 65536, block 65536:  001 0 0x010000     verbatim, 65536   (24 bits)
//! chunk 65536, block 37664:  001 0 0x009320     verbatim, 37664   (24 bits)
//! chunk 32768, block   624:  010 0 0x0270       aligned offset, 624
//! ```
//!
//! The window is the chunk, since a WIM compresses every chunk on its own:
//! the trees start empty, the repeated offsets at (1, 1, 1), and no match
//! reaches before the chunk's first byte.
//!
//! One more thing is decided here rather than copied, because **the
//! specification disagrees with itself**: for a position slot of exactly
//! three footer bits, §2.6.3 splits the low three bits off into the
//! aligned offset tree and §2.7's pseudocode does not. Archives are
//! written §2.6.3's way, which is what `tokens` follows and says. And one
//! rule has no archive to be held to at all: nothing writes an
//! **uncompressed block** into a WIM, a chunk that does not compress
//! being stored as it is, so §2.3.2.1 is implemented as it is worded and
//! checked only against streams written here.

use super::error::Error;

/// A path length is [0, 16] (§2.5), so no code is longer than 16 bits.
const MOST_BITS: u32 = 16;

/// How many symbols of the main tree are the literal bytes (§2.4).
const LITERALS: usize = 256;

/// The alphabets of the other trees (§2.4).
const PRETREE_SYMBOLS: usize = 20;
const ALIGNED_SYMBOLS: usize = 8;
const LENGTH_SYMBOLS: usize = 249;

/// How many main tree symbols one position slot has: one for each length
/// header (§2.6.5).
const PER_SLOT: usize = 8;

/// The shortest match (§2.1.5), which a length header is counted from.
const MIN_MATCH: usize = 2;

/// The footer bits one slot has at most (§2.6.2: slot 38 and every slot
/// after it).
const MOST_FOOTER: usize = 17;

/// How long a block is where the bit after its type says so — measured;
/// see the notes above.
const FULL_BLOCK: usize = 32768;

/// The windows this reads: 2^15 is what a WIM's chunks are, and 2^25 is
/// the largest LZX has (§2.1.2).
const LEAST_WINDOW: u64 = 1 << 15;
const MOST_WINDOW: u64 = 1 << 25;

/// The file size x86 call translation is undone with — measured; see the
/// notes above. It is not the length of anything: §2.2.2 says as much,
/// that "E8_file_size is completely independent of the length of the
/// uncompressed data".
const E8_FILE_SIZE: i32 = 12_000_000;

/// The three block types that are valid (§2.3.1.1).
const VERBATIM: u32 = 1;
const ALIGNED_OFFSET: u32 = 2;
const UNCOMPRESSED: u32 = 3;

/// A canonical Huffman tree, held as the path lengths it was read as and
/// the two tables that decode them: how many codes there are of each
/// length, and the symbols in the order the codes run.
///
/// The lengths are kept because the next block's are written as the
/// difference from these (§2.5).
struct Tree {
    lengths: Vec<u8>,
    /// How many codes are of each length, `counts[0]` unused.
    counts: [u16; MOST_BITS as usize + 1],
    /// Every symbol that has a code, by length and then by symbol, which
    /// is the order §2.4 says the codes are given out in.
    sorted: Vec<u16>,
}

impl Tree {
    fn new(symbols: usize) -> Tree {
        Tree {
            lengths: vec![0; symbols],
            counts: [0; MOST_BITS as usize + 1],
            sorted: vec![0; symbols],
        }
    }

    /// The codes of the lengths now held.
    ///
    /// A tree is either empty — every length zero, which is a block that
    /// uses none of its symbols — or **complete**: §2.4 says a non-empty
    /// tree holds at least two codes and that the codes are canonical, so
    /// a code that leaves a prefix unused is not one this reads.
    fn rebuild(&mut self) -> Result<(), Error> {
        self.counts = [0; MOST_BITS as usize + 1];
        for &length in &self.lengths {
            if u32::from(length) > MOST_BITS {
                return Err(Error::Lzx);
            }
            if length > 0 {
                self.counts[usize::from(length)] += 1;
            }
        }
        let mut left = 1i32;
        for length in 1..=MOST_BITS as usize {
            left <<= 1;
            left -= i32::from(self.counts[length]);
            if left < 0 {
                // More codes of this length than the lengths above it
                // leave room for.
                return Err(Error::Lzx);
            }
        }
        let held: u32 = self.counts.iter().map(|&n| u32::from(n)).sum();
        if held != 0 && left != 0 {
            return Err(Error::Lzx);
        }
        let mut at = [0usize; MOST_BITS as usize + 2];
        for length in 1..=MOST_BITS as usize {
            at[length + 1] = at[length] + usize::from(self.counts[length]);
        }
        for (symbol, &length) in self.lengths.iter().enumerate() {
            if length > 0 {
                let into = &mut at[usize::from(length)];
                self.sorted[*into] = symbol as u16;
                *into += 1;
            }
        }
        Ok(())
    }

    /// The symbol the next bits are the code of.
    ///
    /// The codes are canonical, so they can be walked a bit at a time: at
    /// each length, the codes of that length are the next `counts[length]`
    /// values, and the symbol is however far into them this code is. An
    /// empty tree decodes nothing, which is what reaching a symbol a block
    /// never uses means.
    fn decode(&self, bits: &mut Bits) -> Result<usize, Error> {
        let mut code = 0u32;
        let mut first = 0u32;
        let mut index = 0usize;
        for length in 1..=MOST_BITS as usize {
            code |= bits.take(1)?;
            let count = u32::from(self.counts[length]);
            if code - first < count {
                let at = index + (code - first) as usize;
                return Ok(usize::from(*self.sorted.get(at).ok_or(Error::Lzx)?));
            }
            index += count as usize;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(Error::Lzx)
    }
}

/// The bits of a chunk, read as §2.1.1 writes them: little-endian 16-bit
/// words, the bits of each taken from the most significant down.
///
/// An uncompressed block leaves the bits for the bytes themselves
/// (§2.3.2.1), which is why this says where it has got to.
struct Bits<'a> {
    src: &'a [u8],
    /// The byte the next word will be read from.
    at: usize,
    /// The bits, the next one at the top.
    window: u64,
    /// How many bits of `window` are there to be read.
    held: u32,
}

impl<'a> Bits<'a> {
    fn new(src: &'a [u8], at: usize) -> Bits<'a> {
        Bits {
            src,
            at,
            window: 0,
            held: 0,
        }
    }

    /// At least `need` bits held, a word at a time.
    fn fill(&mut self, need: u32) -> Result<(), Error> {
        while self.held < need {
            let end = self.at.checked_add(2).ok_or(Error::Lzx)?;
            let word = self.src.get(self.at..end).ok_or(Error::Lzx)?;
            let word = u16::from_le_bytes([word[0], word[1]]);
            self.window |= u64::from(word) << (48 - self.held);
            self.held += 16;
            self.at = end;
        }
        Ok(())
    }

    /// The next `take` bits, gone from the window. No bits is no value:
    /// a slot with no footer bits reads none (§2.6.2).
    fn take(&mut self, take: u32) -> Result<u32, Error> {
        if take == 0 {
            return Ok(0);
        }
        debug_assert!(take <= 24);
        self.fill(take)?;
        let value = (self.window >> (64 - take)) as u32;
        self.window <<= take;
        self.held -= take;
        Ok(value)
    }

    /// The bits run on to the next word boundary, and the byte the bytes
    /// of an uncompressed block then begin at.
    ///
    /// §2.3.2.1 says the padding is "1 to 16 bits", so a stream that is
    /// already on a boundary still has a whole word of it. Nothing writes
    /// an uncompressed block into a WIM — a chunk that does not compress
    /// is stored as it is, which `chunks` reads — so this one rule has no
    /// archive to be held to, and it is the specification's words that are
    /// followed.
    fn align(&mut self) -> Result<usize, Error> {
        let spare = self.held % 16;
        self.take(if spare == 0 { 16 } else { spare })?;
        Ok(self.at - (self.held / 8) as usize)
    }
}

/// The base position and footer bits of every slot a window of `window`
/// has (§2.1.6, §2.6.2).
///
/// The specification gives these as a table of 290 rows. This is the rule
/// the table follows: three slots for the repeated offsets and one for the
/// closest offset, then two slots for each further footer bit up to 17,
/// each slot covering `1 << footer` offsets from the one before. The table
/// ends where the base position reaches the window, which for every window
/// LZX has is the slot count §2.1.6 gives — 30 slots for the 32768 a WIM's
/// chunks are, 34 for 2^17, 290 for 2^25.
fn slots(window: u64) -> Option<(Vec<u32>, Vec<u8>)> {
    let mut base = Vec::new();
    let mut footer = Vec::new();
    let mut at = 0u64;
    while at < window {
        let bits = (base.len() / 2).saturating_sub(1).min(MOST_FOOTER);
        base.push(u32::try_from(at).ok()?);
        footer.push(bits as u8);
        at += 1 << bits;
    }
    // A window that the slots do not reach exactly is not one LZX has.
    (at == window).then_some((base, footer))
}

/// Everything a resource's chunks are decompressed with, built once for
/// the resource: the slot tables the window decides, and the trees, whose
/// path lengths a block gives as the difference from the block before.
pub(crate) struct Decoder {
    window: u64,
    /// How wide the Block Size field is — measured; see the notes above.
    size_bits: u32,
    base: Vec<u32>,
    footer: Vec<u8>,
    main: Tree,
    length: Tree,
    aligned: Tree,
    pretree: Tree,
}

impl Decoder {
    /// A decoder for a resource whose chunks hold `chunk` bytes, which is
    /// the window as well, since every chunk is compressed on its own.
    ///
    /// A chunk size that is not a window LZX has is refused as what it is:
    /// a header saying a layout it cannot have.
    pub(crate) fn new(chunk: u64) -> Result<Decoder, Error> {
        if !(LEAST_WINDOW..=MOST_WINDOW).contains(&chunk) {
            return Err(Error::Says);
        }
        let (base, footer) = slots(chunk).ok_or(Error::Says)?;
        let main = LITERALS + PER_SLOT * base.len();
        Ok(Decoder {
            window: chunk,
            size_bits: if chunk > FULL_BLOCK as u64 { 24 } else { 16 },
            base,
            footer,
            main: Tree::new(main),
            length: Tree::new(LENGTH_SYMBOLS),
            aligned: Tree::new(ALIGNED_SYMBOLS),
            pretree: Tree::new(PRETREE_SYMBOLS),
        })
    }

    /// `src` decompressed into `out`, which is as long as the chunk holds.
    ///
    /// `out` is filled whole or this fails: a chunk says how long it is,
    /// and blocks that stop short of it are a chunk that was cut off.
    pub(crate) fn decompress(&mut self, src: &[u8], out: &mut [u8]) -> Result<(), Error> {
        if out.len() as u64 > self.window {
            return Err(Error::Lzx);
        }
        // A chunk of its own: trees with no lengths yet, so that the first
        // block's are the difference from nothing (§2.5), and the repeated
        // offsets as §2.1.4 starts them.
        self.main.lengths.fill(0);
        self.length.lengths.fill(0);
        let mut recent = [1usize; 3];
        let mut bits = Bits::new(src, 0);
        let mut written = 0usize;
        while written < out.len() {
            let kind = bits.take(3)?;
            let size = if bits.take(1)? == 1 {
                FULL_BLOCK
            } else {
                bits.take(self.size_bits)? as usize
            };
            // §2.6: a block is read until exactly as many bytes as its
            // header says are out, so one that reaches past the chunk, or
            // holds nothing at all, is not a block.
            if size == 0 || size > out.len() - written {
                return Err(Error::Lzx);
            }
            let end = written + size;
            if kind == UNCOMPRESSED {
                bits = uncompressed(bits, src, &mut recent, &mut out[written..end])?;
                written = end;
                continue;
            }
            if kind != VERBATIM && kind != ALIGNED_OFFSET {
                return Err(Error::Lzx);
            }
            if kind == ALIGNED_OFFSET {
                // Eight elements of three bits, before the other trees
                // (§2.3.2.3).
                for symbol in 0..ALIGNED_SYMBOLS {
                    self.aligned.lengths[symbol] = bits.take(3)? as u8;
                }
                self.aligned.rebuild()?;
            }
            // The main tree is written as two trees, the literals and then
            // the matches, each with its own pretree (§2.5).
            let matches = self.main.lengths.len();
            lengths(
                &mut bits,
                &mut self.pretree,
                &mut self.main.lengths,
                0,
                LITERALS,
            )?;
            lengths(
                &mut bits,
                &mut self.pretree,
                &mut self.main.lengths,
                LITERALS,
                matches,
            )?;
            self.main.rebuild()?;
            lengths(
                &mut bits,
                &mut self.pretree,
                &mut self.length.lengths,
                0,
                LENGTH_SYMBOLS,
            )?;
            self.length.rebuild()?;
            self.tokens(&mut bits, kind, &mut recent, out, &mut written, end)?;
        }
        untranslate(out);
        Ok(())
    }

    /// The literals and matches of one block, until `end` bytes are out
    /// (§2.7).
    fn tokens(
        &self,
        bits: &mut Bits,
        kind: u32,
        recent: &mut [usize; 3],
        out: &mut [u8],
        written: &mut usize,
        end: usize,
    ) -> Result<(), Error> {
        while *written < end {
            let symbol = self.main.decode(bits)?;
            if symbol < LITERALS {
                out[*written] = symbol as u8;
                *written += 1;
                continue;
            }
            let more = symbol - LITERALS;
            // The symbol holds the length header in its low three bits and
            // the position slot above them (§2.6.5).
            let header = more & 7;
            let length = if header == 7 {
                // The rest of the length is the length tree's (§2.6.4),
                // and that tree's 249 symbols reach 257, which is as long
                // as a match in a WIM gets: there is no Extra Length
                // field (§2.6.6) — measured; see the notes above.
                self.length.decode(bits)? + 7 + MIN_MATCH
            } else {
                header + MIN_MATCH
            };
            let slot = more >> 3;
            let offset = if slot < 3 {
                // A repeated offset: slot 0 is the most recent, and the
                // other two swap with it (§2.1.4, §2.7).
                if slot != 0 {
                    recent.swap(0, slot);
                }
                recent[0]
            } else {
                let footer = u32::from(*self.footer.get(slot).ok_or(Error::Lzx)?);
                let value = if kind == ALIGNED_OFFSET && footer >= 3 {
                    // The low three bits are the aligned offset tree's and
                    // the rest are read as they are. **§2.6.3 and §2.7
                    // disagree** about a slot of exactly three footer
                    // bits: §2.6.3 splits off aligned bits for every
                    // offset over 15, which is every slot from three
                    // footer bits up, while §2.7's pseudocode asks for
                    // more than three. Archives are written the first
                    // way, so that is what is read — an aligned offset
                    // block whose offsets are 16 to 31 comes out as
                    // rubbish the other way round.
                    let verbatim = bits.take(footer - 3)? << 3;
                    verbatim + self.aligned.decode(bits)? as u32
                } else {
                    bits.take(footer)?
                };
                let formatted = self.base[slot] as u64 + u64::from(value);
                // The offset is the formatted offset less the two the
                // repeated offset codes stand in for (§2.6.1, §2.7).
                let offset =
                    usize::try_from(formatted.saturating_sub(2)).map_err(|_| Error::Lzx)?;
                recent[2] = recent[1];
                recent[1] = recent[0];
                recent[0] = offset;
                offset
            };
            if length > end - *written {
                // A match reaching past the block, which is read until
                // exactly as long as it says (§2.6).
                return Err(Error::Lzx);
            }
            if offset == 0 || offset > *written {
                // Of bytes before the chunk, which a chunk cannot reach:
                // each one is compressed on its own.
                return Err(Error::Lzx);
            }
            // A byte at a time: a match may be longer than its offset, so
            // the bytes it copies can be ones it has just written
            // (§2.1.5).
            for _ in 0..length {
                out[*written] = out[*written - offset];
                *written += 1;
            }
        }
        Ok(())
    }
}

/// The x86 call translation of one chunk undone (§2.2.2).
///
/// An `E8` byte begins a call whose four bytes of relative displacement
/// were rewritten as the absolute target, which compresses better where
/// the same function is called from many places. Undoing it is the same
/// scan: every `E8` in all but the last ten bytes, and the four bytes
/// after it read as a target that is in range.
fn untranslate(chunk: &mut [u8]) {
    if chunk.len() <= 10 {
        // Too short to hold a call and its displacement, so §2.2.2 leaves
        // it alone.
        return;
    }
    let mut at = 0usize;
    while at < chunk.len() - 10 {
        if chunk[at] == 0xE8 {
            let four = [chunk[at + 1], chunk[at + 2], chunk[at + 3], chunk[at + 4]];
            let value = i32::from_le_bytes(four);
            // The byte's own place in the chunk, which is where the
            // target was counted from.
            let current = at as i32;
            if value >= -current && value < E8_FILE_SIZE {
                let displacement = if value >= 0 {
                    value - current
                } else {
                    value + E8_FILE_SIZE
                };
                chunk[at + 1..at + 5].copy_from_slice(&displacement.to_le_bytes());
            }
            // The displacement is not a call of its own.
            at += 4;
        }
        at += 1;
    }
}

/// One uncompressed block's repeated offsets and bytes, and the bits of
/// whatever follows it (§2.3.2.1).
fn uncompressed<'a>(
    mut bits: Bits<'a>,
    src: &'a [u8],
    recent: &mut [usize; 3],
    into: &mut [u8],
) -> Result<Bits<'a>, Error> {
    let at = bits.align()?;
    // Three 32-bit repeated offsets and then the bytes themselves, in the
    // bytes of the file rather than in the bits.
    let held = 3 * 4 + into.len();
    let raw = src
        .get(at..)
        .filter(|raw| raw.len() >= held)
        .ok_or(Error::Lzx)?;
    for (slot, at) in recent.iter_mut().zip([0, 4, 8]) {
        *slot = u32::from_le_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]]) as usize;
    }
    into.copy_from_slice(&raw[12..held]);
    // One byte of padding where the block holds an odd number, so that the
    // bits begin on a word boundary again.
    let next = at + held + (into.len() & 1);
    Ok(Bits::new(src, next))
}

/// The path lengths of `lengths[from..to]`, each the difference from the
/// length that element had in the block before, through a pretree of 20
/// elements of four bits (§2.5).
fn lengths(
    bits: &mut Bits,
    pretree: &mut Tree,
    lengths: &mut [u8],
    from: usize,
    to: usize,
) -> Result<(), Error> {
    for symbol in 0..PRETREE_SYMBOLS {
        pretree.lengths[symbol] = bits.take(4)? as u8;
    }
    pretree.rebuild()?;
    let mut at = from;
    while at < to {
        let code = pretree.decode(bits)?;
        match code {
            // The next few elements are not in the tree at all.
            17 => {
                let end = ends(at, 4 + bits.take(4)? as usize, to)?;
                lengths[at..end].fill(0);
                at = end;
            }
            18 => {
                let end = ends(at, 20 + bits.take(5)? as usize, to)?;
                lengths[at..end].fill(0);
                at = end;
            }
            // The next few all have the same length, which the code after
            // this one says.
            19 => {
                let end = ends(at, 4 + bits.take(1)? as usize, to)?;
                let code = pretree.decode(bits)?;
                if code > 16 {
                    return Err(Error::Lzx);
                }
                let value = difference(lengths[at], code);
                lengths[at..end].fill(value);
                at = end;
            }
            0..=16 => {
                lengths[at] = difference(lengths[at], code);
                at += 1;
            }
            _ => return Err(Error::Lzx),
        }
    }
    Ok(())
}

/// Where a run of path lengths ends, which must be inside what is being
/// read: a run reaching past it is a tree that is not this tree's.
fn ends(at: usize, run: usize, to: usize) -> Result<usize, Error> {
    at.checked_add(run)
        .filter(|&end| end <= to)
        .ok_or(Error::Lzx)
}

/// The path length a code stands for, which is the difference from the
/// length that element had before: `(prev - code + 17) mod 17` (§2.5).
fn difference(prev: u8, code: usize) -> u8 {
    ((usize::from(prev) + 17 - code) % 17) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stream written the way §2.1.1 says one is read: the bits most
    /// significant first, in little-endian 16-bit words.
    struct Writing {
        bytes: Vec<u8>,
        word: u32,
        held: u32,
    }

    impl Writing {
        fn new() -> Writing {
            Writing {
                bytes: Vec::new(),
                word: 0,
                held: 0,
            }
        }

        fn bits(&mut self, value: u32, count: u32) -> &mut Writing {
            for at in (0..count).rev() {
                self.word = (self.word << 1) | ((value >> at) & 1);
                self.held += 1;
                if self.held == 16 {
                    self.bytes
                        .extend_from_slice(&(self.word as u16).to_le_bytes());
                    self.word = 0;
                    self.held = 0;
                }
            }
            self
        }

        /// The padding an uncompressed block begins with: enough zero bits
        /// to reach the next word, and a whole word of them where the bits
        /// are already on one (§2.3.2.1).
        fn pad(&mut self) -> &mut Writing {
            self.bits(0, 16 - self.held)
        }

        fn raw(&mut self, bytes: &[u8]) -> &mut Writing {
            assert_eq!(self.held, 0, "bytes begin on a word");
            self.bytes.extend_from_slice(bytes);
            self
        }

        fn done(&self) -> Vec<u8> {
            let mut bytes = self.bytes.clone();
            if self.held > 0 {
                let word = (self.word << (16 - self.held)) as u16;
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            bytes
        }
    }

    /// The four pretree codes these tests write path lengths with: a
    /// length of zero, a length of one, and the two runs of zeros. Four
    /// codes of two bits are a complete code, and the first tree of a
    /// chunk is written as the difference from nothing, so the code for a
    /// length of one is 16: `(0 - 16 + 17) mod 17` (§2.5).
    const ZERO: u32 = 0b00;
    const ONE: u32 = 0b01;
    const SHORT_RUN: u32 = 0b10;
    const LONG_RUN: u32 = 0b11;

    fn pretree(w: &mut Writing) {
        for code in 0..PRETREE_SYMBOLS {
            let length = u32::from(matches!(code, 0 | 16 | 17 | 18)) * 2;
            w.bits(length, 4);
        }
    }

    /// `n` path lengths of zero, in as few codes as the runs allow.
    fn zeros(w: &mut Writing, mut n: usize) {
        while n >= 20 {
            let run = n.min(51);
            w.bits(LONG_RUN, 2).bits((run - 20) as u32, 5);
            n -= run;
        }
        while n >= 4 {
            let run = n.min(19);
            w.bits(SHORT_RUN, 2).bits((run - 4) as u32, 4);
            n -= run;
        }
        for _ in 0..n {
            w.bits(ZERO, 2);
        }
    }

    /// One tree's path lengths: the symbols in `ones` have a code of one
    /// bit, and the rest have none.
    fn tree(w: &mut Writing, ones: &[usize], symbols: usize) {
        pretree(w);
        let mut at = 0;
        for &one in ones {
            zeros(w, one - at);
            w.bits(ONE, 2);
            at = one + 1;
        }
        zeros(w, symbols - at);
    }

    /// How many slots a window of 32768 has, which is what these build
    /// blocks for.
    const SLOTS: usize = 30;

    /// A block header and trees: the symbols in `main` have a code of one
    /// bit each, so two of them make a complete main tree, and the ones
    /// in `length` the same in the length tree. `aligned` is the eight
    /// path lengths of the aligned offset tree, which only an aligned
    /// offset block has.
    fn block(
        w: &mut Writing,
        kind: u32,
        size: usize,
        main: &[usize],
        length: &[usize],
        aligned: &[u8; ALIGNED_SYMBOLS],
    ) {
        w.bits(kind, 3);
        if size == FULL_BLOCK {
            w.bits(1, 1);
        } else {
            w.bits(0, 1).bits(size as u32, 16);
        }
        if kind == ALIGNED_OFFSET {
            for &length in aligned {
                w.bits(u32::from(length), 3);
            }
        }
        let mut main = main.to_vec();
        main.sort_unstable();
        let literals: Vec<usize> = main.iter().copied().filter(|&s| s < LITERALS).collect();
        let matches: Vec<usize> = main
            .iter()
            .filter(|&&s| s >= LITERALS)
            .map(|&s| s - LITERALS)
            .collect();
        tree(w, &literals, LITERALS);
        tree(w, &matches, PER_SLOT * SLOTS);
        tree(w, length, LENGTH_SYMBOLS);
    }

    /// No aligned offset tree, which is what a verbatim block has.
    const NONE: [u8; ALIGNED_SYMBOLS] = [0; ALIGNED_SYMBOLS];

    fn decoded(src: &[u8], size: usize) -> Result<Vec<u8>, Error> {
        let mut decoder = Decoder::new(FULL_BLOCK as u64)?;
        let mut out = vec![0u8; size];
        decoder.decompress(src, &mut out)?;
        Ok(out)
    }

    /// The main tree's symbol for a match of `length` bytes in `slot`
    /// (§2.6.5). A length over eight has a header of 7 and the rest in
    /// the length tree.
    fn match_symbol(slot: usize, length: usize) -> usize {
        LITERALS + slot * PER_SLOT + (length - MIN_MATCH).min(7)
    }

    #[test]
    fn literals_read_as_the_bytes_they_are() {
        let mut w = Writing::new();
        // A main tree of two symbols, so each is one bit: `a` is the
        // lower, so its code is 0 and `b`'s is 1.
        block(
            &mut w,
            VERBATIM,
            4,
            &[b'a' as usize, b'b' as usize],
            &[],
            &NONE,
        );
        w.bits(0, 1).bits(1, 1).bits(0, 1).bits(1, 1);
        assert_eq!(decoded(&w.done(), 4).unwrap(), b"abab");
    }

    #[test]
    fn a_match_copies_the_bytes_before_it() {
        // Offset 1 is formatted offset 3, which is slot 3 with no footer
        // bits (§2.6.2), so the symbol alone says the whole match.
        let symbol = match_symbol(3, 3);
        let mut w = Writing::new();
        block(&mut w, VERBATIM, 4, &[b'a' as usize, symbol], &[], &NONE);
        w.bits(0, 1).bits(1, 1);
        assert_eq!(decoded(&w.done(), 4).unwrap(), b"aaaa");
    }

    #[test]
    fn a_repeated_offset_is_the_offset_of_the_match_before() {
        // Slot 0 is the offset of the last match that was not itself a
        // repeated one (§2.1.4), which the match before makes 1. Two
        // blocks, because a chunk's first byte cannot be a match and a
        // tree of two match symbols has no literal to begin with.
        let first = match_symbol(3, 3);
        let again = match_symbol(0, 4);
        let mut w = Writing::new();
        block(
            &mut w,
            VERBATIM,
            1,
            &[b'a' as usize, b'b' as usize],
            &[],
            &NONE,
        );
        w.bits(0, 1);
        block(&mut w, VERBATIM, 7, &[first, again], &[], &NONE);
        // `again` is the lower symbol, so its code is 0 and `first`'s is
        // 1: a match of three at offset 1, then one of four at the offset
        // that one left behind.
        w.bits(1, 1).bits(0, 1);
        assert_eq!(decoded(&w.done(), 8).unwrap(), b"aaaaaaaa");
    }

    #[test]
    fn a_length_over_eight_comes_from_the_length_tree() {
        // A length header of 7 means the length tree holds the rest, and
        // its first symbol is a match of nine (§2.6.4).
        let symbol = match_symbol(3, 9);
        let mut w = Writing::new();
        block(
            &mut w,
            VERBATIM,
            10,
            &[b'a' as usize, symbol],
            &[0, 1],
            &NONE,
        );
        w.bits(0, 1).bits(1, 1).bits(0, 1);
        assert_eq!(decoded(&w.done(), 10).unwrap(), b"aaaaaaaaaa");
    }

    #[test]
    fn an_aligned_offset_block_takes_the_low_three_bits_from_its_tree() {
        // Slot 8 has three footer bits, which is where §2.6.3 and §2.7
        // disagree: the low three bits are the aligned offset tree's, as
        // §2.6.3 and every archive have it. The tree here is not eight
        // codes of three bits but one of one bit and two of two, so a
        // reader taking three bits as they are would take the wrong ones
        // and the bytes after would be rubbish.
        let symbol = match_symbol(8, 3);
        let aligned = [1, 2, 2, 0, 0, 0, 0, 0];
        let mut w = Writing::new();
        block(
            &mut w,
            ALIGNED_OFFSET,
            19,
            &[b'a' as usize, symbol],
            &[],
            &aligned,
        );
        for _ in 0..16 {
            w.bits(0, 1);
        }
        // The match, and then the aligned offset symbol 2, whose code is
        // `11`: formatted offset 16 + 2, so an offset of 16.
        w.bits(1, 1).bits(0b11, 2);
        assert_eq!(decoded(&w.done(), 19).unwrap(), b"a".repeat(19));
    }

    #[test]
    fn an_uncompressed_block_is_the_bytes_themselves() {
        let mut w = Writing::new();
        w.bits(UNCOMPRESSED, 3).bits(0, 1).bits(5, 16);
        w.pad().raw(&1u32.to_le_bytes()).raw(&1u32.to_le_bytes());
        w.raw(&1u32.to_le_bytes()).raw(b"hello").raw(&[0]);
        assert_eq!(decoded(&w.done(), 5).unwrap(), b"hello");
    }

    #[test]
    fn the_slots_are_the_ones_the_specification_tabulates() {
        let (base, footer) = slots(FULL_BLOCK as u64).unwrap();
        assert_eq!(base.len(), SLOTS);
        // Rows of §2.6.2's own table.
        assert_eq!(base[..10], [0, 1, 2, 3, 4, 6, 8, 12, 16, 24]);
        assert_eq!(footer[..10], [0, 0, 0, 0, 1, 1, 2, 2, 3, 3]);
        assert_eq!((base[29], footer[29]), (24576, 13));
        // And the slot counts §2.1.6 gives for the larger windows.
        for (window, many) in [
            (1 << 16, 32),
            (1 << 17, 34),
            (1 << 18, 36),
            (1 << 19, 38),
            (1 << 20, 42),
            (1 << 21, 50),
            (1 << 22, 66),
            (1 << 23, 98),
            (1 << 24, 162),
            (1 << 25, 290),
        ] {
            assert_eq!(slots(window).unwrap().0.len(), many, "{window}");
        }
    }

    #[test]
    fn x86_calls_are_untranslated_as_the_specification_says() {
        let mut chunk = Vec::new();
        // A call whose target is where it is plus 256, which is in range
        // and so was translated.
        chunk.extend_from_slice(&[0xE8]);
        chunk.extend_from_slice(&256i32.to_le_bytes());
        // A call whose value is past the file size, which was not.
        chunk.extend_from_slice(&[0xE8]);
        chunk.extend_from_slice(&E8_FILE_SIZE.to_le_bytes());
        // A call whose value is negative, which stands for a target
        // beyond the file size.
        chunk.extend_from_slice(&[0xE8]);
        chunk.extend_from_slice(&(-1i32).to_le_bytes());
        // And a call in the last ten bytes, which the scan does not reach.
        let tail = chunk.len();
        chunk.extend_from_slice(&[0u8; 6]);
        chunk.extend_from_slice(&[0xE8]);
        chunk.extend_from_slice(&256i32.to_le_bytes());

        let mut undone = chunk.clone();
        untranslate(&mut undone);
        assert_eq!(&undone[1..5], &256i32.to_le_bytes(), "at 0, so unchanged");
        assert_eq!(
            &undone[6..10],
            &E8_FILE_SIZE.to_le_bytes(),
            "not in range, so left alone"
        );
        assert_eq!(
            &undone[11..15],
            &(E8_FILE_SIZE - 1).to_le_bytes(),
            "negative, so the file size over"
        );
        assert_eq!(&undone[tail..], &chunk[tail..], "the last ten bytes");
    }

    #[test]
    fn a_tree_that_is_not_a_canonical_code_is_refused() {
        // Three codes of one bit, which no tree holds.
        let mut w = Writing::new();
        block(
            &mut w,
            VERBATIM,
            1,
            &[b'a' as usize, b'b' as usize, b'c' as usize],
            &[],
            &NONE,
        );
        w.bits(0, 1);
        assert!(matches!(decoded(&w.done(), 1), Err(Error::Lzx)));
        // And one code of one bit, which leaves half the codes unused.
        let mut w = Writing::new();
        block(&mut w, VERBATIM, 1, &[b'a' as usize], &[], &NONE);
        w.bits(0, 1);
        assert!(matches!(decoded(&w.done(), 1), Err(Error::Lzx)));
    }

    #[test]
    fn a_block_of_a_type_the_format_has_not_is_refused() {
        for kind in [0u32, 4, 5, 6, 7] {
            let mut w = Writing::new();
            w.bits(kind, 3).bits(0, 1).bits(4, 16);
            w.bits(0, 16);
            assert!(
                matches!(decoded(&w.done(), 4), Err(Error::Lzx)),
                "block type {kind}"
            );
        }
    }

    #[test]
    fn a_block_that_does_not_fit_the_chunk_is_refused() {
        // A block holding nothing, and one holding more than the chunk.
        for size in [0usize, 5] {
            let mut w = Writing::new();
            block(
                &mut w,
                VERBATIM,
                size,
                &[b'a' as usize, b'b' as usize],
                &[],
                &NONE,
            );
            w.bits(0, 16);
            assert!(
                matches!(decoded(&w.done(), 4), Err(Error::Lzx)),
                "a block of {size}"
            );
        }
    }

    #[test]
    fn a_match_reaching_before_the_chunk_is_refused() {
        // The first byte of a chunk cannot be a match: there is nothing
        // before it, each chunk being compressed on its own.
        let symbol = match_symbol(3, 3);
        let mut w = Writing::new();
        block(&mut w, VERBATIM, 4, &[b'a' as usize, symbol], &[], &NONE);
        w.bits(1, 1);
        assert!(matches!(decoded(&w.done(), 4), Err(Error::Lzx)));
    }

    #[test]
    fn a_match_reaching_past_its_block_is_refused() {
        // A match of nine where the block says four bytes.
        let symbol = match_symbol(3, 9);
        let mut w = Writing::new();
        block(
            &mut w,
            VERBATIM,
            4,
            &[b'a' as usize, symbol],
            &[0, 1],
            &NONE,
        );
        w.bits(0, 1).bits(1, 1).bits(0, 1);
        assert!(matches!(decoded(&w.done(), 4), Err(Error::Lzx)));
    }

    #[test]
    fn bits_that_run_out_are_refused() {
        let mut w = Writing::new();
        block(
            &mut w,
            VERBATIM,
            4,
            &[b'a' as usize, b'b' as usize],
            &[],
            &NONE,
        );
        w.bits(0, 1);
        let whole = w.done();
        for short in 0..whole.len() {
            let cut = &whole[..short];
            assert!(
                matches!(decoded(cut, 4), Err(Error::Lzx)),
                "{short} of {} bytes",
                whole.len()
            );
        }
    }

    #[test]
    fn a_chunk_longer_than_its_window_is_refused() {
        let mut decoder = Decoder::new(FULL_BLOCK as u64).unwrap();
        let mut out = vec![0u8; FULL_BLOCK + 1];
        assert!(matches!(
            decoder.decompress(&[0; 64], &mut out),
            Err(Error::Lzx)
        ));
    }

    #[test]
    fn a_chunk_size_that_is_not_a_window_is_refused() {
        for chunk in [0u64, 1, 1000, 16384, 32769, 100_000, (1 << 25) + 1, 1 << 26] {
            assert!(
                matches!(Decoder::new(chunk), Err(Error::Says)),
                "a chunk of {chunk}"
            );
        }
        for chunk in [1u64 << 15, 1 << 16, 1 << 20, 1 << 25] {
            assert!(Decoder::new(chunk).is_ok(), "a chunk of {chunk}");
        }
    }
}
