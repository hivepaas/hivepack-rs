//! LZO1X decompression: `lzokay.cpp`'s `decompress`, with the results of
//! liblzo2's `lzo1x_decompress_safe`.
//!
//! lzokay reads the format from its description in the Linux sources
//! (`Documentation/lzo.txt`); its comments, kept here, say what each
//! instruction is. Where lzokay checks less, or in another order, than
//! liblzo2's safe decoder, which SquashFS calls on each block, the port
//! checks as liblzo2 does, so that it fails where liblzo2 fails, with the
//! same error, and leaves the same bytes in the output: each such place is
//! marked `Differs from lzokay`.

use std::fmt;

/// Why a block did not decompress: the codes liblzo2's
/// `lzo1x_decompress_safe` returns, its `LZO_E_*` (`lzoconf.h`), and the
/// names of lzokay's `EResult`.
///
/// Differs from lzokay: its `EResult` numbers these -2, -3, -4 and 1
/// (`InputNotConsumed` is not an error there), and has an `Error`, -1,
/// for a stream that ends with another length than 3 or a length that
/// overflows. The port returns liblzo2's codes, which never include
/// `LZO_E_ERROR` for LZO1X.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Error {
    /// `LZO_E_INPUT_OVERRUN`: the input ends before the end-of-stream
    /// marker, or is too short for what an instruction says follows it.
    InputOverrun = -4,
    /// `LZO_E_OUTPUT_OVERRUN`: the output is too small for what the block
    /// decompresses to.
    OutputOverrun = -5,
    /// `LZO_E_LOOKBEHIND_OVERRUN`: a match refers to before the start of
    /// the output.
    LookbehindOverrun = -6,
    /// `LZO_E_INPUT_NOT_CONSUMED`: the block decompressed, but bytes follow
    /// its end-of-stream marker.
    InputNotConsumed = -8,
}

impl Error {
    /// The number liblzo2 gives this error, `LZO_E_INPUT_OVERRUN` (-4) and
    /// the others.
    pub fn number(self) -> i32 {
        self as i32
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InputOverrun => "LZO: the compressed data ends too soon",
            Error::OutputOverrun => "LZO: the data does not fit in the output",
            Error::LookbehindOverrun => "LZO: a match refers to before the start of the output",
            Error::InputNotConsumed => "LZO: more data follows the end of the compressed data",
        })
    }
}

impl std::error::Error for Error {}

/// `M2MaxOffset`: a 3-byte M1 match (after 4 literals or more) is this
/// much further back than a 2-byte one.
const M2_MAX_OFFSET: usize = 0x0800;
/// `M3Marker`, `M4Marker`: the bits that mark an M3 and an M4 match. An M2
/// match has one of the two bits above them.
const M3_MARKER: u8 = 0x20;
const M4_MARKER: u8 = 0x10;

/// Where a count of zero bytes, each standing for 255, stops: liblzo2's
/// `TEST_IV` and `TEST_OV`, which refuse a length past `(lzo_uint)0 - 511`.
///
/// Differs from lzokay: its `Max255Count` stops the count of bytes, not the
/// length, and returns `EResult::Error`; liblzo2 returns
/// `LZO_E_INPUT_OVERRUN` for a literal run and `LZO_E_OUTPUT_OVERRUN` for a
/// match. Only a 32-bit machine reaches it, after 16 MiB of zero bytes.
const MAX_LENGTH: usize = usize::MAX - 511;

/// Decompresses one LZO1X block, `input`, into `output`, and returns the
/// number of bytes written: `lzokay::decompress`, with the results of
/// liblzo2's `lzo1x_decompress_safe`.
///
/// The block must end with its end-of-stream marker, and nothing may
/// follow it. On an error, what was decompressed before it stays in
/// `output`, as liblzo2 leaves it; nothing past it is written.
pub fn decompress(input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    let in_end = input.len();
    let out_end = output.len();
    // liblzo2's `NEED_IP` and `NEED_OP`: at least `n` bytes left to read, or
    // to write.
    macro_rules! need_ip {
        ($ip:expr, $n:expr) => {
            if in_end - $ip < $n {
                return Err(Error::InputOverrun);
            }
        };
    }
    macro_rules! need_op {
        ($op:expr, $n:expr) => {
            if out_end - $op < $n {
                return Err(Error::OutputOverrun);
            }
        };
    }

    let mut ip = 0;
    let mut op = 0;
    // The literals the last instruction copied: 0 to 3, or 4 for a run of
    // 4 or more, which changes what the next M1 instruction means.
    let mut state = 0;

    // Differs from lzokay: it refuses an input of less than 3 bytes with
    // `InputOverrun`, before writing anything. liblzo2 asks for one byte
    // here, and for the rest where it reads it, so that an output too
    // small for the first literals is `OutputOverrun`.
    need_ip!(ip, 1);
    // First byte encoding.
    if input[0] >= 18 {
        // 22..255 : copy literal string
        //           length = (byte - 17) = 4..238
        //           state = 4 [ don't copy extra literals ]
        //           skip byte
        // 18..21 : copy 1..4 literals
        //          state = (byte - 17) = 1..4  [ copy <state> literals ]
        //          skip byte
        //
        // Differs from lzokay: one branch for both, as their checks and
        // copies are the same; lzokay's comment says 0..3 for the second,
        // where its code copies 1 to 4.
        let len = usize::from(input[0] - 17);
        ip = 1;
        // Differs from lzokay: liblzo2 checks the output first, and asks
        // for 3 bytes more input, the least the next instruction takes.
        need_op!(op, len);
        need_ip!(ip, len + 3);
        copy_literals(&mut output[op..op + len], &input[ip..ip + len]);
        ip += len;
        op += len;
        state = len.min(4);
    }
    // 0..17 : follow regular instruction encoding, see below. It is worth
    //         noting that codes 16 and 17 will represent a block copy from
    //         the dictionary which is empty, and that they will always be
    //         invalid at this place.

    loop {
        // Differs from lzokay: it asks for the one byte of the instruction.
        // liblzo2 asks for 3 where no literals came before (the least an
        // instruction takes with what must follow it), and for nothing
        // after literals, whose own check counted these 3 bytes.
        if state == 0 {
            need_ip!(ip, 3);
        }
        let inst = input[ip];
        ip += 1;
        // The match: how far back, how long, and the literals after it.
        let (distance, len, next_state);
        if inst & 0xc0 != 0 {
            // [M2]
            // 1 L L D D D S S  (128..255)
            //   Copy 5-8 bytes from block within 2kB distance
            //   state = S (copy S literals after this block)
            //   length = 5 + L
            // Always followed by exactly one byte : H H H H H H H H
            //   distance = (H << 3) + D + 1
            //
            // 0 1 L D D D S S  (64..127)
            //   Copy 3-4 bytes from block within 2kB distance
            //   state = S (copy S literals after this block)
            //   length = 3 + L
            // Always followed by exactly one byte : H H H H H H H H
            //   distance = (H << 3) + D + 1
            //
            // Differs from lzokay: no check for the byte, which the check
            // before the instruction counted, as liblzo2 does.
            distance = (usize::from(input[ip]) << 3) + usize::from((inst >> 2) & 0x7) + 1;
            ip += 1;
            len = usize::from(inst >> 5) + 1;
            next_state = usize::from(inst & 0x3);
        } else if inst & M3_MARKER != 0 {
            // [M3]
            // 0 0 1 L L L L L  (32..63)
            //   Copy of small block within 16kB distance (preferably less than 34B)
            //   length = 2 + (L ?: 31 + (zero_bytes * 255) + non_zero_byte)
            // Always followed by exactly one LE16 :  D D D D D D D D : D D D D D D S S
            //   distance = D + 1
            //   state = S (copy S literals after this block)
            len = match usize::from(inst & 0x1f) {
                0 => {
                    let zeros = zero_byte_length(input, &mut ip, Error::OutputOverrun)?;
                    let len = zeros + 31 + usize::from(input[ip]);
                    ip += 1;
                    need_ip!(ip, 2);
                    len
                }
                l => l,
            } + 2;
            // Differs from lzokay: no check for the two bytes when the
            // length is in the instruction, as above.
            let le16 = usize::from(u16::from_le_bytes([input[ip], input[ip + 1]]));
            ip += 2;
            distance = (le16 >> 2) + 1;
            next_state = le16 & 0x3;
        } else if inst & M4_MARKER != 0 {
            // [M4]
            // 0 0 0 1 H L L L  (16..31)
            //   Copy of a block within 16..48kB distance (preferably less than 10B)
            //   length = 2 + (L ?: 7 + (zero_bytes * 255) + non_zero_byte)
            // Always followed by exactly one LE16 :  D D D D D D D D : D D D D D D S S
            //   distance = 16384 + (H << 14) + D
            //   state = S (copy S literals after this block)
            //   End of stream is reached if distance == 16384
            len = match usize::from(inst & 0x7) {
                0 => {
                    let zeros = zero_byte_length(input, &mut ip, Error::OutputOverrun)?;
                    let len = zeros + 7 + usize::from(input[ip]);
                    ip += 1;
                    need_ip!(ip, 2);
                    len
                }
                l => l,
            } + 2;
            let le16 = usize::from(u16::from_le_bytes([input[ip], input[ip + 1]]));
            ip += 2;
            let far = (usize::from(inst & 0x8) << 11) + (le16 >> 2);
            if far == 0 {
                // Stream finished.
                //
                // Differs from lzokay: it fails with `EResult::Error`
                // unless the marker's length is 3, as liblzo2's compressors
                // write it; liblzo2 takes any length.
                return if ip == in_end {
                    Ok(op)
                } else {
                    Err(Error::InputNotConsumed)
                };
            }
            distance = far + 16384;
            next_state = le16 & 0x3;
        } else if state == 0 {
            // [M1] Depends on the number of literals copied by the last
            // instruction. If last instruction did not copy any literal
            // (state == 0), this encoding will be a copy of 4 or more
            // literal, and must be interpreted like this :
            //
            //    0 0 0 0 L L L L  (0..15)  : copy long literal string
            //    length = 3 + (L ?: 15 + (zero_bytes * 255) + non_zero_byte)
            //    state = 4  (no extra literals are copied)
            let len = match usize::from(inst) {
                0 => {
                    let zeros = zero_byte_length(input, &mut ip, Error::InputOverrun)?;
                    let len = zeros + 15 + usize::from(input[ip]);
                    ip += 1;
                    len
                }
                l => l,
            } + 3;
            // copy_literal_run
            //
            // Differs from lzokay: liblzo2 checks the output first, and
            // asks for 3 bytes more input, as for the first literals.
            need_op!(op, len);
            need_ip!(ip, len + 3);
            copy_literals(&mut output[op..op + len], &input[ip..ip + len]);
            ip += len;
            op += len;
            state = 4;
            continue;
        } else if state != 4 {
            // If last instruction used to copy between 1 to 3 literals
            // (encoded in the instruction's opcode or distance), the
            // instruction is a copy of a 2-byte block from the dictionary
            // within a 1kB distance. It is worth noting that this
            // instruction provides little savings since it uses 2 bytes to
            // encode a copy of 2 other bytes but it encodes the number of
            // following literals for free. It must be interpreted like
            // this :
            //
            //    0 0 0 0 D D S S  (0..15)  : copy 2 bytes from <= 1kB distance
            //    length = 2
            //    state = S (copy S literals after this block)
            //  Always followed by exactly one byte : H H H H H H H H
            //    distance = (H << 2) + D + 1
            distance = usize::from(inst >> 2) + (usize::from(input[ip]) << 2) + 1;
            ip += 1;
            len = 2;
            next_state = usize::from(inst & 0x3);
        } else {
            // If last instruction used to copy 4 or more literals (as
            // detected by state == 4), the instruction becomes a copy of a
            // 3-byte block from the dictionary from a 2..3kB distance, and
            // must be interpreted like this :
            //
            //    0 0 0 0 D D S S  (0..15)  : copy 3 bytes from 2..3 kB distance
            //    length = 3
            //    state = S (copy S literals after this block)
            //  Always followed by exactly one byte : H H H H H H H H
            //    distance = (H << 2) + D + 2049
            distance = usize::from(inst >> 2) + (usize::from(input[ip]) << 2) + M2_MAX_OFFSET + 1;
            ip += 1;
            len = 3;
            next_state = usize::from(inst & 0x3);
        }
        if distance > op {
            return Err(Error::LookbehindOverrun);
        }
        // Differs from lzokay: it checks the input for the literals after
        // the match, and the output for both, before copying the match.
        // liblzo2 copies the match first, then checks for the literals:
        // which error comes, and what is left in the output, follow it.
        need_op!(op, len);
        // Copy lookbehind.
        copy_match(output, op, distance, len);
        op += len;
        state = next_state;
        if next_state != 0 {
            // Copy literal.
            need_op!(op, next_state);
            need_ip!(ip, next_state + 3);
            copy_literals(
                &mut output[op..op + next_state],
                &input[ip..ip + next_state],
            );
            ip += next_state;
            op += next_state;
        }
    }
}

/// `CONSUME_ZERO_BYTE_LENGTH`: the zero bytes at `ip` skipped, and what
/// they stand for, 255 each. The first is within the input, and the byte
/// after the last is too, or `ip` is at the end and the error is
/// `InputOverrun`.
///
/// Differs from lzokay: it reads on past the end of the input while the
/// bytes there are zero; liblzo2 checks for a byte after each one. Past
/// [`MAX_LENGTH`], liblzo2 fails with `too_long`.
#[inline(always)]
fn zero_byte_length(input: &[u8], ip: &mut usize, too_long: Error) -> Result<usize, Error> {
    let mut length = 0usize;
    while input[*ip] == 0 {
        length += 255;
        *ip += 1;
        if length > MAX_LENGTH {
            return Err(too_long);
        }
        if *ip == input.len() {
            return Err(Error::InputOverrun);
        }
    }
    Ok(length)
}

/// Copy lookbehind: `len` bytes from `distance` back, which may overlap
/// what they write.
///
/// Differs from lzokay: it copies a byte at a time. The port copies a
/// match apart from what it writes as it copies literals, and one that
/// overlaps it, 8 bytes back or more, in pieces of 8, as liblzo2 does on
/// 64-bit machines; nothing is written past the match either.
#[inline(always)]
fn copy_match(output: &mut [u8], op: usize, distance: usize, len: usize) {
    let from = op - distance;
    if distance >= len {
        let (before, after) = output.split_at_mut(op);
        copy_literals(&mut after[..len], &before[from..from + len]);
    } else if distance >= 8 {
        // Each piece reads bytes written before it, and the last, which
        // ends the match, writes again the same bytes as those before it.
        let mut i = 0;
        while len - i >= 8 {
            let mut piece = [0u8; 8];
            piece.copy_from_slice(&output[from + i..from + i + 8]);
            output[op + i..op + i + 8].copy_from_slice(&piece);
            i += 8;
        }
        if i < len {
            let mut piece = [0u8; 8];
            piece.copy_from_slice(&output[from + len - 8..from + len]);
            output[op + len - 8..op + len].copy_from_slice(&piece);
        }
    } else {
        for i in 0..len {
            output[op + i] = output[from + i];
        }
    }
}

/// `src` copied to `dst`, of the same length, which do not overlap.
///
/// Differs from lzokay: it copies a byte at a time. The port copies
/// lengths up to 32 in two pieces that may overlap, so that the short
/// runs most instructions have take no call to `memcpy`, and longer ones
/// with it.
#[inline(always)]
fn copy_literals(dst: &mut [u8], src: &[u8]) {
    let len = dst.len();
    if len > 32 {
        dst.copy_from_slice(src);
    } else if len >= 16 {
        dst[..16].copy_from_slice(&src[..16]);
        dst[len - 16..].copy_from_slice(&src[len - 16..]);
    } else if len >= 8 {
        dst[..8].copy_from_slice(&src[..8]);
        dst[len - 8..].copy_from_slice(&src[len - 8..]);
    } else if len >= 4 {
        dst[..4].copy_from_slice(&src[..4]);
        dst[len - 4..].copy_from_slice(&src[len - 4..]);
    } else if len > 0 {
        // 1 to 3 bytes: the first, the middle and the last cover them.
        dst[0] = src[0];
        dst[len / 2] = src[len / 2];
        dst[len - 1] = src[len - 1];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// "hello" six times, between commas, as `lzo1x_999_compress` makes
    /// it: 7 literals, a match of 33 bytes 7 back with a literal after it,
    /// and the end-of-stream marker.
    const HELLO: &[u8] = &[
        0x18, b'h', b'e', b'l', b'l', b'o', b',', b' ', 0x3f, 0x19, 0x00, b'\n', 0x11, 0x00, 0x00,
    ];
    const HELLO_TEXT: &[u8] = b"hello, hello, hello, hello, hello, hello\n";

    /// `input` decoded into `capacity` bytes, filled with 0xaa before.
    fn decode(input: &[u8], capacity: usize) -> (Result<usize, Error>, Vec<u8>) {
        let mut out = vec![0xaa; capacity];
        let result = decompress(input, &mut out);
        (result, out)
    }

    #[test]
    fn outputs_of_every_size() {
        let len = HELLO_TEXT.len();
        let (result, out) = decode(HELLO, len);
        assert_eq!(result, Ok(len));
        assert_eq!(out, HELLO_TEXT);
        // Larger: nothing written past the data.
        let (result, out) = decode(HELLO, len + 10);
        assert_eq!(result, Ok(len));
        assert_eq!(&out[..len], HELLO_TEXT);
        assert!(out[len..].iter().all(|&b| b == 0xaa));
        // One byte short: liblzo2 copies the match before it checks for the
        // literal after it, and leaves 40 bytes; lzokay checks both first
        // and leaves 7.
        let (result, out) = decode(HELLO, len - 1);
        assert_eq!(result, Err(Error::OutputOverrun));
        assert_eq!(out, &HELLO_TEXT[..len - 1]);
        // Shorter than the first literals: nothing written.
        let (result, out) = decode(HELLO, 6);
        assert_eq!(result, Err(Error::OutputOverrun));
        assert_eq!(out, [0xaa; 6]);
        assert_eq!(decode(HELLO, 0).0, Err(Error::OutputOverrun));
    }

    #[test]
    fn input_cut_short_or_followed_by_more() {
        for end in 0..HELLO.len() {
            assert_eq!(
                decode(&HELLO[..end], 100).0,
                Err(Error::InputOverrun),
                "{end} bytes"
            );
        }
        let mut more = HELLO.to_vec();
        more.push(0);
        let (result, out) = decode(&more, 100);
        assert_eq!(result, Err(Error::InputNotConsumed));
        // liblzo2 leaves the block decoded.
        assert_eq!(&out[..HELLO_TEXT.len()], HELLO_TEXT);
    }

    #[test]
    fn end_of_stream_marker() {
        assert_eq!(decode(&[0x11, 0x00, 0x00], 0).0, Ok(0));
        assert_eq!(decode(&[], 10).0, Err(Error::InputOverrun));
        assert_eq!(decode(&[0x11, 0x00], 10).0, Err(Error::InputOverrun));
        assert_eq!(
            decode(&[0x11, 0x00, 0x00, 0x00], 10).0,
            Err(Error::InputNotConsumed)
        );
        // Markers of other lengths, which lzokay refuses and liblzo2 takes:
        // 4 bytes, and 255 + 7 + 5 + 2 bytes, after a zero byte.
        assert_eq!(decode(&[0x12, b'a', 0x12, 0x00, 0x00], 10).0, Ok(1));
        assert_eq!(decode(&[0x10, 0x00, 0x05, 0x00, 0x00], 10).0, Ok(0));
        // A first byte of 18 and more is literals, so that 0x12 there needs
        // its literal and 3 bytes after it.
        assert_eq!(decode(&[0x12, 0x00, 0x00], 10).0, Err(Error::InputOverrun));
    }

    #[test]
    fn instructions_after_literals() {
        // One literal, then an M1 match of 2 bytes 1 back.
        let (result, out) = decode(&[0x12, b'a', 0x00, 0x00, 0x11, 0x00, 0x00], 3);
        assert_eq!(result, Ok(3));
        assert_eq!(out, b"aaa");
        // A literal run of 4 in the regular encoding.
        let (result, out) = decode(&[0x01, b'a', b'b', b'c', b'd', 0x11, 0x00, 0x00], 4);
        assert_eq!(result, Ok(4));
        assert_eq!(out, b"abcd");
        // After 4 literals, an M1 match is 3 bytes from 2049 back or more:
        // before the output.
        let (result, out) = decode(
            &[0x15, b'a', b'b', b'c', b'd', 0x00, 0x00, 0x11, 0x00, 0x00],
            10,
        );
        assert_eq!(result, Err(Error::LookbehindOverrun));
        assert_eq!(&out[..5], b"abcd\xaa");
        // A match 2 back after one literal.
        let (result, out) = decode(&[0x12, b'a', 0x04, 0x00, 0x11, 0x00, 0x00], 10);
        assert_eq!(result, Err(Error::LookbehindOverrun));
        assert_eq!(&out[..2], b"a\xaa");
    }

    #[test]
    fn overlapping_matches() {
        // 3 literals, then an M3 match of 33 bytes 3 back, then one of 20
        // bytes 9 back (copied in pieces of 8), then the marker.
        let mut block = vec![0x14, b'x', b'y', b'z', 0x3f, 0x08, 0x00];
        block.extend_from_slice(&[0x32, 0x20, 0x00, 0x11, 0x00, 0x00]);
        let (result, out) = decode(&block, 100);
        assert_eq!(result, Ok(56));
        let mut want = b"xyz".repeat(12);
        for _ in 0..20 {
            want.push(want[want.len() - 9]);
        }
        assert_eq!(&out[..56], &want[..]);
        assert!(out[56..].iter().all(|&b| b == 0xaa));
    }

    #[test]
    fn errors_say_which() {
        assert_eq!(Error::InputOverrun.number(), -4);
        assert_eq!(Error::OutputOverrun.number(), -5);
        assert_eq!(Error::LookbehindOverrun.number(), -6);
        assert_eq!(Error::InputNotConsumed.number(), -8);
        assert_eq!(
            Error::OutputOverrun.to_string(),
            "LZO: the data does not fit in the output"
        );
    }
}
