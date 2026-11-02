//! The LZ4 block format: `lz4.c`'s decoding half, and the constants and
//! helpers it shares with the encoder.

use core::fmt;

/*-************************************
 *  Common Constants
 **************************************/

pub(crate) const MINMATCH: usize = 4;

pub(crate) const WILDCOPYLENGTH: usize = 8;
/// See `doc/lz4_Block_format.md#parsing-restrictions`.
pub(crate) const LASTLITERALS: usize = 5;
/// See `doc/lz4_Block_format.md#parsing-restrictions`.
pub(crate) const MFLIMIT: usize = 12;
/// Ensures it is possible to write 2 × `WILDCOPYLENGTH` without
/// overflowing the output buffer.
const MATCH_SAFEGUARD_DISTANCE: usize = 2 * WILDCOPYLENGTH - MINMATCH;
const FASTLOOP_SAFE_DISTANCE: usize = 64;

pub(crate) const KB: usize = 1 << 10;

pub(crate) const ML_BITS: u32 = 4;
pub(crate) const ML_MASK: usize = (1 << ML_BITS) - 1;
pub(crate) const RUN_BITS: u32 = 8 - ML_BITS;
pub(crate) const RUN_MASK: usize = (1 << RUN_BITS) - 1;

/// `LZ4_MAX_INPUT_SIZE`: the largest input the block functions take.
pub const MAX_INPUT_SIZE: usize = 0x7E00_0000;

const VERSION_MAJOR: u32 = 1;
const VERSION_MINOR: u32 = 10;
const VERSION_RELEASE: u32 = 0;

/// `LZ4_VERSION_NUMBER`.
pub const VERSION_NUMBER: u32 = VERSION_MAJOR * 100 * 100 + VERSION_MINOR * 100 + VERSION_RELEASE;

/// `LZ4_versionNumber()`: 11000 for 1.10.0.
pub fn version_number() -> u32 {
    VERSION_NUMBER
}

/// `LZ4_versionString()`.
pub fn version_string() -> &'static str {
    "1.10.0"
}

/// `LZ4_compressBound()`: the largest a block of `input_size` bytes can
/// compress to, or 0 when `input_size` is more than [`MAX_INPUT_SIZE`].
pub fn compress_bound(input_size: usize) -> usize {
    if input_size > MAX_INPUT_SIZE {
        0
    } else {
        input_size + input_size / 255 + 16
    }
}

/// A block that could not be decoded: liblz4's negative result,
/// `-(position) - 1`, where `position` is how far into the block the
/// decoder had read when it found the error.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct DecodeError {
    position: usize,
}

impl DecodeError {
    fn at(position: usize) -> Self {
        DecodeError { position }
    }

    /// How far into the block the decoder had read when it stopped.
    pub fn position(self) -> usize {
        self.position
    }

    /// The number liblz4 returns for this error: `-(position) - 1`.
    pub fn number(self) -> i64 {
        -(self.position as i64) - 1
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid LZ4 block, at byte {}", self.position)
    }
}

impl core::error::Error for DecodeError {}

/*-************************************
 *  Reading and writing into memory
 **************************************/

/// How the decoder's fast loop reads and writes its pieces: with bounds
/// checks ([`Checked`]), or, with the `unsafe-fast` feature, without
/// (`unchecked::Unchecked`, which only an `unsafe fn` makes). The rest of
/// the decoder is always `Checked`.
pub(crate) trait Mode: Copy {
    /// Whether the pieces are bounds-checked.
    const CHECKED: bool;

    /// `N` bytes of `buf` from `at`.
    fn read<const N: usize>(self, buf: &[u8], at: usize) -> [u8; N];

    /// `bytes` written to `buf` at `at`.
    fn write<const N: usize>(self, buf: &mut [u8], at: usize, bytes: [u8; N]);
}

/// Pieces read and written with bounds checks.
#[derive(Clone, Copy)]
pub(crate) struct Checked;

impl Mode for Checked {
    const CHECKED: bool = true;

    #[inline(always)]
    fn read<const N: usize>(self, buf: &[u8], at: usize) -> [u8; N] {
        let mut bytes = [0; N];
        bytes.copy_from_slice(&buf[at..at + N]);
        bytes
    }

    #[inline(always)]
    fn write<const N: usize>(self, buf: &mut [u8], at: usize, bytes: [u8; N]) {
        buf[at..at + N].copy_from_slice(&bytes);
    }
}

#[inline(always)]
fn read_le16<M: Mode>(m: M, bytes: &[u8], at: usize) -> usize {
    usize::from(u16::from_le_bytes(m.read(bytes, at)))
}

/// `LZ4_memcpy(op, ip, N)` from the block's input to its output.
#[inline(always)]
fn copy_in<M: Mode, const N: usize>(m: M, out: &mut [u8], op: usize, src: &[u8], ip: usize) {
    m.write::<N>(out, op, m.read(src, ip));
}

/// `LZ4_memcpy(op, match, N)` within the output, where the two do not
/// overlap or the copy reads before it writes.
#[inline(always)]
fn copy_within<M: Mode, const N: usize>(m: M, out: &mut [u8], op: usize, from: usize) {
    m.write::<N>(out, op, m.read(out, from));
}

/// How much a wild copy of `step` bytes at a time from `op` until `end`
/// writes: at least once, and up to `step` bytes past `end`.
#[inline(always)]
fn wild_len(op: usize, end: usize, step: usize) -> usize {
    if end > op {
        (end - op).div_ceil(step) * step
    } else {
        step
    }
}

/// A copy of `n` bytes within the output from `from` to `op`, in pieces
/// of `STEP` bytes, each reading what the ones before wrote: when the
/// source ends before the destination starts, one copy does the same.
#[inline(always)]
fn copy_forward<M: Mode, const STEP: usize>(
    m: M,
    out: &mut [u8],
    mut op: usize,
    mut from: usize,
    n: usize,
) {
    // Short copies stay inline, as do unchecked ones.
    if M::CHECKED && n > 32 && op - from >= n {
        out.copy_within(from..from + n, op);
        return;
    }
    let end = op + n;
    while op < end {
        copy_within::<M, STEP>(m, out, op, from);
        op += STEP;
        from += STEP;
    }
}

/// `LZ4_wildCopy8`: copies 8 bytes at a time from `from` to `op` until
/// `end`, at least once, so that up to 8 bytes past `end` are written too.
#[inline(always)]
fn wild_copy8<M: Mode>(m: M, out: &mut [u8], op: usize, from: usize, end: usize) {
    copy_forward::<M, 8>(m, out, op, from, wild_len(op, end, 8));
}

/// `LZ4_wildCopy8` from the input: the source is apart from the output,
/// so one copy does.
#[inline(always)]
fn wild_copy8_in(out: &mut [u8], mut op: usize, src: &[u8], mut ip: usize, end: usize) {
    let n = wild_len(op, end, 8);
    if n > 32 {
        out[op..op + n].copy_from_slice(&src[ip..ip + n]);
        return;
    }
    let end = op + n;
    while op < end {
        copy_in::<Checked, 8>(Checked, out, op, src, ip);
        op += 8;
        ip += 8;
    }
}

/// `LZ4_wildCopy32`: two times 16 bytes at a time (rather than 32 at
/// once, so that offsets of 16 or more work), writing up to 32 bytes past
/// `end`.
#[inline(always)]
fn wild_copy32<M: Mode>(m: M, out: &mut [u8], op: usize, from: usize, end: usize) {
    copy_forward::<M, 16>(m, out, op, from, wild_len(op, end, 32));
}

/// `LZ4_wildCopy32` from the input, in one copy.
#[inline(always)]
fn wild_copy32_in<M: Mode>(m: M, out: &mut [u8], op: usize, src: &[u8], ip: usize, end: usize) {
    let n = wild_len(op, end, 32);
    if n == 32 {
        copy_in::<M, 32>(m, out, op, src, ip);
    } else {
        out[op..op + n].copy_from_slice(&src[ip..ip + n]);
    }
}

const INC32TABLE: [usize; 8] = [0, 1, 2, 1, 0, 4, 4, 4];
const DEC64TABLE: [isize; 8] = [0, 0, 0, -1, -4, 1, 2, 3];

/// The first 8 bytes of a match closer than 8 bytes: 4 one at a time,
/// then 4 from where the first 4 make a period of the offset
/// (`inc32table`), and the copy goes on from `dec64table` further on, 8
/// bytes or more behind. Returns where the copy goes on from.
#[inline(always)]
fn copy_short_offset<M: Mode>(
    m: M,
    out: &mut [u8],
    op: usize,
    mut from: usize,
    offset: usize,
) -> usize {
    // `LZ4_write32(op, 0)`: silences an msan warning when offset == 0.
    m.write(out, op, [0u8; 4]);
    for i in 0..4 {
        let [byte] = m.read::<1>(out, from + i);
        m.write(out, op + i, [byte]);
    }
    from += INC32TABLE[offset & 7];
    copy_within::<M, 4>(m, out, op + 4, from);
    from.wrapping_add_signed(-DEC64TABLE[offset & 7])
}

/// `LZ4_memcpy_using_offset_base`.
#[inline(always)]
fn memcpy_using_offset_base<M: Mode>(
    m: M,
    out: &mut [u8],
    mut op: usize,
    mut from: usize,
    end: usize,
    offset: usize,
) {
    if offset < 8 {
        from = copy_short_offset(m, out, op, from, offset);
        op += 8;
    } else {
        copy_within::<M, 8>(m, out, op, from);
        op += 8;
        from += 8;
    }
    wild_copy8(m, out, op, from, end);
}

/// `LZ4_memcpy_using_offset`: a match closer than 16 bytes, which can
/// write up to 12 bytes past `end`. Offsets of 1, 2 and 4 repeat a
/// pattern of 8 bytes.
#[inline(always)]
fn memcpy_using_offset<M: Mode>(
    m: M,
    out: &mut [u8],
    mut op: usize,
    from: usize,
    end: usize,
    offset: usize,
) {
    let v: [u8; 8] = match offset {
        1 => {
            let [byte] = m.read::<1>(out, from);
            [byte; 8]
        }
        2 => {
            let [a, b] = m.read::<2>(out, from);
            [a, b, a, b, a, b, a, b]
        }
        4 => {
            let [a, b, c, d] = m.read::<4>(out, from);
            [a, b, c, d, a, b, c, d]
        }
        _ => {
            memcpy_using_offset_base(m, out, op, from, end, offset);
            return;
        }
    };
    m.write(out, op, v);
    op += 8;
    while op < end {
        m.write(out, op, v);
        op += 8;
    }
}

/*-************************************
 *  Decompression functions
 **************************************/

/// `dict_directive`: where the history before the output is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum DictDirective {
    /// Nothing before the output, or a prefix of less than 64 KB.
    NoDict,
    /// At least 64 KB of output before the output: every offset is in it.
    WithPrefix64k,
    /// A dictionary apart from the output, with or without a prefix.
    UsingExtDict,
}

/// `read_variable_length`: a length's bytes after its token, adding up
/// until one is not 255. `ilimit` is where, if the length is not complete,
/// the input is necessarily corrupt; with `initial_check`, a first byte at
/// `ilimit` or past it is an error too. The error is `None` (`rvl_error`).
#[inline(always)]
fn read_variable_length(
    src: &[u8],
    ip: &mut usize,
    ilimit: isize,
    initial_check: bool,
) -> Option<usize> {
    if initial_check && *ip as isize >= ilimit {
        // Read limit reached.
        return None;
    }
    let mut s = usize::from(src[*ip]);
    *ip += 1;
    let mut length = s;
    if *ip as isize > ilimit {
        return None;
    }
    // Accumulator overflow detection (32-bit mode only).
    if usize::BITS < 64 && length > usize::MAX / 2 {
        return None;
    }
    if s != 255 {
        return Some(length);
    }
    loop {
        s = usize::from(src[*ip]);
        *ip += 1;
        length += s;
        if *ip as isize > ilimit {
            return None;
        }
        if usize::BITS < 64 && length > usize::MAX / 2 {
            return None;
        }
        if s != 255 {
            return Some(length);
        }
    }
}

/// Where the safe loop starts a sequence: at its token, or, coming from the
/// fast loop or its own shortcut, at one of the labels the C jumps to.
#[derive(Clone, Copy)]
enum Resume {
    Token,
    /// `safe_literal_copy`: the literal length is decoded.
    LiteralCopy {
        token: u8,
        length: usize,
    },
    /// `_copy_match`: the offset is read, the match length is the token's.
    CopyMatch {
        length: usize,
        offset: usize,
    },
    /// `safe_match_copy`: the match length is decoded, `MINMATCH` added.
    MatchCopy {
        length: usize,
        offset: usize,
    },
}

/// The fast loop's copy of a match of up to 18 bytes, 8 or more behind:
/// 8, 8 and 2 bytes, each reading what the one before wrote. 18 or more
/// behind, the source is all before `op`, and one copy does.
#[inline(always)]
fn copy_match18<M: Mode>(m: M, out: &mut [u8], op: usize, offset: usize) {
    if M::CHECKED
        && offset >= 18
        && let Some((hist, rest)) = out.split_at_mut_checked(op)
        && let Some(from) = hist.len().checked_sub(offset)
        && let Some(source) = hist[from..].first_chunk::<18>()
        && let Some(o) = rest.first_chunk_mut::<18>()
    {
        *o = *source;
        return;
    }
    let from = op - offset;
    copy_within::<M, 8>(m, out, op, from);
    copy_within::<M, 8>(m, out, op + 8, from + 8);
    copy_within::<M, 2>(m, out, op + 16, from + 16);
}

/// The fast loop's match, past its fast path: the offset checked, then
/// copied from the external dictionary or from the block. Returns `false`
/// for an error, and moves `op` past the match.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn match_rest<M: Mode, const PARTIAL: bool, const DICT: u8>(
    m: M,
    out: &mut [u8],
    op: &mut usize,
    mut length: usize,
    offset: usize,
    low_prefix: usize,
    dict: &[u8],
    check_offset: bool,
) -> bool {
    let oend = out.len();
    if check_offset && offset > *op - low_prefix + dict.len() {
        // Offset outside the buffers.
        return false;
    }
    // A match starting within the external dictionary.
    if DICT == USING_EXT_DICT && offset > *op - low_prefix {
        if *op + length > oend - LASTLITERALS {
            if PARTIAL {
                length = length.min(oend - *op);
            } else {
                // End-of-block condition violated.
                return false;
            }
        }
        *op = copy_from_dict(
            out,
            *op,
            length,
            offset - (*op - low_prefix),
            low_prefix,
            dict,
        );
        return true;
    }

    // Copy a match within the block.
    let cpy = *op + length;
    let from = *op - offset;
    debug_assert!(oend - *op >= 32);
    if offset < 16 {
        memcpy_using_offset(m, out, *op, from, cpy, offset);
    } else {
        wild_copy32(m, out, *op, from, cpy);
    }
    // Wild-copy correction.
    *op = cpy;
    true
}

/// `LZ4_decompress_generic`: the block `src` decoded into `out[start..]`.
///
/// Differs from liblz4: the output and what comes before it are one slice
/// rather than pointers. `out[low_prefix..start]` is the prefix (the
/// history in the same buffer, `lowPrefix` to `dst`), and `dict` the
/// external dictionary, read when `dict_mode` is `UsingExtDict`. With
/// `WithPrefix64k` the prefix must hold at least 64 KB - 1 bytes, as every
/// offset reaches into it: the caller checks that, where liblz4 trusts its
/// caller. The checks for a pointer that wraps around the address space
/// are left out, as positions in a slice cannot.
///
/// The fast loop (`LZ4_FAST_DEC_LOOP`) is always on, as liblz4 builds it
/// on x86, x86-64 and arm64 with GCC or Apple's compilers: what it writes
/// past the end of a sequence, and so what the output holds past what was
/// decoded, is liblz4's on those.
pub(crate) fn decompress_generic(
    src: &[u8],
    out: &mut [u8],
    start: usize,
    partial: bool,
    dict_mode: DictDirective,
    low_prefix: usize,
    dict: &[u8],
) -> Result<usize, DecodeError> {
    #[cfg(feature = "lz4-unsafe-fast")]
    {
        // SAFETY: the fast loop of `decode` is the only code that uses the
        // mode, and each of its pieces is in its buffer, by the checks
        // liblz4's fast loop makes (which the port makes too):
        //
        // - The loop is entered when `oend - op >= FASTLOOP_SAFE_DISTANCE`,
        //   and goes round again only after a sequence that ends before
        //   `oend - FASTLOOP_SAFE_DISTANCE`, so 64 bytes of output are free
        //   from `op` at its top. The input is never empty there: the
        //   decoder returns first for an empty block, and every sequence
        //   that goes round again stopped at least 1 byte short of `iend`
        //   (the checks below, and `read_variable_length`'s limits).
        // - The token: `ip < iend`.
        // - Literals of up to 14 bytes: 16 copied when `ip + 17 <= iend`,
        //   into the 64 free bytes. Longer ones: in one or more pieces of 32
        //   when `length + 32 <= oend - op` and `length + 32 <= iend - ip`
        //   (computed so as not to wrap), so the last piece, which ends at
        //   most 31 bytes past `length`, is in both.
        // - The offset: 2 bytes at `ip`, which the literal checks left at
        //   least 3 (short) or 32 (long) bytes before `iend`.
        // - A match: copied only when `op + length < oend - 64`. Its source
        //   starts `offset` bytes behind `op`, at `low_prefix` or later
        //   (the offset checks, `outside` and `before_prefix`; with
        //   `WithPrefix64k` the 64 KB before `start`), so at 0 or later,
        //   and reads only bytes before what it writes. The 18-byte copy
        //   (offset 8 or more) writes `op..op + 18`; the others write at most
        //   32 bytes past `op + length` (`wild_copy32`), or 12
        //   (`memcpy_using_offset`), all short of `oend`. Matches from the
        //   external dictionary are copied with bounds checks.
        //
        // Debug builds assert each piece in bounds, and the tests and the
        // fuzzer run with the feature (see `docs/unsafe.md`).
        #[allow(unsafe_code)]
        let m = unsafe { crate::lz4::unchecked::Unchecked::new() };
        dispatch(m, src, out, start, partial, dict_mode, low_prefix, dict)
    }
    #[cfg(not(feature = "lz4-unsafe-fast"))]
    dispatch(
        Checked, src, out, start, partial, dict_mode, low_prefix, dict,
    )
}

/// `decode` for each case, its own code, as liblz4 inlines
/// LZ4_decompress_generic into each API function with its directives as
/// constants.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn dispatch<M: Mode>(
    m: M,
    src: &[u8],
    out: &mut [u8],
    start: usize,
    partial: bool,
    dict_mode: DictDirective,
    low_prefix: usize,
    dict: &[u8],
) -> Result<usize, DecodeError> {
    use DictDirective::{NoDict, UsingExtDict, WithPrefix64k};
    match (partial, dict_mode) {
        (false, NoDict) => decode::<M, false, NO_DICT>(m, src, out, start, low_prefix, dict),
        (false, WithPrefix64k) => {
            decode::<M, false, WITH_PREFIX_64K>(m, src, out, start, low_prefix, dict)
        }
        (false, UsingExtDict) => {
            decode::<M, false, USING_EXT_DICT>(m, src, out, start, low_prefix, dict)
        }
        (true, NoDict) => decode::<M, true, NO_DICT>(m, src, out, start, low_prefix, dict),
        (true, WithPrefix64k) => {
            decode::<M, true, WITH_PREFIX_64K>(m, src, out, start, low_prefix, dict)
        }
        (true, UsingExtDict) => {
            decode::<M, true, USING_EXT_DICT>(m, src, out, start, low_prefix, dict)
        }
    }
}

/// `DictDirective` as constants, for `decode`'s parameter.
const NO_DICT: u8 = 0;
const WITH_PREFIX_64K: u8 = 1;
const USING_EXT_DICT: u8 = 2;

/// `LZ4_decompress_generic`, for one `partialDecoding` and `dict`.
#[inline(always)]
fn decode<M: Mode, const PARTIAL: bool, const DICT: u8>(
    m: M,
    src: &[u8],
    out: &mut [u8],
    start: usize,
    low_prefix: usize,
    dict: &[u8],
) -> Result<usize, DecodeError> {
    let partial = PARTIAL;
    let src_size = src.len();
    let output_size = out.len() - start;
    let iend = src_size;
    let oend = out.len();
    let mut ip = 0usize;
    let mut op = start;

    let dict_size = dict.len();
    let check_offset = dict_size < 64 * KB;

    // The "end" positions for the shortcut.
    let shortiend = iend as isize - 14 /* maxLL */ - 2 /* offset */;
    let shortoend = oend as isize - 14 /* maxLL */ - 18 /* maxML */;

    // Special cases.
    debug_assert!(low_prefix <= op);
    if output_size == 0 {
        // Empty output buffer.
        if partial {
            return Ok(0);
        }
        return if src_size == 1 && src[0] == 0 {
            Ok(0)
        } else {
            Err(DecodeError::at(0))
        };
    }
    if src_size == 0 {
        return Err(DecodeError::at(0));
    }

    // Whether the match `offset` behind `op` starts before the prefix
    // (`match < lowPrefix`), and so in the external dictionary or outside
    // the buffers.
    let before_prefix = |op: usize, offset: usize| offset > op - low_prefix;
    // `match + dictSize < lowPrefix`: outside the buffers.
    let outside = |op: usize, offset: usize| offset > op - low_prefix + dict_size;

    let mut resume = Resume::Token;

    // LZ4_FAST_DEC_LOOP: designed for modern OoO performance CPUs, where
    // copying reliably 32 bytes is preferable to an unpredictable branch.
    'fast: {
        if oend - op < FASTLOOP_SAFE_DISTANCE {
            break 'fast;
        }
        // Decode sequences as long as the output is short of
        // oend - FASTLOOP_SAFE_DISTANCE.
        loop {
            // Main fast loop assertion: FASTLOOP_SAFE_DISTANCE can always
            // be wild-copied.
            debug_assert!(oend - op >= FASTLOOP_SAFE_DISTANCE);
            debug_assert!(ip < iend);

            // Differs from liblz4: the most common sequence, a token, up to
            // 14 literals and an offset in the next 18 bytes of input,
            // through windows of the input and output of a known size,
            // where the compiler sees that the copies are in bounds. The
            // same reads and writes as below.
            if M::CHECKED
                && let Some(w) = src.get(ip..).and_then(<[u8]>::first_chunk::<18>)
                && usize::from(w[0] >> ML_BITS) < RUN_MASK
                && let Some(o) = out.get_mut(op..).and_then(<[u8]>::first_chunk_mut::<32>)
            {
                let token = w[0];
                let lit = usize::from(token >> ML_BITS);
                o[..16].copy_from_slice(&w[1..17]);
                let offset = usize::from(u16::from_le_bytes([w[1 + lit], w[2 + lit]]));
                ip += 1 + lit + 2;
                op += lit;
                let ml = usize::from(token) & ML_MASK;
                if ml != ML_MASK {
                    let length = ml + MINMATCH;
                    if op.saturating_add(length) >= oend - FASTLOOP_SAFE_DISTANCE {
                        resume = Resume::MatchCopy { length, offset };
                        break 'fast;
                    }
                    if (DICT == WITH_PREFIX_64K || !before_prefix(op, offset)) && offset >= 8 {
                        copy_match18(m, out, op, offset);
                        op += length;
                        continue;
                    }
                    if !match_rest::<M, PARTIAL, DICT>(
                        m,
                        out,
                        &mut op,
                        length,
                        offset,
                        low_prefix,
                        dict,
                        check_offset,
                    ) {
                        return Err(DecodeError::at(ip));
                    }
                    continue;
                }
                // A long match length: as below.
                let Some(addl) = read_variable_length(
                    src,
                    &mut ip,
                    iend as isize - LASTLITERALS as isize + 1,
                    false,
                ) else {
                    return Err(DecodeError::at(ip));
                };
                let length = ml + addl + MINMATCH;
                if op.saturating_add(length) >= oend - FASTLOOP_SAFE_DISTANCE {
                    resume = Resume::MatchCopy { length, offset };
                    break 'fast;
                }
                if !match_rest::<M, PARTIAL, DICT>(
                    m,
                    out,
                    &mut op,
                    length,
                    offset,
                    low_prefix,
                    dict,
                    check_offset,
                ) {
                    return Err(DecodeError::at(ip));
                }
                continue;
            }

            let [token] = m.read::<1>(src, ip);
            ip += 1;
            let mut length = usize::from(token >> ML_BITS);

            // Decode the literal length.
            if length == RUN_MASK {
                let Some(addl) =
                    read_variable_length(src, &mut ip, iend as isize - RUN_MASK as isize, true)
                else {
                    return Err(DecodeError::at(ip));
                };
                length += addl;

                // Copy the literals.
                // As `op + length > oend - 32 || ip + length > iend - 32`,
                // without wrapping around.
                if length.saturating_add(32) > oend - op || length.saturating_add(32) > iend - ip {
                    resume = Resume::LiteralCopy { token, length };
                    break 'fast;
                }
                wild_copy32_in(m, out, op, src, ip, op + length);
                ip += length;
                op += length;
            } else if ip as isize <= iend as isize - (16 + 1) {
                // Literals are at most 14 bytes, but compilers optimise a
                // copy of a register's size better. oend is checked once
                // for each loop below.
                copy_in::<M, 16>(m, out, op, src, ip);
                ip += length;
                op += length;
            } else {
                resume = Resume::LiteralCopy { token, length };
                break 'fast;
            }

            // Get the offset.
            let offset = read_le16(m, src, ip);
            ip += 2;

            // Get the match length.
            length = usize::from(token) & ML_MASK;

            if length == ML_MASK {
                let Some(addl) = read_variable_length(
                    src,
                    &mut ip,
                    iend as isize - LASTLITERALS as isize + 1,
                    false,
                ) else {
                    return Err(DecodeError::at(ip));
                };
                length += addl;
                length += MINMATCH;
                if op.saturating_add(length) >= oend - FASTLOOP_SAFE_DISTANCE {
                    resume = Resume::MatchCopy { length, offset };
                    break 'fast;
                }
            } else {
                length += MINMATCH;
                if op.saturating_add(length) >= oend - FASTLOOP_SAFE_DISTANCE {
                    resume = Resume::MatchCopy { length, offset };
                    break 'fast;
                }

                // Fast path: no LZ4_wildCopy32 when true.
                if (DICT == WITH_PREFIX_64K || !before_prefix(op, offset)) && offset >= 8 {
                    copy_match18(m, out, op, offset);
                    op += length;
                    continue;
                }
            }

            if !match_rest::<M, PARTIAL, DICT>(
                m,
                out,
                &mut op,
                length,
                offset,
                low_prefix,
                dict,
                check_offset,
            ) {
                return Err(DecodeError::at(ip));
            }
        }
    }

    // Main loop: decodes the remaining sequences, where the output is
    // within FASTLOOP_SAFE_DISTANCE of its end.
    loop {
        let (token, mut length) = match resume {
            Resume::Token => {
                debug_assert!(ip < iend);
                let token = src[ip];
                ip += 1;
                let mut length = usize::from(token >> ML_BITS);

                // A two-stage shortcut for the most common case:
                // 1) If the literal length is 0..14, and there is enough
                //    space, enter the shortcut and copy 16 bytes on behalf
                //    of the literals.
                // 2) Further if the match length is 4..18, copy 18 bytes in
                //    a similar manner; but enough space in the output for
                //    those 18 bytes was ensured earlier, upon entering the
                //    shortcut (a combined check for both stages).
                if length != RUN_MASK
                    // Strictly "less than" on input, to re-enter the loop
                    // with at least one byte.
                    && ((ip as isize) < shortiend) & ((op as isize) <= shortoend)
                {
                    // Copy the literals.
                    copy_in::<Checked, 16>(Checked, out, op, src, ip);
                    op += length;
                    ip += length;

                    // The second stage: prepare for the match copy, decode
                    // the full info. If it doesn't work out, the info
                    // won't be wasted.
                    length = usize::from(token) & ML_MASK;
                    let offset = read_le16(Checked, src, ip);
                    ip += 2;

                    // Do not deal with overlapping matches.
                    if length != ML_MASK
                        && offset >= 8
                        && (DICT == WITH_PREFIX_64K || !before_prefix(op, offset))
                    {
                        // Copy the match.
                        let from = op - offset;
                        copy_within::<Checked, 8>(Checked, out, op, from);
                        copy_within::<Checked, 8>(Checked, out, op + 8, from + 8);
                        copy_within::<Checked, 2>(Checked, out, op + 16, from + 16);
                        op += length + MINMATCH;
                        // Both stages worked: load the next token.
                        continue;
                    }

                    // The second stage didn't work out, but the info is
                    // ready: propel it right to the match copy.
                    resume = Resume::CopyMatch { length, offset };
                    continue;
                }

                // Decode the literal length.
                if length == RUN_MASK {
                    let Some(addl) =
                        read_variable_length(src, &mut ip, iend as isize - RUN_MASK as isize, true)
                    else {
                        return Err(DecodeError::at(ip));
                    };
                    length += addl;
                }
                (token, length)
            }
            Resume::LiteralCopy { token, length } => (token, length),
            Resume::CopyMatch { .. } | Resume::MatchCopy { .. } => (0, 0),
        };

        // safe_literal_copy: copy the literals.
        if let Resume::Token | Resume::LiteralCopy { .. } = resume {
            let mut cpy = op + length;

            if cpy as isize > oend as isize - MFLIMIT as isize
                || ip as isize + length as isize > iend as isize - (2 + 1 + LASTLITERALS) as isize
            {
                // Either the input parsing restriction or the output one
                // is hit. Decoding a full block, this must be the last
                // sequence, otherwise it's an error (invalid input or
                // dimensions). Decoding partially, it's necessary to ensure
                // there is no buffer overflow.
                if partial {
                    // The output buffer is allowed to be undersized here.
                    // Finishing in the middle of a literals segment, due to
                    // lack of input:
                    if ip + length > iend {
                        length = iend - ip;
                        cpy = op + length;
                    }
                    // or due to lack of output space:
                    if cpy > oend {
                        cpy = oend;
                        length = oend - op;
                    }
                } else if ip + length != iend || cpy > oend {
                    // The last run of literals must take the input exactly,
                    // and fit in the output.
                    return Err(DecodeError::at(ip));
                }
                // liblz4 moves (it supports in-place decompression).
                out[op..op + length].copy_from_slice(&src[ip..ip + length]);
                ip += length;
                op += length;
                // Necessarily the end without partial decoding. With it,
                // the end if the output is full or an offset cannot follow.
                if !partial || cpy == oend || ip as isize >= iend as isize - 2 {
                    break;
                }
            } else {
                // Can write up to 8 bytes past cpy.
                wild_copy8_in(out, op, src, ip, cpy);
                ip += length;
                op = cpy;
            }

            // Get the offset, and the match length.
            let offset = read_le16(Checked, src, ip);
            ip += 2;
            resume = Resume::CopyMatch {
                length: usize::from(token) & ML_MASK,
                offset,
            };
        }

        // _copy_match:
        if let Resume::CopyMatch {
            length: mut ml,
            offset,
        } = resume
        {
            if ml == ML_MASK {
                let Some(addl) = read_variable_length(
                    src,
                    &mut ip,
                    iend as isize - LASTLITERALS as isize + 1,
                    false,
                ) else {
                    return Err(DecodeError::at(ip));
                };
                ml += addl;
            }
            ml += MINMATCH;
            resume = Resume::MatchCopy { length: ml, offset };
        }

        // safe_match_copy:
        let Resume::MatchCopy { mut length, offset } = resume else {
            continue;
        };
        resume = Resume::Token;

        if check_offset && outside(op, offset) {
            // Offset outside the buffers.
            return Err(DecodeError::at(ip));
        }
        // A match starting within the external dictionary.
        if DICT == USING_EXT_DICT && before_prefix(op, offset) {
            if (op + length) as isize > oend as isize - LASTLITERALS as isize {
                if partial {
                    length = length.min(oend - op);
                } else {
                    // Doesn't respect the parsing restriction.
                    return Err(DecodeError::at(ip));
                }
            }
            op = copy_from_dict(
                out,
                op,
                length,
                offset - (op - low_prefix),
                low_prefix,
                dict,
            );
            continue;
        }

        // Copy a match within the block.
        let cpy = op + length;
        let mut from = op - offset;

        // Partial decoding may end anywhere within the block.
        if partial && cpy as isize > oend as isize - MATCH_SAFEGUARD_DISTANCE as isize {
            let mlen = length.min(oend - op);
            let match_end = from + mlen;
            let copy_end = op + mlen;
            if match_end > op {
                // Overlap copy.
                while op < copy_end {
                    out[op] = out[from];
                    op += 1;
                    from += 1;
                }
            } else {
                out.copy_within(from..from + mlen, op);
            }
            op = copy_end;
            if op == oend {
                break;
            }
            continue;
        }

        if offset < 8 {
            from = copy_short_offset(Checked, out, op, from, offset);
        } else {
            copy_within::<Checked, 8>(Checked, out, op, from);
            from += 8;
        }
        op += 8;

        if cpy as isize > oend as isize - MATCH_SAFEGUARD_DISTANCE as isize {
            let o_copy_limit = oend - (WILDCOPYLENGTH - 1);
            if cpy as isize > oend as isize - LASTLITERALS as isize {
                // The last LASTLITERALS bytes must be literals.
                return Err(DecodeError::at(ip));
            }
            if op < o_copy_limit {
                wild_copy8(Checked, out, op, from, o_copy_limit);
                from += o_copy_limit - op;
                op = o_copy_limit;
            }
            while op < cpy {
                out[op] = out[from];
                op += 1;
                from += 1;
            }
        } else {
            copy_within::<Checked, 8>(Checked, out, op, from);
            if length > 16 {
                wild_copy8(Checked, out, op + 8, from + 8, cpy);
            }
        }
        // Wild-copy correction.
        op = cpy;
    }

    // The end of decoding: the number of output bytes decoded.
    Ok(op - start)
}

/// A match that starts `back` bytes before the end of the external
/// dictionary: copied from it, and on into the prefix when it is longer.
/// Returns the output position after it.
#[inline(always)]
fn copy_from_dict(
    out: &mut [u8],
    mut op: usize,
    length: usize,
    back: usize,
    low_prefix: usize,
    dict: &[u8],
) -> usize {
    let dict_end = dict.len();
    if length <= back {
        // The match fits entirely within the external dictionary.
        let from = dict_end - back;
        out[op..op + length].copy_from_slice(&dict[from..from + length]);
        op + length
    } else {
        // The match stretches into both the external dictionary and the
        // current block.
        let copy_size = back;
        let rest_size = length - copy_size;
        out[op..op + copy_size].copy_from_slice(&dict[dict_end - copy_size..]);
        op += copy_size;
        if rest_size > op - low_prefix {
            // Overlap copy.
            let end_of_match = op + rest_size;
            let mut from = low_prefix;
            while op < end_of_match {
                out[op] = out[from];
                op += 1;
                from += 1;
            }
            op
        } else {
            out.copy_within(low_prefix..low_prefix + rest_size, op);
            op + rest_size
        }
    }
}

/*===== Instantiate the API decoding functions. =====*/

/// `LZ4_decompress_safe`: decodes the block `src` into `dst`, which must
/// have room for all of it, and returns the size decoded. Malformed input
/// is an error, never a read or write outside the buffers.
///
/// The decoder writes past what it decodes, within `dst`, as liblz4 does
/// (its wild copies): only the first bytes, as many as returned, are the
/// block.
pub fn decompress_safe(src: &[u8], dst: &mut [u8]) -> Result<usize, DecodeError> {
    decompress_generic(src, dst, 0, false, DictDirective::NoDict, 0, &[])
}

/// `LZ4_decompress_safe_partial`: decodes at most `target_output_size`
/// bytes of the block `src` (and at most `dst.len()`), stopping there.
/// `src` may be cut short after what that needs, or be the whole block.
///
/// liblz4 1.10.0 notes that it can stop short of `target_output_size`
/// only at the block's end: then the result is less.
pub fn decompress_safe_partial(
    src: &[u8],
    dst: &mut [u8],
    target_output_size: usize,
) -> Result<usize, DecodeError> {
    let capacity = target_output_size.min(dst.len());
    decompress_generic(
        src,
        &mut dst[..capacity],
        0,
        true,
        DictDirective::NoDict,
        0,
        &[],
    )
}

/// `LZ4_decompress_safe_usingDict` with a dictionary apart from the
/// output (`LZ4_decompress_safe_forceExtDict`): the block `src` was
/// compressed with `dict` before it.
pub fn decompress_safe_using_dict(
    src: &[u8],
    dst: &mut [u8],
    dict: &[u8],
) -> Result<usize, DecodeError> {
    if dict.is_empty() {
        return decompress_safe(src, dst);
    }
    decompress_generic(src, dst, 0, false, DictDirective::UsingExtDict, 0, dict)
}

/// `LZ4_decompress_safe_partial_usingDict` with a dictionary apart from the
/// output (`LZ4_decompress_safe_partial_forceExtDict`).
pub fn decompress_safe_partial_using_dict(
    src: &[u8],
    dst: &mut [u8],
    target_output_size: usize,
    dict: &[u8],
) -> Result<usize, DecodeError> {
    if dict.is_empty() {
        return decompress_safe_partial(src, dst, target_output_size);
    }
    let capacity = target_output_size.min(dst.len());
    decompress_generic(
        src,
        &mut dst[..capacity],
        0,
        true,
        DictDirective::UsingExtDict,
        0,
        dict,
    )
}

/// How a block is decoded after a prefix of `prefix_len` bytes in the
/// same buffer: the directive, and the lowest position a match may start.
fn prefix_mode(prefix_len: usize) -> (DictDirective, usize) {
    if prefix_len >= 64 * KB - 1 {
        // `LZ4_decompress_safe_withPrefix64k`: every offset is in the
        // prefix.
        (
            DictDirective::WithPrefix64k,
            prefix_len - prefix_len.min(64 * KB),
        )
    } else {
        // `LZ4_decompress_safe_withSmallPrefix`.
        (DictDirective::NoDict, 0)
    }
}

/// `LZ4_decompress_safe_usingDict` with the dictionary right before the
/// output: `buf[..prefix_len]` is the dictionary (or the blocks decoded
/// before), and the block `src` is decoded into `buf[prefix_len..]`.
///
/// # Panics
///
/// If `prefix_len` is more than `buf.len()`.
pub fn decompress_safe_with_prefix(
    src: &[u8],
    buf: &mut [u8],
    prefix_len: usize,
) -> Result<usize, DecodeError> {
    let (mode, low_prefix) = prefix_mode(prefix_len);
    decompress_generic(src, buf, prefix_len, false, mode, low_prefix, &[])
}

/// `LZ4_decompress_safe_partial_usingDict` with the dictionary right
/// before the output, as [`decompress_safe_with_prefix`].
///
/// # Panics
///
/// If `prefix_len` is more than `buf.len()`.
pub fn decompress_safe_partial_with_prefix(
    src: &[u8],
    buf: &mut [u8],
    prefix_len: usize,
    target_output_size: usize,
) -> Result<usize, DecodeError> {
    let capacity = target_output_size.min(buf.len() - prefix_len);
    let (mode, low_prefix) = prefix_mode(prefix_len);
    decompress_generic(
        src,
        &mut buf[..prefix_len + capacity],
        prefix_len,
        true,
        mode,
        low_prefix,
        &[],
    )
}

/// `LZ4_streamDecode_t`: blocks compressed one after another, each with
/// the ones before as its history (`LZ4_decompress_safe_continue`).
///
/// Differs from liblz4: liblz4 remembers where the last block was decoded,
/// and the caller keeps it there, decodes the next block right after it, or
/// says where it moved (`LZ4_setStreamDecode`). The stream keeps a copy of
/// the last 64 KB instead, decodes each block after it, and copies it to
/// the output: what liblz4 does when the blocks are decoded one after
/// another in one buffer, with the dictionary of `set_dict` elsewhere. The
/// output is the same however liblz4's caller places its blocks, but the
/// result of a malformed block can differ, as it does between liblz4's own
/// ways (a match that ends in the block's last 5 bytes is refused when it
/// starts in a dictionary apart from the output, and not always when it
/// starts in the output).
#[derive(Clone, Debug, Default)]
pub struct StreamDecode {
    /// The last 64 KB of the blocks decoded, or all of them if less.
    window: Vec<u8>,
    /// `prefixSize`: the size of all the blocks decoded, one after another.
    prefix_size: usize,
    /// `externalDict`: the dictionary of `set_dict`.
    ext_dict: Vec<u8>,
    /// No block was decoded since `set_dict` gave a dictionary: the next is
    /// decoded with it alone (`LZ4_decompress_safe_forceExtDict`).
    dict_pending: bool,
}

impl StreamDecode {
    /// `LZ4_createStreamDecode`: a stream with no history yet.
    pub fn new() -> Self {
        StreamDecode::default()
    }

    /// `LZ4_setStreamDecode`: `dict` is the history of the next block,
    /// in place of what came before. An empty one is no history.
    pub fn set_dict(&mut self, dict: &[u8]) {
        self.window.clear();
        self.ext_dict.clear();
        // Only the last 64 KB are ever read; more is the same to liblz4's
        // checks.
        self.ext_dict
            .extend_from_slice(&dict[dict.len() - dict.len().min(64 * KB)..]);
        self.prefix_size = 0;
        self.dict_pending = !dict.is_empty();
    }

    /// `LZ4_decompress_safe_continue`: decodes the next block into `dst`,
    /// with the blocks decoded before as its history.
    pub fn decompress_safe_continue(
        &mut self,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, DecodeError> {
        let start = self.window.len();
        let mut buf = core::mem::take(&mut self.window);
        buf.resize(start + dst.len(), 0);
        let result = if self.dict_pending {
            // The buffer is switched: the dictionary alone.
            decompress_generic(
                src,
                &mut buf,
                start,
                false,
                DictDirective::UsingExtDict,
                start,
                &self.ext_dict,
            )
        } else if self.prefix_size == 0 {
            // The first call: no dictionary yet.
            decompress_generic(
                src,
                &mut buf,
                start,
                false,
                DictDirective::NoDict,
                start,
                &[],
            )
        } else if self.prefix_size >= 64 * KB - 1 {
            decompress_generic(
                src,
                &mut buf,
                start,
                false,
                DictDirective::WithPrefix64k,
                start - start.min(64 * KB),
                &[],
            )
        } else if self.ext_dict.is_empty() {
            decompress_generic(
                src,
                &mut buf,
                start,
                false,
                DictDirective::NoDict,
                start - self.prefix_size,
                &[],
            )
        } else {
            // `LZ4_decompress_safe_doubleDict`: the blocks so far as the
            // prefix, the dictionary before them.
            decompress_generic(
                src,
                &mut buf,
                start,
                false,
                DictDirective::UsingExtDict,
                start - self.prefix_size,
                &self.ext_dict,
            )
        };
        let decoded = match result {
            Ok(decoded) => decoded,
            Err(e) => {
                buf.truncate(start);
                self.window = buf;
                return Err(e);
            }
        };
        dst[..decoded].copy_from_slice(&buf[start..start + decoded]);
        if decoded > 0 {
            // liblz4 takes a result of 0 as it takes an error: nothing
            // changes.
            if self.dict_pending {
                self.dict_pending = false;
                self.prefix_size = decoded;
            } else {
                self.prefix_size += decoded;
            }
        }
        buf.truncate(start + decoded);
        let keep = buf.len().min(64 * KB);
        buf.drain(..buf.len() - keep);
        self.window = buf;
        Ok(decoded)
    }
}
