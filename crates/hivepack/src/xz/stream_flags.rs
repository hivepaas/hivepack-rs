//! Stream Header and Stream Footer: port of `common/stream_flags_common.{h,c}`
//! and `common/stream_flags_decoder.c`.

use crate::xz::check::{CHECK_ID_MAX, Check, crc32};
use crate::xz::common::{Ret, VLI_UNKNOWN, read32le, write32le};

/// `LZMA_STREAM_HEADER_SIZE`: the size of the Stream Header and of the
/// Stream Footer.
pub(crate) const STREAM_HEADER_SIZE: usize = 12;

/// `LZMA_STREAM_FLAGS_SIZE`.
const STREAM_FLAGS_SIZE: usize = 2;

/// `LZMA_BACKWARD_SIZE_MIN`.
pub(crate) const BACKWARD_SIZE_MIN: u64 = 4;
/// `LZMA_BACKWARD_SIZE_MAX`.
pub(crate) const BACKWARD_SIZE_MAX: u64 = 1 << 34;

/// `lzma_header_magic`.
pub(crate) const HEADER_MAGIC: [u8; 6] = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
/// `lzma_footer_magic`.
const FOOTER_MAGIC: [u8; 2] = [0x59, 0x5A];

/// `lzma_stream_flags`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct StreamFlags {
    pub(crate) version: u32,
    /// Backward Size, or LZMA_VLI_UNKNOWN in a Stream Header.
    pub(crate) backward_size: u64,
    pub(crate) check: Check,
}

impl StreamFlags {
    pub(crate) fn new() -> StreamFlags {
        StreamFlags {
            version: 0,
            backward_size: VLI_UNKNOWN,
            check: Check::NONE,
        }
    }
}

/// `is_backward_size_valid`.
fn is_backward_size_valid(options: &StreamFlags) -> bool {
    options.backward_size >= BACKWARD_SIZE_MIN
        && options.backward_size <= BACKWARD_SIZE_MAX
        && options.backward_size & 3 == 0
}

/// `stream_flags_decode`: true if the flags are not supported.
fn stream_flags_decode(options: &mut StreamFlags, input: &[u8]) -> bool {
    // Reserved bits must be unset.
    if input[0] != 0x00 || input[1] & 0xF0 != 0 {
        return true;
    }
    options.version = 0;
    options.check = Check(u32::from(input[1] & 0x0F));
    false
}

/// `lzma_stream_header_decode`.
pub(crate) fn header_decode(options: &mut StreamFlags, input: &[u8]) -> Ret {
    // Magic
    if input[..HEADER_MAGIC.len()] != HEADER_MAGIC {
        return Ret::FormatError;
    }

    // Verify the CRC32 so we can distinguish between corrupt and
    // unsupported files.
    let flags = &input[HEADER_MAGIC.len()..];
    let crc = crc32(&flags[..STREAM_FLAGS_SIZE], 0);
    if crc != read32le(&flags[STREAM_FLAGS_SIZE..]) {
        return Ret::DataError;
    }

    // Stream Flags
    if stream_flags_decode(options, flags) {
        return Ret::OptionsError;
    }

    // Set Backward Size to indicate unknown value. That way
    // lzma_stream_flags_compare() can be used to compare Stream Header and
    // Stream Footer while keeping it useful also for comparing two Stream
    // Footers.
    options.backward_size = VLI_UNKNOWN;
    Ret::Ok
}

/// `lzma_stream_footer_decode`.
pub(crate) fn footer_decode(options: &mut StreamFlags, input: &[u8]) -> Ret {
    // Magic
    if input[4 * 2 + STREAM_FLAGS_SIZE..][..FOOTER_MAGIC.len()] != FOOTER_MAGIC {
        return Ret::FormatError;
    }

    // CRC32
    let crc = crc32(&input[4..4 + 4 + STREAM_FLAGS_SIZE], 0);
    if crc != read32le(input) {
        return Ret::DataError;
    }

    // Stream Flags
    if stream_flags_decode(options, &input[4 * 2..]) {
        return Ret::OptionsError;
    }

    // Backward Size
    options.backward_size = (u64::from(read32le(&input[4..])) + 1) * 4;
    Ret::Ok
}

/// `lzma_stream_flags_compare`.
pub(crate) fn compare(a: &StreamFlags, b: &StreamFlags) -> Ret {
    // We can compare only version 0 structures.
    if a.version != 0 || b.version != 0 {
        return Ret::OptionsError;
    }

    // Check type
    if a.check.0 > CHECK_ID_MAX || b.check.0 > CHECK_ID_MAX {
        return Ret::ProgError;
    }
    if a.check != b.check {
        return Ret::DataError;
    }

    // Backward Sizes are compared only if both are known.
    if a.backward_size != VLI_UNKNOWN && b.backward_size != VLI_UNKNOWN {
        if !is_backward_size_valid(a) || !is_backward_size_valid(b) {
            return Ret::ProgError;
        }
        if a.backward_size != b.backward_size {
            return Ret::DataError;
        }
    }
    Ret::Ok
}

/// `stream_flags_encode`: true if the check is out of range.
fn stream_flags_encode(options: &StreamFlags, out: &mut [u8]) -> bool {
    if options.check.0 > CHECK_ID_MAX {
        return true;
    }
    out[0] = 0x00;
    out[1] = options.check.0 as u8;
    false
}

/// `lzma_stream_header_encode`: the Stream Header into `out[..12]`.
pub(crate) fn header_encode(options: &StreamFlags, out: &mut [u8]) -> Ret {
    if options.version != 0 {
        return Ret::OptionsError;
    }

    out[..HEADER_MAGIC.len()].copy_from_slice(&HEADER_MAGIC);

    if stream_flags_encode(options, &mut out[HEADER_MAGIC.len()..]) {
        return Ret::ProgError;
    }

    let crc = crc32(
        &out[HEADER_MAGIC.len()..HEADER_MAGIC.len() + STREAM_FLAGS_SIZE],
        0,
    );
    write32le(&mut out[HEADER_MAGIC.len() + STREAM_FLAGS_SIZE..], crc);

    Ret::Ok
}

/// `lzma_stream_footer_encode`: the Stream Footer into `out[..12]`.
pub(crate) fn footer_encode(options: &StreamFlags, out: &mut [u8]) -> Ret {
    if options.version != 0 {
        return Ret::OptionsError;
    }

    if !is_backward_size_valid(options) {
        return Ret::ProgError;
    }

    write32le(&mut out[4..], (options.backward_size / 4 - 1) as u32);

    if stream_flags_encode(options, &mut out[2 * 4..]) {
        return Ret::ProgError;
    }

    let crc = crc32(&out[4..4 + 4 + STREAM_FLAGS_SIZE], 0);

    write32le(out, crc);

    out[2 * 4 + STREAM_FLAGS_SIZE..2 * 4 + STREAM_FLAGS_SIZE + FOOTER_MAGIC.len()]
        .copy_from_slice(&FOOTER_MAGIC);

    Ret::Ok
}
