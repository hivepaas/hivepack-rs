//! Blocks: port of `common/block_header_decoder.c`,
//! `common/block_header_encoder.c`, `common/block_util.c`,
//! `common/block_decoder.c`, `common/block_encoder.c` and
//! `common/block_buffer_encoder.c`, with `lzma_block` of
//! `api/lzma/block.h`.

use crate::xz::check::{CHECK_ID_MAX, CHECK_SIZE_MAX, Check, CheckState, crc32};
use crate::xz::common::{
    Action, NextCoder, Ret, VLI_MAX, VLI_UNKNOWN, bufcpy, read32le, vli_is_valid, write32le,
};
use crate::xz::filter::{
    FILTER_LZMA2, FILTERS_MAX, Filter, FilterOptions, filter_flags_decode, filter_flags_encode,
    filter_flags_size, raw_decoder_init, raw_encoder_init, raw_encoder_reinit,
};
use crate::xz::lzma_common::{DICT_SIZE_MIN, LzmaOptions};
use crate::xz::lzma_encoder::LZMA2_CHUNK_MAX;
use crate::xz::vli;

/// `LZMA_BLOCK_HEADER_SIZE_MIN`.
pub(crate) const BLOCK_HEADER_SIZE_MIN: u32 = 8;
/// `LZMA_BLOCK_HEADER_SIZE_MAX`.
pub(crate) const BLOCK_HEADER_SIZE_MAX: u32 = 1024;

/// `UNPADDED_SIZE_MIN`.
pub(crate) const UNPADDED_SIZE_MIN: u64 = 5;
/// `UNPADDED_SIZE_MAX`.
pub(crate) const UNPADDED_SIZE_MAX: u64 = VLI_MAX & !3;

/// `lzma_block_header_size_decode`.
pub(crate) fn header_size_decode(b: u8) -> u32 {
    (u32::from(b) + 1) * 4
}

/// `vli_ceil4`.
pub(crate) fn vli_ceil4(vli: u64) -> u64 {
    (vli + 3) & !3
}

/// `lzma_block`: the options of a Block, as its header gives them and as
/// decoding it fills them in.
#[derive(Clone, Debug)]
pub(crate) struct Block {
    pub(crate) version: u32,
    pub(crate) header_size: u32,
    pub(crate) check: Check,
    pub(crate) compressed_size: u64,
    pub(crate) uncompressed_size: u64,
    pub(crate) filters: Vec<Filter>,
    pub(crate) raw_check: [u8; CHECK_SIZE_MAX],
    pub(crate) ignore_check: bool,
}

impl Block {
    pub(crate) fn new() -> Block {
        Block {
            version: 0,
            header_size: 0,
            check: Check::NONE,
            compressed_size: VLI_UNKNOWN,
            uncompressed_size: VLI_UNKNOWN,
            filters: Vec::new(),
            raw_check: [0; CHECK_SIZE_MAX],
            ignore_check: false,
        }
    }

    /// `lzma_block_header_decode`: the Block Header in `input`, whose size
    /// `header_size` already has.
    pub(crate) fn header_decode(&mut self, input: &[u8]) -> Ret {
        // Initialize the filter options array. This way the caller can
        // safely free() the options even if an error occurs in this
        // function.
        self.filters.clear();

        // Versions 0 and 1 are supported. If a newer version was specified,
        // we need to downgrade it.
        if self.version > 1 {
            self.version = 1;
        }

        // This isn't a Block Header option but since the decompressor will
        // read it if version >= 1, it's better to initialize it here than
        // to expect the caller to do it since in almost all cases this
        // should be false.
        self.ignore_check = false;

        // Validate Block Header Size and Check type. The caller must have
        // already set these, so it is a programming error if this test
        // fails.
        if header_size_decode(input[0]) != self.header_size || self.check.0 > CHECK_ID_MAX {
            return Ret::ProgError;
        }

        // Exclude the CRC32 field.
        let in_size = self.header_size as usize - 4;

        // Verify CRC32
        if crc32(&input[..in_size], 0) != read32le(&input[in_size..]) {
            return Ret::DataError;
        }

        // Check for unsupported flags.
        if input[1] & 0x3C != 0 {
            return Ret::OptionsError;
        }

        // Start after the Block Header Size and Block Flags fields.
        let header = &input[..in_size];
        let mut in_pos = 2;

        // Compressed Size
        if input[1] & 0x40 != 0 {
            match vli::decode_single(&mut self.compressed_size, header, &mut in_pos) {
                Ret::Ok => {}
                ret => return ret,
            }

            // Validate Compressed Size. This checks that it isn't zero and
            // that the total size of the Block is a valid VLI.
            if self.unpadded_size() == 0 {
                return Ret::DataError;
            }
        } else {
            self.compressed_size = VLI_UNKNOWN;
        }

        // Uncompressed Size
        if input[1] & 0x80 != 0 {
            match vli::decode_single(&mut self.uncompressed_size, header, &mut in_pos) {
                Ret::Ok => {}
                ret => return ret,
            }
        } else {
            self.uncompressed_size = VLI_UNKNOWN;
        }

        // Filter Flags
        let filter_count = usize::from(input[1] & 3) + 1;
        for _ in 0..filter_count {
            match filter_flags_decode(header, &mut in_pos) {
                Ok(filter) => self.filters.push(filter),
                Err(ret) => {
                    self.filters.clear();
                    return ret;
                }
            }
        }

        // Padding
        while in_pos < in_size {
            let byte = input[in_pos];
            in_pos += 1;
            if byte != 0x00 {
                self.filters.clear();
                // Possibly some new field present so use
                // LZMA_OPTIONS_ERROR instead of LZMA_DATA_ERROR.
                return Ret::OptionsError;
            }
        }
        Ret::Ok
    }

    /// `lzma_block_unpadded_size`: 0 for invalid options, LZMA_VLI_UNKNOWN
    /// while the compressed size is not known.
    pub(crate) fn unpadded_size(&self) -> u64 {
        // Validate the values that we are interested in i.e. all but
        // Uncompressed Size and the filters.
        if self.version > 1
            || self.header_size < BLOCK_HEADER_SIZE_MIN
            || self.header_size > BLOCK_HEADER_SIZE_MAX
            || self.header_size & 3 != 0
            || !vli_is_valid(self.compressed_size)
            || self.compressed_size == 0
            || self.check.0 > CHECK_ID_MAX
        {
            return 0;
        }

        // If Compressed Size is unknown, return that we cannot know size of
        // the Block either.
        if self.compressed_size == VLI_UNKNOWN {
            return VLI_UNKNOWN;
        }

        // Calculate Unpadded Size and validate it.
        let unpadded_size =
            self.compressed_size + u64::from(self.header_size) + u64::from(self.check.size());
        if unpadded_size > UNPADDED_SIZE_MAX {
            return 0;
        }
        unpadded_size
    }
}

/// The sequence of the Block decoder.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sequence {
    Code,
    Padding,
    Check,
}

/// `lzma_block_coder` of `block_decoder.c`.
pub(crate) struct BlockDecoder {
    sequence: Sequence,
    /// The filters.
    next: Box<dyn NextCoder>,
    /// Decoding options; the sizes are filled in once the Block ends, as
    /// liblzma fills in the application's `lzma_block`.
    pub(crate) block: Block,
    /// Compressed Size calculated while decoding.
    compressed_size: u64,
    /// Uncompressed Size calculated while decoding.
    uncompressed_size: u64,
    /// Maximum allowed Compressed Size; this takes into account the size of
    /// the Block Header and Check fields when Compressed Size is unknown.
    compressed_limit: u64,
    /// Maximum allowed Uncompressed Size.
    uncompressed_limit: u64,
    /// Position when reading the Check field.
    check_pos: usize,
    /// Check of the uncompressed data.
    check: CheckState,
    /// True if the integrity check won't be calculated and verified.
    ignore_check: bool,
}

/// `is_size_valid`.
fn is_size_valid(size: u64, reference: u64) -> bool {
    reference == VLI_UNKNOWN || reference == size
}

impl BlockDecoder {
    /// `lzma_block_decoder_init`.
    pub(crate) fn new(block: Block) -> Result<BlockDecoder, Ret> {
        // Validate the options. lzma_block_unpadded_size() does that for us
        // except for Uncompressed Size and filters. Filters are validated
        // by the raw decoder.
        if block.unpadded_size() == 0 || !vli_is_valid(block.uncompressed_size) {
            return Err(Ret::ProgError);
        }

        // Basic initializations
        let compressed_limit = if block.compressed_size == VLI_UNKNOWN {
            (VLI_MAX & !3) - u64::from(block.header_size) - u64::from(block.check.size())
        } else {
            block.compressed_size
        };
        let uncompressed_limit = if block.uncompressed_size == VLI_UNKNOWN {
            VLI_MAX
        } else {
            block.uncompressed_size
        };

        // If the Check ID is not supported, we will just skip it.
        let check = CheckState::new(block.check);
        let ignore_check = if block.version >= 1 {
            block.ignore_check
        } else {
            false
        };

        // Initialize the filter chain.
        let next = raw_decoder_init(&block.filters)?;
        Ok(BlockDecoder {
            sequence: Sequence::Code,
            next,
            block,
            compressed_size: 0,
            uncompressed_size: 0,
            compressed_limit,
            uncompressed_limit,
            check_pos: 0,
            check,
            ignore_check,
        })
    }
}

impl NextCoder for BlockDecoder {
    /// `block_decode`.
    fn code(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        output: &mut [u8],
        out_pos: &mut usize,
        action: Action,
    ) -> Ret {
        if self.sequence == Sequence::Code {
            // Limit the amount of input and output space that we give to
            // the raw decoder based on the information we have (or don't
            // have) from Block Header.
            let in_start = *in_pos;
            let out_start = *out_pos;
            let in_stop = *in_pos
                + ((input.len() - *in_pos) as u64).min(self.compressed_limit - self.compressed_size)
                    as usize;
            let out_stop = *out_pos
                + ((output.len() - *out_pos) as u64)
                    .min(self.uncompressed_limit - self.uncompressed_size)
                    as usize;

            let ret = self.next.code(
                &input[..in_stop],
                in_pos,
                &mut output[..out_stop],
                out_pos,
                action,
            );

            let in_used = *in_pos - in_start;
            let out_used = *out_pos - out_start;

            // Because we have limited the input and output sizes, we know
            // that these cannot grow too big or overflow.
            self.compressed_size += in_used as u64;
            self.uncompressed_size += out_used as u64;

            if ret == Ret::Ok {
                let comp_done = self.compressed_size == self.block.compressed_size;
                let uncomp_done = self.uncompressed_size == self.block.uncompressed_size;

                // If both input and output amounts match the sizes in Block
                // Header but we still got LZMA_OK instead of
                // LZMA_STREAM_END, the file is broken.
                if comp_done && uncomp_done {
                    return Ret::DataError;
                }

                // If the decoder has consumed all the input that it needs
                // but it still couldn't fill the output buffer or return
                // LZMA_STREAM_END, the file is broken.
                if comp_done && *out_pos < output.len() {
                    return Ret::DataError;
                }

                // If the decoder has produced all the output but it still
                // didn't return LZMA_STREAM_END or consume more input
                // (for example, detecting an end of payload marker may need
                // more input but produce no output) the file is broken.
                if uncomp_done && *in_pos < input.len() {
                    return Ret::DataError;
                }
            }

            // Don't waste time updating the integrity check if it will be
            // ignored. Also skip it if no new output was produced.
            if !self.ignore_check && out_used > 0 {
                self.check
                    .update(self.block.check, &output[out_start..out_start + out_used]);
            }

            if ret != Ret::StreamEnd {
                return ret;
            }

            // Compressed and Uncompressed Sizes are now at their final
            // values. Verify that they match the values given to us.
            if !is_size_valid(self.compressed_size, self.block.compressed_size)
                || !is_size_valid(self.uncompressed_size, self.block.uncompressed_size)
            {
                return Ret::DataError;
            }

            // Copy the values into coder->block. The caller may use this
            // information to construct Index.
            self.block.compressed_size = self.compressed_size;
            self.block.uncompressed_size = self.uncompressed_size;

            self.sequence = Sequence::Padding;
        }

        if self.sequence == Sequence::Padding {
            // Compressed Data is padded to a multiple of four bytes.
            while self.compressed_size & 3 != 0 {
                if *in_pos >= input.len() {
                    return Ret::Ok;
                }

                // We use compressed_size here just get the Padding right.
                // The actual Compressed Size was stored to coder->block
                // already, and won't be modified by us anymore.
                self.compressed_size += 1;

                let byte = input[*in_pos];
                *in_pos += 1;
                if byte != 0x00 {
                    return Ret::DataError;
                }
            }

            if self.block.check == Check::NONE {
                return Ret::StreamEnd;
            }

            if !self.ignore_check {
                self.check.finish(self.block.check);
            }

            self.sequence = Sequence::Check;
        }

        // Sequence::Check
        let check_size = self.block.check.size() as usize;
        bufcpy(
            input,
            in_pos,
            &mut self.block.raw_check[..check_size],
            &mut self.check_pos,
        );
        if self.check_pos < check_size {
            return Ret::Ok;
        }

        // Validate the Check only if we support it. coder->check.buffer
        // may be uninitialized when the Check ID is not supported.
        if !self.ignore_check
            && self.block.check.is_supported()
            && self.block.raw_check[..check_size] != self.check.buffer[..check_size]
        {
            return Ret::DataError;
        }
        Ret::StreamEnd
    }
}

/// `COMPRESSED_SIZE_MAX`: the maximum Compressed Size of a Block, so that
/// the whole Block stays a valid VLI, its padding included.
pub(crate) const COMPRESSED_SIZE_MAX: u64 =
    (VLI_MAX - BLOCK_HEADER_SIZE_MAX as u64 - CHECK_SIZE_MAX as u64) & !3;

impl Block {
    /// `lzma_block_header_size`: the size of the Block Header, into
    /// `header_size`.
    pub(crate) fn header_size_compute(&mut self) -> Ret {
        if self.version > 1 {
            return Ret::OptionsError;
        }

        // Block Header Size + Block Flags + CRC32.
        let mut size: u32 = 1 + 1 + 4;

        // Compressed Size
        if self.compressed_size != VLI_UNKNOWN {
            let add = vli::size(self.compressed_size);
            if add == 0 || self.compressed_size == 0 {
                return Ret::ProgError;
            }

            size += add;
        }

        // Uncompressed Size
        if self.uncompressed_size != VLI_UNKNOWN {
            let add = vli::size(self.uncompressed_size);
            if add == 0 {
                return Ret::ProgError;
            }

            size += add;
        }

        // List of Filter Flags
        if self.filters.is_empty() {
            return Ret::ProgError;
        }

        for (i, filter) in self.filters.iter().enumerate() {
            // Don't allow too many filters.
            if i == FILTERS_MAX {
                return Ret::ProgError;
            }

            match filter_flags_size(filter) {
                Ok(add) => size += add,
                Err(ret) => return ret,
            }
        }

        // Pad to a multiple of four bytes.
        self.header_size = (size + 3) & !3;

        // NOTE: We don't verify that the encoded size of the Block stays
        // within limits. This is because it is possible that we are called
        // with exaggerated Compressed Size (e.g. LZMA_VLI_MAX) to reserve
        // space for Block Header, and later called again with lower,
        // real values.

        Ret::Ok
    }

    /// `lzma_block_header_encode`: the Block Header into
    /// `out[..header_size]`.
    pub(crate) fn header_encode(&self, out: &mut [u8]) -> Ret {
        // Validate everything but filters.
        if self.unpadded_size() == 0 || !vli_is_valid(self.uncompressed_size) {
            return Ret::ProgError;
        }

        // Size of the Block Header without CRC32
        let out_size = self.header_size as usize - 4;

        // Encode the Block Header Size.
        out[0] = (out_size / 4) as u8;

        // We write Block Flags in pieces.
        out[1] = 0x00;
        let mut out_pos = 2;

        // Compressed Size
        if self.compressed_size != VLI_UNKNOWN {
            let ret = vli::encode_single(self.compressed_size, &mut out[..out_size], &mut out_pos);
            if ret != Ret::Ok {
                return ret;
            }

            out[1] |= 0x40;
        }

        // Uncompressed Size
        if self.uncompressed_size != VLI_UNKNOWN {
            let ret =
                vli::encode_single(self.uncompressed_size, &mut out[..out_size], &mut out_pos);
            if ret != Ret::Ok {
                return ret;
            }

            out[1] |= 0x80;
        }

        // Filter Flags
        if self.filters.is_empty() {
            return Ret::ProgError;
        }

        let mut filter_count = 0;
        loop {
            // There can be a maximum of four filters.
            if filter_count == FILTERS_MAX {
                return Ret::ProgError;
            }

            let ret = filter_flags_encode(
                &self.filters[filter_count],
                &mut out[..out_size],
                &mut out_pos,
            );
            if ret != Ret::Ok {
                return ret;
            }

            filter_count += 1;
            if filter_count == self.filters.len() {
                break;
            }
        }

        out[1] |= (filter_count - 1) as u8;

        // Padding
        out[out_pos..out_size].fill(0);

        // CRC32
        let crc = crc32(&out[..out_size], 0);
        write32le(&mut out[out_size..], crc);

        Ret::Ok
    }
}

/// The sequence of the Block encoder.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum EncSequence {
    Code,
    Padding,
    Check,
}

/// `lzma_block_coder` of `block_encoder.c`.
pub(crate) struct BlockEncoder {
    /// The filters in the chain.
    next: Box<dyn NextCoder>,
    /// Encoding options; the sizes are written back here when the
    /// encoding has been finished.
    pub(crate) block: Block,
    sequence: EncSequence,
    /// Compressed Size calculated while encoding
    compressed_size: u64,
    /// Uncompressed Size calculated while encoding
    uncompressed_size: u64,
    /// Position in the Check field
    pos: usize,
    /// Check of the uncompressed data
    check: CheckState,
}

impl BlockEncoder {
    /// `lzma_block_encoder_init`, with the coder of the Block before if
    /// any, whose LZ encoder keeps its memory, as liblzma's does.
    pub(crate) fn new(block: Block, old: Option<BlockEncoder>) -> Result<BlockEncoder, Ret> {
        // The contents of the structure may depend on the version so check
        // the version first.
        if block.version > 1 {
            return Err(Ret::OptionsError);
        }

        // If the Check ID is not supported, we cannot calculate the check
        // and thus not create a proper Block.
        if block.check.0 > CHECK_ID_MAX {
            return Err(Ret::ProgError);
        }

        if !block.check.is_supported() {
            return Err(Ret::UnsupportedCheck);
        }

        // Initialize the check, then the requested filters.
        let check = CheckState::new(block.check);
        let next = raw_encoder_reinit(&block.filters, old.map(|old| old.next))?;

        Ok(BlockEncoder {
            next,
            block,
            sequence: EncSequence::Code,
            compressed_size: 0,
            uncompressed_size: 0,
            pos: 0,
            check,
        })
    }
}

impl NextCoder for BlockEncoder {
    /// `block_encode`.
    fn code(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        output: &mut [u8],
        out_pos: &mut usize,
        action: Action,
    ) -> Ret {
        // Check that our amount of input stays in proper limits.
        if VLI_MAX - self.uncompressed_size < (input.len() - *in_pos) as u64 {
            return Ret::DataError;
        }

        if self.sequence == EncSequence::Code {
            let in_start = *in_pos;
            let out_start = *out_pos;

            let ret = self.next.code(input, in_pos, output, out_pos, action);

            let in_used = *in_pos - in_start;
            let out_used = *out_pos - out_start;

            if COMPRESSED_SIZE_MAX - self.compressed_size < out_used as u64 {
                return Ret::DataError;
            }

            self.compressed_size += out_used as u64;

            // No need to check for overflow because we have already
            // checked it at the beginning of this function.
            self.uncompressed_size += in_used as u64;

            if in_used > 0 {
                self.check
                    .update(self.block.check, &input[in_start..*in_pos]);
            }

            if ret != Ret::StreamEnd || action == Action::SyncFlush {
                return ret;
            }

            // Copy the values into coder->block. The caller may use this
            // information to construct Index.
            self.block.compressed_size = self.compressed_size;
            self.block.uncompressed_size = self.uncompressed_size;

            self.sequence = EncSequence::Padding;
        }

        if self.sequence == EncSequence::Padding {
            // Pad Compressed Data to a multiple of four bytes. We can use
            // coder->compressed_size for this since we don't need it for
            // anything else anymore.
            while self.compressed_size & 3 != 0 {
                if *out_pos >= output.len() {
                    return Ret::Ok;
                }

                output[*out_pos] = 0x00;
                *out_pos += 1;
                self.compressed_size += 1;
            }

            if self.block.check == Check::NONE {
                return Ret::StreamEnd;
            }

            self.check.finish(self.block.check);

            self.sequence = EncSequence::Check;
        }

        // SEQ_CHECK
        let check_size = self.block.check.size() as usize;
        bufcpy(
            &self.check.buffer[..check_size],
            &mut self.pos,
            output,
            out_pos,
        );
        if self.pos < check_size {
            return Ret::Ok;
        }

        self.block.raw_check[..check_size].copy_from_slice(&self.check.buffer[..check_size]);
        Ret::StreamEnd
    }
}

// block_buffer_encoder.c

/// `HEADERS_BOUND`: the size of the Block Header, Block Padding and Check
/// at most.
const BLOCK_HEADERS_BOUND: u64 =
    (1 + 1 + 2 * crate::xz::common::VLI_BYTES_MAX as u64 + 3 + 4 + CHECK_SIZE_MAX as u64 + 3) & !3;

/// `lzma2_bound`: the size of the LZMA2 data of `uncompressed_size` bytes
/// stored as uncompressed chunks, or 0 if too large.
fn lzma2_bound(uncompressed_size: u64) -> u64 {
    // Prevent integer overflow in overhead calculation.
    if uncompressed_size > COMPRESSED_SIZE_MAX {
        return 0;
    }

    // Calculate the exact overhead of the LZMA2 headers: Round
    // uncompressed_size up to the next multiple of LZMA2_CHUNK_MAX,
    // multiply by the size of per-chunk header, and add one byte for the
    // end marker.
    let overhead = uncompressed_size.div_ceil(u64::from(LZMA2_CHUNK_MAX)) * 3 + 1;

    // Catch the possible integer overflow.
    if COMPRESSED_SIZE_MAX - overhead < uncompressed_size {
        return 0;
    }

    uncompressed_size + overhead
}

/// `lzma_block_buffer_bound64`.
pub(crate) fn block_buffer_bound64(uncompressed_size: u64) -> u64 {
    // If the data doesn't compress, we always use uncompressed LZMA2
    // chunks.
    let mut lzma2_size = lzma2_bound(uncompressed_size);
    if lzma2_size == 0 {
        return 0;
    }

    // Take Block Padding into account.
    lzma2_size = (lzma2_size + 3) & !3;

    // No risk of integer overflow because lzma2_bound() already takes
    // into account the size of the headers in the Block.
    BLOCK_HEADERS_BOUND + lzma2_size
}

/// `block_encode_uncompressed`: the data as uncompressed LZMA2 chunks.
fn block_encode_uncompressed(
    block: &mut Block,
    input: &[u8],
    out: &mut [u8],
    out_pos: &mut usize,
) -> Ret {
    // Use LZMA2 uncompressed chunks. We wouldn't need a dictionary at all,
    // but we set this to the minimum value to keep the Filter Flags
    // valid.
    let lzma2 = LzmaOptions {
        dict_size: DICT_SIZE_MIN,
        ..LzmaOptions::default()
    };

    let filters_orig = core::mem::replace(
        &mut block.filters,
        vec![Filter {
            id: FILTER_LZMA2,
            options: Some(FilterOptions::Lzma(lzma2)),
        }],
    );

    // Set the above filter options to *block temporarily so that we can
    // encode the Block Header.
    if block.header_size_compute() != Ret::Ok {
        block.filters = filters_orig;
        return Ret::ProgError;
    }

    // Check that there's enough output space. The caller has already set
    // block->compressed_size to what lzma2_bound() has returned, so we can
    // reuse that value. We know that compressed_size is a known valid VLI
    // and header_size is a small value so their sum will never overflow.
    if ((out.len() - *out_pos) as u64) < u64::from(block.header_size) + block.compressed_size {
        block.filters = filters_orig;
        return Ret::BufError;
    }

    if block.header_encode(&mut out[*out_pos..]) != Ret::Ok {
        block.filters = filters_orig;
        return Ret::ProgError;
    }

    block.filters = filters_orig;
    *out_pos += block.header_size as usize;

    // Encode the data using LZMA2 uncompressed chunks.
    let mut in_pos = 0;
    let mut control = 0x01; // Dictionary reset

    while in_pos < input.len() {
        // Control byte: Indicate uncompressed chunk, of which the first
        // resets the dictionary.
        out[*out_pos] = control;
        *out_pos += 1;
        control = 0x02; // No dictionary reset

        // Size of the uncompressed chunk
        let copy_size = (input.len() - in_pos).min(LZMA2_CHUNK_MAX as usize);
        out[*out_pos] = ((copy_size - 1) >> 8) as u8;
        out[*out_pos + 1] = ((copy_size - 1) & 0xFF) as u8;
        *out_pos += 2;

        // The actual data
        out[*out_pos..*out_pos + copy_size].copy_from_slice(&input[in_pos..in_pos + copy_size]);

        in_pos += copy_size;
        *out_pos += copy_size;
    }

    // End marker
    out[*out_pos] = 0x00;
    *out_pos += 1;

    Ret::Ok
}

/// `block_encode_normal`: the data compressed with the Block's filters,
/// or LZMA_BUF_ERROR if it does not fit in `out` and its Compressed Size
/// from `lzma2_bound`.
fn block_encode_normal(
    block: &mut Block,
    input: &[u8],
    out: &mut [u8],
    out_pos: &mut usize,
) -> Ret {
    // Find out the size of the Block Header.
    let ret = block.header_size_compute();
    if ret != Ret::Ok {
        return ret;
    }

    // Reserve space for the Block Header and skip it for now.
    if out.len() - *out_pos <= block.header_size as usize {
        return Ret::BufError;
    }

    let out_start = *out_pos;
    *out_pos += block.header_size as usize;

    // Limit out_size so that we stop encoding if the output would grow
    // bigger than what uncompressed Block would be.
    let mut out_size = out.len();
    if (out_size - *out_pos) as u64 > block.compressed_size {
        out_size = *out_pos + block.compressed_size as usize;
    }

    // TODO: In many common cases this could be optimized to use
    // significantly less memory.
    let mut ret = match raw_encoder_init(&block.filters) {
        Ok(mut raw_encoder) => {
            let mut in_pos = 0;
            raw_encoder.code(
                input,
                &mut in_pos,
                &mut out[..out_size],
                out_pos,
                Action::Finish,
            )
        }
        Err(ret) => ret,
    };

    if ret == Ret::StreamEnd {
        // Compression was successful. Write the Block Header.
        block.compressed_size = (*out_pos - (out_start + block.header_size as usize)) as u64;
        ret = block.header_encode(&mut out[out_start..]);
        if ret != Ret::Ok {
            ret = Ret::ProgError;
        }
    } else if ret == Ret::Ok {
        // Output buffer became full.
        ret = Ret::BufError;
    }

    // Reset *out_pos if something went wrong.
    if ret != Ret::Ok {
        *out_pos = out_start;
    }

    ret
}

/// `lzma_block_buffer_encode`: `input` as one Block, in one call.
pub(crate) fn block_buffer_encode(
    block: &mut Block,
    input: &[u8],
    out: &mut [u8],
    out_pos: &mut usize,
) -> Ret {
    block_buffer_encode_with(block, input, out, out_pos, true)
}

/// `lzma_block_uncomp_encode`: `input` as one Block of uncompressed LZMA2
/// chunks, in one call.
pub(crate) fn block_uncomp_encode(
    block: &mut Block,
    input: &[u8],
    out: &mut [u8],
    out_pos: &mut usize,
) -> Ret {
    block_buffer_encode_with(block, input, out, out_pos, false)
}

/// `block_buffer_encode` of `block_buffer_encoder.c`.
fn block_buffer_encode_with(
    block: &mut Block,
    input: &[u8],
    out: &mut [u8],
    out_pos: &mut usize,
    try_to_compress: bool,
) -> Ret {
    // Validate the arguments.
    if *out_pos > out.len() {
        return Ret::ProgError;
    }

    // The contents of the structure may depend on the version so check
    // the version before validating the contents of *block.
    if block.version > 1 {
        return Ret::OptionsError;
    }

    if block.check.0 > CHECK_ID_MAX || block.filters.is_empty() {
        return Ret::ProgError;
    }

    if !block.check.is_supported() {
        return Ret::UnsupportedCheck;
    }

    // Size of a Block has to be a multiple of four, so limit the size
    // here already. This way we don't need to check it again when adding
    // Block Padding.
    let mut out_size = out.len() - ((out.len() - *out_pos) & 3);

    // Get the size of the Check field.
    let check_size = block.check.size() as usize;

    // Reserve space for the Check field.
    if out_size - *out_pos <= check_size {
        return Ret::BufError;
    }

    out_size -= check_size;

    // Initialize block->uncompressed_size and calculate the worst-case
    // value for block->compressed_size.
    block.uncompressed_size = input.len() as u64;
    block.compressed_size = lzma2_bound(input.len() as u64);
    if block.compressed_size == 0 {
        return Ret::DataError;
    }

    // Do the actual compression.
    let mut ret = Ret::BufError;
    if try_to_compress {
        ret = block_encode_normal(block, input, &mut out[..out_size], out_pos);
    }

    if ret != Ret::Ok {
        // If the error was something else than output buffer becoming
        // full, return the error now.
        if ret != Ret::BufError {
            return ret;
        }

        // The data was incompressible (at least with the options given to
        // us) or the output buffer was too small. Use the uncompressed
        // chunks of LZMA2 to wrap the data into a valid Block. If we
        // haven't been given enough output space, even this may fail.
        ret = block_encode_uncompressed(block, input, &mut out[..out_size], out_pos);
        if ret != Ret::Ok {
            return ret;
        }
    }

    // Block Padding. No buffer overflow here, because we already adjusted
    // out_size so that (out_size - out_start) is a multiple of four.
    let mut i = block.compressed_size;
    while i & 3 != 0 {
        out[*out_pos] = 0x00;
        *out_pos += 1;
        i += 1;
    }

    // If there's no Check field, we are done now.
    if check_size > 0 {
        // Calculate the integrity check. We reserved space for the Check
        // field earlier so we don't need to check for available output
        // space here.
        let mut check = CheckState::new(block.check);
        check.update(block.check, input);
        check.finish(block.check);

        block.raw_check[..check_size].copy_from_slice(&check.buffer[..check_size]);
        out[*out_pos..*out_pos + check_size].copy_from_slice(&check.buffer[..check_size]);
        *out_pos += check_size;
    }

    Ret::Ok
}
