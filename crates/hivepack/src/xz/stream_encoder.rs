//! The .xz encoder: port of `common/stream_encoder.c`,
//! `common/index_encoder.c`, `common/stream_buffer_encoder.c`, and of the
//! parts of `common/index.c` that the encoders use.

use crate::xz::block::{
    Block, BlockEncoder, UNPADDED_SIZE_MAX, UNPADDED_SIZE_MIN, block_buffer_bound64,
    block_buffer_encode, vli_ceil4,
};
use crate::xz::check::{CHECK_ID_MAX, Check, crc32};
use crate::xz::common::{Action, NextCoder, Ret, VLI_BYTES_MAX, VLI_MAX, VLI_UNKNOWN, bufcpy};
use crate::xz::filter::{Filter, filters_copy};
use crate::xz::index_hash::{INDEX_INDICATOR, index_size};
use crate::xz::stream_flags::{
    BACKWARD_SIZE_MAX, STREAM_HEADER_SIZE, StreamFlags, footer_encode, header_encode,
};
use crate::xz::vli;

/// `LZMA_BLOCK_HEADER_SIZE_MAX`, for the buffer of the Stream encoder.
const BLOCK_HEADER_SIZE_MAX: usize = 1024;

/// `lzma_index` as the encoders use it: the Records of the Blocks of one
/// Stream.
///
/// Differs from liblzma, without a difference to see: liblzma's
/// `lzma_index` holds Streams of groups of Records in trees, for finding
/// Blocks by offset; the encoders only append Records and write them out
/// in order, which a list does.
#[derive(Clone, Debug, Default)]
pub(crate) struct Index {
    /// Unpadded Size and Uncompressed Size of each Block.
    records: Vec<(u64, u64)>,
    /// The sum of the Unpadded Sizes, each rounded up to four bytes.
    total_size: u64,
    /// The sum of the Uncompressed Sizes.
    uncompressed_size: u64,
    /// The size of the List of Records field.
    index_list_size: u64,
}

impl Index {
    /// `lzma_index_append`.
    pub(crate) fn append(&mut self, unpadded_size: u64, uncompressed_size: u64) -> Ret {
        // Validate.
        if !(UNPADDED_SIZE_MIN..=UNPADDED_SIZE_MAX).contains(&unpadded_size)
            || uncompressed_size > VLI_MAX
        {
            return Ret::ProgError;
        }

        let compressed_base = self.total_size;
        let uncompressed_base = self.uncompressed_size;
        let index_list_size_add =
            u64::from(vli::size(unpadded_size) + vli::size(uncompressed_size));

        // Check that uncompressed size will not overflow.
        if uncompressed_base + uncompressed_size > VLI_MAX {
            return Ret::DataError;
        }

        // Check that the new unpadded sum will not overflow. This is
        // checked again in index_file_size(), but the unpadded sum is
        // passed to vli_ceil4() which expects a valid lzma_vli value.
        if compressed_base + unpadded_size > UNPADDED_SIZE_MAX {
            return Ret::DataError;
        }

        // Check that the file size will stay within limits.
        let count = self.records.len() as u64;
        if index_file_size(
            compressed_base + unpadded_size,
            count + 1,
            self.index_list_size + index_list_size_add,
        ) == VLI_UNKNOWN
        {
            return Ret::DataError;
        }

        // The size of the Index field must not exceed the maximum value
        // that can be stored in the Backward Size field.
        if index_size(count + 1, self.index_list_size + index_list_size_add) > BACKWARD_SIZE_MAX {
            return Ret::DataError;
        }

        // Add the new Record, and update the totals.
        self.records.push((unpadded_size, uncompressed_size));
        self.total_size += vli_ceil4(unpadded_size);
        self.uncompressed_size += uncompressed_size;
        self.index_list_size += index_list_size_add;

        Ret::Ok
    }

    /// `lzma_index_size`: the size of the Index field.
    pub(crate) fn size(&self) -> u64 {
        index_size(self.records.len() as u64, self.index_list_size)
    }

    /// `lzma_index_padding_size`.
    fn padding_size(&self) -> usize {
        // Index Indicator + Number of Records + List of Records + CRC32,
        // not counting the CRC32: (4 - that) & 3.
        let unpadded =
            1 + u64::from(vli::size(self.records.len() as u64)) + self.index_list_size + 4;
        (4u64.wrapping_sub(unpadded) & 3) as usize
    }
}

/// `index_file_size`, for one Stream from the start of the file without
/// Stream Padding: its size, or LZMA_VLI_UNKNOWN if it would be too big.
fn index_file_size(unpadded_sum: u64, record_count: u64, index_list_size: u64) -> u64 {
    // Stream Header + Blocks + Index + Stream Footer
    let mut file_size = 2 * STREAM_HEADER_SIZE as u64 + vli_ceil4(unpadded_sum);
    if file_size > VLI_MAX {
        return VLI_UNKNOWN;
    }

    // The same applies here.
    file_size += index_size(record_count, index_list_size);
    if file_size > VLI_MAX {
        return VLI_UNKNOWN;
    }

    file_size
}

/// The sequence of the Index encoder.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum IndexSequence {
    Indicator,
    Count,
    Unpadded,
    Uncompressed,
    Next,
    Padding,
    Crc32,
}

/// `lzma_index_coder`: the Index encoder.
pub(crate) struct IndexEncoder {
    sequence: IndexSequence,
    /// The Record being encoded, the next after it, and how many there
    /// are: the iterator.
    record: usize,
    next_record: usize,
    /// Position in integers
    pos: usize,
    /// CRC32 of the List of Records field
    crc32: u32,
}

impl IndexEncoder {
    /// `index_encoder_reset`.
    pub(crate) fn new() -> IndexEncoder {
        IndexEncoder {
            sequence: IndexSequence::Indicator,
            record: 0,
            next_record: 0,
            pos: 0,
            crc32: 0,
        }
    }

    /// `index_encode`.
    pub(crate) fn encode(&mut self, index: &Index, out: &mut [u8], out_pos: &mut usize) -> Ret {
        // Position where to start calculating CRC32. The idea is that we
        // need to call lzma_crc32() only once per call to index_encode().
        let out_start = *out_pos;

        // Return value to use if we return at the end of this function.
        let mut ret = Ret::Ok;

        // liblzma's switch falls through from SEQ_NEXT to SEQ_UNPADDED and
        // from SEQ_PADDING to SEQ_CRC32, without the loop's condition.
        'out: while *out_pos < out.len() {
            match self.sequence {
                IndexSequence::Indicator => {
                    out[*out_pos] = INDEX_INDICATOR;
                    *out_pos += 1;
                    self.sequence = IndexSequence::Count;
                    continue;
                }
                IndexSequence::Count => {
                    let count = index.records.len() as u64;
                    ret = vli::encode(count, &mut self.pos, out, out_pos);
                    if ret != Ret::StreamEnd {
                        break 'out;
                    }

                    ret = Ret::Ok;
                    self.pos = 0;
                    self.sequence = IndexSequence::Next;
                    continue;
                }
                IndexSequence::Next => {
                    // lzma_index_iter_next(LZMA_INDEX_ITER_BLOCK)
                    if self.next_record == index.records.len() {
                        // Get the size of the Index Padding field.
                        self.pos = index.padding_size();
                        self.sequence = IndexSequence::Padding;
                        continue;
                    }
                    self.record = self.next_record;
                    self.next_record += 1;

                    self.sequence = IndexSequence::Unpadded;
                }
                IndexSequence::Padding => {
                    if self.pos > 0 {
                        self.pos -= 1;
                        out[*out_pos] = 0x00;
                        *out_pos += 1;
                        continue;
                    }

                    // Finish the CRC32 calculation.
                    self.crc32 = crc32(&out[out_start..*out_pos], self.crc32);

                    self.sequence = IndexSequence::Crc32;
                }
                _ => {}
            }

            match self.sequence {
                IndexSequence::Unpadded | IndexSequence::Uncompressed => {
                    let (unpadded, uncompressed) = index.records[self.record];
                    let size = if self.sequence == IndexSequence::Unpadded {
                        unpadded
                    } else {
                        uncompressed
                    };

                    ret = vli::encode(size, &mut self.pos, out, out_pos);
                    if ret != Ret::StreamEnd {
                        break 'out;
                    }

                    ret = Ret::Ok;
                    self.pos = 0;

                    // Advance to SEQ_UNCOMPRESSED or SEQ_NEXT.
                    self.sequence = if self.sequence == IndexSequence::Unpadded {
                        IndexSequence::Uncompressed
                    } else {
                        IndexSequence::Next
                    };
                }
                IndexSequence::Crc32 => {
                    // We don't use the main loop, because we don't want
                    // coder->crc32 to be touched anymore.
                    loop {
                        if *out_pos == out.len() {
                            return Ret::Ok;
                        }

                        out[*out_pos] = (self.crc32 >> (self.pos * 8)) as u8;
                        *out_pos += 1;
                        self.pos += 1;
                        if self.pos >= 4 {
                            break;
                        }
                    }

                    return Ret::StreamEnd;
                }
                _ => return Ret::ProgError,
            }
        }

        // Update the CRC32.
        let out_used = *out_pos - out_start;
        if out_used > 0 {
            self.crc32 = crc32(&out[out_start..*out_pos], self.crc32);
        }

        ret
    }
}

/// `lzma_index_buffer_encode`: the Index in one call.
fn index_buffer_encode(index: &Index, out: &mut [u8], out_pos: &mut usize) -> Ret {
    // Validate the arguments.
    if *out_pos > out.len() {
        return Ret::ProgError;
    }

    // Don't try to encode if there's not enough output space.
    if ((out.len() - *out_pos) as u64) < index.size() {
        return Ret::BufError;
    }

    // Do the actual encoding. This should never fail, but store the
    // original *out_pos just in case.
    let out_start = *out_pos;
    let mut coder = IndexEncoder::new();
    let ret = coder.encode(index, out, out_pos);

    if ret == Ret::StreamEnd {
        Ret::Ok
    } else {
        *out_pos = out_start;
        Ret::ProgError
    }
}

/// The sequence of the Stream encoder.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Sequence {
    StreamHeader,
    BlockInit,
    BlockHeader,
    BlockEncode,
    IndexEncode,
    StreamFooter,
}

/// `lzma_stream_coder` of `stream_encoder.c`.
pub(crate) struct StreamEncoder {
    sequence: Sequence,
    /// True if Block encoder has been initialized by
    /// stream_encoder_init() or stream_encoder_update() and thus doesn't
    /// need to be initialized in stream_encode().
    block_encoder_is_initialized: bool,
    /// Block
    block_encoder: Option<BlockEncoder>,
    /// The filter chain currently in use
    filters: Vec<Filter>,
    /// The check of the Blocks.
    check: Check,
    /// Index encoder.
    index_encoder: IndexEncoder,
    /// Index to hold sizes of the Blocks
    index: Index,
    /// Read position in buffer[]
    buffer_pos: usize,
    /// Total number of bytes in buffer[]
    buffer_size: usize,
    /// Buffer to hold Stream Header, Block Header, and Stream Footer.
    /// Block Header has biggest maximum size.
    buffer: Box<[u8; BLOCK_HEADER_SIZE_MAX]>,
}

impl StreamEncoder {
    /// `stream_encoder_init`.
    pub(crate) fn new(filters: &[Filter], check: Check) -> Result<StreamEncoder, Ret> {
        let mut coder = StreamEncoder {
            sequence: Sequence::StreamHeader,
            block_encoder_is_initialized: false,
            block_encoder: None,
            filters: Vec::new(),
            check,
            index_encoder: IndexEncoder::new(),
            index: Index::default(),
            buffer_pos: 0,
            buffer_size: STREAM_HEADER_SIZE,
            buffer: Box::new([0; BLOCK_HEADER_SIZE_MAX]),
        };

        // Encode the Stream Header
        let stream_flags = StreamFlags {
            version: 0,
            backward_size: VLI_UNKNOWN,
            check,
        };
        let ret = header_encode(&stream_flags, &mut coder.buffer[..]);
        if ret != Ret::Ok {
            return Err(ret);
        }

        // Initialize the Block encoder. This way we detect unsupported
        // filter chains when initializing the Stream encoder instead of
        // giving an error after Stream Header has already been written
        // out.
        //
        // stream_encoder_update(), with no incomplete Block: the whole
        // chain is tried.
        let temp = filters_copy(filters)?;
        coder.block_encoder_is_initialized = false;
        coder.block_encoder_init(&temp)?;
        coder.block_encoder_is_initialized = true;
        coder.filters = temp;

        Ok(coder)
    }

    /// `block_encoder_init`: a Block encoder for `filters`.
    fn block_encoder_init(&mut self, filters: &[Filter]) -> Result<(), Ret> {
        // Prepare the Block options. Even though Block encoder doesn't
        // need compressed_size, uncompressed_size, and header_size to be
        // initialized, it is a good idea to do it here, because this way
        // we catch if someone gave us Filter ID that cannot be used in
        // Blocks/Streams.
        let mut block = Block::new();
        block.version = 0;
        block.check = self.check;
        block.filters = filters.to_vec();
        block.compressed_size = VLI_UNKNOWN;
        block.uncompressed_size = VLI_UNKNOWN;
        let ret = block.header_size_compute();
        if ret != Ret::Ok {
            return Err(ret);
        }

        // Initialize the actual Block encoder.
        self.block_encoder = Some(BlockEncoder::new(block, self.block_encoder.take())?);
        Ok(())
    }
}

impl NextCoder for StreamEncoder {
    /// `stream_encode`.
    fn code(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        output: &mut [u8],
        out_pos: &mut usize,
        action: Action,
    ) -> Ret {
        // Main loop
        while *out_pos < output.len() {
            match self.sequence {
                Sequence::StreamHeader | Sequence::BlockHeader | Sequence::StreamFooter => {
                    bufcpy(
                        &self.buffer[..self.buffer_size],
                        &mut self.buffer_pos,
                        output,
                        out_pos,
                    );
                    if self.buffer_pos < self.buffer_size {
                        return Ret::Ok;
                    }

                    if self.sequence == Sequence::StreamFooter {
                        return Ret::StreamEnd;
                    }

                    self.buffer_pos = 0;
                    self.sequence = if self.sequence == Sequence::StreamHeader {
                        Sequence::BlockInit
                    } else {
                        Sequence::BlockEncode
                    };
                }

                Sequence::BlockInit => {
                    if *in_pos == input.len() {
                        // If we are requested to flush or finish the
                        // current Block, return LZMA_STREAM_END immediately
                        // since there's nothing to do.
                        if action != Action::Finish {
                            return if action == Action::Run {
                                Ret::Ok
                            } else {
                                Ret::StreamEnd
                            };
                        }

                        // The application had used LZMA_FULL_FLUSH to
                        // finish the previous Block, but now wants to
                        // finish without encoding new data, or it is
                        // simply creating an empty Stream with no Blocks.
                        //
                        // Initialize the Index encoder, and continue to
                        // actually encoding the Index.
                        self.index_encoder = IndexEncoder::new();
                        self.sequence = Sequence::IndexEncode;
                        continue;
                    }

                    // Initialize the Block encoder unless it was already
                    // initialized by stream_encoder_init() or
                    // stream_encoder_update().
                    if !self.block_encoder_is_initialized {
                        let filters = core::mem::take(&mut self.filters);
                        let ret = self.block_encoder_init(&filters);
                        self.filters = filters;
                        if let Err(ret) = ret {
                            return ret;
                        }
                    }

                    // Make it false so that we don't skip the
                    // initialization with the next Block.
                    self.block_encoder_is_initialized = false;

                    // Encode the Block Header. This shouldn't fail since we
                    // have already initialized the Block encoder.
                    let Some(block_encoder) = self.block_encoder.as_ref() else {
                        return Ret::ProgError;
                    };
                    if block_encoder.block.header_encode(&mut self.buffer[..]) != Ret::Ok {
                        return Ret::ProgError;
                    }

                    self.buffer_size = block_encoder.block.header_size as usize;
                    self.sequence = Sequence::BlockHeader;
                }

                Sequence::BlockEncode => {
                    const CONVERT: [Action; 5] = [
                        Action::Run,
                        Action::SyncFlush,
                        Action::Finish,
                        Action::Finish,
                        Action::Finish,
                    ];

                    let Some(block_encoder) = self.block_encoder.as_mut() else {
                        return Ret::ProgError;
                    };
                    let ret = block_encoder.code(
                        input,
                        in_pos,
                        output,
                        out_pos,
                        CONVERT[action as usize],
                    );
                    if ret != Ret::StreamEnd || action == Action::SyncFlush {
                        return ret;
                    }

                    // Add a new Index Record.
                    let block = &block_encoder.block;
                    let unpadded_size = block.unpadded_size();
                    let ret = self.index.append(unpadded_size, block.uncompressed_size);
                    if ret != Ret::Ok {
                        return ret;
                    }

                    self.sequence = Sequence::BlockInit;
                }

                Sequence::IndexEncode => {
                    // Call the Index encoder. It doesn't take any input.
                    let ret = self.index_encoder.encode(&self.index, output, out_pos);
                    if ret != Ret::StreamEnd {
                        return ret;
                    }

                    // Encode the Stream Footer into coder->buffer.
                    let stream_flags = StreamFlags {
                        version: 0,
                        backward_size: self.index.size(),
                        check: self.check,
                    };

                    if footer_encode(&stream_flags, &mut self.buffer[..]) != Ret::Ok {
                        return Ret::ProgError;
                    }

                    self.buffer_size = STREAM_HEADER_SIZE;
                    self.sequence = Sequence::StreamFooter;
                }
            }
        }

        Ret::Ok
    }
}

// stream_buffer_encoder.c

/// `INDEX_BOUND`: maximum size of Index that has exactly one Record.
const INDEX_BOUND: u64 = (1 + 1 + 2 * VLI_BYTES_MAX as u64 + 4 + 3) & !3;

/// `HEADERS_BOUND`: Stream Header, Stream Footer, and Index.
const HEADERS_BOUND: u64 = 2 * STREAM_HEADER_SIZE as u64 + INDEX_BOUND;

/// `lzma_stream_buffer_bound`: the most space `stream_buffer_encode`
/// needs for `uncompressed_size` bytes, or 0 if too large.
pub(crate) fn stream_buffer_bound(uncompressed_size: usize) -> usize {
    // Catch the possible integer overflow and also prevent the size of the
    // Stream exceeding LZMA_VLI_MAX (theoretically possible on 64-bit
    // system).
    let block_bound = block_buffer_bound64(uncompressed_size as u64);
    if block_bound == 0 || block_bound > usize::MAX as u64 {
        return 0;
    }

    if (usize::MAX as u64).min(VLI_MAX) - block_bound < HEADERS_BOUND {
        return 0;
    }

    (block_bound + HEADERS_BOUND) as usize
}

/// `lzma_stream_buffer_encode`: `input` as one .xz Stream, in one call.
pub(crate) fn stream_buffer_encode(
    filters: &[Filter],
    check: Check,
    input: &[u8],
    out: &mut [u8],
    out_pos_ptr: &mut usize,
) -> Ret {
    // Sanity checks
    if check.0 > CHECK_ID_MAX || *out_pos_ptr > out.len() {
        return Ret::ProgError;
    }

    if !check.is_supported() {
        return Ret::UnsupportedCheck;
    }

    // Note for the paranoids: Index encoder prevents the Stream from
    // getting too big and still being accepted with LZMA_OK, and Block
    // encoder catches if the input is too big. So we don't need to
    // separately check if the buffers are too big.

    // Use a local copy. We update *out_pos_ptr only if everything
    // succeeds.
    let mut out_pos = *out_pos_ptr;

    // Check that there's enough space for both Stream Header and Stream
    // Footer.
    if out.len() - out_pos <= 2 * STREAM_HEADER_SIZE {
        return Ret::BufError;
    }

    // Reserve space for Stream Footer so we don't need to check for
    // available space again before encoding Stream Footer.
    let out_size = out.len() - STREAM_HEADER_SIZE;

    // Encode the Stream Header.
    let mut stream_flags = StreamFlags {
        version: 0,
        backward_size: VLI_UNKNOWN,
        check,
    };

    if header_encode(&stream_flags, &mut out[out_pos..]) != Ret::Ok {
        return Ret::ProgError;
    }

    out_pos += STREAM_HEADER_SIZE;

    // Encode a Block but only if there is at least one byte of input.
    let mut block = Block::new();
    block.version = 0;
    block.check = check;
    block.filters = filters.to_vec();

    if !input.is_empty() {
        let ret = block_buffer_encode(&mut block, input, &mut out[..out_size], &mut out_pos);
        if ret != Ret::Ok {
            return ret;
        }
    }

    // Index
    {
        // Create an Index. It will have one Record if there was at least
        // one byte of input to encode. Otherwise the Index will be empty.
        let mut index = Index::default();

        let mut ret = Ret::Ok;

        if !input.is_empty() {
            ret = index.append(block.unpadded_size(), block.uncompressed_size);
        }

        // If adding the Record was successful, encode the Index and get
        // its size which will be stored into Stream Footer.
        if ret == Ret::Ok {
            ret = index_buffer_encode(&index, &mut out[..out_size], &mut out_pos);

            stream_flags.backward_size = index.size();
        }

        if ret != Ret::Ok {
            return ret;
        }
    }

    // Stream Footer. We have already reserved space for this.
    if footer_encode(&stream_flags, &mut out[out_pos..]) != Ret::Ok {
        return Ret::ProgError;
    }

    out_pos += STREAM_HEADER_SIZE;

    // Everything went fine, make the new output position available to the
    // application.
    *out_pos_ptr = out_pos;
    Ret::Ok
}
