//! The .xz Stream decoder: port of `common/stream_decoder.c`.

use crate::xz::block::{BLOCK_HEADER_SIZE_MAX, Block, BlockDecoder, header_size_decode};
use crate::xz::check::Check;
use crate::xz::common::{
    Action, CONCATENATED, IGNORE_CHECK, MEMUSAGE_BASE, NextCoder, Ret, SUPPORTED_FLAGS,
    TELL_ANY_CHECK, TELL_NO_CHECK, TELL_UNSUPPORTED_CHECK, bufcpy,
};
use crate::xz::filter::raw_decoder_memusage;
use crate::xz::index_hash::{INDEX_INDICATOR, IndexHash};
use crate::xz::stream_flags::{self, STREAM_HEADER_SIZE, StreamFlags};

/// The sequence of the Stream decoder.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sequence {
    StreamHeader,
    BlockHeader,
    BlockInit,
    BlockRun,
    Index,
    StreamFooter,
    StreamPadding,
}

/// `lzma_stream_coder` of `stream_decoder.c`.
pub(crate) struct StreamDecoder {
    sequence: Sequence,
    /// Block decoder.
    block_decoder: Option<BlockDecoder>,
    /// Block options decoded by the Block Header decoder and used by the
    /// Block decoder.
    block_options: Block,
    /// Stream Flags from Stream Header.
    stream_flags: StreamFlags,
    /// Index is hashed so that it can be compared to the sizes of Blocks
    /// with O(1) memory usage.
    index_hash: IndexHash,
    /// Memory usage limit.
    memlimit: u64,
    /// Amount of memory actually needed (only an estimate).
    memusage: u64,
    /// If true, LZMA_NO_CHECK is returned if the Stream has no integrity
    /// check.
    tell_no_check: bool,
    /// If true, LZMA_UNSUPPORTED_CHECK is returned if the Stream has an
    /// integrity check that isn't supported by this liblzma build.
    tell_unsupported_check: bool,
    /// If true, LZMA_GET_CHECK is returned after decoding Stream Header.
    tell_any_check: bool,
    /// If true, we will tell the Block decoder to skip calculating and
    /// verifying the integrity check.
    ignore_check: bool,
    /// If true, we will decode concatenated Streams that possibly have
    /// Stream Padding between or after them. LZMA_STREAM_END is returned
    /// once the application isn't giving us any new input (LZMA_FINISH),
    /// and we aren't in the middle of a Stream, and possible Stream Padding
    /// is a multiple of four bytes.
    concatenated: bool,
    /// When decoding concatenated Streams, this is true as long as we are
    /// decoding the first Stream. This is needed to avoid misleading
    /// LZMA_FORMAT_ERROR in case the later Streams don't have valid magic
    /// bytes.
    first_stream: bool,
    /// Write position in buffer[] and position in Stream Padding.
    pos: usize,
    /// Buffer to hold Stream Header, Block Header, and Stream Footer. Block
    /// Header has biggest maximum size.
    buffer: Box<[u8; BLOCK_HEADER_SIZE_MAX as usize]>,
}

impl StreamDecoder {
    /// `lzma_stream_decoder_init`.
    pub(crate) fn new(memlimit: u64, flags: u32) -> Result<StreamDecoder, Ret> {
        // Validate the flags.
        if flags & !SUPPORTED_FLAGS != 0 {
            return Err(Ret::OptionsError);
        }
        let mut coder = StreamDecoder {
            sequence: Sequence::StreamHeader,
            block_decoder: None,
            block_options: Block::new(),
            stream_flags: StreamFlags::new(),
            index_hash: IndexHash::new(),
            memlimit: memlimit.max(1),
            memusage: MEMUSAGE_BASE,
            tell_no_check: flags & TELL_NO_CHECK != 0,
            tell_unsupported_check: flags & TELL_UNSUPPORTED_CHECK != 0,
            tell_any_check: flags & TELL_ANY_CHECK != 0,
            ignore_check: flags & IGNORE_CHECK != 0,
            concatenated: flags & CONCATENATED != 0,
            first_stream: true,
            pos: 0,
            buffer: Box::new([0; BLOCK_HEADER_SIZE_MAX as usize]),
        };
        coder.reset();
        Ok(coder)
    }

    /// `stream_decoder_reset`.
    fn reset(&mut self) {
        // Initialize the Index hash used to verify the Index.
        self.index_hash = IndexHash::new();

        // Reset the rest of the variables.
        self.sequence = Sequence::StreamHeader;
        self.pos = 0;
    }
}

impl NextCoder for StreamDecoder {
    /// `stream_decode`.
    fn code(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        output: &mut [u8],
        out_pos: &mut usize,
        action: Action,
    ) -> Ret {
        // When decoding the actual Block, it may be able to produce more
        // output even if we don't give it any new input.
        loop {
            match self.sequence {
                Sequence::StreamHeader => {
                    // Copy the Stream Header to the internal buffer.
                    bufcpy(
                        input,
                        in_pos,
                        &mut self.buffer[..STREAM_HEADER_SIZE],
                        &mut self.pos,
                    );

                    // Return if we didn't get the whole Stream Header yet.
                    if self.pos < STREAM_HEADER_SIZE {
                        return Ret::Ok;
                    }
                    self.pos = 0;

                    // Decode the Stream Header.
                    let ret = stream_flags::header_decode(&mut self.stream_flags, &self.buffer[..]);
                    if ret != Ret::Ok {
                        return if ret == Ret::FormatError && !self.first_stream {
                            Ret::DataError
                        } else {
                            ret
                        };
                    }

                    // If we are decoding concatenated Streams, and the
                    // later Streams have invalid Header Magic Bytes, we
                    // give LZMA_DATA_ERROR instead of LZMA_FORMAT_ERROR.
                    self.first_stream = false;

                    // Copy the type of the Check so that Block Header and
                    // Block decoders see it.
                    self.block_options.check = self.stream_flags.check;

                    // Even if we return LZMA_*_CHECK below, we want to
                    // continue from Block Header decoding.
                    self.sequence = Sequence::BlockHeader;

                    // Detect if there's no integrity check or if it is
                    // unsupported if those were requested by the
                    // application.
                    if self.tell_no_check && self.stream_flags.check == Check::NONE {
                        return Ret::NoCheck;
                    }
                    if self.tell_unsupported_check && !self.stream_flags.check.is_supported() {
                        return Ret::UnsupportedCheck;
                    }
                    if self.tell_any_check {
                        return Ret::GetCheck;
                    }
                }
                Sequence::BlockHeader => {
                    if *in_pos >= input.len() {
                        return Ret::Ok;
                    }
                    if self.pos == 0 {
                        // Detect if it's Index.
                        if input[*in_pos] == INDEX_INDICATOR {
                            self.sequence = Sequence::Index;
                            continue;
                        }

                        // Calculate the size of the Block Header. Note that
                        // Block Header decoder wants to see this byte too
                        // so don't advance *in_pos.
                        self.block_options.header_size = header_size_decode(input[*in_pos]);
                    }

                    // Copy the Block Header to the internal buffer.
                    let header_size = self.block_options.header_size as usize;
                    bufcpy(
                        input,
                        in_pos,
                        &mut self.buffer[..header_size],
                        &mut self.pos,
                    );

                    // Return if we didn't get the whole Block Header yet.
                    if self.pos < header_size {
                        return Ret::Ok;
                    }
                    self.pos = 0;
                    self.sequence = Sequence::BlockInit;
                }
                Sequence::BlockInit => {
                    // Checking memusage and doing the initialization needs
                    // its own sequence point because we need to be able to
                    // retry if we return LZMA_MEMLIMIT_ERROR.

                    // Version 1 is needed to support the .ignore_check
                    // option.
                    self.block_options.version = 1;

                    // Decode the Block Header.
                    let header_size = self.block_options.header_size as usize;
                    let ret = self
                        .block_options
                        .header_decode(&self.buffer[..header_size]);
                    if ret != Ret::Ok {
                        return ret;
                    }

                    // If LZMA_IGNORE_CHECK was used, this flag needs to be
                    // set. It has to be set after lzma_block_header_decode()
                    // because it always resets this to false.
                    self.block_options.ignore_check = self.ignore_check;

                    // Check the memory usage limit.
                    let memusage = raw_decoder_memusage(&self.block_options.filters);
                    let ret = if memusage == u64::MAX {
                        // One or more unknown Filter IDs.
                        Ret::OptionsError
                    } else {
                        // Now we know how much memory this Block decoder
                        // needs. Update the memusage variable.
                        self.memusage = memusage;
                        if memusage > self.memlimit {
                            // The chain would need too much memory.
                            Ret::MemlimitError
                        } else {
                            // Memory usage is OK. Initialize the Block
                            // decoder.
                            match BlockDecoder::new(self.block_options.clone()) {
                                Ok(decoder) => {
                                    self.block_decoder = Some(decoder);
                                    Ret::Ok
                                }
                                Err(ret) => {
                                    self.block_decoder = None;
                                    ret
                                }
                            }
                        }
                    };

                    // Free the allocated filter options since they are
                    // needed only to initialize the Block decoder.
                    self.block_options.filters.clear();

                    // Check if memory usage calculation and Block decoder
                    // initialization succeeded.
                    if ret != Ret::Ok {
                        return ret;
                    }
                    self.sequence = Sequence::BlockRun;
                }
                Sequence::BlockRun => {
                    let Some(decoder) = self.block_decoder.as_mut() else {
                        return Ret::ProgError;
                    };
                    let ret = decoder.code(input, in_pos, output, out_pos, action);
                    if ret != Ret::StreamEnd {
                        return ret;
                    }

                    // Block decoded successfully. Add the new size pair to
                    // the Index hash.
                    let ret = self.index_hash.append(
                        decoder.block.unpadded_size(),
                        decoder.block.uncompressed_size,
                    );
                    if ret != Ret::Ok {
                        return ret;
                    }
                    self.sequence = Sequence::BlockHeader;
                }
                Sequence::Index => {
                    // If we don't have any input, don't call
                    // lzma_index_hash_decode() since it would return
                    // LZMA_BUF_ERROR, which we must not do here.
                    if *in_pos >= input.len() {
                        return Ret::Ok;
                    }

                    // Decode the Index and compare it to the hash
                    // calculated from the sizes of the Blocks (if any).
                    let ret = self.index_hash.decode(input, in_pos);
                    if ret != Ret::StreamEnd {
                        return ret;
                    }
                    self.sequence = Sequence::StreamFooter;
                }
                Sequence::StreamFooter => {
                    // Copy the Stream Footer to the internal buffer.
                    bufcpy(
                        input,
                        in_pos,
                        &mut self.buffer[..STREAM_HEADER_SIZE],
                        &mut self.pos,
                    );

                    // Return if we didn't get the whole Stream Footer yet.
                    if self.pos < STREAM_HEADER_SIZE {
                        return Ret::Ok;
                    }
                    self.pos = 0;

                    // Decode the Stream Footer. The decoder gives
                    // LZMA_FORMAT_ERROR if the magic bytes don't match, so
                    // convert that return code to LZMA_DATA_ERROR.
                    let mut footer_flags = StreamFlags::new();
                    let ret = stream_flags::footer_decode(&mut footer_flags, &self.buffer[..]);
                    if ret != Ret::Ok {
                        return if ret == Ret::FormatError {
                            Ret::DataError
                        } else {
                            ret
                        };
                    }

                    // Check that Index Size stored in the Stream Footer
                    // matches the real size of the Index field.
                    if self.index_hash.size() != footer_flags.backward_size {
                        return Ret::DataError;
                    }

                    // Compare that the Stream Flags fields are identical in
                    // both Stream Header and Stream Footer.
                    let ret = stream_flags::compare(&self.stream_flags, &footer_flags);
                    if ret != Ret::Ok {
                        return ret;
                    }

                    if !self.concatenated {
                        return Ret::StreamEnd;
                    }
                    self.sequence = Sequence::StreamPadding;
                }
                Sequence::StreamPadding => {
                    // Skip over possible Stream Padding.
                    loop {
                        if *in_pos >= input.len() {
                            // Unless LZMA_FINISH was used, we cannot know
                            // if there's more input coming later.
                            if action != Action::Finish {
                                return Ret::Ok;
                            }

                            // Stream Padding must be a multiple of four
                            // bytes.
                            return if self.pos == 0 {
                                Ret::StreamEnd
                            } else {
                                Ret::DataError
                            };
                        }

                        // If the byte is not zero, it probably indicates
                        // beginning of a new Stream (or the file is
                        // corrupt).
                        if input[*in_pos] != 0x00 {
                            break;
                        }

                        *in_pos += 1;
                        self.pos = (self.pos + 1) & 3;
                    }

                    // Stream Padding must be a multiple of four bytes (empty
                    // Stream Padding is OK).
                    if self.pos != 0 {
                        *in_pos += 1;
                        return Ret::DataError;
                    }

                    // Prepare to decode the next Stream.
                    self.reset();
                }
            }
        }
    }

    /// `stream_decoder_get_check`.
    fn get_check(&self) -> Option<Check> {
        Some(self.stream_flags.check)
    }

    /// `stream_decoder_memconfig`.
    fn memconfig(
        &mut self,
        memusage: &mut u64,
        old_memlimit: &mut u64,
        new_memlimit: u64,
    ) -> Option<Ret> {
        *memusage = self.memusage;
        *old_memlimit = self.memlimit;

        if new_memlimit != 0 {
            if new_memlimit < self.memusage {
                return Some(Ret::MemlimitError);
            }
            self.memlimit = new_memlimit;
        }
        Some(Ret::Ok)
    }
}

/// Not in liblzma: what [`StreamDecoder`] counts against its limit for the
/// first Block of the Stream that `stream` starts, its filters'
/// `lzma_raw_decoder_memusage`, or [`MEMUSAGE_BASE`] for a Stream of no
/// Block; none if that Stream Header or Block Header cannot be read from
/// `stream`, or names an unknown filter.
#[cfg(feature = "open")]
pub(crate) fn first_block_memusage(stream: &[u8]) -> Option<u64> {
    let mut flags = StreamFlags::new();
    let header = stream.get(..STREAM_HEADER_SIZE)?;
    if stream_flags::header_decode(&mut flags, header) != Ret::Ok {
        return None;
    }
    let first = *stream.get(STREAM_HEADER_SIZE)?;
    if first == INDEX_INDICATOR {
        return Some(MEMUSAGE_BASE);
    }
    let mut block = Block::new();
    block.version = 1;
    block.header_size = header_size_decode(first);
    block.check = flags.check;
    let end = STREAM_HEADER_SIZE + block.header_size as usize;
    if block.header_decode(stream.get(STREAM_HEADER_SIZE..end)?) != Ret::Ok {
        return None;
    }
    match raw_decoder_memusage(&block.filters) {
        u64::MAX => None,
        memusage => Some(memusage),
    }
}
