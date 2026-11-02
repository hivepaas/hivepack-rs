//! The LZMA2 encoder: port of `lzma/lzma2_encoder.{h,c}`.

use crate::xz::common::{Action, Ret, bufcpy};
use crate::xz::filter::FILTER_LZMA2;
use crate::xz::lz_encoder::{LzEncOptions, Mf, is_enc_dict_size_valid};
use crate::xz::lzma_common::{DICT_SIZE_MIN, LzmaOptions};
use crate::xz::lzma_encoder::{
    LZMA2_CHUNK_MAX, LzmaEncoder, encoder_memusage, get_dist_slot, lclppb_encode,
};

/// Maximum number of uncompressed bytes in a chunk.
const LZMA2_UNCOMPRESSED_MAX: u32 = 1 << 21;

/// Maximum size of LZMA2 headers.
const LZMA2_HEADER_MAX: usize = 6;

/// Size of a header for uncompressed chunk.
const LZMA2_HEADER_UNCOMPRESSED: usize = 3;

/// `sizeof(lzma_lzma2_coder)` in liblzma on 64-bit systems, which its
/// memory usage counts.
const LZMA2_CODER_SIZE: u64 = 65_704;

/// The sequence of the LZMA2 encoder.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sequence {
    Init,
    LzmaEncode,
    LzmaCopy,
    UncompressedHeader,
    UncompressedCopy,
}

/// `lzma_lzma2_coder`.
pub(crate) struct Lzma2Encoder {
    sequence: Sequence,
    /// LZMA encoder
    lzma: LzmaEncoder,
    /// LZMA options currently in use.
    opt_cur: LzmaOptions,
    need_properties: bool,
    need_state_reset: bool,
    need_dictionary_reset: bool,
    /// Uncompressed size of a chunk
    uncompressed_size: usize,
    /// Compressed size of a chunk (excluding headers); this is also used
    /// to indicate the end of buf[] in SEQ_LZMA_COPY.
    compressed_size: usize,
    /// Read position in buf[]
    buf_pos: usize,
    /// Buffer to hold the chunk header and LZMA compressed data
    buf: Box<[u8]>,
}

impl Lzma2Encoder {
    /// `lzma2_encoder_init` without an encoder: the encoder and the LZ
    /// encoder's options.
    pub(crate) fn new(options: &LzmaOptions) -> Result<(Lzma2Encoder, LzEncOptions), Ret> {
        let mut coder = Lzma2Encoder {
            sequence: Sequence::Init,
            lzma: LzmaEncoder::blank(),
            opt_cur: options.clone(),
            need_properties: true,
            need_state_reset: false,
            need_dictionary_reset: false,
            uncompressed_size: 0,
            compressed_size: 0,
            buf_pos: 0,
            buf: vec![0; LZMA2_HEADER_MAX + LZMA2_CHUNK_MAX as usize].into_boxed_slice(),
        };
        let lz_options = coder.init(options)?;
        Ok((coder, lz_options))
    }

    /// `lzma2_encoder_init` with an encoder, whose memory is kept; the LZ
    /// encoder's options.
    pub(crate) fn init(&mut self, options: &LzmaOptions) -> Result<LzEncOptions, Ret> {
        self.opt_cur = options.clone();

        self.sequence = Sequence::Init;
        self.need_properties = true;
        self.need_state_reset = false;
        self.need_dictionary_reset = self
            .opt_cur
            .preset_dict
            .as_ref()
            .is_none_or(|d| d.is_empty());

        // Initialize LZMA encoder
        let mut lz_options = self.lzma.init(FILTER_LZMA2, &self.opt_cur)?;

        // Make sure that we will always have enough history available in
        // case we need to use uncompressed chunks. They are used when the
        // compressed size of a chunk is not smaller than the uncompressed
        // size, so we need to have at least LZMA2_COMPRESSED_MAX bytes
        // history available.
        if lz_options.before_size + lz_options.dict_size < LZMA2_CHUNK_MAX {
            lz_options.before_size = LZMA2_CHUNK_MAX - lz_options.dict_size;
        }

        Ok(lz_options)
    }

    /// `lzma2_header_lzma`.
    fn header_lzma(&mut self) {
        let mut pos;

        if self.need_properties {
            pos = 0;

            self.buf[pos] = if self.need_dictionary_reset {
                0x80 + (3 << 5)
            } else {
                0x80 + (2 << 5)
            };
        } else {
            pos = 1;

            self.buf[pos] = if self.need_state_reset {
                0x80 + (1 << 5)
            } else {
                0x80
            };
        }

        // Set the start position for copying.
        self.buf_pos = pos;

        // Uncompressed size
        let mut size = self.uncompressed_size - 1;
        self.buf[pos] += (size >> 16) as u8;
        pos += 1;
        self.buf[pos] = ((size >> 8) & 0xFF) as u8;
        pos += 1;
        self.buf[pos] = (size & 0xFF) as u8;
        pos += 1;

        // Compressed size
        size = self.compressed_size - 1;
        self.buf[pos] = (size >> 8) as u8;
        pos += 1;
        self.buf[pos] = (size & 0xFF) as u8;
        pos += 1;

        // Properties, if needed
        if self.need_properties {
            // The options were validated when the encoder was made.
            self.buf[pos] = lclppb_encode(&self.opt_cur).unwrap_or(0);
        }

        self.need_properties = false;
        self.need_state_reset = false;
        self.need_dictionary_reset = false;

        // The copying code uses coder->compressed_size to indicate the end
        // of coder->buf[], so we need add the maximum size of the header
        // here.
        self.compressed_size += LZMA2_HEADER_MAX;
    }

    /// `lzma2_header_uncompressed`.
    fn header_uncompressed(&mut self) {
        // If this is the first chunk, we need to include dictionary reset
        // indicator.
        self.buf[0] = if self.need_dictionary_reset { 1 } else { 2 };

        self.need_dictionary_reset = false;

        // "Compressed" size
        self.buf[1] = ((self.uncompressed_size - 1) >> 8) as u8;
        self.buf[2] = ((self.uncompressed_size - 1) & 0xFF) as u8;

        // Set the start position for copying.
        self.buf_pos = 0;
    }

    /// `lzma2_encode`.
    pub(crate) fn encode(&mut self, mf: &mut Mf, out: &mut [u8], out_pos: &mut usize) -> Ret {
        // liblzma's switch falls through from SEQ_INIT to SEQ_LZMA_ENCODE,
        // from there to SEQ_LZMA_COPY, and from SEQ_UNCOMPRESSED_HEADER to
        // SEQ_UNCOMPRESSED_COPY, within one turn of its loop; its "break"
        // goes back to the loop's condition, here "continue".
        while *out_pos < out.len() {
            if self.sequence == Sequence::Init {
                // If there's no input left and we are flushing or
                // finishing, don't start a new chunk.
                if mf.unencoded() == 0 {
                    // Write end of payload marker if finishing.
                    if mf.action == Action::Finish {
                        out[*out_pos] = 0;
                        *out_pos += 1;
                    }

                    return if mf.action == Action::Run {
                        Ret::Ok
                    } else {
                        Ret::StreamEnd
                    };
                }

                if self.need_state_reset
                    && let Err(ret) = self.lzma.reset(&self.opt_cur)
                {
                    return ret;
                }

                self.uncompressed_size = 0;
                self.compressed_size = 0;
                self.sequence = Sequence::LzmaEncode;
            }

            if self.sequence == Sequence::LzmaEncode {
                // Calculate how much more uncompressed data this chunk
                // could accept.
                let left = LZMA2_UNCOMPRESSED_MAX - self.uncompressed_size as u32;
                let limit = if left < mf.match_len_max {
                    // Must flush immediately since the next LZMA symbol
                    // could make the uncompressed size of the chunk too
                    // big.
                    0
                } else {
                    // Calculate maximum read_limit that is OK from point
                    // of view of LZMA2 chunk size.
                    mf.read_pos - mf.read_ahead + left - mf.match_len_max
                };

                // Save the start position so that we can update
                // coder->uncompressed_size.
                let read_start = mf.read_pos - mf.read_ahead;

                // Call the LZMA encoder until the chunk is finished.
                let ret = self.lzma.encode(
                    mf,
                    &mut self.buf[LZMA2_HEADER_MAX..LZMA2_HEADER_MAX + LZMA2_CHUNK_MAX as usize],
                    &mut self.compressed_size,
                    limit,
                );

                self.uncompressed_size += (mf.read_pos - mf.read_ahead - read_start) as usize;

                if ret != Ret::StreamEnd {
                    return Ret::Ok;
                }

                // See if the chunk compressed. If it didn't, we encode it
                // as uncompressed chunk. This saves a few bytes of space
                // and makes decoding faster.
                if self.compressed_size >= self.uncompressed_size {
                    self.uncompressed_size += mf.read_ahead as usize;
                    mf.read_ahead = 0;
                    self.header_uncompressed();
                    self.need_state_reset = true;
                    self.sequence = Sequence::UncompressedHeader;
                    continue;
                }

                // The chunk did compress at least by one byte, so we store
                // the chunk as LZMA.
                self.header_lzma();

                self.sequence = Sequence::LzmaCopy;
            }

            if self.sequence == Sequence::LzmaCopy {
                // Copy the compressed chunk along its headers to the output
                // buffer.
                bufcpy(
                    &self.buf[..self.compressed_size],
                    &mut self.buf_pos,
                    out,
                    out_pos,
                );
                if self.buf_pos != self.compressed_size {
                    return Ret::Ok;
                }

                self.sequence = Sequence::Init;
                continue;
            }

            if self.sequence == Sequence::UncompressedHeader {
                // Copy the three-byte header to indicate uncompressed
                // chunk.
                bufcpy(
                    &self.buf[..LZMA2_HEADER_UNCOMPRESSED],
                    &mut self.buf_pos,
                    out,
                    out_pos,
                );
                if self.buf_pos != LZMA2_HEADER_UNCOMPRESSED {
                    return Ret::Ok;
                }

                self.sequence = Sequence::UncompressedCopy;
            }

            if self.sequence == Sequence::UncompressedCopy {
                // Copy the uncompressed data as is from the dictionary to
                // the output buffer.
                mf.read(out, out_pos, &mut self.uncompressed_size);
                if self.uncompressed_size != 0 {
                    return Ret::Ok;
                }

                self.sequence = Sequence::Init;
            }
        }

        Ret::Ok
    }
}

/// `lzma_lzma2_encoder_memusage`.
pub(crate) fn lzma2_encoder_memusage(options: &LzmaOptions) -> u64 {
    let lzma_mem = encoder_memusage(options);
    if lzma_mem == u64::MAX {
        return u64::MAX;
    }

    LZMA2_CODER_SIZE + lzma_mem
}

/// `lzma_lzma2_block_size`: the size of the Blocks of the threaded encoder,
/// u64::MAX if the dictionary size is invalid.
pub(crate) fn lzma2_block_size(options: &LzmaOptions) -> u64 {
    if !is_enc_dict_size_valid(options.dict_size) {
        return u64::MAX;
    }

    // Use at least 1 MiB to keep compression ratio better.
    (u64::from(options.dict_size) * 3).max(1 << 20)
}

/// `lzma_lzma2_props_encode`: the one byte of properties of LZMA2.
pub(crate) fn lzma2_props_encode(options: &LzmaOptions, out: &mut [u8]) -> Ret {
    let mut d = options.dict_size.max(DICT_SIZE_MIN);

    // Round up to the next 2^n - 1 or 2^n + 2^(n - 1) - 1 depending on
    // which one is the next:
    d -= 1;
    d |= d >> 2;
    d |= d >> 3;
    d |= d >> 4;
    d |= d >> 8;
    d |= d >> 16;

    // Get the highest two bits using the proper encoding:
    out[0] = if d == u32::MAX {
        40
    } else {
        (get_dist_slot(d + 1) - 24) as u8
    };

    Ret::Ok
}
