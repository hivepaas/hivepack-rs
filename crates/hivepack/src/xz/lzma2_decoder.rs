//! The LZMA2 decoder: port of `lzma/lzma2_decoder.c`.
//!
//! LZMA2 is LZMA in chunks, each with a control byte that says whether it
//! is compressed or stored, and what it resets: the dictionary, the
//! state, the properties.

use crate::xz::common::Ret;
use crate::xz::lz_decoder::{Dict, LzOptions};
use crate::xz::lzma_common::LzmaOptions;
use crate::xz::lzma_decoder::{LzmaDecoder, decoder_memusage_nocheck, lclppb_decode};

/// `sizeof(lzma_lzma2_coder)` in liblzma on 64-bit systems, which its
/// memory usage counts.
pub(crate) const LZMA2_CODER_SIZE: u64 = 184;

/// The sequence: what the next bytes are.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sequence {
    Control,
    Uncompressed1,
    Uncompressed2,
    Compressed0,
    Compressed1,
    Properties,
    Lzma,
    Copy,
}

/// `lzma_lzma2_coder`.
pub(crate) struct Lzma2Decoder {
    sequence: Sequence,
    /// Sequence after the size fields have been decoded.
    next_sequence: Sequence,
    /// LZMA decoder.
    pub(crate) lzma: LzmaDecoder,
    /// Uncompressed size of LZMA chunk.
    uncompressed_size: usize,
    /// Compressed size of the chunk (naturally equals to uncompressed size
    /// of uncompressed chunk).
    compressed_size: usize,
    /// True if properties are needed. This is false before the first LZMA
    /// chunk.
    need_properties: bool,
    /// True if dictionary reset is needed. This is false before the first
    /// chunk (LZMA or uncompressed).
    need_dictionary_reset: bool,
    options: LzmaOptions,
}

impl Lzma2Decoder {
    /// `lzma2_decoder_init`: the decoder and the dictionary's options.
    pub(crate) fn new(options: &LzmaOptions) -> (Lzma2Decoder, LzOptions<'_>) {
        let (lzma, lz_options) = LzmaDecoder::create(options);
        let decoder = Lzma2Decoder {
            sequence: Sequence::Control,
            next_sequence: Sequence::Control,
            lzma,
            uncompressed_size: 0,
            compressed_size: 0,
            need_properties: true,
            need_dictionary_reset: options.preset_dict.as_ref().is_none_or(|d| d.is_empty()),
            options: options.clone(),
        };
        (decoder, lz_options)
    }

    /// `lzma2_decode`.
    pub(crate) fn decode(&mut self, dict: &mut Dict, input: &[u8], in_pos: &mut usize) -> Ret {
        // With SEQ_LZMA it is possible that no new input is needed to do
        // some decoding (it can be e.g. a repeated match).
        while *in_pos < input.len() || self.sequence == Sequence::Lzma {
            match self.sequence {
                Sequence::Control => {
                    let control = u32::from(input[*in_pos]);
                    *in_pos += 1;

                    // End marker
                    if control == 0x00 {
                        return Ret::StreamEnd;
                    }

                    if control >= 0xE0 || control == 1 {
                        // Dictionary reset implies that next LZMA chunk has
                        // to set new properties.
                        self.need_properties = true;
                        self.need_dictionary_reset = true;
                    } else if self.need_dictionary_reset {
                        return Ret::DataError;
                    }

                    if control >= 0x80 {
                        // LZMA chunk. The highest five bits of the
                        // uncompressed size are taken from the control
                        // byte.
                        self.uncompressed_size = ((control & 0x1F) << 16) as usize;
                        self.sequence = Sequence::Uncompressed1;

                        // See if there are new properties or if we need to
                        // reset the state.
                        if control >= 0xC0 {
                            // When there are new properties, state reset is
                            // done at SEQ_PROPERTIES.
                            self.need_properties = false;
                            self.next_sequence = Sequence::Properties;
                        } else if self.need_properties {
                            return Ret::DataError;
                        } else {
                            self.next_sequence = Sequence::Lzma;

                            // If only state reset is wanted with old
                            // properties, do the resetting here for
                            // simplicity.
                            if control >= 0xA0 {
                                self.lzma.reset(&self.options);
                            }
                        }
                    } else {
                        // Invalid control values
                        if control > 2 {
                            return Ret::DataError;
                        }

                        // It's uncompressed chunk
                        self.sequence = Sequence::Compressed0;
                        self.next_sequence = Sequence::Copy;
                    }

                    if self.need_dictionary_reset {
                        // Finish the dictionary reset and let the caller
                        // flush the dictionary to the actual output buffer.
                        self.need_dictionary_reset = false;
                        dict.reset();
                        return Ret::Ok;
                    }
                }
                Sequence::Uncompressed1 => {
                    self.uncompressed_size += (input[*in_pos] as usize) << 8;
                    *in_pos += 1;
                    self.sequence = Sequence::Uncompressed2;
                }
                Sequence::Uncompressed2 => {
                    self.uncompressed_size += input[*in_pos] as usize + 1;
                    *in_pos += 1;
                    self.sequence = Sequence::Compressed0;
                    self.lzma
                        .set_uncompressed(self.uncompressed_size as u64, false);
                }
                Sequence::Compressed0 => {
                    self.compressed_size = (input[*in_pos] as usize) << 8;
                    *in_pos += 1;
                    self.sequence = Sequence::Compressed1;
                }
                Sequence::Compressed1 => {
                    self.compressed_size += input[*in_pos] as usize + 1;
                    *in_pos += 1;
                    self.sequence = self.next_sequence;
                }
                Sequence::Properties => {
                    let byte = input[*in_pos];
                    *in_pos += 1;
                    if lclppb_decode(&mut self.options, byte) {
                        return Ret::DataError;
                    }
                    self.lzma.reset(&self.options);
                    self.sequence = Sequence::Lzma;
                }
                Sequence::Lzma => {
                    // Store the start offset so that we can update
                    // compressed_size later.
                    let in_start = *in_pos;
                    // Decode from in[] to *dict.
                    let in_limit = *in_pos + (input.len() - *in_pos).min(self.compressed_size + 1);
                    let ret = self.lzma.decode(dict, &input[..in_limit], in_pos);

                    // Validate and update coder->compressed_size.
                    let in_used = *in_pos - in_start;
                    if in_used > self.compressed_size {
                        return Ret::DataError;
                    }
                    self.compressed_size -= in_used;

                    // Return if we didn't finish the chunk, or an error
                    // occurred.
                    if ret != Ret::StreamEnd {
                        return ret;
                    }

                    // The LZMA decoder must have consumed the whole chunk
                    // now. We don't need to worry about uncompressed size
                    // since it is checked by the LZMA decoder.
                    if self.compressed_size != 0 {
                        return Ret::DataError;
                    }
                    self.sequence = Sequence::Control;
                }
                Sequence::Copy => {
                    // Copy from input to the dictionary as is.
                    dict.write(input, in_pos, &mut self.compressed_size);
                    if self.compressed_size != 0 {
                        return Ret::Ok;
                    }
                    self.sequence = Sequence::Control;
                }
            }
        }
        Ret::Ok
    }
}

/// `lzma_lzma2_decoder_memusage`.
pub(crate) fn decoder_memusage(options: &LzmaOptions) -> u64 {
    LZMA2_CODER_SIZE + decoder_memusage_nocheck(options)
}

/// `lzma_lzma2_props_decode`: the options of an LZMA2 filter from its byte
/// of properties.
pub(crate) fn props_decode(props: &[u8]) -> Result<LzmaOptions, Ret> {
    if props.len() != 1 {
        return Err(Ret::OptionsError);
    }

    // Check that reserved bits are unset.
    if props[0] & 0xC0 != 0 {
        return Err(Ret::OptionsError);
    }

    // Decode the dictionary size.
    if props[0] > 40 {
        return Err(Ret::OptionsError);
    }

    let dict_size = if props[0] == 40 {
        u32::MAX
    } else {
        (2 | u32::from(props[0] & 1)) << (u32::from(props[0]) / 2 + 11)
    };
    Ok(LzmaOptions {
        dict_size,
        ..LzmaOptions::default()
    })
}
