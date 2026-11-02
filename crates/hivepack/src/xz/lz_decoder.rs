//! The LZ decoder: the dictionary that LZMA and LZMA2 decode into, and the
//! coder that copies it out. Port of `lz/lz_decoder.{h,c}`.

use crate::xz::common::{Action, BUFFER_SIZE, NextCoder, Ret, bufcpy};
use crate::xz::lzma_decoder::LzmaDecoder;
use crate::xz::lzma2_decoder::Lzma2Decoder;

/// `LZ_DICT_EXTRA`: none, as the port copies exactly what is asked
/// (`LZMA_LZ_DECODER_CONFIG` 1, `memcpy()` for copies that do not
/// overlap).
pub(crate) const LZ_DICT_EXTRA: usize = 0;

/// `LZ_DICT_REPEAT_MAX`: the most `dict_repeat()` copies. The buffer is
/// `2 * LZ_DICT_REPEAT_MAX` bytes larger than the dictionary: the last
/// bytes are copied to the start when the buffer wraps, and as many are
/// kept between the oldest byte and the write position.
pub(crate) const LZ_DICT_REPEAT_MAX: usize = 288;

/// `LZ_DICT_INIT_POS`: the position in the buffer when the dictionary is
/// empty.
pub(crate) const LZ_DICT_INIT_POS: usize = 2 * LZ_DICT_REPEAT_MAX;

/// `lzma_dict`: the dictionary (history buffer).
#[derive(Default)]
pub(crate) struct Dict {
    /// The dictionary buffer.
    pub(crate) buf: Vec<u8>,
    /// Write position in dictionary. The next byte will be written to
    /// buf[pos].
    pub(crate) pos: usize,
    /// Indicates how full the dictionary is. This is used by
    /// dict_is_distance_valid() to detect corrupt files that would read
    /// beyond the beginning of the dictionary.
    pub(crate) full: usize,
    /// Write limit.
    pub(crate) limit: usize,
    /// Allocated size of buf. This is 2 * LZ_DICT_REPEAT_MAX bytes larger
    /// than the actual dictionary size.
    pub(crate) size: usize,
    /// True once the dictionary has become full and the writing position
    /// has been wrapped in decode_buffer().
    pub(crate) has_wrapped: bool,
    /// True when dictionary should be reset before decoding more data.
    pub(crate) need_reset: bool,
}

impl Dict {
    /// `dict_get`: a byte from the history buffer.
    #[inline(always)]
    pub(crate) fn get(&self, distance: u32) -> u8 {
        let distance = distance as usize;
        let at = if distance < self.pos {
            self.pos - distance - 1
        } else {
            self.pos + self.size - LZ_DICT_REPEAT_MAX - distance - 1
        };
        self.buf[at]
    }

    /// `dict_get0`: `dict_get(dict, 0)`.
    #[inline(always)]
    pub(crate) fn get0(&self) -> u8 {
        self.buf[self.pos - 1]
    }

    /// `dict_is_distance_valid`.
    #[inline(always)]
    pub(crate) fn is_distance_valid(&self, distance: usize) -> bool {
        self.full > distance
    }

    /// `dict_repeat`: repeats `*len` bytes at `distance`, as many as fit
    /// before the limit; true if some are left.
    #[inline(always)]
    pub(crate) fn repeat(&mut self, distance: u32, len: &mut u32) -> bool {
        // Don't write past the end of the dictionary.
        let dict_avail = self.limit - self.pos;
        let left = dict_avail.min(*len as usize);
        *len -= left as u32;

        let distance = distance as usize;
        let back = if distance < self.pos {
            self.pos - distance - 1
        } else {
            self.pos + self.size - LZ_DICT_REPEAT_MAX - distance - 1
        };

        if distance < left {
            // Source and target areas overlap, thus we can't use memcpy()
            // nor even memmove() safely.
            for i in 0..left {
                self.buf[self.pos + i] = self.buf[back + i];
            }
        } else {
            self.buf.copy_within(back..back + left, self.pos);
        }
        self.pos += left;

        // Update how full the dictionary is.
        if !self.has_wrapped {
            self.full = self.pos - LZ_DICT_INIT_POS;
        }
        *len != 0
    }

    /// `dict_put`.
    #[inline(always)]
    pub(crate) fn put(&mut self, byte: u8) {
        self.buf[self.pos] = byte;
        self.pos += 1;
        if !self.has_wrapped {
            self.full = self.pos - LZ_DICT_INIT_POS;
        }
    }

    /// `dict_put_safe`: puts one byte into the dictionary; true if the
    /// dictionary was already full and the byte couldn't be added.
    #[inline(always)]
    pub(crate) fn put_safe(&mut self, byte: u8) -> bool {
        if self.pos == self.limit {
            return true;
        }
        self.put(byte);
        false
    }

    /// `dict_write`: copies up to `*left` bytes of input into the
    /// dictionary.
    pub(crate) fn write(&mut self, input: &[u8], in_pos: &mut usize, left: &mut usize) {
        let in_size = if input.len() - *in_pos > *left {
            *in_pos + *left
        } else {
            input.len()
        };
        let limit = self.limit;
        *left -= bufcpy(
            &input[..in_size],
            in_pos,
            &mut self.buf[..limit],
            &mut self.pos,
        );
        if !self.has_wrapped {
            self.full = self.pos - LZ_DICT_INIT_POS;
        }
    }

    /// `dict_reset`.
    pub(crate) fn reset(&mut self) {
        self.need_reset = true;
    }
}

/// `lzma_lz_options`.
pub(crate) struct LzOptions<'a> {
    pub(crate) dict_size: usize,
    pub(crate) preset_dict: Option<&'a [u8]>,
}

/// `lzma_lz_decoder`: the LZ-based decoder, LZMA or LZMA2.
pub(crate) enum Lz {
    Lzma(Box<LzmaDecoder>),
    Lzma2(Box<Lzma2Decoder>),
}

impl Lz {
    /// `code`: decodes from `input[*in_pos..]` to the dictionary.
    fn code(&mut self, dict: &mut Dict, input: &[u8], in_pos: &mut usize) -> Ret {
        match self {
            Lz::Lzma(lz) => lz.decode(dict, input, in_pos),
            Lz::Lzma2(lz) => lz.decode(dict, input, in_pos),
        }
    }
}

/// The `lzma_coder` of `lz_decoder.c`.
pub(crate) struct LzCoder {
    /// Dictionary (history buffer).
    dict: Dict,
    /// The actual LZ-based decoder e.g. LZMA.
    pub(crate) lz: Lz,
    /// Next filter in the chain, if any. Note that LZMA and LZMA2 are only
    /// allowed as the last filter, but the long-range filter in future can
    /// be in the middle of the chain.
    next: Option<Box<dyn NextCoder>>,
    /// True if the next filter in the chain has returned LZMA_STREAM_END.
    next_finished: bool,
    /// True if the LZ decoder (e.g. LZMA) has detected end of payload
    /// marker. This may become true before next_finished becomes true.
    this_finished: bool,
    /// Temporary buffer needed when the LZ-based filter is not the last
    /// filter in the chain.
    temp_pos: usize,
    temp_size: usize,
    temp: Box<[u8; BUFFER_SIZE]>,
}

impl LzCoder {
    /// `lzma_lz_decoder_init`, for the LZ decoder `lz`, whose `lz_init`
    /// gave `lz_options`, and the rest of the chain `next`.
    pub(crate) fn new(
        lz: Lz,
        lz_options: &LzOptions<'_>,
        next: Option<Box<dyn NextCoder>>,
    ) -> Result<LzCoder, Ret> {
        // If the dictionary size is very small, increase it to 4096 bytes.
        // This is to prevent constant wrapping of the dictionary, which
        // would slow things down. The downside is that since we don't
        // check separately for the real dictionary size, we may happily
        // accept corrupt files.
        let mut dict_size = lz_options.dict_size.max(4096);

        // Make dictionary size a multiple of 16. Some LZ-based decoders
        // like LZMA use the lowest bits lzma_dict.pos to know the
        // alignment of the data.
        //
        // Avoid integer overflow.
        if dict_size > usize::MAX - 15 - 2 * LZ_DICT_REPEAT_MAX - LZ_DICT_EXTRA {
            return Err(Ret::MemError);
        }
        dict_size = (dict_size + 15) & !15;

        // Reserve extra space as explained in the comment of
        // LZ_DICT_REPEAT_MAX.
        let alloc_size = dict_size + 2 * LZ_DICT_REPEAT_MAX;

        // Differs from liblzma, without a difference to see: the buffer's
        // memory is reserved here, as liblzma allocates it, but its length
        // grows as the dictionary is written (decode_buffer() makes room up
        // to the write limit), zeroed where liblzma leaves it as it was
        // allocated. liblzma reads only what it wrote.
        let mut buf = Vec::new();
        if buf.try_reserve_exact(alloc_size + LZ_DICT_EXTRA).is_err() {
            return Err(Ret::MemError);
        }
        buf.resize(LZ_DICT_INIT_POS, 0);

        let mut dict = Dict {
            buf,
            pos: 0,
            full: 0,
            limit: 0,
            // NOTE: Yes, alloc_size, not dict_size. The way dict.full is
            // updated will take care that we will still reject distances
            // larger than dict_size.
            size: alloc_size,
            has_wrapped: false,
            need_reset: false,
        };
        dict.lz_reset();

        // Use the preset dictionary if it was given to us.
        if let Some(preset_dict) = lz_options.preset_dict
            && !preset_dict.is_empty()
        {
            // If the preset dictionary is bigger than the actual
            // dictionary, copy only the tail.
            let copy_size = preset_dict.len().min(dict_size);
            let offset = preset_dict.len() - copy_size;
            let pos = dict.pos;
            dict.buf.resize(pos + copy_size, 0);
            dict.buf[pos..pos + copy_size].copy_from_slice(&preset_dict[offset..]);
            // dict.pos isn't zero after lz_decoder_reset().
            dict.pos += copy_size;
            dict.full = copy_size;
        }

        Ok(LzCoder {
            dict,
            lz,
            next,
            next_finished: false,
            this_finished: false,
            temp_pos: 0,
            temp_size: 0,
            temp: Box::new([0; BUFFER_SIZE]),
        })
    }
}

impl LzCoder {
    /// The next filter in the chain, made after this one.
    pub(crate) fn set_next(&mut self, next: Option<Box<dyn NextCoder>>) {
        self.next = next;
    }
}

impl Dict {
    /// `lz_decoder_reset`.
    fn lz_reset(&mut self) {
        self.pos = LZ_DICT_INIT_POS;
        self.full = 0;
        self.buf[LZ_DICT_INIT_POS - 1] = 0;
        self.has_wrapped = false;
        self.need_reset = false;
    }
}

impl LzCoder {
    /// `decode_buffer`.
    fn decode_buffer(
        dict: &mut Dict,
        lz: &mut Lz,
        input: &[u8],
        in_pos: &mut usize,
        output: &mut [u8],
        out_pos: &mut usize,
    ) -> Ret {
        loop {
            // Wrap the dictionary if needed.
            if dict.pos == dict.size {
                // See the comment of LZ_DICT_REPEAT_MAX.
                dict.pos = LZ_DICT_REPEAT_MAX;
                dict.has_wrapped = true;
                let size = dict.size;
                dict.buf.copy_within(size - LZ_DICT_REPEAT_MAX..size, 0);
            }

            // Store the current dictionary position. It is needed to know
            // where to start copying to the out[] buffer.
            let dict_start = dict.pos;

            // Calculate how much we allow lz.code() to decode. It must not
            // decode past the end of the dictionary buffer, and we don't
            // want it to decode more than is actually needed to fill the
            // out[] buffer.
            dict.limit = dict.pos + (output.len() - *out_pos).min(dict.size - dict.pos);
            if dict.buf.len() < dict.limit {
                dict.buf.resize(dict.limit, 0);
            }

            // Call the lz.code() to do the actual decoding.
            let ret = lz.code(dict, input, in_pos);

            // Copy the decoded data from the dictionary to the out[]
            // buffer.
            let copy_size = dict.pos - dict_start;
            output[*out_pos..*out_pos + copy_size]
                .copy_from_slice(&dict.buf[dict_start..dict_start + copy_size]);
            *out_pos += copy_size;

            // Reset the dictionary if so requested by lz.code().
            if dict.need_reset {
                dict.lz_reset();

                // Since we reset dictionary, we don't check if dictionary
                // became full.
                if ret != Ret::Ok || *out_pos == output.len() {
                    return ret;
                }
            } else {
                // Return if everything got decoded or an error occurred, or
                // if there's no more data to decode.
                //
                // Note that detecting if there's something to decode is
                // done by looking if dictionary become full instead of
                // looking if *in_pos == in_size. This is because it is
                // possible that all the input was consumed already but some
                // data is pending to be written to the dictionary.
                if ret != Ret::Ok || *out_pos == output.len() || dict.pos < dict.size {
                    return ret;
                }
            }
        }
    }
}

impl NextCoder for LzCoder {
    /// `lz_decode`.
    fn code(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        output: &mut [u8],
        out_pos: &mut usize,
        action: Action,
    ) -> Ret {
        let Some(next) = self.next.as_mut() else {
            return Self::decode_buffer(
                &mut self.dict,
                &mut self.lz,
                input,
                in_pos,
                output,
                out_pos,
            );
        };

        // We aren't the last coder in the chain, we need to decode our
        // input to a temporary buffer.
        while *out_pos < output.len() {
            // Fill the temporary buffer if it is empty.
            if !self.next_finished && self.temp_pos == self.temp_size {
                self.temp_pos = 0;
                self.temp_size = 0;

                let ret = next.code(
                    input,
                    in_pos,
                    &mut self.temp[..],
                    &mut self.temp_size,
                    action,
                );

                if ret == Ret::StreamEnd {
                    self.next_finished = true;
                } else if ret != Ret::Ok || self.temp_size == 0 {
                    return ret;
                }
            }

            if self.this_finished {
                if self.temp_size != 0 {
                    return Ret::DataError;
                }
                if self.next_finished {
                    return Ret::StreamEnd;
                }
                return Ret::Ok;
            }

            let ret = Self::decode_buffer(
                &mut self.dict,
                &mut self.lz,
                &self.temp[..self.temp_size],
                &mut self.temp_pos,
                output,
                out_pos,
            );

            if ret == Ret::StreamEnd {
                self.this_finished = true;
            } else if ret != Ret::Ok {
                return ret;
            } else if self.next_finished && *out_pos < output.len() {
                return Ret::DataError;
            }
        }
        Ret::Ok
    }
}

/// `sizeof(lzma_coder)` of `lz_decoder.c` in liblzma on 64-bit systems,
/// which its memory usage counts.
pub(crate) const LZ_CODER_SIZE: u64 = 4288;

/// `lzma_lz_decoder_memusage`.
pub(crate) fn lz_decoder_memusage(dictionary_size: u64) -> u64 {
    LZ_CODER_SIZE + dictionary_size + 2 * LZ_DICT_REPEAT_MAX as u64 + LZ_DICT_EXTRA as u64
}
