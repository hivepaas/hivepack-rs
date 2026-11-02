//! The BCJ filters, which convert the addresses of branches in executable
//! code: port of `simple/simple_coder.c`, `simple_decoder.c` and
//! `simple_encoder.c`, the frame they share, with each filter in a module
//! of its own (`x86.c` in `x86.rs`, and so on).

mod arm;
mod arm64;
mod armthumb;
mod ia64;
mod powerpc;
mod riscv;
mod sparc;
mod x86;

pub use arm64::{bcj_arm64_decode, bcj_arm64_encode};
pub use riscv::{bcj_riscv_decode, bcj_riscv_encode};
pub use x86::{bcj_x86_decode, bcj_x86_encode};

use crate::xz::common::{Action, NextCoder, Ret, bufcpy, read32le, write32le};
use crate::xz::filter::{
    BcjOptions, FILTER_ARM, FILTER_ARM64, FILTER_ARMTHUMB, FILTER_IA64, FILTER_POWERPC,
    FILTER_RISCV, FILTER_SPARC, FILTER_X86,
};

/// A filter of the frame: liblzma's `filter` function pointer and its
/// `simple` state.
#[derive(Clone, Copy, Debug)]
enum Kind {
    X86(x86::X86),
    PowerPc,
    Ia64,
    Arm,
    ArmThumb,
    Arm64,
    Sparc,
    Riscv,
}

impl Kind {
    /// `filter`: converts what it can of `buffer`, whose first byte is at
    /// `now_pos`; the number of bytes it went through.
    fn filter(&mut self, now_pos: u32, is_encoder: bool, buffer: &mut [u8]) -> usize {
        match self {
            Kind::X86(simple) => simple.code(now_pos, is_encoder, buffer),
            Kind::PowerPc => powerpc::code(now_pos, is_encoder, buffer),
            Kind::Ia64 => ia64::code(now_pos, is_encoder, buffer),
            Kind::Arm => arm::code(now_pos, is_encoder, buffer),
            Kind::ArmThumb => armthumb::code(now_pos, is_encoder, buffer),
            Kind::Arm64 => arm64::code(now_pos, is_encoder, buffer),
            Kind::Sparc => sparc::code(now_pos, is_encoder, buffer),
            Kind::Riscv => {
                if is_encoder {
                    riscv::encode(now_pos, buffer)
                } else {
                    riscv::decode(now_pos, buffer)
                }
            }
        }
    }
}

/// `lzma_simple_coder`.
pub(crate) struct SimpleCoder {
    /// Next filter in the chain
    next: Option<Box<dyn NextCoder>>,
    /// True if the next coder in the chain has returned LZMA_STREAM_END.
    end_was_reached: bool,
    /// True if filter() should encode the data; false to decode.
    /// Currently all simple filters use the same function for encoding
    /// and decoding, because the difference between encoders and decoders
    /// is very small.
    is_encoder: bool,
    /// The filter and its state.
    kind: Kind,
    /// The lowest 32 bits of the current position in the data. Most
    /// filters need this to do conversions between absolute and relative
    /// addresses.
    now_pos: u32,
    /// Size of the memory allocated for the buffer.
    allocated: usize,
    /// Flushing position in the temporary buffer. buffer[pos] is the next
    /// byte to be copied to out[].
    pos: usize,
    /// buffer[filtered] is the first unfiltered byte. When pos is smaller
    /// than filtered, there is unflushed filtered data in the buffer.
    filtered: usize,
    /// Total number of bytes (both filtered and unfiltered) currently in
    /// the temporary buffer.
    size: usize,
    /// Temporary buffer
    buffer: Box<[u8]>,
}

impl SimpleCoder {
    /// `lzma_simple_coder_init` of the filter `id`, before the next filter
    /// is made: LZMA_OPTIONS_ERROR for a start offset that is not a
    /// multiple of the filter's alignment.
    pub(crate) fn new(id: u64, start_offset: u32, is_encoder: bool) -> Result<SimpleCoder, Ret> {
        // The filter, how much it may leave unfiltered at most, and the
        // alignment of its positions: the arguments of
        // lzma_simple_coder_init in x86_coder_init() and the others.
        let (kind, unfiltered_max, alignment) = match id {
            FILTER_X86 => (Kind::X86(x86::X86::new()), 5, 1),
            FILTER_POWERPC => (Kind::PowerPc, 4, 4),
            FILTER_IA64 => (Kind::Ia64, 16, 16),
            FILTER_ARM => (Kind::Arm, 4, 4),
            FILTER_ARMTHUMB => (Kind::ArmThumb, 4, 2),
            FILTER_ARM64 => (Kind::Arm64, 4, 4),
            FILTER_SPARC => (Kind::Sparc, 4, 4),
            FILTER_RISCV => (Kind::Riscv, 8, 2),
            _ => return Err(Ret::OptionsError),
        };

        if start_offset & (alignment - 1) != 0 {
            return Err(Ret::OptionsError);
        }

        Ok(SimpleCoder {
            next: None,
            end_was_reached: false,
            is_encoder,
            kind,
            now_pos: start_offset,
            allocated: 2 * unfiltered_max,
            pos: 0,
            filtered: 0,
            size: 0,
            buffer: vec![0; 2 * unfiltered_max].into_boxed_slice(),
        })
    }

    /// The next filter in the chain, made after this one.
    pub(crate) fn set_next(&mut self, next: Option<Box<dyn NextCoder>>) {
        self.next = next;
    }

    /// `copy_or_code`: the input, or the next filter's output, into
    /// `out[*out_pos..]`.
    fn copy_or_code(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        out: &mut [u8],
        out_pos: &mut usize,
        action: Action,
    ) -> Ret {
        match self.next.as_mut() {
            None => {
                bufcpy(input, in_pos, out, out_pos);

                // If we are encoding and finishing, check if we have
                // reached the end of the input.
                if self.is_encoder && action == Action::Finish && *in_pos == input.len() {
                    self.end_was_reached = true;
                }
            }
            Some(next) => {
                // Call the next coder in the chain to provide us some
                // data.
                let ret = next.code(input, in_pos, out, out_pos, action);

                if ret == Ret::StreamEnd {
                    self.end_was_reached = true;
                } else if ret != Ret::Ok {
                    return ret;
                }
            }
        }

        Ret::Ok
    }

    /// `call_filter`.
    fn call_filter(&mut self, buffer_range: Option<&mut [u8]>) -> usize {
        let filtered = match buffer_range {
            Some(buffer) => self.kind.filter(self.now_pos, self.is_encoder, buffer),
            None => {
                let size = self.size;
                self.kind
                    .filter(self.now_pos, self.is_encoder, &mut self.buffer[..size])
            }
        };
        self.now_pos = self.now_pos.wrapping_add(filtered as u32);
        filtered
    }
}

impl NextCoder for SimpleCoder {
    /// `simple_code`.
    fn code(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        out: &mut [u8],
        out_pos: &mut usize,
        action: Action,
    ) -> Ret {
        // TODO: Add partial support for LZMA_SYNC_FLUSH. We can support it
        // in cases when the filter is able to filter everything. With most
        // simple filters it can be done at offset that is a multiple of 2,
        // 4, or 16. With x86 filter, it needs good luck, and thus cannot be
        // made to work predictably.
        if action == Action::SyncFlush {
            return Ret::OptionsError;
        }

        // Flush already filtered data from coder->buffer[] to out[].
        if self.pos < self.filtered {
            bufcpy(&self.buffer[..self.filtered], &mut self.pos, out, out_pos);

            // If we couldn't flush all the filtered data, return to
            // application immediately.
            if self.pos < self.filtered {
                return Ret::Ok;
            }

            if self.end_was_reached {
                return Ret::StreamEnd;
            }
        }

        // If we get here, there is no filtered data left in the buffer.
        self.filtered = 0;

        // If there is more output space left than there is unfiltered data
        // in coder->buffer[], flush coder->buffer[] to out[], and copy/code
        // new data to out[]. This way we don't need to use the temporary
        // buffer when we have a lot of output space.
        let out_avail = out.len() - *out_pos;
        let buf_avail = self.size - self.pos;
        if out_avail > buf_avail || buf_avail == 0 {
            // Store the old position so that we know from which byte to
            // start filtering.
            let out_start = *out_pos;

            // Flush data from coder->buffer[] to out[], but don't reset
            // coder->pos and coder->size yet. This way the coder can be
            // restarted if the next filter in the chain returns e.g.
            // LZMA_MEM_ERROR.
            out[*out_pos..*out_pos + buf_avail]
                .copy_from_slice(&self.buffer[self.pos..self.pos + buf_avail]);
            *out_pos += buf_avail;

            // Copy/Encode/Decode more data to out[].
            {
                let ret = self.copy_or_code(input, in_pos, out, out_pos, action);
                if ret != Ret::Ok {
                    return ret;
                }
            }

            // Filter out[] unless there is nothing to filter. This way we
            // avoid null pointer + 0 (undefined behavior) when out == NULL.
            let size = *out_pos - out_start;
            let filtered = if size == 0 {
                0
            } else {
                self.call_filter(Some(&mut out[out_start..*out_pos]))
            };

            let unfiltered = size - filtered;

            // Now we can update coder->pos and coder->size, because the
            // next coder in the chain (if any) was successful.
            self.pos = 0;
            self.size = unfiltered;

            if self.end_was_reached {
                // The last byte has been copied to out[] already. They are
                // left as is.
                self.size = 0;
            } else if unfiltered > 0 {
                // There is unfiltered data left in out[]. Copy it to
                // coder->buffer[] and rewind *out_pos appropriately.
                *out_pos -= unfiltered;
                self.buffer[..unfiltered].copy_from_slice(&out[*out_pos..*out_pos + unfiltered]);
            }
        } else if self.pos > 0 {
            self.buffer.copy_within(self.pos..self.pos + buf_avail, 0);
            self.size -= self.pos;
            self.pos = 0;
        }

        // If coder->buffer[] isn't empty, try to fill it by copying/decoding
        // more data. Then filter coder->buffer[] and copy the successfully
        // filtered data to out[]. It is probable, that some filtered and
        // unfiltered data will be left to coder->buffer[].
        if self.size > 0 {
            {
                let mut size = self.size;
                let allocated = self.allocated;
                let mut buffer = core::mem::take(&mut self.buffer);
                let ret =
                    self.copy_or_code(input, in_pos, &mut buffer[..allocated], &mut size, action);
                self.buffer = buffer;
                self.size = size;
                if ret != Ret::Ok {
                    return ret;
                }
            }

            self.filtered = self.call_filter(None);

            // Everything is considered to be filtered if coder->buffer[]
            // contains the last bytes of the data.
            if self.end_was_reached {
                self.filtered = self.size;
            }

            // Flush as much as possible.
            bufcpy(&self.buffer[..self.filtered], &mut self.pos, out, out_pos);
        }

        // Check if we got everything done.
        if self.end_was_reached && self.pos == self.size {
            return Ret::StreamEnd;
        }

        Ret::Ok
    }
}

/// `lzma_simple_props_decode`: the start offset, or none.
pub(crate) fn props_decode(props: &[u8]) -> Result<Option<BcjOptions>, Ret> {
    if props.is_empty() {
        return Ok(None);
    }

    if props.len() != 4 {
        return Err(Ret::OptionsError);
    }

    let start_offset = read32le(props);

    // Don't leave an options structure allocated if start_offset is zero.
    Ok((start_offset != 0).then_some(BcjOptions { start_offset }))
}

/// `lzma_simple_props_encode`: the start offset, unless it is zero.
pub(crate) fn props_encode(options: &BcjOptions, out: &mut [u8]) {
    if options.start_offset != 0 {
        write32le(out, options.start_offset);
    }
}
