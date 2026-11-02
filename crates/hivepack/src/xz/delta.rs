//! The delta filter: port of `delta/delta_common.c`, `delta_decoder.c`
//! and `delta_encoder.c`.

use crate::xz::common::{Action, NextCoder, Ret};
use crate::xz::filter::{DELTA_DIST_MAX, DELTA_DIST_MIN, DELTA_TYPE_BYTE, DeltaOptions};

/// `sizeof(lzma_delta_coder)` in liblzma on 64-bit systems, which its
/// memory usage counts.
const DELTA_CODER_SIZE: u64 = 352;

/// `lzma_delta_coder`: the distance and the history, without the next
/// coder.
struct Delta {
    /// Delta distance
    distance: usize,
    /// Position in history[]
    pos: u8,
    /// Buffer to hold history of the original data
    history: [u8; DELTA_DIST_MAX as usize],
}

impl Delta {
    /// `lzma_delta_coder_init`, but for the next coder.
    fn new(options: Option<DeltaOptions>) -> Result<Delta, Ret> {
        // Validate the options.
        if coder_memusage(options.as_ref()) == u64::MAX {
            return Err(Ret::OptionsError);
        }
        let options = options.ok_or(Ret::OptionsError)?;

        // Set the delta distance and reset the history.
        Ok(Delta {
            distance: options.dist as usize,
            pos: 0,
            history: [0; DELTA_DIST_MAX as usize],
        })
    }

    /// `decode_buffer`.
    ///
    /// Differs from liblzma, without a difference to see: liblzma adds the
    /// byte `distance` back from the history to each, and stores each in
    /// the history. Past the first `distance` bytes, the port adds the one
    /// in `buffer`, which is the same byte, and stores only the last 256 in
    /// the history at the end, where liblzma would have them. Each byte
    /// then waits for an addition, not for a store to the history and a
    /// load from it (and at a distance of 1, not for a load at all).
    fn decode_buffer(&mut self, buffer: &mut [u8]) {
        let distance = self.distance;
        let head = distance.min(buffer.len());
        for byte in &mut buffer[..head] {
            *byte = byte.wrapping_add(self.history[(distance + self.pos as usize) & 0xFF]);
            self.history[self.pos as usize] = *byte;
            self.pos = self.pos.wrapping_sub(1);
        }

        if distance == 1 && head == 1 {
            // The byte before, kept in a register rather than loaded.
            let mut prev = buffer[0];
            for byte in &mut buffer[1..] {
                prev = byte.wrapping_add(prev);
                *byte = prev;
            }
        } else {
            for i in head..buffer.len() {
                buffer[i] = buffer[i].wrapping_add(buffer[i - distance]);
            }
        }

        // Byte i of the rest goes at pos - (i - head) in the history, and
        // only the last 256 stay there.
        let rest = buffer.len() - head;
        for i in head + rest.saturating_sub(DELTA_DIST_MAX as usize)..buffer.len() {
            self.history[self.pos.wrapping_sub((i - head) as u8) as usize] = buffer[i];
        }
        self.pos = self.pos.wrapping_sub(rest as u8);
    }

    /// `copy_and_encode`.
    fn copy_and_encode(&mut self, input: &[u8], output: &mut [u8]) {
        let distance = self.distance;
        for (out, &byte) in output.iter_mut().zip(input) {
            let tmp = self.history[(distance + self.pos as usize) & 0xFF];
            self.history[self.pos as usize] = byte;
            self.pos = self.pos.wrapping_sub(1);
            *out = byte.wrapping_sub(tmp);
        }
    }

    /// `encode_in_place`.
    fn encode_in_place(&mut self, buffer: &mut [u8]) {
        let distance = self.distance;
        for byte in buffer {
            let tmp = self.history[(distance + self.pos as usize) & 0xFF];
            self.history[self.pos as usize] = *byte;
            self.pos = self.pos.wrapping_sub(1);
            *byte = byte.wrapping_sub(tmp);
        }
    }
}

/// `lzma_delta_coder_memusage`: u64::MAX for invalid options.
pub(crate) fn coder_memusage(options: Option<&DeltaOptions>) -> u64 {
    match options {
        Some(opt)
            if opt.delta_type == DELTA_TYPE_BYTE
                && (DELTA_DIST_MIN..=DELTA_DIST_MAX).contains(&opt.dist) =>
        {
            DELTA_CODER_SIZE
        }
        _ => u64::MAX,
    }
}

/// The delta decoder, `delta_decode`.
pub(crate) struct DeltaDecoder {
    delta: Delta,
    next: Option<Box<dyn NextCoder>>,
}

impl DeltaDecoder {
    /// `lzma_delta_decoder_init`, before the next filter is made.
    pub(crate) fn new(options: Option<DeltaOptions>) -> Result<DeltaDecoder, Ret> {
        Ok(DeltaDecoder {
            delta: Delta::new(options)?,
            next: None,
        })
    }

    /// The next filter in the chain, made after this one.
    pub(crate) fn set_next(&mut self, next: Option<Box<dyn NextCoder>>) {
        self.next = next;
    }
}

impl NextCoder for DeltaDecoder {
    fn code(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        output: &mut [u8],
        out_pos: &mut usize,
        action: Action,
    ) -> Ret {
        // The delta filter is never the last one.
        let Some(next) = self.next.as_mut() else {
            return Ret::ProgError;
        };

        let out_start = *out_pos;

        let ret = next.code(input, in_pos, output, out_pos, action);

        // out might be NULL. In that case size == 0. Null pointer + 0 is
        // undefined behavior so skip the call in that case as it would do
        // nothing anyway.
        if *out_pos > out_start {
            self.delta.decode_buffer(&mut output[out_start..*out_pos]);
        }

        ret
    }
}

/// The delta encoder, `delta_encode`.
pub(crate) struct DeltaEncoder {
    delta: Delta,
    next: Option<Box<dyn NextCoder>>,
}

impl DeltaEncoder {
    /// `lzma_delta_encoder_init`, before the next filter is made: with the
    /// input from it, or from the caller if none.
    pub(crate) fn new(options: Option<DeltaOptions>) -> Result<DeltaEncoder, Ret> {
        Ok(DeltaEncoder {
            delta: Delta::new(options)?,
            next: None,
        })
    }

    /// The next filter in the chain, made after this one.
    pub(crate) fn set_next(&mut self, next: Option<Box<dyn NextCoder>>) {
        self.next = next;
    }
}

impl NextCoder for DeltaEncoder {
    fn code(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        output: &mut [u8],
        out_pos: &mut usize,
        action: Action,
    ) -> Ret {
        match self.next.as_mut() {
            None => {
                // If there is no next filter in the chain, encode the input
                // into the output.
                let size = (input.len() - *in_pos).min(output.len() - *out_pos);
                if size > 0 {
                    self.delta.copy_and_encode(
                        &input[*in_pos..*in_pos + size],
                        &mut output[*out_pos..*out_pos + size],
                    );
                }

                *in_pos += size;
                *out_pos += size;

                if action != Action::Run && *in_pos == input.len() {
                    Ret::StreamEnd
                } else {
                    Ret::Ok
                }
            }
            Some(next) => {
                let out_start = *out_pos;

                let ret = next.code(input, in_pos, output, out_pos, action);

                // Like above, avoid null pointer + 0.
                if *out_pos > out_start {
                    self.delta.encode_in_place(&mut output[out_start..*out_pos]);
                }

                ret
            }
        }
    }
}

/// `lzma_delta_props_decode`.
pub(crate) fn props_decode(props: &[u8]) -> Result<DeltaOptions, Ret> {
    if props.len() != 1 {
        return Err(Ret::OptionsError);
    }

    Ok(DeltaOptions {
        delta_type: DELTA_TYPE_BYTE,
        dist: u32::from(props[0]) + 1,
    })
}

/// `lzma_delta_props_encode`.
pub(crate) fn props_encode(options: Option<&DeltaOptions>, out: &mut [u8]) -> Ret {
    // The caller must have already validated the options, so it's
    // LZMA_PROG_ERROR if they are invalid.
    let Some(opt) = options.filter(|_| coder_memusage(options) != u64::MAX) else {
        return Ret::ProgError;
    };

    out[0] = (opt.dist - DELTA_DIST_MIN) as u8;

    Ret::Ok
}
