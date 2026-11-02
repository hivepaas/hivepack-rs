//! The .lzma encoder: port of `common/alone_encoder.c`.

use crate::xz::common::{Action, NextCoder, Ret, bufcpy, write32le};
use crate::xz::filter::{FILTER_LZMA1, Filter, FilterOptions, raw_encoder_init};
use crate::xz::lzma_common::{DICT_SIZE_MIN, LzmaOptions};
use crate::xz::lzma_encoder::lclppb_encode;

const ALONE_HEADER_SIZE: usize = 1 + 4 + 8;

/// The sequence of the .lzma encoder.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sequence {
    Header,
    Code,
}

/// `lzma_alone_coder` of `alone_encoder.c`.
pub(crate) struct AloneEncoder {
    next: Box<dyn NextCoder>,
    sequence: Sequence,
    header_pos: usize,
    header: [u8; ALONE_HEADER_SIZE],
}

impl AloneEncoder {
    /// `alone_encoder_init`.
    pub(crate) fn new(options: &LzmaOptions) -> Result<AloneEncoder, Ret> {
        // Encode the header:
        let mut header = [0u8; ALONE_HEADER_SIZE];

        // - Properties (1 byte)
        header[0] = lclppb_encode(options).ok_or(Ret::OptionsError)?;

        // - Dictionary size (4 bytes)
        if options.dict_size < DICT_SIZE_MIN {
            return Err(Ret::OptionsError);
        }

        // Round up to the next 2^n or 2^n + 2^(n - 1) depending on which
        // one is the next unless it is UINT32_MAX. While the header would
        // allow any 32-bit integer, we do this to keep the decoder of
        // liblzma accepting the resulting files.
        let mut d = options.dict_size - 1;
        d |= d >> 2;
        d |= d >> 3;
        d |= d >> 4;
        d |= d >> 8;
        d |= d >> 16;
        d = d.saturating_add(1);

        write32le(&mut header[1..], d);

        // - Uncompressed size (always unknown and using EOPM)
        header[1 + 4..].fill(0xFF);

        // Initialize the LZMA encoder.
        let filter = Filter {
            id: FILTER_LZMA1,
            options: Some(FilterOptions::Lzma(options.clone())),
        };
        let next = raw_encoder_init(core::slice::from_ref(&filter))?;

        Ok(AloneEncoder {
            next,
            sequence: Sequence::Header,
            header_pos: 0,
            header,
        })
    }
}

impl NextCoder for AloneEncoder {
    /// `alone_encode`.
    fn code(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        output: &mut [u8],
        out_pos: &mut usize,
        action: Action,
    ) -> Ret {
        while *out_pos < output.len() {
            match self.sequence {
                Sequence::Header => {
                    bufcpy(&self.header, &mut self.header_pos, output, out_pos);
                    if self.header_pos < ALONE_HEADER_SIZE {
                        return Ret::Ok;
                    }

                    self.sequence = Sequence::Code;
                }

                Sequence::Code => {
                    return self.next.code(input, in_pos, output, out_pos, action);
                }
            }
        }

        Ret::Ok
    }
}
