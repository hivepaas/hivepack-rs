//! The .lzma (LZMA_Alone) decoder: port of `common/alone_decoder.c`.

use crate::xz::common::{Action, MEMUSAGE_BASE, NextCoder, Ret, VLI_UNKNOWN};
use crate::xz::filter::{FILTER_LZMA1EXT, Filter, FilterOptions, filter_init};
use crate::xz::lzma_common::{LZMA1EXT_ALLOW_EOPM, LzmaOptions};
use crate::xz::lzma_decoder::{decoder_memusage_nocheck, lclppb_decode};

/// The sequence of the .lzma decoder.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sequence {
    Properties,
    DictionarySize,
    UncompressedSize,
    CoderInit,
    Code,
}

/// `lzma_alone_coder`.
pub(crate) struct AloneDecoder {
    next: Option<Box<dyn NextCoder>>,
    sequence: Sequence,
    /// If true, reject files that are unlikely to be .lzma files. If
    /// false, more non-.lzma files get accepted and will give
    /// LZMA_DATA_ERROR either immediately or after a few output bytes.
    picky: bool,
    /// Position in the header fields.
    pos: usize,
    /// Uncompressed size decoded from the header.
    uncompressed_size: u64,
    /// Memory usage limit.
    memlimit: u64,
    /// Amount of memory actually needed (only an estimate).
    memusage: u64,
    /// Options decoded from the header needed to initialize the LZMA
    /// decoder.
    options: LzmaOptions,
}

impl AloneDecoder {
    /// `lzma_alone_decoder_init`.
    pub(crate) fn new(memlimit: u64, picky: bool) -> AloneDecoder {
        AloneDecoder {
            next: None,
            sequence: Sequence::Properties,
            picky,
            pos: 0,
            uncompressed_size: 0,
            memlimit: memlimit.max(1),
            memusage: MEMUSAGE_BASE,
            options: LzmaOptions::default(),
        }
    }
}

impl AloneDecoder {
    /// `SEQ_CODER_INIT`.
    fn coder_init(&mut self) -> Result<(), Ret> {
        if self.memusage > self.memlimit {
            return Err(Ret::MemlimitError);
        }
        let filter = Filter {
            id: FILTER_LZMA1EXT,
            options: Some(FilterOptions::Lzma(self.options.clone())),
        };
        match filter_init(core::slice::from_ref(&filter)) {
            Ok(next) => self.next = Some(next),
            Err(ret) => {
                self.next = None;
                return Err(ret);
            }
        }
        self.sequence = Sequence::Code;
        Ok(())
    }
}

impl NextCoder for AloneDecoder {
    /// `alone_decode`.
    fn code(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        output: &mut [u8],
        out_pos: &mut usize,
        action: Action,
    ) -> Ret {
        while *out_pos < output.len() && (self.sequence == Sequence::Code || *in_pos < input.len())
        {
            match self.sequence {
                Sequence::Properties => {
                    if lclppb_decode(&mut self.options, input[*in_pos]) {
                        return Ret::FormatError;
                    }
                    self.sequence = Sequence::DictionarySize;
                    *in_pos += 1;
                }
                Sequence::DictionarySize => {
                    self.options.dict_size |= u32::from(input[*in_pos]) << (self.pos * 8);

                    self.pos += 1;
                    if self.pos == 4 {
                        if self.picky && self.options.dict_size != u32::MAX {
                            // A hack to ditch tons of false positives: We
                            // allow only dictionary sizes that are 2^n or
                            // 2^n + 2^(n-1). LZMA_Alone created only files
                            // with 2^n, but accepts any dictionary size.
                            let mut d = self.options.dict_size.wrapping_sub(1);
                            d |= d >> 2;
                            d |= d >> 3;
                            d |= d >> 4;
                            d |= d >> 8;
                            d |= d >> 16;
                            d = d.wrapping_add(1);

                            if d != self.options.dict_size {
                                return Ret::FormatError;
                            }
                        }
                        self.pos = 0;
                        self.sequence = Sequence::UncompressedSize;
                    }
                    *in_pos += 1;
                }
                Sequence::UncompressedSize => {
                    self.uncompressed_size |= u64::from(input[*in_pos]) << (self.pos * 8);
                    *in_pos += 1;
                    self.pos += 1;
                    if self.pos < 8 {
                        continue;
                    }

                    // Another hack to ditch false positives: Assume that if
                    // the uncompressed size is known, it must be less than
                    // 256 GiB.
                    if self.picky
                        && self.uncompressed_size != VLI_UNKNOWN
                        && self.uncompressed_size >= 1 << 38
                    {
                        return Ret::FormatError;
                    }

                    // Use LZMA_FILTER_LZMA1EXT features to specify the
                    // uncompressed size and that the end marker is allowed
                    // even when the uncompressed size is known. Both .lzma
                    // header and LZMA1EXT use UINT64_MAX indicate that size
                    // is unknown.
                    self.options.ext_flags = LZMA1EXT_ALLOW_EOPM;
                    self.options.ext_size_low = self.uncompressed_size as u32;
                    self.options.ext_size_high = (self.uncompressed_size >> 32) as u32;

                    // Calculate the memory usage so that it is ready for
                    // SEQ_CODER_INIT.
                    self.memusage = decoder_memusage_nocheck(&self.options) + MEMUSAGE_BASE;

                    self.pos = 0;
                    self.sequence = Sequence::CoderInit;

                    // Falls through to SEQ_CODER_INIT, whatever is left
                    // of the input.
                    if let Err(ret) = self.coder_init() {
                        return ret;
                    }
                }
                Sequence::CoderInit => {
                    if let Err(ret) = self.coder_init() {
                        return ret;
                    }
                }
                Sequence::Code => {
                    let Some(next) = self.next.as_mut() else {
                        return Ret::ProgError;
                    };
                    return next.code(input, in_pos, output, out_pos, action);
                }
            }
        }
        Ret::Ok
    }

    /// `alone_decoder_memconfig`.
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
