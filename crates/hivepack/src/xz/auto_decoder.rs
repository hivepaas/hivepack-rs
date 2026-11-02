//! The decoder of .xz, .lzma and .lz, chosen by the first byte: port of
//! `common/auto_decoder.c`.

use crate::xz::alone_decoder::AloneDecoder;
use crate::xz::check::Check;
use crate::xz::common::{
    Action, CONCATENATED, MEMUSAGE_BASE, NextCoder, Ret, SUPPORTED_FLAGS, TELL_ANY_CHECK,
    TELL_NO_CHECK,
};
use crate::xz::lzip_decoder::LzipDecoder;
use crate::xz::stream_decoder::StreamDecoder;

/// The sequence of the auto decoder.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sequence {
    Init,
    Code,
    Finish,
}

/// `lzma_auto_coder`.
pub(crate) struct AutoDecoder {
    /// .xz Stream decoder, LZMA_Alone decoder, or lzip decoder
    next: Option<Box<dyn NextCoder>>,
    memlimit: u64,
    flags: u32,
    sequence: Sequence,
}

impl AutoDecoder {
    /// `auto_decoder_init`.
    pub(crate) fn new(memlimit: u64, flags: u32) -> Result<AutoDecoder, Ret> {
        if flags & !SUPPORTED_FLAGS != 0 {
            return Err(Ret::OptionsError);
        }
        Ok(AutoDecoder {
            next: None,
            memlimit: memlimit.max(1),
            flags,
            sequence: Sequence::Init,
        })
    }
}

impl NextCoder for AutoDecoder {
    /// `auto_decode`.
    fn code(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        output: &mut [u8],
        out_pos: &mut usize,
        action: Action,
    ) -> Ret {
        if self.sequence == Sequence::Init {
            if *in_pos >= input.len() {
                return Ret::Ok;
            }

            // Update the sequence now, because we want to continue from
            // SEQ_CODE even if we return some LZMA_*_CHECK.
            self.sequence = Sequence::Code;

            // Detect the file format. .xz files start with 0xFD which
            // cannot be the first byte of .lzma (LZMA_Alone) format. The .lz
            // format starts with 0x4C which could be the first byte of a
            // .lzma file but luckily it would mean lc=3, lp=1, pb=1 which
            // are very unlikely values in .lzma.
            if input[*in_pos] == 0xFD {
                match StreamDecoder::new(self.memlimit, self.flags) {
                    Ok(next) => self.next = Some(Box::new(next)),
                    Err(ret) => return ret,
                }
            } else if input[*in_pos] == 0x4C {
                match LzipDecoder::new(self.memlimit, self.flags) {
                    Ok(next) => self.next = Some(Box::new(next)),
                    Err(ret) => return ret,
                }
            } else {
                self.next = Some(Box::new(AloneDecoder::new(self.memlimit, true)));

                // If the application wants to know about missing integrity
                // check or about the check in general, we need to handle it
                // here, because LZMA_Alone decoder doesn't accept any flags.
                if self.flags & TELL_NO_CHECK != 0 {
                    return Ret::NoCheck;
                }
                if self.flags & TELL_ANY_CHECK != 0 {
                    return Ret::GetCheck;
                }
            }
        }

        if self.sequence == Sequence::Code {
            let Some(next) = self.next.as_mut() else {
                return Ret::ProgError;
            };
            let ret = next.code(input, in_pos, output, out_pos, action);
            if ret != Ret::StreamEnd || self.flags & CONCATENATED == 0 {
                return ret;
            }
            self.sequence = Sequence::Finish;
        }

        // When LZMA_CONCATENATED was used and we were decoding a LZMA_Alone
        // file, we need to check that there is no trailing garbage and wait
        // for LZMA_FINISH.
        if *in_pos < input.len() {
            return Ret::DataError;
        }
        if action == Action::Finish {
            Ret::StreamEnd
        } else {
            Ret::Ok
        }
    }

    /// `auto_decoder_get_check`.
    fn get_check(&self) -> Option<Check> {
        // It is LZMA_Alone if get_check is NULL.
        Some(
            self.next
                .as_ref()
                .and_then(|next| next.get_check())
                .unwrap_or(Check::NONE),
        )
    }

    /// `auto_decoder_memconfig`.
    fn memconfig(
        &mut self,
        memusage: &mut u64,
        old_memlimit: &mut u64,
        new_memlimit: u64,
    ) -> Option<Ret> {
        let ret = match self.next.as_mut() {
            // A decoder is initialized and it has memconfig.
            Some(next) => next
                .memconfig(memusage, old_memlimit, new_memlimit)
                .unwrap_or(Ret::ProgError),
            None => {
                // No coder is configured yet. Use the base value as the
                // current memory usage.
                *memusage = MEMUSAGE_BASE;
                *old_memlimit = self.memlimit;
                if new_memlimit != 0 && new_memlimit < *memusage {
                    Ret::MemlimitError
                } else {
                    Ret::Ok
                }
            }
        };

        if ret == Ret::Ok && new_memlimit != 0 {
            self.memlimit = new_memlimit;
        }
        Some(ret)
    }
}
