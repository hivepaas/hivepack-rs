//! The .lz (lzip) decoder: port of `common/lzip_decoder.c`.

use crate::xz::check::{Check, crc32};
use crate::xz::common::{
    Action, CONCATENATED, IGNORE_CHECK, MEMUSAGE_BASE, NextCoder, Ret, SUPPORTED_FLAGS,
    TELL_ANY_CHECK, bufcpy, read32le, read64le,
};
use crate::xz::filter::{FILTER_LZMA1, Filter, FilterOptions, filter_init};
use crate::xz::lzma_common::LzmaOptions;
use crate::xz::lzma_decoder::decoder_memusage_nocheck;

/// `LZIP_V0_FOOTER_SIZE`.
const LZIP_V0_FOOTER_SIZE: usize = 12;
/// `LZIP_V1_FOOTER_SIZE`.
const LZIP_V1_FOOTER_SIZE: usize = 20;
/// `LZIP_FOOTER_SIZE_MAX`.
const LZIP_FOOTER_SIZE_MAX: usize = LZIP_V1_FOOTER_SIZE;

// lc/lp/pb are hardcoded in the .lz format.
const LZIP_LC: u32 = 3;
const LZIP_LP: u32 = 0;
const LZIP_PB: u32 = 2;

/// The sequence of the .lz decoder.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sequence {
    IdString,
    Version,
    DictSize,
    CoderInit,
    LzmaStream,
    MemberFooter,
}

/// `lzma_lzip_coder`.
pub(crate) struct LzipDecoder {
    sequence: Sequence,
    /// .lz member format version
    version: u32,
    /// CRC32 of the uncompressed data in the .lz member
    crc32: u32,
    /// Uncompressed size of the .lz member
    uncompressed_size: u64,
    /// Compressed size of the .lz member
    member_size: u64,
    /// Memory usage limit
    memlimit: u64,
    /// Amount of memory actually needed
    memusage: u64,
    /// If true, LZMA_GET_CHECK is returned after decoding the header
    /// fields. As all files use CRC32 this is redundant but it's an easy
    /// way to keep the behavior consistent with the .xz decoder.
    tell_any_check: bool,
    /// If true, we won't calculate or verify the CRC32 of the uncompressed
    /// data.
    ignore_check: bool,
    /// If true, we will decode concatenated .lz members and stop if
    /// non-.lz data is seen after at least one member has been
    /// successfully decoded.
    concatenated: bool,
    /// When decoding concatenated .lz members, this is true as long as we
    /// are decoding the first .lz member. This is needed to avoid
    /// incorrect LZMA_FORMAT_ERROR in case there is non-.lz data after
    /// .lz member(s).
    first_member: bool,
    /// Reading position in the header and footer fields
    pos: usize,
    /// Buffer to hold the .lz footer fields
    buffer: [u8; LZIP_FOOTER_SIZE_MAX],
    /// Options decoded from the .lz header that needed to initialize the
    /// LZMA1 decoder.
    options: LzmaOptions,
    /// LZMA1 decoder
    lzma_decoder: Option<Box<dyn NextCoder>>,
}

impl LzipDecoder {
    /// `lzma_lzip_decoder_init`.
    pub(crate) fn new(memlimit: u64, flags: u32) -> Result<LzipDecoder, Ret> {
        if flags & !SUPPORTED_FLAGS != 0 {
            return Err(Ret::OptionsError);
        }
        Ok(LzipDecoder {
            sequence: Sequence::IdString,
            version: 0,
            crc32: 0,
            uncompressed_size: 0,
            member_size: 0,
            memlimit: memlimit.max(1),
            memusage: MEMUSAGE_BASE,
            tell_any_check: flags & TELL_ANY_CHECK != 0,
            ignore_check: flags & IGNORE_CHECK != 0,
            concatenated: flags & CONCATENATED != 0,
            first_member: true,
            pos: 0,
            buffer: [0; LZIP_FOOTER_SIZE_MAX],
            options: LzmaOptions::default(),
            lzma_decoder: None,
        })
    }
}

impl NextCoder for LzipDecoder {
    /// `lzip_decode`.
    fn code(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        output: &mut [u8],
        out_pos: &mut usize,
        action: Action,
    ) -> Ret {
        loop {
            match self.sequence {
                Sequence::IdString => {
                    // The "ID string" or magic bytes are "LZIP" in US-ASCII.
                    const LZIP_ID_STRING: [u8; 4] = [0x4C, 0x5A, 0x49, 0x50];

                    while self.pos < LZIP_ID_STRING.len() {
                        if *in_pos >= input.len() {
                            // If we are on the 2nd+ concatenated member and
                            // the input ends before we can read the magic
                            // bytes, we discard the bytes that were already
                            // read (up to 3) and finish. See the reasoning
                            // below.
                            return if !self.first_member && action == Action::Finish {
                                Ret::StreamEnd
                            } else {
                                Ret::Ok
                            };
                        }

                        if input[*in_pos] != LZIP_ID_STRING[self.pos] {
                            // The .lz format allows putting non-.lz data at
                            // the end of the file. If we have seen at least
                            // one valid .lz member already, then we won't
                            // consume the byte at *in_pos and will return
                            // LZMA_STREAM_END. This way apps can easily
                            // locate and read the non-.lz data after the .lz
                            // member(s).
                            //
                            // NOTE: It's possible that the first 1-3 bytes
                            // of the non-.lz data have been consumed
                            // already. It's an unfortunate quirk of the
                            // format.
                            return if !self.first_member {
                                Ret::StreamEnd
                            } else {
                                Ret::FormatError
                            };
                        }

                        *in_pos += 1;
                        self.pos += 1;
                    }

                    self.pos = 0;
                    self.crc32 = 0;
                    self.uncompressed_size = 0;
                    self.member_size = LZIP_ID_STRING.len() as u64;
                    self.sequence = Sequence::Version;
                }
                Sequence::Version => {
                    if *in_pos >= input.len() {
                        return Ret::Ok;
                    }

                    self.version = u32::from(input[*in_pos]);
                    *in_pos += 1;

                    // We support version 0 and unextended version 1.
                    if self.version > 1 {
                        return Ret::OptionsError;
                    }

                    self.member_size += 1;
                    self.sequence = Sequence::DictSize;

                    // .lz versions 0 and 1 use CRC32 as the integrity
                    // check so if the application wanted to know that
                    // (LZMA_TELL_ANY_CHECK) we can tell it now.
                    if self.tell_any_check {
                        return Ret::GetCheck;
                    }
                }
                Sequence::DictSize => {
                    if *in_pos >= input.len() {
                        return Ret::Ok;
                    }

                    let ds = u32::from(input[*in_pos]);
                    *in_pos += 1;
                    self.member_size += 1;

                    // The five lowest bits are for the base-2 logarithm of
                    // the dictionary size and the highest three bits are
                    // the fractional part (0/16 to 7/16) that will be
                    // subtracted to get the final value.
                    //
                    // For example, with 0xB5:
                    //     b2log = 21
                    //     fracnum = 5
                    //     dict_size = 2^21 - 2^21 * 5 / 16 = 1408 KiB
                    let b2log = ds & 0x1F;
                    let fracnum = ds >> 5;

                    // The format versions 0 and 1 allow dictionary size in
                    // the range [4 KiB, 512 MiB].
                    if !(12..=29).contains(&b2log) || (b2log == 12 && fracnum > 0) {
                        return Ret::DataError;
                    }

                    //   2^[b2log] - 2^[b2log] * [fracnum] / 16
                    // = 2^[b2log] - [fracnum] * 2^([b2log] - 4)
                    self.options.dict_size = (1 << b2log) - (fracnum << (b2log - 4));
                    self.options.preset_dict = None;
                    self.options.lc = LZIP_LC;
                    self.options.lp = LZIP_LP;
                    self.options.pb = LZIP_PB;

                    // Calculate the memory usage so that it is ready for
                    // SEQ_CODER_INIT.
                    self.memusage = decoder_memusage_nocheck(&self.options) + MEMUSAGE_BASE;

                    self.sequence = Sequence::CoderInit;
                }
                Sequence::CoderInit => {
                    if self.memusage > self.memlimit {
                        return Ret::MemlimitError;
                    }

                    let filter = Filter {
                        id: FILTER_LZMA1,
                        options: Some(FilterOptions::Lzma(self.options.clone())),
                    };
                    match filter_init(core::slice::from_ref(&filter)) {
                        Ok(decoder) => self.lzma_decoder = Some(decoder),
                        Err(ret) => {
                            self.lzma_decoder = None;
                            return ret;
                        }
                    }

                    // LZMA1 decoder has been initialized. Now CRC32 must be
                    // initialized.
                    self.crc32 = 0;
                    self.sequence = Sequence::LzmaStream;
                }
                Sequence::LzmaStream => {
                    let Some(decoder) = self.lzma_decoder.as_mut() else {
                        return Ret::ProgError;
                    };
                    let in_start = *in_pos;
                    let out_start = *out_pos;

                    let ret = decoder.code(input, in_pos, output, out_pos, action);

                    let out_used = *out_pos - out_start;

                    self.member_size += (*in_pos - in_start) as u64;
                    self.uncompressed_size += out_used as u64;

                    // Don't update the CRC32 if the integrity check will be
                    // ignored or if there was no new output. The latter is
                    // important in case out == NULL to avoid null pointer +
                    // 0 which is undefined behavior.
                    if !self.ignore_check && out_used > 0 {
                        self.crc32 = crc32(&output[out_start..*out_pos], self.crc32);
                    }

                    if ret != Ret::StreamEnd {
                        return ret;
                    }
                    self.sequence = Sequence::MemberFooter;
                }
                Sequence::MemberFooter => {
                    // The footer of .lz version 0 lacks the Member size
                    // field. This is the only difference between version 0
                    // and unextended version 1 formats.
                    let footer_size = if self.version == 0 {
                        LZIP_V0_FOOTER_SIZE
                    } else {
                        LZIP_V1_FOOTER_SIZE
                    };

                    // Copy the CRC32, Data size, and Member size fields to
                    // the internal buffer.
                    bufcpy(
                        input,
                        in_pos,
                        &mut self.buffer[..footer_size],
                        &mut self.pos,
                    );

                    // Return if we didn't get the whole footer yet.
                    if self.pos < footer_size {
                        return Ret::Ok;
                    }

                    self.pos = 0;
                    self.member_size += footer_size as u64;

                    // Check that the CRC32 from the .lz file matches with
                    // what we calculated from the uncompressed data.
                    if !self.ignore_check && self.crc32 != read32le(&self.buffer[0..]) {
                        return Ret::DataError;
                    }

                    // Check that the uncompressed size matches.
                    if self.uncompressed_size != read64le(&self.buffer[4..]) {
                        return Ret::DataError;
                    }

                    // Check that the compressed size of the .lz member
                    // matches if the format version is 1.
                    if self.version > 0 && self.member_size != read64le(&self.buffer[12..]) {
                        return Ret::DataError;
                    }

                    // We decoded one member successfully. If we are not
                    // decoding concatenated .lz members, we are done.
                    if !self.concatenated {
                        return Ret::StreamEnd;
                    }

                    self.first_member = false;
                    self.sequence = Sequence::IdString;
                }
            }
        }
    }

    /// `lzip_decoder_get_check`.
    fn get_check(&self) -> Option<Check> {
        Some(Check::CRC32)
    }

    /// `lzip_decoder_memconfig`.
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
