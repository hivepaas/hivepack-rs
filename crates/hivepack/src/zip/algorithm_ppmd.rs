//! PPMd, ZIP's method 98, which libzip does not read: PPMd var.I rev. 1
//! [APPNOTE 5.10], with `ppmd8.rs`, the port of 7-Zip's. Decompressing
//! only.
//!
//! The data starts with two bytes, little-endian: the model's order less
//! one in bits 0 to 3, its memory in MiB less one in bits 4 to 11, and how
//! it is restored when that runs out in bits 12 to 15; the range coder's
//! bytes follow, to the end of the payload's marker. It is read as 7-Zip's
//! ZIP handler reads it (its PPMd decoder in full file mode, which needs
//! the marker): an order of 1 or a restore method past 2 is a data error,
//! the third method (freezing the model) not supported, as 7-Zip is built
//! without it; and after the marker, the range decoder must have ended
//! where the data does. What follows the data is the compressing layer's
//! to check, as for the other methods: with `ZIP_CHECKCONS` only, where
//! 7-Zip always refuses it.

use std::collections::VecDeque;

use crate::zip::algorithm_deflate::CompressionStatus;
use crate::zip::error::{Error, ErrorCode};
use crate::zip::ppmd8::{self, ByteIn, Ppmd8};

/// The version needed to extract PPMd data [APPNOTE 4.4.3.2].
pub(crate) const VERSION_NEEDED: u8 = 63;

/// The most `Ppmd8_DecodeSymbol` reads for a symbol: a normalization of
/// the range coder reads at most 8 bytes, and one is made after each of
/// the at most 17 contexts a symbol is looked for in, so 1 KiB is more than
/// enough. A symbol is decoded only with that much input waiting, or the
/// input's end, so that what it reads is what reading the whole data at
/// once would read.
const LOOKAHEAD: usize = 1024;

/// The input waiting, as the range decoder reads it: 0 past its end, and
/// remembered (`CByteInBufWrap`'s `Extra`).
struct Input<'a> {
    queue: &'a mut VecDeque<u8>,
    extra: &'a mut bool,
}

impl ByteIn for Input<'_> {
    fn read_byte(&mut self) -> u8 {
        match self.queue.pop_front() {
            Some(b) => b,
            None => {
                *self.extra = true;
                0
            }
        }
    }
}

/// Where the stream is.
enum State {
    /// Before its two bytes of parameters.
    Header,
    /// Its parameters read, before the range decoder's first four bytes.
    Start {
        order: u32,
        restore_method: u32,
        ppmd: Box<Ppmd8>,
    },
    /// Decoding.
    Decoding(Box<Ppmd8>),
    /// After the marker.
    Done,
}

/// A PPMd stream being decompressed.
pub(crate) struct Ppmd {
    queue: VecDeque<u8>,
    end_of_input: bool,
    /// Bytes were read past the input's end.
    extra: bool,
    state: State,
    /// An error found after bytes were given out, for the next call.
    pending: Option<Error>,
}

/// A data error: 7-Zip's `S_FALSE`.
fn data_error() -> Error {
    Error::new(ErrorCode::CompressedData, 0)
}

impl Ppmd {
    pub(crate) fn decompressor() -> Ppmd {
        Ppmd {
            queue: VecDeque::new(),
            end_of_input: false,
            extra: false,
            state: State::Header,
            pending: None,
        }
    }

    /// The version needed to extract it.
    pub(crate) fn version_needed(&self) -> u8 {
        VERSION_NEEDED
    }

    /// `general_purpose_bit_flags`: none.
    pub(crate) fn general_purpose_bit_flags(&self) -> u16 {
        0
    }

    pub(crate) fn start(&mut self) -> Result<(), Error> {
        self.queue.clear();
        self.end_of_input = false;
        self.extra = false;
        self.state = State::Header;
        self.pending = None;
        Ok(())
    }

    pub(crate) fn end(&mut self) -> Result<(), Error> {
        self.state = State::Done;
        Ok(())
    }

    /// `input`: `length` bytes at the start of the buffer, kept until the
    /// range decoder reads them.
    pub(crate) fn input(&mut self, buffer: &[u8], length: usize) -> Result<(), Error> {
        self.queue.extend(&buffer[..length]);
        Ok(())
    }

    /// `end_of_input`: whether input is left over.
    pub(crate) fn end_of_input(&mut self) -> bool {
        self.end_of_input = true;
        !self.queue.is_empty()
    }

    /// Whether input is left that the stream did not read: after its end,
    /// what follows it, for the compressing layer to refuse with
    /// `ZIP_CHECKCONS` (as it refuses what follows the other methods' data).
    pub(crate) fn input_left(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Whether there is enough input for `want` bytes to be read as from all
    /// of it.
    fn enough(&self, want: usize) -> bool {
        self.end_of_input || self.queue.len() >= want
    }

    /// `process`: decompresses into `data`, returning the status and the
    /// bytes written.
    pub(crate) fn process(
        &mut self,
        _buffer: &[u8],
        data: &mut [u8],
    ) -> (CompressionStatus, usize) {
        if let Some(error) = self.pending.take() {
            return (CompressionStatus::Error(error), 0);
        }
        loop {
            match std::mem::replace(&mut self.state, State::Done) {
                State::Header => {
                    if !self.enough(2) {
                        self.state = State::Header;
                        return (CompressionStatus::NeedData, 0);
                    }
                    let mut input = Input {
                        queue: &mut self.queue,
                        extra: &mut self.extra,
                    };
                    let val = u32::from(input.read_byte()) | u32::from(input.read_byte()) << 8;
                    if self.extra {
                        return (CompressionStatus::Error(data_error()), 0);
                    }
                    let order = (val & 0xF) + 1;
                    let mem = ((val >> 4) & 0xFF) + 1;
                    let restore_method = val >> 12;
                    if order < ppmd8::MIN_ORDER || restore_method > 2 {
                        return (CompressionStatus::Error(data_error()), 0);
                    }
                    if restore_method == 2 {
                        // Freezing the model, which 7-Zip does not read.
                        return (
                            CompressionStatus::Error(Error::new(ErrorCode::CompNotSupp, 0)),
                            0,
                        );
                    }
                    let Some(ppmd) = Ppmd8::new(mem << 20) else {
                        return (
                            CompressionStatus::Error(Error::new(ErrorCode::Memory, 0)),
                            0,
                        );
                    };
                    self.state = State::Start {
                        order,
                        restore_method,
                        ppmd,
                    };
                }
                State::Start {
                    order,
                    restore_method,
                    mut ppmd,
                } => {
                    if !self.enough(4) {
                        self.state = State::Start {
                            order,
                            restore_method,
                            ppmd,
                        };
                        return (CompressionStatus::NeedData, 0);
                    }
                    let mut input = Input {
                        queue: &mut self.queue,
                        extra: &mut self.extra,
                    };
                    if !ppmd.init_range_dec(&mut input) {
                        return (CompressionStatus::Error(data_error()), 0);
                    }
                    ppmd.init(order, restore_method);
                    self.state = State::Decoding(ppmd);
                }
                State::Decoding(mut ppmd) => {
                    let mut written = 0;
                    while written < data.len() {
                        if !self.enough(LOOKAHEAD) {
                            self.state = State::Decoding(ppmd);
                            return (CompressionStatus::NeedData, written);
                        }
                        let mut input = Input {
                            queue: &mut self.queue,
                            extra: &mut self.extra,
                        };
                        let sym = ppmd.decode_symbol(&mut input);
                        if self.extra || sym == ppmd8::SYM_ERROR {
                            return self.fail(written);
                        }
                        if sym == ppmd8::SYM_END {
                            if !ppmd.range_dec_is_finished_ok() {
                                return self.fail(written);
                            }
                            return (CompressionStatus::End, written);
                        }
                        data[written] = sym as u8;
                        written += 1;
                    }
                    self.state = State::Decoding(ppmd);
                    return (CompressionStatus::Ok, written);
                }
                State::Done => return (CompressionStatus::End, 0),
            }
        }
    }

    /// A data error after `written` bytes: those first, then the error.
    fn fail(&mut self, written: usize) -> (CompressionStatus, usize) {
        if written == 0 {
            return (CompressionStatus::Error(data_error()), 0);
        }
        self.pending = Some(data_error());
        (CompressionStatus::Ok, written)
    }
}
