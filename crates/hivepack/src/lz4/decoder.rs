//! Reading `.lz4` files: the frames of the frame format one after another,
//! skippable frames skipped, and the legacy format.
//!
//! This is the port's own, with what the `lz4` program's decompression does
//! (`lz4 -d`, `programs/lz4io.c`, which is under the GPL and is not ported):
//! liblz4's file functions (`lz4file.c`) read one frame only, from a file
//! of at least 19 bytes.

use std::io::{self, Read};

use crate::lz4::lz4::{self, KB};
use crate::lz4::lz4frame::{
    DecompressOptions, DecompressionContext, InBuffer, MAGIC_SKIPPABLE_START, MAGICNUMBER,
    OutBuffer,
};

/// The magic number of the legacy format.
pub const LEGACY_MAGICNUMBER: u32 = 0x184C_2102;
/// The size of the legacy format's blocks: all but the last are full.
pub const LEGACY_BLOCKSIZE: usize = 8 << 20;

/// How much input the decoder reads at a time.
const INPUT_SIZE: usize = 64 * KB;

/// Whether a magic number starts a frame: of the frame format, a skippable
/// frame, or the legacy format.
fn known_magic(magic: u32) -> bool {
    magic == MAGICNUMBER
        || magic & 0xFFFF_FFF0 == MAGIC_SKIPPABLE_START
        || magic == LEGACY_MAGICNUMBER
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    /// Between frames: the next 4 bytes are a magic number, or the end.
    Magic,
    /// In a frame (or skippable frame), which the context decodes.
    Frame,
    /// In a legacy frame, before a block's size.
    Legacy,
    /// The end: no more frames.
    Done,
}

/// A reader of `.lz4` data: everything `lz4 -d` decodes, as one stream.
///
/// - Frames of the frame format, one after another, their checksums
///   checked.
/// - Skippable frames, skipped.
/// - The legacy format (`lz4 -l`, which the Linux kernel's images use):
///   blocks of 8 MB, ending at the end of the input or where a magic number
///   follows.
///
/// As `lz4 -d`, an empty input is an empty stream, and data that is not a
/// frame, at the start or after the frames, is an error
/// ([`io::ErrorKind::InvalidData`]; `lz4 -d` says "Stream followed by
/// undecodable data" for the latter, and fails), as is damaged data. A
/// frame cut short is an error too ([`io::ErrorKind::UnexpectedEof`]).
///
/// Differs from `lz4 -d` 1.10.0: a legacy frame may follow a frame of the
/// frame format, as the format's description says, where `lz4 -d` gives
/// `ERROR_frameType_unknown`; and a skippable frame cut short is an error,
/// where `lz4 -d` seeks past the end of its file.
#[derive(Debug)]
pub struct Decoder<R> {
    inner: R,
    dctx: DecompressionContext,
    state: State,
    input: Box<[u8]>,
    input_pos: usize,
    input_len: usize,
    /// No more input: `inner` returned 0.
    input_end: bool,
    /// A legacy block, decoded, and how much of it was read.
    legacy: Vec<u8>,
    legacy_pos: usize,
    legacy_block: Vec<u8>,
    frames: u64,
}

impl<R: Read> Decoder<R> {
    /// A decoder of what `inner` reads.
    pub fn new(inner: R) -> Self {
        Decoder {
            inner,
            dctx: DecompressionContext::new(),
            state: State::Magic,
            input: vec![0; INPUT_SIZE].into_boxed_slice(),
            input_pos: 0,
            input_len: 0,
            input_end: false,
            legacy: Vec::new(),
            legacy_pos: 0,
            legacy_block: Vec::new(),
            frames: 0,
        }
    }

    /// The reader the input comes from.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// The reader the input comes from. Reading from it skips what the
    /// decoder has not read yet of what it took.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// The reader, and what the decoder took from it but did not decode.
    pub fn into_inner(self) -> (R, Vec<u8>) {
        let rest = self.input[self.input_pos..self.input_len].to_vec();
        (self.inner, rest)
    }

    /// How many frames (skippable and legacy ones included) were started.
    pub fn frames(&self) -> u64 {
        self.frames
    }

    /// More input, if what is left is empty and there is more. Returns
    /// what is left.
    fn fill(&mut self) -> io::Result<usize> {
        if self.input_pos == self.input_len && !self.input_end {
            self.input_pos = 0;
            self.input_len = 0;
            loop {
                match self.inner.read(&mut self.input) {
                    Ok(0) => self.input_end = true,
                    Ok(n) => self.input_len = n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
                break;
            }
        }
        Ok(self.input_len - self.input_pos)
    }

    /// The next 4 bytes, little-endian, or `None` at the end of the input.
    /// 1 to 3 bytes are an error.
    fn read_u32(&mut self) -> io::Result<Option<u32>> {
        let mut bytes = [0; 4];
        let mut got = 0;
        while got < 4 {
            if self.fill()? == 0 {
                if got == 0 {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "LZ4 data cut short",
                ));
            }
            let take = (4 - got).min(self.input_len - self.input_pos);
            bytes[got..got + take]
                .copy_from_slice(&self.input[self.input_pos..self.input_pos + take]);
            self.input_pos += take;
            got += take;
        }
        Ok(Some(u32::from_le_bytes(bytes)))
    }

    /// The next frame after its magic number, already read.
    fn start(&mut self, magic: u32) -> io::Result<()> {
        if !known_magic(magic) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                if self.frames == 0 {
                    "not LZ4 data"
                } else {
                    "LZ4 stream followed by undecodable data"
                },
            ));
        }
        self.frames += 1;
        if magic == LEGACY_MAGICNUMBER {
            self.state = State::Legacy;
            return Ok(());
        }
        // The context reads the frame from its magic number.
        self.dctx.reset();
        let mut output = OutBuffer::new(&mut []);
        let bytes = magic.to_le_bytes();
        let mut input = InBuffer::new(&bytes);
        while input.pos < bytes.len() {
            self.dctx
                .decompress(&mut output, &mut input, DecompressOptions::default())
                .map_err(frame_error)?;
        }
        self.state = State::Frame;
        Ok(())
    }

    /// The next legacy block, or the end of the legacy frame.
    fn legacy_block(&mut self) -> io::Result<()> {
        let Some(size) = self.read_u32()? else {
            self.state = State::Done;
            return Ok(());
        };
        if known_magic(size) {
            return self.start(size);
        }
        let size = size as usize;
        if size > lz4::compress_bound(LEGACY_BLOCKSIZE) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid LZ4 legacy block size",
            ));
        }
        self.legacy_block.clear();
        while self.legacy_block.len() < size {
            if self.fill()? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "LZ4 data cut short",
                ));
            }
            let take = (size - self.legacy_block.len()).min(self.input_len - self.input_pos);
            self.legacy_block
                .extend_from_slice(&self.input[self.input_pos..self.input_pos + take]);
            self.input_pos += take;
        }
        self.legacy.resize(LEGACY_BLOCKSIZE, 0);
        let decoded = lz4::decompress_safe(&self.legacy_block, &mut self.legacy)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.legacy.truncate(decoded);
        self.legacy_pos = 0;
        Ok(())
    }
}

fn frame_error(error: crate::lz4::lz4frame::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

impl<R: Read> Read for Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match self.state {
                State::Done => return Ok(0),
                State::Magic => match self.read_u32()? {
                    None => self.state = State::Done,
                    Some(magic) => self.start(magic)?,
                },
                State::Legacy => {
                    if self.legacy_pos < self.legacy.len() {
                        let n = buf.len().min(self.legacy.len() - self.legacy_pos);
                        buf[..n]
                            .copy_from_slice(&self.legacy[self.legacy_pos..self.legacy_pos + n]);
                        self.legacy_pos += n;
                        return Ok(n);
                    }
                    self.legacy_block()?;
                }
                State::Frame => {
                    let left = self.fill()?;
                    let mut input = InBuffer::new(&self.input[self.input_pos..self.input_len]);
                    let mut output = OutBuffer::new(buf);
                    let hint = self
                        .dctx
                        .decompress(&mut output, &mut input, DecompressOptions::default())
                        .map_err(frame_error)?;
                    self.input_pos += input.pos;
                    let written = output.pos;
                    if hint == 0 {
                        self.state = State::Magic;
                    } else if left == 0 && written == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "LZ4 frame cut short",
                        ));
                    }
                    if written > 0 {
                        return Ok(written);
                    }
                }
            }
        }
    }
}
