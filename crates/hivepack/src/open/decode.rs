//! The decompressors as `io::Read`: zstd, xz (and lzip and .lzma), gzip,
//! bzip2 and pbzx (xz streams, a block at a time), each over hivepack's
//! port of its library, through one adapter; LZ4, whose port has its own
//! reader of `.lz4` files; and RPM packages, whose lead and headers
//! hivepack::cpio's port of libarchive's filter takes off.
//!
//! A file can hold several streams one after the other, as their tools
//! make and read them: zstd frames (skippable ones too), gzip members,
//! bzip2 streams (pbzip2 writes one per block), xz streams with their
//! padding, lzip members. After the last, gzip and bzip2 allow zeros, which
//! tar's blocking leaves; lzip allows anything, as its format says, which
//! is read and ignored. Anything else after a stream is an error, as is a
//! stream cut short. LZ4's reader does the same as `lz4 -d`: frames,
//! skippable frames and the legacy format one after the other, and nothing
//! else after them.

use std::io::{self, Read};

use crate::open::detect::{Layer, is_skippable};

/// An error of a layer's data, inside the `io::Error` a read returns.
#[derive(Debug)]
pub struct DecodeError {
    /// The layer whose data failed.
    pub layer: Layer,
    /// What its library said.
    pub message: String,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.layer, self.message)
    }
}

impl std::error::Error for DecodeError {}

/// A layer's error, as a read returns it.
fn decode_error(layer: Layer, message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, DecodeError { layer, message })
}

/// What a step of a codec did.
#[derive(Default)]
struct Step {
    consumed: usize,
    produced: usize,
    /// A stream (a frame, a member) ended.
    ended: bool,
    /// The data failed: what was produced before is given out first, as
    /// the tools write it before they stop.
    error: Option<String>,
}

/// A decompressor, a step at a time.
trait Codec {
    /// From `input` into `output`; `finish` once the input has no more.
    fn step(&mut self, input: &[u8], output: &mut [u8], finish: bool) -> Step;

    /// After a stream ended: whether `next`, the bytes after it (as many
    /// as [`MAGIC_LEN`] when there are), starts another, which is begun.
    fn restart(&mut self, _next: &[u8]) -> bool {
        false
    }

    /// What may follow the last stream.
    fn after_last(&self) -> After {
        After::Nothing
    }
}

/// What may follow the last stream.
#[derive(Clone, Copy, PartialEq, Eq)]
enum After {
    Nothing,
    Zeros,
    /// Anything, read to its end and ignored, so that the layers around
    /// are read to theirs.
    Anything,
}

/// The bytes [`Codec::restart`] looks at.
const MAGIC_LEN: usize = 6;

const BUFFER: usize = 64 * 1024;

/// A codec over a reader.
struct Decoder<R, C> {
    inner: R,
    codec: C,
    layer: Layer,
    buf: Box<[u8]>,
    start: usize,
    end: usize,
    eof: bool,
    /// The last stream ended, and nothing follows yet.
    ended: bool,
    done: bool,
    /// The error every later read returns.
    failed: Option<String>,
}

impl<R: Read, C: Codec> Decoder<R, C> {
    fn new(inner: R, codec: C, layer: Layer) -> Decoder<R, C> {
        Decoder {
            inner,
            codec,
            layer,
            buf: vec![0; BUFFER].into_boxed_slice(),
            start: 0,
            end: 0,
            eof: false,
            ended: false,
            done: false,
            failed: None,
        }
    }

    fn error(&mut self, message: String) -> io::Error {
        self.failed = Some(message.clone());
        decode_error(self.layer, message)
    }

    /// At least `want` bytes in the buffer, unless the input ends first.
    fn fill(&mut self, want: usize) -> io::Result<()> {
        if self.end - self.start >= want || self.eof {
            return Ok(());
        }
        // Move what is left to the start.
        self.buf.copy_within(self.start..self.end, 0);
        self.end -= self.start;
        self.start = 0;
        while self.end - self.start < want && !self.eof {
            match self.inner.read(&mut self.buf[self.end..]) {
                Ok(0) => self.eof = true,
                Ok(n) => self.end += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// After a stream: another, what may follow the last ([`After`]), or
    /// an error.
    fn after_stream(&mut self) -> io::Result<()> {
        self.fill(MAGIC_LEN)?;
        if self.start == self.end {
            self.done = true;
            return Ok(());
        }
        if self.codec.restart(&self.buf[self.start..self.end]) {
            self.ended = false;
            return Ok(());
        }
        if self.codec.after_last() == After::Anything {
            while self.start < self.end {
                self.start = self.end;
                self.fill(1)?;
            }
            self.done = true;
            return Ok(());
        }
        if self.codec.after_last() == After::Zeros {
            loop {
                if self.buf[self.start..self.end].iter().any(|&c| c != 0) {
                    break;
                }
                self.start = self.end;
                self.fill(1)?;
                if self.start == self.end {
                    self.done = true;
                    return Ok(());
                }
            }
        }
        Err(self.error("trailing data after the end of the stream".into()))
    }
}

impl<R: Read, C: Codec> Read for Decoder<R, C> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if let Some(message) = &self.failed {
            let message = message.clone();
            return Err(self.error(message));
        }
        if out.is_empty() || self.done {
            return Ok(0);
        }
        loop {
            if self.ended {
                self.after_stream()?;
                if self.done {
                    return Ok(0);
                }
            }
            self.fill(1)?;
            let finish = self.eof;
            let step = self
                .codec
                .step(&self.buf[self.start..self.end], out, finish);
            self.start += step.consumed;
            if let Some(e) = step.error {
                if step.produced > 0 {
                    self.failed = Some(e);
                    return Ok(step.produced);
                }
                return Err(self.error(e));
            }
            if step.ended {
                self.ended = true;
            }
            if step.produced > 0 {
                return Ok(step.produced);
            }
            if step.ended {
                continue;
            }
            if step.consumed == 0 && self.start == self.end && self.eof {
                return Err(self.error("the stream is cut short".into()));
            }
            if step.consumed == 0 && self.start < self.end {
                // Input there, room for output, and no progress.
                return Err(self.error("no progress".into()));
            }
        }
    }
}

/// zstd: a context that goes on from one frame to the next.
struct ZstdCodec {
    dctx: crate::zstd::DCtx,
}

impl Codec for ZstdCodec {
    fn step(&mut self, input: &[u8], output: &mut [u8], _finish: bool) -> Step {
        let mut i = crate::zstd::InBuffer::new(input);
        let mut o = crate::zstd::OutBuffer::new(output);
        let result = self.dctx.decompress_stream(&mut o, &mut i);
        let mut step = Step {
            consumed: i.pos,
            produced: o.pos,
            ..Step::default()
        };
        match result {
            Ok(hint) => step.ended = hint == 0,
            Err(e) => step.error = Some(e.to_string()),
        }
        step
    }

    fn restart(&mut self, next: &[u8]) -> bool {
        // Another frame, or a skippable one: the context reads on.
        next.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) || is_skippable(next)
    }
}

/// gzip: members one after the other, zeros after them.
struct GzipCodec {
    z: crate::deflate::Inflate,
}

impl Codec for GzipCodec {
    fn step(&mut self, input: &[u8], output: &mut [u8], _finish: bool) -> Step {
        let mut i = crate::deflate::InBuffer::new(input);
        let mut o = crate::deflate::OutBuffer::new(output);
        let status = self
            .z
            .inflate(&mut o, &mut i, crate::deflate::Flush::NoFlush);
        let mut step = Step {
            consumed: i.pos,
            produced: o.pos,
            ..Step::default()
        };
        match status {
            Ok(crate::deflate::Status::StreamEnd) => step.ended = true,
            Ok(crate::deflate::Status::Ok) => {}
            Ok(crate::deflate::Status::NeedDict) => step.error = Some("needs a dictionary".into()),
            Err(e) if e.code() == crate::deflate::ErrorCode::Buf => {}
            Err(e) => step.error = Some(e.to_string()),
        }
        step
    }

    fn restart(&mut self, next: &[u8]) -> bool {
        if next.starts_with(&[0x1F, 0x8B]) {
            self.z.reset();
            return true;
        }
        false
    }

    fn after_last(&self) -> After {
        After::Zeros
    }
}

/// bzip2: streams one after the other, zeros after them.
struct Bzip2Codec {
    d: crate::bzip2::Decompress,
}

impl Codec for Bzip2Codec {
    fn step(&mut self, input: &[u8], output: &mut [u8], _finish: bool) -> Step {
        let mut i = crate::bzip2::InBuffer::new(input);
        let mut o = crate::bzip2::OutBuffer::new(output);
        let result = self.d.decompress(&mut o, &mut i);
        let mut step = Step {
            consumed: i.pos,
            produced: o.pos,
            ..Step::default()
        };
        match result {
            Ok(status) => step.ended = status == crate::bzip2::Status::StreamEnd,
            Err(e) => step.error = Some(e.to_string()),
        }
        step
    }

    fn restart(&mut self, next: &[u8]) -> bool {
        if next.len() >= 4 && next.starts_with(b"BZh") && (b'1'..=b'9').contains(&next[3]) {
            self.d = crate::bzip2::Decompress::new(false);
            return true;
        }
        false
    }

    fn after_last(&self) -> After {
        After::Zeros
    }
}

/// xz, lzip and .lzma: liblzma's decoders, xz's and lzip's concatenated
/// streams read by the decoder itself.
struct XzCodec {
    s: crate::xz::Stream,
    after: After,
}

impl Codec for XzCodec {
    fn step(&mut self, input: &[u8], output: &mut [u8], finish: bool) -> Step {
        let mut i = crate::xz::InBuffer::new(input);
        let mut o = crate::xz::OutBuffer::new(output);
        let action = if finish {
            crate::xz::Action::Finish
        } else {
            crate::xz::Action::Run
        };
        let result = self.s.code(&mut o, &mut i, action);
        let mut step = Step {
            consumed: i.pos,
            produced: o.pos,
            ..Step::default()
        };
        match result {
            Ok(status) => step.ended = status == crate::xz::Status::StreamEnd,
            Err(crate::xz::Error::Buf) => {}
            Err(e) => step.error = Some(e.to_string()),
        }
        step
    }

    fn after_last(&self) -> After {
        self.after
    }
}

/// pbzx's header: `pbzx` and the block size, a 64-bit big-endian number.
const PBZX_HEADER: usize = 12;
/// A chunk's header: its size, then the size of what stores it.
const PBZX_CHUNK_HEADER: usize = 16;

/// A 64-bit big-endian number, pbzx's.
fn be64(b: &[u8]) -> u64 {
    b.iter().take(8).fold(0, |n, &c| n << 8 | u64::from(c))
}

/// Where pbzx's reader is.
enum PbzxState {
    /// In a header, the file's or a chunk's: the bytes of it so far.
    Header,
    /// In a stored chunk: the bytes left to copy.
    Stored(u64),
    /// In a chunk compressed with xz: one stream, of `left_in` more bytes,
    /// that decompresses to `left_out` more.
    Xz {
        s: crate::xz::Stream,
        left_in: u64,
        left_out: u64,
    },
}

/// pbzx, as Apple's tools read it (`pkgutil --expand-full`): after the
/// header, chunks one after the other to the end of the stream, each of
/// at most the block size, decompressed and stored. A chunk whose stored
/// size is its size is stored as it is, whatever its first bytes, and any
/// other is one xz stream that decompresses to exactly its size. A chunk
/// of nothing is allowed; a header cut short, or anything after the last
/// chunk, is not.
struct PbzxCodec {
    xz_memlimit: u64,
    header: [u8; PBZX_CHUNK_HEADER],
    have: usize,
    /// The block size, once the file's header is read.
    block: Option<u64>,
    state: PbzxState,
}

impl PbzxCodec {
    fn new(xz_memlimit: u64) -> PbzxCodec {
        PbzxCodec {
            xz_memlimit,
            header: [0; PBZX_CHUNK_HEADER],
            have: 0,
            block: None,
            state: PbzxState::Header,
        }
    }

    /// The next chunk, from its header: an error's message if it cannot be.
    fn begin_chunk(&mut self, block: u64) -> Result<(), String> {
        let size = be64(&self.header[..8]);
        let stored = be64(&self.header[8..16]);
        if size > block || stored > block {
            return Err("a chunk is larger than the block size".into());
        }
        self.state = if stored == size {
            PbzxState::Stored(size)
        } else {
            PbzxState::Xz {
                s: crate::xz::Stream::stream_decoder(self.xz_memlimit, 0)
                    .map_err(|e| e.to_string())?,
                left_in: stored,
                left_out: size,
            }
        };
        Ok(())
    }
}

impl Codec for PbzxCodec {
    fn step(&mut self, mut input: &[u8], output: &mut [u8], finish: bool) -> Step {
        let mut step = Step::default();
        loop {
            match &mut self.state {
                PbzxState::Header => {
                    // At the end, between chunks, the stream ends.
                    if self.have == 0 && input.is_empty() {
                        step.ended = finish && self.block.is_some();
                        return step;
                    }
                    let want = match self.block {
                        None => PBZX_HEADER,
                        Some(_) => PBZX_CHUNK_HEADER,
                    };
                    let n = (want - self.have).min(input.len());
                    self.header[self.have..self.have + n].copy_from_slice(&input[..n]);
                    self.have += n;
                    input = &input[n..];
                    step.consumed += n;
                    if self.have < want {
                        return step;
                    }
                    self.have = 0;
                    let Some(block) = self.block else {
                        if !self.header.starts_with(b"pbzx") {
                            step.error = Some("not a pbzx stream".into());
                            return step;
                        }
                        self.block = Some(be64(&self.header[4..12]));
                        continue;
                    };
                    if let Err(e) = self.begin_chunk(block) {
                        step.error = Some(e);
                        return step;
                    }
                }
                PbzxState::Stored(left) => {
                    if *left == 0 {
                        self.state = PbzxState::Header;
                        continue;
                    }
                    let room = output.len() - step.produced;
                    let n = (*left).min(room as u64).min(input.len() as u64) as usize;
                    if n == 0 {
                        return step;
                    }
                    output[step.produced..step.produced + n].copy_from_slice(&input[..n]);
                    input = &input[n..];
                    *left -= n as u64;
                    step.consumed += n;
                    step.produced += n;
                }
                PbzxState::Xz {
                    s,
                    left_in,
                    left_out,
                } => {
                    let take = (*left_in).min(input.len() as u64) as usize;
                    let room = (output.len() - step.produced) as u64;
                    // Past its size, a byte more would be too many.
                    let mut past = [0u8; 1];
                    let out: &mut [u8] = if *left_out == 0 {
                        &mut past
                    } else {
                        let n = room.min(*left_out) as usize;
                        &mut output[step.produced..step.produced + n]
                    };
                    if out.is_empty() {
                        return step;
                    }
                    // The chunk ends where its stored size says.
                    let action = if take as u64 == *left_in {
                        crate::xz::Action::Finish
                    } else {
                        crate::xz::Action::Run
                    };
                    let mut i = crate::xz::InBuffer::new(&input[..take]);
                    let mut o = crate::xz::OutBuffer::new(out);
                    let result = s.code(&mut o, &mut i, action);
                    let (consumed, produced) = (i.pos, o.pos);
                    input = &input[consumed..];
                    *left_in -= consumed as u64;
                    step.consumed += consumed;
                    if *left_out == 0 && produced > 0 {
                        step.error = Some("a chunk decompresses to more than its size".into());
                        return step;
                    }
                    *left_out -= produced as u64;
                    step.produced += produced;
                    match result {
                        Ok(crate::xz::Status::StreamEnd) => {
                            if *left_in > 0 {
                                step.error = Some("data after a chunk's xz stream".into());
                                return step;
                            }
                            if *left_out > 0 {
                                step.error =
                                    Some("a chunk decompresses to less than its size".into());
                                return step;
                            }
                            self.state = PbzxState::Header;
                        }
                        Ok(_) if consumed == 0 && produced == 0 => return step,
                        Ok(_) => {}
                        Err(crate::xz::Error::Buf) if *left_in == 0 => {
                            step.error = Some("a chunk's xz stream is cut short".into());
                            return step;
                        }
                        Err(crate::xz::Error::Buf) => return step,
                        Err(e) => {
                            step.error = Some(e.to_string());
                            return step;
                        }
                    }
                }
            }
        }
    }
}

/// An error of the reader under LZ4's, told apart from LZ4's own on its
/// way through LZ4's reader, which passes it on as it is.
#[derive(Debug)]
struct Below(io::Error);

impl std::fmt::Display for Below {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Below {}

/// The reader under LZ4's, its errors marked [`Below`].
struct Tagged<R>(R);

impl<R: Read> Read for Tagged<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf).map_err(|e| match e.kind() {
            io::ErrorKind::Interrupted => e,
            kind => io::Error::new(kind, Below(e)),
        })
    }
}

/// LZ4: hivepack::lz4's reader of `.lz4` files, its errors given as the
/// other layers' are: a [`DecodeError`] that stays, and the errors of the
/// reader under it as they are.
struct Lz4Layer<R> {
    decoder: crate::lz4::Decoder<Tagged<R>>,
    failed: Option<String>,
}

impl<R: Read> Read for Lz4Layer<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(message) = &self.failed {
            return Err(decode_error(Layer::Lz4, message.clone()));
        }
        let e = match self.decoder.read(buf) {
            Ok(n) => return Ok(n),
            Err(e) => e,
        };
        let kind = e.kind();
        let message = match e.into_inner().map(|inner| inner.downcast::<Below>()) {
            Some(Ok(below)) => return Err(below.0),
            Some(Err(inner)) => inner.to_string(),
            None => io::Error::from(kind).to_string(),
        };
        self.failed = Some(message.clone());
        Err(decode_error(Layer::Lz4, message))
    }
}

/// An RPM package's payload: hivepack::cpio's port of libarchive's RPM
/// filter, its errors given as the other layers' are, and the errors of
/// the reader under it as they are.
struct RpmLayer<R> {
    reader: crate::cpio::rpm::Reader<R>,
}

impl<R: Read> Read for RpmLayer<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf).map_err(|e| {
            let Some(error) = e
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<crate::cpio::Error>())
            else {
                return e;
            };
            // libarchive says nothing of a package that ends before its
            // payload.
            let message = match error.message() {
                Some(text) => String::from_utf8_lossy(&text).into_owned(),
                None => "the stream is cut short".into(),
            };
            decode_error(Layer::Rpm, message)
        })
    }
}

/// The limits of the decoders.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DecodeLimits {
    pub(crate) zstd_window_log_max: u32,
    pub(crate) xz_memlimit: u64,
}

/// The decoder of `layer` over `inner`.
pub(crate) fn decoder<'a, R: Read + Send + 'a>(
    layer: Layer,
    inner: R,
    limits: DecodeLimits,
) -> io::Result<Box<dyn Read + Send + 'a>> {
    let invalid = |e: String| io::Error::new(io::ErrorKind::InvalidInput, e);
    Ok(match layer {
        Layer::Zstd => {
            let mut dctx = crate::zstd::DCtx::new();
            dctx.set_parameter(crate::zstd::DParameter::WindowLogMax(
                limits.zstd_window_log_max,
            ))
            .map_err(|e| invalid(e.to_string()))?;
            Box::new(Decoder::new(inner, ZstdCodec { dctx }, layer))
        }
        Layer::Gzip => {
            let z = crate::deflate::Inflate::new(16 + 15).map_err(|e| invalid(e.to_string()))?;
            Box::new(Decoder::new(inner, GzipCodec { z }, layer))
        }
        Layer::Bzip2 => Box::new(Decoder::new(
            inner,
            Bzip2Codec {
                d: crate::bzip2::Decompress::new(false),
            },
            layer,
        )),
        Layer::Xz | Layer::Lzip | Layer::Lzma => {
            let flags = crate::xz::CONCATENATED;
            let s = match layer {
                Layer::Xz => crate::xz::Stream::stream_decoder(limits.xz_memlimit, flags),
                Layer::Lzip => crate::xz::Stream::lzip_decoder(limits.xz_memlimit, flags),
                _ => crate::xz::Stream::alone_decoder(limits.xz_memlimit),
            }
            .map_err(|e| invalid(e.to_string()))?;
            // lzip and xz ignore what follows a .lz file's last member.
            let after = if layer == Layer::Lzip {
                After::Anything
            } else {
                After::Nothing
            };
            Box::new(Decoder::new(inner, XzCodec { s, after }, layer))
        }
        Layer::Pbzx => Box::new(Decoder::new(
            inner,
            PbzxCodec::new(limits.xz_memlimit),
            layer,
        )),
        Layer::Rpm => Box::new(RpmLayer {
            reader: crate::cpio::rpm::Reader::new(inner),
        }),
        Layer::Lz4 => Box::new(Lz4Layer {
            decoder: crate::lz4::Decoder::new(Tagged(inner)),
            failed: None,
        }),
        Layer::Age => return Err(invalid("age is not a compressor".into())),
    })
}
