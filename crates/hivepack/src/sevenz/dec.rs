//! Decoding a folder: `7zDec.c`.
//!
//! Differs from the LZMA SDK, whose decoder writes a whole folder into one
//! buffer, then runs its filter over it: the port's folder is a reader,
//! which decodes as much as it is asked for, so that a solid folder of any
//! size can be read in pieces. Its checks are the SDK's, made when each
//! stream ends rather than when the whole buffer is decoded. LZMA and LZMA2
//! are decoded by `hivepack::xz`, a port of liblzma's decoders, rather than
//! by the SDK's `LzmaDec.c`: the output is the same, and on damaged data
//! either may stop at another byte, with the same error. liblzma takes no
//! LZMA properties with `lc + lp` above 4, though, which `lzma_dec` decodes.
//!
//! The folders the SDK decodes take its path, with its checks. Others, which
//! the SDK answers `SZ_ERROR_UNSUPPORTED`, are decoded as 7-Zip's program
//! decodes them: any graph of coders, with more methods. Each coder's stream
//! must end where its output does and its input must be read to its end,
//! which `7zz t` calls an error too.
//!
//! Not in the SDK either: given more than one thread
//! ([`Archive::set_threads`](crate::sevenz::Archive::set_threads)), an LZMA2 coder is
//! decoded by `lzma2_mt.rs`, a block in each thread, where its stream resets
//! the dictionary; with one, as the SDK's is.

use std::io::{Read, Seek};

use crate::bzip2::Decompress;
use crate::crypto::AES_BLOCK_LENGTH;
use crate::deflate::{Flush, Inflate, Inflate9};
use crate::xz::{
    Action, FILTER_LZMA1EXT, Filter, FilterOptions, InBuffer, LZMA1EXT_ALLOW_EOPM, LzmaOptions,
    OutBuffer, Status, Stream,
};

use crate::sevenz::aes7z::{AesCoder, Decoding, K_AES};
use crate::sevenz::arc_in::{self, Ar, Folder, Sd};
use crate::sevenz::bcj2::{self, Bcj2Dec, Delta};
use crate::sevenz::bra;
use crate::sevenz::error::{Error, Result};
use crate::sevenz::lzma_dec::LzmaDec;
use crate::sevenz::lzma2_mt::Lzma2Mt;
use crate::sevenz::ppmd7::{self, ByteIn, Ppmd7};

/// `k_Copy`.
const K_COPY: u32 = 0;
/// `k_LZMA2`.
const K_LZMA2: u32 = 0x21;
/// `k_LZMA`.
const K_LZMA: u32 = 0x30101;
/// `k_BCJ2`.
const K_BCJ2: u32 = 0x303011B;
/// `k_ARM64`.
const K_ARM64: u32 = 0xa;
/// `k_ARMT`.
const K_ARMT: u32 = 0x3030701;
/// `k_Delta`.
const K_DELTA: u32 = 3;
/// `k_RISCV`.
const K_RISCV: u32 = 0xb;
/// `k_BCJ`.
const K_BCJ: u32 = 0x3030103;
/// `k_PPC`.
const K_PPC: u32 = 0x3030205;
/// `k_IA64`.
const K_IA64: u32 = 0x3030401;
/// `k_ARM`.
const K_ARM: u32 = 0x3030501;
/// `k_SPARC`.
const K_SPARC: u32 = 0x3030805;

/// `k_PPMD`.
const K_PPMD: u32 = 0x30401;

// What 7-Zip's program decodes and the SDK does not (`DOC/Methods.txt`).
const K_SWAP2: u32 = 0x20302;
const K_SWAP4: u32 = 0x20304;
const K_DEFLATE: u32 = 0x40108;
const K_DEFLATE64: u32 = 0x40109;
const K_BZIP2: u32 = 0x40202;
const K_ZSTD: u32 = 0x4F7_1101;

/// How much of a packed stream is read at a time.
const PACK_BUF_SIZE: usize = 1 << 16;

/// `IS_MAIN_METHOD`.
fn is_main_method(m: u32) -> bool {
    matches!(m, K_COPY | K_LZMA | K_LZMA2 | K_PPMD)
}

/// `IS_SUPPORTED_CODER`.
fn is_supported_coder(c: &arc_in::CoderInfo) -> bool {
    c.num_streams == 1 && is_main_method(c.method_id)
}

/// `IS_BCJ2`.
fn is_bcj2(c: &arc_in::CoderInfo) -> bool {
    c.method_id == K_BCJ2 && c.num_streams == 4
}

/// `CheckSupportedFolder`.
fn check_supported_folder(f: &Folder) -> Result<()> {
    if f.num_coders < 1 || f.num_coders > 4 {
        return Err(Error::Unsupported);
    }
    if !is_supported_coder(&f.coders[0]) {
        return Err(Error::Unsupported);
    }
    if f.num_coders == 1 {
        if f.num_pack_streams != 1 || f.pack_streams[0] != 0 || f.num_bonds != 0 {
            return Err(Error::Unsupported);
        }
        return Ok(());
    }
    if f.num_coders == 2 {
        let c = &f.coders[1];
        if c.num_streams != 1
            || f.num_pack_streams != 1
            || f.pack_streams[0] != 0
            || f.num_bonds != 1
            || f.bonds[0].in_index != 1
            || f.bonds[0].out_index != 0
        {
            return Err(Error::Unsupported);
        }
        return match c.method_id {
            K_DELTA | K_BCJ | K_PPC | K_IA64 | K_SPARC | K_ARM | K_RISCV | K_ARM64 | K_ARMT => {
                Ok(())
            }
            _ => Err(Error::Unsupported),
        };
    }
    if f.num_coders == 4 {
        if !is_supported_coder(&f.coders[1])
            || !is_supported_coder(&f.coders[2])
            || !is_bcj2(&f.coders[3])
        {
            return Err(Error::Unsupported);
        }
        if f.num_pack_streams != 4
            || f.pack_streams[0] != 2
            || f.pack_streams[1] != 6
            || f.pack_streams[2] != 1
            || f.pack_streams[3] != 0
            || f.num_bonds != 3
            || f.bonds[0].in_index != 5
            || f.bonds[0].out_index != 0
            || f.bonds[1].in_index != 4
            || f.bonds[1].out_index != 1
            || f.bonds[2].in_index != 3
            || f.bonds[2].out_index != 2
        {
            return Err(Error::Unsupported);
        }
        return Ok(());
    }
    Err(Error::Unsupported)
}

/// A coder's input, read through a buffer of its own, so that several can be
/// read in turns: a packed stream, a range of the archive, or another coder's
/// output.
pub(crate) struct PackReader {
    pos: u64,
    end: u64,
    buf: Vec<u8>,
    start: usize,
    len: usize,
    /// The coder it comes from, whose bytes count from `pos` 0.
    source: Option<Box<Node>>,
}

impl PackReader {
    /// The `size` bytes of the archive at `pos`.
    pub(crate) fn new(pos: u64, size: u64) -> Self {
        PackReader {
            pos,
            end: pos.saturating_add(size),
            buf: Vec::new(),
            start: 0,
            len: 0,
            source: None,
        }
    }

    /// The output of `node`, of `size` bytes.
    fn from_node(node: Node, size: u64) -> Self {
        PackReader {
            source: Some(Box::new(node)),
            ..PackReader::new(0, size)
        }
    }

    /// What is left of the stream, read or not.
    pub(crate) fn remaining(&self) -> u64 {
        (self.len - self.start) as u64 + (self.end - self.pos)
    }

    /// The buffered bytes, read from the archive when there are none; empty
    /// at the stream's end. A short archive is `eof`.
    pub(crate) fn fill<R: Read + Seek>(&mut self, r: &mut R, eof: Error) -> Result<&[u8]> {
        if self.start == self.len && self.pos < self.end {
            if self.buf.is_empty() {
                self.buf = vec![0; PACK_BUF_SIZE];
            }
            let want = (self.end - self.pos).min(PACK_BUF_SIZE as u64) as usize;
            let mut got = 0;
            if let Some(node) = &mut self.source {
                got = node.read(r, &mut self.buf[..want])?;
            } else {
                arc_in::seek_to(r, self.pos)?;
                while got < want {
                    match r.read(&mut self.buf[got..want]) {
                        Ok(0) => break,
                        Ok(n) => got += n,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => return Err(Error::Read),
                    }
                }
            }
            if got == 0 {
                return Err(eof);
            }
            self.pos += got as u64;
            self.start = 0;
            self.len = got;
        }
        Ok(&self.buf[self.start..self.len])
    }

    pub(crate) fn consume(&mut self, n: usize) {
        self.start += n;
    }

    /// The checks of the coder it comes from, at the end of its output.
    fn finish_source<R: Read + Seek>(&mut self, r: &mut R) -> Result<()> {
        if let Some(node) = &mut self.source
            && node.read(r, &mut [0u8; 1])? != 0
        {
            return Err(Error::Data);
        }
        Ok(())
    }
}

/// A main method: a packed stream decoded into `out_size` bytes.
enum Main {
    /// `SzDecodeCopy`.
    Copy,
    /// `SzDecodeLzma` and `SzDecodeLzma2`.
    Lzma(Box<Stream>),
    /// LZMA2 in threads: not in the SDK.
    Lzma2Mt(Box<Lzma2Mt>),
    /// `SzDecodeLzma`, for what liblzma's decoder does not take.
    LzmaDec(Box<LzmaDec>),
    /// `SzDecodePpmd`; the range decoder is started by the first read.
    Ppmd(Box<Ppmd7>, bool),
    /// Deflate.
    Inflate(Box<Inflate>),
    /// Deflate64.
    Inflate9(Box<Inflate9>),
    /// BZip2: one stream after another, as 7-Zip reads them.
    Bzip2(Box<Decompress>),
    /// `7zAES`.
    Aes(Box<AesCoder>),
    /// Zstandard, which 7-Zip's program does not take in 7z, and forks of it
    /// write: one frame after another.
    Zstd(Box<crate::zstd::DCtx>),
}

/// What a step of a decoder from other crates did: the bytes it read and
/// wrote, and whether its stream or frame ended.
fn step(method: &mut Main, input: &[u8], out: &mut [u8]) -> Result<(usize, usize, bool)> {
    match method {
        Main::Inflate(z) => {
            let mut i = crate::deflate::InBuffer::new(input);
            let mut o = crate::deflate::OutBuffer::new(out);
            let status = z
                .inflate(&mut o, &mut i, Flush::SyncFlush)
                .map_err(|_| Error::Data)?;
            Ok((i.pos, o.pos, status == crate::deflate::Status::StreamEnd))
        }
        Main::Inflate9(z) => {
            let mut i = crate::deflate::InBuffer::new(input);
            let mut o = crate::deflate::OutBuffer::new(out);
            let status = z.inflate(&mut o, &mut i).map_err(|_| Error::Data)?;
            Ok((i.pos, o.pos, status == crate::deflate::Status::StreamEnd))
        }
        Main::Bzip2(z) => {
            let mut i = crate::bzip2::InBuffer::new(input);
            let mut o = crate::bzip2::OutBuffer::new(out);
            let status = z.decompress(&mut o, &mut i).map_err(|_| Error::Data)?;
            Ok((i.pos, o.pos, status == crate::bzip2::Status::StreamEnd))
        }
        Main::Zstd(z) => {
            let mut i = crate::zstd::InBuffer::new(input);
            let mut o = crate::zstd::OutBuffer::new(out);
            let hint = z
                .decompress_stream(&mut o, &mut i)
                .map_err(|_| Error::Data)?;
            Ok((i.pos, o.pos, hint == 0))
        }
        _ => Err(Error::Fail),
    }
}

/// The largest window of Zstandard's that `limit` bytes hold, as a log.
fn zstd_window_log_max(limit: u64) -> u32 {
    let most = if usize::BITS == 64 { 31 } else { 30 };
    limit.max(1).ilog2().clamp(10, most)
}

/// `CByteInToLook`: the range decoder's bytes, from a packed stream. Past
/// its end they are 0, and `extra` tells.
struct PackBytes<'a, R> {
    input: &'a mut PackReader,
    reader: &'a mut R,
    extra: bool,
    res: Option<Error>,
}

impl<R: Read + Seek> ByteIn for PackBytes<'_, R> {
    #[inline(always)]
    fn read_byte(&mut self) -> u8 {
        let input = &mut *self.input;
        if input.start < input.len {
            let b = input.buf[input.start];
            input.start += 1;
            return b;
        }
        match input.fill(self.reader, Error::Data) {
            Ok(buf) if !buf.is_empty() => {
                let b = buf[0];
                input.consume(1);
                b
            }
            Ok(_) => {
                self.extra = true;
                0
            }
            Err(e) => {
                self.extra = true;
                self.res = Some(e);
                0
            }
        }
    }
}

impl<R> PackBytes<'_, R> {
    /// What `SzDecodePpmd` returns for a decoding that stopped.
    fn error(&self) -> Error {
        self.res.unwrap_or(Error::Data)
    }
}

/// `n` bytes of a coder's dictionary or model, out of what the folder may
/// use (`Options::decoder_memory_limit`).
fn charge(limit: &mut u64, n: u64) -> Result<()> {
    *limit = limit.checked_sub(n).ok_or(Error::Mem)?;
    Ok(())
}

/// `SzDecodePpmd`'s checks of its properties, and the decoder for them.
fn ppmd_decoder(props: &[u8], limit: &mut u64) -> Result<Box<Ppmd7>> {
    if props.len() != 5 {
        return Err(Error::Unsupported);
    }
    let order = u32::from(props[0]);
    let mem_size = u32::from_le_bytes([props[1], props[2], props[3], props[4]]);
    if !(ppmd7::MIN_ORDER..=ppmd7::MAX_ORDER).contains(&order)
        || !(ppmd7::MIN_MEM_SIZE..=ppmd7::MAX_MEM_SIZE).contains(&mem_size)
    {
        return Err(Error::Unsupported);
    }
    charge(limit, u64::from(mem_size))?;
    let mut ppmd = Ppmd7::new(mem_size)?;
    ppmd.init(order);
    Ok(ppmd)
}

struct MainCoder {
    method: Main,
    input: PackReader,
    out_size: u64,
    out_pos: u64,
    /// The decoder has ended its stream.
    ended: bool,
}

/// `LzmaProps_Decode`: `lc`, `lp`, `pb` and the size of the dictionary.
fn lzma_props(props: &[u8]) -> Result<(u32, u32, u32, u32)> {
    if props.len() < 5 {
        return Err(Error::Unsupported);
    }
    let dict_size = u32::from_le_bytes([props[1], props[2], props[3], props[4]]).max(4096);
    let mut d = u32::from(props[0]);
    if d >= 9 * 5 * 5 {
        return Err(Error::Unsupported);
    }
    let lc = d % 9;
    d /= 9;
    Ok((lc, d % 5, d / 5, dict_size))
}

/// The decoder for LZMA or LZMA2 properties, which are checked. The
/// dictionary needs to be no larger than the output.
fn lzma_decoder(props: &[u8], out_size: u64, lzma2: bool, limit: &mut u64) -> Result<Stream> {
    let dict_cap = out_size.clamp(4096, u64::from(u32::MAX)) as u32;
    let filter = if lzma2 {
        // SzDecodeLzma2, Lzma2Dec_AllocateProbs.
        if props.len() != 1 {
            return Err(Error::Data);
        }
        let prop = u32::from(props[0]);
        if prop > 40 {
            return Err(Error::Unsupported);
        }
        let dict_size = if prop == 40 {
            u32::MAX
        } else {
            (2 | (prop & 1)) << (prop / 2 + 11)
        };
        let dict_size = dict_size.min(dict_cap).max(4096);
        charge(limit, u64::from(dict_size))?;
        let options = LzmaOptions {
            dict_size,
            ..LzmaOptions::preset(0).ok_or(Error::Fail)?
        };
        Filter::lzma2(options)
    } else {
        let (lc, lp, pb, dict_size) = lzma_props(props)?;
        let dict_size = dict_size.min(dict_cap).max(4096);
        charge(limit, u64::from(dict_size))?;
        let options = LzmaOptions {
            dict_size,
            lc,
            lp,
            pb,
            ext_flags: LZMA1EXT_ALLOW_EOPM,
            ext_size_low: out_size as u32,
            ext_size_high: (out_size >> 32) as u32,
            ..LzmaOptions::preset(0).ok_or(Error::Fail)?
        };
        Filter {
            id: FILTER_LZMA1EXT,
            options: Some(FilterOptions::Lzma(options)),
        }
    };
    Stream::raw_decoder(&[filter]).map_err(|e| match e {
        crate::xz::Error::Mem => Error::Mem,
        _ => Error::Unsupported,
    })
}

impl MainCoder {
    /// The coder of `method_id`, which may use up to `threads` threads.
    fn new(
        method_id: u32,
        props: &[u8],
        input: PackReader,
        out_size: u64,
        limit: &mut u64,
        threads: u32,
    ) -> Result<Self> {
        let in_size = input.remaining();
        let method = match method_id {
            K_COPY => {
                // Check it.
                if in_size != out_size {
                    return Err(Error::Data);
                }
                Main::Copy
            }
            K_LZMA => match lzma_props(props)? {
                (lc, lp, pb, dict_size) if lc + lp > 4 => {
                    charge(limit, u64::from(dict_size).min(out_size))?;
                    Main::LzmaDec(Box::new(LzmaDec::new(lc, lp, pb, dict_size, out_size)?))
                }
                _ => Main::Lzma(Box::new(lzma_decoder(props, out_size, false, limit)?)),
            },
            K_LZMA2 if threads > 1 => {
                Main::Lzma2Mt(Box::new(Lzma2Mt::new(props, out_size, threads, limit)?))
            }
            K_LZMA2 => Main::Lzma(Box::new(lzma_decoder(props, out_size, true, limit)?)),
            K_PPMD => Main::Ppmd(ppmd_decoder(props, limit)?, false),
            K_DEFLATE => Main::Inflate(Box::new(Inflate::new(-15).map_err(|_| Error::Mem)?)),
            K_DEFLATE64 => Main::Inflate9(Box::default()),
            K_BZIP2 => Main::Bzip2(Box::new(Decompress::new(false))),
            K_ZSTD => {
                let mut dctx = crate::zstd::DCtx::new();
                dctx.set_parameter(crate::zstd::DParameter::WindowLogMax(zstd_window_log_max(
                    *limit,
                )))
                .map_err(|_| Error::Fail)?;
                Main::Zstd(Box::new(dctx))
            }
            _ => return Err(Error::Unsupported),
        };
        Ok(MainCoder {
            method,
            input,
            out_size,
            out_pos: 0,
            ended: false,
        })
    }

    /// Up to `out.len()` bytes; 0 at the end of the output, once the input
    /// is checked to end there too.
    fn read<R: Read + Seek>(&mut self, r: &mut R, out: &mut [u8]) -> Result<usize> {
        let want = (out.len() as u64).min(self.out_size - self.out_pos) as usize;
        if want == 0 {
            if !out.is_empty() {
                self.finish(r)?;
            }
            return Ok(0);
        }
        let out = &mut out[..want];
        match &mut self.method {
            Main::Copy => {
                let buf = self.input.fill(r, Error::InputEof)?;
                let n = buf.len().min(want);
                out[..n].copy_from_slice(&buf[..n]);
                self.input.consume(n);
                self.out_pos += n as u64;
                Ok(n)
            }
            Main::Ppmd(ppmd, started) => {
                let mut bytes = PackBytes {
                    input: &mut self.input,
                    reader: r,
                    extra: false,
                    res: None,
                };
                if !*started {
                    *started = true;
                    if !ppmd.range_dec_init(&mut bytes) || bytes.extra {
                        return Err(bytes.error());
                    }
                }
                for b in out.iter_mut() {
                    let sym = ppmd.decode_symbol(&mut bytes);
                    if bytes.extra || sym < 0 {
                        return Err(bytes.error());
                    }
                    *b = sym as u8;
                }
                self.out_pos += want as u64;
                Ok(want)
            }
            Main::LzmaDec(dec) => {
                let mut bytes = PackBytes {
                    input: &mut self.input,
                    reader: r,
                    extra: false,
                    res: None,
                };
                let res = dec.read(&mut bytes, out);
                if bytes.extra {
                    return Err(bytes.error());
                }
                let n = res?;
                self.out_pos += n as u64;
                Ok(n)
            }
            Main::Aes(aes) => loop {
                let n = aes.take(out);
                if n > 0 {
                    self.out_pos += n as u64;
                    return Ok(n);
                }
                // As many whole blocks as there are, across the reads of a
                // source that gives less than it is asked for.
                let space = aes.space();
                let mut filled = 0;
                while filled < space.len() && self.input.remaining() > 0 {
                    let buf = self.input.fill(r, Error::Data)?;
                    let n = buf.len().min(space.len() - filled);
                    space[filled..filled + n].copy_from_slice(&buf[..n]);
                    self.input.consume(n);
                    filled += n;
                }
                let whole = filled / AES_BLOCK_LENGTH * AES_BLOCK_LENGTH;
                if whole == 0 {
                    return Err(Error::Data);
                }
                aes.decrypt(whole);
            },
            Main::Inflate(_) | Main::Inflate9(_) | Main::Bzip2(_) | Main::Zstd(_) => loop {
                let buf = if self.input.remaining() == 0 {
                    &[][..]
                } else {
                    self.input.fill(r, Error::Data)?
                };
                let (read, written, ended) = step(&mut self.method, buf, out)?;
                self.input.consume(read);
                self.out_pos += written as u64;
                self.ended = ended;
                if ended && self.out_pos != self.out_size {
                    // Another BZip2 stream or Zstandard frame may follow;
                    // the others have only one stream.
                    if self.input.remaining() == 0 {
                        return Err(Error::Data);
                    }
                    match self.method {
                        Main::Bzip2(_) => {
                            self.method = Main::Bzip2(Box::new(Decompress::new(false)));
                        }
                        Main::Zstd(_) => {}
                        _ => return Err(Error::Data),
                    }
                    self.ended = false;
                }
                if written > 0 {
                    return Ok(written);
                }
                if read == 0 {
                    // No progress.
                    return Err(Error::Data);
                }
            },
            Main::Lzma2Mt(mt) => {
                let n = mt.read(&mut self.input, r, out)?;
                if n == 0 {
                    // The stream ended before the output.
                    self.ended = true;
                    return Err(Error::Data);
                }
                self.out_pos += n as u64;
                Ok(n)
            }
            Main::Lzma(stream) => loop {
                let buf = if self.input.remaining() == 0 {
                    &[][..]
                } else {
                    self.input.fill(r, Error::Data)?
                };
                let mut input = InBuffer::new(buf);
                let mut output = OutBuffer::new(out);
                let action = if buf.is_empty() {
                    Action::Finish
                } else {
                    Action::Run
                };
                let status = stream
                    .code(&mut output, &mut input, action)
                    .map_err(|e| match e {
                        crate::xz::Error::Mem => Error::Mem,
                        _ => Error::Data,
                    })?;
                let (read, written) = (input.pos, output.pos);
                self.input.consume(read);
                self.out_pos += written as u64;
                if status == Status::StreamEnd {
                    self.ended = true;
                    if self.out_pos != self.out_size {
                        return Err(Error::Data);
                    }
                }
                if written > 0 {
                    return Ok(written);
                }
                if self.ended || read == 0 {
                    // No progress.
                    return Err(Error::Data);
                }
            },
        }
    }

    /// The checks at the end of the output: all of the input read, and, for
    /// LZMA, the end of its stream.
    fn finish<R: Read + Seek>(&mut self, r: &mut R) -> Result<()> {
        if matches!(self.method, Main::Aes(_)) {
            // Whole blocks past the output are not looked at.
            while self.input.remaining() > 0 {
                let n = self.input.fill(r, Error::Data)?.len();
                self.input.consume(n);
            }
        }
        if matches!(
            self.method,
            Main::Inflate(_) | Main::Inflate9(_) | Main::Bzip2(_) | Main::Zstd(_)
        ) {
            // The decoder stops at the size: the end of its stream follows.
            while !self.ended {
                let buf = if self.input.remaining() == 0 {
                    &[][..]
                } else {
                    self.input.fill(r, Error::Data)?
                };
                let (read, written, ended) = step(&mut self.method, buf, &mut [0u8; 1])?;
                self.input.consume(read);
                if written != 0 || (read == 0 && !ended) {
                    return Err(Error::Data);
                }
                self.ended = ended;
            }
        }
        if let Main::Ppmd(ppmd, started) = &mut self.method {
            if !*started {
                *started = true;
                let mut bytes = PackBytes {
                    input: &mut self.input,
                    reader: r,
                    extra: false,
                    res: None,
                };
                if !ppmd.range_dec_init(&mut bytes) || bytes.extra {
                    return Err(bytes.error());
                }
            }
            if !ppmd.range_dec_is_finished_ok() {
                return Err(Error::Data);
            }
        }
        if let Main::LzmaDec(dec) = &mut self.method {
            let mut bytes = PackBytes {
                input: &mut self.input,
                reader: r,
                extra: false,
                res: None,
            };
            let res = dec.finish(&mut bytes);
            if bytes.extra {
                return Err(bytes.error());
            }
            res?;
        }
        if let Main::Lzma2Mt(mt) = &mut self.method {
            mt.finish(&mut self.input, r)?;
            self.ended = true;
        }
        if let Main::Lzma(stream) = &mut self.method
            && !self.ended
        {
            // The decoder stops at the size: an end marker may follow.
            let buf = if self.input.remaining() == 0 {
                &[][..]
            } else {
                self.input.fill(r, Error::Data)?
            };
            let mut input = InBuffer::new(buf);
            let mut out = [0u8; 1];
            let mut output = OutBuffer::new(&mut out);
            let status = stream
                .code(&mut output, &mut input, Action::Finish)
                .map_err(|_| Error::Data)?;
            let read = input.pos;
            self.input.consume(read);
            if status != Status::StreamEnd || output.pos != 0 {
                return Err(Error::Data);
            }
            self.ended = true;
        }
        if self.input.remaining() != 0 {
            return Err(Error::Data);
        }
        self.input.finish_source(r)
    }
}

/// A branch converter or the delta filter, on the main coder's output.
enum FilterKind {
    X86(u32),
    Arm,
    Armt,
    Arm64,
    Ppc,
    Sparc,
    Ia64,
    Riscv,
    Delta(Box<Delta>),
    /// Units of 2 or 4 bytes reversed.
    Swap(usize),
}

/// How many bytes past the converted ones a branch converter keeps for its
/// next call, at most.
const FILTER_BUF_SIZE: usize = 1 << 16;

struct FilterCoder {
    kind: FilterKind,
    pc: u32,
    /// Output of the main coder: `buf[..converted]` converted, up to
    /// `filled` read.
    buf: Vec<u8>,
    start: usize,
    converted: usize,
    filled: usize,
    /// The main coder has ended.
    eof: bool,
}

impl FilterCoder {
    /// The filter of the 2-coder folder, with `SzFolder_Decode2`'s checks of
    /// its properties.
    fn new(method_id: u32, props: &[u8]) -> Result<Self> {
        let mut pc = 0;
        let kind = match method_id {
            K_DELTA => {
                if props.len() != 1 {
                    return Err(Error::Unsupported);
                }
                FilterKind::Delta(Box::new(Delta::new(usize::from(props[0]) + 1)))
            }
            K_ARM64 | K_RISCV => {
                if props.len() == 4 {
                    pc = u32::from_le_bytes([props[0], props[1], props[2], props[3]]);
                    let align = if method_id == K_ARM64 { 3 } else { 1 };
                    if pc & align != 0 {
                        return Err(Error::Unsupported);
                    }
                } else if !props.is_empty() {
                    return Err(Error::Unsupported);
                }
                if method_id == K_ARM64 {
                    FilterKind::Arm64
                } else {
                    FilterKind::Riscv
                }
            }
            _ => {
                if !props.is_empty() {
                    return Err(Error::Unsupported);
                }
                match method_id {
                    K_BCJ => FilterKind::X86(bra::X86_STATE_INIT),
                    K_PPC => FilterKind::Ppc,
                    K_IA64 => FilterKind::Ia64,
                    K_SPARC => FilterKind::Sparc,
                    K_ARM => FilterKind::Arm,
                    K_ARMT => FilterKind::Armt,
                    K_SWAP2 => FilterKind::Swap(2),
                    K_SWAP4 => FilterKind::Swap(4),
                    _ => return Err(Error::Unsupported),
                }
            }
        };
        Ok(FilterCoder {
            kind,
            pc,
            buf: vec![0; FILTER_BUF_SIZE],
            start: 0,
            converted: 0,
            filled: 0,
            eof: false,
        })
    }

    /// Converts what it can of `buf[converted..filled]`.
    fn convert(&mut self) {
        let data = &mut self.buf[self.converted..self.filled];
        let n = match &mut self.kind {
            FilterKind::Delta(delta) => {
                delta.decode(data);
                data.len()
            }
            FilterKind::X86(state) => bra::x86_dec(data, self.pc, state),
            FilterKind::Arm => bra::arm_dec(data, self.pc),
            FilterKind::Armt => bra::armt_dec(data, self.pc),
            FilterKind::Arm64 => bra::arm64_dec(data, self.pc),
            FilterKind::Ppc => bra::ppc_dec(data, self.pc),
            FilterKind::Sparc => bra::sparc_dec(data, self.pc),
            FilterKind::Ia64 => bra::ia64_dec(data, self.pc),
            FilterKind::Riscv => bra::riscv_dec(data, self.pc),
            FilterKind::Swap(unit) => {
                let n = data.len() / *unit * *unit;
                for chunk in data[..n].chunks_exact_mut(*unit) {
                    chunk.reverse();
                }
                n
            }
        };
        self.pc = self.pc.wrapping_add(n as u32);
        self.converted += n;
        if self.eof {
            // The rest stays as it is, as the SDK leaves the end of its
            // buffer.
            self.converted = self.filled;
        }
    }

    fn read<R: Read + Seek>(
        &mut self,
        inner: &mut Node,
        r: &mut R,
        out: &mut [u8],
    ) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.start < self.converted {
                let n = (self.converted - self.start).min(out.len());
                out[..n].copy_from_slice(&self.buf[self.start..self.start + n]);
                self.start += n;
                return Ok(n);
            }
            if self.eof {
                return Ok(0);
            }
            // Move what is not converted to the front, and read more.
            self.buf.copy_within(self.start..self.filled, 0);
            self.filled -= self.start;
            self.converted -= self.start;
            self.start = 0;
            let n = inner.read(r, &mut self.buf[self.filled..])?;
            if n == 0 {
                self.eof = true;
            }
            self.filled += n;
            self.convert();
        }
    }
}

/// The BCJ2 coder's inputs: three coders and the RC stream.
struct Bcj2Coder {
    dec: Bcj2Dec,
    /// MAIN, CALL, JUMP: the outputs of coders 2, 1 and 0 in the SDK's folders.
    coders: [Node; 3],
    rc: PackReader,
    /// Buffered input of each stream: `bufs[i][starts[i]..lens[i]]`.
    bufs: [Vec<u8>; bcj2::NUM_STREAMS],
    starts: [usize; bcj2::NUM_STREAMS],
    lens: [usize; bcj2::NUM_STREAMS],
    /// The stream has no more input.
    ends: [bool; bcj2::NUM_STREAMS],
    out_size: u64,
    out_pos: u64,
}

impl Bcj2Coder {
    /// Whether stream `s` has nothing buffered the decoder can take: CALL
    /// and JUMP are read 4 bytes at a time.
    fn is_empty(&self, s: usize) -> bool {
        let left = self.lens[s] - self.starts[s];
        if s == bcj2::STREAM_CALL || s == bcj2::STREAM_JUMP {
            left < 4
        } else {
            left == 0
        }
    }

    /// More input for stream `s`, whose buffer is empty.
    fn refill<R: Read + Seek>(&mut self, s: usize, r: &mut R) -> Result<()> {
        let buf = &mut self.bufs[s];
        if buf.is_empty() {
            buf.resize(PACK_BUF_SIZE, 0);
        }
        buf.copy_within(self.starts[s]..self.lens[s], 0);
        self.lens[s] -= self.starts[s];
        self.starts[s] = 0;
        let before = self.lens[s];
        let mut len = before;
        if s == bcj2::STREAM_RC {
            let src = self.rc.fill(r, Error::InputEof)?;
            let n = src.len().min(PACK_BUF_SIZE - len);
            buf[len..len + n].copy_from_slice(&src[..n]);
            self.rc.consume(n);
            len += n;
            if self.rc.remaining() == 0 {
                self.ends[s] = true;
            }
        } else {
            let coder = &mut self.coders[s];
            // Whole addresses for CALL and JUMP: their sizes are checked to
            // be multiples of 4.
            loop {
                let n = coder.read(r, &mut buf[len..])?;
                len += n;
                if n == 0 {
                    self.ends[s] = true;
                    break;
                }
                if s == bcj2::STREAM_MAIN || len.is_multiple_of(4) {
                    break;
                }
            }
        }
        self.lens[s] = len;
        Ok(())
    }

    /// Each empty buffer refilled, while its stream has more: then an empty
    /// buffer is a stream at its end, as the SDK's decoder, given whole
    /// streams, sees it.
    fn top_up<R: Read + Seek>(&mut self, r: &mut R) -> Result<()> {
        for s in 0..bcj2::NUM_STREAMS {
            if self.is_empty(s) && !self.ends[s] {
                self.refill(s, r)?;
            }
        }
        Ok(())
    }

    fn read<R: Read + Seek>(&mut self, r: &mut R, out: &mut [u8]) -> Result<usize> {
        let want = (out.len() as u64).min(self.out_size - self.out_pos) as usize;
        if want == 0 {
            if !out.is_empty() {
                self.finish(r)?;
            }
            return Ok(0);
        }
        loop {
            self.top_up(r)?;
            let mut p = bcj2::Bufs {
                bufs: [
                    &self.bufs[0][self.starts[0]..self.lens[0]],
                    &self.bufs[1][self.starts[1]..self.lens[1]],
                    &self.bufs[2][self.starts[2]..self.lens[2]],
                    &self.bufs[3][self.starts[3]..self.lens[3]],
                ],
                dest: &mut out[..want],
                dest_pos: 0,
            };
            let res = self.dec.decode(&mut p);
            let left = p.bufs.map(<[u8]>::len);
            let written = p.dest_pos;
            for (s, left) in left.into_iter().enumerate() {
                self.starts[s] = self.lens[s] - left;
            }
            res?;
            self.out_pos += written as u64;
            if written > 0 {
                return Ok(written);
            }
            // The output is not full: the decoder needs a stream that has
            // no more.
            let s = self.dec.state;
            if s >= bcj2::NUM_STREAMS || self.ends[s] {
                return Err(Error::Data);
            }
        }
    }

    /// The checks of `SzFolder_Decode2` once the output is full: every
    /// stream read to its end, and the decoder at a place it may end.
    fn finish<R: Read + Seek>(&mut self, r: &mut R) -> Result<()> {
        self.top_up(r)?;
        for s in 0..bcj2::NUM_STREAMS {
            if self.starts[s] != self.lens[s] || !self.ends[s] {
                return Err(Error::Data);
            }
        }
        if !self.dec.is_maybe_finished() {
            return Err(Error::Data);
        }
        self.rc.finish_source(r)
    }
}

/// A coder and those that feed it, as a reader of its output.
enum Node {
    Main(Box<MainCoder>),
    Filter(Box<FilterCoder>, Box<Node>),
    Bcj2(Box<Bcj2Coder>),
}

impl Node {
    fn read<R: Read + Seek>(&mut self, r: &mut R, out: &mut [u8]) -> Result<usize> {
        match self {
            Node::Main(main) => main.read(r, out),
            Node::Filter(filter, inner) => filter.read(inner, r, out),
            Node::Bcj2(bcj2) => bcj2.read(r, out),
        }
    }
}

/// Whether a coder with this method is a filter.
fn is_filter(id: u32) -> bool {
    matches!(
        id,
        K_DELTA
            | K_BCJ
            | K_PPC
            | K_IA64
            | K_SPARC
            | K_ARM
            | K_RISCV
            | K_ARM64
            | K_ARMT
            | K_SWAP2
            | K_SWAP4
    )
}

/// A folder the SDK does not decode, as a graph of coders from the unpacked
/// stream back to the packed ones.
struct Graph<'a> {
    decoding: &'a mut Decoding,
    folder: &'a Folder,
    data: &'a [u8],
    unpack_sizes: &'a [u64],
    pack_positions: &'a [u64],
    start_pos: u64,
    limit: u64,
    used: [bool; arc_in::NUM_CODERS_IN_FOLDER_MAX],
}

impl Graph<'_> {
    /// The input stream `in_index`: bound to a coder, or a packed stream.
    fn input(&mut self, in_index: u32) -> Result<PackReader> {
        let f = self.folder;
        for bond in &f.bonds[..f.num_bonds as usize] {
            if bond.in_index == in_index {
                let coder = bond.out_index as usize;
                let size = self.unpack_sizes[coder];
                return Ok(PackReader::from_node(self.node(coder)?, size));
            }
        }
        for (si, &stream) in f.pack_streams[..f.num_pack_streams as usize]
            .iter()
            .enumerate()
        {
            if stream == in_index {
                let offset = self.pack_positions[si];
                return Ok(PackReader::new(
                    self.start_pos.wrapping_add(offset),
                    self.pack_positions[si + 1] - offset,
                ));
            }
        }
        Err(Error::Unsupported)
    }

    /// Coder `ci`, once: the bonds may make a loop.
    fn node(&mut self, ci: usize) -> Result<Node> {
        if self.used[ci] {
            return Err(Error::Unsupported);
        }
        self.used[ci] = true;
        let f = self.folder;
        let c = &f.coders[ci];
        let props = &self.data[c.props_offset..c.props_offset + usize::from(c.props_size)];
        let out_size = self.unpack_sizes[ci];
        let first: u32 = f.coders[..ci]
            .iter()
            .map(|c| u32::from(c.num_streams))
            .sum();
        if is_bcj2(c) {
            let mut inputs = Vec::with_capacity(bcj2::NUM_STREAMS);
            for i in 0..bcj2::NUM_STREAMS as u32 {
                inputs.push(self.input(first + i)?);
            }
            let mut inputs = inputs.into_iter();
            let (Some(main), Some(call), Some(jump), Some(rc)) =
                (inputs.next(), inputs.next(), inputs.next(), inputs.next())
            else {
                return Err(Error::Fail);
            };
            let main_size = main.remaining();
            let (call_size, jump_size) = (call.remaining(), jump.remaining());
            if call_size & 3 != 0
                || jump_size & 3 != 0
                || main_size.wrapping_add(call_size).wrapping_add(jump_size) != out_size
            {
                return Err(Error::Data);
            }
            let coders = [main, call, jump].map(|input| {
                let size = input.remaining();
                MainCoder {
                    method: Main::Copy,
                    input,
                    out_size: size,
                    out_pos: 0,
                    ended: false,
                }
            });
            return Ok(Node::Bcj2(Box::new(Bcj2Coder {
                dec: Bcj2Dec::new(),
                coders: coders.map(|main| Node::Main(Box::new(main))),
                rc,
                bufs: Default::default(),
                starts: [0; bcj2::NUM_STREAMS],
                lens: [0; bcj2::NUM_STREAMS],
                ends: [false; bcj2::NUM_STREAMS],
                out_size,
                out_pos: 0,
            })));
        }
        if c.num_streams != 1 {
            return Err(Error::Unsupported);
        }
        let input = self.input(first)?;
        if c.method_id == K_AES {
            // The input is whole blocks, the last of them padded, and `7zz`
            // takes more of them than the output needs.
            let in_size = input.remaining();
            if !in_size.is_multiple_of(AES_BLOCK_LENGTH as u64) || in_size < out_size {
                return Err(Error::Data);
            }
            return Ok(Node::Main(Box::new(MainCoder {
                method: Main::Aes(Box::new(AesCoder::new(props, self.decoding)?)),
                input,
                out_size,
                out_pos: 0,
                ended: false,
            })));
        }
        if is_filter(c.method_id) {
            let filter = FilterCoder::new(c.method_id, props)?;
            // Only a size the filter's input has: it changes none.
            if input.remaining() != out_size {
                return Err(Error::Data);
            }
            let inner = MainCoder::new(K_COPY, &[], input, out_size, &mut self.limit, 1)?;
            return Ok(Node::Filter(
                Box::new(filter),
                Box::new(Node::Main(Box::new(inner))),
            ));
        }
        let threads = self.decoding.threads;
        let main = MainCoder::new(
            c.method_id,
            props,
            input,
            out_size,
            &mut self.limit,
            threads,
        )?;
        Ok(Node::Main(Box::new(main)))
    }
}

/// A folder's decoder, `SzAr_DecodeFolder`, as a reader of its unpacked
/// stream; the folder's CRC, when it has one, is checked at its end.
pub(crate) struct FolderDecoder {
    root: Node,
    size: u64,
    pos: u64,
    crc: u32,
    expected_crc: Option<u32>,
    failed: Option<Error>,
    /// Bad data then may be a wrong password.
    encrypted: bool,
}

/// Whether folder `fo` of `p` has an AES coder.
pub(crate) fn folder_is_encrypted(p: &Ar, fo: usize) -> bool {
    let data = &p.coders_data[p.fo_coders_offsets[fo]..p.fo_coders_offsets[fo + 1]];
    arc_in::get_next_folder_item(&mut Sd::new(data)).is_ok_and(|f| {
        f.coders[..f.num_coders as usize]
            .iter()
            .any(|c| c.method_id == K_AES)
    })
}

impl FolderDecoder {
    /// The decoder of folder `fo` of `p`, whose packed streams start at
    /// `start_pos` in the archive. Its coders' dictionaries and models take
    /// no more than `decoding.limit` bytes.
    pub(crate) fn new(p: &Ar, fo: usize, start_pos: u64, decoding: &mut Decoding) -> Result<Self> {
        let mut limit = decoding.limit;
        let start = p.fo_coders_offsets[fo];
        let data = &p.coders_data[start..p.fo_coders_offsets[fo + 1]];
        let mut sd = Sd::new(data);
        let folder = arc_in::get_next_folder_item(&mut sd)?;
        if !sd.data.is_empty()
            || folder.unpack_stream != u32::from(p.fo_to_main_unpack_size_index[fo])
        {
            return Err(Error::Fail);
        }
        let out_size = p.folder_unpack_size(fo);
        let unpack_sizes = &p.coder_unpack_sizes[p.fo_to_coder_unpack_sizes[fo] as usize..];
        let pack_positions = &p.pack_positions[p.fo_start_pack_stream_index[fo] as usize..];

        if check_supported_folder(&folder).is_err() {
            let encrypted = folder.coders[..folder.num_coders as usize]
                .iter()
                .any(|c| c.method_id == K_AES);
            let mut graph = Graph {
                decoding,
                folder: &folder,
                data,
                unpack_sizes,
                pack_positions,
                start_pos,
                limit,
                used: [false; arc_in::NUM_CODERS_IN_FOLDER_MAX],
            };
            let root = graph.node(folder.unpack_stream as usize)?;
            if graph.used[..folder.num_coders as usize].contains(&false) {
                return Err(Error::Unsupported);
            }
            return Ok(FolderDecoder {
                root,
                size: out_size,
                pos: 0,
                crc: 0,
                expected_crc: p.folder_crcs.check(fo).then(|| p.folder_crcs.vals[fo]),
                failed: None,
                encrypted,
            });
        }
        let props = |ci: usize| {
            let c = &folder.coders[ci];
            &data[c.props_offset..c.props_offset + usize::from(c.props_size)]
        };
        let pack = |si: usize| -> (u64, u64) {
            let offset = pack_positions[si];
            (
                start_pos.wrapping_add(offset),
                pack_positions[si + 1] - offset,
            )
        };

        let root = if folder.num_coders == 4 {
            // Coders 0 and 1 make the JUMP and CALL streams, coder 2 the
            // MAIN one, from packed streams 3, 2 and 0; packed stream 1 is
            // the RC stream.
            let mut mains = Vec::with_capacity(3);
            for (ci, si) in [(0usize, 3usize), (1, 2), (2, 0)] {
                let unpack_size = unpack_sizes[ci];
                if ci == 2 && unpack_size > out_size {
                    // Check it.
                    return Err(Error::Param);
                }
                let (pos, in_size) = pack(si);
                // The MAIN stream is the large one.
                let threads = if ci == 2 { decoding.threads } else { 1 };
                mains.push(MainCoder::new(
                    folder.coders[ci].method_id,
                    props(ci),
                    PackReader::new(pos, in_size),
                    unpack_size,
                    &mut limit,
                    threads,
                )?);
            }
            let (jump_size, call_size, main_size) =
                (unpack_sizes[0], unpack_sizes[1], unpack_sizes[2]);
            if jump_size & 3 != 0
                || call_size & 3 != 0
                || main_size.wrapping_add(jump_size).wrapping_add(call_size) != out_size
            {
                return Err(Error::Data);
            }
            let mut mains = mains.into_iter();
            let (Some(jump), Some(call), Some(main)) = (mains.next(), mains.next(), mains.next())
            else {
                return Err(Error::Fail);
            };
            let (rc_pos, rc_size) = pack(1);
            Node::Bcj2(Box::new(Bcj2Coder {
                dec: Bcj2Dec::new(),
                coders: [main, call, jump].map(|main| Node::Main(Box::new(main))),
                rc: PackReader::new(rc_pos, rc_size),
                bufs: Default::default(),
                starts: [0; bcj2::NUM_STREAMS],
                lens: [0; bcj2::NUM_STREAMS],
                ends: [false; bcj2::NUM_STREAMS],
                out_size,
                out_pos: 0,
            }))
        } else {
            let (pos, in_size) = pack(0);
            let main = MainCoder::new(
                folder.coders[0].method_id,
                props(0),
                PackReader::new(pos, in_size),
                out_size,
                &mut limit,
                decoding.threads,
            )?;
            let main = Node::Main(Box::new(main));
            if folder.num_coders == 2 {
                Node::Filter(
                    Box::new(FilterCoder::new(folder.coders[1].method_id, props(1))?),
                    Box::new(main),
                )
            } else {
                main
            }
        };
        Ok(FolderDecoder {
            root,
            size: out_size,
            pos: 0,
            crc: 0,
            expected_crc: p.folder_crcs.check(fo).then(|| p.folder_crcs.vals[fo]),
            failed: None,
            encrypted: false,
        })
    }

    /// The folder's unpacked size.
    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    /// How much of the folder has been read.
    pub(crate) fn position(&self) -> u64 {
        self.pos
    }

    /// Up to `out.len()` bytes of the folder; 0 at its end, once checked.
    pub(crate) fn read<R: Read + Seek>(&mut self, r: &mut R, out: &mut [u8]) -> Result<usize> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        let res = self.read_inner(r, out).map_err(|e| match e {
            Error::Data | Error::Crc if self.encrypted => Error::WrongPassword,
            e => e,
        });
        if let Err(e) = res {
            self.failed = Some(e);
        }
        res
    }

    fn read_inner<R: Read + Seek>(&mut self, r: &mut R, out: &mut [u8]) -> Result<usize> {
        let at_end = self.pos == self.size;
        let probe = &mut [0u8; 1][..];
        // At the end, the coders are asked once more, to check their ends.
        let out = if at_end && !out.is_empty() {
            probe
        } else {
            out
        };
        let n = self.root.read(r, out)?;
        if at_end {
            if n != 0 {
                return Err(Error::Data);
            }
            if let Some(expected) = self.expected_crc.take()
                && self.crc != expected
            {
                return Err(Error::Crc);
            }
            return Ok(0);
        }
        if n == 0 && !out.is_empty() {
            // The coders ended before the folder's size.
            return Err(Error::Data);
        }
        // Most folders have none: 7-Zip gives each file a CRC instead.
        if self.expected_crc.is_some() {
            self.crc = crate::deflate::crc32(self.crc, &out[..n]);
        }
        self.pos += n as u64;
        Ok(n)
    }
}

/// `SzAr_DecodeFolder`: all of folder `fo` into `out`, which holds its
/// unpacked size, checked.
pub(crate) fn decode_folder<R: Read + Seek>(
    p: &Ar,
    fo: usize,
    in_stream: &mut R,
    start_pos: u64,
    decoding: &mut Decoding,
    out: &mut [u8],
) -> Result<()> {
    let mut folder = FolderDecoder::new(p, fo, start_pos, decoding)?;
    if out.len() as u64 != folder.size() {
        return Err(Error::Fail);
    }
    let mut at = 0;
    while at < out.len() {
        let n = folder.read(in_stream, &mut out[at..])?;
        at += n;
    }
    let mut end = [0u8; 1];
    folder.read(in_stream, &mut end)?;
    Ok(())
}
