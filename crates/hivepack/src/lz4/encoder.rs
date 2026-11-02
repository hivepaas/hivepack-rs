//! Writing `.lz4` files: one frame of the frame format, from liblz4's file
//! functions (`lz4file.c`, `LZ4F_writeOpen`, `LZ4F_write` and
//! `LZ4F_writeClose`).

use std::io::{self, Write};

use crate::lz4::lz4frame::{Error, HEADER_SIZE_MAX, get_block_size};
use crate::lz4::lz4frame_compress::{CompressionContext, Preferences, compress_bound};

/// A writer of `.lz4` data: what is written is compressed into one frame,
/// which `finish` ends.
///
/// The input goes to `CompressionContext::compress_update` a block at most
/// at a time, as `LZ4F_write` gives it, and `flush` compresses what the
/// context keeps (`LZ4F_flush`), so the frame is liblz4's for the same
/// writes and flushes.
#[derive(Debug)]
pub struct Encoder<W: Write> {
    inner: W,
    cctx: CompressionContext,
    buffer: Vec<u8>,
    /// `maxWriteSize`: the block size.
    max_write_size: usize,
    /// A call failed, which leaves the frame unfinished.
    failed: bool,
}

fn frame_error(e: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, e.name())
}

impl<W: Write> Encoder<W> {
    /// `LZ4F_writeOpen`: an encoder writing a frame with `prefs` (or the
    /// defaults) into `inner`, its header first.
    pub fn new(mut inner: W, prefs: Option<&Preferences>) -> io::Result<Self> {
        let max_write_size = prefs.map_or(64 << 10, |p| get_block_size(p.frame_info.block_size_id));
        let mut cctx = CompressionContext::new();
        let mut header = [0; HEADER_SIZE_MAX];
        let size = cctx
            .compress_begin(&mut header, prefs)
            .map_err(frame_error)?;
        inner.write_all(&header[..size])?;
        Ok(Encoder {
            inner,
            cctx,
            buffer: vec![0; compress_bound(max_write_size, prefs)],
            max_write_size,
            failed: false,
        })
    }

    /// The writer the frame goes to.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// The writer the frame goes to. Writing into it breaks the frame.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    fn check(&self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("an earlier call failed"));
        }
        Ok(())
    }

    /// `LZ4F_writeClose`: the frame ended, what the context keeps
    /// compressed, then the end mark and the checksum. Returns the writer.
    /// A content size in the preferences that is not what was written is an
    /// error (`ERROR_frameSize_wrong`), and then, as in liblz4, the end of
    /// the frame is not written.
    pub fn finish(mut self) -> io::Result<W> {
        self.check()?;
        let size = self
            .cctx
            .compress_end(&mut self.buffer)
            .map_err(frame_error)?;
        self.inner.write_all(&self.buffer[..size])?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for Encoder<W> {
    /// Up to a block of `buf` compressed (`LZ4F_compressUpdate`), and what
    /// it makes written.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.check()?;
        let chunk = buf.len().min(self.max_write_size);
        let size = match self.cctx.compress_update(&mut self.buffer, &buf[..chunk]) {
            Ok(size) => size,
            Err(e) => {
                self.failed = true;
                return Err(frame_error(e));
            }
        };
        if let Err(e) = self.inner.write_all(&self.buffer[..size]) {
            self.failed = true;
            return Err(e);
        }
        Ok(chunk)
    }

    /// What the context keeps compressed into a block (`LZ4F_flush`) and
    /// written, then the writer flushed.
    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        let size = match self.cctx.flush(&mut self.buffer) {
            Ok(size) => size,
            Err(e) => {
                self.failed = true;
                return Err(frame_error(e));
            }
        };
        if let Err(e) = self.inner.write_all(&self.buffer[..size]) {
            self.failed = true;
            return Err(e);
        }
        self.inner.flush()
    }
}
