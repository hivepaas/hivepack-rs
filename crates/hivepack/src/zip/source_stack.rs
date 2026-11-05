//! The sources libzip stacks to read an entry, and those `zip_close` stacks
//! on the data it writes, with the rules every `zip_source_t` follows
//! around its callback: port of the reading parts of `zip_source_read.c`,
//! `zip_source_open.c`, `zip_source_close.c`, `zip_source_at_eof.c`,
//! `zip_source_stat.c`, `zip_source_get_file_attributes.c`,
//! `zip_source_get_dostime.c` and `zip_source_layered.c`.
//!
//! Differs from libzip: a stack is a struct, not a chain of callbacks. To
//! read, it is always a window on the archive, on an empty buffer or on
//! new data, then the decrypting layer if the data is encrypted, the
//! decompressing layer if it is compressed, then the CRC layer if the CRC
//! is to be checked; to write, the data or an entry's stack, then layers to
//! decompress, compute the CRC and compress.
//! Each layer keeps the state libzip keeps in its `zip_source_t`. Not in
//! libzip: what a thread compressed can stand for the data and the layers
//! up to the compressing one (see `close_threads.rs`).

use std::io::Read;
use std::sync::Arc;

use crate::zip::close_threads::Precompressed;
use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::get_encryption_implementation::{Decrypt, Encrypt};
use crate::zip::source::ReadAt;
use crate::zip::source_compress::{Compress, Decompress};
use crate::zip::source_crc::Crc;
use crate::zip::source_data::{DataSource, FileAttributes};
use crate::zip::source_window::{Lower, UpperWindow, Window};
use crate::zip::zip::Stat;

/// A layer: its callback's context, and what `zip_source_t` keeps.
pub(crate) struct Layer<T> {
    pub(crate) ctx: T,
    error: Error,
    /// EOF reached
    eof: bool,
    /// a previous ZIP_SOURCE_READ reported an error
    had_read_error: bool,
    /// byte read to determine EOF for sources that don't support
    /// ZIP_SOURCE_AT_EOF
    next_byte: Option<u8>,
}

impl<T> Layer<T> {
    pub(crate) fn new(ctx: T) -> Layer<T> {
        Layer {
            ctx,
            error: Error::OK,
            eof: false,
            had_read_error: false,
            next_byte: None,
        }
    }

    /// What `zip_source_open` resets once the callback opened.
    pub(crate) fn opened(&mut self) {
        self.eof = false;
        self.had_read_error = false;
        self.error = Error::OK;
    }

    /// Reads up to `data.len()` bytes with the callback `call`, until the
    /// callback returns none: port of `zip_source_read`. After an error,
    /// every read fails with it, and the bytes read before it in the same
    /// call are returned first.
    pub(crate) fn read(
        &mut self,
        data: &mut [u8],
        call: &mut dyn FnMut(&mut T, &mut [u8]) -> Result<usize>,
    ) -> Result<usize> {
        if self.had_read_error {
            return Err(self.error);
        }
        if self.eof || data.is_empty() {
            return Ok(0);
        }

        let mut bytes_read = 0;
        if let Some(byte) = self.next_byte.take() {
            data[0] = byte;
            bytes_read = 1;
        }

        while bytes_read < data.len() {
            match call(&mut self.ctx, &mut data[bytes_read..]) {
                Err(e) => {
                    self.had_read_error = true;
                    self.error = e;
                    return if bytes_read == 0 {
                        Err(e)
                    } else {
                        Ok(bytes_read)
                    };
                }
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(n) => bytes_read += n,
            }
        }
        Ok(bytes_read)
    }
}

/// The sources reading one entry, from the bottom up.
pub(crate) struct Stack<'a, R: ?Sized> {
    pub(crate) lower: Lower<'a, R>,
    pub(crate) window: Layer<Window>,
    pub(crate) decrypt: Option<Layer<Decrypt>>,
    pub(crate) decompress: Option<Layer<Decompress>>,
    pub(crate) crc: Option<Layer<Crc>>,
    /// the window on the decompressed data, for part of an entry
    pub(crate) partial: Option<Layer<UpperWindow>>,
    /// the entry, for the window's errors
    pub(crate) index: u64,
}

fn read_window<R: ReadAt + ?Sized>(
    window: &mut Layer<Window>,
    lower: &mut Lower<'_, R>,
    data: &mut [u8],
) -> Result<usize> {
    window.read(data, &mut |ctx, buf| ctx.read(lower, buf))
}

/// `zip_source_stat` of the window: the lower source's, then the window's.
fn stat_window<R: ReadAt + ?Sized>(window: &Layer<Window>, lower: &Lower<'_, R>) -> Stat<'static> {
    let mut st = lower.stat();
    window.ctx.stat(&mut st);
    st
}

/// The source under the decompressing layer: the decrypting one, or the
/// window.
fn read_below_decompress<R: ReadAt + ?Sized>(
    decrypt: &mut Option<Layer<Decrypt>>,
    window: &mut Layer<Window>,
    lower: &mut Lower<'_, R>,
    data: &mut [u8],
) -> Result<usize> {
    match decrypt {
        Some(decrypt) => decrypt.read(data, &mut |ctx, buf| {
            ctx.read(buf, &mut |b| read_window(window, lower, b))
        }),
        None => read_window(window, lower, data),
    }
}

fn stat_below_decompress<R: ReadAt + ?Sized>(
    decrypt: &Option<Layer<Decrypt>>,
    window: &Layer<Window>,
    lower: &Lower<'_, R>,
) -> Stat<'static> {
    let mut st = stat_window(window, lower);
    if let Some(decrypt) = decrypt {
        // It cannot fail: the decrypting layer is made only on a window
        // whose compressed size holds what it takes away.
        let _ = decrypt.ctx.stat(&mut st);
    }
    st
}

fn read_decompress<R: ReadAt + ?Sized>(
    decompress: &mut Layer<Decompress>,
    decrypt: &mut Option<Layer<Decrypt>>,
    window: &mut Layer<Window>,
    lower: &mut Lower<'_, R>,
    data: &mut [u8],
) -> Result<usize> {
    decompress.read(data, &mut |ctx, buf| {
        ctx.read(buf, &mut |b| {
            read_below_decompress(decrypt, window, lower, b)
        })
    })
}

/// The source under the CRC layer: the decompressing one, or what is under
/// it.
fn read_below_crc<R: ReadAt + ?Sized>(
    decompress: &mut Option<Layer<Decompress>>,
    decrypt: &mut Option<Layer<Decrypt>>,
    window: &mut Layer<Window>,
    lower: &mut Lower<'_, R>,
    data: &mut [u8],
) -> Result<usize> {
    match decompress {
        Some(decompress) => read_decompress(decompress, decrypt, window, lower, data),
        None => read_below_decompress(decrypt, window, lower, data),
    }
}

fn stat_below_crc<R: ReadAt + ?Sized>(
    decompress: &Option<Layer<Decompress>>,
    decrypt: &Option<Layer<Decrypt>>,
    window: &Layer<Window>,
    lower: &Lower<'_, R>,
) -> Stat<'static> {
    let mut st = stat_below_decompress(decrypt, window, lower);
    if let Some(decompress) = decompress {
        decompress.ctx.stat(&mut st);
    }
    st
}

/// Whether the window is at its end: a window on an entry's data always
/// has one.
fn window_at_eof(window: &mut Layer<Window>) -> bool {
    if !window.eof && window.ctx.at_eof() == Some(true) {
        window.eof = true;
    }
    window.eof
}

/// Whether the source under the CRC layer is at its end: port of
/// `zip_source_at_eof`. The window knows, and so does the layer that
/// decrypts WinZip AES; ZipCrypto's asks the window. The decompressing
/// source does not know, and cannot seek, so a byte is read and kept for
/// the next read.
fn at_eof_below_crc<R: ReadAt + ?Sized>(
    decompress: &mut Option<Layer<Decompress>>,
    decrypt: &mut Option<Layer<Decrypt>>,
    window: &mut Layer<Window>,
    lower: &mut Lower<'_, R>,
) -> Result<bool> {
    match (decompress, decrypt) {
        (None, None) => Ok(window_at_eof(window)),
        (None, Some(layer)) => {
            if !layer.eof {
                // ZipCrypto passes ZIP_SOURCE_AT_EOF to the window's
                // callback.
                let at_eof = match layer.ctx.at_eof() {
                    Some(at_eof) => at_eof,
                    None => window.ctx.at_eof() == Some(true),
                };
                if at_eof {
                    layer.eof = true;
                }
            }
            Ok(layer.eof)
        }
        (Some(layer), decrypt) => {
            if !layer.eof {
                let mut d = [0];
                let n = read_decompress(layer, decrypt, window, lower, &mut d)?;
                if n > 0 {
                    layer.next_byte = Some(d[0]);
                }
            }
            Ok(layer.eof)
        }
    }
}

/// The source under the partial window: the CRC layer, or what is under
/// it.
fn read_below_partial<R: ReadAt + ?Sized>(
    crc: &mut Option<Layer<Crc>>,
    decompress: &mut Option<Layer<Decompress>>,
    decrypt: &mut Option<Layer<Decrypt>>,
    window: &mut Layer<Window>,
    lower: &mut Lower<'_, R>,
    data: &mut [u8],
) -> Result<usize> {
    match crc {
        Some(crc) => crc.read(data, &mut |ctx, buf| {
            let n = read_below_crc(decompress, decrypt, window, lower, buf);
            ctx.read(buf, n, || {
                stat_below_crc(decompress, decrypt, window, lower)
            })
        }),
        None => read_below_crc(decompress, decrypt, window, lower, data),
    }
}

impl<R: ReadAt + ?Sized> Stack<'_, R> {
    /// The size the stack below the partial window gives in its stat, if
    /// it gives one.
    pub(crate) fn size_below_partial(&self) -> Option<u64> {
        let st = stat_below_crc(&self.decompress, &self.decrypt, &self.window, &self.lower);
        (st.valid & crate::zip::zip::stat::SIZE != 0).then_some(st.size)
    }

    /// Opens the layers, the lowest first: port of `zip_source_open`.
    pub(crate) fn open(&mut self) -> Result<()> {
        if let Err(e) = self.window.ctx.open(&mut self.lower, self.index) {
            self.window.error = e;
            return Err(e);
        }
        self.window.opened();

        if let Some(layer) = self.decrypt.as_mut() {
            let st = stat_window(&self.window, &self.lower);
            let dostime = self.window.ctx.dos_time();
            let (window, lower) = (&mut self.window, &mut self.lower);
            if let Err(e) = layer
                .ctx
                .open(&mut |b| read_window(window, lower, b), &st, dostime)
            {
                layer.error = e;
                return Err(e);
            }
            layer.opened();
        }

        if self.decompress.is_some() {
            let st = stat_below_decompress(&self.decrypt, &self.window, &self.lower);
            let mut attributes = self.window.ctx.file_attributes();
            attributes.merge_lower(&self.lower.file_attributes()?);
            if let Some(decompress) = self.decompress.as_mut() {
                if let Err(e) = decompress.ctx.open(&st, &attributes) {
                    decompress.error = e;
                    return Err(e);
                }
                decompress.opened();
            }
        }

        if let Some(crc) = self.crc.as_mut() {
            crc.ctx.open();
            crc.opened();
        }

        let Stack {
            lower,
            window,
            decrypt,
            decompress,
            crc,
            partial,
            ..
        } = self;
        if let Some(partial) = partial {
            if let Err(e) = partial
                .ctx
                .open(&mut |b| read_below_partial(crc, decompress, decrypt, window, lower, b))
            {
                partial.error = e;
                return Err(e);
            }
            partial.opened();
        }
        Ok(())
    }

    /// `zip_source_read` of the top layer.
    pub(crate) fn read(&mut self, data: &mut [u8]) -> Result<usize> {
        let Stack {
            lower,
            window,
            decrypt,
            decompress,
            crc,
            partial,
            ..
        } = self;
        match partial {
            Some(partial) => partial.read(data, &mut |ctx, buf| {
                ctx.read(buf, &mut |b| {
                    read_below_partial(crc, decompress, decrypt, window, lower, b)
                })
            }),
            None => read_below_partial(crc, decompress, decrypt, window, lower, data),
        }
    }

    /// Closes the layers, the top first: port of `zip_source_close`. The
    /// first error is the one returned.
    pub(crate) fn close(&mut self) -> Result<()> {
        let Stack {
            lower,
            window,
            decrypt,
            decompress,
            crc,
            ..
        } = self;
        let mut ret = Ok(());
        if let Some(crc) = crc {
            let at_eof = at_eof_below_crc(decompress, decrypt, window, lower);
            if let Err(e) = crc.ctx.close(at_eof, || {
                stat_below_crc(decompress, decrypt, window, lower)
            }) {
                crc.error = e;
                ret = Err(e);
            }
        }
        if let Some(decompress) = decompress
            && let Err(e) = decompress.ctx.close()
        {
            decompress.error = e;
            if ret.is_ok() {
                ret = Err(e);
            }
        }
        if let Some(layer) = decrypt
            && let Err(e) = layer.ctx.close(&mut |b| read_window(window, lower, b))
        {
            layer.error = e;
            if ret.is_ok() {
                ret = Err(e);
            }
        }
        ret
    }
}

impl<R: ReadAt + ?Sized> Stack<'_, R> {
    /// `zip_source_stat` of the top layer.
    pub(crate) fn stat(&self) -> Result<Stat<'static>> {
        let mut st = stat_below_crc(&self.decompress, &self.decrypt, &self.window, &self.lower);
        if let Some(crc) = &self.crc {
            crc.ctx.stat(&mut st)?;
        }
        if let Some(partial) = &self.partial {
            partial.ctx.stat(&mut st);
        }
        Ok(st)
    }

    /// `zip_source_get_file_attributes` of the top layer: the window's,
    /// from the entry's header, over those of new data, under those of the
    /// decompressing layer.
    pub(crate) fn file_attributes(&self) -> Result<FileAttributes> {
        let mut attributes = self.window.ctx.file_attributes();
        attributes.merge_lower(&self.lower.file_attributes()?);
        if let Some(decompress) = &self.decompress {
            let mut upper = decompress.ctx.file_attributes();
            upper.merge_lower(&attributes);
            attributes = upper;
        }
        Ok(attributes)
    }

    /// `zip_source_get_dos_time` of the top layer: the window's, which the
    /// CRC layer passes on and the decrypting and decompressing ones do
    /// not; none for a part of the data, whose window has none.
    pub(crate) fn dos_time(&self) -> Option<(u16, u16)> {
        match (&self.decrypt, &self.decompress, &self.partial) {
            (None, None, None) => self.window.ctx.dos_time(),
            _ => None,
        }
    }
}

/// What `add_data` reads an entry's data from: its new data, or the stack
/// that reads an entry of the archive, to recompress it.
pub(crate) enum Base<'a, R: ?Sized> {
    Data {
        source: Arc<dyn DataSource>,
        /// the position of the next read
        layer: Layer<u64>,
    },
    Entry(Box<Stack<'a, R>>),
    /// Data read once from its start, as [`Writer`](crate::zip::Writer) adds it:
    /// what is known of it is told beforehand.
    Reader {
        reader: &'a mut dyn Read,
        stat: Stat<'static>,
        attributes: FileAttributes,
        /// the bytes read so far
        layer: Layer<u64>,
    },
}

impl<R: ReadAt + ?Sized> Base<'_, R> {
    /// The new data `source`.
    pub(crate) fn data(source: Arc<dyn DataSource>) -> Self {
        Base::Data {
            source,
            layer: Layer::new(0),
        }
    }

    fn open(&mut self) -> Result<()> {
        match self {
            Base::Data { layer, .. } => {
                layer.ctx = 0;
                layer.opened();
                Ok(())
            }
            Base::Entry(stack) => stack.open(),
            Base::Reader { layer, .. } => {
                // It cannot go back to its start.
                if layer.ctx != 0 {
                    return Err(Error::new(ErrorCode::Inval, 0));
                }
                layer.opened();
                Ok(())
            }
        }
    }

    fn read(&mut self, data: &mut [u8]) -> Result<usize> {
        match self {
            Base::Data { source, layer } => layer.read(data, &mut |position, buf| {
                let n = source.read_at(*position, buf)?;
                *position += n as u64;
                Ok(n)
            }),
            Base::Entry(stack) => stack.read(data),
            Base::Reader { reader, layer, .. } => layer.read(data, &mut |position, buf| loop {
                match reader.read(buf) {
                    Ok(n) => {
                        *position += n as u64;
                        return Ok(n);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => {
                        return Err(Error::new(ErrorCode::Read, e.raw_os_error().unwrap_or(0)));
                    }
                }
            }),
        }
    }

    fn close(&mut self) -> Result<()> {
        match self {
            Base::Data { .. } | Base::Reader { .. } => Ok(()),
            Base::Entry(stack) => stack.close(),
        }
    }

    /// `zip_source_stat`.
    pub(crate) fn stat(&self) -> Result<Stat<'static>> {
        match self {
            Base::Data { source, .. } => source.stat(),
            Base::Entry(stack) => stack.stat(),
            Base::Reader { stat, .. } => Ok(*stat),
        }
    }

    /// `zip_source_get_file_attributes`.
    pub(crate) fn file_attributes(&self) -> Result<FileAttributes> {
        match self {
            Base::Data { source, .. } => source.file_attributes(),
            Base::Entry(stack) => stack.file_attributes(),
            Base::Reader { attributes, .. } => Ok(*attributes),
        }
    }

    /// `zip_source_get_dos_time`.
    pub(crate) fn dos_time(&self) -> Result<Option<(u16, u16)>> {
        match self {
            Base::Data { source, .. } => source.dos_time(),
            Base::Entry(stack) => Ok(stack.dos_time()),
            Base::Reader { .. } => Ok(None),
        }
    }
}

/// The sources `add_data` stacks on an entry's data, from the bottom up.
/// The decrypting layer passes the attributes of the source under it on.
pub(crate) struct WriteStack<'a, R: ?Sized> {
    pub(crate) base: Base<'a, R>,
    pub(crate) decrypt: Option<Layer<Decrypt>>,
    pub(crate) decompress: Option<Layer<Decompress>>,
    pub(crate) crc: Option<Layer<Crc>>,
    pub(crate) compress: Option<Layer<Compress>>,
    /// Not in libzip: what a thread read and compressed of the base, which
    /// stands for the base and the layers up to the compressing one, the
    /// others then none. The base still answers what is asked of the data.
    pub(crate) precompressed: Option<Layer<Precompressed>>,
    pub(crate) encrypt: Option<Layer<Encrypt>>,
}

/// Reads from the base, through the decrypting layer if there is one.
fn read_decrypted<R: ReadAt + ?Sized>(
    base: &mut Base<'_, R>,
    decrypt: &mut Option<Layer<Decrypt>>,
    data: &mut [u8],
) -> Result<usize> {
    match decrypt {
        Some(decrypt) => decrypt.read(data, &mut |ctx, buf| ctx.read(buf, &mut |b| base.read(b))),
        None => base.read(data),
    }
}

/// Reads from the layers under the compressing one.
fn read_below_compress<R: ReadAt + ?Sized>(
    base: &mut Base<'_, R>,
    decrypt: &mut Option<Layer<Decrypt>>,
    decompress: &mut Option<Layer<Decompress>>,
    crc: &mut Option<Layer<Crc>>,
    data: &mut [u8],
) -> Result<usize> {
    let read_below_crc = |base: &mut Base<'_, R>,
                          decrypt: &mut Option<Layer<Decrypt>>,
                          decompress: &mut Option<Layer<Decompress>>,
                          data: &mut [u8]|
     -> Result<usize> {
        match decompress {
            Some(decompress) => decompress.read(data, &mut |ctx, buf| {
                ctx.read(buf, &mut |b| read_decrypted(base, decrypt, b))
            }),
            None => read_decrypted(base, decrypt, data),
        }
    };
    match crc {
        Some(crc) => crc.read(data, &mut |ctx, buf| {
            let n = read_below_crc(base, decrypt, decompress, buf);
            // A CRC layer that computes the CRC never asks for the stat.
            ctx.read(buf, n, Stat::default)
        }),
        None => read_below_crc(base, decrypt, decompress, data),
    }
}

/// `zip_source_stat` under the compressing layer.
fn stat_below_compress<R: ReadAt + ?Sized>(
    base: &Base<'_, R>,
    decrypt: &Option<Layer<Decrypt>>,
    decompress: &Option<Layer<Decompress>>,
    crc: &Option<Layer<Crc>>,
) -> Result<Stat<'static>> {
    let mut st = base.stat()?;
    if let Some(decrypt) = decrypt {
        decrypt.ctx.stat(&mut st)?;
    }
    if let Some(decompress) = decompress {
        decompress.ctx.stat(&mut st);
    }
    if let Some(crc) = crc {
        crc.ctx.stat(&mut st)?;
    }
    Ok(st)
}

/// `zip_source_get_file_attributes` under the compressing layer.
fn attributes_below_compress<R: ReadAt + ?Sized>(
    base: &Base<'_, R>,
    decompress: &Option<Layer<Decompress>>,
) -> Result<FileAttributes> {
    let mut attributes = base.file_attributes()?;
    if let Some(decompress) = decompress {
        let mut upper = decompress.ctx.file_attributes();
        upper.merge_lower(&attributes);
        attributes = upper;
    }
    Ok(attributes)
}

impl<R: ReadAt + ?Sized> WriteStack<'_, R> {
    /// Opens the layers, the lowest first: port of `zip_source_open`.
    pub(crate) fn open(&mut self) -> Result<()> {
        match self.precompressed.as_mut() {
            // What opening the layers under it gave in the thread.
            Some(layer) => {
                if let Err(e) = layer.ctx.open() {
                    layer.error = e;
                    return Err(e);
                }
                layer.opened();
            }
            None => self.open_below_encrypt()?,
        }
        if let Some(encrypt) = self.encrypt.as_mut() {
            if let Err(e) = encrypt.ctx.open() {
                encrypt.error = e;
                return Err(e);
            }
            encrypt.opened();
        }
        Ok(())
    }

    /// Opens the layers under the encrypting one.
    fn open_below_encrypt(&mut self) -> Result<()> {
        self.base.open()?;
        if let Some(layer) = self.decrypt.as_mut() {
            let st = self.base.stat()?;
            let dostime = self.base.dos_time()?;
            let base = &mut self.base;
            if let Err(e) = layer.ctx.open(&mut |b| base.read(b), &st, dostime) {
                layer.error = e;
                return Err(e);
            }
            layer.opened();
        }
        if self.decompress.is_some() {
            let mut st = self.base.stat()?;
            if let Some(decrypt) = &self.decrypt {
                decrypt.ctx.stat(&mut st)?;
            }
            let attributes = self.base.file_attributes()?;
            if let Some(decompress) = self.decompress.as_mut() {
                if let Err(e) = decompress.ctx.open(&st, &attributes) {
                    decompress.error = e;
                    return Err(e);
                }
                decompress.opened();
            }
        }
        if let Some(crc) = self.crc.as_mut() {
            crc.ctx.open();
            crc.opened();
        }
        if self.compress.is_some() {
            // The compressing layer asks for the stat and attributes of the
            // source below it when it opens.
            let st = stat_below_compress(&self.base, &self.decrypt, &self.decompress, &self.crc)?;
            let attributes = attributes_below_compress(&self.base, &self.decompress)?;
            if let Some(compress) = self.compress.as_mut() {
                if let Err(e) = compress.ctx.open(&st, &attributes) {
                    compress.error = e;
                    return Err(e);
                }
                compress.opened();
            }
        }
        Ok(())
    }

    /// `zip_source_read` of the top layer.
    pub(crate) fn read(&mut self, data: &mut [u8]) -> Result<usize> {
        let WriteStack {
            base,
            decrypt,
            decompress,
            crc,
            compress,
            precompressed,
            encrypt,
        } = self;
        let mut read_below_encrypt =
            |data: &mut [u8]| match (precompressed.as_mut(), compress.as_mut()) {
                (Some(layer), _) => {
                    layer.ctx.count_read();
                    layer.read(data, &mut |ctx, buf| ctx.read(buf))
                }
                (None, Some(compress)) => compress.read(data, &mut |ctx, buf| {
                    ctx.read(buf, &mut |b| {
                        read_below_compress(base, decrypt, decompress, crc, b)
                    })
                }),
                (None, None) => read_below_compress(base, decrypt, decompress, crc, data),
            };
        match encrypt {
            Some(encrypt) => {
                encrypt.read(data, &mut |ctx, buf| ctx.read(buf, &mut read_below_encrypt))
            }
            None => read_below_encrypt(data),
        }
    }

    /// Closes the layers, the top first: port of `zip_source_close`.
    pub(crate) fn close(&mut self) -> Result<()> {
        let mut ret = Ok(());
        if let Some(encrypt) = self.encrypt.as_mut() {
            encrypt.ctx.close();
        }
        if self.precompressed.is_some() {
            // The thread closed the layers under it, and closing fails
            // nothing that reads this.
            return ret;
        }
        if let Some(compress) = self.compress.as_mut()
            && let Err(e) = compress.ctx.close()
        {
            compress.error = e;
            ret = Err(e);
        }
        if let Some(decompress) = self.decompress.as_mut()
            && let Err(e) = decompress.ctx.close()
        {
            decompress.error = e;
            if ret.is_ok() {
                ret = Err(e);
            }
        }
        let base = &mut self.base;
        if let Some(layer) = self.decrypt.as_mut()
            && let Err(e) = layer.ctx.close(&mut |b| base.read(b))
        {
            layer.error = e;
            if ret.is_ok() {
                ret = Err(e);
            }
        }
        if let Err(e) = self.base.close()
            && ret.is_ok()
        {
            ret = Err(e);
        }
        ret
    }

    /// `zip_source_stat` under the encrypting layer.
    pub(crate) fn stat_below_encrypt(&self) -> Result<Stat<'static>> {
        if let Some(layer) = &self.precompressed {
            return layer.ctx.shown().stat;
        }
        let mut st = stat_below_compress(&self.base, &self.decrypt, &self.decompress, &self.crc)?;
        if let Some(compress) = &self.compress {
            compress.ctx.stat(&mut st);
        }
        Ok(st)
    }

    /// `zip_source_stat` of the top layer.
    pub(crate) fn stat(&self) -> Result<Stat<'static>> {
        let mut st = self.stat_below_encrypt()?;
        if let Some(encrypt) = &self.encrypt {
            encrypt.ctx.stat(&mut st);
        }
        Ok(st)
    }

    /// `zip_source_get_dos_time` under the encrypting layer: the base's,
    /// which only the CRC layer passes on.
    pub(crate) fn dos_time_below_encrypt(&self) -> Result<Option<(u16, u16)>> {
        if self.decrypt.is_some()
            || self.decompress.is_some()
            || self.compress.is_some()
            || self.precompressed.is_some()
        {
            return Ok(None);
        }
        self.base.dos_time()
    }

    /// `zip_source_get_file_attributes` of the top layer.
    pub(crate) fn file_attributes(&self) -> Result<FileAttributes> {
        let mut attributes = match &self.precompressed {
            Some(layer) => layer.ctx.shown().attributes?,
            None => self.attributes_below_encrypt()?,
        };
        if let Some(encrypt) = &self.encrypt {
            let mut upper = encrypt.ctx.file_attributes();
            upper.merge_lower(&attributes);
            attributes = upper;
        }
        Ok(attributes)
    }

    /// `zip_source_get_file_attributes` under the encrypting layer.
    pub(crate) fn attributes_below_encrypt(&self) -> Result<FileAttributes> {
        let mut attributes = attributes_below_compress(&self.base, &self.decompress)?;
        if let Some(compress) = &self.compress {
            let mut upper = compress.ctx.file_attributes();
            upper.merge_lower(&attributes);
            attributes = upper;
        }
        Ok(attributes)
    }

    /// What the stat and the attributes under the encrypting layer change
    /// with, besides the base: whether the CRC is complete, whether the
    /// compressed stream ended, and whether it was stored. Not in libzip.
    pub(crate) fn shown_key(&self) -> (bool, bool, bool) {
        let complete = self.crc.as_ref().is_some_and(|crc| crc.ctx.complete());
        let (ended, stored) = self
            .compress
            .as_ref()
            .map_or((false, false), |compress| compress.ctx.ended());
        (complete, ended, stored)
    }
}
