//! The decompressors: `decompress.c`, each a call to hivepack's port of the
//! library squashfuse calls.
//!
//! | Id | squashfuse calls | Here |
//! |---|---|---|
//! | 1, zlib | zlib's `uncompress` | `hivepack::deflate::Inflate`, as `uncompress` drives it |
//! | 2, LZMA | liblzma's `lzma_alone_decoder`, as squashfs-tools reads it | `hivepack::xz::Stream::alone_decoder` |
//! | 3, LZO | liblzo2's `lzo1x_decompress_safe` | `hivepack::lzo::decompress`, its port |
//! | 4, xz | liblzma's `lzma_stream_buffer_decode` | `hivepack::xz::Stream::stream_decoder` |
//! | 5, LZ4 | liblz4's `LZ4_decompress_safe` | `hivepack::lz4::block::decompress_safe` |
//! | 6, zstd | libzstd's `ZSTD_decompress` | `hivepack::zstd::decompress` |

use crate::deflate::{
    Flush, InBuffer as ZIn, Inflate, MAX_WBITS, OutBuffer as ZOut, Status as ZStatus,
};
use crate::xz::{Action, InBuffer, OutBuffer, Status, Stream};

use super::squashfs_fs::{
    LZ4_COMPRESSION, LZMA_COMPRESSION, LZO_COMPRESSION, XZ_COMPRESSION, ZLIB_COMPRESSION,
    ZSTD_COMPRESSION,
};

/// A compressor of SquashFS: the superblock's `compression`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Compression {
    /// 1: zlib (mksquashfs's `gzip`).
    Zlib,
    /// 2: LZMA, the legacy format squashfs-tools 4.0 to 4.3 wrote.
    Lzma,
    /// 3: LZO.
    Lzo,
    /// 4: xz.
    Xz,
    /// 5: LZ4.
    Lz4,
    /// 6: zstd.
    Zstd,
    /// Another id.
    Unknown(u16),
}

impl Compression {
    /// The compressor of an id.
    pub fn from_id(id: u16) -> Compression {
        match id {
            ZLIB_COMPRESSION => Compression::Zlib,
            LZMA_COMPRESSION => Compression::Lzma,
            LZO_COMPRESSION => Compression::Lzo,
            XZ_COMPRESSION => Compression::Xz,
            LZ4_COMPRESSION => Compression::Lz4,
            ZSTD_COMPRESSION => Compression::Zstd,
            other => Compression::Unknown(other),
        }
    }

    /// `sqfs_compression_name`: the name squashfuse gives it, if any.
    pub fn name(self) -> Option<&'static str> {
        match self {
            Compression::Zlib => Some("zlib"),
            Compression::Lzma => Some("lzma"),
            Compression::Lzo => Some("lzo"),
            Compression::Xz => Some("xz"),
            Compression::Lz4 => Some("lz4"),
            Compression::Zstd => Some("zstd"),
            Compression::Unknown(_) => None,
        }
    }

    /// Whether its data is read: all but unknown ids.
    pub fn is_supported(self) -> bool {
        sqfs_decompressor_get(self).is_some()
    }
}

/// `sqfs_decompressor`: a block's data, decompressed into at most `outsize`
/// bytes, or `None` if it does not decompress.
///
/// Differs from squashfuse: the zlib and zstd decoders are kept from one
/// block to the next (`Contexts`), where zlib's `uncompress` and
/// `ZSTD_decompress` make one for each block; each is reset first, and
/// decodes the same.
pub type Decompressor = fn(&mut Contexts, &[u8], usize) -> Option<Vec<u8>>;

/// The decoders kept from one block to the next.
#[derive(Default)]
pub struct Contexts {
    zlib: Option<Inflate>,
    zstd: Option<crate::zstd::DCtx>,
}

impl std::fmt::Debug for Contexts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Contexts").finish_non_exhaustive()
    }
}

/// `sqfs_decompressor_get`: the decompressor of a compressor, if it is
/// read.
pub fn sqfs_decompressor_get(compression: Compression) -> Option<Decompressor> {
    match compression {
        Compression::Zlib => Some(sqfs_decompressor_zlib),
        Compression::Lzma => Some(sqfs_decompressor_lzma),
        Compression::Lzo => Some(sqfs_decompressor_lzo),
        Compression::Xz => Some(sqfs_decompressor_xz),
        Compression::Lz4 => Some(sqfs_decompressor_lz4),
        Compression::Zstd => Some(sqfs_decompressor_zstd),
        Compression::Unknown(_) => None,
    }
}

/// `sqfs_decompressor_zlib`: zlib's `uncompress` (`uncompr.c`), which
/// inflates until the stream ends, and fails on anything else.
fn sqfs_decompressor_zlib(ctx: &mut Contexts, input: &[u8], outsize: usize) -> Option<Vec<u8>> {
    let mut out = vec![0u8; outsize];
    let strm = match &mut ctx.zlib {
        Some(strm) => {
            strm.reset();
            strm
        }
        None => ctx.zlib.insert(Inflate::new(MAX_WBITS).ok()?),
    };
    let mut src = ZIn::new(input);
    let mut dst = ZOut::new(&mut out);
    loop {
        match strm.inflate(&mut dst, &mut src, Flush::NoFlush) {
            Ok(ZStatus::StreamEnd) => break,
            Ok(ZStatus::Ok) => continue,
            // Z_NEED_DICT is Z_DATA_ERROR to `uncompress`.
            Ok(ZStatus::NeedDict) | Err(_) => return None,
        }
    }
    let n = dst.pos;
    out.truncate(n);
    Some(out)
}

/// `sqfs_decompressor_xz`: `lzma_stream_buffer_decode`, without a memory
/// limit or flags: one .xz Stream, which must end.
fn sqfs_decompressor_xz(_: &mut Contexts, input: &[u8], outsize: usize) -> Option<Vec<u8>> {
    let mut out = vec![0u8; outsize];
    let mut strm = Stream::stream_decoder(u64::MAX, 0).ok()?;
    let mut src = InBuffer::new(input);
    let mut dst = OutBuffer::new(&mut out);
    match strm.code(&mut dst, &mut src, Action::Finish) {
        Ok(Status::StreamEnd) => {
            let n = dst.pos;
            out.truncate(n);
            Some(out)
        }
        _ => None,
    }
}

/// The LZMA header: the properties, then the size.
const LZMA_PROPS_SIZE: usize = 5;
const LZMA_UNCOMP_SIZE: usize = 8;
const LZMA_HEADER_SIZE: usize = LZMA_PROPS_SIZE + LZMA_UNCOMP_SIZE;
/// What the LZMA decoder may allocate.
const MEMLIMIT: u64 = 32 * 1024 * 1024;

/// `sqfs_decompressor_lzma`, which squashfuse took from squashfs-tools: a
/// .lzma header whose size is the block's, given to the decoder as
/// unknown, then the data, which must end, or fill that size.
fn sqfs_decompressor_lzma(_: &mut Contexts, input: &[u8], outsize: usize) -> Option<Vec<u8>> {
    if input.len() < LZMA_HEADER_SIZE {
        return None;
    }
    let mut strm = Stream::alone_decoder(MEMLIMIT).ok()?;
    let mut lzma_header = [0u8; LZMA_HEADER_SIZE];
    lzma_header.copy_from_slice(&input[..LZMA_HEADER_SIZE]);
    let uncompressed_size = u32::from_le_bytes([
        lzma_header[LZMA_PROPS_SIZE],
        lzma_header[LZMA_PROPS_SIZE + 1],
        lzma_header[LZMA_PROPS_SIZE + 2],
        lzma_header[LZMA_PROPS_SIZE + 3],
    ]);
    if u64::from(uncompressed_size) > outsize as u64 {
        return None;
    }
    lzma_header[LZMA_PROPS_SIZE..].fill(255);

    let mut out = vec![0u8; outsize];
    let mut dst = OutBuffer::new(&mut out);
    let mut header = InBuffer::new(&lzma_header);
    match strm.code(&mut dst, &mut header, Action::Run) {
        Ok(Status::Ok) if header.pos == header.src.len() => {}
        _ => return None,
    }
    let mut src = InBuffer::new(&input[LZMA_HEADER_SIZE..]);
    let res = strm.code(&mut dst, &mut src, Action::Finish);
    let done = match res {
        Ok(Status::StreamEnd) => true,
        Ok(Status::Ok) => {
            strm.total_out() >= u64::from(uncompressed_size) && src.pos == src.src.len()
        }
        _ => false,
    };
    if !done {
        return None;
    }
    out.truncate(uncompressed_size as usize);
    Some(out)
}

/// `sqfs_decompressor_lzo`: `lzo1x_decompress_safe`, whose every error
/// fails, `LZO_E_INPUT_NOT_CONSUMED` among them (bytes after the block's
/// end).
fn sqfs_decompressor_lzo(_: &mut Contexts, input: &[u8], outsize: usize) -> Option<Vec<u8>> {
    let mut out = vec![0u8; outsize];
    let n = crate::lzo::decompress(input, &mut out).ok()?;
    out.truncate(n);
    Some(out)
}

/// `sqfs_decompressor_lz4`: `LZ4_decompress_safe`.
fn sqfs_decompressor_lz4(_: &mut Contexts, input: &[u8], outsize: usize) -> Option<Vec<u8>> {
    let mut out = vec![0u8; outsize];
    let n = crate::lz4::block::decompress_safe(input, &mut out).ok()?;
    out.truncate(n);
    Some(out)
}

/// `sqfs_decompressor_zstd`: `ZSTD_decompress`, the frames one after the
/// other.
fn sqfs_decompressor_zstd(ctx: &mut Contexts, input: &[u8], outsize: usize) -> Option<Vec<u8>> {
    let mut out = vec![0u8; outsize];
    let dctx = ctx.zstd.get_or_insert_with(crate::zstd::DCtx::new);
    let n = dctx.decompress(&mut out, input).ok()?;
    out.truncate(n);
    Some(out)
}
