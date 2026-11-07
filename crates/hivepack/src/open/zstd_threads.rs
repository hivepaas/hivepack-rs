//! zstd frames one after the other, as pzstd and zstd's seekable format
//! write them, decoded a frame in each thread ([`Threaded`]).
//!
//! A frame's end is found without decoding it: after its header, each
//! block's header gives the size of what follows it, and the last block
//! says it is the last. So the input is cut where the frames end, never
//! where the threads would. Each frame goes to a thread, which decodes it
//! into memory with a decoder of its own, as libzstd decodes a frame in one
//! call, and its output is taken only if that decodes it whole. Skippable
//! frames, which pzstd writes before each frame, are passed over. Anything
//! else (a header or block that one thread would refuse, a window larger
//! than `Limits::zstd_window_log_max` allows, a frame that fails, a frame
//! larger than a thread takes, what follows the last frame, an error of the
//! reader under) hands what is left, from that frame's start, to the
//! decoder of one thread, which reads it as it would have.
//!
//! A frame that says its size is decoded into that much; one that does
//! not, into as much as its blocks may hold, each at most its block size,
//! and no more than 64 MiB: a frame that decodes to more is left to one
//! thread with what follows.
//! What the frames in flight hold, their bytes, what they decode to and a
//! decoder each, is bounded by `Limits::zstd_memlimit`.

use std::io::Read;
use std::sync::Arc;

use crate::open::decode::{Decoder, ZstdCodec};
use crate::open::detect::Layer;
use crate::open::pieces::{Left, Pieces, Plan, Threaded, Work};
use crate::zstd::{CONTENTSIZE_UNKNOWN, DCtx, FrameHeaderState, FrameType};

/// The most bytes a frame may take, and decode to, in a thread: a frame of
/// pzstd's at level 19 is about 10 MB, decoded to 32 MiB.
const MAX_FRAME: usize = 64 << 20;

/// What a thread's decoder takes besides its output.
const DECODER: u64 = 256 << 10;

/// A block's header.
const BLOCK_HEADER: usize = 3;

/// A skippable frame's header: its magic and the size of what follows.
const SKIPPABLE_HEADER: usize = 8;

/// The frame at the start of `read`: its size and what a thread decodes it
/// into, as much as it may decode to and no more than [`MAX_FRAME`], or what
/// more is needed to tell; `None` where one thread would refuse it, or it
/// is too large.
fn frame(read: &[u8], window_log_max: u32) -> Option<Result<(usize, usize), usize>> {
    let header = match crate::zstd::get_frame_header(read).ok()? {
        FrameHeaderState::NeedsInput(n) => return Some(Err(n.max(read.len() + 1))),
        FrameHeaderState::Complete(header) => header,
    };
    if header.frame_type != FrameType::Frame
        || header.dict_id != 0
        || header.window_size > 1u64 << window_log_max
    {
        return None;
    }
    let block_max = header.block_size_max as usize;
    let mut at = header.header_size as usize;
    let mut most = 0usize;
    loop {
        if at > MAX_FRAME {
            return None;
        }
        let Some(bytes) = read.get(at..at + BLOCK_HEADER) else {
            return Some(Err(at + BLOCK_HEADER));
        };
        let block = u32::from(bytes[0]) | u32::from(bytes[1]) << 8 | u32::from(bytes[2]) << 16;
        let (last, kind, size) = (block & 1 != 0, (block >> 1) & 3, (block >> 3) as usize);
        if size > block_max {
            return None;
        }
        let (stored, decoded) = match kind {
            // Raw: its bytes.
            0 => (size, size),
            // RLE: one byte, `size` times.
            1 => (1, size),
            // Compressed: as much as a block holds.
            2 => (size, block_max),
            _ => return None,
        };
        at += BLOCK_HEADER + stored;
        // Blocks split small, as zstd's high levels do, hold less: a thread
        // takes no more than [`MAX_FRAME`] in all.
        most = most.saturating_add(decoded).min(MAX_FRAME);
        if last {
            break;
        }
    }
    if header.checksum_flag {
        at += 4;
    }
    let most = match header.frame_content_size {
        CONTENTSIZE_UNKNOWN => most,
        size if size <= most as u64 => size as usize,
        _ => return None,
    };
    (at <= MAX_FRAME && most <= MAX_FRAME).then_some(Ok((at, most)))
}

/// What a thread does with a frame: what it decodes to, at most `most`
/// bytes, if it decodes whole into that.
fn decode_frame(bytes: &[u8], most: usize) -> Option<Vec<u8>> {
    let mut dctx = DCtx::new();
    let mut out = vec![0; most];
    let n = dctx.decompress(&mut out, bytes).ok()?;
    out.truncate(n);
    out.shrink_to_fit();
    Some(out)
}

/// zstd, cut into frames.
#[derive(Clone)]
pub(super) struct ZstdFrames {
    window_log_max: u32,
    /// A frame was taken: what follows is another, or the end.
    after_frame: bool,
}

impl Pieces for ZstdFrames {
    fn plan(&self, read: &[u8]) -> Plan {
        if read.len() < SKIPPABLE_HEADER {
            return Plan::Need(SKIPPABLE_HEADER);
        }
        if crate::zstd::is_skippable_frame(read) {
            let size = u32::from_le_bytes([read[4], read[5], read[6], read[7]]);
            let len = SKIPPABLE_HEADER + size as usize;
            return Plan::Piece {
                len,
                cost: len as u64,
            };
        }
        match frame(read, self.window_log_max) {
            Some(Ok((len, most))) => Plan::Piece {
                len,
                cost: (len + most) as u64 + DECODER,
            },
            Some(Err(need)) => Plan::Need(need),
            None => Plan::Stop,
        }
    }

    fn take(&mut self, bytes: &Arc<Vec<u8>>) -> Work {
        self.after_frame = true;
        if crate::zstd::is_skippable_frame(bytes) {
            return Work::Nothing;
        }
        let most = match frame(bytes, self.window_log_max) {
            Some(Ok((_, most))) => most,
            _ => 0,
        };
        let bytes = Arc::clone(bytes);
        Work::Decode(Box::new(move || decode_frame(&bytes, most)))
    }

    fn may_end(&self) -> bool {
        self.after_frame
    }

    fn serial<'a, R: Read + Send + 'a>(&self, left: Left<R>) -> Box<dyn Read + Send + 'a> {
        match ZstdCodec::new(self.window_log_max) {
            Ok(codec) => {
                let mut decoder = Decoder::new(left, codec, Layer::Zstd);
                if self.after_frame {
                    decoder.after_a_stream();
                }
                Box::new(decoder)
            }
            // Not with a window log the opener took.
            Err(e) => Box::new(Failed(Some(e))),
        }
    }
}

/// A reader that fails with what it holds.
struct Failed(Option<std::io::Error>);

impl Read for Failed {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(self
            .0
            .take()
            .unwrap_or_else(|| std::io::Error::other("zstd's decoder could not be made")))
    }
}

/// zstd over `inner`, in `threads` threads, windows of at most
/// `window_log_max` and the frames in flight holding `memory` at most.
pub(super) fn zstd_threads<'a, R: Read + Send + 'a>(
    inner: R,
    threads: u32,
    window_log_max: u32,
    memory: u64,
) -> Threaded<'a, R, ZstdFrames> {
    let format = ZstdFrames {
        window_log_max,
        after_frame: false,
    };
    Threaded::new(inner, format, threads, memory, "hivepack-zstd")
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;
    use crate::zstd::{CCtx, CParameter};

    fn text(len: usize, seed: u32) -> Vec<u8> {
        let mut seed = seed;
        (0..len)
            .map(|_| {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
                b"abcdefgh  \n"[(seed >> 16) as usize % 11]
            })
            .collect()
    }

    /// `data` as one frame, at `level`, with its size and checksum or not.
    fn frame_of(data: &[u8], level: i32, sized: bool) -> Vec<u8> {
        let mut cctx = CCtx::new();
        cctx.set_parameter(CParameter::CompressionLevel(level))
            .unwrap();
        cctx.set_parameter(CParameter::ChecksumFlag(sized)).unwrap();
        cctx.set_parameter(CParameter::ContentSizeFlag(sized))
            .unwrap();
        let mut out = vec![0; crate::zstd::compress_bound(data.len()).unwrap() + 64];
        let n = if sized {
            cctx.compress2(&mut out, data).unwrap()
        } else {
            // Streamed, as from a pipe: no size.
            let mut input = crate::zstd::InBuffer::new(data);
            let mut output = crate::zstd::OutBuffer::new(&mut out);
            loop {
                let left = cctx
                    .compress_stream2(&mut output, &mut input, crate::zstd::EndDirective::End)
                    .unwrap();
                if left == 0 {
                    break output.pos;
                }
            }
        };
        out.truncate(n);
        out
    }

    /// pzstd's way: a skippable frame of the frame's size before each.
    fn frames(data: &[u8], cut: usize) -> Vec<u8> {
        let mut file = Vec::new();
        for (i, piece) in data.chunks(cut).enumerate() {
            let frame = frame_of(piece, 1 + (i % 3) as i32, i % 2 == 0);
            file.extend(0x184D_2A50u32.to_le_bytes());
            file.extend(4u32.to_le_bytes());
            file.extend((frame.len() as u32).to_le_bytes());
            file.extend(frame);
        }
        file
    }

    fn read_all(mut reader: impl Read) -> (Vec<u8>, Option<String>) {
        let mut data = Vec::new();
        let mut piece = vec![0; 1000];
        loop {
            match reader.read(&mut piece) {
                Ok(0) => return (data, None),
                Ok(n) => data.extend(&piece[..n]),
                Err(e) => return (data, Some(e.to_string())),
            }
        }
    }

    fn one(file: &[u8], window_log_max: u32) -> (Vec<u8>, Option<String>) {
        let codec = ZstdCodec::new(window_log_max).unwrap();
        read_all(Decoder::new(file, codec, Layer::Zstd))
    }

    fn threads(file: &[u8], n: u32, window_log_max: u32) -> (Vec<u8>, Option<String>) {
        read_all(zstd_threads(file, n, window_log_max, 1 << 30))
    }

    #[test]
    fn frames_come_out_as_one_thread_reads_them() {
        let data = text(300_000, 3);
        let file = frames(&data, 40_000);
        assert!(one(&file, 27) == (data.clone(), None));
        for n in [2, 5] {
            assert!(threads(&file, n, 27) == (data.clone(), None));
        }
        let mut reader = zstd_threads(&file[..], 3, 27, 1 << 30);
        assert!(read_all(&mut reader) == (data.clone(), None));
        assert!(!reader.is_serial());
        // Room for one frame at a time, or for none.
        for memory in [400 << 10, 1 << 10] {
            let reader = zstd_threads(&file[..], 4, 27, memory);
            assert!(read_all(reader) == (data.clone(), None));
        }
        // One frame: one thread.
        let one_frame = frame_of(&data, 3, true);
        assert!(threads(&one_frame, 3, 27) == (data, None));
    }

    /// `CompressFrames`'s frames, and its seek table, a skippable frame,
    /// are all taken from the threads.
    #[test]
    fn compress_frames_are_taken_from_the_threads() {
        use crate::zstd::{CompressFrames, EndDirective, FramesOptions, InBuffer, OutBuffer};
        let data = text(300_000, 5);
        let options = FramesOptions {
            frame_size: 40_000,
            ..FramesOptions::default()
        };
        let mut frames = CompressFrames::new(&options).unwrap();
        let mut file = vec![0; crate::zstd::compress_bound(data.len()).unwrap() + 4096];
        let mut output = OutBuffer::new(&mut file);
        let mut input = InBuffer::new(&data);
        while frames
            .compress_stream(&mut output, &mut input, EndDirective::End)
            .unwrap()
            != 0
        {}
        let n = output.pos;
        file.truncate(n);
        let mut reader = zstd_threads(&file[..], 3, 27, 1 << 30);
        assert!(read_all(&mut reader) == (data, None));
        assert!(!reader.is_serial());
    }

    #[test]
    fn damage_anywhere_comes_out_as_one_thread_reads_it() {
        let file = frames(&text(80_000, 5), 10_000);
        let step = (file.len() / 40).max(1);
        for at in (0..file.len()).step_by(step) {
            let mut damaged = file.clone();
            damaged[at] ^= 0x5A;
            let alone = one(&damaged, 27);
            let (data, error) = threads(&damaged, 3, 27);
            // What libzstd gives out before an error depends on its output
            // buffer: the start of it, and the same error.
            assert!(error == alone.1, "{at}");
            let n = data.len().min(alone.0.len());
            assert!(data[..n] == alone.0[..n], "{at}");
        }
        for len in (0..file.len()).step_by(step) {
            let cut = &file[..len];
            let alone = one(cut, 27);
            let (data, error) = threads(cut, 3, 27);
            assert!(error == alone.1, "{len}");
            let n = data.len().min(alone.0.len());
            assert!(data[..n] == alone.0[..n], "{len}");
        }
        let mut after = file.clone();
        after.extend(b"more");
        assert!(threads(&after, 3, 27) == one(&after, 27));
        // A window past the limit.
        let wide = frame_of(&text(2 << 20, 9), 19, true);
        let file = [frames(&text(50_000, 1), 10_000), wide].concat();
        assert!(threads(&file, 3, 20) == one(&file, 20));
        assert!(one(&file, 20).1.is_some());
    }

    #[test]
    fn an_error_of_the_reader_under_comes_where_one_thread_meets_it() {
        struct Failing<'a>(&'a [u8]);
        impl Read for Failing<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.0.is_empty() {
                    return Err(io::Error::other("the disk is gone"));
                }
                let n = buf.len().min(self.0.len()).min(700);
                buf[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        let file = frames(&text(60_000, 7), 10_000);
        let cut = &file[..file.len() * 2 / 3];
        let codec = ZstdCodec::new(27).unwrap();
        let alone = read_all(Decoder::new(Failing(cut), codec, Layer::Zstd));
        assert!(alone.1.as_deref() == Some("the disk is gone"));
        let (data, error) = read_all(zstd_threads(Failing(cut), 3, 27, 1 << 30));
        assert!(error == alone.1);
        assert!(alone.0.starts_with(&data) || data.starts_with(&alone.0));
    }
}
