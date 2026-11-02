//! Times hivepack::lz4 against liblz4 1.10.0 and lz4_flex on the same
//! inputs: decoding the blocks liblz4 compressed at each level, or, with
//! `--frame`, reading the frames it wrote.
//!
//! ```text
//! cargo run --release -p lz4-bench -- [--levels 1,9] [--rounds 3] [--seconds 1] [--frame] [--compress] PATH...
//! ```
//!
//! Level 1 is `LZ4_compress_default`, levels 2 to 12 `LZ4_compress_HC`, and
//! negative levels `LZ4_compress_fast` with that acceleration, as the `lz4`
//! program takes them. A block is one call, with all the input and room for
//! all the output, as `LZ4_decompress_safe` is. A frame is read as a
//! stream, with each library's own reader of `.lz4` data, into one buffer
//! of the content's size: for liblz4 the lz4 crate's `Decoder`, which feeds
//! `LZ4F_decompress` 32 KB at a time; for the port its `Decoder`, and its
//! frame context in one call (the "context" column).
//!
//! With `--compress`, blocks are compressed instead, or with `--frame`,
//! frames of 4 MB linked blocks with a content checksum, by each library's
//! writer (for liblz4 the lz4 crate's `Encoder`, which gives
//! `LZ4F_compressUpdate` a block at a time; for the port its `Encoder`,
//! the same way): the port's must be liblz4's, byte for byte. lz4_flex has
//! one level, its own, timed at level 1 only.
//!
//! lz4_flex is built with its safe code (`safe-decode`, its default), or
//! with its unsafe code when the tool is built with
//! `--no-default-features`. `--features unsafe-fast` builds the port with
//! its feature.
//!
//! Each PATH is a file, or a folder whose files are each an input. Rounds
//! take turns between the implementations, so a noisy machine slows them
//! alike. Speeds are the range over rounds in MB/s of uncompressed data
//! (10^6 bytes per second), and the output is a Markdown table.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, String>;

trait Codec {
    fn name(&self) -> String;
    /// Decodes the block `input`, whose content is `size` bytes long.
    fn decompress(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()>;
    /// Reads the frame `input`, whose content is `size` bytes long.
    fn read_frame(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()>;
    /// Compresses `input` as a block at `level` (1, or a negative
    /// acceleration).
    fn compress(&mut self, input: &[u8], level: i32, output: &mut Vec<u8>) -> Result<()>;
    /// `input` compressed into a frame by the library's writer.
    fn write_frame(&mut self, input: &[u8], level: i32, output: &mut Vec<u8>) -> Result<()>;
    /// Whether the library compresses at `level`.
    fn compresses_at(&self, _level: i32) -> bool {
        true
    }
}

fn bound(len: usize) -> usize {
    len + len / 255 + 16
}

fn read_all(mut reader: impl Read, size: usize, output: &mut Vec<u8>) -> Result<()> {
    output.clear();
    output.resize(size, 0);
    reader.read_exact(output).map_err(|e| e.to_string())?;
    let mut rest = [0; 1];
    match reader.read(&mut rest) {
        Ok(0) => Ok(()),
        other => Err(format!("more than the content: {other:?}")),
    }
}

/// liblz4 1.10.0 through the lz4 crate.
struct Liblz4;

impl Codec for Liblz4 {
    fn name(&self) -> String {
        "liblz4 1.10.0".into()
    }

    fn decompress(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()> {
        output.clear();
        output.resize(size, 0);
        match lz4::block::decompress_to_buffer(input, Some(size as i32), output) {
            Ok(len) if len == size => Ok(()),
            other => Err(format!("liblz4: {other:?}")),
        }
    }

    fn read_frame(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()> {
        let decoder = lz4::Decoder::new(input).map_err(|e| e.to_string())?;
        read_all(decoder, size, output)
    }

    fn compress(&mut self, input: &[u8], level: i32, output: &mut Vec<u8>) -> Result<()> {
        output.clear();
        output.resize(bound(input.len()), 0);
        let n = lz4::block::compress_to_buffer(input, Some(c_mode(level)), false, output)
            .map_err(|e| e.to_string())?;
        output.truncate(n);
        Ok(())
    }

    fn write_frame(&mut self, input: &[u8], level: i32, output: &mut Vec<u8>) -> Result<()> {
        output.clear();
        let mut encoder = lz4::EncoderBuilder::new()
            .block_size(lz4::BlockSize::Max4MB)
            .block_checksum(lz4::liblz4::BlockChecksum::NoBlockChecksum)
            .checksum(lz4::ContentChecksum::ChecksumEnabled)
            .level(level.max(0) as u32)
            .build(std::mem::take(output))
            .map_err(|e| e.to_string())?;
        std::io::Write::write_all(&mut encoder, input).map_err(|e| e.to_string())?;
        let (mut frame, result) = encoder.finish();
        result.map_err(|e| e.to_string())?;
        std::mem::swap(output, &mut frame);
        Ok(())
    }
}

/// The lz4 crate's mode for `level`, as the `lz4` program takes it.
fn c_mode(level: i32) -> lz4::block::CompressionMode {
    match level {
        1 => lz4::block::CompressionMode::DEFAULT,
        l if l > 1 => lz4::block::CompressionMode::HIGHCOMPRESSION(l),
        l => lz4::block::CompressionMode::FAST(-l),
    }
}

/// hivepack::lz4.
struct Port;

impl Codec for Port {
    fn name(&self) -> String {
        if hivepack::lz4::UNSAFE_FAST {
            "hivepack-lz4 (unsafe-fast)".into()
        } else {
            "hivepack-lz4".into()
        }
    }

    fn decompress(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()> {
        output.clear();
        output.resize(size, 0);
        match hivepack::lz4::block::decompress_safe(input, output) {
            Ok(len) if len == size => Ok(()),
            other => Err(format!("port: {other:?}")),
        }
    }

    fn read_frame(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()> {
        read_all(hivepack::lz4::Decoder::new(input), size, output)
    }

    fn compress(&mut self, input: &[u8], level: i32, output: &mut Vec<u8>) -> Result<()> {
        output.clear();
        output.resize(bound(input.len()), 0);
        let n = match level {
            1 => hivepack::lz4::block::compress_default(input, output),
            l if l > 1 => hivepack::lz4::hc::compress_hc(input, output, l),
            l => hivepack::lz4::block::compress_fast(input, output, -l),
        };
        output.truncate(n);
        Ok(())
    }

    fn write_frame(&mut self, input: &[u8], level: i32, output: &mut Vec<u8>) -> Result<()> {
        use hivepack::lz4::frame::{BlockSizeId, FrameInfo, Preferences};
        let prefs = Preferences {
            frame_info: FrameInfo {
                block_size_id: BlockSizeId::Max4Mb,
                content_checksum: true,
                ..FrameInfo::default()
            },
            compression_level: level.max(0),
            ..Preferences::default()
        };
        output.clear();
        let mut encoder = hivepack::lz4::Encoder::new(std::mem::take(output), Some(&prefs))
            .map_err(|e| e.to_string())?;
        std::io::Write::write_all(&mut encoder, input).map_err(|e| e.to_string())?;
        *output = encoder.finish().map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// hivepack::lz4's frame context, in one call: what the port's frame decoding
/// costs without a reader around it.
struct PortContext;

impl Codec for PortContext {
    fn name(&self) -> String {
        "hivepack-lz4 context".into()
    }

    fn decompress(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()> {
        Port.decompress(input, size, output)
    }

    fn read_frame(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()> {
        use hivepack::lz4::frame::{DecompressOptions, DecompressionContext, InBuffer, OutBuffer};
        output.clear();
        output.resize(size, 0);
        let mut dctx = DecompressionContext::new();
        let mut out = OutBuffer::new(output);
        let mut src = InBuffer::new(input);
        match dctx.decompress(&mut out, &mut src, DecompressOptions::default()) {
            Ok(0) if out.pos == size => Ok(()),
            other => Err(format!(
                "port context: {other:?}, {} of {size} bytes",
                out.pos
            )),
        }
    }

    fn compress(&mut self, input: &[u8], level: i32, output: &mut Vec<u8>) -> Result<()> {
        Port.compress(input, level, output)
    }

    fn write_frame(&mut self, input: &[u8], level: i32, output: &mut Vec<u8>) -> Result<()> {
        Port.write_frame(input, level, output)
    }
}

/// lz4_flex.
struct Flex;

impl Codec for Flex {
    fn name(&self) -> String {
        if cfg!(feature = "flex-safe") {
            "lz4_flex 0.14.0 (safe)".into()
        } else {
            "lz4_flex 0.14.0 (unsafe)".into()
        }
    }

    fn decompress(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()> {
        output.clear();
        output.resize(size, 0);
        match lz4_flex::block::decompress_into(input, output) {
            Ok(len) if len == size => Ok(()),
            other => Err(format!("lz4_flex: {other:?}")),
        }
    }

    fn read_frame(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()> {
        read_all(lz4_flex::frame::FrameDecoder::new(input), size, output)
    }

    /// lz4_flex has one level, its own: its blocks are not liblz4's.
    fn compress(&mut self, input: &[u8], _level: i32, output: &mut Vec<u8>) -> Result<()> {
        output.clear();
        output.resize(lz4_flex::block::get_maximum_output_size(input.len()), 0);
        let n = lz4_flex::block::compress_into(input, output).map_err(|e| e.to_string())?;
        output.truncate(n);
        Ok(())
    }

    fn write_frame(&mut self, input: &[u8], _level: i32, output: &mut Vec<u8>) -> Result<()> {
        use lz4_flex::frame::{BlockMode, BlockSize, FrameEncoder, FrameInfo};
        output.clear();
        // Linked blocks, as liblz4's: lz4_flex's default is independent
        // ones.
        let info = FrameInfo::new()
            .block_size(BlockSize::Max4MB)
            .block_mode(BlockMode::Linked)
            .content_checksum(true);
        let mut encoder = FrameEncoder::with_frame_info(info, std::mem::take(output));
        std::io::Write::write_all(&mut encoder, input).map_err(|e| e.to_string())?;
        *output = encoder.finish().map_err(|e| e.to_string())?;
        Ok(())
    }

    fn compresses_at(&self, level: i32) -> bool {
        level == 1
    }
}

/// `data` compressed by liblz4 at `level`, as a block, or as a frame of
/// linked 4 MB blocks with a content checksum (the `lz4` program's
/// defaults).
fn c_compress(data: &[u8], level: i32, frame: bool) -> Result<Vec<u8>> {
    if frame {
        let mut encoder = lz4::EncoderBuilder::new()
            .block_size(lz4::BlockSize::Max4MB)
            .block_checksum(lz4::liblz4::BlockChecksum::NoBlockChecksum)
            .checksum(lz4::ContentChecksum::ChecksumEnabled)
            .level(level.max(0) as u32)
            .build(Vec::new())
            .map_err(|e| e.to_string())?;
        std::io::Write::write_all(&mut encoder, data).map_err(|e| e.to_string())?;
        let (frame, result) = encoder.finish();
        result.map_err(|e| e.to_string())?;
        return Ok(frame);
    }
    lz4::block::compress(data, Some(c_mode(level)), false).map_err(|e| e.to_string())
}

struct Options {
    levels: Vec<i32>,
    rounds: u32,
    budget: Duration,
    frame: bool,
    compress: bool,
    paths: Vec<PathBuf>,
}

fn options(args: impl Iterator<Item = String>) -> Result<Options> {
    let mut options = Options {
        levels: vec![1, 9],
        rounds: 3,
        budget: Duration::from_secs(1),
        frame: false,
        compress: false,
        paths: Vec::new(),
    };
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--levels" => {
                options.levels = value()?
                    .split(',')
                    .map(|l| match l.parse() {
                        Ok(level @ -65537..=12) if level != 0 => Ok(level),
                        _ => Err(format!("bad level {l:?}")),
                    })
                    .collect::<Result<_>>()?;
            }
            "--frame" => options.frame = true,
            "--compress" => options.compress = true,
            "--rounds" => options.rounds = value()?.parse().map_err(|_| "bad --rounds")?,
            "--seconds" => {
                let seconds: f64 = value()?.parse().map_err(|_| "bad --seconds")?;
                options.budget =
                    Duration::try_from_secs_f64(seconds).map_err(|_| "bad --seconds")?;
            }
            "-h" | "--help" => {
                return Err(
                    "usage: lz4-bench [--levels 1,9] [--rounds N] [--seconds S] [--frame] [--compress] PATH..."
                        .into(),
                );
            }
            _ if arg.starts_with("--") => return Err(format!("unknown option {arg}")),
            _ => options.paths.push(PathBuf::from(arg)),
        }
    }
    if options.paths.is_empty() || options.rounds == 0 {
        return Err("give at least one input file or folder, and at least one round".into());
    }
    Ok(options)
}

fn inputs(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    for path in paths {
        if path.is_dir() {
            let mut files: Vec<PathBuf> = std::fs::read_dir(path)
                .map_err(|e| format!("{}: {e}", path.display()))?
                .filter_map(|entry| entry.ok().map(|e| e.path()))
                .filter(|p| p.is_file())
                .filter(|p| {
                    !p.file_name()
                        .is_some_and(|n| n.as_encoded_bytes().starts_with(b"."))
                })
                .collect();
            files.sort();
            found.extend(files);
        } else {
            found.push(path.clone());
        }
    }
    Ok(found)
}

fn time(budget: Duration, mut op: impl FnMut() -> Result<()>) -> Result<f64> {
    op()?;
    let start = Instant::now();
    let mut runs = 0u32;
    loop {
        op()?;
        runs += 1;
        if start.elapsed() >= budget {
            return Ok(start.elapsed().as_secs_f64() / f64::from(runs));
        }
    }
}

struct Range(f64, f64);

impl Range {
    fn add(range: Option<Range>, value: f64) -> Option<Range> {
        Some(match range {
            None => Range(value, value),
            Some(Range(low, high)) => Range(low.min(value), high.max(value)),
        })
    }
}

impl std::fmt::Display for Range {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.round() == self.1.round() {
            write!(f, "{:.0}", self.0)
        } else {
            write!(f, "{:.0}–{:.0}", self.0, self.1)
        }
    }
}

fn bench(options: &Options, codecs: &mut [Box<dyn Codec>], input: &Path) -> Result<()> {
    let data = std::fs::read(input).map_err(|e| format!("{}: {e}", input.display()))?;
    let name = input.file_name().map_or_else(
        || input.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let megabytes = data.len() as f64 / 1e6;
    let mut scratch = Vec::new();
    for &level in &options.levels {
        let compressed = c_compress(&data, level, options.frame)?;
        let ratio = data.len() as f64 / compressed.len().max(1) as f64;
        let mut speeds: Vec<Option<Range>> = codecs.iter().map(|_| None).collect();
        for _ in 0..options.rounds {
            for (i, codec) in codecs.iter_mut().enumerate() {
                if options.compress && !codec.compresses_at(level) {
                    continue;
                }
                let seconds = time(options.budget, || {
                    if options.compress && options.frame {
                        codec.write_frame(&data, level, &mut scratch)
                    } else if options.compress {
                        codec.compress(&data, level, &mut scratch)
                    } else if options.frame {
                        codec.read_frame(&compressed, data.len(), &mut scratch)
                    } else {
                        codec.decompress(&compressed, data.len(), &mut scratch)
                    }
                })?;
                if options.compress {
                    // liblz4's block or frame, byte for byte, but for
                    // lz4_flex's own.
                    if i < 2 && scratch != compressed {
                        return Err(format!(
                            "{}: {name} level {level} is not liblz4's output",
                            codec.name()
                        ));
                    }
                } else if scratch != data {
                    return Err(format!(
                        "{}: {name} level {level} does not round trip",
                        codec.name()
                    ));
                }
                speeds[i] = Range::add(speeds[i].take(), megabytes / seconds);
            }
        }
        let best: Vec<f64> = speeds
            .iter()
            .map(|r| r.as_ref().map_or(0.0, |r| r.1))
            .collect();
        let cells: Vec<String> = speeds
            .iter()
            .map(|r| r.as_ref().map_or_else(String::new, Range::to_string))
            .collect();
        let ratios: Vec<String> = best[1..]
            .iter()
            .map(|&b| {
                if b > 0.0 {
                    format!("{:.2}×", b / best[0])
                } else {
                    String::new()
                }
            })
            .collect();
        println!(
            "| {name} | {megabytes:.1} | {level} | {ratio:.2} | {} | {} |",
            cells.join(" | "),
            ratios.join(" | ")
        );
    }
    Ok(())
}

fn run() -> Result<()> {
    let options = options(std::env::args().skip(1))?;
    let mut codecs: Vec<Box<dyn Codec>> = vec![Box::new(Liblz4), Box::new(Port), Box::new(Flex)];
    if options.frame && !options.compress {
        codecs.insert(2, Box::new(PortContext));
    }
    let header: Vec<String> = codecs.iter().map(|c| c.name()).collect();
    let versus: Vec<String> = codecs[1..]
        .iter()
        .map(|c| format!("{}/liblz4", c.name()))
        .collect();
    let mode = if options.compress && options.frame {
        "Frames written"
    } else if options.compress {
        "Blocks compressed"
    } else if options.frame {
        "Frames read"
    } else {
        "Blocks decoded"
    };
    println!("{mode}, MB/s:\n");
    println!(
        "| input | MB | level | ratio | {} | {} |",
        header.join(" | "),
        versus.join(" | ")
    );
    println!(
        "|---|---|---|---|{}{}",
        "---|".repeat(codecs.len()),
        "---|".repeat(codecs.len() - 1)
    );
    for input in inputs(&options.paths)? {
        bench(&options, &mut codecs, &input)?;
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("lz4-bench: {error}");
            ExitCode::FAILURE
        }
    }
}
