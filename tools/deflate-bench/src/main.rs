//! Times hivepack::deflate against zlib on the same inputs: decompressing
//! raw deflate streams that zlib wrote at each level, as in a ZIP archive,
//! or, with `--compress`, compressing at each level. The compressed streams
//! must be the same, byte for byte.
//!
//! ```text
//! cargo run --release -p deflate-bench -- [--levels 1,6,9] [--rounds 3] [--seconds 0.5] [--stream | --compress] PATH...
//! ```
//!
//! Compression is one call, with all the input and room for all the
//! output, on a stream made for the level and reset between runs. Without
//! `--stream`, each decompression is one call, with all the input
//! and an output buffer of the right size. With it, the input and output go
//! in pieces of 16 KiB, as zlib's `zpipe.c` example does, each piece of
//! output then appended to the result.
//!
//! Each PATH is a file, or a folder whose files are each an input. Rounds
//! take turns between the implementations, so a noisy machine slows them
//! alike. Speeds are the range over rounds in MB/s of uncompressed data
//! (10^6 bytes per second), and the output is a Markdown table.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};
use hivepack::deflate::{Deflate, Flush, InBuffer, Inflate, OutBuffer, Status};

type Result<T> = std::result::Result<T, String>;

/// The piece size with `--stream`: `CHUNK` in zlib's `zpipe.c`.
const CHUNK: usize = 16384;

trait Codec {
    fn name(&self) -> String;
    /// Decompresses the raw deflate stream `input`, whose content is `size`
    /// bytes long, in one call.
    fn decompress(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()>;
    /// The same in pieces of `CHUNK`.
    fn decompress_stream(&mut self, input: &[u8], output: &mut Vec<u8>) -> Result<()>;
    /// Compresses `input` at `level` as raw deflate, in one call.
    fn compress(&mut self, level: u32, input: &[u8], output: &mut Vec<u8>) -> Result<()>;
}

/// Room for the compressed form of `len` bytes: deflateBound for the
/// default window and memory level.
fn bound(len: usize) -> usize {
    len + (len >> 12) + (len >> 14) + (len >> 25) + 13 - 6
}

/// zlib 1.3.2 through flate2, reusing one stream as zpipe would for many
/// files.
struct Zlib {
    stream: Decompress,
    piece: Vec<u8>,
    compressor: Option<(u32, Compress)>,
}

impl Codec for Zlib {
    fn name(&self) -> String {
        "zlib 1.3.2".into()
    }

    fn decompress(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()> {
        self.stream.reset(false);
        output.clear();
        output.resize(size, 0);
        match self
            .stream
            .decompress(input, output, FlushDecompress::Finish)
        {
            Ok(flate2::Status::StreamEnd) => Ok(()),
            other => Err(format!("zlib: {other:?}")),
        }
    }

    fn decompress_stream(&mut self, input: &[u8], output: &mut Vec<u8>) -> Result<()> {
        self.stream.reset(false);
        output.clear();
        let mut pos = 0;
        loop {
            let end = (pos + CHUNK).min(input.len());
            let (before_in, before_out) = (self.stream.total_in(), self.stream.total_out());
            let status = self
                .stream
                .decompress(&input[pos..end], &mut self.piece, FlushDecompress::None)
                .map_err(|e| format!("zlib: {e}"))?;
            pos += (self.stream.total_in() - before_in) as usize;
            output
                .extend_from_slice(&self.piece[..(self.stream.total_out() - before_out) as usize]);
            if status == flate2::Status::StreamEnd {
                return Ok(());
            }
        }
    }

    fn compress(&mut self, level: u32, input: &[u8], output: &mut Vec<u8>) -> Result<()> {
        let c = match &mut self.compressor {
            Some((l, c)) if *l == level => {
                c.reset();
                c
            }
            slot => {
                let c = Compress::new_with_window_bits(Compression::new(level), false, 15);
                &mut slot.insert((level, c)).1
            }
        };
        output.clear();
        output.resize(bound(input.len()), 0);
        match c.compress(input, output, FlushCompress::Finish) {
            Ok(flate2::Status::StreamEnd) => {
                output.truncate(c.total_out() as usize);
                Ok(())
            }
            other => Err(format!("zlib: {other:?}")),
        }
    }
}

/// The port, used the same way.
struct Port {
    stream: Inflate,
    piece: Vec<u8>,
    compressor: Option<(u32, Deflate)>,
}

impl Codec for Port {
    fn name(&self) -> String {
        "hivepack-deflate".into()
    }

    fn decompress(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()> {
        self.stream.reset();
        output.clear();
        output.resize(size, 0);
        let mut out = OutBuffer::new(output);
        match self
            .stream
            .inflate(&mut out, &mut InBuffer::new(input), Flush::Finish)
        {
            Ok(Status::StreamEnd) => Ok(()),
            other => Err(format!("hivepack-deflate: {other:?}")),
        }
    }

    fn decompress_stream(&mut self, input: &[u8], output: &mut Vec<u8>) -> Result<()> {
        self.stream.reset();
        output.clear();
        let mut pos = 0;
        loop {
            let end = (pos + CHUNK).min(input.len());
            let mut source = InBuffer {
                src: &input[..end],
                pos,
            };
            let mut out = OutBuffer::new(&mut self.piece);
            let status = self
                .stream
                .inflate(&mut out, &mut source, Flush::NoFlush)
                .map_err(|e| format!("hivepack-deflate: {e}"))?;
            pos = source.pos;
            let written = out.pos;
            output.extend_from_slice(&self.piece[..written]);
            if status == Status::StreamEnd {
                return Ok(());
            }
        }
    }

    fn compress(&mut self, level: u32, input: &[u8], output: &mut Vec<u8>) -> Result<()> {
        let c = match &mut self.compressor {
            Some((l, c)) if *l == level => {
                c.reset();
                c
            }
            slot => {
                let c = Deflate::new(level as i32, -15, 8, 0).map_err(|e| e.to_string())?;
                &mut slot.insert((level, c)).1
            }
        };
        output.clear();
        output.resize(bound(input.len()), 0);
        let mut out = OutBuffer::new(output);
        match c.deflate(&mut out, &mut InBuffer::new(input), Flush::Finish) {
            Ok(Status::StreamEnd) => {
                let written = out.pos;
                output.truncate(written);
                Ok(())
            }
            other => Err(format!("hivepack-deflate: {other:?}")),
        }
    }
}

/// `data` as a raw deflate stream from zlib at `level`.
fn compress(level: u32, data: &[u8]) -> Result<Vec<u8>> {
    let mut c = Compress::new_with_window_bits(Compression::new(level), false, 15);
    let mut out = Vec::with_capacity(data.len() + data.len() / 1000 + 64);
    loop {
        let before = c.total_in() as usize;
        match c.compress_vec(&data[before..], &mut out, FlushCompress::Finish) {
            Ok(flate2::Status::StreamEnd) => return Ok(out),
            Ok(_) => out.reserve(out.capacity()),
            Err(e) => return Err(format!("zlib: {e}")),
        }
    }
}

struct Options {
    levels: Vec<u32>,
    rounds: usize,
    budget: Duration,
    stream: bool,
    compress: bool,
    paths: Vec<PathBuf>,
}

fn options(args: impl Iterator<Item = String>) -> Result<Options> {
    let mut options = Options {
        levels: vec![1, 6, 9],
        rounds: 3,
        budget: Duration::from_millis(500),
        stream: false,
        compress: false,
        paths: Vec::new(),
    };
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--levels" => {
                options.levels = value()?
                    .split(',')
                    .map(|l| l.parse().map_err(|_| format!("bad level {l:?}")))
                    .collect::<Result<_>>()?;
            }
            "--stream" => options.stream = true,
            "--compress" => options.compress = true,
            "--rounds" => options.rounds = value()?.parse().map_err(|_| "bad --rounds")?,
            "--seconds" => {
                let seconds: f64 = value()?.parse().map_err(|_| "bad --seconds")?;
                options.budget =
                    Duration::try_from_secs_f64(seconds).map_err(|_| "bad --seconds")?;
            }
            "-h" | "--help" => {
                return Err(
                    "usage: deflate-bench [--levels 1,6,9] [--rounds N] [--seconds S] [--stream | --compress] PATH..."
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

/// Every input file under `paths`, sorted within each folder.
fn inputs(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    for path in paths {
        if path.is_dir() {
            let mut files: Vec<PathBuf> = std::fs::read_dir(path)
                .map_err(|e| format!("{}: {e}", path.display()))?
                .filter_map(|entry| entry.ok().map(|e| e.path()))
                .filter(|p| p.is_file())
                // Hidden files, such as the `.complete` mark of a fetched set.
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

/// Seconds per run of `op`, repeated for at least `budget` after a warm-up.
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
        let compressed = compress(level, &data)?;
        let ratio = data.len() as f64 / compressed.len().max(1) as f64;
        let mut speeds: Vec<Option<Range>> = codecs.iter().map(|_| None).collect();
        let mut streams: Vec<Vec<u8>> = codecs.iter().map(|_| Vec::new()).collect();
        for _ in 0..options.rounds {
            for (i, codec) in codecs.iter_mut().enumerate() {
                if options.compress {
                    let seconds = time(options.budget, || {
                        codec.compress(level, &data, &mut scratch)
                    })?;
                    streams[i] = scratch.clone();
                    if streams[i] != compressed {
                        return Err(format!(
                            "{}: {name} level {level} is not zlib's stream",
                            codec.name()
                        ));
                    }
                    speeds[i] = Range::add(speeds[i].take(), megabytes / seconds);
                    continue;
                }
                let seconds = time(options.budget, || {
                    if options.stream {
                        codec.decompress_stream(&compressed, &mut scratch)
                    } else {
                        codec.decompress(&compressed, data.len(), &mut scratch)
                    }
                })?;
                if scratch != data {
                    return Err(format!(
                        "{}: {name} level {level} does not round trip",
                        codec.name()
                    ));
                }
                speeds[i] = Range::add(speeds[i].take(), megabytes / seconds);
            }
        }
        // The port's speed relative to zlib's, from the best rounds.
        let best: Vec<f64> = speeds
            .iter()
            .map(|r| r.as_ref().map_or(0.0, |r| r.1))
            .collect();
        let cells: Vec<String> = speeds
            .iter()
            .map(|r| r.as_ref().map_or_else(String::new, Range::to_string))
            .collect();
        println!(
            "| {name} | {megabytes:.1} | {level} | {ratio:.2} | {} | {:.2}× |",
            cells.join(" | "),
            best[1] / best[0]
        );
    }
    Ok(())
}

fn run() -> Result<()> {
    let options = options(std::env::args().skip(1))?;
    let mut codecs: Vec<Box<dyn Codec>> = vec![
        Box::new(Zlib {
            stream: Decompress::new(false),
            piece: vec![0; CHUNK],
            compressor: None,
        }),
        Box::new(Port {
            stream: Inflate::new(-15).map_err(|e| e.to_string())?,
            piece: vec![0; CHUNK],
            compressor: None,
        }),
    ];
    let header: Vec<String> = codecs.iter().map(|c| c.name()).collect();
    let mode = if options.compress {
        "Compression, one call"
    } else if options.stream {
        "Decompression, streaming"
    } else {
        "Decompression, one call"
    };
    println!("{mode}, MB/s:\n");
    println!(
        "| input | MB | level | ratio | {} | port/zlib |",
        header.join(" | ")
    );
    println!("|---|---|---|---|{}---|", "---|".repeat(codecs.len()));
    for input in inputs(&options.paths)? {
        bench(&options, &mut codecs, &input)?;
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("deflate-bench: {error}");
            ExitCode::FAILURE
        }
    }
}
