//! Times hivepack::bzip2 against libbzip2 on the same inputs: decompressing
//! the streams libbzip2 wrote at each block size, fast or, with `--small`,
//! small, or, with `--compress`, compressing at each block size. The
//! compressed streams must be the same, byte for byte.
//!
//! ```text
//! cargo run --release -p bzip2-bench -- [--levels 1,9] [--rounds 3] [--seconds 1] [--small | --compress | --threads N] PATH...
//! ```
//!
//! With `--threads N`, the streams one after the other of
//! `hivepack::bzip2::CompressMt` instead: compressed with one thread and
//! with N (`0` for as many as the machine has), which must give the same
//! file, then read through `hivepack::open::Opener` with one thread and
//! with N; and libbzip2's one stream read with N too, which has nothing to
//! share. Each is timed once a round, as packwing runs them: a megabyte
//! of input and output at a time.
//!
//! Each run is one call, with all the input and room for all the output,
//! on a new stream, as `BZ2_bzBuffToBuffCompress` and
//! `BZ2_bzBuffToBuffDecompress` do.
//!
//! Each PATH is a file, or a folder whose files are each an input. Rounds
//! take turns between the implementations, so a noisy machine slows them
//! alike. Speeds are the range over rounds in MB/s of uncompressed data
//! (10^6 bytes per second), and the output is a Markdown table.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Decompress,
    Small,
    Compress,
    Threads(u32),
}

trait Codec {
    fn name(&self) -> String;
    /// Decompresses `input`, whose content is `size` bytes long.
    fn decompress(
        &mut self,
        input: &[u8],
        size: usize,
        small: bool,
        output: &mut Vec<u8>,
    ) -> Result<()>;
    /// Compresses `input` with blocks of `level` × 100,000 bytes.
    fn compress(&mut self, level: u32, input: &[u8], output: &mut Vec<u8>) -> Result<()>;
}

/// Room for the compressed form of `len` bytes, as bzip2's manual gives
/// it: 1% more, and 600 bytes.
fn bound(len: usize) -> usize {
    len + len / 100 + 601
}

/// libbzip2 1.0.8 through the bzip2 crate.
struct Libbzip2;

impl Codec for Libbzip2 {
    fn name(&self) -> String {
        "libbzip2 1.0.8".into()
    }

    fn decompress(
        &mut self,
        input: &[u8],
        size: usize,
        small: bool,
        output: &mut Vec<u8>,
    ) -> Result<()> {
        let mut stream = bzip2::Decompress::new(small);
        output.clear();
        output.resize(size, 0);
        match stream.decompress(input, output) {
            Ok(bzip2::Status::StreamEnd) => Ok(()),
            other => Err(format!("libbzip2: {other:?}")),
        }
    }

    fn compress(&mut self, level: u32, input: &[u8], output: &mut Vec<u8>) -> Result<()> {
        let mut stream = bzip2::Compress::new(bzip2::Compression::new(level), 0);
        output.clear();
        output.resize(bound(input.len()), 0);
        match stream.compress(input, output, bzip2::Action::Finish) {
            Ok(bzip2::Status::StreamEnd) => {
                output.truncate(stream.total_out() as usize);
                Ok(())
            }
            other => Err(format!("libbzip2: {other:?}")),
        }
    }
}

/// hivepack::bzip2.
struct Port;

impl Codec for Port {
    fn name(&self) -> String {
        "hivepack-bzip2".into()
    }

    fn decompress(
        &mut self,
        input: &[u8],
        size: usize,
        small: bool,
        output: &mut Vec<u8>,
    ) -> Result<()> {
        output.clear();
        output.resize(size, 0);
        match hivepack::bzip2::buff_to_buff_decompress(output, input, small) {
            Ok(len) if len == size => Ok(()),
            other => Err(format!("port: {other:?}")),
        }
    }

    fn compress(&mut self, level: u32, input: &[u8], output: &mut Vec<u8>) -> Result<()> {
        output.clear();
        output.resize(bound(input.len()), 0);
        let len = hivepack::bzip2::buff_to_buff_compress(output, input, level as i32, 0)
            .map_err(|e| format!("port: {e}"))?;
        output.truncate(len);
        Ok(())
    }
}

struct Options {
    levels: Vec<u32>,
    rounds: u32,
    budget: Duration,
    mode: Mode,
    paths: Vec<PathBuf>,
}

fn options(args: impl Iterator<Item = String>) -> Result<Options> {
    let mut options = Options {
        levels: vec![1, 9],
        rounds: 3,
        budget: Duration::from_secs(1),
        mode: Mode::Decompress,
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
                        Ok(level @ 1..=9) => Ok(level),
                        _ => Err(format!("bad level {l:?}")),
                    })
                    .collect::<Result<_>>()?;
            }
            "--small" => options.mode = Mode::Small,
            "--compress" => options.mode = Mode::Compress,
            "--threads" => {
                options.mode = Mode::Threads(value()?.parse().map_err(|_| "bad --threads")?);
            }
            "--rounds" => options.rounds = value()?.parse().map_err(|_| "bad --rounds")?,
            "--seconds" => {
                let seconds: f64 = value()?.parse().map_err(|_| "bad --seconds")?;
                options.budget =
                    Duration::try_from_secs_f64(seconds).map_err(|_| "bad --seconds")?;
            }
            "-h" | "--help" => {
                return Err(
                    "usage: bzip2-bench [--levels 1,9] [--rounds N] [--seconds S] [--small | --compress | --threads N] PATH..."
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
            write!(f, "{:.1}", self.0)
        } else {
            write!(f, "{:.1}–{:.1}", self.0, self.1)
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
        let mut compressed = Vec::new();
        Libbzip2.compress(level, &data, &mut compressed)?;
        let ratio = data.len() as f64 / compressed.len().max(1) as f64;
        let mut speeds: Vec<Option<Range>> = codecs.iter().map(|_| None).collect();
        for _ in 0..options.rounds {
            for (i, codec) in codecs.iter_mut().enumerate() {
                let seconds = match options.mode {
                    Mode::Compress => {
                        let seconds = time(options.budget, || {
                            codec.compress(level, &data, &mut scratch)
                        })?;
                        if scratch != compressed {
                            return Err(format!(
                                "{}: {name} level {level} is not libbzip2's stream",
                                codec.name()
                            ));
                        }
                        seconds
                    }
                    mode => {
                        let small = mode == Mode::Small;
                        let seconds = time(options.budget, || {
                            codec.decompress(&compressed, data.len(), small, &mut scratch)
                        })?;
                        if scratch != data {
                            return Err(format!(
                                "{}: {name} level {level} does not round trip",
                                codec.name()
                            ));
                        }
                        seconds
                    }
                };
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
        println!(
            "| {name} | {megabytes:.1} | {level} | {ratio:.2} | {} | {:.2}× |",
            cells.join(" | "),
            best[1] / best[0]
        );
    }
    Ok(())
}

/// `input` through `hivepack::bzip2::CompressMt`, a megabyte at a time.
fn compress_mt(level: u32, threads: hivepack::Threads, input: &[u8]) -> Result<Vec<u8>> {
    use hivepack::bzip2::{Action, CompressMt, InBuffer, OutBuffer, Status};
    let mut stream =
        CompressMt::new(level as i32, 0, threads).map_err(|e| format!("CompressMt: {e}"))?;
    let mut file = Vec::new();
    let mut room = vec![0; 1 << 20];
    let mut chunks = input.chunks(1 << 20).peekable();
    loop {
        let chunk = chunks.next().unwrap_or(&[]);
        let action = if chunks.peek().is_none() {
            Action::Finish
        } else {
            Action::Run
        };
        let mut src = InBuffer::new(chunk);
        loop {
            let mut dst = OutBuffer::new(&mut room);
            let status = stream
                .compress(&mut dst, &mut src, action)
                .map_err(|e| format!("CompressMt: {e}"))?;
            let made = dst.pos;
            file.extend_from_slice(&room[..made]);
            match status {
                Status::StreamEnd => return Ok(file),
                Status::RunOk if src.pos == src.src.len() => break,
                _ => {}
            }
        }
    }
}

/// `file` read through `hivepack::open::Opener` with `threads`.
fn open_with(threads: hivepack::Threads, file: &[u8], output: &mut Vec<u8>) -> Result<()> {
    use std::io::Read;
    let mut opener =
        hivepack::open::Opener::new(|| Ok(std::io::Cursor::new(file))).threads(threads);
    let mut opened = opener.open().map_err(|e| format!("open: {e}"))?;
    output.clear();
    opened
        .read_to_end(output)
        .map_err(|e| format!("open: {e}"))?;
    Ok(())
}

/// Seconds `op` takes, once.
fn once(op: impl FnOnce() -> Result<()>) -> Result<f64> {
    let start = Instant::now();
    op()?;
    Ok(start.elapsed().as_secs_f64())
}

fn bench_threads(options: &Options, threads: u32, input: &Path) -> Result<()> {
    let many = hivepack::Threads::of(threads);
    let one = hivepack::Threads::One;
    let data = std::fs::read(input).map_err(|e| format!("{}: {e}", input.display()))?;
    let name = input.file_name().map_or_else(
        || input.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let megabytes = data.len() as f64 / 1e6;
    for &level in &options.levels {
        let mut single = Vec::new();
        Libbzip2.compress(level, &data, &mut single)?;
        let mut file = Vec::new();
        let mut speeds: [Option<Range>; 5] = Default::default();
        let mut scratch = Vec::new();
        for _ in 0..options.rounds {
            let mut timed = [0.0; 5];
            timed[0] = once(|| {
                file = compress_mt(level, one, &data)?;
                Ok(())
            })?;
            timed[1] = once(|| {
                if compress_mt(level, many, &data)? != file {
                    return Err(format!("{name} level {level}: not the same with threads"));
                }
                Ok(())
            })?;
            for (i, (threads, file)) in [(one, &file), (many, &file), (many, &single)]
                .into_iter()
                .enumerate()
            {
                timed[2 + i] = once(|| open_with(threads, file, &mut scratch))?;
                if scratch != data {
                    return Err(format!("{name} level {level}: does not round trip"));
                }
            }
            for (speed, seconds) in speeds.iter_mut().zip(timed) {
                *speed = Range::add(speed.take(), megabytes / seconds);
            }
        }
        let ratio = data.len() as f64 / file.len().max(1) as f64;
        let single_ratio = data.len() as f64 / single.len().max(1) as f64;
        let cells: Vec<String> = speeds
            .iter()
            .map(|r| r.as_ref().map_or_else(String::new, Range::to_string))
            .collect();
        println!(
            "| {name} | {megabytes:.1} | {level} | {ratio:.3} ({single_ratio:.3}) | {} |",
            cells.join(" | ")
        );
    }
    Ok(())
}

fn run() -> Result<()> {
    let options = options(std::env::args().skip(1))?;
    if let Mode::Threads(threads) = options.mode {
        let many = hivepack::Threads::of(threads).count();
        println!("Streams one after the other, MB/s, with 1 thread and {many}:\n");
        println!(
            "| input | MB | level | ratio (one stream's) | compress, 1 | compress, {many} | decompress, 1 | decompress, {many} | one stream, {many} |"
        );
        println!("|---|---|---|---|---|---|---|---|---|");
        for input in inputs(&options.paths)? {
            bench_threads(&options, threads, &input)?;
        }
        return Ok(());
    }
    let mut codecs: Vec<Box<dyn Codec>> = vec![Box::new(Libbzip2), Box::new(Port)];
    let header: Vec<String> = codecs.iter().map(|c| c.name()).collect();
    let mode = match options.mode {
        Mode::Decompress => "Decompression",
        Mode::Small => "Decompression, small",
        Mode::Compress | Mode::Threads(_) => "Compression",
    };
    println!("{mode}, MB/s:\n");
    println!(
        "| input | MB | level | ratio | {} | port/libbzip2 |",
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
            eprintln!("bzip2-bench: {error}");
            ExitCode::FAILURE
        }
    }
}
