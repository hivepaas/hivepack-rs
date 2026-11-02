//! Times zstd implementations on the same inputs: compression at each level,
//! and decompression of what libzstd wrote.
//!
//! ```text
//! cargo run --release -p zstd-bench -- [--levels 1,3,19] [--rounds 3] [--seconds 0.5] [--stream] [--workers 1,2,4,8] [--target-cblock-size N] PATH...
//! ```
//!
//! With `--target-cblock-size`, compression cuts blocks to about that size
//! compressed (`ZSTD_c_targetCBlockSize`), on both sides; in one call, it
//! then goes through `ZSTD_compress2`, as `ZSTD_compressCCtx` leaves the
//! parameter out.
//!
//! With `--workers`, only compression, through `ZSTD_compress2` with
//! `ZSTD_c_nbWorkers` at each count given: a row per count, and the ratio of
//! the speeds. The frames must be the same.
//!
//! With `--stream`, compression goes through `ZSTD_compressStream2`, in
//! pieces of `ZSTD_CStreamInSize` and `ZSTD_CStreamOutSize`, the size not
//! pledged, and decompression through `ZSTD_decompressStream`, in pieces of
//! `ZSTD_DStreamInSize` and `ZSTD_DStreamOutSize`, as the zstd command line
//! reads and writes, each piece of output then appended to the result.
//!
//! Each PATH is a file, or a folder whose files are each an input. Rounds take
//! turns between implementations, so a noisy machine slows them all alike.
//! Speeds are the range over rounds in MB/s of uncompressed data (10^6 bytes
//! per second), and the output is a Markdown table.
//!

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use zstd::zstd_safe::{self, CCtx, DCtx};

type Result<T> = std::result::Result<T, String>;

trait Codec {
    fn name(&self) -> String;
    /// Whether [`Codec::compress`] works at `level` yet.
    fn compresses(&self, _level: i32) -> bool {
        true
    }
    fn compress(&mut self, level: i32, input: &[u8], output: &mut Vec<u8>) -> Result<()>;
    /// The same by streaming, one piece at a time.
    fn compress_stream(&mut self, level: i32, input: &[u8], output: &mut Vec<u8>) -> Result<()>;
    /// The same through `ZSTD_compress2`, with `workers` threads.
    fn compress_workers(
        &mut self,
        level: i32,
        workers: u32,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<()>;
    /// Decompresses `input`, whose content is `size` bytes long.
    fn decompress(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()>;
    /// The same by streaming, one piece at a time.
    fn decompress_stream(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()>;
}

/// libzstd through the `zstd` crate, reusing one context of each kind as
/// `zstd -b` does.
struct Libzstd {
    compressor: CCtx<'static>,
    /// `ZSTD_c_targetCBlockSize`, 0 for none.
    target_cblock_size: u32,
    decompressor: DCtx<'static>,
    /// A piece of streamed output, decompressed and compressed.
    piece: Vec<u8>,
    compressed_piece: Vec<u8>,
}

fn error_name(code: usize) -> String {
    zstd_safe::get_error_name(code).to_string()
}

impl Codec for Libzstd {
    fn name(&self) -> String {
        // zstd-sys assembles libzstd's Huffman decoding loop only for x86-64
        // outside Windows; everywhere else libzstd runs its C loop.
        let asm = cfg!(all(target_arch = "x86_64", not(windows)));
        format!(
            "libzstd {}{}",
            zstd_safe::version_string(),
            if asm { "" } else { " (no asm)" }
        )
    }

    fn compress(&mut self, level: i32, input: &[u8], output: &mut Vec<u8>) -> Result<()> {
        output.clear();
        output.reserve(zstd_safe::compress_bound(input.len()));
        if self.target_cblock_size != 0 {
            // ZSTD_compressCCtx would leave the target out.
            for parameter in [
                zstd_safe::CParameter::CompressionLevel(level),
                zstd_safe::CParameter::TargetCBlockSize(self.target_cblock_size),
            ] {
                self.compressor
                    .set_parameter(parameter)
                    .map_err(error_name)?;
            }
            return self
                .compressor
                .compress2(output, input)
                .map(drop)
                .map_err(error_name);
        }
        self.compressor
            .compress(output, input, level)
            .map(drop)
            .map_err(error_name)
    }

    fn compress_stream(&mut self, level: i32, input: &[u8], output: &mut Vec<u8>) -> Result<()> {
        use zstd_safe::zstd_sys::ZSTD_EndDirective;
        output.clear();
        self.compressor
            .reset(zstd_safe::ResetDirective::SessionOnly)
            .map_err(error_name)?;
        for parameter in [
            zstd_safe::CParameter::CompressionLevel(level),
            zstd_safe::CParameter::TargetCBlockSize(self.target_cblock_size),
        ] {
            self.compressor
                .set_parameter(parameter)
                .map_err(error_name)?;
        }
        let mut in_pos = 0;
        loop {
            let in_end = input.len().min(in_pos + CCtx::in_size());
            let directive = if in_end == input.len() {
                ZSTD_EndDirective::ZSTD_e_end
            } else {
                ZSTD_EndDirective::ZSTD_e_continue
            };
            let (remaining, written) = {
                let mut src = zstd_safe::InBuffer::around(&input[..in_end]);
                src.set_pos(in_pos);
                let mut dst = zstd_safe::OutBuffer::around(&mut self.compressed_piece[..]);
                let remaining = self
                    .compressor
                    .compress_stream2(&mut dst, &mut src, directive)
                    .map_err(error_name)?;
                in_pos = src.pos();
                (remaining, dst.pos())
            };
            output.extend_from_slice(&self.compressed_piece[..written]);
            if directive == ZSTD_EndDirective::ZSTD_e_end && remaining == 0 {
                return Ok(());
            }
        }
    }

    fn compress_workers(
        &mut self,
        level: i32,
        workers: u32,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<()> {
        use zstd_safe::CParameter;
        output.clear();
        output.reserve(zstd_safe::compress_bound(input.len()));
        for parameter in [
            CParameter::CompressionLevel(level),
            CParameter::NbWorkers(workers),
            CParameter::TargetCBlockSize(self.target_cblock_size),
        ] {
            self.compressor
                .set_parameter(parameter)
                .map_err(error_name)?;
        }
        self.compressor
            .compress2(output, input)
            .map(drop)
            .map_err(error_name)
    }

    fn decompress(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()> {
        output.clear();
        output.reserve(size);
        self.decompressor
            .decompress(output, input)
            .map(drop)
            .map_err(error_name)
    }

    fn decompress_stream(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()> {
        output.clear();
        output.reserve(size);
        let mut in_pos = 0;
        loop {
            let in_end = input.len().min(in_pos + DCtx::in_size());
            let (hint, written) = {
                let mut src = zstd_safe::InBuffer::around(&input[..in_end]);
                src.set_pos(in_pos);
                let mut dst = zstd_safe::OutBuffer::around(&mut self.piece[..]);
                let hint = self
                    .decompressor
                    .decompress_stream(&mut dst, &mut src)
                    .map_err(error_name)?;
                in_pos = src.pos();
                (hint, dst.pos())
            };
            output.extend_from_slice(&self.piece[..written]);
            if hint == 0 && in_pos == input.len() {
                return Ok(());
            }
            if written == 0 && in_pos == input.len() {
                return Err("the input stops inside a frame".into());
            }
        }
    }
}

/// The port.
struct Hivepack {
    cctx: hivepack::zstd::CCtx,
    /// `ZSTD_c_targetCBlockSize`, 0 for none.
    target_cblock_size: u32,
    dctx: hivepack::zstd::DCtx,
    /// A piece of streamed output, decompressed and compressed.
    piece: Vec<u8>,
    compressed_piece: Vec<u8>,
}

impl Codec for Hivepack {
    fn name(&self) -> String {
        if hivepack::zstd::UNSAFE_FAST {
            "hivepack-zstd (unsafe-fast)".into()
        } else {
            "hivepack-zstd".into()
        }
    }

    fn compress(&mut self, level: i32, input: &[u8], output: &mut Vec<u8>) -> Result<()> {
        use hivepack::zstd::CParameter;
        output.resize(hivepack::zstd::compress_bound(input.len()).unwrap_or(0), 0);
        let size = if self.target_cblock_size != 0 {
            // As libzstd, through compress2.
            for parameter in [
                CParameter::CompressionLevel(level),
                CParameter::TargetCBlockSize(self.target_cblock_size),
            ] {
                self.cctx
                    .set_parameter(parameter)
                    .map_err(|e| e.to_string())?;
            }
            self.cctx.compress2(output, input)
        } else {
            self.cctx.compress(output, input, level)
        }
        .map_err(|e| e.to_string())?;
        output.truncate(size);
        Ok(())
    }

    fn compress_stream(&mut self, level: i32, input: &[u8], output: &mut Vec<u8>) -> Result<()> {
        use hivepack::zstd::{CParameter, EndDirective, ResetDirective};
        output.clear();
        let error = |e: hivepack::zstd::Error| e.to_string();
        self.cctx
            .reset(ResetDirective::SessionOnly)
            .map_err(error)?;
        for parameter in [
            CParameter::CompressionLevel(level),
            CParameter::TargetCBlockSize(self.target_cblock_size),
        ] {
            self.cctx.set_parameter(parameter).map_err(error)?;
        }
        let mut in_pos = 0;
        loop {
            let in_end = input.len().min(in_pos + hivepack::zstd::cstream_in_size());
            let directive = if in_end == input.len() {
                EndDirective::End
            } else {
                EndDirective::Continue
            };
            let mut written = 0;
            let remaining = self
                .cctx
                .compress_stream2_simple_args(
                    &mut self.compressed_piece,
                    &mut written,
                    &input[..in_end],
                    &mut in_pos,
                    directive,
                )
                .map_err(error)?;
            output.extend_from_slice(&self.compressed_piece[..written]);
            if directive == EndDirective::End && remaining == 0 {
                return Ok(());
            }
        }
    }

    fn compress_workers(
        &mut self,
        level: i32,
        workers: u32,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<()> {
        use hivepack::zstd::CParameter;
        output.resize(hivepack::zstd::compress_bound(input.len()).unwrap_or(0), 0);
        for parameter in [
            CParameter::CompressionLevel(level),
            CParameter::NbWorkers(workers),
            CParameter::TargetCBlockSize(self.target_cblock_size),
        ] {
            self.cctx
                .set_parameter(parameter)
                .map_err(|e| e.to_string())?;
        }
        let size = self
            .cctx
            .compress2(output, input)
            .map_err(|e| e.to_string())?;
        output.truncate(size);
        Ok(())
    }

    fn decompress(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()> {
        output.resize(size, 0);
        let decoded = self
            .dctx
            .decompress(output, input)
            .map_err(|e| e.to_string())?;
        output.truncate(decoded);
        Ok(())
    }

    fn decompress_stream(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()> {
        output.clear();
        output.reserve(size);
        let mut in_pos = 0;
        loop {
            let in_end = input.len().min(in_pos + hivepack::zstd::dstream_in_size());
            let mut written = 0;
            let hint = self
                .dctx
                .decompress_stream_simple_args(
                    &mut self.piece,
                    &mut written,
                    &input[..in_end],
                    &mut in_pos,
                )
                .map_err(|e| e.to_string())?;
            output.extend_from_slice(&self.piece[..written]);
            if hint == 0 && in_pos == input.len() {
                return Ok(());
            }
            if written == 0 && in_pos == input.len() {
                return Err("the input stops inside a frame".into());
            }
        }
    }
}

struct Options {
    stream: bool,
    /// With `--workers`: compression only, with these numbers of threads.
    workers: Vec<u32>,
    /// `--target-cblock-size`: `ZSTD_c_targetCBlockSize`, 0 for none.
    target_cblock_size: u32,
    levels: Vec<i32>,
    rounds: usize,
    budget: Duration,
    paths: Vec<PathBuf>,
}

fn parse(args: impl Iterator<Item = String>) -> Result<Options> {
    let mut options = Options {
        stream: false,
        workers: Vec::new(),
        target_cblock_size: 0,
        levels: vec![1, 3, 9, 19],
        rounds: 3,
        budget: Duration::from_millis(500),
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
            "--workers" => {
                options.workers = value()?
                    .split(',')
                    .map(|w| w.parse().map_err(|_| format!("bad worker count {w:?}")))
                    .collect::<Result<_>>()?;
            }
            "--target-cblock-size" => {
                options.target_cblock_size =
                    value()?.parse().map_err(|_| "bad --target-cblock-size")?;
            }
            "--rounds" => options.rounds = value()?.parse().map_err(|_| "bad --rounds")?,
            "--seconds" => {
                let seconds: f64 = value()?.parse().map_err(|_| "bad --seconds")?;
                options.budget =
                    Duration::try_from_secs_f64(seconds).map_err(|_| "bad --seconds")?;
            }
            "-h" | "--help" => {
                return Err(
                    "usage: zstd-bench [--levels 1,3,19] [--rounds N] [--seconds S] [--stream] [--workers 1,2,4,8] [--target-cblock-size N] PATH..."
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
        // A decimal for the slow levels, which run at a few MB/s.
        let digits = if self.1 < 10.0 { 1 } else { 0 };
        let scale = if digits == 1 { 10.0 } else { 1.0 };
        if (self.0 * scale).round() == (self.1 * scale).round() {
            write!(f, "{:.*}", digits, self.0)
        } else {
            write!(f, "{:.*}–{:.*}", digits, self.0, digits, self.1)
        }
    }
}

/// With `--workers`: a row per level and number of threads, compression
/// only, the same frames from every codec.
fn bench_workers(
    options: &Options,
    codecs: &mut [Box<dyn Codec>],
    name: &str,
    data: &[u8],
) -> Result<()> {
    let megabytes = data.len() as f64 / 1e6;
    let mut frames: Vec<Vec<u8>> = codecs.iter().map(|_| Vec::new()).collect();
    for &level in &options.levels {
        for &workers in &options.workers {
            let mut speeds: Vec<Option<Range>> = codecs.iter().map(|_| None).collect();
            for _ in 0..options.rounds {
                for (i, codec) in codecs.iter_mut().enumerate() {
                    let seconds = time(options.budget, || {
                        codec.compress_workers(level, workers, data, &mut frames[i])
                    })?;
                    speeds[i] = Range::add(speeds[i].take(), megabytes / seconds);
                }
            }
            if frames.iter().any(|frame| *frame != frames[0]) {
                return Err(format!(
                    "{name} level {level}, {workers} workers: the frames differ"
                ));
            }
            let ratio = data.len() as f64 / frames[0].len().max(1) as f64;
            let best = |range: &Option<Range>| range.as_ref().map_or(0.0, |r| r.1);
            let cells: Vec<String> = speeds
                .iter()
                .map(|r| {
                    r.as_ref()
                        .map_or_else(|| "–".to_string(), |r| r.to_string())
                })
                .collect();
            println!(
                "| {name} | {megabytes:.1} | {level} | {workers} | {ratio:.3} | {} | {:.2} |",
                cells.join(" | "),
                best(&speeds[1]) / best(&speeds[0]).max(f64::MIN_POSITIVE)
            );
        }
    }
    Ok(())
}

fn bench(options: &Options, codecs: &mut [Box<dyn Codec>], input: &Path) -> Result<()> {
    let data = std::fs::read(input).map_err(|e| format!("{}: {e}", input.display()))?;
    let name = input.file_name().map_or_else(
        || input.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    if !options.workers.is_empty() {
        return bench_workers(options, codecs, &name, &data);
    }
    let megabytes = data.len() as f64 / 1e6;
    let mut compressed = Vec::new();
    let mut scratch = Vec::new();
    for &level in &options.levels {
        // libzstd's output is what every decoder reads.
        codecs[0].compress(level, &data, &mut compressed)?;
        let ratio = data.len() as f64 / compressed.len().max(1) as f64;
        let mut compress: Vec<Option<Range>> = codecs.iter().map(|_| None).collect();
        let mut decompress: Vec<Option<Range>> = codecs.iter().map(|_| None).collect();
        for _ in 0..options.rounds {
            for (i, codec) in codecs.iter_mut().enumerate() {
                if codec.compresses(level) {
                    let seconds = time(options.budget, || {
                        if options.stream {
                            codec.compress_stream(level, &data, &mut scratch)
                        } else {
                            codec.compress(level, &data, &mut scratch)
                        }
                    })?;
                    compress[i] = Range::add(compress[i].take(), megabytes / seconds);
                }
                let seconds = time(options.budget, || {
                    if options.stream {
                        codec.decompress_stream(&compressed, data.len(), &mut scratch)
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
                decompress[i] = Range::add(decompress[i].take(), megabytes / seconds);
            }
        }
        let cells: Vec<String> = compress
            .iter()
            .zip(&decompress)
            .map(|(c, d)| {
                let show = |r: &Option<Range>| {
                    r.as_ref()
                        .map_or_else(|| "–".to_string(), |r| r.to_string())
                };
                format!("{} | {}", show(c), show(d))
            })
            .collect();
        println!(
            "| {name} | {:.1} | {level} | {ratio:.3} | {} |",
            megabytes,
            cells.join(" | ")
        );
    }
    Ok(())
}

fn run() -> Result<()> {
    let options = parse(std::env::args().skip(1))?;
    let mut codecs: Vec<Box<dyn Codec>> = vec![
        Box::new(Libzstd {
            compressor: CCtx::create(),
            target_cblock_size: options.target_cblock_size,
            decompressor: DCtx::create(),
            piece: vec![0; DCtx::out_size()],
            compressed_piece: vec![0; CCtx::out_size()],
        }),
        Box::new(Hivepack {
            cctx: hivepack::zstd::CCtx::new(),
            target_cblock_size: options.target_cblock_size,
            dctx: hivepack::zstd::DCtx::new(),
            piece: vec![0; hivepack::zstd::dstream_out_size()],
            compressed_piece: vec![0; hivepack::zstd::cstream_out_size()],
        }),
    ];
    if !options.workers.is_empty() {
        let header: Vec<String> = codecs
            .iter()
            .map(|c| format!("{} compress2", c.name()))
            .collect();
        println!(
            "| input | MB | level | workers | ratio | {} | ratio of speeds |",
            header.join(" | ")
        );
        println!("|---|---|---|---|---|{}---|", "---|".repeat(codecs.len()));
        for input in inputs(&options.paths)? {
            bench(&options, &mut codecs, &input)?;
        }
        return Ok(());
    }
    let how = if options.stream { " (stream)" } else { "" };
    let header: Vec<String> = codecs
        .iter()
        .map(|c| format!("{0} compress{how} | {0} decompress{how}", c.name()))
        .collect();
    println!("| input | MB | level | ratio | {} |", header.join(" | "));
    println!("|---|---|---|---|{}", "---|".repeat(2 * codecs.len()));
    for input in inputs(&options.paths)? {
        bench(&options, &mut codecs, &input)?;
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("zstd-bench: {error}");
            ExitCode::FAILURE
        }
    }
}
