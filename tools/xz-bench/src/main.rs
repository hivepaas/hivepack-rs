//! Times hivepack::xz against liblzma on the same inputs: decoding the .xz
//! Streams liblzma wrote at each preset, with a check, CRC64 unless
//! `--check` says otherwise, or with `--compress`, encoding them. Both must
//! give the input back, and the same Streams.
//!
//! ```text
//! cargo run --release -p xz-bench -- [--presets 0,6,9] [--check none|crc32|crc64|sha256] [--filter FILTER] [--threads N] [--compress] [--rounds 3] [--seconds 1] PATH...
//! ```
//!
//! With `--filter`, the Streams have that filter before LZMA2: `x86`,
//! `powerpc`, `ia64`, `arm`, `armthumb`, `arm64`, `sparc`, `riscv`, or
//! `delta:<distance>`. With `--threads`, the threaded encoders write them,
//! in Blocks of the preset's size, and both must write the same Streams; and
//! without `--compress`, the threaded decoders decode those.
//!
//! Each run is one call, with all the input and room for all the output,
//! on a new .xz decoder or encoder.
//!
//! Each PATH is a file, or a folder whose files are each an input. Rounds
//! take turns between the implementations, so a noisy machine slows them
//! alike. Speeds are the range over rounds in MB/s of uncompressed data
//! (10^6 bytes per second), and the output is a Markdown table.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, String>;

/// A filter before LZMA2.
#[derive(Clone, Copy)]
enum Filter {
    /// A BCJ filter, by its ID.
    Bcj(u64),
    /// Delta, with its distance.
    Delta(u32),
}

impl Filter {
    fn parse(text: &str) -> Result<Filter> {
        if let Some(distance) = text.strip_prefix("delta:") {
            return match distance.parse() {
                Ok(distance @ 1..=256) => Ok(Filter::Delta(distance)),
                _ => Err(format!("bad delta distance {distance:?}")),
            };
        }
        let id = match text {
            "x86" => hivepack::xz::FILTER_X86,
            "powerpc" => hivepack::xz::FILTER_POWERPC,
            "ia64" => hivepack::xz::FILTER_IA64,
            "arm" => hivepack::xz::FILTER_ARM,
            "armthumb" => hivepack::xz::FILTER_ARMTHUMB,
            "arm64" => hivepack::xz::FILTER_ARM64,
            "sparc" => hivepack::xz::FILTER_SPARC,
            "riscv" => hivepack::xz::FILTER_RISCV,
            _ => return Err(format!("bad filter {text:?}")),
        };
        Ok(Filter::Bcj(id))
    }
}

trait Codec {
    fn name(&self) -> String;
    /// Decodes `input`, whose content is `size` bytes long, in `threads`
    /// threads if any.
    fn decompress(
        &mut self,
        threads: Option<u32>,
        input: &[u8],
        size: usize,
        output: &mut Vec<u8>,
    ) -> Result<()>;
    /// Encodes `input` as a .xz Stream at `preset`, with `check`, and
    /// `filter` before LZMA2 if any, in `threads` threads if any.
    fn compress(
        &mut self,
        preset: u32,
        check: liblzma::stream::Check,
        filter: Option<Filter>,
        threads: Option<u32>,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<()>;
}

/// liblzma's number for a check.
fn check_number(check: liblzma::stream::Check) -> u32 {
    match check {
        liblzma::stream::Check::None => 0,
        liblzma::stream::Check::Crc32 => 1,
        liblzma::stream::Check::Crc64 => 4,
        _ => 10,
    }
}

/// liblzma 5.8.4 through the liblzma crate.
struct Liblzma;

impl Liblzma {
    /// The .xz encoder of `xz -<preset>`, with `check`, and `filter` before
    /// LZMA2 if any, in `threads` threads if any.
    fn encoder(
        preset: u32,
        check: liblzma::stream::Check,
        filter: Option<Filter>,
        threads: Option<u32>,
    ) -> Result<liblzma::stream::Stream> {
        if let Some(threads) = threads {
            let mut builder = liblzma::stream::MtStreamBuilder::new();
            builder.threads(threads).preset(preset).check(check);
            if filter.is_some() {
                builder.filters(Liblzma::filters(preset, filter)?);
            }
            return builder.encoder().map_err(|e| format!("liblzma: {e}"));
        }
        if filter.is_none() {
            return liblzma::stream::Stream::new_easy_encoder(preset, check)
                .map_err(|e| format!("liblzma: {e}"));
        }
        liblzma::stream::Stream::new_stream_encoder(&Liblzma::filters(preset, filter)?, check)
            .map_err(|e| format!("liblzma: {e}"))
    }

    /// The chain of `filter`, if any, and LZMA2 at `preset`.
    fn filters(preset: u32, filter: Option<Filter>) -> Result<liblzma::stream::Filters> {
        let mut filters = liblzma::stream::Filters::new();
        match filter {
            None => {}
            Some(Filter::Delta(distance)) => {
                filters
                    .delta_properties(&[(distance - 1) as u8])
                    .map_err(|e| format!("liblzma: {e}"))?;
            }
            Some(Filter::Bcj(hivepack::xz::FILTER_X86)) => {
                filters.x86();
            }
            Some(Filter::Bcj(hivepack::xz::FILTER_POWERPC)) => {
                filters.powerpc();
            }
            Some(Filter::Bcj(hivepack::xz::FILTER_IA64)) => {
                filters.ia64();
            }
            Some(Filter::Bcj(hivepack::xz::FILTER_ARM)) => {
                filters.arm();
            }
            Some(Filter::Bcj(hivepack::xz::FILTER_ARMTHUMB)) => {
                filters.arm_thumb();
            }
            Some(Filter::Bcj(hivepack::xz::FILTER_ARM64)) => {
                filters.arm64();
            }
            Some(Filter::Bcj(hivepack::xz::FILTER_SPARC)) => {
                filters.sparc();
            }
            Some(Filter::Bcj(_)) => {
                filters.riscv();
            }
        }
        let options = liblzma::stream::LzmaOptions::new_preset(preset)
            .map_err(|e| format!("liblzma: {e}"))?;
        filters.lzma2(&options);
        Ok(filters)
    }

    /// `input` as `xz -<preset>` writes it, with `check`, and `filter`
    /// before LZMA2 if any.
    fn compress(
        preset: u32,
        check: liblzma::stream::Check,
        filter: Option<Filter>,
        threads: Option<u32>,
        input: &[u8],
    ) -> Result<Vec<u8>> {
        let mut stream = Liblzma::encoder(preset, check, filter, threads)?;
        let mut output = Vec::with_capacity(input.len() + input.len() / 2 + 4096);
        match stream.process_vec(input, &mut output, liblzma::stream::Action::Finish) {
            Ok(liblzma::stream::Status::StreamEnd) => Ok(output),
            other => Err(format!("liblzma: {other:?}")),
        }
    }
}

impl Codec for Liblzma {
    fn name(&self) -> String {
        "liblzma 5.8.4".into()
    }

    fn compress(
        &mut self,
        preset: u32,
        check: liblzma::stream::Check,
        filter: Option<Filter>,
        threads: Option<u32>,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<()> {
        let mut stream = Liblzma::encoder(preset, check, filter, threads)?;
        output.clear();
        // The threaded encoder's Blocks each have their header.
        output.resize(
            hivepack::xz::stream_buffer_bound(input.len()) + (input.len() >> 10) + 4096,
            0,
        );
        match stream.process(input, output, liblzma::stream::Action::Finish) {
            Ok(liblzma::stream::Status::StreamEnd) => {
                output.truncate(stream.total_out() as usize);
                Ok(())
            }
            other => Err(format!("liblzma: {other:?}")),
        }
    }

    fn decompress(
        &mut self,
        threads: Option<u32>,
        input: &[u8],
        size: usize,
        output: &mut Vec<u8>,
    ) -> Result<()> {
        let mut stream = match threads {
            Some(threads) => liblzma::stream::MtStreamBuilder::new()
                .threads(threads)
                .memlimit_threading(u64::MAX)
                .memlimit_stop(u64::MAX)
                .decoder(),
            None => liblzma::stream::Stream::new_stream_decoder(u64::MAX, 0),
        }
        .map_err(|e| format!("liblzma: {e}"))?;
        output.clear();
        output.resize(size, 0);
        match stream.process(input, output, liblzma::stream::Action::Finish) {
            Ok(liblzma::stream::Status::StreamEnd) if stream.total_out() == size as u64 => Ok(()),
            other => Err(format!("liblzma: {other:?}")),
        }
    }
}

/// hivepack::xz.
struct Port;

impl Codec for Port {
    fn name(&self) -> String {
        "hivepack-xz".into()
    }

    fn compress(
        &mut self,
        preset: u32,
        check: liblzma::stream::Check,
        filter: Option<Filter>,
        threads: Option<u32>,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<()> {
        let check = hivepack::xz::Check(check_number(check));
        let filters = match filter {
            None => None,
            Some(filter) => {
                let lzma2 = hivepack::xz::LzmaOptions::preset(preset).ok_or("port: bad preset")?;
                Some(vec![
                    match filter {
                        Filter::Bcj(id) => hivepack::xz::Filter::bcj(id, 0),
                        Filter::Delta(distance) => hivepack::xz::Filter::delta(distance),
                    },
                    hivepack::xz::Filter::lzma2(lzma2),
                ])
            }
        };
        let mut stream = match (threads, filters) {
            (Some(threads), filters) => {
                hivepack::xz::Stream::stream_encoder_mt(&hivepack::xz::MtOptions {
                    threads,
                    preset,
                    check,
                    filters,
                    ..hivepack::xz::MtOptions::default()
                })
            }
            (None, None) => hivepack::xz::Stream::easy_encoder(preset, check),
            (None, Some(filters)) => hivepack::xz::Stream::stream_encoder(&filters, check),
        }
        .map_err(|e| format!("port: {e}"))?;
        output.clear();
        // The threaded encoder's Blocks each have their header.
        output.resize(
            hivepack::xz::stream_buffer_bound(input.len()) + (input.len() >> 10) + 4096,
            0,
        );
        let mut out = hivepack::xz::OutBuffer::new(output);
        let status = stream.code(
            &mut out,
            &mut hivepack::xz::InBuffer::new(input),
            hivepack::xz::Action::Finish,
        );
        let len = out.pos;
        match status {
            Ok(hivepack::xz::Status::StreamEnd) => {
                output.truncate(len);
                Ok(())
            }
            other => Err(format!("port: {other:?}")),
        }
    }

    fn decompress(
        &mut self,
        threads: Option<u32>,
        input: &[u8],
        size: usize,
        output: &mut Vec<u8>,
    ) -> Result<()> {
        let mut stream = match threads {
            Some(threads) => hivepack::xz::Stream::stream_decoder_mt(&hivepack::xz::MtOptions {
                threads,
                ..hivepack::xz::MtOptions::default()
            }),
            None => hivepack::xz::Stream::stream_decoder(u64::MAX, 0),
        }
        .map_err(|e| format!("port: {e}"))?;
        output.clear();
        output.resize(size, 0);
        let mut out = hivepack::xz::OutBuffer::new(output);
        let status = stream.code(
            &mut out,
            &mut hivepack::xz::InBuffer::new(input),
            hivepack::xz::Action::Finish,
        );
        match status {
            Ok(hivepack::xz::Status::StreamEnd) if out.pos == size => Ok(()),
            other => Err(format!("port: {other:?}")),
        }
    }
}

struct Options {
    compress: bool,
    presets: Vec<u32>,
    check: liblzma::stream::Check,
    filter: Option<Filter>,
    threads: Option<u32>,
    rounds: u32,
    budget: Duration,
    paths: Vec<PathBuf>,
}

fn options(args: impl Iterator<Item = String>) -> Result<Options> {
    let mut options = Options {
        compress: false,
        presets: vec![0, 6, 9],
        check: liblzma::stream::Check::Crc64,
        filter: None,
        threads: None,
        rounds: 3,
        budget: Duration::from_secs(1),
        paths: Vec::new(),
    };
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--presets" => {
                options.presets = value()?
                    .split(',')
                    .map(|p| match p.parse() {
                        Ok(preset @ 0..=9) => Ok(preset),
                        _ => Err(format!("bad preset {p:?}")),
                    })
                    .collect::<Result<_>>()?;
            }
            "--check" => {
                options.check = match value()?.as_str() {
                    "none" => liblzma::stream::Check::None,
                    "crc32" => liblzma::stream::Check::Crc32,
                    "crc64" => liblzma::stream::Check::Crc64,
                    "sha256" => liblzma::stream::Check::Sha256,
                    other => return Err(format!("bad check {other:?}")),
                };
            }
            "--filter" => options.filter = Some(Filter::parse(&value()?)?),
            "--threads" => {
                options.threads = Some(value()?.parse().map_err(|_| "bad --threads")?);
            }
            "--compress" => options.compress = true,
            "--rounds" => options.rounds = value()?.parse().map_err(|_| "bad --rounds")?,
            "--seconds" => {
                let seconds: f64 = value()?.parse().map_err(|_| "bad --seconds")?;
                options.budget =
                    Duration::try_from_secs_f64(seconds).map_err(|_| "bad --seconds")?;
            }
            "-h" | "--help" => {
                return Err(
                    "usage: xz-bench [--presets 0,6,9] [--check none|crc32|crc64|sha256] [--filter FILTER] [--threads N] [--compress] [--rounds N] [--seconds S] PATH..."
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
    for &preset in &options.presets {
        let compressed = Liblzma::compress(
            preset,
            options.check,
            options.filter,
            options.threads,
            &data,
        )?;
        let ratio = data.len() as f64 / compressed.len().max(1) as f64;
        let mut speeds: Vec<Option<Range>> = codecs.iter().map(|_| None).collect();
        for _ in 0..options.rounds {
            for (i, codec) in codecs.iter_mut().enumerate() {
                let seconds = if options.compress {
                    let seconds = time(options.budget, || {
                        codec.compress(
                            preset,
                            options.check,
                            options.filter,
                            options.threads,
                            &data,
                            &mut scratch,
                        )
                    })?;
                    if scratch != compressed {
                        return Err(format!(
                            "{}: {name} preset {preset} is not liblzma's Stream",
                            codec.name()
                        ));
                    }
                    seconds
                } else {
                    let seconds = time(options.budget, || {
                        codec.decompress(options.threads, &compressed, data.len(), &mut scratch)
                    })?;
                    if scratch != data {
                        return Err(format!(
                            "{}: {name} preset {preset} does not round trip",
                            codec.name()
                        ));
                    }
                    seconds
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
            "| {name} | {megabytes:.1} | {preset} | {ratio:.2} | {} | {:.2}× |",
            cells.join(" | "),
            best[1] / best[0]
        );
    }
    Ok(())
}

fn run() -> Result<()> {
    let options = options(std::env::args().skip(1))?;
    let mut codecs: Vec<Box<dyn Codec>> = vec![Box::new(Liblzma), Box::new(Port)];
    let header: Vec<String> = codecs.iter().map(|c| c.name()).collect();
    println!(
        "{}, MB/s:\n",
        if options.compress {
            "Compression"
        } else {
            "Decompression"
        }
    );
    println!(
        "| input | MB | preset | ratio | {} | port/liblzma |",
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
            eprintln!("xz-bench: {error}");
            ExitCode::FAILURE
        }
    }
}
