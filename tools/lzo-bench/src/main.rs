//! Times hivepack::lzo against liblzo2 2.10's `lzo1x_decompress_safe` and
//! lzokay's decompressor, the code it ports, on the same blocks.
//!
//! ```text
//! cargo run --release -p lzo-bench -- [--methods 1,999] [--block 131072] [--rounds 5] PATH...
//! ```
//!
//! Each file is compressed in blocks of `--block` bytes (SquashFS's default,
//! 128 KiB, unless told; 0 for one block), as SquashFS compresses a file's
//! blocks, by each of liblzo2's compressors `--methods` names (`1` for
//! `lzo1x_1`, `999` for `lzo1x_999`, and the others `tools/lzo-oracle`
//! knows). Each round then decodes every block into exactly its length,
//! once with liblzo2 and lzokay, in the oracle's process, and once with the
//! port, here; the port's output must be the file. A round decodes a
//! file as many times as make 50 MB, and keeps the fastest.
//!
//! liblzo2 and lzokay are reached through `tools/lzo-oracle`, which
//! `scripts/testdata.py fetch --set lzo-oracle` builds with `-O2`, as
//! liblzo2's own build does: its `time` request decodes a file of blocks
//! and says how long each took.
//!
//! Each PATH is a file, or a folder whose files are each an input. Rounds
//! take turns between the implementations, so a noisy machine slows them
//! alike. Speeds are the best round's, in MB/s of decompressed data (10^6
//! bytes per second), and the output is a Markdown table.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitCode, Stdio};
use std::time::Instant;

type Result<T> = std::result::Result<T, String>;

/// The oracle, running.
struct Oracle {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Oracle {
    fn spawn() -> Result<Oracle> {
        let cache = std::env::var_os("HIVEPACK_TESTDATA").map_or_else(
            || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/testdata"),
            PathBuf::from,
        );
        let program = cache.join("lzo-oracle/oracle");
        let mut child = Command::new(&program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| {
                format!(
                    "{}: {e} (python3 scripts/testdata.py fetch --set lzo-oracle)",
                    program.display()
                )
            })?;
        let input = child.stdin.take().ok_or("the oracle's stdin")?;
        let output = BufReader::new(child.stdout.take().ok_or("the oracle's stdout")?);
        Ok(Oracle {
            child,
            input,
            output,
        })
    }

    fn ask(&mut self, request: &str) -> Result<Vec<String>> {
        writeln!(self.input, "{request}").map_err(|e| e.to_string())?;
        self.input.flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        self.output
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        if line.trim() == "bad" || line.is_empty() {
            return Err(format!("the oracle answered {line:?} to {request}"));
        }
        Ok(line.split_whitespace().map(str::to_string).collect())
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn fnv64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

struct Options {
    methods: Vec<String>,
    block: usize,
    rounds: u32,
    paths: Vec<PathBuf>,
}

fn options() -> Result<Options> {
    let mut options = Options {
        methods: vec!["1".into(), "999".into()],
        block: 131_072,
        rounds: 5,
        paths: Vec::new(),
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "--methods" => {
                options.methods = value("--methods")?.split(',').map(str::to_string).collect();
            }
            "--block" => {
                options.block = value("--block")?.parse().map_err(|_| "bad --block")?;
            }
            "--rounds" => {
                options.rounds = value("--rounds")?.parse().map_err(|_| "bad --rounds")?;
            }
            "-h" | "--help" => {
                return Err(
                    "usage: lzo-bench [--methods 1,999] [--block 131072] [--rounds 5] PATH..."
                        .into(),
                );
            }
            _ => options.paths.push(PathBuf::from(arg)),
        }
    }
    if options.paths.is_empty() {
        return Err("no input: name files or folders, such as target/testdata/silesia".into());
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

/// The blocks of a file the oracle's `compressfile` wrote: each one's
/// compressed bytes and length.
fn blocks(path: &Path) -> Result<Vec<(Vec<u8>, usize)>> {
    let file = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut blocks = Vec::new();
    let mut at = 0;
    let word = |at: usize| -> Result<usize> {
        let bytes = file.get(at..at + 4).ok_or("a file of blocks cut short")?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
    };
    while at < file.len() {
        let (compressed, len) = (word(at)?, word(at + 4)?);
        let block = file
            .get(at + 8..at + 8 + compressed)
            .ok_or("a file of blocks cut short")?;
        blocks.push((block.to_vec(), len));
        at += 8 + compressed;
    }
    Ok(blocks)
}

fn run(options: &Options) -> Result<()> {
    let mut oracle = Oracle::spawn()?;
    let scratch = std::env::temp_dir().join(format!("lzo-bench-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).map_err(|e| e.to_string())?;
    println!(
        "Decompression of blocks of {} bytes, MB/s, best of {} rounds:\n",
        options.block, options.rounds
    );
    println!(
        "| input | MB | compressor | ratio | liblzo2 2.10 | lzokay | port | port/liblzo2 | port/lzokay |"
    );
    println!("|---|---|---|---|---|---|---|---|---|");
    for input in inputs(&options.paths)? {
        let data = std::fs::read(&input).map_err(|e| format!("{}: {e}", input.display()))?;
        let name = input.file_name().map_or_else(
            || input.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        let megabytes = data.len() as f64 / 1e6;
        let input = input.canonicalize().map_err(|e| e.to_string())?;
        for method in &options.methods {
            let path = scratch.join(format!("{name}.{method}"));
            let answer = oracle.ask(&format!(
                "compressfile {method} {} {} {}",
                options.block,
                input.display(),
                path.display()
            ))?;
            let compressed: f64 = answer[1].parse().map_err(|_| "bad size")?;
            let blocks = blocks(&path)?;
            let mut out = vec![0u8; data.len()];
            let (mut best_c, mut best_k, mut best_port) = (f64::MAX, f64::MAX, f64::MAX);
            // Each round decodes the file as many times as make 50 MB, and
            // keeps the fastest, so that a small file is timed over more
            // than a few hundred microseconds.
            let times = (50_000_000 / data.len().max(1)).max(1);
            for round in 0..options.rounds {
                let answer = oracle.ask(&format!("time {times} {}", path.display()))?;
                let hash = u64::from_str_radix(&answer[0], 16).map_err(|_| "bad hash")?;
                if round == 0 && hash != fnv64(&data) {
                    return Err(format!("{name}: liblzo2 does not decode its blocks"));
                }
                let ns = |word: &str| word.parse::<f64>().map_err(|_| "bad time".to_string());
                best_c = best_c.min(ns(&answer[1])? / 1e9);
                best_k = best_k.min(ns(&answer[2])? / 1e9);

                for _ in 0..times {
                    let start = Instant::now();
                    let mut written = 0;
                    for (block, len) in &blocks {
                        let out = &mut out[written..written + len];
                        if hivepack::lzo::decompress(block, out) != Ok(*len) {
                            return Err(format!("{name}: the port does not decode a block"));
                        }
                        written += len;
                    }
                    best_port = best_port.min(start.elapsed().as_secs_f64());
                }
                // Once: comparing reads both through the caches, which the
                // oracle's rounds do not.
                if round == 0 && out != data {
                    return Err(format!("{name}: the port's output is not the file"));
                }
            }
            let _ = std::fs::remove_file(&path);
            println!(
                "| {name} | {megabytes:.1} | lzo1x_{method} | {:.2} | {:.0} | {:.0} | {:.0} | {:.2}× | {:.2}× |",
                compressed / data.len().max(1) as f64,
                megabytes / best_c,
                megabytes / best_k,
                megabytes / best_port,
                best_c / best_port,
                best_k / best_port,
            );
        }
    }
    let _ = std::fs::remove_dir(&scratch);
    Ok(())
}

fn main() -> ExitCode {
    match options().and_then(|options| run(&options)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("lzo-bench: {e}");
            ExitCode::FAILURE
        }
    }
}
