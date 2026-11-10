//! `--libdeflate`: times `hivepack::deflate::Compressor`, the port of
//! libdeflate's compressor, against libdeflate 1.26 itself, and against the
//! zlib port at the nearest zlib level, on the same inputs.
//!
//! libdeflate is reached through `tools/libdeflate-oracle`, which
//! `scripts/testdata.py fetch --set libdeflate-oracle` builds with the
//! flags of libdeflate's own release build: its `time` request compresses a
//! file in the oracle's process and says how long the call took. The port
//! and zlib's are timed in this process the same way, one call with room
//! for the whole stream. Rounds take turns, and each speed is the best
//! round's. The port's streams must be libdeflate's, byte for byte.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Instant;

use hivepack::deflate::{Compressor, Deflate, Flush, InBuffer, OutBuffer, Status};

use crate::{Options, Result, inputs};

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
        let program = cache.join("libdeflate-oracle/oracle");
        let mut child = Command::new(&program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| {
                format!(
                    "{}: {e} (python3 scripts/testdata.py fetch --set libdeflate-oracle)",
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

    /// libdeflate's stream size, its hash and the seconds one call took.
    fn time(&mut self, level: u32, path: &Path) -> Result<(usize, u64, f64)> {
        let path = path.canonicalize().map_err(|e| e.to_string())?;
        writeln!(self.input, "time {level} 1 {}", path.display()).map_err(|e| e.to_string())?;
        self.input.flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        self.output
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        let words: Vec<&str> = line.split_whitespace().collect();
        let [size, hash, ns] = words[..] else {
            return Err(format!("the oracle answered {line:?}"));
        };
        let size = size.parse().map_err(|_| "bad size")?;
        let hash = u64::from_str_radix(hash, 16).map_err(|_| "bad hash")?;
        let ns: f64 = ns.parse().map_err(|_| "bad time")?;
        Ok((size, hash, ns / 1e9))
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

/// The zlib port's raw deflate stream size at `level`, and the seconds it
/// took.
fn zlib_port(compressor: &mut Deflate, data: &[u8], out: &mut [u8]) -> Result<(usize, f64)> {
    compressor.reset();
    let start = Instant::now();
    let mut output = OutBuffer::new(out);
    let status = compressor.deflate(&mut output, &mut InBuffer::new(data), Flush::Finish);
    let seconds = start.elapsed().as_secs_f64();
    match status {
        Ok(Status::StreamEnd) => Ok((output.pos, seconds)),
        other => Err(format!("the zlib port: {other:?}")),
    }
}

pub fn run(options: &Options) -> Result<()> {
    let mut oracle = Oracle::spawn()?;
    println!("Compression, one call, MB/s (sizes in bytes):\n");
    println!(
        "| input | MB | level | libdeflate 1.26 | port | port/libdeflate | size | zlib port (level) | its size |"
    );
    println!("|---|---|---|---|---|---|---|---|---|");
    for input in inputs(&options.paths)? {
        let data = std::fs::read(&input).map_err(|e| format!("{}: {e}", input.display()))?;
        let name = input.file_name().map_or_else(
            || input.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        let megabytes = data.len() as f64 / 1e6;
        for &level in &options.levels {
            let mut port = Compressor::new(level as i32).ok_or(format!("bad level {level}"))?;
            let zlib_level = level.min(9);
            let mut zlib = Deflate::new(zlib_level as i32, -15, 8, 0).map_err(|e| e.to_string())?;
            let mut out = vec![0u8; port.deflate_compress_bound(data.len())];
            let mut zlib_out = vec![0u8; data.len() + data.len() / 1000 + 1024];
            let (mut best_c, mut best_port, mut best_zlib) = (f64::MAX, f64::MAX, f64::MAX);
            let (mut size, mut zlib_size) = (0, 0);
            for _ in 0..options.rounds {
                let (c_size, c_hash, c_seconds) = oracle.time(level, &input)?;
                best_c = best_c.min(c_seconds);

                let start = Instant::now();
                size = port.deflate_compress(&data, &mut out);
                best_port = best_port.min(start.elapsed().as_secs_f64());
                if size != c_size || fnv64(&out[..size]) != c_hash {
                    return Err(format!("{name} level {level}: not libdeflate's stream"));
                }

                let (z_size, z_seconds) = zlib_port(&mut zlib, &data, &mut zlib_out)?;
                zlib_size = z_size;
                best_zlib = best_zlib.min(z_seconds);
            }
            println!(
                "| {name} | {megabytes:.1} | {level} | {:.1} | {:.1} | {:.2}× | {size} | {:.1} ({zlib_level}) | {zlib_size} |",
                megabytes / best_c,
                megabytes / best_port,
                best_c / best_port,
                megabytes / best_zlib,
            );
        }
    }
    Ok(())
}
