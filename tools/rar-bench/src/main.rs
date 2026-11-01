//! Times hivepack-rar against UnRAR 7.3.2 on the RAR archives of libarchive's,
//! rarfile's, junrar's and unrar.rs's tests: testing an archive, from its file.
//!
//! ```text
//! python3 scripts/testdata.py fetch --set rar-bench-unrar --set libarchive-rar \
//!     --set rarfile-tests --set junrar-tests --set unrar-rs-tests
//! cargo run --release -p rar-bench -- [--rounds 5] [--seconds 0.5] [--top 12]
//! ```
//!
//! RAR is only ever read here, so these are the archives there are, the biggest
//! about 1 MB. `--top` keeps those that unpack to the most. An archive is left out
//! if either side cannot go through it without a password, or if they disagree
//! on the bytes: that is for `crates/rar/tests/oracle.rs` to look into, and it is
//! said on standard error.
//!
//! UnRAR runs in a program of its own, `tools/rar-oracle/bench.cpp`, on one
//! thread, as the port does. Rounds take turns between the two, and each runs for
//! at least `--seconds`. The output is a Markdown table of the best speeds, and
//! the port's over UnRAR's: above 1 the port is faster.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use hivepack_rar::{Archive, Extract};

type Result<T> = std::result::Result<T, String>;

const SETS: [&str; 4] = [
    "libarchive-rar",
    "rarfile-tests",
    "junrar-tests",
    "unrar-rs-tests",
];

/// UnRAR's program.
struct UnRar {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl UnRar {
    fn spawn(path: &Path) -> Result<UnRar> {
        let mut child = Command::new(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| {
                format!(
                    "{}: {e}: run `python3 scripts/testdata.py fetch --set rar-bench-unrar`",
                    path.display()
                )
            })?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = BufReader::new(child.stdout.take().ok_or("no stdout")?);
        Ok(UnRar {
            child,
            stdin,
            stdout,
        })
    }

    /// How long testing `path` took and the bytes it gave, if it could.
    fn test(&mut self, path: &Path) -> Result<Option<(Duration, u64)>> {
        writeln!(self.stdin, "test {}", path.display()).map_err(|e| e.to_string())?;
        self.stdin.flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        self.stdout
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        let mut words = line.split_whitespace();
        let Some(nanos) = words.next().and_then(|w| w.parse().ok()) else {
            return Ok(None);
        };
        let bytes = words
            .next()
            .and_then(|w| w.parse().ok())
            .ok_or_else(|| format!("UnRAR said {line:?}"))?;
        Ok(Some((Duration::from_nanos(nanos), bytes)))
    }
}

impl Drop for UnRar {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// How long testing `path` took and the bytes it gave, if it could, as UnRAR's
/// interface goes through an archive.
fn port_test(path: &Path) -> Option<(Duration, u64)> {
    let start = Instant::now();
    let file = File::open(path).ok()?;
    let mut arc = Archive::open(file, true).ok()?;
    let mut extract = Extract::new();
    let mut bytes = 0u64;
    loop {
        let size = arc.read_header().ok()?;
        let go = extract
            .current_file(&mut arc, size, &mut |data| {
                bytes += data.len() as u64;
                Ok(())
            })
            .ok()?;
        if extract.missing_password || extract.bad_password || extract.missing_volume {
            return None;
        }
        if !go {
            break;
        }
    }
    Some((start.elapsed(), bytes))
}

/// The files under `dir` that start as a RAR archive does, without the later
/// volumes of split ones.
fn archives(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            archives(&path, found);
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let volume = name.contains(".part") || name.contains("vols") || name.contains("volume");
        let mut start = [0; 4];
        let rar = File::open(&path)
            .and_then(|mut f| f.read_exact(&mut start))
            .is_ok()
            && &start == b"Rar!";
        if rar && !volume {
            found.push(path);
        }
    }
}

/// RAR 5 or older, from the signature.
fn format_of(path: &Path) -> &'static str {
    let mut start = [0; 8];
    let five = File::open(path)
        .and_then(|mut f| f.read_exact(&mut start))
        .is_ok()
        && start[6] == 1;
    if five { "RAR 5" } else { "RAR 1.5 to 4" }
}

struct Options {
    rounds: usize,
    seconds: f64,
    top: usize,
}

fn parse_options() -> Result<Options> {
    let mut options = Options {
        rounds: 5,
        seconds: 0.5,
        top: 12,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg} takes a value"));
        match arg.as_str() {
            "--rounds" => options.rounds = value()?.parse().map_err(|_| "--rounds")?,
            "--seconds" => options.seconds = value()?.parse().map_err(|_| "--seconds")?,
            "--top" => options.top = value()?.parse().map_err(|_| "--top")?,
            _ => return Err(format!("what is {arg}?")),
        }
    }
    Ok(options)
}

/// Runs `one` for at least `seconds`, and gives the best speed, in bytes a second.
fn round(seconds: f64, mut one: impl FnMut() -> Result<(Duration, u64)>) -> Result<f64> {
    let (mut spent, mut total) = (Duration::ZERO, 0u64);
    while spent.as_secs_f64() < seconds {
        let (took, bytes) = one()?;
        spent += took;
        total += bytes;
    }
    Ok(total as f64 / spent.as_secs_f64())
}

fn real_main() -> Result<()> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let options = parse_options()?;
    let testdata = repository.join("target/testdata");
    let mut unrar = UnRar::spawn(&testdata.join("rar-bench-unrar/oracle"))?;

    let mut found = Vec::new();
    for set in SETS {
        archives(&testdata.join(set), &mut found);
    }
    found.sort();

    let mut usable = Vec::new();
    for path in found {
        let port = port_test(&path).map(|(_, bytes)| bytes);
        let reference = unrar.test(&path)?.map(|(_, bytes)| bytes);
        match (port, reference) {
            (Some(a), Some(b)) if a == b && a > 0 => usable.push((a, path)),
            (Some(a), Some(b)) if a != b => {
                eprintln!("{}: the port gave {a} bytes, UnRAR {b}", path.display());
            }
            _ => {}
        }
    }
    usable.sort_by_key(|(bytes, _)| std::cmp::Reverse(*bytes));
    let mut seen = Vec::new();
    usable.retain(|(bytes, path)| {
        let name = path.file_name().map(|n| n.to_os_string());
        let new = !seen.contains(&(*bytes, name.clone()));
        seen.push((*bytes, name));
        new
    });
    usable.truncate(options.top);

    println!("| Archive | hivepack-rar | UnRAR | Port / UnRAR |\n|---|---|---|---|");
    let mut ratios = Vec::new();
    for (bytes, path) in &usable {
        let (mut port_best, mut unrar_best) = (0f64, 0f64);
        for _ in 0..options.rounds {
            let port = round(options.seconds, || {
                port_test(path).ok_or_else(|| format!("{}: failed", path.display()))
            })?;
            let reference = round(options.seconds, || {
                unrar
                    .test(path)?
                    .ok_or_else(|| format!("{}: failed", path.display()))
            })?;
            port_best = port_best.max(port);
            unrar_best = unrar_best.max(reference);
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        println!(
            "| {name}, {}, {:.1} MB | {:.0} MB/s | {:.0} MB/s | {:.2}× |",
            format_of(path),
            *bytes as f64 / 1e6,
            port_best / 1e6,
            unrar_best / 1e6,
            port_best / unrar_best
        );
        ratios.push(port_best / unrar_best);
    }
    if !ratios.is_empty() {
        let mean = ratios.iter().sum::<f64>() / ratios.len() as f64;
        println!("| **Mean of {}** | | | {mean:.2}× |", ratios.len());
    }
    Ok(())
}

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rar-bench: {e}");
            ExitCode::FAILURE
        }
    }
}
