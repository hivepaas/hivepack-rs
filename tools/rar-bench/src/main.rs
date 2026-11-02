//! Times hivepack::rar against UnRAR 7.3.2 on `testdata/rar`: testing an archive,
//! from its file.
//!
//! ```text
//! python3 scripts/testdata.py fetch --set rar-bench-unrar
//! cargo run --release -p rar-bench -- [--rounds 5] [--seconds 0.5] [--only TEXT]
//! ```
//!
//! RAR is never written here: `scripts/make_rar_testdata.py` made those archives
//! with RARLAB's programs, from this repository's files and some bytes of its own.
//! Those with `password` in their name take the password `hivepack`.
//!
//! UnRAR runs in a program of its own, `tools/rar-oracle/bench.cpp`, on one
//! thread, as the port does. Rounds take turns between the two, and each runs for
//! at least `--seconds`. Both must give the same bytes. The output is a Markdown
//! table of the best speeds, and the port's over UnRAR's: above 1 the port is
//! faster.

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use hivepack::rar::{Archive, Extract};

type Result<T> = std::result::Result<T, String>;

/// The password of those archives that have one.
const PASSWORD: &str = "hivepack";

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
        let word = if has_password(path) { "testpw" } else { "test" };
        writeln!(self.stdin, "{word} {}", path.display()).map_err(|e| e.to_string())?;
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
    let mut arc = if has_password(path) {
        Archive::open_with_password(file, true, PASSWORD).ok()?
    } else {
        Archive::open(file, true).ok()?
    };
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

fn has_password(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|n| n.to_string_lossy().contains("password"))
}

struct Options {
    rounds: usize,
    seconds: f64,
    only: Option<String>,
}

fn parse_options() -> Result<Options> {
    let mut options = Options {
        rounds: 5,
        seconds: 0.5,
        only: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg} takes a value"));
        match arg.as_str() {
            "--rounds" => options.rounds = value()?.parse().map_err(|_| "--rounds")?,
            "--seconds" => options.seconds = value()?.parse().map_err(|_| "--seconds")?,
            "--only" => options.only = Some(value()?),
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

    let mut usable = Vec::new();
    let folder = repository.join("testdata/rar");
    let entries = std::fs::read_dir(&folder).map_err(|e| format!("{}: {e}", folder.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        let name = path.to_string_lossy();
        if name.ends_with(".rar") && options.only.as_ref().is_none_or(|o| name.contains(o)) {
            let (_, bytes) =
                port_test(&path).ok_or_else(|| format!("{}: the port failed", path.display()))?;
            usable.push((bytes, path));
        }
    }
    usable.sort_by(|a, b| a.1.cmp(&b.1));

    println!("| Archive | hivepack-rar | UnRAR | Port / UnRAR |\n|---|---|---|---|");
    let mut ratios = Vec::new();
    for (bytes, path) in &usable {
        let (mut port_best, mut unrar_best) = (0f64, 0f64);
        for _ in 0..options.rounds {
            let port = round(options.seconds, || {
                port_test(path).ok_or_else(|| format!("{}: failed", path.display()))
            })?;
            let reference = round(options.seconds, || {
                let done = unrar
                    .test(path)?
                    .ok_or_else(|| format!("{}: UnRAR failed", path.display()))?;
                if done.1 != *bytes {
                    return Err(format!("{}: UnRAR gave {} bytes", path.display(), done.1));
                }
                Ok(done)
            })?;
            port_best = port_best.max(port);
            unrar_best = unrar_best.max(reference);
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        println!(
            "| {name}, {:.1} MB | {:.0} MB/s | {:.0} MB/s | {:.2}× |",
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
