//! Times hivepack-7z against the 7z decoder of the LZMA SDK 26.05, and against
//! 7-Zip's program for what the SDK's decoder does not read, on the same
//! archives, in each thing a 7z reader does: opening, listing, and reading each
//! method and filter; and against `7zz` writing them.
//!
//! ```text
//! python3 scripts/testdata.py fetch --group generated --group bench
//! cargo run --release -p sevenz-bench -- [--only TEXT] [--rounds 5] [--seconds 0.5]
//!     [--limit-mb 64] [--small 5000] [--many 100000] [--dir DIR] [DATA]
//! ```
//!
//! DATA is a folder of files to archive, by default the Silesia corpus, cut to
//! `--limit-mb` in all. `7zz`, built from the same release, makes every archive.
//! "Many" archives hold `--many` files of 16 bytes with paths for names, where
//! what counts is the header, and "small" ones `--small` files of 4 KiB in folders
//! of their own, where what counts is starting a decoder for each.
//!
//! The SDK runs in a program of its own, `tools/7z-oracle/bench.c`, built with
//! `-O2` and without the assembly decoders that 7-Zip's releases use, as `7zz` is
//! built here. Against the SDK, only the work itself is timed, not opening an
//! archive to read it or hashing what was read. Against `7zz`, which is a process
//! each time, `7zz t -mmt=1` is timed whole, and the port opens the archive and
//! reads its files, checking their CRCs as `7zz` does; those rows are for what the
//! SDK cannot read, and `7zz`'s start counts against it a little.
//!
//! Rounds take turns between the two, so that a noisy machine slows them alike,
//! and each round runs for at least `--seconds`. The output is a Markdown table of
//! the best speeds, which what else the machine does cannot make better, and the
//! port's over the reference's: above 1 the port is faster. Against the SDK, both
//! must read the same bytes.
//!
//! The writing rows are against `7zz a -mmt=1`, timed whole, and the port reads
//! the same files and writes a file through a buffer. The encoders are not the same
//! (`hivepack-xz` is liblzma's, `7zz` has its own), so that each row also says what
//! size each made, and a speed means nothing without it. The port's archives must
//! pass `7zz t`.

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use hivepack_7z::{Archive, Method, NewEntry, Options, WriteOptions, Writer};

type Result<T> = std::result::Result<T, String>;

const PASSWORD: &str = "correct-horse-battery-staple";
/// The size of the buffer in front of the file, the SDK's `BUF_SIZE`.
const BUF_SIZE: usize = 1 << 18;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Input {
    Big,
    Small,
    Many,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    /// `SzArEx_Open`.
    Open,
    /// Each file's name.
    Names,
    /// `SzAr_DecodeFolder` on each folder.
    Decode,
    /// `SzArEx_Extract` on each file.
    Extract,
    /// The SDK's `SzArEx_Extract` against the port's `Archive::files`, which
    /// reads a folder in pieces.
    Files,
    /// `7zz t` against opening the archive and `Archive::files`.
    Tool,
}

struct Workload {
    category: &'static str,
    name: &'static str,
    input: Input,
    /// What `7zz a` is given to make the archive.
    options: &'static str,
    op: Op,
    per_entry: bool,
}

const fn data(
    category: &'static str,
    name: &'static str,
    options: &'static str,
    op: Op,
) -> Workload {
    Workload {
        category,
        name,
        input: Input::Big,
        options,
        op,
        per_entry: false,
    }
}

const fn entries(
    category: &'static str,
    name: &'static str,
    input: Input,
    options: &'static str,
    op: Op,
) -> Workload {
    Workload {
        category,
        name,
        input,
        options,
        op,
        per_entry: true,
    }
}

const BCJ2: &str = "-m0=BCJ2 -m1=LZMA:d=16m -m2=LZMA:d=1m -m3=LZMA:d=1m -mb0s0:1 -mb0s1:2 -mb0s2:3";

const WORKLOADS: &[Workload] = &[
    entries(
        "Opening many files",
        "Open, header not compressed",
        Input::Many,
        "-m0=Copy -mhc=off",
        Op::Open,
    ),
    entries(
        "Opening many files",
        "Open, header compressed",
        Input::Many,
        "-m0=Copy",
        Op::Open,
    ),
    entries(
        "Opening many files",
        "Each file's name",
        Input::Many,
        "-m0=Copy",
        Op::Names,
    ),
    data("Reading, against the SDK", "Copy", "-m0=Copy", Op::Decode),
    data(
        "Reading, against the SDK",
        "LZMA",
        "-m0=LZMA:d=16m",
        Op::Decode,
    ),
    data(
        "Reading, against the SDK",
        "LZMA, lc=5:lp=3",
        "-m0=LZMA:d=16m:lc=5:lp=3",
        Op::Decode,
    ),
    data(
        "Reading, against the SDK",
        "LZMA2",
        "-m0=LZMA2:d=16m",
        Op::Decode,
    ),
    data(
        "Reading, against the SDK",
        "PPMd, order 6",
        "-m0=PPMd:mem=256m:o=6",
        Op::Decode,
    ),
    data(
        "Reading, against the SDK",
        "BCJ and LZMA",
        "-m0=BCJ -m1=LZMA:d=16m",
        Op::Decode,
    ),
    data(
        "Reading, against the SDK",
        "ARM64 and LZMA",
        "-m0=ARM64 -m1=LZMA:d=16m",
        Op::Decode,
    ),
    data(
        "Reading, against the SDK",
        "Delta and LZMA",
        "-m0=Delta:4 -m1=LZMA:d=16m",
        Op::Decode,
    ),
    data(
        "Reading, against the SDK",
        "BCJ2 and LZMA",
        BCJ2,
        Op::Decode,
    ),
    data(
        "Reading, against the SDK",
        "LZMA, solid, file by file with `extract`",
        "-m0=LZMA:d=16m",
        Op::Extract,
    ),
    data(
        "Reading, against the SDK",
        "LZMA, solid, file by file with `files`",
        "-m0=LZMA:d=16m",
        Op::Files,
    ),
    entries(
        "Reading, against the SDK",
        "LZMA, not solid, small files",
        Input::Small,
        "-m0=LZMA:d=64k -ms=off",
        Op::Decode,
    ),
    entries(
        "Reading, against the SDK",
        "PPMd, not solid, small files",
        Input::Small,
        "-m0=PPMd:mem=1m:o=6 -ms=off",
        Op::Decode,
    ),
    data(
        "Reading past the SDK, against `7zz t`",
        "Deflate",
        "-m0=Deflate",
        Op::Tool,
    ),
    data(
        "Reading past the SDK, against `7zz t`",
        "Deflate64",
        "-m0=Deflate64",
        Op::Tool,
    ),
    data(
        "Reading past the SDK, against `7zz t`",
        "BZip2",
        "-m0=BZip2",
        Op::Tool,
    ),
    data(
        "Reading past the SDK, against `7zz t`",
        "Swap4",
        "-m0=Swap4",
        Op::Tool,
    ),
    data(
        "Reading past the SDK, against `7zz t`",
        "AES-256, Copy",
        "-m0=Copy -pPASSWORD",
        Op::Tool,
    ),
    data(
        "Reading past the SDK, against `7zz t`",
        "AES-256, LZMA2",
        "-m0=LZMA2:d=16m -pPASSWORD",
        Op::Tool,
    ),
    entries(
        "Reading past the SDK, against `7zz t`",
        "AES-256, not solid, small files",
        Input::Small,
        "-m0=LZMA:d=64k -ms=off -pPASSWORD",
        Op::Tool,
    ),
];

/// The SDK's program.
struct Sdk {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Sdk {
    fn spawn(path: &Path) -> Result<Sdk> {
        let mut child = Command::new(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| {
                format!(
                    "{}: {e}: run `python3 scripts/testdata.py fetch --group generated --group bench`",
                    path.display()
                )
            })?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = BufReader::new(child.stdout.take().ok_or("no stdout")?);
        Ok(Sdk {
            child,
            stdin,
            stdout,
        })
    }

    /// A request's time and value.
    fn ask(&mut self, request: &str) -> Result<(Duration, u64)> {
        writeln!(self.stdin, "{request}").map_err(|e| e.to_string())?;
        self.stdin.flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        self.stdout
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        let mut words = line.split_whitespace();
        let bad = || format!("the SDK's answer to `{request}`: {line}");
        let nanos: u64 = words.next().and_then(|w| w.parse().ok()).ok_or_else(bad)?;
        let value: u64 = words.next().and_then(|w| w.parse().ok()).ok_or_else(bad)?;
        Ok((Duration::from_nanos(nanos), value))
    }
}

impl Drop for Sdk {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn text(path: &Path) -> Result<&str> {
    let text = path
        .to_str()
        .ok_or_else(|| format!("{path:?} is not UTF-8"))?;
    if text.contains(' ') {
        return Err(format!("{text} has a space in it"));
    }
    Ok(text)
}

fn fnv64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

type Opened = Archive<BufReader<File>>;

fn open_with(path: &Path, password: bool) -> Result<Opened> {
    let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let options = Options {
        password: password.then(|| PASSWORD.to_string()),
        ..Options::default()
    };
    Archive::open_with(BufReader::with_capacity(BUF_SIZE, file), &options)
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn port_open(path: &Path) -> Result<(Duration, u64)> {
    let start = Instant::now();
    let archive = open_with(path, false)?;
    let time = start.elapsed();
    Ok((time, archive.len() as u64))
}

fn port_names(path: &Path) -> Result<(Duration, u64)> {
    let archive = open_with(path, false)?;
    let mut value = 0;
    let start = Instant::now();
    for entry in archive.entries() {
        value += entry.name_utf16.len() as u64;
    }
    Ok((start.elapsed(), value))
}

fn port_decode(path: &Path) -> Result<(Duration, u64)> {
    let mut archive = open_with(path, false)?;
    let (mut total, mut value) = (Duration::ZERO, 0u64);
    for folder in 0..archive.folders() {
        let start = Instant::now();
        let data = archive.decode_folder(folder).map_err(|e| e.to_string())?;
        total += start.elapsed();
        value = value.wrapping_add(fnv64(&data));
    }
    Ok((total, value))
}

fn port_extract(path: &Path) -> Result<(Duration, u64)> {
    let mut archive = open_with(path, false)?;
    let (mut total, mut value) = (Duration::ZERO, 0u64);
    for index in 0..archive.len() {
        let start = Instant::now();
        let data = archive.extract(index).map_err(|e| e.to_string())?;
        total += start.elapsed();
        value = value.wrapping_add(fnv64(&data));
    }
    Ok((total, value))
}

/// `Archive::files` on each file, into a buffer kept from one to the next.
fn read_files(archive: &mut Opened) -> Result<u64> {
    let mut files = archive.files();
    let mut buf = vec![0; 1 << 16];
    let mut bytes = 0;
    while files.next().map_err(|e| e.to_string())?.is_some() {
        loop {
            let got = files.read(&mut buf).map_err(|e| e.to_string())?;
            if got == 0 {
                break;
            }
            bytes += got as u64;
        }
    }
    Ok(bytes)
}

fn port_files(path: &Path) -> Result<(Duration, u64)> {
    let mut archive = open_with(path, false)?;
    let start = Instant::now();
    let bytes = read_files(&mut archive)?;
    Ok((start.elapsed(), bytes))
}

fn port_tool(path: &Path, password: bool) -> Result<(Duration, u64)> {
    let start = Instant::now();
    let mut archive = open_with(path, password)?;
    let bytes = read_files(&mut archive)?;
    Ok((start.elapsed(), bytes))
}

fn tool_test(tool: &Path, path: &Path, password: bool) -> Result<(Duration, u64)> {
    let mut command = Command::new(tool);
    command.args(["t", "-mmt=1", "-bd", "-bso0", "-bse0", "-bsp0"]);
    if password {
        command.arg(format!("-p{PASSWORD}"));
    }
    command
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let start = Instant::now();
    let status = command.status().map_err(|e| e.to_string())?;
    let time = start.elapsed();
    if !status.success() {
        return Err(format!("7zz t {}: {status}", path.display()));
    }
    Ok((time, 0))
}

/// A row of writing: the input, the port's options, `7zz`'s.
struct WriteRow {
    name: &'static str,
    input: Input,
    method: Method,
    solid: bool,
    password: bool,
    per_entry: bool,
    tool: &'static str,
}

const fn write_row(
    name: &'static str,
    input: Input,
    method: Method,
    tool: &'static str,
) -> WriteRow {
    WriteRow {
        name,
        input,
        method,
        solid: true,
        password: false,
        per_entry: false,
        tool,
    }
}

const WRITE_ROWS: &[WriteRow] = &[
    write_row("Copy", Input::Big, Method::Copy, "-m0=Copy"),
    write_row(
        "LZMA2, xz's preset 1, 1 MiB",
        Input::Big,
        Method::Lzma2 { preset: 1 },
        "-m0=LZMA2:d=1m -mx=1",
    ),
    write_row(
        "LZMA2, xz's preset 6, 8 MiB",
        Input::Big,
        Method::Lzma2 { preset: 6 },
        "-m0=LZMA2:d=8m -mx=5",
    ),
    write_row(
        "LZMA, xz's preset 6, 8 MiB",
        Input::Big,
        Method::Lzma { preset: 6 },
        "-m0=LZMA:d=8m -mx=5",
    ),
    write_row(
        "Deflate, level 6",
        Input::Big,
        Method::Deflate { level: 6 },
        "-m0=Deflate -mx=5",
    ),
    write_row(
        "BZip2, blocks of 900 KiB",
        Input::Big,
        Method::BZip2 { level: 9 },
        "-m0=BZip2:d=900k -mx=5",
    ),
    WriteRow {
        password: true,
        ..write_row(
            "AES-256, LZMA2, names too",
            Input::Big,
            Method::Lzma2 { preset: 1 },
            "-m0=LZMA2:d=1m -mx=1 -mhe=on -pPASSWORD",
        )
    },
    WriteRow {
        solid: false,
        per_entry: true,
        ..write_row(
            "LZMA2, not solid, small files",
            Input::Small,
            Method::Lzma2 { preset: 1 },
            "-m0=LZMA2:d=1m -mx=1 -ms=off",
        )
    },
    WriteRow {
        per_entry: true,
        ..write_row("Copy, many files", Input::Many, Method::Copy, "-m0=Copy")
    },
];

/// The files under `folder`, by their names in it, with the folders they are in
/// as `7zz` adds them.
fn walk(folder: &Path, prefix: &str, out: &mut Vec<(String, Option<PathBuf>)>) -> Result<()> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(folder)
        .map_err(|e| e.to_string())?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    for path in entries {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("a name that is not text")?;
        let name = format!("{prefix}{name}");
        if path.is_dir() {
            out.push((name.clone(), None));
            walk(&path, &format!("{name}/"), out)?;
        } else {
            out.push((name, Some(path)));
        }
    }
    Ok(())
}

fn port_write(
    row: &WriteRow,
    files: &[(String, Option<PathBuf>)],
    out: &Path,
) -> Result<(Duration, u64)> {
    let error = |e: hivepack_7z::Error| e.name().to_string();
    let options = WriteOptions {
        method: row.method,
        solid_block_size: row.solid.then_some(1 << 32),
        password: row.password.then(|| PASSWORD.to_string()),
        encrypt_headers: row.password,
        ..WriteOptions::default()
    };
    let start = Instant::now();
    let file = File::create(out).map_err(|e| e.to_string())?;
    let mut w =
        Writer::with_options(BufWriter::with_capacity(BUF_SIZE, file), options).map_err(error)?;
    for (name, path) in files {
        match path {
            None => w.add_directory(NewEntry::new(name)).map_err(error)?,
            Some(path) => {
                let mut input = File::open(path).map_err(|e| e.to_string())?;
                w.add_file(NewEntry::new(name), &mut input)
                    .map_err(|e| e.to_string())?;
            }
        }
    }
    w.finish().map_err(error)?;
    let time = start.elapsed();
    Ok((
        time,
        std::fs::metadata(out).map_err(|e| e.to_string())?.len(),
    ))
}

fn tool_write(tool: &Path, dir: &Path, row: &WriteRow, out: &Path) -> Result<(Duration, u64)> {
    let _ = std::fs::remove_file(out);
    let folder = match row.input {
        Input::Big => "big",
        Input::Small => "small",
        Input::Many => "many",
    };
    let options = row.tool.replace("PASSWORD", PASSWORD);
    let start = Instant::now();
    let status = Command::new(tool)
        .current_dir(dir.join(folder))
        .args(["a", "-mmt=1", "-bd", "-bso0", "-bse0", "-bsp0", "-y"])
        .args(options.split_whitespace())
        .arg(out)
        .arg(".")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .map_err(|e| e.to_string())?;
    let time = start.elapsed();
    if !status.success() {
        return Err(format!("7zz a {options}: {status}"));
    }
    Ok((
        time,
        std::fs::metadata(out).map_err(|e| e.to_string())?.len(),
    ))
}

/// The writing rows.
fn bench_writing(options: &Options_, tool: &Path, dir: &Path, big_bytes: u64) -> Result<()> {
    let mut printed = false;
    let port_out = dir.join("written-port.7z");
    let tool_out = dir.join("written-tool.7z");
    for row in WRITE_ROWS {
        if let Some(only) = &options.only
            && !"Writing, against 7zz a -mmt=1".contains(only.as_str())
            && !row.name.contains(only.as_str())
        {
            continue;
        }
        if !printed {
            println!("| **Writing, against `7zz a -mmt=1`** | | | |");
            printed = true;
        }
        let folder = match row.input {
            Input::Big => "big",
            Input::Small => "small",
            Input::Many => "many",
        };
        let mut files = Vec::new();
        walk(&dir.join(folder), "", &mut files)?;
        let (mut port_times, mut tool_times) = (Vec::new(), Vec::new());
        let (mut port_size, mut tool_size) = (0, 0);
        for round in 0..options.rounds {
            for port in [round % 2 == 0, round % 2 == 1] {
                let (mut total, mut runs) = (Duration::ZERO, 0u32);
                while runs == 0 || total.as_secs_f64() < options.seconds {
                    let (time, size) = if port {
                        port_write(row, &files, &port_out)?
                    } else {
                        tool_write(tool, dir, row, &tool_out)?
                    };
                    total += time;
                    runs += 1;
                    if port {
                        port_size = size;
                    } else {
                        tool_size = size;
                    }
                }
                let time = total.as_secs_f64() / f64::from(runs);
                if port {
                    port_times.push(time);
                } else {
                    tool_times.push(time);
                }
            }
        }
        tool_test(tool, &port_out, row.password)?;
        let amount = match row.input {
            Input::Many => options.many as f64,
            Input::Small => options.small as f64,
            Input::Big => big_bytes as f64,
        };
        let (port_time, tool_time) = (best(&port_times), best(&tool_times));
        println!(
            "| {}: {:.2} MB, `7zz` {:.2} MB | {} | {} | {:.2}× |",
            row.name,
            port_size as f64 / 1e6,
            tool_size as f64 / 1e6,
            speed(amount, port_time, row.per_entry),
            speed(amount, tool_time, row.per_entry),
            tool_time / port_time
        );
        std::io::stdout().flush().map_err(|e| e.to_string())?;
    }
    let _ = std::fs::remove_file(port_out);
    let _ = std::fs::remove_file(tool_out);
    Ok(())
}

struct Options_ {
    only: Option<String>,
    rounds: usize,
    seconds: f64,
    limit_mb: usize,
    small: usize,
    many: usize,
    dir: Option<PathBuf>,
    data: PathBuf,
}

fn parse_options(repository: &Path) -> Result<Options_> {
    let mut options = Options_ {
        only: None,
        rounds: 5,
        seconds: 0.5,
        limit_mb: 64,
        small: 5_000,
        many: 100_000,
        dir: None,
        data: repository.join("target/testdata/silesia"),
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--only" => options.only = Some(value()?),
            "--rounds" => options.rounds = value()?.parse().map_err(|_| "--rounds")?,
            "--seconds" => options.seconds = value()?.parse().map_err(|_| "--seconds")?,
            "--limit-mb" => options.limit_mb = value()?.parse().map_err(|_| "--limit-mb")?,
            "--small" => options.small = value()?.parse().map_err(|_| "--small")?,
            "--many" => options.many = value()?.parse().map_err(|_| "--many")?,
            "--dir" => options.dir = Some(PathBuf::from(value()?)),
            _ if arg.starts_with("--") => return Err(format!("unknown option {arg}")),
            _ => options.data = PathBuf::from(arg),
        }
    }
    Ok(options)
}

/// The inputs as folders: `big`, the files of `data` cut to `limit` bytes in all,
/// `small`, pieces of them, and `many`, short files with paths for names.
fn make_inputs(data: &Path, dir: &Path, limit: usize, small: usize, many: usize) -> Result<u64> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(data)
        .map_err(|e| format!("{}: {e}", data.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.is_file())
        .collect();
    paths.sort();
    if paths.is_empty() {
        return Err(format!("{} has no files", data.display()));
    }
    let share = limit / paths.len();
    let write = |path: PathBuf, bytes: &[u8]| -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut out = BufWriter::new(File::create(&path).map_err(|e| e.to_string())?);
        out.write_all(bytes).map_err(|e| e.to_string())?;
        out.flush().map_err(|e| e.to_string())
    };
    let mut files = Vec::new();
    let mut big_bytes = 0;
    for path in &paths {
        let mut bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        bytes.truncate(share);
        let name = path
            .file_name()
            .ok_or_else(|| format!("{}: no name", path.display()))?;
        write(dir.join("big").join(name), &bytes)?;
        big_bytes += bytes.len() as u64;
        files.push(bytes);
    }
    let piece = |i: usize, len: usize| {
        let bytes = &files[i % files.len()];
        let len = len.min(bytes.len());
        let room = (bytes.len() - len).max(1);
        let start = i.wrapping_mul(0x9E37) % room;
        &bytes[start..start + len]
    };
    for i in 0..small {
        write(
            dir.join("small")
                .join(format!("dir{:02}/file{i:06}", i % 50)),
            piece(i, 4096),
        )?;
    }
    for i in 0..many {
        write(
            dir.join("many").join(format!(
                "dir{:03}/sub{:03}/file{i:06}.txt",
                i % 100,
                i % 997
            )),
            piece(i, 16),
        )?;
    }
    Ok(big_bytes)
}

fn make_archive(tool: &Path, dir: &Path, input: Input, options: &str, out: &Path) -> Result<()> {
    let folder = match input {
        Input::Big => "big",
        Input::Small => "small",
        Input::Many => "many",
    };
    let options = options.replace("PASSWORD", PASSWORD);
    let status = Command::new(tool)
        .current_dir(dir.join(folder))
        .args(["a", "-bd", "-bso0", "-bse0", "-bsp0", "-y"])
        .args(options.split_whitespace())
        .arg(out)
        .arg(".")
        .stdin(Stdio::null())
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("7zz a {options}: {status}"));
    }
    Ok(())
}

fn best(values: &[f64]) -> f64 {
    values.iter().copied().fold(f64::INFINITY, f64::min)
}

fn speed(amount: f64, seconds: f64, per_entry: bool) -> String {
    let speed = amount / seconds;
    if per_entry {
        let digits = usize::from(speed < 1e5);
        format!("{:.*} k files/s", digits, speed / 1e3)
    } else {
        format!("{:.1} MB/s", speed / 1e6)
    }
}

fn real_main() -> Result<()> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let options = parse_options(&repository)?;
    let dir = match &options.dir {
        Some(dir) => dir.clone(),
        None => repository
            .join("target")
            .join(format!("7z-bench-{}", std::process::id())),
    };
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let dir = dir.canonicalize().map_err(|e| e.to_string())?;
    let big_bytes = make_inputs(
        &options.data,
        &dir,
        options.limit_mb << 20,
        options.small,
        options.many,
    )?;
    let tool = repository
        .join("target/testdata/7zz/7zz")
        .canonicalize()
        .map_err(|e| {
            format!("7zz: {e}: run `python3 scripts/testdata.py fetch --group generated`")
        })?;
    let mut sdk = Sdk::spawn(&repository.join("target/testdata/7z-bench-sdk/oracle"))?;

    println!("| Workload | hivepack-7z | The reference | Port / reference |\n|---|---|---|---|");
    let mut category = "";
    let mut made: Vec<(Input, &str, PathBuf)> = Vec::new();
    for w in WORKLOADS {
        if let Some(only) = &options.only
            && !w.category.contains(only.as_str())
            && !w.name.contains(only.as_str())
        {
            continue;
        }
        if w.category != category {
            category = w.category;
            println!("| **{category}** | | | |");
        }
        let archive = match made
            .iter()
            .find(|(input, opts, _)| *input == w.input && *opts == w.options)
        {
            Some((_, _, path)) => path.clone(),
            None => {
                let path = dir.join(format!("archive-{}.7z", made.len()));
                make_archive(&tool, &dir, w.input, w.options, &path)?;
                made.push((w.input, w.options, path.clone()));
                path
            }
        };
        let password = w.options.contains("-p");
        let path = text(&archive)?;
        let mut run = |port: bool| -> Result<(Duration, u64)> {
            match (w.op, port) {
                (Op::Open, true) => port_open(&archive),
                (Op::Names, true) => port_names(&archive),
                (Op::Decode, true) => port_decode(&archive),
                (Op::Extract, true) => port_extract(&archive),
                (Op::Files, true) => port_files(&archive),
                (Op::Tool, true) => port_tool(&archive, password),
                (Op::Open, false) => sdk.ask(&format!("open {path}")),
                (Op::Names, false) => sdk.ask(&format!("names {path}")),
                (Op::Decode, false) => sdk.ask(&format!("decode {path}")),
                (Op::Extract | Op::Files, false) => sdk.ask(&format!("extract {path}")),
                (Op::Tool, false) => tool_test(&tool, &archive, password),
            }
        };
        let mut port_times = Vec::new();
        let mut other_times = Vec::new();
        let (mut port_value, mut other_value) = (0, 0);
        for round in 0..options.rounds {
            // Which goes first changes each round.
            for port in [round % 2 == 0, round % 2 == 1] {
                let (mut total, mut runs) = (Duration::ZERO, 0u32);
                while runs == 0 || total.as_secs_f64() < options.seconds {
                    let (time, value) = run(port)?;
                    total += time;
                    runs += 1;
                    if port {
                        port_value = value;
                    } else {
                        other_value = value;
                    }
                }
                let time = total.as_secs_f64() / f64::from(runs);
                if port {
                    port_times.push(time);
                } else {
                    other_times.push(time);
                }
            }
        }
        // `files` counts bytes where the SDK's side hashes, and `7zz` tells
        // nothing but that it found no error.
        if matches!(w.op, Op::Open | Op::Names | Op::Decode | Op::Extract)
            && port_value != other_value
        {
            return Err(format!(
                "{}, {}: the port got {port_value}, the SDK {other_value}",
                w.category, w.name
            ));
        }
        let amount = match w.input {
            Input::Many => options.many as f64,
            Input::Small => options.small as f64,
            Input::Big => big_bytes as f64,
        };
        let port_time = best(&port_times);
        let other_time = best(&other_times);
        println!(
            "| {} | {} | {} | {:.2}× |",
            w.name,
            speed(amount, port_time, w.per_entry),
            speed(amount, other_time, w.per_entry),
            other_time / port_time
        );
        std::io::stdout().flush().map_err(|e| e.to_string())?;
    }
    drop(sdk);
    bench_writing(&options, &tool, &dir, big_bytes)?;
    if options.dir.is_none() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(())
}

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sevenz-bench: {e}");
            ExitCode::FAILURE
        }
    }
}
