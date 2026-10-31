//! Times hivepack-tar against Go's archive/tar (Go 1.27.2), which it ports, on the
//! same archives, in each thing a tar reader does: going through the entries of
//! each format, reading their data, and writing them.
//!
//! ```text
//! python3 scripts/testdata.py fetch --group bench
//! cargo run --release -p tar-bench -- [--only TEXT] [--rounds 5] [--seconds 0.5]
//!     [--limit-mb 64] [--small 20000] [--many 200000] [--dir DIR] [DATA]
//! ```
//!
//! DATA is a folder of files to archive, by default the Silesia corpus, cut to
//! `--limit-mb` in all. "Big" archives hold them as they are, "small" ones `--small`
//! pieces of 4 KiB from them, and "many" ones `--many` entries of 16 bytes, where
//! what counts is the headers. Go's `tar.Writer` makes the archives, and GNU tar,
//! as `gtar` or `tar`, the sparse ones, which `tar.Writer` does not write; without
//! it, or if it finds no holes in the files, those rows are left out.
//!
//! Go runs in a program of its own, `tools/tar-bench/go`. Most rows read from
//! memory, so that only the reader is timed, through a plain reader on both sides.
//! Others read from a file: through a buffer of 64 KiB on each side, or one read
//! at a time. A file given as it is lets Go seek past data, as does
//! `Reader::seekable` on the port's side.
//!
//! The writing rows take the same entries, made before the clock starts: to
//! nowhere, so that only the writer is timed, or to a file through a buffer of
//! 64 KiB, where the two files must be the same.
//!
//! Rounds take turns between the two, so that a noisy machine slows them alike,
//! and each round runs for at least `--seconds`. The output is a Markdown table of
//! the best speeds, which what else the machine does cannot make better, and the
//! port's over Go's: above 1 the port is faster. Both must find the same entries
//! and the same bytes.

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use hivepack_tar::{Format, Header, Reader, TYPE_REG, Time, Writer};

type Result<T> = std::result::Result<T, String>;

const CHUNK: usize = 1 << 16;

/// The entries of the sparse archives, and the size of each.
const SPARSE_FILES: usize = 200;
const SPARSE_SIZE: u64 = 1 << 20;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Archive {
    Ustar,
    Pax,
    Gnu,
    Big,
    Small,
    SparseGnu,
    SparsePax,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Where {
    Memory,
    Buffered,
    File,
    /// The file as it is, which both seek.
    Seekable,
    /// Written, and kept by nobody.
    Nowhere,
}

impl Where {
    fn word(self) -> &'static str {
        match self {
            Where::Memory => "mem",
            Where::Buffered => "buf",
            Where::File => "file",
            Where::Seekable => "seek",
            Where::Nowhere => "-",
        }
    }
}

struct Workload {
    category: &'static str,
    name: &'static str,
    archive: Archive,
    from: Where,
    /// The data read, or skipped.
    read: bool,
    per_entry: bool,
    /// The archive written, not read.
    write: bool,
}

const fn entries(
    category: &'static str,
    name: &'static str,
    archive: Archive,
    from: Where,
) -> Workload {
    Workload {
        category,
        name,
        archive,
        from,
        read: false,
        per_entry: true,
        write: false,
    }
}

const fn data(
    category: &'static str,
    name: &'static str,
    archive: Archive,
    from: Where,
    read: bool,
) -> Workload {
    Workload {
        category,
        name,
        archive,
        from,
        read,
        per_entry: false,
        write: false,
    }
}

const fn writing(
    category: &'static str,
    name: &'static str,
    archive: Archive,
    from: Where,
    per_entry: bool,
) -> Workload {
    Workload {
        category,
        name,
        archive,
        from,
        read: false,
        per_entry,
        write: true,
    }
}

const WORKLOADS: &[Workload] = &[
    entries(
        "Going through entries, from memory",
        "USTAR",
        Archive::Ustar,
        Where::Memory,
    ),
    entries(
        "Going through entries, from memory",
        "PAX, long names and times in nanoseconds",
        Archive::Pax,
        Where::Memory,
    ),
    entries(
        "Going through entries, from memory",
        "GNU, long names",
        Archive::Gnu,
        Where::Memory,
    ),
    entries(
        "Going through entries, from memory",
        "GNU sparse",
        Archive::SparseGnu,
        Where::Memory,
    ),
    entries(
        "Going through entries, from memory",
        "PAX sparse 1.0",
        Archive::SparsePax,
        Where::Memory,
    ),
    entries(
        "Going through entries, from a file",
        "USTAR, through a buffer",
        Archive::Ustar,
        Where::Buffered,
    ),
    entries(
        "Going through entries, from a file",
        "USTAR, one read at a time",
        Archive::Ustar,
        Where::File,
    ),
    data(
        "Reading data, from memory",
        "Big entries",
        Archive::Big,
        Where::Memory,
        true,
    ),
    Workload {
        per_entry: true,
        ..data(
            "Reading data, from memory",
            "Small entries",
            Archive::Small,
            Where::Memory,
            true,
        )
    },
    data(
        "Reading data, from memory",
        "GNU sparse, the holes as zeros",
        Archive::SparseGnu,
        Where::Memory,
        true,
    ),
    data(
        "Reading data, from memory",
        "PAX sparse 1.0, the holes as zeros",
        Archive::SparsePax,
        Where::Memory,
        true,
    ),
    data(
        "Reading data, from a file",
        "Big entries, through a buffer",
        Archive::Big,
        Where::Buffered,
        true,
    ),
    data(
        "Reading data, from a file",
        "Big entries, one read at a time",
        Archive::Big,
        Where::File,
        true,
    ),
    data(
        "Skipping data",
        "Big entries, from memory",
        Archive::Big,
        Where::Memory,
        false,
    ),
    data(
        "Skipping data",
        "Big entries, through a buffer",
        Archive::Big,
        Where::Buffered,
        false,
    ),
    data(
        "Skipping data",
        "Big entries, seeking in a file",
        Archive::Big,
        Where::Seekable,
        false,
    ),
    entries(
        "Skipping data",
        "Small entries, seeking in a file",
        Archive::Small,
        Where::Seekable,
    ),
    writing(
        "Writing entries, to nowhere",
        "USTAR",
        Archive::Ustar,
        Where::Nowhere,
        true,
    ),
    writing(
        "Writing entries, to nowhere",
        "PAX, long names and times in nanoseconds",
        Archive::Pax,
        Where::Nowhere,
        true,
    ),
    writing(
        "Writing entries, to nowhere",
        "GNU, long names",
        Archive::Gnu,
        Where::Nowhere,
        true,
    ),
    writing(
        "Writing entries, to nowhere",
        "Small entries",
        Archive::Small,
        Where::Nowhere,
        true,
    ),
    writing(
        "Writing to a file",
        "USTAR, through a buffer",
        Archive::Ustar,
        Where::Buffered,
        true,
    ),
    writing(
        "Writing to a file",
        "Big entries, through a buffer",
        Archive::Big,
        Where::Buffered,
        false,
    ),
];

/// Go's program.
struct Go {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Go {
    fn spawn(path: &Path) -> Result<Go> {
        let mut child = Command::new(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| {
                format!(
                    "{}: {e}: run `python3 scripts/testdata.py fetch --group bench`",
                    path.display()
                )
            })?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = BufReader::new(child.stdout.take().ok_or("no stdout")?);
        Ok(Go {
            child,
            stdin,
            stdout,
        })
    }

    fn ask(&mut self, request: &str) -> Result<(Duration, u64)> {
        writeln!(self.stdin, "{request}").map_err(|e| e.to_string())?;
        self.stdin.flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        self.stdout
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        let mut words = line.split_whitespace();
        let bad = || format!("Go's answer to `{request}`: {line}");
        let nanos: u64 = words.next().and_then(|w| w.parse().ok()).ok_or_else(bad)?;
        let value: u64 = words.next().and_then(|w| w.parse().ok()).ok_or_else(bad)?;
        Ok((Duration::from_nanos(nanos), value))
    }
}

impl Drop for Go {
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

/// Each entry, with its data skipped.
fn go_through<R: Read>(reader: R) -> Result<(Duration, u64)> {
    go_through_all(Reader::new(reader))
}

fn go_through_all<R: Read>(mut tar: Reader<R>) -> Result<(Duration, u64)> {
    let mut value = 0;
    let start = Instant::now();
    while let Some(header) = tar.next().map_err(|e| e.to_string())? {
        value += header.name.len() as u64 + header.size as u64;
    }
    Ok((start.elapsed(), value))
}

/// Each entry, and its data.
fn read_all<R: Read>(reader: R) -> Result<(Duration, u64)> {
    read_all_of(Reader::new(reader))
}

fn read_all_of<R: Read>(mut tar: Reader<R>) -> Result<(Duration, u64)> {
    let mut buf = vec![0; CHUNK];
    let mut value = 0;
    let start = Instant::now();
    while tar.next().map_err(|e| e.to_string())?.is_some() {
        loop {
            let got = tar.read(&mut buf).map_err(|e| e.to_string())?;
            if got == 0 {
                break;
            }
            value += got as u64;
        }
    }
    Ok((start.elapsed(), value))
}

fn port(path: &Path, memory: &[u8], from: Where, read: bool) -> Result<(Duration, u64)> {
    let file = || File::open(path).map_err(|e| e.to_string());
    match (from, read) {
        (Where::Memory, true) => read_all(memory),
        (Where::Memory, false) => go_through(memory),
        (Where::Buffered, true) => read_all(BufReader::with_capacity(CHUNK, file()?)),
        (Where::Buffered, false) => go_through(BufReader::with_capacity(CHUNK, file()?)),
        (Where::File, true) => read_all(file()?),
        (Where::File, false) => go_through(file()?),
        (Where::Seekable, true) => read_all_of(Reader::seekable(file()?)),
        (Where::Seekable, false) => go_through_all(Reader::seekable(file()?)),
        (Where::Nowhere, _) => Err("nothing to read from".into()),
    }
}

/// The entries of a "many" archive, as Go's `manyItems` makes them.
fn many_entries(archive: Archive, count: usize) -> Vec<(Header, Vec<u8>)> {
    let long = "a-long-folder-name/".repeat(8);
    (0..count)
        .map(|i| {
            let name = format!("dir{:03}/sub{:03}/file{i:06}.txt", i % 100, i % 997);
            let mut header = Header {
                typeflag: TYPE_REG,
                name: name.clone().into_bytes(),
                size: 16,
                mode: 0o644,
                mod_time: Some(Time {
                    secs: 1_700_000_000,
                    nanos: 0,
                }),
                format: Format::USTAR,
                ..Default::default()
            };
            if archive != Archive::Ustar {
                header.name = format!("{long}{name}").into_bytes();
                header.format = Format::GNU;
            }
            if archive == Archive::Pax {
                header.format = Format::PAX;
                header.mod_time = Some(Time {
                    secs: 1_700_000_000,
                    nanos: i as u32 + 1,
                });
            }
            (header, b"sixteen bytes...".to_vec())
        })
        .collect()
}

/// The entries of a list, as Go's `packItems` makes them.
fn list_entries(list: &Path) -> Result<Vec<(Header, Vec<u8>)>> {
    let text = std::fs::read_to_string(list).map_err(|e| e.to_string())?;
    let mut files: std::collections::HashMap<&str, Vec<u8>> = std::collections::HashMap::new();
    let mut entries = Vec::new();
    for line in text.lines() {
        let field: Vec<&str> = line.split('\t').collect();
        let [name, file, offset, length] = field[..] else {
            return Err(format!("{}: {line}", list.display()));
        };
        if !files.contains_key(file) {
            let bytes = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
            files.insert(file, bytes);
        }
        let offset: usize = offset.parse().map_err(|_| "an offset")?;
        let length: usize = length.parse().map_err(|_| "a length")?;
        let header = Header {
            typeflag: TYPE_REG,
            name: name.as_bytes().to_vec(),
            size: length as i64,
            mode: 0o644,
            mod_time: Some(Time {
                secs: 1_700_000_000,
                nanos: 0,
            }),
            format: Format::USTAR,
            ..Default::default()
        };
        entries.push((header, files[file][offset..offset + length].to_vec()));
    }
    Ok(entries)
}

/// Counts what is written, and keeps none of it, as Go's `nowhere` does.
#[derive(Default)]
struct Nowhere(u64);

impl Write for Nowhere {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0 += b.len() as u64;
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn write_entries<W: Write>(w: W, entries: &[(Header, Vec<u8>)]) -> Result<W> {
    let mut tar = Writer::new(w);
    for (header, data) in entries {
        tar.write_header(header).map_err(|e| e.to_string())?;
        tar.write_all(data).map_err(|e| e.to_string())?;
    }
    tar.close().map_err(|e| e.to_string())?;
    Ok(tar.into_inner())
}

/// The entries written, timed, to nowhere or to `out`.
fn port_write(entries: &[(Header, Vec<u8>)], out: Option<&Path>) -> Result<(Duration, u64)> {
    let Some(out) = out else {
        let start = Instant::now();
        let w = write_entries(Nowhere::default(), entries)?;
        return Ok((start.elapsed(), w.0));
    };
    let file = File::create(out).map_err(|e| e.to_string())?;
    let start = Instant::now();
    let w = write_entries(BufWriter::with_capacity(CHUNK, file), entries)?;
    let time = start.elapsed();
    let file = w.into_inner().map_err(|e| e.to_string())?;
    let len = file.metadata().map_err(|e| e.to_string())?.len();
    Ok((time, len))
}

/// Times the two in turn: which goes first changes each round. The best times of
/// the port and of Go, and what each found.
fn rounds(
    options: &Options,
    go: &mut Go,
    request: &str,
    mut run: impl FnMut() -> Result<(Duration, u64)>,
) -> Result<(f64, f64, u64, u64)> {
    let mut port_times = Vec::new();
    let mut go_times = Vec::new();
    let (mut port_value, mut go_value) = (0, 0);
    for round in 0..options.rounds {
        for is_port in [round % 2 == 0, round % 2 == 1] {
            let (mut total, mut runs) = (Duration::ZERO, 0u32);
            while runs == 0 || total.as_secs_f64() < options.seconds {
                let (time, value) = if is_port { run()? } else { go.ask(request)? };
                total += time;
                runs += 1;
                if is_port {
                    port_value = value;
                } else {
                    go_value = value;
                }
            }
            let time = total.as_secs_f64() / f64::from(runs);
            if is_port {
                port_times.push(time);
            } else {
                go_times.push(time);
            }
        }
    }
    Ok((best(&port_times), best(&go_times), port_value, go_value))
}

struct Options {
    only: Option<String>,
    rounds: usize,
    seconds: f64,
    limit_mb: usize,
    small: usize,
    many: usize,
    dir: Option<PathBuf>,
    data: PathBuf,
}

fn parse_options(repository: &Path) -> Result<Options> {
    let mut options = Options {
        only: None,
        rounds: 5,
        seconds: 0.5,
        limit_mb: 64,
        small: 20_000,
        many: 200_000,
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

/// The lists Go's program packs: the files of `data`, cut to `limit` bytes in all,
/// as files of their own, and pieces of them.
fn make_lists(
    data: &Path,
    dir: &Path,
    limit: usize,
    small: usize,
) -> Result<(PathBuf, PathBuf, u64)> {
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
    let big = dir.join("big.list");
    let pieces = dir.join("small.list");
    let mut big_out = BufWriter::new(File::create(&big).map_err(|e| e.to_string())?);
    let mut small_out = BufWriter::new(File::create(&pieces).map_err(|e| e.to_string())?);
    let mut lens = Vec::new();
    let mut inputs = Vec::new();
    let mut total = 0;
    for (i, path) in paths.iter().enumerate() {
        let mut bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        bytes.truncate(share);
        let input = dir.join(format!("input-{i}"));
        std::fs::write(&input, &bytes).map_err(|e| e.to_string())?;
        writeln!(big_out, "file{i}\t{}\t0\t{}", text(&input)?, bytes.len())
            .map_err(|e| e.to_string())?;
        total += bytes.len() as u64;
        lens.push(bytes.len());
        inputs.push(input);
    }
    for i in 0..small {
        let file = i % inputs.len();
        let len = 4096.min(lens[file]);
        let room = (lens[file] - len).max(1);
        writeln!(
            small_out,
            "dir{:02}/file{i:06}\t{}\t{}\t{len}",
            i % 50,
            text(&inputs[file])?,
            i.wrapping_mul(0x9E37) % room
        )
        .map_err(|e| e.to_string())?;
    }
    big_out.flush().map_err(|e| e.to_string())?;
    small_out.flush().map_err(|e| e.to_string())?;
    Ok((big, pieces, total))
}

/// GNU tar's name here, if it is installed.
fn gnu_tar() -> Option<&'static str> {
    ["gtar", "tar"].into_iter().find(|tar| {
        Command::new(tar)
            .arg("--version")
            .stderr(Stdio::null())
            .output()
            .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).contains("GNU tar"))
    })
}

/// Sparse archives, by GNU tar: files with 4 KiB of data every 64 KiB.
fn make_sparse(tar: &str, dir: &Path, out: &Path, options: &[&str]) -> Result<()> {
    let folder = dir.join("sparse");
    if !folder.exists() {
        std::fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
        for i in 0..SPARSE_FILES {
            let file =
                File::create(folder.join(format!("file{i:04}"))).map_err(|e| e.to_string())?;
            file.set_len(SPARSE_SIZE).map_err(|e| e.to_string())?;
            let mut file = std::io::BufWriter::new(file);
            let mut at = 0;
            while at < SPARSE_SIZE {
                std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(at))
                    .map_err(|e| e.to_string())?;
                file.write_all(&[b'x'; 4096]).map_err(|e| e.to_string())?;
                at += 1 << 16;
            }
            file.flush().map_err(|e| e.to_string())?;
        }
    }
    let status = Command::new(tar)
        .current_dir(dir)
        .args(["--sparse", "-cf"])
        .arg(out)
        .args(options)
        .arg("sparse")
        .stdin(Stdio::null())
        .status()
        .map_err(|e| format!("GNU tar: {e}"))?;
    if !status.success() {
        return Err(format!("tar {options:?}: {status}"));
    }
    let len = std::fs::metadata(out).map_err(|e| e.to_string())?.len();
    if len > SPARSE_FILES as u64 * SPARSE_SIZE / 2 {
        return Err(format!("tar {options:?} found no holes: {len} bytes"));
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
        format!("{:.*} k entries/s", digits, speed / 1e3)
    } else {
        format!("{:.0} MB/s", speed / 1e6)
    }
}

fn print_row(w: &Workload, amount: f64, port_time: f64, go_time: f64) -> Result<()> {
    println!(
        "| {} | {} | {} | {:.2}× |",
        w.name,
        speed(amount, port_time, w.per_entry),
        speed(amount, go_time, w.per_entry),
        go_time / port_time
    );
    std::io::stdout().flush().map_err(|e| e.to_string())
}

fn real_main() -> Result<()> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let options = parse_options(&repository)?;
    let dir = match &options.dir {
        Some(dir) => dir.clone(),
        None => repository
            .join("target")
            .join(format!("tar-bench-{}", std::process::id())),
    };
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let dir = dir.canonicalize().map_err(|e| e.to_string())?;
    let mut go = Go::spawn(&repository.join("target/testdata/tar-bench-go/oracle"))?;
    let (big_list, small_list, big_bytes) =
        make_lists(&options.data, &dir, options.limit_mb << 20, options.small)?;

    println!("| Workload | hivepack-tar | Go | Port / Go |\n|---|---|---|---|");
    // On macOS, GNU tar writes these files whole, whose rows would then time something else.
    let tar = gnu_tar().filter(|tar| {
        make_sparse(tar, &dir, &dir.join("probe.tar"), &["--format=gnu"])
            .inspect_err(|e| eprintln!("the sparse rows are left out: {e}"))
            .is_ok()
    });
    if gnu_tar().is_none() {
        eprintln!("no GNU tar here: the sparse rows are left out");
    }
    let mut category = "";
    let mut made: Vec<(Archive, PathBuf, Vec<u8>, u64)> = Vec::new();
    for w in WORKLOADS {
        if let Some(only) = &options.only
            && !w.category.contains(only.as_str())
            && !w.name.contains(only.as_str())
        {
            continue;
        }
        let sparse = matches!(w.archive, Archive::SparseGnu | Archive::SparsePax);
        if sparse && tar.is_none() {
            continue;
        }
        if w.category != category {
            category = w.category;
            println!("| **{category}** | | | |");
        }
        if w.write {
            let (entries, request_end, amount) = match w.archive {
                Archive::Small => (
                    list_entries(&small_list)?,
                    format!("writepack {{}} {}", text(&small_list)?),
                    options.small as f64,
                ),
                Archive::Big => (
                    list_entries(&big_list)?,
                    format!("writepack {{}} {}", text(&big_list)?),
                    big_bytes as f64,
                ),
                kind => {
                    let word = format!("{kind:?}").to_lowercase();
                    (
                        many_entries(kind, options.many),
                        format!("writemany {{}} {word} {}", options.many),
                        options.many as f64,
                    )
                }
            };
            let to_file = w.from != Where::Nowhere;
            let port_out = dir.join("written-port.tar");
            let go_out = dir.join("written-go.tar");
            let target = if to_file { text(&go_out)? } else { "-" };
            let request = request_end.replacen("{}", target, 1);
            let out = to_file.then_some(port_out.as_path());
            let (port_time, go_time, port_value, go_value) =
                rounds(&options, &mut go, &request, || port_write(&entries, out))?;
            if port_value != go_value {
                return Err(format!(
                    "{}, {}: the port wrote {port_value} bytes, Go {go_value}",
                    w.category, w.name
                ));
            }
            if to_file {
                let same = std::fs::read(&port_out).map_err(|e| e.to_string())?
                    == std::fs::read(&go_out).map_err(|e| e.to_string())?;
                if !same {
                    return Err(format!(
                        "{}, {}: the files are not the same",
                        w.category, w.name
                    ));
                }
                let _ = std::fs::remove_file(&port_out);
                let _ = std::fs::remove_file(&go_out);
            }
            print_row(w, amount, port_time, go_time)?;
            continue;
        }
        if !made.iter().any(|(archive, ..)| *archive == w.archive) {
            let path = dir.join(format!("{:?}.tar", w.archive));
            let out = text(&path)?;
            let many = options.many;
            match w.archive {
                Archive::Ustar => go.ask(&format!("many {out} ustar {many}")).map(|_| ())?,
                Archive::Pax => go.ask(&format!("many {out} pax {many}")).map(|_| ())?,
                Archive::Gnu => go.ask(&format!("many {out} gnu {many}")).map(|_| ())?,
                Archive::Big => go
                    .ask(&format!("pack {out} {}", text(&big_list)?))
                    .map(|_| ())?,
                Archive::Small => go
                    .ask(&format!("pack {out} {}", text(&small_list)?))
                    .map(|_| ())?,
                Archive::SparseGnu => {
                    make_sparse(tar.unwrap_or("tar"), &dir, &path, &["--format=gnu"])?
                }
                Archive::SparsePax => {
                    make_sparse(
                        tar.unwrap_or("tar"),
                        &dir,
                        &path,
                        &["--format=pax", "--sparse-version=1.0"],
                    )?;
                }
            }
            let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
            let count = match w.archive {
                Archive::Ustar | Archive::Pax | Archive::Gnu => options.many as u64,
                Archive::Small => options.small as u64,
                // The folder too.
                Archive::SparseGnu | Archive::SparsePax => SPARSE_FILES as u64 + 1,
                Archive::Big => 0,
            };
            made.push((w.archive, path, bytes, count));
        }
        let Some((_, path, memory, count)) =
            made.iter().find(|(archive, ..)| *archive == w.archive)
        else {
            return Err("an archive that is not there".into());
        };
        let request = format!(
            "{} {} {}",
            if w.read { "read" } else { "list" },
            text(path)?,
            w.from.word()
        );
        let (port_time, go_time, port_value, go_value) =
            rounds(&options, &mut go, &request, || {
                port(path, memory, w.from, w.read)
            })?;
        if port_value != go_value {
            return Err(format!(
                "{}, {}: the port got {port_value}, Go {go_value}",
                w.category, w.name
            ));
        }
        let amount = if w.per_entry {
            *count as f64
        } else if matches!(w.archive, Archive::Big) {
            big_bytes as f64
        } else {
            (SPARSE_FILES as u64 * SPARSE_SIZE) as f64
        };
        print_row(w, amount, port_time, go_time)?;
    }
    drop(go);
    if options.dir.is_none() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(())
}

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tar-bench: {e}");
            ExitCode::FAILURE
        }
    }
}
