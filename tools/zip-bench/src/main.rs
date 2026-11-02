//! Times hivepack::zip against libzip 1.12.1 on the same archives, in each
//! thing an archive library does: opening, listing, finding names, reading,
//! writing, encrypting and editing.
//!
//! ```text
//! python3 scripts/testdata.py fetch --group bench
//! cargo run --release -p zip-bench -- [--only TEXT] [--rounds 5] [--seconds 0.5]
//!     [--limit-mb 64] [--small 20000] [--many 200000] [--dir DIR] [DATA]
//! ```
//!
//! DATA is a folder of files to archive, by default the Silesia corpus. They
//! are cut to `--limit-mb` in all, as LZMA at its level 6 takes minutes on the
//! whole corpus. "big" archives hold them as they are, "small" ones `--small`
//! pieces of 4 KiB from them, where what counts is the work for each entry, and
//! "many" ones `--many` entries of 16 bytes with paths for names, where what
//! counts is the central directory. `--only` keeps the workloads whose category
//! or name holds the text.
//!
//! libzip runs in a program of its own, `tools/zip-oracle/bench.c`, built with
//! the same libzip, zlib, nettle, libbzip2 and liblzma sources as the oracle,
//! all with `-O2` and without assembly files (liblzma's x86-64 range decoder is
//! inline, and stays). The real libzip, with a crypto library that uses the
//! processor's AES instructions, can be much faster. Only the work itself is timed, on both sides, not opening an archive
//! to read its entries or copying one to edit it; archives are files in `--dir`,
//! by default in `target/`, not the system's temporary folder, which can be
//! memory, and the input is in memory.
//!
//! Rounds take turns between the two, so that a noisy machine slows them
//! alike, and each round runs for at least `--seconds`. The output is a Markdown
//! table of the best speeds, which what else the machine does cannot make better,
//! and the port's over libzip's: above 1 the port is faster. Both must get the same results: the same counts, and, except for
//! encrypted archives, which use random bytes, the same bytes written.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use hivepack::zip::{Archive, BufferSource, Flags, OpenFlags, cm, em};

type Result<T> = std::result::Result<T, String>;

const PASSWORD: &str = "correct-horse-battery-staple";
/// The size of each read, as `zip_fread` is called by most programs.
const CHUNK: usize = 1 << 16;
/// The mtime of every entry written, so that the bytes can be compared.
const MTIME: i64 = 1_700_000_000;

/// An entry of a list: its name, and where its data is.
struct Item {
    name: String,
    file: usize,
    offset: usize,
    len: usize,
}

/// What archives hold, and the same as a list file for libzip's program.
struct List {
    path: PathBuf,
    items: Vec<Item>,
    bytes: u64,
}

/// How an archive's entries are stored.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Method {
    method: i32,
    level: u32,
    encryption: u16,
}

const fn plain(method: u16, level: u32) -> Method {
    Method {
        method: method as i32,
        level,
        encryption: em::NONE,
    }
}

const fn encrypted(encryption: u16) -> Method {
    Method {
        method: cm::STORE as i32,
        level: 0,
        encryption,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Which {
    Big,
    Small,
    /// `--small` divided by 10: a key is hashed for each entry.
    SmallFew,
    Many,
}

#[derive(Clone, Copy)]
enum Edit {
    RenameOne,
    RenameAll,
    CommentAll,
    DeleteHalf,
    AddOne,
}

impl Edit {
    fn name(self) -> &'static str {
        match self {
            Edit::RenameOne => "rename-one",
            Edit::RenameAll => "rename-all",
            Edit::CommentAll => "comment-all",
            Edit::DeleteHalf => "delete-half",
            Edit::AddOne => "add-one",
        }
    }
}

#[derive(Clone, Copy)]
enum Op {
    Open(bool),
    List,
    Locate,
    Read,
    Write,
    Edit(Edit),
}

struct Workload {
    category: &'static str,
    name: &'static str,
    which: Which,
    method: Method,
    op: Op,
    /// Speeds are in entries, not in bytes.
    per_entry: bool,
}

const fn work(
    category: &'static str,
    name: &'static str,
    which: Which,
    method: Method,
    op: Op,
) -> Workload {
    Workload {
        category,
        name,
        which,
        method,
        op,
        per_entry: false,
    }
}

const fn entries(
    category: &'static str,
    name: &'static str,
    which: Which,
    method: Method,
    op: Op,
) -> Workload {
    Workload {
        category,
        name,
        which,
        method,
        op,
        per_entry: true,
    }
}

const STORE: Method = plain(cm::STORE, 0);
const DEFLATE: Method = plain(cm::DEFLATE, 6);

const WORKLOADS: &[Workload] = &[
    entries(
        "Opening",
        "open, many entries",
        Which::Many,
        STORE,
        Op::Open(false),
    ),
    entries(
        "Opening",
        "open with ZIP_CHECKCONS, many entries",
        Which::Many,
        STORE,
        Op::Open(true),
    ),
    entries(
        "Finding",
        "zip_stat_index, each entry",
        Which::Many,
        STORE,
        Op::List,
    ),
    entries(
        "Finding",
        "zip_name_locate, each entry",
        Which::Many,
        STORE,
        Op::Locate,
    ),
    work("Reading", "stored", Which::Big, STORE, Op::Read),
    work("Reading", "Deflate", Which::Big, DEFLATE, Op::Read),
    work(
        "Reading",
        "bzip2",
        Which::Big,
        plain(cm::BZIP2, 9),
        Op::Read,
    ),
    work("Reading", "LZMA", Which::Big, plain(cm::LZMA, 6), Op::Read),
    work("Reading", "XZ", Which::Big, plain(cm::XZ, 6), Op::Read),
    entries(
        "Reading",
        "stored, small entries",
        Which::Small,
        STORE,
        Op::Read,
    ),
    entries(
        "Reading",
        "Deflate, small entries",
        Which::Small,
        DEFLATE,
        Op::Read,
    ),
    work("Writing", "stored", Which::Big, STORE, Op::Write),
    work(
        "Writing",
        "Deflate, level 1",
        Which::Big,
        plain(cm::DEFLATE, 1),
        Op::Write,
    ),
    work(
        "Writing",
        "Deflate, level 6",
        Which::Big,
        DEFLATE,
        Op::Write,
    ),
    work(
        "Writing",
        "Deflate, level 9",
        Which::Big,
        plain(cm::DEFLATE, 9),
        Op::Write,
    ),
    work(
        "Writing",
        "bzip2, level 1",
        Which::Big,
        plain(cm::BZIP2, 1),
        Op::Write,
    ),
    work(
        "Writing",
        "bzip2, level 9",
        Which::Big,
        plain(cm::BZIP2, 9),
        Op::Write,
    ),
    work(
        "Writing",
        "LZMA, level 1",
        Which::Big,
        plain(cm::LZMA, 1),
        Op::Write,
    ),
    work(
        "Writing",
        "LZMA, level 6",
        Which::Big,
        plain(cm::LZMA, 6),
        Op::Write,
    ),
    work(
        "Writing",
        "XZ, level 1",
        Which::Big,
        plain(cm::XZ, 1),
        Op::Write,
    ),
    work(
        "Writing",
        "XZ, level 6",
        Which::Big,
        plain(cm::XZ, 6),
        Op::Write,
    ),
    entries(
        "Writing",
        "stored, small entries",
        Which::Small,
        STORE,
        Op::Write,
    ),
    entries(
        "Writing",
        "Deflate, small entries",
        Which::Small,
        DEFLATE,
        Op::Write,
    ),
    work(
        "Decrypting",
        "ZipCrypto",
        Which::Big,
        encrypted(em::TRAD_PKWARE),
        Op::Read,
    ),
    work(
        "Decrypting",
        "WinZip AES-128",
        Which::Big,
        encrypted(em::AES_128),
        Op::Read,
    ),
    work(
        "Decrypting",
        "WinZip AES-256",
        Which::Big,
        encrypted(em::AES_256),
        Op::Read,
    ),
    entries(
        "Decrypting",
        "WinZip AES-256, small entries",
        Which::SmallFew,
        encrypted(em::AES_256),
        Op::Read,
    ),
    work(
        "Encrypting",
        "ZipCrypto",
        Which::Big,
        encrypted(em::TRAD_PKWARE),
        Op::Write,
    ),
    work(
        "Encrypting",
        "WinZip AES-128",
        Which::Big,
        encrypted(em::AES_128),
        Op::Write,
    ),
    work(
        "Encrypting",
        "WinZip AES-256",
        Which::Big,
        encrypted(em::AES_256),
        Op::Write,
    ),
    entries(
        "Encrypting",
        "WinZip AES-256, small entries",
        Which::SmallFew,
        encrypted(em::AES_256),
        Op::Write,
    ),
    work(
        "Editing",
        "rename one entry, the data copied",
        Which::Big,
        DEFLATE,
        Op::Edit(Edit::RenameOne),
    ),
    work(
        "Editing",
        "add one entry, the data copied",
        Which::Big,
        DEFLATE,
        Op::Edit(Edit::AddOne),
    ),
    entries(
        "Editing",
        "rename each entry",
        Which::Many,
        STORE,
        Op::Edit(Edit::RenameAll),
    ),
    entries(
        "Editing",
        "set each entry's comment",
        Which::Many,
        STORE,
        Op::Edit(Edit::CommentAll),
    ),
    entries(
        "Editing",
        "delete half of the entries",
        Which::Many,
        STORE,
        Op::Edit(Edit::DeleteHalf),
    ),
];

/// libzip's program.
struct Libzip {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Libzip {
    fn spawn(path: &Path) -> Result<Libzip> {
        // The time zone libzip writes DOS times in, as the port always does.
        let mut child = Command::new(path)
            .env("TZ", "UTC")
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
        Ok(Libzip {
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
        let bad = || format!("libzip's answer to `{request}`: {line}");
        let nanos: u64 = words.next().and_then(|w| w.parse().ok()).ok_or_else(bad)?;
        let value: u64 = words.next().and_then(|w| w.parse().ok()).ok_or_else(bad)?;
        Ok((Duration::from_nanos(nanos), value))
    }
}

impl Drop for Libzip {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `path` for `format!`, which the requests are lines of.
fn text(path: &Path) -> Result<&str> {
    let text = path
        .to_str()
        .ok_or_else(|| format!("{path:?} is not UTF-8"))?;
    if text.contains(' ') {
        return Err(format!("{text} has a space in it"));
    }
    Ok(text)
}

fn zip_err(what: &str) -> impl Fn(hivepack::zip::Error) -> String + '_ {
    move |e| format!("{what}: {e}")
}

/// An archive for writing in, as `ZIP_CREATE` opens a file that is not there.
fn new_archive() -> Result<Archive<Vec<u8>>> {
    Archive::open(Vec::new(), OpenFlags::CREATE).map_err(zip_err("a new archive"))
}

struct Bench {
    files: Vec<Vec<u8>>,
    lists: HashMap<Which, List>,
    dir: PathBuf,
    libzip: Libzip,
    /// Archives made, by libzip, to read and edit.
    archives: HashMap<(Which, Method), PathBuf>,
}

impl Bench {
    fn archive(&mut self, which: Which, method: Method) -> Result<PathBuf> {
        if let Some(path) = self.archives.get(&(which, method)) {
            return Ok(path.clone());
        }
        let path = self
            .dir
            .join(format!("archive-{}.zip", self.archives.len()));
        let request = write_request(&path, &self.lists[&which].path, method)?;
        self.libzip.ask(&request)?;
        self.archives.insert((which, method), path.clone());
        Ok(path)
    }

    fn port_open(&self, path: &Path, check: bool) -> Result<(Duration, u64)> {
        let file = File::open(path).map_err(|e| e.to_string())?;
        let flags = if check {
            OpenFlags::RDONLY | OpenFlags::CHECKCONS
        } else {
            OpenFlags::RDONLY
        };
        let start = Instant::now();
        let archive = Archive::open(file, flags).map_err(zip_err("open"))?;
        let time = start.elapsed();
        Ok((time, archive.get_num_entries(Flags::NONE)))
    }

    fn port_list(&self, path: &Path) -> Result<(Duration, u64)> {
        let archive = read_archive(path)?;
        let n = archive.get_num_entries(Flags::NONE);
        let mut value = 0;
        let start = Instant::now();
        for i in 0..n {
            let stat = archive
                .stat_index(i, Flags::NONE)
                .map_err(zip_err("stat"))?;
            value += stat.size + stat.name.map_or(0, |name| name.len() as u64);
        }
        Ok((start.elapsed(), value))
    }

    fn port_locate(&self, path: &Path) -> Result<(Duration, u64)> {
        let archive = read_archive(path)?;
        let n = archive.get_num_entries(Flags::NONE);
        let mut names = Vec::with_capacity(n as usize);
        for i in 0..n {
            names.push(archive.get_name(i, Flags::NONE).map_err(zip_err("name"))?);
        }
        let mut value = 0;
        let start = Instant::now();
        for name in &names {
            value += archive
                .name_locate(name, Flags::NONE)
                .map_err(zip_err("locate"))?;
        }
        Ok((start.elapsed(), value))
    }

    fn port_read(&self, path: &Path, method: Method) -> Result<(Duration, u64)> {
        let mut archive = read_archive(path)?;
        if method.encryption != em::NONE {
            archive.set_default_password(Some(PASSWORD.as_bytes()));
        }
        let n = archive.get_num_entries(Flags::NONE);
        let mut buf = vec![0; CHUNK];
        let mut value = 0;
        let start = Instant::now();
        for i in 0..n {
            let mut file = archive
                .fopen_index(i, Flags::NONE)
                .map_err(zip_err("fopen"))?;
            loop {
                let got = file.fread(&mut buf).map_err(zip_err("fread"))?;
                if got == 0 {
                    break;
                }
                value += got as u64;
            }
            file.fclose().map_err(zip_err("fclose"))?;
        }
        Ok((start.elapsed(), value))
    }

    fn port_write(&self, list: &List, out: &Path, method: Method) -> Result<(Duration, u64)> {
        // The data is in memory, as libzip's is, from a buffer it does not
        // copy: an Arc each, made outside the timing.
        let sources: Vec<std::sync::Arc<[u8]>> = list
            .items
            .iter()
            .map(|item| self.files[item.file][item.offset..item.offset + item.len].into())
            .collect();
        let _ = std::fs::remove_file(out);
        let start = Instant::now();
        let mut archive = new_archive()?;
        // The crate's own source is `/dev/urandom`, which Windows does not have.
        // libzip's side draws from a stand-in too.
        archive.set_random_source(Some(std::sync::Arc::new(|bytes: &mut [u8]| {
            bytes.fill(0x5A);
            Ok(())
        })));
        for (item, data) in list.items.iter().zip(sources) {
            let index = archive
                .file_add(item.name.as_bytes(), BufferSource::new(data), Flags::NONE)
                .map_err(zip_err("file_add"))?;
            archive
                .file_set_mtime(index, MTIME, Flags::NONE)
                .map_err(zip_err("mtime"))?;
            archive
                .set_file_compression(index, method.method, method.level)
                .map_err(zip_err("compression"))?;
            if method.encryption != em::NONE {
                archive
                    .file_set_encryption(index, method.encryption, Some(PASSWORD.as_bytes()))
                    .map_err(zip_err("encryption"))?;
            }
        }
        let file = File::create(out).map_err(|e| e.to_string())?;
        archive
            .close_to(BufWriter::new(file))
            .map_err(zip_err("close"))?;
        let time = start.elapsed();
        Ok((
            time,
            std::fs::metadata(out).map_err(|e| e.to_string())?.len(),
        ))
    }

    fn port_edit(&self, input: &Path, out: &Path, edit: Edit) -> Result<(Duration, u64)> {
        let file = File::open(input).map_err(|e| e.to_string())?;
        let mut archive = Archive::open(file, OpenFlags::default()).map_err(zip_err("open"))?;
        let n = archive.get_num_entries(Flags::NONE);
        let names = if matches!(edit, Edit::RenameAll) {
            let mut names = Vec::with_capacity(n as usize);
            for i in 0..n {
                let mut name = b"renamed/".to_vec();
                name.extend_from_slice(archive.get_name(i, Flags::NONE).map_err(zip_err("name"))?);
                names.push(name);
            }
            names
        } else {
            Vec::new()
        };
        let added: std::sync::Arc<[u8]> = vec![0; 4096].into();
        let _ = std::fs::remove_file(out);
        let start = Instant::now();
        match edit {
            Edit::RenameOne => archive
                .file_rename(0, b"renamed", Flags::NONE)
                .map_err(zip_err("rename"))?,
            Edit::RenameAll => {
                for (i, name) in names.iter().enumerate() {
                    archive
                        .file_rename(i as u64, name, Flags::NONE)
                        .map_err(zip_err("rename"))?;
                }
            }
            Edit::CommentAll => {
                for i in 0..n {
                    archive
                        .file_set_comment(i, b"a comment", Flags::NONE)
                        .map_err(zip_err("comment"))?;
                }
            }
            Edit::DeleteHalf => {
                for i in (0..n).step_by(2) {
                    archive.delete(i).map_err(zip_err("delete"))?;
                }
            }
            Edit::AddOne => {
                let index = archive
                    .file_add(b"added", BufferSource::new(added), Flags::NONE)
                    .map_err(zip_err("file_add"))?;
                archive
                    .file_set_mtime(index, MTIME, Flags::NONE)
                    .map_err(zip_err("mtime"))?;
                archive
                    .set_file_compression(index, i32::from(cm::STORE), 0)
                    .map_err(zip_err("compression"))?;
            }
        }
        let file = File::create(out).map_err(|e| e.to_string())?;
        archive
            .close_to(BufWriter::new(file))
            .map_err(zip_err("close"))?;
        let time = start.elapsed();
        Ok((
            time,
            std::fs::metadata(out).map_err(|e| e.to_string())?.len(),
        ))
    }

    /// One run of a workload by the port, and by libzip.
    fn run(&mut self, w: &Workload, port: bool) -> Result<(Duration, u64)> {
        let out = self.dir.join(if port {
            "out-port.zip"
        } else {
            "out-libzip.zip"
        });
        match w.op {
            Op::Write => {
                let list = &self.lists[&w.which];
                if port {
                    self.port_write(list, &out, w.method)
                } else {
                    let request = write_request(&out, &list.path, w.method)?;
                    self.libzip.ask(&request)
                }
            }
            Op::Edit(edit) => {
                let input = self.archive(w.which, w.method)?;
                if port {
                    self.port_edit(&input, &out, edit)
                } else {
                    self.libzip.ask(&format!(
                        "edit {} {} {}",
                        text(&input)?,
                        text(&out)?,
                        edit.name()
                    ))
                }
            }
            Op::Open(check) => {
                let path = self.archive(w.which, w.method)?;
                if port {
                    self.port_open(&path, check)
                } else {
                    self.libzip
                        .ask(&format!("open {} {}", text(&path)?, i32::from(check)))
                }
            }
            Op::List => {
                let path = self.archive(w.which, w.method)?;
                if port {
                    self.port_list(&path)
                } else {
                    self.libzip.ask(&format!("list {}", text(&path)?))
                }
            }
            Op::Locate => {
                let path = self.archive(w.which, w.method)?;
                if port {
                    self.port_locate(&path)
                } else {
                    self.libzip.ask(&format!("locate {}", text(&path)?))
                }
            }
            Op::Read => {
                let path = self.archive(w.which, w.method)?;
                if port {
                    self.port_read(&path, w.method)
                } else {
                    let password = if w.method.encryption == em::NONE {
                        "-"
                    } else {
                        PASSWORD
                    };
                    self.libzip
                        .ask(&format!("read {} {CHUNK} {password}", text(&path)?))
                }
            }
        }
    }

    /// The time of one run, over at least `seconds`, and its value.
    fn timed(&mut self, w: &Workload, port: bool, seconds: f64) -> Result<(f64, u64)> {
        let mut total = Duration::ZERO;
        let mut runs = 0u32;
        let mut value = 0;
        while runs == 0 || total.as_secs_f64() < seconds {
            let (time, got) = self.run(w, port)?;
            total += time;
            runs += 1;
            value = got;
        }
        Ok((total.as_secs_f64() / f64::from(runs), value))
    }

    /// Whether what the two wrote is the same; workloads that write only.
    fn same_output(&self) -> Result<bool> {
        let port = std::fs::read(self.dir.join("out-port.zip")).map_err(|e| e.to_string())?;
        let libzip = std::fs::read(self.dir.join("out-libzip.zip")).map_err(|e| e.to_string())?;
        Ok(port == libzip)
    }
}

fn read_archive(path: &Path) -> Result<Archive<File>> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    Archive::open(file, OpenFlags::RDONLY).map_err(zip_err("open"))
}

fn write_request(out: &Path, list: &Path, method: Method) -> Result<String> {
    Ok(format!(
        "write {} {} {} {} {} {PASSWORD}",
        text(out)?,
        text(list)?,
        method.method,
        method.level,
        method.encryption
    ))
}

fn best(values: &[f64]) -> f64 {
    values.iter().copied().fold(f64::INFINITY, f64::min)
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

fn parse_options() -> Result<Options> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
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

/// The files of `data`, cut to `limit` bytes in all, each by its share.
fn load_files(data: &Path, limit: usize) -> Result<Vec<(PathBuf, String, Vec<u8>)>> {
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
    let mut files = Vec::new();
    for path in paths {
        let mut bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        bytes.truncate(share);
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("a file name that is not UTF-8")?
            .to_string();
        files.push((path, name, bytes));
    }
    Ok(files)
}

fn write_list(path: &Path, items: Vec<Item>, inputs: &[PathBuf]) -> Result<List> {
    let mut out = BufWriter::new(File::create(path).map_err(|e| e.to_string())?);
    let mut bytes = 0;
    for item in &items {
        writeln!(
            out,
            "{}\t{}\t{}\t{}",
            item.name,
            text(&inputs[item.file])?,
            item.offset,
            item.len
        )
        .map_err(|e| e.to_string())?;
        bytes += item.len as u64;
    }
    out.flush().map_err(|e| e.to_string())?;
    Ok(List {
        path: path.to_path_buf(),
        items,
        bytes,
    })
}

fn speed(amount: f64, seconds: f64, per_entry: bool) -> String {
    let speed = amount / seconds;
    if per_entry {
        let digits = usize::from(speed < 1e5);
        format!("{:.*} k entries/s", digits, speed / 1e3)
    } else {
        format!("{:.1} MB/s", speed / 1e6)
    }
}

fn real_main() -> Result<()> {
    let options = parse_options()?;
    let dir = match &options.dir {
        Some(dir) => dir.clone(),
        None => Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("zip-bench-{}", std::process::id())),
    };
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let loaded = load_files(&options.data, options.limit_mb << 20)?;
    // The inputs as files of their own, cut as they are here, for libzip's
    // program to load.
    let mut inputs = Vec::new();
    let mut names = Vec::new();
    let mut files = Vec::new();
    for (i, (_, name, bytes)) in loaded.into_iter().enumerate() {
        let path = dir.join(format!("input-{i}"));
        std::fs::write(&path, &bytes).map_err(|e| e.to_string())?;
        inputs.push(path);
        names.push(name);
        files.push(bytes);
    }

    let big = names
        .iter()
        .enumerate()
        .map(|(file, name)| Item {
            name: name.clone(),
            file,
            offset: 0,
            len: files[file].len(),
        })
        .collect();
    let pieces = |count: usize, len: usize| -> Vec<Item> {
        (0..count)
            .map(|i| {
                let file = i % files.len();
                let room = files[file].len().saturating_sub(len).max(1);
                let offset = i.wrapping_mul(0x9E37) % room;
                Item {
                    name: format!("dir{:03}/sub{:03}/file{i:06}.txt", i % 100, i % 997),
                    file,
                    offset,
                    len: len.min(files[file].len()),
                }
            })
            .collect()
    };
    let mut lists = HashMap::new();
    lists.insert(Which::Big, write_list(&dir.join("big.list"), big, &inputs)?);
    lists.insert(
        Which::Small,
        write_list(
            &dir.join("small.list"),
            pieces(options.small, 4096),
            &inputs,
        )?,
    );
    lists.insert(
        Which::SmallFew,
        write_list(
            &dir.join("few.list"),
            pieces(options.small / 10, 4096),
            &inputs,
        )?,
    );
    lists.insert(
        Which::Many,
        write_list(&dir.join("many.list"), pieces(options.many, 16), &inputs)?,
    );

    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let program = repository.join("target/testdata/zip-bench-libzip/oracle");
    let mut bench = Bench {
        files,
        lists,
        dir: dir.clone(),
        libzip: Libzip::spawn(&program)?,
        archives: HashMap::new(),
    };

    println!("| Workload | hivepack-zip | libzip | Port / libzip |\n|---|---|---|---|");
    let mut category = "";
    let mut different = Vec::new();
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
        let mut port_times = Vec::new();
        let mut libzip_times = Vec::new();
        let (mut port_value, mut libzip_value) = (0, 0);
        for round in 0..options.rounds {
            // Which goes first changes each round.
            for port in [round % 2 == 0, round % 2 == 1] {
                let (time, value) = bench.timed(w, port, options.seconds)?;
                if port {
                    port_times.push(time);
                    port_value = value;
                } else {
                    libzip_times.push(time);
                    libzip_value = value;
                }
            }
        }
        // A size written with random bytes is the same too, as the encryption
        // adds the same to each entry.
        if port_value != libzip_value {
            return Err(format!(
                "{} {}: the port got {port_value}, libzip {libzip_value}",
                w.category, w.name
            ));
        }
        if matches!(w.op, Op::Write | Op::Edit(_))
            && w.method.encryption == em::NONE
            && !bench.same_output()?
        {
            different.push(format!("{}, {}", w.category, w.name));
        }
        let list = &bench.lists[&w.which];
        let amount = if w.per_entry {
            list.items.len() as f64
        } else {
            list.bytes as f64
        };
        let port_time = best(&port_times);
        let libzip_time = best(&libzip_times);
        println!(
            "| {} | {} | {} | {:.2}× |",
            w.name,
            speed(amount, port_time, w.per_entry),
            speed(amount, libzip_time, w.per_entry),
            libzip_time / port_time
        );
        std::io::stdout().flush().map_err(|e| e.to_string())?;
    }
    if !different.is_empty() {
        println!("\nThe bytes written differ in: {}.", different.join("; "));
    }
    if options.dir.is_none() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(())
}

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("zip-bench: {e}");
            ExitCode::FAILURE
        }
    }
}
