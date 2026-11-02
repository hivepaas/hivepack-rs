//! Times hivepack-age against age v1.3.2, the reference implementation in Go, on
//! the same files: finding the file key with each kind of identity, reading the
//! payload, writing files to each kind of recipient, parsing keys and making them.
//!
//! ```text
//! python3 scripts/testdata.py fetch --group bench
//! cargo run --release -p age-bench -- [--only TEXT] [--rounds 5] [--seconds 0.5]
//!     [--limit-mb 64] [--dir DIR] [DATA]
//! ```
//!
//! DATA is a file to encrypt, or a folder of them to join, by default the Silesia
//! corpus, cut to `--limit-mb` in all. age itself, in a program of its own
//! (`tools/age-bench/go`), makes every file and key. Files are in memory on both
//! sides, and read as `age --decrypt` reads them, through a buffer. Only the port's
//! `decrypt_file` is used, which also looks for armor. Files written go to a writer
//! that only counts, and the port's random bytes come from `getrandom`, as a program
//! gives them.
//!
//! Rounds take turns between the two, so that a noisy machine slows them alike,
//! and each round runs for at least `--seconds`. The output is a Markdown table of
//! the best speeds, which what else the machine does cannot make better, and the
//! port's over age's: above 1 the port is faster. Both must read the same bytes.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitCode, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hivepack_age::{
    ArmoredWriter, BoxedIdentity, BoxedRecipient, Identity, RandomSource, Recipient,
    ScryptIdentity, ScryptRecipient, X25519Identity, decrypt_file, encrypt,
    identities_to_recipients, parse_identities, parse_identities_file, parse_recipients_file,
};

type Result<T> = std::result::Result<T, String>;

const PASSPHRASE: &[u8] = b"correct-horse-battery-staple";
const CHUNK: usize = 1 << 16;

/// What a workload times.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Decrypt,
    Encrypt,
    ParseKeys,
    ParseRecipients,
    Keygen,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Input {
    Empty,
    Small,
    Big,
}

struct Workload {
    category: &'static str,
    name: &'static str,
    op: Op,
    /// Go's name for how it is encrypted.
    kind: &'static str,
    input: Input,
    /// Files or keys in each run.
    count: u64,
}

const fn work(
    category: &'static str,
    name: &'static str,
    kind: &'static str,
    input: Input,
    count: u64,
) -> Workload {
    Workload {
        category,
        name,
        op: Op::Decrypt,
        kind,
        input,
        count,
    }
}

const fn write(name: &'static str, kind: &'static str, input: Input, count: u64) -> Workload {
    Workload {
        category: "Writing a file",
        name,
        op: Op::Encrypt,
        kind,
        input,
        count,
    }
}

const fn on_keys(name: &'static str, op: Op, count: u64) -> Workload {
    Workload {
        category: "Parsing keys and making them",
        name,
        op,
        kind: "",
        input: Input::Empty,
        count,
    }
}

const KEYS: &str = "Finding the file key, in an empty file";
const WORKLOADS: &[Workload] = &[
    work(KEYS, "X25519", "x25519", Input::Empty, 200),
    work(
        KEYS,
        "X25519, the last of ten recipients",
        "x25519-ten",
        Input::Empty,
        200,
    ),
    work(KEYS, "ssh-ed25519", "ssh", Input::Empty, 200),
    work(
        KEYS,
        "Passphrase, scrypt at 2^14",
        "scrypt14",
        Input::Empty,
        1,
    ),
    work(
        KEYS,
        "Passphrase, scrypt at 2^18, age's default",
        "scrypt18",
        Input::Empty,
        1,
    ),
    work("Reading the payload", "Big file", "x25519", Input::Big, 1),
    work(
        "Reading the payload",
        "Big file, in ASCII armor",
        "armored",
        Input::Big,
        1,
    ),
    work(
        "Reading the payload",
        "Files of 4 KiB",
        "x25519",
        Input::Small,
        200,
    ),
    write("Empty, to X25519", "x25519", Input::Empty, 200),
    write("Empty, to ten X25519 keys", "x25519-ten", Input::Empty, 200),
    write("Empty, to ssh-ed25519", "ssh", Input::Empty, 200),
    write("Empty, scrypt at 2^14", "scrypt14", Input::Empty, 1),
    write(
        "Empty, scrypt at 2^18, age's default",
        "scrypt18",
        Input::Empty,
        1,
    ),
    write("Big file", "x25519", Input::Big, 1),
    write("Big file, in ASCII armor", "armored", Input::Big, 1),
    write("Files of 4 KiB", "x25519", Input::Small, 200),
    on_keys("A file of 1,000 age keys", Op::ParseKeys, 1000),
    on_keys("A file of 1,000 recipients", Op::ParseRecipients, 1000),
    on_keys("Making a key", Op::Keygen, 200),
];

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
        let bad = || format!("age's answer to `{request}`: {line}");
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

/// The recipients for files of `kind`, from the keys age wrote.
fn recipients(kind: &str, dir: &Path, random: &RandomSource) -> Result<Vec<BoxedRecipient>> {
    let mut list: Vec<BoxedRecipient> = Vec::new();
    match kind {
        "scrypt14" | "scrypt18" => {
            let mut r = ScryptRecipient::new(PASSPHRASE)?;
            r.set_work_factor(if kind == "scrypt14" { 14 } else { 18 });
            list.push(Box::new(r));
            return Ok(list);
        }
        "x25519-ten" => {
            for _ in 0..9 {
                let other = X25519Identity::generate(Some(random)).map_err(|e| e.to_string())?;
                list.push(Box::new(other.to_recipient()));
            }
        }
        _ => {}
    }
    let boxed = identity(kind, dir)?;
    let identities: Vec<&dyn Identity> = boxed
        .iter()
        .map(|id| id.as_ref() as &dyn Identity)
        .collect();
    list.extend(identities_to_recipients(&identities)?);
    Ok(list)
}

/// A writer that only counts.
struct Counter<'a>(&'a mut u64);

impl Write for Counter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        *self.0 += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Writes all of `data` to `w`, 64 KiB at a time.
fn write_all<W: Write>(w: &mut W, data: &[u8]) -> Result<()> {
    for chunk in data.chunks(CHUNK) {
        w.write_all(chunk).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn encrypt_all(
    data: &[u8],
    to: &[&dyn Recipient],
    armored: bool,
    random: &RandomSource,
    count: u64,
) -> Result<(Duration, u64)> {
    let mut value = 0;
    let start = Instant::now();
    for _ in 0..count {
        if armored {
            let dst = ArmoredWriter::new(Counter(&mut value));
            let mut w = encrypt(dst, to, Some(random)).map_err(|e| e.to_string())?;
            write_all(&mut w, data)?;
            let dst = w.finish().map_err(|e| e.to_string())?;
            dst.finish().map_err(|e| e.to_string())?;
        } else {
            let mut w =
                encrypt(Counter(&mut value), to, Some(random)).map_err(|e| e.to_string())?;
            write_all(&mut w, data)?;
            w.finish().map_err(|e| e.to_string())?;
        }
    }
    Ok((start.elapsed(), value))
}

/// The identity for files of `kind`, from the keys age wrote.
fn identity(kind: &str, dir: &Path) -> Result<Vec<BoxedIdentity>> {
    let open = |name: &str| File::open(dir.join(name)).map_err(|e| e.to_string());
    match kind {
        "x25519" | "x25519-ten" | "armored" => {
            let mut key = String::new();
            open("x25519.key")?
                .read_to_string(&mut key)
                .map_err(|e| e.to_string())?;
            let id = X25519Identity::parse(key.trim())?;
            Ok(vec![Box::new(id)])
        }
        "ssh" => parse_identities_file(open("ssh.key")?, std::sync::Arc::new(|_| Ok(Vec::new()))),
        "scrypt14" | "scrypt18" => Ok(vec![Box::new(ScryptIdentity::new(PASSPHRASE)?)]),
        _ => Err(format!("kind: {kind}")),
    }
}

fn decrypt_all(data: &[u8], identities: &[&dyn Identity], count: u64) -> Result<(Duration, u64)> {
    let mut buf = vec![0; CHUNK];
    let mut value = 0;
    let start = Instant::now();
    for _ in 0..count {
        let mut plain = decrypt_file(data, identities).map_err(|e| e.to_string())?;
        loop {
            let got = plain.read(&mut buf).map_err(|e| e.to_string())?;
            if got == 0 {
                break;
            }
            value += got as u64;
        }
    }
    Ok((start.elapsed(), value))
}

struct Options {
    only: Option<String>,
    rounds: usize,
    seconds: f64,
    limit_mb: usize,
    dir: Option<PathBuf>,
    data: PathBuf,
}

fn parse_options(repository: &Path) -> Result<Options> {
    let mut options = Options {
        only: None,
        rounds: 5,
        seconds: 0.5,
        limit_mb: 64,
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
            "--dir" => options.dir = Some(PathBuf::from(value()?)),
            _ if arg.starts_with("--") => return Err(format!("unknown option {arg}")),
            _ => options.data = PathBuf::from(arg),
        }
    }
    Ok(options)
}

/// The data to encrypt: the files of `data`, or `data` itself, cut to `limit`.
fn load(data: &Path, limit: usize) -> Result<Vec<u8>> {
    if data.is_file() {
        let mut bytes = std::fs::read(data).map_err(|e| e.to_string())?;
        bytes.truncate(limit);
        return Ok(bytes);
    }
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
    let mut out = Vec::with_capacity(limit);
    for path in paths {
        let mut bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
        bytes.truncate(share);
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

fn best(values: &[f64]) -> f64 {
    values.iter().copied().fold(f64::INFINITY, f64::min)
}

fn real_main() -> Result<()> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let options = parse_options(&repository)?;
    let dir = match &options.dir {
        Some(dir) => dir.clone(),
        None => repository
            .join("target")
            .join(format!("age-bench-{}", std::process::id())),
    };
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let dir = dir.canonicalize().map_err(|e| e.to_string())?;
    let mut go = Go::spawn(&repository.join("target/testdata/age-bench-go/oracle"))?;
    go.ask(&format!("keys {}", text(&dir)?))?;

    let random: RandomSource =
        Arc::new(|bytes: &mut [u8]| getrandom::fill(bytes).map_err(std::io::Error::other));

    let big = load(&options.data, options.limit_mb << 20)?;
    let inputs = [
        ("empty", &big[..0]),
        ("small", &big[..big.len().min(4096)]),
        ("big", &big[..]),
    ];
    for (name, bytes) in inputs {
        std::fs::write(dir.join(name), bytes).map_err(|e| e.to_string())?;
    }

    println!("| Workload | hivepack-age | age | Port / age |\n|---|---|---|---|");
    let mut category = "";
    for (index, w) in WORKLOADS.iter().enumerate() {
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
        let (input_name, input_len) = match w.input {
            Input::Empty => ("empty", 0),
            Input::Small => ("small", big.len().min(4096)),
            Input::Big => ("big", big.len()),
        };
        let input_path = dir.join(input_name);
        let input_bytes = &big[..input_len];
        let path = match w.op {
            Op::ParseKeys => dir.join("many.keys"),
            Op::ParseRecipients => dir.join("many.pub"),
            _ => dir.join(format!("file-{index}.age")),
        };
        if w.op == Op::Decrypt {
            go.ask(&format!(
                "make {} {} {}",
                text(&path)?,
                text(&input_path)?,
                w.kind
            ))?;
        }
        let bytes = match w.op {
            Op::Decrypt | Op::ParseKeys | Op::ParseRecipients => {
                std::fs::read(&path).map_err(|e| e.to_string())?
            }
            Op::Encrypt | Op::Keygen => Vec::new(),
        };
        let boxed = if w.op == Op::Decrypt {
            identity(w.kind, &dir)?
        } else {
            Vec::new()
        };
        let identities: Vec<&dyn Identity> = boxed
            .iter()
            .map(|id| id.as_ref() as &dyn Identity)
            .collect();
        let to = if w.op == Op::Encrypt {
            recipients(w.kind, &dir, &random)?
        } else {
            Vec::new()
        };
        let to: Vec<&dyn Recipient> = to.iter().map(|r| r.as_ref() as &dyn Recipient).collect();
        let request = match w.op {
            Op::Decrypt => format!(
                "decrypt {} {} {} {}",
                text(&path)?,
                w.kind,
                text(&dir)?,
                w.count
            ),
            Op::Encrypt => format!(
                "encrypt {} {} {} {}",
                text(&input_path)?,
                w.kind,
                text(&dir)?,
                w.count
            ),
            Op::ParseKeys => format!("parse {}", text(&path)?),
            Op::ParseRecipients => format!("recipients {}", text(&path)?),
            Op::Keygen => format!("keygen {}", w.count),
        };

        let mut port_times = Vec::new();
        let mut go_times = Vec::new();
        let (mut port_value, mut go_value) = (0, 0);
        for round in 0..options.rounds {
            // Which goes first changes each round.
            for port in [round % 2 == 0, round % 2 == 1] {
                let (mut total, mut runs) = (Duration::ZERO, 0u32);
                while runs == 0 || total.as_secs_f64() < options.seconds {
                    let (time, value) = if !port {
                        go.ask(&request)?
                    } else {
                        match w.op {
                            Op::Decrypt => decrypt_all(&bytes, &identities, w.count)?,
                            Op::Encrypt => encrypt_all(
                                input_bytes,
                                &to,
                                w.kind == "armored",
                                &random,
                                w.count,
                            )?,
                            Op::ParseKeys => {
                                let start = Instant::now();
                                let ids = parse_identities(&bytes[..])?;
                                (start.elapsed(), ids.len() as u64)
                            }
                            Op::ParseRecipients => {
                                let start = Instant::now();
                                let file = parse_recipients_file(&bytes[..])?;
                                (start.elapsed(), file.recipients.len() as u64)
                            }
                            Op::Keygen => {
                                let start = Instant::now();
                                for _ in 0..w.count {
                                    X25519Identity::generate(Some(&random))
                                        .map_err(|e| e.to_string())?;
                                }
                                (start.elapsed(), w.count)
                            }
                        }
                    };
                    total += time;
                    runs += 1;
                    if port {
                        port_value = value;
                    } else {
                        go_value = value;
                    }
                }
                let time = total.as_secs_f64() / f64::from(runs);
                if port {
                    port_times.push(time);
                } else {
                    go_times.push(time);
                }
            }
        }
        if port_value != go_value {
            return Err(format!(
                "{}, {}: the port got {port_value}, age {go_value}",
                w.category, w.name
            ));
        }
        let port_time = best(&port_times);
        let go_time = best(&go_times);
        let speed = |seconds: f64| {
            if matches!(w.input, Input::Big) {
                format!("{:.0} MB/s", input_len as f64 / seconds / 1e6)
            } else if matches!(w.op, Op::ParseKeys | Op::ParseRecipients | Op::Keygen) {
                format!("{:.0} k keys/s", w.count as f64 / seconds / 1e3)
            } else {
                format!("{:.1} files/s", w.count as f64 / seconds)
            }
        };
        println!(
            "| {} | {} | {} | {:.2}× |",
            w.name,
            speed(port_time),
            speed(go_time),
            go_time / port_time
        );
        std::io::stdout().flush().map_err(|e| e.to_string())?;
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
            eprintln!("age-bench: {e}");
            ExitCode::FAILURE
        }
    }
}
