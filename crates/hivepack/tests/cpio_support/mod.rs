//! What the tests share: the oracle program, built with libarchive by
//! `scripts/testdata.py`, libarchive's test archives, a seeded generator,
//! and the text forms of the requests and answers.

// Test helpers: a broken oracle should stop the test.
#![allow(dead_code, clippy::expect_used, clippy::unwrap_used, clippy::panic)]

pub mod archive;

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

pub fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Where `scripts/testdata.py` puts what it fetches and builds.
pub fn testdata() -> PathBuf {
    std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| repository().join("target/testdata"))
}

/// Whether CI requires `group` (`HIVEPACK_TESTDATA_REQUIRED`).
fn required(group: &str) -> bool {
    let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
    required.split(',').any(|g| g == "all" || g == group)
}

/// libarchive's cpio and RPM test archives (the `libarchive-cpio` set), by
/// name, or none with a note when they are not fetched; CI lists the
/// `core` group in `HIVEPACK_TESTDATA_REQUIRED`, and then they must be
/// there.
pub fn libarchive_archives() -> Vec<(String, Vec<u8>)> {
    let folder = testdata().join("libarchive-cpio");
    if !folder.join(".complete").exists() {
        assert!(
            !required("core"),
            "libarchive's cpio archives are missing: run `python3 scripts/testdata.py fetch`"
        );
        eprintln!("skipping: libarchive's cpio archives are not fetched");
        return Vec::new();
    }
    let mut archives: Vec<(String, Vec<u8>)> = std::fs::read_dir(&folder)
        .expect("the folder")
        .map(|entry| entry.expect("an entry").path())
        .filter(|path| path.file_name().is_some_and(|n| n != ".complete"))
        .map(|path| {
            let name = path
                .file_name()
                .expect("a name")
                .to_string_lossy()
                .into_owned();
            (name, std::fs::read(&path).expect("the archive"))
        })
        .collect();
    archives.sort();
    archives
}

/// The oracle program, running.
pub struct Oracle {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Oracle {
    /// `tools/cpio-oracle` built by `scripts/testdata.py`, or `None` with a
    /// note when it has not been built. CI lists the `generated` group in
    /// `HIVEPACK_TESTDATA_REQUIRED` where it builds the oracles, and then a
    /// missing oracle fails the test.
    pub fn spawn() -> Option<Oracle> {
        let folder = testdata().join("cpio-oracle");
        if !folder.join(".complete").exists() {
            assert!(
                !required("generated"),
                "the oracle is missing: run `python3 scripts/testdata.py fetch --group generated`"
            );
            eprintln!(
                "skipping: the oracle is not built (scripts/testdata.py fetch --group generated)"
            );
            return None;
        }
        let mut child = Command::new(folder.join("oracle"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("the oracle starts");
        let input = child.stdin.take().expect("stdin");
        let output = BufReader::new(child.stdout.take().expect("stdout"));
        Some(Oracle {
            child,
            input,
            output,
        })
    }

    pub fn ask(&mut self, request: &str) -> String {
        writeln!(self.input, "{request}").expect("request sent");
        self.input.flush().expect("request sent");
        let mut line = String::new();
        self.output.read_line(&mut line).expect("answer read");
        let line = line.trim_end().to_string();
        assert!(
            !line.is_empty() && !line.contains("BAD"),
            "the oracle answered {line:.300} to {request:.200}"
        );
        line
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".into();
    }
    let mut text = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

pub fn unhex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// xorshift64*, so that failures can be replayed.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    pub fn pick<T: Copy>(&mut self, values: &[T]) -> T {
        values[self.below(values.len() as u64) as usize]
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }

    /// Fewer than `n` random bytes.
    pub fn bytes_below(&mut self, n: u64) -> Vec<u8> {
        let len = self.below(n) as usize;
        self.bytes(len)
    }
}

/// A gzip stream's data, as far as it goes.
pub fn gunzip(data: &[u8]) -> Vec<u8> {
    use hivepack::deflate::{Flush, InBuffer, Inflate, OutBuffer, Status};
    let mut z = Inflate::new(16 + 15).unwrap();
    let mut out = Vec::new();
    let mut input = InBuffer::new(data);
    let mut piece = vec![0; 1 << 16];
    loop {
        let mut output = OutBuffer::new(&mut piece);
        let status = z.inflate(&mut output, &mut input, Flush::NoFlush);
        let written = output.pos;
        out.extend_from_slice(&piece[..written]);
        match status {
            Ok(Status::StreamEnd) => return out,
            Ok(_) if written > 0 => {}
            _ => panic!("not gzip: {status:?}"),
        }
    }
}

/// A bzip2 stream's data.
pub fn bunzip2(data: &[u8]) -> Vec<u8> {
    use hivepack::bzip2::{Decompress, InBuffer, OutBuffer, Status};
    let mut d = Decompress::new(false);
    let mut out = Vec::new();
    let mut input = InBuffer::new(data);
    let mut piece = vec![0; 1 << 16];
    loop {
        let mut output = OutBuffer::new(&mut piece);
        let status = d.decompress(&mut output, &mut input);
        let written = output.pos;
        out.extend_from_slice(&piece[..written]);
        match status {
            Ok(Status::StreamEnd) => return out,
            Ok(_) if written > 0 => {}
            _ => panic!("not bzip2: {status:?}"),
        }
    }
}
