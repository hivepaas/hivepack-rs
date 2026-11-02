// hivepack::rar's tests. UnRAR's license, which they are under with the
// crate:
//
// UnRAR source code may be used in any software to handle RAR archives
// without limitations free of charge, but cannot be used to develop RAR
// (WinRAR) compatible archiver and to re-create RAR compression algorithm,
// which is proprietary. Distribution of modified UnRAR source code in
// separate form or as a part of other software is permitted, provided that
// full text of this paragraph, starting from "UnRAR source code" words, is
// included in license, or in documentation if license is not available, and
// in source code comments of resulting package.

//! What the comparison tests with UnRAR share: the oracle program, built by
//! `scripts/testdata.py`, the test archives, a seeded generator, and the
//! text forms of the requests and answers.

// Test helpers: a broken oracle should stop the test.
#![allow(dead_code, clippy::expect_used, clippy::panic)]

pub mod patch;

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

/// libarchive's RAR test archives (the `libarchive-rar` set), by name, or
/// none with a note when they are not fetched; CI lists the `core` group
/// in `HIVEPACK_TESTDATA_REQUIRED`, and then they must be there.
/// The RAR archives that rarfile, junrar and unrar.rs keep for their tests,
/// whatever their names, or nothing if they are not fetched.
pub fn other_projects_archives() -> Vec<(String, Vec<u8>)> {
    fn walk(folder: &std::path::Path, found: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(folder).expect("the folder") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                walk(&path, found);
            } else {
                found.push(path);
            }
        }
    }
    let mut archives = Vec::new();
    for set in ["rarfile-tests", "junrar-tests", "unrar-rs-tests"] {
        let folder = testdata().join(set);
        if !folder.join(".complete").exists() {
            let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
            assert!(
                !required.split(',').any(|g| g == "all" || g == "generated"),
                "{set} is missing: run `python3 scripts/testdata.py fetch`"
            );
            eprintln!("skipping: {set} is not fetched");
            continue;
        }
        let mut found = Vec::new();
        walk(&folder, &mut found);
        found.sort();
        for path in found {
            let is_archive = path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
                let e = e.to_ascii_lowercase();
                e == "rar"
                    || e == "sfx"
                    || e == "exe"
                    || e.starts_with('r')
                        && e.len() == 3
                        && e[1..].bytes().all(|b| b.is_ascii_digit())
            });
            if is_archive {
                let name = path
                    .strip_prefix(&folder)
                    .expect("in it")
                    .display()
                    .to_string();
                archives.push((
                    format!("{set}/{name}"),
                    std::fs::read(&path).expect("the archive"),
                ));
            }
        }
    }
    archives
}

pub fn libarchive_archives() -> Vec<(String, Vec<u8>)> {
    let folder = testdata().join("libarchive-rar");
    if !folder.join(".complete").exists() {
        let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
        assert!(
            !required.split(',').any(|g| g == "all" || g == "core"),
            "libarchive's RAR archives are missing: run `python3 scripts/testdata.py fetch`"
        );
        eprintln!("skipping: libarchive's RAR archives are not fetched");
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
    /// The oracle built by `scripts/testdata.py`, or `None` with a note when
    /// it has not been built. CI lists the `generated` group in
    /// `HIVEPACK_TESTDATA_REQUIRED` where it builds the oracle, and then a
    /// missing oracle fails the test.
    pub fn spawn() -> Option<Oracle> {
        let folder = testdata().join("rar-oracle");
        if !folder.join(".complete").exists() {
            let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
            assert!(
                !required.split(',').any(|g| g == "all" || g == "generated"),
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
            line != "bad" && !line.is_empty() && !line.ends_with(" bad"),
            "the oracle answered {line:?} to {request:.200}"
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

pub fn fnv64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// An answer as the recorded file keeps it: as it is when short, else its
/// FNV-1a hash.
pub fn recorded_form(answer: &str) -> String {
    if answer.len() <= 160 {
        answer.to_string()
    } else {
        format!("fnv64:{:016x}", fnv64(answer.as_bytes()))
    }
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
}

/// Bytes changed, bits flipped, cut short or lengthened.
pub fn damage(rng: &mut Rng, stream: &[u8]) -> Vec<u8> {
    let mut damaged = stream.to_vec();
    for _ in 0..1 + rng.below(3) {
        if damaged.is_empty() {
            break;
        }
        let at = rng.below(damaged.len() as u64) as usize;
        match rng.below(4) {
            0 => damaged[at] ^= 1 << rng.below(8),
            1 => damaged[at] = rng.next() as u8,
            2 => damaged.truncate(at),
            _ => damaged.insert(at, rng.next() as u8),
        }
    }
    damaged
}
