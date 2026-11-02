//! What the tests share: the oracle program, built with libarchive by
//! `scripts/testdata.py`, a seeded generator, and the text forms of the
//! requests and answers.

// Test helpers: a broken oracle should stop the test.
#![allow(dead_code, clippy::expect_used, clippy::panic)]

pub mod archive;

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::Duration;

pub fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The oracle program, running, with a thread that reads its answers so
/// that a request libarchive never answers (it can loop for ever) times
/// out.
pub struct Oracle {
    folder: PathBuf,
    child: Child,
    input: ChildStdin,
    answers: Receiver<String>,
}

/// How long the oracle may take to answer.
const PATIENCE: Duration = Duration::from_secs(30);

impl Oracle {
    /// The oracle `name` (`xar-oracle`) built by `scripts/testdata.py`,
    /// or `None` with a note when it has not been built. CI lists the
    /// `generated` group in `HIVEPACK_TESTDATA_REQUIRED` where it builds the
    /// oracles, and then a missing oracle fails the test.
    pub fn spawn(name: &str) -> Option<Oracle> {
        let cache = std::env::var_os("HIVEPACK_TESTDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| repository().join("target/testdata"));
        let folder = cache.join(name);
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
        Some(Oracle::start(folder))
    }

    fn start(folder: PathBuf) -> Oracle {
        let mut child = Command::new(folder.join("oracle"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("the oracle starts");
        let input = child.stdin.take().expect("stdin");
        let output = BufReader::new(child.stdout.take().expect("stdout"));
        let (send, answers) = channel();
        std::thread::spawn(move || {
            for line in output.lines() {
                let Ok(line) = line else { return };
                if send.send(line).is_err() {
                    return;
                }
            }
        });
        Oracle {
            folder,
            child,
            input,
            answers,
        }
    }

    pub fn ask(&mut self, request: &str) -> String {
        self.ask_or_hang(request)
            .unwrap_or_else(|| panic!("the oracle did not answer {request:.200}"))
    }

    /// The answer, or `None` when the oracle did not answer in time: it is
    /// then started again.
    pub fn ask_or_hang(&mut self, request: &str) -> Option<String> {
        writeln!(self.input, "{request}").expect("request sent");
        self.input.flush().expect("request sent");
        match self.answers.recv_timeout(PATIENCE) {
            Ok(line) => {
                let line = line.trim_end().to_string();
                assert!(
                    line != "bad" && !line.is_empty() && !line.ends_with(" bad"),
                    "the oracle answered {line:?} to {request:.200}"
                );
                Some(line)
            }
            Err(RecvTimeoutError::Timeout) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
                *self = Oracle::start(self.folder.clone());
                None
            }
            Err(RecvTimeoutError::Disconnected) => panic!("the oracle died on {request:.200}"),
        }
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
}

/// A set of test files in the test data cache (`scripts/testdata.py`), or
/// `None` with a note when it has not been fetched; a missing set fails
/// the test where CI requires its group.
pub fn testdata(set: &str, group: &str) -> Option<PathBuf> {
    let cache = std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| repository().join("target/testdata"));
    let folder = cache.join(set);
    if folder.join(".complete").exists() {
        return Some(folder);
    }
    let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
    assert!(
        !required.split(',').any(|g| g == "all" || g == group),
        "the set {set} is missing: run `python3 scripts/testdata.py fetch --group {group}`"
    );
    eprintln!("skipping: {set} is not fetched (scripts/testdata.py fetch --group {group})");
    None
}
