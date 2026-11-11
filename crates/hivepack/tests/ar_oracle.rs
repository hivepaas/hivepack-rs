//! Comparison with libarchive's ar reader through `tools/ar-oracle`:
//! libarchive's own test archive (the `libarchive-ar` set), as it is and
//! damaged; archives libarchive's writers make, BSD's and SVR4's, as they
//! are and damaged; archives made here with what the writers do not make,
//! as they are and damaged. Both read every entry and all of its data, or
//! skip it; the headers, the data's length and hash, the errors and how the
//! archive ends must be the same.
//!
//! - With the oracle built, everything is compared with libarchive directly.
//! - Everywhere, including where it is not built (Windows, and the emulated
//!   i686 and s390x jobs), `testdata/oracle/ar.txt` replays answers
//!   libarchive gave earlier. `cargo test -p hivepack --all-features --test
//!   ar_oracle record_oracle_answers -- --ignored` rewrites that file.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "ar_support/mod.rs"]
mod support;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Read;
use std::path::PathBuf;

use hivepack::ar::{Error, Header, Reader};
use support::{
    Oracle, Rng, crafted, damage, field, hex, libarchive_archive, name, repository, unhex,
};

/// The width of `mode_t` where libarchive runs: 4 bytes on Linux, 2 on
/// macOS, where a mode keeps its low 16 bits.
fn mode_width(oracle: &mut Oracle) -> u32 {
    let reply = oracle.ask("sizes");
    reply
        .strip_prefix("ok ")
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("sizes: {reply}"))
}

fn message(e: &Error) -> String {
    e.message().map_or_else(|| "~".to_string(), |m| hex(&m))
}

fn fnv(data: &[u8], mut hash: u64) -> u64 {
    for &b in data {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

const FNV: u64 = 0xcbf29ce484222325;

fn header(format: i32, h: &Header, mode_width: u32) -> String {
    let mode = if mode_width == 2 {
        h.mode & 0xffff
    } else {
        h.mode
    };
    format!(
        "{format},{},{mode:o},{},{},{},{}",
        hex(&h.path),
        h.uid,
        h.gid,
        h.size,
        h.mod_time
    )
}

/// A reader that gives its bytes in pieces of random sizes: what the port
/// looks at must not depend on them.
struct Pieces<'a> {
    data: &'a [u8],
    rng: Rng,
}

impl Read for Pieces<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let most = match self.rng.below(4) {
            0 => 1 + self.rng.below(7) as usize,
            1 => 1 + self.rng.below(200) as usize,
            _ => 1 + self.rng.below(1 << 17) as usize,
        };
        let n = most.min(buf.len()).min(self.data.len());
        buf[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        Ok(n)
    }
}

/// The port's answer to `read <mode> <archive>`, as the oracle words it.
fn answer(archive: &[u8], mode: &str, mode_width: u32, rng: &mut Rng) -> String {
    let mode = mode.as_bytes();
    let mut ar = Reader::new(Pieces {
        data: archive,
        rng: Rng(rng.next() | 1),
    });
    let mut out = String::new();
    let mut first = true;
    loop {
        let next = ar.next();
        if first {
            if let Err(e @ Error::Unrecognized) = &next {
                return format!("fatal:{}", message(e));
            }
            out.push_str("open");
            first = false;
        }
        out.push('|');
        let h = match next {
            Ok(Some(h)) => h,
            Ok(None) => {
                out.push_str("eof");
                return out;
            }
            Err(e) => {
                let _ = write!(out, "fatal:{}", message(&e));
                return out;
            }
        };
        let format = ar.format().map_or(0, |f| f.code());
        let _ = write!(out, "ok;{}", header(format, &h, mode_width));
        if mode[1] == b'k' {
            out.push_str(";skip");
            continue;
        }
        // The data, in pieces of random sizes.
        let mut hash = FNV;
        let mut total: u64 = 0;
        let mut buf = vec![0; 1 << 16];
        let end = loop {
            let want = 1 + rng.below(buf.len() as u64) as usize;
            match ar.read(&mut buf[..want]) {
                Ok(0) => break "eof".to_string(),
                Ok(n) => {
                    hash = fnv(&buf[..n], hash);
                    total += n as u64;
                }
                Err(e) => break format!("fatal:{}", message(&Error::from(e))),
            }
        };
        let _ = write!(out, ";{total},{hash:016x},{end}");
        if end != "eof" {
            out.push_str("|stop");
            return out;
        }
    }
}

/// The ways an archive is read: in memory or as a stream, its data read or
/// skipped.
const MODES: [&str; 4] = ["md", "sd", "mk", "sk"];

/// What the comparisons saw: the kinds of errors, and how many answers.
#[derive(Default)]
struct Seen {
    kinds: BTreeMap<String, usize>,
    compared: usize,
}

impl Seen {
    /// The kinds of errors in an answer: each message up to its first
    /// number.
    fn add(&mut self, answer: &str) {
        self.compared += 1;
        for part in answer.split(['|', ';', ',']) {
            let Some(text) = part.strip_prefix("fatal:") else {
                continue;
            };
            let message = if text == "~" {
                b"none".to_vec()
            } else {
                unhex(text)
            };
            let message = String::from_utf8_lossy(&message);
            let kind: String = message
                .chars()
                .take_while(|c| !c.is_ascii_digit() && *c != '(')
                .collect();
            *self
                .kinds
                .entry(format!("fatal: {}", kind.trim()))
                .or_default() += 1;
        }
    }

    fn check(&self, kinds: &[&str]) {
        eprintln!("{} answers: {:#?}", self.compared, self.kinds);
        for kind in kinds {
            assert!(
                self.kinds.contains_key(*kind),
                "no {kind} in {:#?}",
                self.kinds
            );
        }
    }
}

/// Compares the port's answer to `read` with libarchive's, and gives it.
fn compare(
    oracle: &mut Oracle,
    mode_width: u32,
    what: &str,
    archive: &[u8],
    mode: &str,
    rng: &mut Rng,
    seen: &mut Seen,
) -> String {
    let want = oracle.ask(&format!("read {mode} {}", hex(archive)));
    let got = answer(archive, mode, mode_width, rng);
    assert_eq!(got, want, "{what} read with {mode}: {}", hex(archive));
    seen.add(&want);
    want
}

#[test]
fn port_matches_libarchive_on_its_archive() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let Some(archive) = libarchive_archive() else {
        return;
    };
    let width = mode_width(&mut oracle);
    let mut rng = Rng(0xa400_0001);
    let mut seen = Seen::default();
    for mode in MODES {
        let answer = compare(
            &mut oracle,
            width,
            "ar.ar",
            &archive,
            mode,
            &mut rng,
            &mut seen,
        );
        assert!(answer.ends_with("|eof"), "{answer}");
    }
    // Its long name, from the filename table, and its two short ones.
    let names: Vec<Vec<u8>> = {
        let mut ar = Reader::new(&archive[..]);
        std::iter::from_fn(|| ar.next().unwrap().map(|h| h.path)).collect()
    };
    assert_eq!(
        names,
        [&b"yyytttsssaaafff.o"[..], b"gghh.o", b"hhhhjjjjkkkkllll.o"]
    );
}

/// How many damaged copies of libarchive's archive.
const DAMAGED: u64 = 400;

#[test]
fn port_matches_libarchive_on_its_archive_damaged() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let Some(archive) = libarchive_archive() else {
        return;
    };
    let width = mode_width(&mut oracle);
    let mut rng = Rng(0xa400_0002);
    let mut seen = Seen::default();
    for i in 0..DAMAGED {
        let damaged = damage(&mut Rng(0xa4da_0000 + i), archive.clone());
        let mode = MODES[(i % 4) as usize];
        compare(
            &mut oracle,
            width,
            &format!("damaged {i}"),
            &damaged,
            mode,
            &mut rng,
            &mut seen,
        );
    }
    seen.check(&[
        "fatal: Incorrect file header signature",
        "fatal: Truncated ar archive",
    ]);
}

/// A request for libarchive's writers: entries of random names, long ones
/// among them (BSD's before their data, SVR4's in a filename table the
/// request gives first), modes, owners, times and data.
fn written_spec(rng: &mut Rng) -> String {
    let svr4 = rng.below(2) == 0;
    let count = rng.below(8) as usize;
    let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..count)
        .map(|_| {
            let len = rng.pick(&[1, 3, 14, 15, 16, 17, 30, 100]);
            let mut path = name(rng, len);
            path.retain(|&b| b != 0 && b != b'\n' && b != b'/' && b != b' ');
            if path.is_empty() {
                path.push(b'a');
            }
            let size = rng.pick(&[0, 1, 2, 5, 100, 4097]);
            (path, rng.bytes(size))
        })
        .collect();
    let mut lines = Vec::new();
    let mut line = |path: &[u8], data: &[u8], rng: &mut Rng| {
        let mode = rng.pick(&[0o644, 0o755, 0o600, 0o7777]);
        let uid = rng.pick(&[0, 1000, 99_999]);
        let gid = rng.pick(&[0, 100, 99_999]);
        let mtime: u64 = rng.pick(&[0, 1_700_000_000, 99_999_999_999]);
        lines.push(format!(
            "{} {mode:o} {uid} {gid} {mtime} {}",
            hex(path),
            hex(data)
        ));
    };
    if svr4 && entries.iter().any(|(p, _)| p.len() > 15) && rng.below(8) > 0 {
        let mut table = Vec::new();
        for (path, _) in entries.iter().filter(|(p, _)| p.len() > 15) {
            table.extend(path);
            table.extend(b"/\n");
        }
        line(b"//", &table, rng);
    }
    for (path, data) in &entries {
        line(path, data, rng);
    }
    let format = if svr4 { "svr4" } else { "bsd" };
    format!("write {format} {}", hex(lines.join("\n").as_bytes()))
}

/// Archives libarchive's writers make, as many as they do not refuse of
/// `count` requests.
fn written(oracle: &mut Oracle, rng: &mut Rng, count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .filter_map(|_| {
            let reply = oracle.ask(&written_spec(rng));
            reply.strip_prefix("ok ").map(unhex)
        })
        .collect()
}

#[test]
fn port_matches_libarchive_on_written_archives() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let width = mode_width(&mut oracle);
    let mut rng = Rng(0xa400_0003);
    let mut seen = Seen::default();
    let archives = written(&mut oracle, &mut rng, 300);
    assert!(archives.len() > 200, "only {} written", archives.len());
    for (i, archive) in archives.iter().enumerate() {
        let what = format!("written {i}");
        for mode in ["md", "sk"] {
            let answer = compare(
                &mut oracle,
                width,
                &what,
                archive,
                mode,
                &mut rng,
                &mut seen,
            );
            assert!(answer.ends_with("|eof"), "{what}: {answer}");
        }
        for d in 0..3 {
            let damaged = damage(&mut Rng(0xa4d1_0000 + i as u64 * 4 + d), archive.clone());
            let mode = MODES[(d % 4) as usize];
            compare(
                &mut oracle,
                width,
                &format!("{what} damaged {d}"),
                &damaged,
                mode,
                &mut rng,
                &mut seen,
            );
        }
    }
    seen.check(&["fatal: Incorrect file header signature"]);
}

/// How many crafted archives, by default; `AR_COUNT` and `AR_SEED` choose
/// others.
const CRAFTED: u64 = 1500;

#[test]
fn port_matches_libarchive_on_crafted_archives() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let width = mode_width(&mut oracle);
    let count = std::env::var("AR_COUNT")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(CRAFTED);
    let seed = std::env::var("AR_SEED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0xa4c4_0000u64);
    let mut rng = Rng(0xa400_0004 ^ seed);
    let mut seen = Seen::default();
    for i in 0..count {
        let archive = crafted(&mut Rng(seed + i));
        let what = format!("crafted {} (AR_SEED={seed})", seed + i);
        for mode in ["md", "sk"] {
            compare(
                &mut oracle,
                width,
                &what,
                &archive,
                mode,
                &mut rng,
                &mut seen,
            );
        }
        let damaged = damage(&mut Rng(0xa4d2_0000 ^ (seed + i)), archive);
        let mode = MODES[(i % 4) as usize];
        compare(
            &mut oracle,
            width,
            &format!("{what} damaged"),
            &damaged,
            mode,
            &mut rng,
            &mut seen,
        );
    }
    if count >= CRAFTED {
        seen.check(&[
            "fatal: Unrecognized archive format",
            "fatal: Incorrect file header signature",
            "fatal: Found entry with empty filename",
            "fatal: Invalid filename table size",
            "fatal: More than one filename table exists",
            "fatal: Invalid string table",
            "fatal: Can't find long filename for GNU/SVR",
            "fatal: Bad input file size",
            "fatal: Truncated input file",
            "fatal: Truncated ar archive",
            "fatal: none",
        ]);
    }
}

/// A field, as the writers would not write it, read the same.
#[test]
fn port_matches_libarchive_on_odd_fields() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let width = mode_width(&mut oracle);
    let mut rng = Rng(0xa400_0005);
    let mut seen = Seen::default();
    for i in 0..600u64 {
        let mut h = b"!<arch>\nname.o/         ".to_vec();
        let mut fields_rng = Rng(0xa4f1_0000 + i);
        h.extend(field(&mut fields_rng, 12, 1_700_000_000, 10, true));
        h.extend(field(&mut fields_rng, 6, 1000, 10, i % 3 == 0));
        h.extend(field(&mut fields_rng, 6, 100, 10, i % 3 == 1));
        h.extend(field(&mut fields_rng, 8, 0o100644, 8, true));
        h.extend(field(&mut fields_rng, 10, 3, 10, i % 2 == 0));
        h.extend(b"`\nabc\n");
        compare(
            &mut oracle,
            width,
            &format!("odd fields {i}"),
            &h,
            MODES[(i % 4) as usize],
            &mut rng,
            &mut seen,
        );
    }
}

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/ar.txt")
}

/// The crafted archive of the recorded answers numbered `i`, as it is or
/// damaged.
fn recorded_crafted(i: u64, damaged: bool) -> Vec<u8> {
    let archive = crafted(&mut Rng(0x2ec0_a400 + i));
    if damaged {
        damage(&mut Rng(0xda4a_a400 + i), archive)
    } else {
        archive
    }
}

/// How many of the requests of each kind have recorded answers.
const RECORDED_CRAFTED: u64 = 400;
const RECORDED_DAMAGED: u64 = 60;
const RECORDED_WRITTEN: usize = 30;

/// An answer short enough to keep.
const RECORDED_ANSWER_MAX: usize = 4 << 10;

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/ar.txt");
    let mut rng = Rng(0x7ec0_a401);
    let mut width = 4;
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        if let Some(rest) = line.strip_prefix("platform ") {
            width = rest.parse().unwrap();
            continue;
        }
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        let words: Vec<&str> = request.split(' ').collect();
        let got = match words[..] {
            ["read", mode, archive] => answer(&unhex(archive), mode, width, &mut rng),
            ["crafted", i, mode] => answer(
                &recorded_crafted(i.parse().unwrap(), false),
                mode,
                width,
                &mut rng,
            ),
            ["crafted-damaged", i, mode] => answer(
                &recorded_crafted(i.parse().unwrap(), true),
                mode,
                width,
                &mut rng,
            ),
            _ => panic!("unknown request {request:.100}"),
        };
        assert_eq!(got, want, "{request:.200}");
        checked += 1;
    }
    assert!(checked >= 1000, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/ar.txt from the oracle"]
fn record_oracle_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let width = mode_width(&mut oracle);
    let mut text = format!(
        "# Answers from libarchive 3.8.10's ar reader (tools/ar-oracle), replayed by\n\
         # crates/hivepack/tests/ar_oracle.rs. \"read <mode> <archive>\" is the oracle's request:\n\
         # libarchive's test archive, damaged copies of it, and archives its writers made;\n\
         # \"crafted <i> <mode>\" is an archive made by the test, \"crafted-damaged <i> <mode>\" its\n\
         # damaged copy. Recorded where mode_t is as many bytes wide as \"platform\" says.\n\
         # Regenerate with: cargo test -p hivepack --all-features --test ar_oracle record_oracle_answers -- --ignored\n\
         platform {width}\n"
    );
    let ask = |oracle: &mut Oracle, text: &mut String, request: String, oracle_request: String| {
        let reply = oracle.ask(&oracle_request);
        if reply.len() <= RECORDED_ANSWER_MAX {
            let _ = writeln!(text, "{request}\t{reply}");
        }
    };
    let archive = libarchive_archive().expect("libarchive's archive");
    for mode in MODES {
        let request = format!("read {mode} {}", hex(&archive));
        ask(&mut oracle, &mut text, request.clone(), request);
    }
    for i in 0..RECORDED_DAMAGED {
        let damaged = damage(&mut Rng(0xa4da_0000 + i), archive.clone());
        let request = format!("read {} {}", MODES[(i % 4) as usize], hex(&damaged));
        ask(&mut oracle, &mut text, request.clone(), request);
    }
    let mut rng = Rng(0x7ec0_a402);
    let written: Vec<Vec<u8>> = written(&mut oracle, &mut rng, 200)
        .into_iter()
        .filter(|a| a.len() <= 1500)
        .take(RECORDED_WRITTEN)
        .collect();
    for archive in written {
        let request = format!("read md {}", hex(&archive));
        ask(&mut oracle, &mut text, request.clone(), request);
    }
    for i in 0..RECORDED_CRAFTED {
        let archive = recorded_crafted(i, false);
        for mode in ["md", "sk"] {
            ask(
                &mut oracle,
                &mut text,
                format!("crafted {i} {mode}"),
                format!("read {mode} {}", hex(&archive)),
            );
        }
        let mode = MODES[(i % 4) as usize];
        ask(
            &mut oracle,
            &mut text,
            format!("crafted-damaged {i} {mode}"),
            format!("read {mode} {}", hex(&recorded_crafted(i, true))),
        );
    }
    std::fs::create_dir_all(recorded_path().parent().expect("folder")).expect("folder");
    std::fs::write(recorded_path(), text).expect("written");
}
