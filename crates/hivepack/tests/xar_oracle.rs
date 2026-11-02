//! Comparison with libarchive's XAR reader through `tools/xar-oracle`:
//! libarchive's own test archives (its `.uu` files, and the archives
//! `test_read_format_xar.c` holds as byte arrays), as they are and
//! damaged; archives libarchive's writer makes from random trees, as they
//! are and damaged; small archives of macOS's `xar` and `pkgbuild`; and
//! archives made here with tables of contents that use every element and
//! attribute the reader knows, and many it does not, as they are and
//! damaged. Both read every entry and all of its data; the headers,
//! extended attributes, warnings, the data's length and hash, the errors
//! and how the archive ends must be the same.
//!
//! The messages of libxml2's errors are libxml2's own, which the port does
//! not copy (`docs/xar.md`): "XML Parsing error: ..." is compared up to
//! its prefix.
//!
//! - With the oracle built, everything is compared with libarchive directly.
//! - Everywhere, including where it is not built, `testdata/oracle/xar.txt`
//!   replays answers libarchive gave earlier for the archives the test
//!   makes again without it. `cargo test -p hivepack --all-features --test xar_oracle
//!   record_oracle_answers -- --ignored` rewrites that file.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "xar_support/mod.rs"]
mod support;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Cursor, Read};
use std::path::PathBuf;

use hivepack::xar::{Dev, Error, Header, Reader};
use support::archive;
use support::{Oracle, Rng, hex, repository, testdata, unhex};

/// How much of an entry's data is compared.
const LIMIT: u64 = 64 << 20;

/// `ARCHIVE_FORMAT_XAR`.
const FORMAT_XAR: i32 = 0xA0000;

/// The widths of `mode_t` and `dev_t` where libarchive runs, which narrow
/// what it gives, and how its system puts device numbers together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Sizes {
    mode: u32,
    dev: u32,
    linux: bool,
}

/// The sizes of Linux, where the recorded answers were made.
const LINUX: Sizes = Sizes {
    mode: 4,
    dev: 8,
    linux: true,
};

fn sizes(oracle: &mut Oracle) -> Sizes {
    let reply = oracle.ask("sizes");
    let parts: Vec<&str> = reply.split(' ').collect();
    Sizes {
        mode: parts[1].parse().unwrap(),
        dev: parts[2].parse().unwrap(),
        linux: parts[3] == "linux",
    }
}

fn bytes(b: &Option<Vec<u8>>) -> String {
    match b {
        None => "~".into(),
        Some(b) => hex(b),
    }
}

fn number<T: ToString>(n: Option<T>) -> String {
    n.map_or_else(|| "~".into(), |n| n.to_string())
}

/// `makedev`, `major` and `minor` of glibc or of macOS.
fn makedev(sizes: Sizes, major: u64, minor: u64) -> u64 {
    if sizes.linux {
        let (ma, mi) = (major & 0xffff_ffff, minor & 0xffff_ffff);
        ((ma & 0xfff) << 8) | ((ma & 0xffff_f000) << 32) | (mi & 0xff) | ((mi & 0xffff_ff00) << 12)
    } else {
        ((major << 24) | minor) & 0xffff_ffff
    }
}

fn major(sizes: Sizes, dev: u64) -> u64 {
    if sizes.linux {
        ((dev >> 32) & 0xffff_f000) | ((dev >> 8) & 0xfff)
    } else {
        (dev >> 24) & 0xff
    }
}

fn minor(sizes: Sizes, dev: u64) -> u64 {
    if sizes.linux {
        ((dev >> 12) & 0xffff_ff00) | (dev & 0xff)
    } else {
        dev & 0xff_ffff
    }
}

/// A `dev_t` as the oracle prints it: signed, as wide as it is.
fn dev_t(sizes: Sizes, v: u64) -> i64 {
    if sizes.dev == 4 {
        i64::from(v as u32 as i32)
    } else {
        v as i64
    }
}

fn header(format: i32, h: &Header, sizes: Sizes) -> String {
    let mode = if sizes.mode == 2 {
        h.mode & 0xffff
    } else {
        h.mode
    };
    let dev = match h.dev {
        None => "~".to_string(),
        Some(Dev::Number(d)) => format!(
            "{}/{}/{}",
            dev_t(sizes, d),
            dev_t(sizes, major(sizes, d)),
            dev_t(sizes, minor(sizes, d))
        ),
        Some(Dev::Parts { major, minor }) => format!(
            "{}/{}/{}",
            dev_t(sizes, makedev(sizes, major, minor)),
            dev_t(sizes, major),
            dev_t(sizes, minor)
        ),
    };
    format!(
        "{format},{},{mode:o},{},{},{},{},{},{},{},{},{},~,{},{dev},{},{},{}",
        bytes(&h.path),
        h.uid,
        h.gid,
        bytes(&h.uname),
        bytes(&h.gname),
        h.nlink,
        h.size as i64,
        number(h.atime),
        number(h.mtime),
        number(h.ctime),
        h.ino,
        bytes(&h.symlink),
        bytes(&h.hardlink),
        bytes(&h.fflags_text),
    )
}

fn message(e: &Error) -> String {
    bytes(&e.message())
}

/// The port's answer to `read <mode> <archive>`, as the oracle words it;
/// the data is read in pieces of random sizes.
fn answer(archive: &[u8], mode: &str, sizes: Sizes, rng: &mut Rng) -> String {
    if mode == "m" {
        answer_with(Reader::seekable(Cursor::new(archive)), sizes, rng)
    } else {
        // Not seekable: the reader cannot know the input is a cursor.
        let r: Box<dyn Read + '_> = Box::new(archive);
        answer_with(Reader::new(r), sizes, rng)
    }
}

fn answer_with<R: Read>(mut xar: Reader<R>, sizes: Sizes, rng: &mut Rng) -> String {
    let mut out = String::new();
    let mut first = true;
    loop {
        let next = xar.next();
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
            Err(e @ Error::CannotSeek) => {
                let _ = write!(out, "failed:{}", message(&e));
                continue;
            }
            Err(e) => {
                let _ = write!(out, "fatal:{}", message(&e));
                return out;
            }
        };
        match &h.warning {
            None => out.push_str("ok"),
            Some(w) => {
                let _ = write!(out, "warn:{}", hex(&w.message()));
            }
        }
        let format = if xar.format_name().is_some() {
            FORMAT_XAR
        } else {
            0
        };
        let _ = write!(out, ";{};", header(format, &h, sizes));
        if h.xattrs.is_empty() {
            out.push('-');
        } else {
            let list: Vec<String> = h
                .xattrs
                .iter()
                .map(|x| format!("{}={}", hex(&x.name), hex(&x.value)))
                .collect();
            out.push_str(&list.join("."));
        }

        // The data, in pieces of random sizes.
        let mut hash: u64 = 0xcbf29ce484222325;
        let mut total: u64 = 0;
        let mut buf = vec![0; 1 << 17];
        let end = loop {
            let want = match rng.below(4) {
                0 => 1 + rng.below(16) as usize,
                _ => 1 + rng.below(buf.len() as u64) as usize,
            };
            match xar.read(&mut buf[..want]) {
                Ok(0) => break "eof".to_string(),
                Ok(n) => {
                    let keep = (n as u64).min(LIMIT - total) as usize;
                    for &b in &buf[..keep] {
                        hash ^= u64::from(b);
                        hash = hash.wrapping_mul(0x100000001b3);
                    }
                    total += keep as u64;
                    if keep < n {
                        break "limit".to_string();
                    }
                }
                Err(e) => break format!("fatal:{}", message(&Error::from(e))),
            }
        };
        let _ = write!(out, ";{total},{hash:016x},-,{end}");
        if end != "eof" {
            out.push_str("|stop");
            return out;
        }
    }
}

/// The message as compared: libxml2's own text after "XML Parsing error: "
/// is left out, and "Unable to allocate copy buffer", which libarchive
/// says where it cannot have as much memory as a damaged size asks for,
/// is "Truncated archive file", as the port says (`docs/xar.md`).
fn normalized_message(text: &str) -> String {
    if text == "~" || text == "-" {
        return text.to_string();
    }
    let m = unhex(text);
    if m.starts_with(b"XML Parsing error: ") {
        return hex(b"XML Parsing error: ...");
    }
    if m == b"Unable to allocate copy buffer" {
        return hex(b"Truncated archive file");
    }
    text.to_string()
}

/// An answer with its messages normalized.
fn normalized(answer: &str) -> String {
    let mut out = String::with_capacity(answer.len());
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut String| {
        let mut t = token.as_str();
        for prefix in ["warn:", "failed:", "fatal:"] {
            if let Some(rest) = t.strip_prefix(prefix) {
                out.push_str(prefix);
                out.push_str(&normalized_message(rest));
                t = "";
                break;
            }
        }
        out.push_str(t);
        token.clear();
    };
    for c in answer.chars() {
        if matches!(c, '|' | ';' | ',') {
            flush(&mut token, &mut out);
            out.push(c);
        } else {
            token.push(c);
        }
    }
    flush(&mut token, &mut out);
    out
}

/// The answer with the data of its last entry left out where its size or
/// checksum is wrong. libarchive gives data that is not compressed in one
/// block, all of it, when the archive is in memory, and so nothing of it
/// when its size or checksum is wrong at the end; the port gives it in
/// pieces as it reads it, as libarchive does from an input that comes in
/// blocks (`docs/xar.md`). Compressed data comes in the same blocks from
/// both.
fn stored_end(answer: &str) -> String {
    let Some(rest) = answer.strip_suffix("|stop") else {
        return answer.to_string();
    };
    let Some(at) = rest.rfind(';') else {
        return answer.to_string();
    };
    let data: Vec<&str> = rest[at + 1..].split(',').collect();
    let checksum = format!("fatal:{}", hex(b"Checksum error"));
    let size = format!("fatal:{}", hex(b"Decompressed size error"));
    if data.len() == 4 && (data[3] == checksum || data[3] == size) {
        return format!("{};0,cbf29ce484222325,-,{}|stop", &rest[..at], data[3]);
    }
    answer.to_string()
}

/// Whether a difference between the answers is one the widths of
/// `mode_t` and `dev_t` explain: where they are narrower than on Linux,
/// libarchive refuses larger values in the TOC, which the port takes.
fn explained_by_widths(sizes: Sizes, archive: &[u8]) -> bool {
    if sizes.mode == 4 && sizes.dev == 8 {
        return false;
    }
    let toc = archive::toc_start(archive);
    let text = String::from_utf8_lossy(&toc);
    let mut wide = false;
    for (tag, base, limit) in [
        (
            "mode",
            8,
            if sizes.mode == 2 {
                0xffff
            } else {
                u64::MAX >> 32
            },
        ),
        (
            "deviceno",
            10,
            if sizes.dev == 4 {
                0x7fff_ffff
            } else {
                u64::MAX
            },
        ),
        (
            "major",
            10,
            if sizes.dev == 4 {
                0x7fff_ffff
            } else {
                u64::MAX
            },
        ),
        (
            "minor",
            10,
            if sizes.dev == 4 {
                0x7fff_ffff
            } else {
                u64::MAX
            },
        ),
    ] {
        let open = format!("<{tag}>");
        for piece in text.split(&open).skip(1) {
            let digits: String = piece.chars().take_while(|c| c.is_digit(base)).collect();
            if u64::from_str_radix(&digits, base).map_or(!digits.is_empty(), |v| v > limit) {
                wide = true;
            }
        }
    }
    wide
}

/// Compares the port's answer with libarchive's, and gives libarchive's.
fn compare(
    oracle: &mut Oracle,
    sizes: Sizes,
    what: &str,
    archive: &[u8],
    mode: &str,
    rng: &mut Rng,
) -> String {
    let got = answer(archive, mode, sizes, rng);
    let Some(want) = oracle.ask_or_hang(&format!("read {mode} {}", hex(archive))) else {
        // libarchive goes round its list of hard links' originals for ever
        // when one is made an original twice (`docs/xar.md`): the port
        // fails as it does for the other repeats.
        let refused = format!("|fatal:{}", hex(b"File with multiple link attributes"));
        assert!(
            got.ends_with(&refused),
            "{what} read with {mode}: libarchive hangs, the port answers {got:.3000}"
        );
        return "hang".to_string();
    };
    if normalized(&got) != normalized(&want)
        && normalized(&stored_end(&got)) != normalized(&want)
        && !explained_by_widths(sizes, archive)
    {
        let dump = repository().join("target/xar-mismatch.xar");
        let _ = std::fs::write(&dump, archive);
        panic!(
            "{what} read with {mode} (saved in {}):\n port: {got:.3000}\n  lib: {want:.3000}",
            dump.display()
        );
    }
    want
}

/// libarchive's `.uu` test archives, uudecoded by `scripts/testdata.py`.
fn libarchive_uu() -> Vec<(String, Vec<u8>)> {
    let Some(folder) = testdata("libarchive-xar", "core") else {
        return Vec::new();
    };
    let mut names: Vec<PathBuf> = std::fs::read_dir(&folder)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "xar"))
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|p| {
            let name = p.file_stem().unwrap().to_string_lossy().into_owned();
            (name, std::fs::read(&p).unwrap())
        })
        .collect()
}

/// The archives `test_read_format_xar.c` holds as C arrays, by name.
fn libarchive_arrays() -> Vec<(String, Vec<u8>)> {
    let Some(folder) = testdata("libarchive-3.8.10-source", "core") else {
        return Vec::new();
    };
    let source = folder.join("libarchive-3.8.10/libarchive/test/test_read_format_xar.c");
    let text = std::fs::read_to_string(source).unwrap();
    let mut out = Vec::new();
    let mut rest = text.as_str();
    while let Some(at) = rest.find("static unsigned char ") {
        rest = &rest[at + "static unsigned char ".len()..];
        let name = rest[..rest.find('[').unwrap()].to_string();
        let body = &rest[rest.find('{').unwrap() + 1..rest.find("};").unwrap()];
        let data: Vec<u8> = body
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
            .collect();
        out.push((name, data));
    }
    assert!(out.len() >= 14, "only {} arrays", out.len());
    out
}

/// All of libarchive's test archives.
fn libarchive_archives() -> Vec<(String, Vec<u8>)> {
    let mut all = libarchive_uu();
    all.extend(libarchive_arrays());
    all
}

/// The ways an archive is read: in memory (seekable) or as a stream.
const MODES: [&str; 2] = ["m", "s"];

#[test]
fn port_matches_libarchive_on_its_archives() {
    let Some(mut oracle) = Oracle::spawn("xar-oracle") else {
        return;
    };
    let sizes = sizes(&mut oracle);
    let mut rng = Rng(0x0a7c_4a7e);
    for (name, archive) in libarchive_archives() {
        for mode in MODES {
            compare(&mut oracle, sizes, &name, &archive, mode, &mut rng);
        }
    }
}

/// libarchive's archive `name`, damaged the `i`th way.
fn libarchive_damaged(name: &str, archive: &[u8], i: u64) -> Vec<u8> {
    let seed = name.bytes().fold(0x9e37_79b9_7f4a_7c15u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    });
    let mut rng = Rng(seed ^ (i + 1).wrapping_mul(0x2545_f491_4f6c_dd1d));
    archive::damage(&mut rng, archive)
}

/// How many damaged copies of each of libarchive's archives.
const DAMAGED: u64 = 150;

#[test]
fn port_matches_libarchive_on_its_archives_damaged() {
    let Some(mut oracle) = Oracle::spawn("xar-oracle") else {
        return;
    };
    let sizes = sizes(&mut oracle);
    let mut rng = Rng(0x0dd_4a7e);
    let mut seen = BTreeMap::new();
    for (name, archive) in libarchive_archives() {
        for i in 0..DAMAGED {
            let damaged = libarchive_damaged(&name, &archive, i);
            let mode = MODES[(i % 2) as usize];
            let answer = compare(
                &mut oracle,
                sizes,
                &format!("{name} damaged {i}"),
                &damaged,
                mode,
                &mut rng,
            );
            ends(&answer, &mut seen);
        }
    }
    eprintln!("{seen:#?}");
}

/// The kinds of warnings and errors in an answer: each message up to its
/// first number or colon.
fn ends(answer: &str, seen: &mut BTreeMap<String, usize>) {
    if answer.ends_with("|eof") {
        *seen.entry("(read to the end)".into()).or_default() += 1;
    }
    *seen.entry("(entries)".into()).or_default() += answer.matches("|ok;").count();
    for part in answer.split(['|', ';', ',']) {
        for (tag, text) in [
            ("warn", part.strip_prefix("warn:")),
            ("failed", part.strip_prefix("failed:")),
            ("fatal", part.strip_prefix("fatal:")),
        ] {
            let Some(text) = text else { continue };
            let message = if text == "~" || text == "-" {
                b"(none)".to_vec()
            } else {
                unhex(text)
            };
            let message = String::from_utf8_lossy(&message);
            let kind: String = message
                .chars()
                .take_while(|c| !c.is_ascii_digit() && *c != '(' && *c != ':')
                .collect();
            *seen.entry(format!("{tag}: {}", kind.trim())).or_default() += 1;
        }
    }
}

/// A name for a file: ASCII, long, UTF-8, or with what XML must escape.
fn name(rng: &mut Rng) -> String {
    let len = match rng.below(8) {
        0 => 1 + rng.below(3),
        1 => 100 + rng.below(200),
        _ => 3 + rng.below(12),
    } as usize;
    let alphabets: [&[char]; 4] = [
        &['a', 'b', 'z', '.', '-', ' ', '~', '#', ';', '1'],
        &['&', '<', '>', '"', '\'', 'x', ']'],
        &['é', 'ü', 'ñ', 'Ø', 'ß', 'Ä'],
        &['中', '文', 'カ', '한', '😀', '𝄞'],
    ];
    let pick = rng.below(4) as usize;
    let text: String = (0..len)
        .map(|_| {
            let alphabet = alphabets[if rng.below(4) == 0 {
                rng.below(4) as usize
            } else {
                pick
            }];
            alphabet[rng.below(alphabet.len() as u64) as usize]
        })
        .collect();
    let text = text.replace('/', "_");
    if text.is_empty() || text == "." || text == ".." {
        "x".into()
    } else {
        text
    }
}

/// The options and entries of a `write` request: a random tree.
fn written_spec(rng: &mut Rng) -> (String, String) {
    let mut options = Vec::new();
    let sums = ["none", "sha1", "md5", "sha256", "sha512"];
    if rng.below(4) != 0 {
        options.push(format!(
            "compression={}",
            rng.pick(&["none", "gzip", "bzip2", "lzma", "xz", "gzip"])
        ));
    }
    if rng.below(3) == 0 {
        options.push(format!("compression-level={}", rng.below(10)));
    }
    if rng.below(2) == 0 {
        options.push(format!("checksum={}", rng.pick(&sums)));
    }
    if rng.below(2) == 0 {
        options.push(format!("toc-checksum={}", rng.pick(&sums)));
    }
    let mut lines = Vec::new();
    let mut dirs = vec![String::new()];
    let mut files: Vec<String> = Vec::new();
    let count = 1 + rng.below(25);
    for _ in 0..count {
        let parent = dirs[rng.below(dirs.len() as u64) as usize].clone();
        let mut path = name(rng);
        if !parent.is_empty() {
            path = format!("{parent}/{path}");
        }
        let time = |rng: &mut Rng| -> i64 {
            match rng.below(6) {
                0 => -(rng.below(4_000_000_000) as i64),
                1 => 4_102_444_800 + rng.below(100_000_000_000) as i64,
                _ => rng.below(2_000_000_000) as i64,
            }
        };
        let (mtime, atime, ctime) = (time(rng), time(rng), time(rng));
        let birth = if rng.below(2) == 0 {
            "~".to_string()
        } else {
            time(rng).to_string()
        };
        let mode = rng.below(0o10000);
        let (uid, gid) = if rng.below(5) == 0 {
            (rng.below(1 << 40), rng.below(1 << 40))
        } else {
            (rng.below(70000), rng.below(70000))
        };
        let (kind, link, size, rdev) = match rng.below(12) {
            0..=2 => {
                dirs.push(path.clone());
                ("d", String::new(), 0, 0)
            }
            3 => ("l", name(rng), 0, 0),
            4 if !files.is_empty() => (
                "h",
                files[rng.below(files.len() as u64) as usize].clone(),
                0,
                0,
            ),
            5 => (
                rng.pick(&["c", "b", "p"]),
                String::new(),
                0,
                rng.next() & 0xffff_ffff,
            ),
            _ => {
                let size = match rng.below(6) {
                    0 => 0,
                    1 => rng.below(100),
                    2 => 65536 * (1 + rng.below(3)) + rng.below(3),
                    3 => rng.below(300_000),
                    _ => rng.below(5000),
                };
                files.push(path.clone());
                ("f", String::new(), size, 0)
            }
        };
        let owner = |rng: &mut Rng| -> String {
            match rng.below(3) {
                0 => "-".into(),
                _ => hex(name(rng).as_bytes()),
            }
        };
        let (uname, gname) = (owner(rng), owner(rng));
        let xattrs = if rng.below(4) == 0 {
            let list: Vec<String> = (0..1 + rng.below(3))
                .map(|i| {
                    let value: Vec<u8> = (0..rng.below(if i == 0 { 100 } else { 70_000 }))
                        .map(|j| (j * 13 % 256) as u8)
                        .collect();
                    format!(
                        "{}={}",
                        hex(format!("user.{}", name(rng)).as_bytes()),
                        hex(&value)
                    )
                })
                .collect();
            list.join(".")
        } else {
            "-".to_string()
        };
        let fflags = if rng.below(6) == 0 {
            hex(rng
                .pick(&[
                    "nodump",
                    "uchg",
                    "nodump,uappend",
                    "schg",
                    "arch",
                    "opaque",
                    "noatime",
                    "sync,dirsync",
                    "compress",
                ])
                .as_bytes())
        } else {
            "-".to_string()
        };
        lines.push(format!(
            "{kind} {mode:o} {uid} {gid} {mtime} {atime} {ctime} {birth} {} {} {size} {rdev} {uname} {gname} {xattrs} {fflags}",
            hex(path.as_bytes()),
            hex(link.as_bytes())
        ));
    }
    let options = if options.is_empty() {
        "-".to_string()
    } else {
        hex(options.join(",").as_bytes())
    };
    (options, hex(lines.join("\n").as_bytes()))
}

/// Archives libarchive's writer makes from random trees.
fn written(oracle: &mut Oracle, rng: &mut Rng, count: usize) -> Vec<Vec<u8>> {
    let mut archives = Vec::new();
    let mut tries = 0;
    while archives.len() < count {
        tries += 1;
        assert!(tries < 10 * count + 10, "the writer keeps failing");
        let (options, entries) = written_spec(rng);
        let reply = oracle.ask(&format!("write {options} {entries}"));
        if let Some(archive) = reply.strip_prefix("ok ") {
            archives.push(unhex(archive));
        }
    }
    archives
}

#[test]
fn port_matches_libarchive_on_written_archives() {
    let Some(mut oracle) = Oracle::spawn("xar-oracle") else {
        return;
    };
    let sizes = sizes(&mut oracle);
    let count: usize = std::env::var("XAR_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    let mut rng = Rng(0x5717_e4a7);
    let mut seen = BTreeMap::new();
    for (i, archive) in written(&mut oracle, &mut rng, count)
        .into_iter()
        .enumerate()
    {
        for mode in MODES {
            compare(
                &mut oracle,
                sizes,
                &format!("written {i}"),
                &archive,
                mode,
                &mut rng,
            );
        }
        for d in 0..4 {
            let damaged = archive::damage(&mut rng, &archive);
            let mode = MODES[rng.below(2) as usize];
            let answer = compare(
                &mut oracle,
                sizes,
                &format!("written {i} damaged {d}"),
                &damaged,
                mode,
                &mut rng,
            );
            ends(&answer, &mut seen);
        }
    }
    eprintln!("{seen:#?}");
}

#[test]
fn port_matches_libarchive_on_crafted_archives() {
    let Some(mut oracle) = Oracle::spawn("xar-oracle") else {
        return;
    };
    let sizes = sizes(&mut oracle);
    let seed: u64 = std::env::var("XAR_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0xc4af_7ed4a7);
    let count: usize = std::env::var("XAR_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);
    let mut rng = Rng(seed);
    let mut seen = BTreeMap::new();
    for i in 0..count {
        let archive = archive::crafted(&mut rng);
        for mode in MODES {
            let answer = compare(
                &mut oracle,
                sizes,
                &format!("crafted {i}"),
                &archive,
                mode,
                &mut rng,
            );
            ends(&answer, &mut seen);
        }
        for d in 0..3 {
            let damaged = archive::damage(&mut rng, &archive);
            let mode = MODES[rng.below(2) as usize];
            let answer = compare(
                &mut oracle,
                sizes,
                &format!("crafted {i} damaged {d}"),
                &damaged,
                mode,
                &mut rng,
            );
            ends(&answer, &mut seen);
        }
    }
    eprintln!("{seen:#?}");
}

/// A file made an original of hard links twice, after another: libarchive
/// loops for ever on it (`docs/xar.md`), and the port refuses it.
#[test]
fn original_twice_is_refused() {
    let toc = b"<?xml version=\"1.0\"?><xar><toc>\
        <file id=\"1\"><name>a</name><type link=\"original\">file</type>\
        <file id=\"2\"><name>b</name><type link=\"original\">file</type></file>\
        <type link=\"original\">file</type></file></toc></xar>";
    let archive = archive::assemble(toc, 6, archive::NONE, b"");
    let got = answer(&archive, "m", LINUX, &mut Rng(1));
    assert_eq!(
        got,
        format!("open|fatal:{}", hex(b"File with multiple link attributes"))
    );
    if let Some(mut oracle) = Oracle::spawn("xar-oracle") {
        assert_eq!(
            oracle.ask_or_hang(&format!("read m {}", hex(&archive))),
            None
        );
    }
}

/// A name in base64 that decodes to nothing leaves libarchive's string
/// without a buffer, and the entry without a path; under it, a file's path
/// is its parent's, empty, then `/` and its name (directories with a mode,
/// as libarchive leaves out those with nothing but a name and a type).
/// Damaged copies of the
/// written archives found it, when the damage fell in such a name.
#[test]
fn a_name_that_decodes_to_nothing_is_no_path() {
    let toc = b"<?xml version=\"1.0\"?><xar><toc>\
        <file id=\"1\"><name enctype=\"base64\">&gt;w7H=</name><type>directory</type><mode>0755</mode>\
        <file id=\"2\"><name>b</name><type>directory</type><mode>0755</mode></file></file>\
        <file id=\"3\"><name enctype=\"base64\">YQ==</name><type>directory</type><mode>0755</mode></file>\
        </toc></xar>";
    let archive = archive::assemble(toc, 6, archive::NONE, b"");
    let mut xar = Reader::new(&archive[..]);
    let mut paths = Vec::new();
    while let Some(h) = xar.next().unwrap() {
        paths.push(h.path);
    }
    assert_eq!(paths, [None, Some(b"/b".to_vec()), Some(b"a".to_vec())]);
    if let Some(mut oracle) = Oracle::spawn("xar-oracle") {
        let sizes = sizes(&mut oracle);
        for mode in ["m", "s"] {
            compare(&mut oracle, sizes, "no path", &archive, mode, &mut Rng(3));
        }
    }
}

/// An entry's data read only as far as its size, not to its end, is
/// skipped from there: the next entry follows, from a stream too, where
/// libarchive counts the last block twice and goes back for it
/// (`docs/xar.md`).
#[test]
fn data_read_in_part_is_skipped_where_it_ends() {
    let path = repository().join("testdata/xar/tiny.pkg");
    let archive = std::fs::read(path).unwrap();
    let mut xar = Reader::new(&archive[..]);
    let mut names = Vec::new();
    while let Some(h) = xar.next().unwrap() {
        let mut data = vec![0; h.size as usize];
        xar.read_exact(&mut data).unwrap();
        names.push(h.path.unwrap());
    }
    assert_eq!(names, [&b"Bom"[..], b"Payload", b"PackageInfo"]);
}

/// The archives macOS's `xar`, `pkgbuild` and `productbuild` made, in
/// `testdata/xar`.
fn macos_archives() -> Vec<(String, Vec<u8>)> {
    let folder = repository().join("testdata/xar");
    let mut names: Vec<PathBuf> = std::fs::read_dir(&folder)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "xar" || e == "pkg"))
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|p| {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            (name, std::fs::read(&p).unwrap())
        })
        .collect()
}

#[test]
fn port_matches_libarchive_on_macos_archives() {
    let Some(mut oracle) = Oracle::spawn("xar-oracle") else {
        return;
    };
    let sizes = sizes(&mut oracle);
    let mut rng = Rng(0x3ac0_54a7);
    for (name, archive) in macos_archives() {
        for mode in MODES {
            let answer = compare(&mut oracle, sizes, &name, &archive, mode, &mut rng);
            assert!(answer.ends_with("|eof"), "{name}: {answer:.300}");
        }
        for i in 0..100 {
            let damaged = archive::damage(&mut rng, &archive);
            let mode = MODES[i % 2];
            compare(
                &mut oracle,
                sizes,
                &format!("{name} damaged {i}"),
                &damaged,
                mode,
                &mut rng,
            );
        }
    }
}

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/xar.txt")
}

/// The crafted archive of the recorded answers numbered `i`, as it is or
/// damaged the `d`th way.
fn recorded_crafted(i: u64, d: Option<u64>) -> Vec<u8> {
    let archive = archive::crafted(&mut Rng(0x2ec0_4a70 + i));
    match d {
        None => archive,
        Some(d) => archive::damage(&mut Rng(0xda4a_9e70 + i * 16 + d), &archive),
    }
}

/// The archive a recorded request names, or `None` when its set is not
/// fetched here.
fn recorded_archive(words: &[&str]) -> Option<Vec<u8>> {
    let find = |all: Vec<(String, Vec<u8>)>, name: &str| {
        all.into_iter().find(|(n, _)| n == name).map(|(_, a)| a)
    };
    Some(match words {
        ["libarchive", name] => find(libarchive_archives(), name)?,
        ["libarchive", name, i] => {
            let a = find(libarchive_archives(), name)?;
            libarchive_damaged(name, &a, i.parse().unwrap())
        }
        ["macos", name] => find(macos_archives(), name)?,
        ["macos", name, i] => {
            let a = find(macos_archives(), name)?;
            libarchive_damaged(name, &a, i.parse().unwrap())
        }
        ["crafted", i] => recorded_crafted(i.parse().unwrap(), None),
        ["crafted", i, d] => recorded_crafted(i.parse().unwrap(), Some(d.parse().unwrap())),
        _ => panic!("unknown request {words:?}"),
    })
}

/// How many damaged copies of each of libarchive's and macOS's archives,
/// and how many crafted archives, have recorded answers.
const RECORDED_DAMAGED: u64 = 8;
const RECORDED_CRAFTED: u64 = 60;

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/xar.txt");
    let mut rng = Rng(0x7ec0_4a71);
    let mut sizes = LINUX;
    let mut checked = 0;
    let mut cache: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty() && !l.starts_with("xml "))
    {
        if let Some(rest) = line.strip_prefix("sizes ") {
            let parts: Vec<&str> = rest.split(' ').collect();
            sizes = Sizes {
                mode: parts[0].parse().unwrap(),
                dev: parts[1].parse().unwrap(),
                linux: parts[2] == "linux",
            };
            continue;
        }
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        let words: Vec<&str> = request.split(' ').collect();
        let (mode, words) = words.split_last().unwrap();
        let key = words.join(" ");
        let archive = cache
            .entry(key)
            .or_insert_with(|| recorded_archive(words))
            .clone();
        let Some(archive) = archive else { continue };
        let got = answer(&archive, mode, sizes, &mut rng);
        assert!(
            normalized(&got) == normalized(want)
                || normalized(&stored_end(&got)) == normalized(want),
            "{request}:\n port: {got:.2000}\n  lib: {want:.2000}"
        );
        checked += 1;
    }
    // Without libarchive's archives (the `core` group, which the emulated
    // jobs leave out), only the crafted ones and macOS's are read.
    let floor = if libarchive_archives().is_empty() {
        200
    } else {
        300
    };
    assert!(checked >= floor, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/xar.txt from the oracle"]
fn record_oracle_answers() {
    let mut oracle = Oracle::spawn("xar-oracle").expect("the oracle is built");
    let sizes = sizes(&mut oracle);
    let mut text = format!(
        "# Answers from libarchive 3.8.10's XAR reader and libxml2 2.15.4 (tools/xar-oracle), replayed by crates/xar/tests/oracle.rs\n\
         # and crates/hivepack/src/xar/xml/tests.rs. \"libarchive <archive> [<n>] <mode>\" is one of libarchive's test archives, or its damaged\n\
         # copy n; \"macos <archive> [<n>] <mode>\" one in testdata/xar; \"crafted <i> [<n>] <mode>\" an archive made by the test, or\n\
         # its damaged copy n; \"xml <failat> <document>\" a document read by xmlTextReader. Recorded where mode_t and dev_t are as\n\
         # many bytes wide as \"sizes\" says.\n\
         # Regenerate with: cargo test -p hivepack --all-features --test xar_oracle record_oracle_answers -- --ignored\n\
         sizes {} {} {}\n",
        sizes.mode,
        sizes.dev,
        if sizes.linux { "linux" } else { "darwin" }
    );
    let mut ask = |request: String, archive: &[u8], mode: &str| {
        let reply = oracle
            .ask_or_hang(&format!("read {mode} {}", hex(archive)))
            .expect("an answer");
        let _ = writeln!(text, "{request} {mode}\t{reply}");
    };
    for (name, archive) in libarchive_archives() {
        for mode in MODES {
            ask(format!("libarchive {name}"), &archive, mode);
        }
        for i in 0..RECORDED_DAMAGED {
            ask(
                format!("libarchive {name} {i}"),
                &libarchive_damaged(&name, &archive, i),
                MODES[(i % 2) as usize],
            );
        }
    }
    for (name, archive) in macos_archives() {
        for mode in MODES {
            ask(format!("macos {name}"), &archive, mode);
        }
        for i in 0..RECORDED_DAMAGED {
            ask(
                format!("macos {name} {i}"),
                &libarchive_damaged(&name, &archive, i),
                MODES[(i % 2) as usize],
            );
        }
    }
    for i in 0..RECORDED_CRAFTED {
        let archive = recorded_crafted(i, None);
        ask(format!("crafted {i}"), &archive, "m");
        ask(format!("crafted {i}"), &archive, "s");
        let d = i % 3;
        ask(
            format!("crafted {i} {d}"),
            &recorded_crafted(i, Some(d)),
            MODES[(i % 2) as usize],
        );
    }
    // The XML reader's answers: the edge cases of its unit tests.
    for (failat, document) in xml_requests() {
        let failat_text = failat.map_or_else(|| "-".to_string(), |f| f.to_string());
        let request = format!("xml {failat_text} {}", hex(&document));
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{reply}");
    }
    std::fs::write(recorded_path(), text).expect("written");
}

/// The XML documents of the recorded answers: the TOCs of crafted
/// archives, whole, damaged, and with the read failing half way.
fn xml_requests() -> Vec<(Option<usize>, Vec<u8>)> {
    let mut out = Vec::new();
    for i in 0..60 {
        let Some(toc) = archive::toc(&recorded_crafted(i, None)) else {
            continue;
        };
        if toc.len() > 16_000 {
            continue;
        }
        let damaged = archive::toc(&recorded_crafted(i, Some(i % 3)));
        out.push((None, toc.clone()));
        out.push((Some(toc.len() / 2), toc));
        if let Some(d) = damaged
            && d.len() <= 16_000
        {
            out.push((None, d));
        }
    }
    out
}
