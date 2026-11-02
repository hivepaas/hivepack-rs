//! Comparison with libarchive's cpio reader and RPM filter through
//! `tools/cpio-oracle`: libarchive's own test archives (the
//! `libarchive-cpio` set), as they are and damaged; archives libarchive's
//! writers make from random trees, as they are and damaged; archives and
//! RPM packages made here with what neither has, as they are and damaged.
//! Both read every entry and all of its data, or skip it; the headers,
//! warnings, the data's length and hash, the errors and how the archive
//! ends must be the same.
//!
//! - With the oracle built, everything is compared with libarchive directly.
//! - Everywhere, including where it is not built (Windows, and the emulated
//!   i686 and s390x jobs), `testdata/oracle/cpio.txt` replays answers
//!   libarchive gave earlier. `cargo test -p hivepack --all-features --test cpio_oracle
//!   record_oracle_answers -- --ignored` rewrites that file.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "cpio_support/mod.rs"]
mod support;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Read;
use std::path::PathBuf;

use hivepack::cpio::{Device, Error, Header, Reader, rpm};
use support::archive::{self, Kind};
use support::{Oracle, Rng, bunzip2, gunzip, hex, libarchive_archives, repository, unhex};

/// Where libarchive runs: the widths of `mode_t` and `dev_t`, which narrow
/// what it gives, and its `makedev`, `major` and `minor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Platform {
    mode: u32,
    /// `dev_t` is 4 bytes and signed, with BSD's `makedev` (8 bits of the
    /// major number, 24 of the minor), as on macOS; else 8 bytes with
    /// glibc's.
    bsd: bool,
}

/// Linux, where the recorded answers were made.
const LINUX: Platform = Platform {
    mode: 4,
    bsd: false,
};

/// `dev`, `major` and `minor` of `d` where libarchive runs.
fn devices(d: Device, p: Platform) -> [i64; 3] {
    if p.bsd {
        match d {
            Device::Number(x) => [
                i64::from(x as i32),
                i64::from((x >> 24) & 0xff),
                i64::from(x & 0xff_ffff),
            ],
            Device::Split { major, minor } => [
                i64::from((major << 24) | minor) as i32 as i64,
                i64::from(major as i32),
                i64::from(minor as i32),
            ],
        }
    } else {
        match d {
            Device::Number(x) => {
                let x = u64::from(x);
                [
                    x as i64,
                    ((x >> 8) & 0xfff) as i64,
                    ((x & 0xff) | ((x >> 12) & 0xfff00)) as i64,
                ]
            }
            Device::Split { major, minor } => {
                let (major, minor) = (u64::from(major), u64::from(minor));
                let dev = ((major & 0xfff) << 8)
                    | ((major & 0xffff_f000) << 32)
                    | (minor & 0xff)
                    | ((minor & 0xffff_ff00) << 12);
                [dev as i64, major as i64, minor as i64]
            }
        }
    }
}

fn platform(oracle: &mut Oracle) -> Platform {
    let reply = oracle.ask("sizes");
    let parts: Vec<i64> = reply
        .split(' ')
        .skip(1)
        .map(|n| n.parse().unwrap())
        .collect();
    let [mode, dev, makedev, major, minor] = parts[..] else {
        panic!("sizes: {reply}");
    };
    for bsd in [false, true] {
        let p = Platform {
            mode: mode as u32,
            bsd,
        };
        let made = devices(
            Device::Split {
                major: 0x1234_5678,
                minor: 0x9abc_def0,
            },
            p,
        )[0];
        let split = devices(Device::Number(0x9abc_def0), p);
        if made == makedev && split[1] == major && split[2] == minor && (dev == 4) == bsd {
            return p;
        }
    }
    panic!("an unknown makedev: {reply}");
}

fn bytes(b: &Option<Vec<u8>>) -> String {
    match b {
        None => "~".into(),
        Some(b) => hex(b),
    }
}

fn message(e: &Error) -> String {
    bytes(&e.message())
}

fn fnv(data: &[u8], mut hash: u64) -> u64 {
    for &b in data {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

const FNV: u64 = 0xcbf29ce484222325;

fn header(format: i32, h: &Header, p: Platform) -> String {
    let mode = if p.mode == 2 { h.mode & 0xffff } else { h.mode };
    let [dev, devmajor, devminor] = devices(h.dev, p);
    let [rdev, rdevmajor, rdevminor] = devices(h.rdev, p);
    format!(
        "{format},{},{mode:o},{},{},{},{},{},{},{dev},{devmajor},{devminor},{rdev},{rdevmajor},{rdevminor},{},{}",
        hex(&h.path),
        h.uid,
        h.gid,
        h.nlink,
        h.ino,
        h.size,
        h.mod_time,
        bytes(&h.symlink),
        bytes(&h.hardlink),
    )
}

/// A reader that gives its bytes in pieces of random sizes, as no reader
/// in libarchive's tests does: what the port looks at must not depend on
/// them.
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

/// The RPM filters libarchive's `choose_filters` stacks on `archive`, as
/// many as their bids say (up to 25), and what the last gives; or the
/// message of the failure that ends the opening.
fn layers(archive: &[u8], rng: &mut Rng) -> Result<(usize, Vec<u8>), String> {
    let mut data = archive.to_vec();
    let mut n = 0;
    while rpm::bid(&data) > 0 {
        n += 1;
        if n == 25 {
            return Err(hex(b"Input requires too many filters for decoding"));
        }
        let mut out = Vec::new();
        let pieces = Pieces {
            data: &data,
            rng: Rng(rng.next() | 1),
        };
        match rpm::Reader::new(pieces).read_to_end(&mut out) {
            Ok(_) => data = out,
            Err(e) => return Err(message(&Error::from(e))),
        }
    }
    Ok((n, data))
}

/// The port's answer to `read <mode> <archive>`, as the oracle words it,
/// and whether it may differ from libarchive's where `makedev` makes two
/// devices one (which changes what is a hard link).
fn answer(archive: &[u8], mode: &str, p: Platform, rng: &mut Rng) -> (String, bool) {
    let mode = mode.as_bytes();
    let (filters, data) = match layers(archive, rng) {
        Ok(layers) => layers,
        Err(message) => return (format!("fatal:{message}"), false),
    };
    let mut cpio = Reader::new(Pieces {
        data: &data,
        rng: Rng(rng.next() | 1),
    });
    cpio.set_pwb(mode[2] == b'1');
    let mut out = String::new();
    let mut first = true;
    // libarchive's links by the device it sees.
    let mut links: Vec<(i64, u64, u32, Vec<u8>)> = Vec::new();
    let mut ambiguous = false;
    loop {
        let next = cpio.next();
        if first {
            if let Err(e @ Error::Unrecognized) = &next {
                return (format!("fatal:{}", message(e)), false);
            }
            let _ = write!(out, "open,{filters}");
            first = false;
        }
        out.push('|');
        let h = match next {
            Ok(Some(h)) => h,
            Ok(None) => {
                out.push_str("eof");
                return (out, ambiguous);
            }
            Err(e) => {
                let _ = write!(out, "fatal:{}", message(&e));
                return (out, ambiguous);
            }
        };
        if h.nlink > 1 {
            let dev = devices(h.dev, p)[0];
            let found = links
                .iter()
                .position(|(d, ino, _, _)| *d == dev && *ino == h.ino);
            let target = found.map(|i| links[i].3.clone());
            match found {
                Some(i) => {
                    links[i].2 -= 1;
                    if links[i].2 == 0 {
                        links.remove(i);
                    }
                }
                None => links.push((dev, h.ino, h.nlink - 1, h.path.clone())),
            }
            ambiguous |= target != h.hardlink;
        }
        match &h.warning {
            None => out.push_str("ok"),
            Some(w) => {
                let _ = write!(out, "warn:{}", hex(&w.message()));
            }
        }
        let format = cpio.format().map_or(0, |f| f.code());
        let _ = write!(out, ";{}", header(format, &h, p));
        if mode[1] == b'k' {
            out.push_str(";skip");
            continue;
        }

        // The data, in pieces of random sizes.
        let mut hash = FNV;
        let mut total: u64 = 0;
        let mut buf = vec![0; 1 << 17];
        let end = loop {
            let want = 1 + rng.below(buf.len() as u64) as usize;
            match cpio.read(&mut buf[..want]) {
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
            return (out, ambiguous);
        }
    }
}

/// The port's answer to `rpm <archive>`.
fn rpm_answer(archive: &[u8], rng: &mut Rng) -> String {
    match layers(archive, rng) {
        Ok((n, data)) => format!("ok {n};{},{:016x},eof", data.len(), fnv(&data, FNV)),
        Err(message) => format!("fatal:{message}"),
    }
}

/// The ways an archive is read: in memory or as a stream, its data read or
/// skipped, with the `pwb` option or without.
const MODES: [&str; 4] = ["md0", "sd0", "mk0", "md1"];

/// What the comparisons saw: the kinds of warnings and errors, and how
/// many answers could not be compared where `makedev` makes devices one.
#[derive(Default)]
struct Seen {
    kinds: BTreeMap<String, usize>,
    ambiguous: usize,
    compared: usize,
}

impl Seen {
    /// The kinds of warnings and errors in an answer: each message up to
    /// its first number.
    fn add(&mut self, answer: &str) {
        self.compared += 1;
        for part in answer.split(['|', ';', ',', ' ']) {
            for (tag, text) in [
                ("warn", part.strip_prefix("warn:")),
                ("fatal", part.strip_prefix("fatal:")),
            ] {
                let Some(text) = text else { continue };
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
                    .entry(format!("{tag}: {}", kind.trim()))
                    .or_default() += 1;
            }
        }
    }
}

/// Compares the port's answer to `read` with libarchive's, and gives it.
fn compare(
    oracle: &mut Oracle,
    p: Platform,
    what: &str,
    archive: &[u8],
    mode: &str,
    rng: &mut Rng,
    seen: &mut Seen,
) -> String {
    let want = oracle.ask(&format!("read {mode} {}", hex(archive)));
    let (got, ambiguous) = answer(archive, mode, p, rng);
    if ambiguous && p.bsd && got != want {
        seen.ambiguous += 1;
        return want;
    }
    assert_eq!(got, want, "{what} read with {mode}");
    seen.add(&want);
    want
}

/// Compares the port's answer to `rpm` with libarchive's.
fn compare_rpm(oracle: &mut Oracle, what: &str, archive: &[u8], rng: &mut Rng, seen: &mut Seen) {
    let want = oracle.ask(&format!("rpm {}", hex(archive)));
    assert_eq!(
        rpm_answer(archive, rng),
        want,
        "{what} through the RPM filter"
    );
    seen.add(&want);
}

/// libarchive's archives, by name, and what is inside some: the two parts
/// of its afio test together, the gzipped archive and the RPM packages'
/// payloads uncompressed.
fn libarchive_set() -> Vec<(String, Vec<u8>)> {
    let mut set = libarchive_archives();
    let find = |name: &str, set: &[(String, Vec<u8>)]| {
        set.iter()
            .find(|(n, _)| n == name)
            .map(|(_, d)| d.clone())
            .expect(name)
    };
    if set.is_empty() {
        return set;
    }
    let mut afio = find("cpio_afio_header.part1.cpio", &set);
    afio.extend(find("cpio_afio_header.part2.cpio", &set));
    let mut more = vec![
        ("cpio_afio_header.cpio".to_string(), afio),
        (
            "test_write_disk_appledouble.cpio".to_string(),
            gunzip(&find("test_write_disk_appledouble.cpio.gz", &set)),
        ),
    ];
    for name in ["cpio_svr4_gzip_rpm.rpm", "cpio_svr4_bzip2_rpm.rpm"] {
        let mut payload = Vec::new();
        rpm::Reader::new(&find(name, &set)[..])
            .read_to_end(&mut payload)
            .unwrap();
        let cpio = if payload.starts_with(b"BZh") {
            bunzip2(&payload)
        } else {
            gunzip(&payload)
        };
        more.push((name.replace(".rpm", ".payload.cpio"), cpio));
    }
    set.extend(more);
    set.sort();
    set
}

#[test]
fn port_matches_libarchive_on_its_archives() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let p = platform(&mut oracle);
    let mut rng = Rng(0xc910_0001);
    let mut seen = Seen::default();
    let set = libarchive_set();
    for (name, archive) in &set {
        for mode in MODES {
            compare(&mut oracle, p, name, archive, mode, &mut rng, &mut seen);
        }
        compare_rpm(&mut oracle, name, archive, &mut rng, &mut seen);
    }
    eprintln!("{} answers: {:#?}", seen.compared, seen.kinds);
    if !set.is_empty() {
        for kind in [
            "fatal: Truncated input file",
            "fatal: Unrecognized archive format",
        ] {
            assert!(
                seen.kinds.contains_key(kind),
                "no {kind} in {:#?}",
                seen.kinds
            );
        }
    }
}

/// libarchive's archive `name`, damaged the `i`th way.
fn libarchive_damaged(name: &str, archive: &[u8], i: u64) -> Vec<u8> {
    let seed = name.bytes().fold(0x9e37_79b9_7f4a_7c15u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    });
    let mut rng = Rng(seed ^ (i + 1).wrapping_mul(0x2545_f491_4f6c_dd1d));
    archive::damage(&mut rng, archive.to_vec())
}

/// How many damaged copies of each of libarchive's archives.
const DAMAGED: u64 = 150;

#[test]
fn port_matches_libarchive_on_its_archives_damaged() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let p = platform(&mut oracle);
    let mut rng = Rng(0xc910_0002);
    let mut seen = Seen::default();
    for (name, archive) in libarchive_set() {
        // The largest, a symbolic link of 128 KiB, fewer times.
        let count = if archive.len() > 64 << 10 {
            DAMAGED / 10
        } else {
            DAMAGED
        };
        for i in 0..count {
            let damaged = libarchive_damaged(&name, &archive, i);
            let what = format!("{name} damaged {i}");
            let mode = MODES[(i % MODES.len() as u64) as usize];
            compare(&mut oracle, p, &what, &damaged, mode, &mut rng, &mut seen);
            if name.ends_with(".rpm") {
                compare_rpm(&mut oracle, &what, &damaged, &mut rng, &mut seen);
            }
        }
    }
    eprintln!(
        "{} answers ({} left out for makedev): {:#?}",
        seen.compared, seen.ambiguous, seen.kinds
    );
}

/// The format, block size and entries of a `write` request: a random
/// tree.
fn written_spec(rng: &mut Rng) -> String {
    let format = rng.pick(&["odc", "newc", "bin", "pwb"]);
    let block = rng.pick(&[0, 512, 10240]);
    let device = |rng: &mut Rng| {
        if format == "newc" {
            format!("{}:{}", rng.below(1 << 12), rng.below(1 << 20))
        } else {
            rng.below(1 << 18).to_string()
        }
    };
    let time = |rng: &mut Rng| -> i64 {
        match rng.below(6) {
            0 => -(rng.below(2_000_000_000) as i64),
            1 => 4_102_444_800 + rng.below(10_000_000_000) as i64,
            2 => rng.pick(&[0, 0x7fff_ffff, 0xffff_ffff, 0x1_0000_0000]),
            _ => rng.below(2_000_000_000) as i64,
        }
    };
    let mut kinds = vec!["f", "f", "f", "f", "d", "l", "c", "b", "h"];
    if format == "pwb" {
        kinds.retain(|k| *k != "l");
    }
    if format == "odc" || format == "newc" {
        kinds.extend(["p", "s"]);
    }
    let mut lines = Vec::new();
    let mut ino = 100 + rng.below(1000);
    for _ in 0..1 + rng.below(25) {
        let perm = rng.below(0o10000);
        let (uid, gid) = (rng.below(300_000), rng.below(70000));
        let dev = device(rng);
        let kind = rng.pick(&kinds);
        let path = archive::name(rng);
        let size = match rng.below(6) {
            0 => 0,
            1 => 1 + rng.below(4),
            2 => rng.below(70_000),
            _ => rng.below(3000),
        };
        ino += 1;
        // Each entry: its type, path, links, size and link.
        type Entry<'a> = (&'a str, Vec<u8>, u64, u64, Vec<u8>);
        let mut entries: Vec<Entry> = Vec::new();
        match kind {
            "h" => {
                // Hard links: the data on the first, or on the last as GNU
                // cpio writes newc.
                let copies = 2 + rng.below(3);
                let last = format == "newc" || rng.below(3) == 0;
                for c in 0..copies {
                    let mut p = path.clone();
                    p.extend_from_slice(format!(".{c}").as_bytes());
                    let has = (c + 1 == copies) == last;
                    entries.push(("f", p, copies, if has { size } else { 0 }, Vec::new()));
                }
            }
            "l" => entries.push(("l", path, 1, 0, archive::name(rng))),
            "f" => entries.push(("f", path, 1, size, Vec::new())),
            other => entries.push((other, path, 1 + rng.below(2), 0, Vec::new())),
        }
        for (kind, path, nlink, size, link) in entries {
            let rdev = if kind == "c" || kind == "b" {
                device(rng)
            } else {
                "0".into()
            };
            lines.push(format!(
                "{kind} {perm:o} {uid} {gid} {nlink} {ino} {dev} {rdev} {} {} {} {size}",
                time(rng),
                hex(&path),
                hex(&link),
            ));
        }
    }
    format!(
        "write {format} {block} {}",
        hex(lines.join("\n").as_bytes())
    )
}

/// Archives libarchive's writers make from random trees.
fn written(oracle: &mut Oracle, rng: &mut Rng, count: usize) -> Vec<Vec<u8>> {
    let mut archives = Vec::new();
    while archives.len() < count {
        let reply = oracle.ask(&written_spec(rng));
        if let Some(archive) = reply.strip_prefix("ok ") {
            archives.push(unhex(archive));
        }
    }
    archives
}

#[test]
fn port_matches_libarchive_on_written_archives() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let p = platform(&mut oracle);
    let mut rng = Rng(0xc910_0003);
    let mut seen = Seen::default();
    for (i, archive) in written(&mut oracle, &mut rng, 300).into_iter().enumerate() {
        let what = format!("written {i}");
        for mode in ["md0", "mk0", "md1"] {
            compare(&mut oracle, p, &what, &archive, mode, &mut rng, &mut seen);
        }
        for d in 0..4 {
            let damaged = archive::damage(&mut rng, archive.clone());
            let mode = MODES[rng.below(MODES.len() as u64) as usize];
            let what = format!("written {i} damaged {d}");
            compare(&mut oracle, p, &what, &damaged, mode, &mut rng, &mut seen);
        }
    }
    eprintln!(
        "{} answers ({} left out for makedev): {:#?}",
        seen.compared, seen.ambiguous, seen.kinds
    );
}

#[test]
fn port_matches_libarchive_on_crafted_archives() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let p = platform(&mut oracle);
    let seed: u64 = std::env::var("CPIO_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0xc4af_7ed0);
    let count: usize = std::env::var("CPIO_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);
    let mut rng = Rng(seed);
    let mut seen = Seen::default();
    for i in 0..count {
        let archive = archive::crafted(&mut rng);
        let what = format!("crafted {i}");
        for mode in ["md0", "mk0"] {
            compare(&mut oracle, p, &what, &archive, mode, &mut rng, &mut seen);
        }
        for d in 0..3 {
            let damaged = archive::damage(&mut rng, archive.clone());
            let mode = MODES[rng.below(MODES.len() as u64) as usize];
            let what = format!("crafted {i} damaged {d}");
            compare(&mut oracle, p, &what, &damaged, mode, &mut rng, &mut seen);
        }
    }
    eprintln!(
        "{} answers ({} left out for makedev): {:#?}",
        seen.compared, seen.ambiguous, seen.kinds
    );
    if count >= 1000 {
        for kind in [
            "warn: Skipped",
            "fatal: Skipped",
            "fatal: none",
            "fatal: Truncated input file",
            "fatal: End of file trying to read next cpio header",
            "fatal: Rejecting malformed cpio archive: pathname exceeds",
            "fatal: Rejecting malformed cpio archive: symlink contents exceed",
            "fatal: Nonsensical file size",
            "fatal: Unrecognized archive format",
        ] {
            assert!(
                seen.kinds.contains_key(kind),
                "no {kind} in {:#?}",
                seen.kinds
            );
        }
    }
}

/// A crafted RPM package.
fn crafted_rpm(rng: &mut Rng) -> Vec<u8> {
    let payload = archive::payload(rng);
    archive::rpm(rng, &payload)
}

#[test]
fn port_matches_libarchive_on_rpm_packages() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let p = platform(&mut oracle);
    let mut rng = Rng(0xc910_0004);
    let mut seen = Seen::default();
    for i in 0..500 {
        let package = crafted_rpm(&mut rng);
        let what = format!("package {i}");
        compare_rpm(&mut oracle, &what, &package, &mut rng, &mut seen);
        compare(&mut oracle, p, &what, &package, "md0", &mut rng, &mut seen);
        for d in 0..3 {
            let damaged = archive::damage(&mut rng, package.clone());
            let what = format!("package {i} damaged {d}");
            compare_rpm(&mut oracle, &what, &damaged, &mut rng, &mut seen);
            if d == 0 {
                compare(&mut oracle, p, &what, &damaged, "mk0", &mut rng, &mut seen);
            }
        }
    }
    // Packages inside packages, up to libarchive's limit and past it.
    let inner = archive::crafted_kind(&mut rng, Kind::Newc);
    let mut package = inner;
    for depth in 1..=26 {
        package = archive::rpm_plain(&package);
        let what = format!("{depth} packages deep");
        compare_rpm(&mut oracle, &what, &package, &mut rng, &mut seen);
        compare(&mut oracle, p, &what, &package, "md0", &mut rng, &mut seen);
    }
    eprintln!("{} answers: {:#?}", seen.compared, seen.kinds);
    for kind in [
        "fatal: Unrecognized rpm header",
        "fatal: Truncated input file",
        "fatal: none",
        "fatal: Input requires too many filters for decoding",
    ] {
        assert!(
            seen.kinds.contains_key(kind),
            "no {kind} in {:#?}",
            seen.kinds
        );
    }
}

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/cpio.txt")
}

/// The crafted archive of the recorded answers numbered `i`, as it is or
/// damaged the `d`th way.
fn recorded_crafted(i: u64, d: Option<u64>) -> Vec<u8> {
    let archive = archive::crafted(&mut Rng(0x2ec0_4d00 + i));
    match d {
        None => archive,
        Some(d) => archive::damage(&mut Rng(0xda4a_9e00 + i * 16 + d), archive),
    }
}

/// The crafted package of the recorded answers numbered `i`, as it is or
/// damaged the `d`th way.
fn recorded_package(i: u64, d: Option<u64>) -> Vec<u8> {
    let package = crafted_rpm(&mut Rng(0x7e40_4d00 + i));
    match d {
        None => package,
        Some(d) => archive::damage(&mut Rng(0x7e4a_9e00 + i * 16 + d), package),
    }
}

/// How many of the requests of each kind have recorded answers.
const RECORDED_CRAFTED: u64 = 250;
const RECORDED_PACKAGES: u64 = 100;
const RECORDED_DAMAGED: u64 = 5;
const RECORDED_WRITTEN: usize = 20;

/// An answer short enough to keep.
const RECORDED_ANSWER_MAX: usize = 6 << 10;

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/cpio.txt");
    let mut rng = Rng(0x7ec0_4d01);
    let mut p = LINUX;
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        if let Some(rest) = line.strip_prefix("platform ") {
            let (mode, bsd) = rest.split_once(' ').unwrap();
            p = Platform {
                mode: mode.parse().unwrap(),
                bsd: bsd == "bsd",
            };
            continue;
        }
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        let words: Vec<&str> = request.split(' ').collect();
        let got = match words[..] {
            ["read", mode, archive] => answer(&unhex(archive), mode, p, &mut rng).0,
            ["rpm", archive] => rpm_answer(&unhex(archive), &mut rng),
            ["crafted", i, mode] => {
                answer(
                    &recorded_crafted(i.parse().unwrap(), None),
                    mode,
                    p,
                    &mut rng,
                )
                .0
            }
            ["crafted", i, d, mode] => {
                let archive = recorded_crafted(i.parse().unwrap(), Some(d.parse().unwrap()));
                answer(&archive, mode, p, &mut rng).0
            }
            ["package", i] => rpm_answer(&recorded_package(i.parse().unwrap(), None), &mut rng),
            ["package", i, d] => {
                let package = recorded_package(i.parse().unwrap(), Some(d.parse().unwrap()));
                rpm_answer(&package, &mut rng)
            }
            ["package-read", i, mode] => {
                let package = recorded_package(i.parse().unwrap(), None);
                answer(&package, mode, p, &mut rng).0
            }
            _ => panic!("unknown request {request:.100}"),
        };
        assert_eq!(got, want, "{request:.200}");
        checked += 1;
    }
    assert!(checked >= 900, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/cpio.txt from the oracle"]
fn record_oracle_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let p = platform(&mut oracle);
    let mut text = format!(
        "# Answers from libarchive 3.8.10's cpio reader and RPM filter (tools/cpio-oracle), replayed by\n\
         # crates/hivepack/tests/cpio_oracle.rs. \"read <mode> <archive>\" and \"rpm <archive>\" are the oracle's requests:\n\
         # libarchive's small test archives, damaged copies of them, and archives its writers made;\n\
         # \"crafted <i> [<n>] <mode>\" is an archive made by the test, or its damaged copy n, and\n\
         # \"package <i> [<n>]\" and \"package-read <i> <mode>\" a package made by the test. Recorded where\n\
         # mode_t is as many bytes wide as \"platform\" says, with glibc's or BSD's makedev.\n\
         # Regenerate with: cargo test -p hivepack --all-features --test cpio_oracle record_oracle_answers -- --ignored\n\
         platform {} {}\n",
        p.mode,
        if p.bsd { "bsd" } else { "glibc" }
    );
    let mut ask = |text: &mut String, request: String, oracle_request: String| {
        let reply = oracle.ask(&oracle_request);
        if reply.len() <= RECORDED_ANSWER_MAX {
            let _ = writeln!(text, "{request}\t{reply}");
        }
    };
    for (name, archive) in libarchive_set() {
        if name == "huge_rpm.rpm" {
            // An RPM header that says it is 32 GiB.
            for request in [
                format!("rpm {}", hex(&archive)),
                format!("read md0 {}", hex(&archive)),
            ] {
                ask(&mut text, request.clone(), request);
            }
        }
        if archive.len() > 2048 {
            continue;
        }
        for (i, mode) in MODES.iter().enumerate() {
            if i < 2 || name.contains("bin") {
                let request = format!("read {mode} {}", hex(&archive));
                ask(&mut text, request.clone(), request);
            }
        }
        if name.ends_with(".rpm") {
            let request = format!("rpm {}", hex(&archive));
            ask(&mut text, request.clone(), request);
        }
        for i in 0..RECORDED_DAMAGED {
            let damaged = libarchive_damaged(&name, &archive, i);
            let request = if name.ends_with(".rpm") && i % 2 == 0 {
                format!("rpm {}", hex(&damaged))
            } else {
                format!("read {} {}", MODES[(i % 4) as usize], hex(&damaged))
            };
            ask(&mut text, request.clone(), request);
        }
    }
    let mut rng = Rng(0x7ec0_4d02);
    let mut kept = 0;
    for archive in written(&mut oracle_again(), &mut rng, 200) {
        if kept == RECORDED_WRITTEN || archive.len() > 2000 {
            continue;
        }
        kept += 1;
        let request = format!("read md0 {}", hex(&archive));
        ask(&mut text, request.clone(), request);
    }
    for i in 0..RECORDED_CRAFTED {
        let archive = recorded_crafted(i, None);
        for mode in ["md0", "mk0"] {
            ask(
                &mut text,
                format!("crafted {i} {mode}"),
                format!("read {mode} {}", hex(&archive)),
            );
        }
        let d = i % 4;
        let mode = MODES[(i % 4) as usize];
        ask(
            &mut text,
            format!("crafted {i} {d} {mode}"),
            format!("read {mode} {}", hex(&recorded_crafted(i, Some(d)))),
        );
    }
    for i in 0..RECORDED_PACKAGES {
        let package = recorded_package(i, None);
        ask(
            &mut text,
            format!("package {i}"),
            format!("rpm {}", hex(&package)),
        );
        ask(
            &mut text,
            format!("package-read {i} md0"),
            format!("read md0 {}", hex(&package)),
        );
        let d = i % 4;
        ask(
            &mut text,
            format!("package {i} {d}"),
            format!("rpm {}", hex(&recorded_package(i, Some(d)))),
        );
    }
    std::fs::create_dir_all(recorded_path().parent().expect("folder")).expect("folder");
    std::fs::write(recorded_path(), text).expect("written");
}

/// A second oracle, for the requests that write while the first is lent
/// to the recorder.
fn oracle_again() -> Oracle {
    Oracle::spawn().expect("the oracle is built")
}
