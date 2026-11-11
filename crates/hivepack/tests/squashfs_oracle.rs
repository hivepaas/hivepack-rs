//! Comparison with squashfuse 0.6.5 through `tools/squashfs-oracle`: both
//! open an image, walk every entry in the same order (`sqfs_traverse`), and
//! give each inode's fields, attributes, link target, extended attributes,
//! export table entry, the inode its path looks up to, and its data's
//! length and hash; the lines must be the same, errors and how the walk
//! ends among them. The order matters: squashfuse's data and fragment
//! caches are keyed by where a block is, and the port's are the same.
//!
//! - `testdata/squashfs`: small images of every compressor that
//!   squashfs-tools 4.6.1 made, as they are and damaged. With the oracle
//!   built, they are compared with squashfuse directly; everywhere else
//!   (Windows, and the emulated i686 and s390x jobs) `testdata/oracle/
//!   squashfs.txt` replays the hashes of squashfuse's answers. `cargo test
//!   -p hivepack --test squashfs_oracle record_oracle_answers -- --ignored`
//!   rewrites that file.
//! - `squashfs-images`, the images `tools/squashfs-images/make.py` makes
//!   with mksquashfs 4.6.1 (`scripts/testdata.py`), as they are and
//!   damaged, with the oracle.
//! - `squashfs-real`: a snap (KeeWeb 1.18.7's) and an AppImage
//!   (appimagetool 1.9.1's, its image at the end of its ELF program), read
//!   whole, and damaged in their tables.
//!
//! LZO images, which the port does not read yet, must fail to open with
//! `SQFS_BADCOMP`, as squashfuse built without LZO does, until it does.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "squashfs_support/mod.rs"]
mod support;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use hivepack::squashfs::Compression;
use support::{
    FNV_OFFSET, Limits, Oracle, Scratch, WHOLE, damaged, elf_end, fnv1a, port_list, repository, set,
};

/// How much of a damaged image is compared.
const DAMAGED: Limits = Limits {
    entries: 3000,
    data: 256 << 10,
};

fn committed() -> Vec<(String, Vec<u8>)> {
    let folder = repository().join("testdata/squashfs");
    let mut images: Vec<_> = std::fs::read_dir(&folder)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "sqfs"))
        .collect();
    images.sort();
    images
        .into_iter()
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read(&p).unwrap(),
            )
        })
        .collect()
}

/// The seed of an image's damaged copies, from its name.
fn seed(name: &str) -> u64 {
    fnv1a(FNV_OFFSET, name.as_bytes())
}

/// Whether the image (at `offset`) is LZO, which the port does not read
/// yet.
fn lzo_pending(image: &[u8], offset: usize) -> bool {
    image.len() >= offset + 22
        && u16::from_le_bytes([image[offset + 20], image[offset + 21]]) == 3
        && !Compression::Lzo.is_supported()
}

/// The hash of an answer.
fn answer_hash(lines: &[String]) -> String {
    let mut hash = FNV_OFFSET;
    for line in lines {
        hash = fnv1a(hash, line.as_bytes());
        hash = fnv1a(hash, b"\n");
    }
    format!("{hash:016x}")
}

/// The first line where two answers differ, for the message.
fn difference(port: &[String], oracle: &[String]) -> String {
    let at = port
        .iter()
        .zip(oracle)
        .position(|(a, b)| a != b)
        .unwrap_or(port.len().min(oracle.len()));
    let around =
        |lines: &[String]| lines[at.saturating_sub(3)..(at + 2).min(lines.len())].join("\n  ");
    format!(
        "line {at}:\n port:\n  {}\n squashfuse:\n  {}",
        around(port),
        around(oracle)
    )
}

/// Compares the port with squashfuse on `image`, as a file for the oracle;
/// for an LZO image while the port does not read it, the port must fail to
/// open it. The oracle's answer.
fn compare(
    oracle: &mut Oracle,
    scratch: &Scratch,
    image: &[u8],
    offset: usize,
    limits: Limits,
    what: &str,
) -> Vec<String> {
    let path = scratch.write(image);
    let expected = oracle.list(path, offset as u64, limits);
    check(image, offset, limits, &expected, what);
    expected
}

/// Checks the port's answer on `image` against squashfuse's.
fn check(image: &[u8], offset: usize, limits: Limits, expected: &[String], what: &str) {
    let port = port_list(Cursor::new(image), offset as u64, limits);
    if lzo_pending(image, offset) {
        // What squashfuse checks before the compressor fails the same.
        let before =
            expected.len() == 1 && (expected[0] == "end init 2" || expected[0] == "end init 3");
        if before {
            assert_eq!(port, expected, "{what}");
        } else {
            assert_eq!(port, ["end init 4"], "{what}: LZO must fail to open");
        }
        return;
    }
    // Where squashfuse reads past a metadata block, what it reads is what
    // was in memory: the answers are the same up to there.
    if let Some(at) = port.iter().position(|l| l.ends_with(" err past")) {
        let word = |l: &str| l.split(' ').next().map(str::to_string);
        assert!(
            port[..at] == expected[..at.min(expected.len())]
                && expected.get(at).and_then(|l| word(l)) == word(&port[at]),
            "{what}: {}",
            difference(&port, expected)
        );
        PAST_COUNT.fetch_add(1, Ordering::Relaxed);
        return;
    }
    assert!(port == expected, "{what}: {}", difference(&port, expected));
}

/// How many answers parted where squashfuse reads past a metadata block.
static PAST_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Every request on the committed images: each image whole, and its
/// damaged copies.
fn committed_requests() -> Vec<(String, Vec<u8>, Limits)> {
    let mut requests = Vec::new();
    for (name, image) in committed() {
        requests.push((format!("{name} whole"), image.clone(), WHOLE));
        for (i, (how, copy)) in damaged(&image, 0, 300, seed(&name)).into_iter().enumerate() {
            requests.push((format!("{name} {i} {how}"), copy, DAMAGED));
        }
    }
    requests
}

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/squashfs.txt")
}

/// The recorded answers' hashes, by request.
fn recorded() -> BTreeMap<String, String> {
    std::fs::read_to_string(recorded_path())
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| {
            let (request, hash) = l.rsplit_once('\t').unwrap();
            (request.to_string(), hash.to_string())
        })
        .collect()
}

#[test]
fn committed_images() {
    let requests = committed_requests();
    let mut compared = 0;
    match Oracle::spawn() {
        Some(mut oracle) => {
            let scratch = Scratch::new("committed.sqfs");
            for (what, image, limits) in &requests {
                compare(&mut oracle, &scratch, image, 0, *limits, what);
                compared += 1;
            }
        }
        None => {
            let recorded = recorded();
            for (what, image, limits) in &requests {
                let key = what.split(' ').take(2).collect::<Vec<_>>().join(" ");
                let hash = recorded
                    .get(&key)
                    .unwrap_or_else(|| panic!("{key} not recorded"));
                let port = port_list(Cursor::new(image), 0, *limits);
                if lzo_pending(image, 0) {
                    assert!(port.len() == 1 && port[0].starts_with("end init"), "{what}");
                } else if let Some((at, hash)) =
                    hash.strip_prefix("past ").and_then(|h| h.split_once(' '))
                {
                    let at: usize = at.parse().unwrap();
                    assert!(port[at].ends_with(" err past"), "{what}");
                    assert_eq!(answer_hash(&port[..at]), hash, "{what}");
                    PAST_COUNT.fetch_add(1, Ordering::Relaxed);
                } else {
                    assert_eq!(&answer_hash(&port), hash, "{what}");
                }
                compared += 1;
            }
        }
    }
    eprintln!(
        "{compared} committed images and damaged copies compared, {} parting where squashfuse reads past a block",
        PAST_COUNT.load(Ordering::Relaxed)
    );
    assert_eq!(compared, requests.len());
}

#[test]
#[ignore = "rewrites testdata/oracle/squashfs.txt with the oracle's answers"]
fn record_oracle_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let scratch = Scratch::new("record.sqfs");
    let mut text = String::from(
        "# squashfuse 0.6.5's answers to tests/squashfs_oracle.rs on testdata/squashfs,\n\
         # by image and copy (whole, or the number of the damaged copy): the FNV-1a\n\
         # hash of the answer's lines. Rewritten by `cargo test -p hivepack --test\n\
         # squashfs_oracle record_oracle_answers -- --ignored`.\n",
    );
    for (what, image, limits) in committed_requests() {
        let key = what.split(' ').take(2).collect::<Vec<_>>().join(" ");
        let path = scratch.write(&image);
        let answer = oracle.list(path, 0, limits);
        // Where squashfuse reads past a metadata block, the answer up to
        // there.
        let port = port_list(Cursor::new(&image), 0, limits);
        match port.iter().position(|l| l.ends_with(" err past")) {
            Some(at) => {
                let _ = writeln!(text, "{key}\tpast {at} {}", answer_hash(&answer[..at]));
            }
            None => {
                let _ = writeln!(text, "{key}\t{}", answer_hash(&answer));
            }
        }
    }
    std::fs::write(recorded_path(), text).unwrap();
}

#[test]
fn generated_images() {
    let Some(folder) = set("squashfs-images", "generated") else {
        return;
    };
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let scratch = Scratch::new("generated.sqfs");
    let mut images: Vec<_> = std::fs::read_dir(&folder)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "sqfs"))
        .collect();
    images.sort();
    assert!(images.len() >= 20, "{} images", images.len());
    let copies: usize = std::env::var("HIVEPACK_SQUASHFS_COPIES")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(48);
    let mut compared = 0;
    for path in images {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let image = std::fs::read(&path).unwrap();
        let answer = compare(
            &mut oracle,
            &scratch,
            &image,
            0,
            WHOLE,
            &format!("{name} whole"),
        );
        if !lzo_pending(&image, 0) {
            assert_eq!(answer.last().map(String::as_str), Some("end ok"), "{name}");
            assert!(
                !answer.iter().any(|l| l.contains(" err ")),
                "{name} reads with errors"
            );
        }
        compared += 1;
        for (i, (how, copy)) in damaged(&image, 0, copies, seed(&name))
            .into_iter()
            .enumerate()
        {
            compare(
                &mut oracle,
                &scratch,
                &copy,
                0,
                DAMAGED,
                &format!("{name} {i} {how}"),
            );
            compared += 1;
        }
    }
    eprintln!(
        "{compared} generated images and damaged copies compared, {} parting where squashfuse reads past a block",
        PAST_COUNT.load(Ordering::Relaxed)
    );
}

#[test]
fn real_files() {
    let Some(folder) = set("squashfs-real", "generated") else {
        return;
    };
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let scratch = Scratch::new("real.sqfs");
    let mut compared = 0;
    for (name, appimage) in [
        ("KeeWeb-1.18.7.linux.snap", false),
        ("appimagetool-x86_64.AppImage", true),
    ] {
        let image = std::fs::read(folder.join(name)).unwrap();
        let offset = if appimage { elf_end(&image) } else { 0 };
        assert_eq!(&image[offset..offset + 4], b"hsqs", "{name}");
        // The file as it is, which the oracle reads in place.
        let expected = oracle.list(&folder.join(name), offset as u64, WHOLE);
        check(&image, offset, WHOLE, &expected, name);
        assert_eq!(
            expected.last().map(String::as_str),
            Some("end ok"),
            "{name}"
        );
        compared += 1;
        // Damaged in the tables, past the data: the data region of a large
        // image is left to the generated ones.
        let copies: Vec<_> = damaged(&image, offset, 40, seed(name))
            .into_iter()
            .filter(|(how, _)| !how.contains("in data") && !how.starts_with("cut in data"))
            .collect();
        for (i, (how, copy)) in copies.into_iter().enumerate() {
            compare(
                &mut oracle,
                &scratch,
                &copy,
                offset,
                DAMAGED,
                &format!("{name} {i} {how}"),
            );
            compared += 1;
        }
    }
    eprintln!(
        "{compared} real files and damaged copies compared, {} parting where squashfuse reads past a block",
        PAST_COUNT.load(Ordering::Relaxed)
    );
}

/// The port's side of the oracle's `read`: every regular file read whole,
/// 128 KiB at a time, from opening the image on: files, bytes, nanoseconds.
fn port_read_all(path: &std::path::Path, offset: u64) -> (u64, u64, u128) {
    let start = std::time::Instant::now();
    let file = std::fs::File::open(path).unwrap();
    let mut fs = hivepack::squashfs::Squashfs::open_at(file, offset).unwrap();
    let root = fs.root().unwrap();
    let mut walk = fs.traverse(&root).unwrap();
    let mut buf = vec![0u8; 1 << 17];
    let (mut files, mut bytes) = (0, 0);
    while let Some(step) = walk.next(&mut fs).unwrap() {
        let hivepack::squashfs::Step::Entry { entry, .. } = step else {
            continue;
        };
        let inode = fs.inode(entry.inode).unwrap();
        if !inode.is_file() {
            continue;
        }
        files += 1;
        let mut at = 0;
        while at < inode.file_size() {
            at += fs.read_at(&inode, at, &mut buf).unwrap() as u64;
        }
        bytes += at;
    }
    (files, bytes, start.elapsed().as_nanos())
}

/// The speed comparison of `docs/squashfs.md`: every file of the snap, the
/// AppImage and some of the generated images read whole, by squashfuse and
/// by the port, in turns, the best of seven rounds each. Run it with
/// `cargo test --release -p hivepack --test squashfs_oracle speed --
/// --ignored --nocapture`.
#[test]
#[ignore = "a benchmark"]
fn speed() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let real = set("squashfs-real", "generated").unwrap();
    let images = set("squashfs-images", "generated").unwrap();
    let appimage = real.join("appimagetool-x86_64.AppImage");
    let offset = elf_end(&std::fs::read(&appimage).unwrap()) as u64;
    let mut cases = vec![
        (real.join("KeeWeb-1.18.7.linux.snap"), 0),
        (appimage, offset),
    ];
    for name in [
        "gzip",
        "lzma",
        "xz",
        "lz4",
        "zstd",
        "zstd-b1m",
        "gzip-uncompressed",
    ] {
        cases.push((images.join(format!("{name}.sqfs")), 0));
    }
    for (path, offset) in cases {
        let (mut best_c, mut best_r) = (u128::MAX, u128::MAX);
        let mut size = (0, 0);
        for _ in 0..7 {
            let answer = oracle.ask(&format!("read {offset} {}", path.display()));
            let f: Vec<&str> = answer[0].split(' ').collect();
            assert_eq!(f.len(), 4, "{answer:?}");
            best_c = best_c.min(f[3].parse().unwrap());
            let (files, bytes, ns) = port_read_all(&path, offset);
            assert_eq!(
                (files.to_string(), bytes.to_string()),
                (f[1].to_string(), f[2].to_string())
            );
            size = (files, bytes);
            best_r = best_r.min(ns);
        }
        let mbs = |ns: u128| size.1 as f64 / (ns as f64 / 1e9) / 1e6;
        eprintln!(
            "{}: {} files, {} bytes: squashfuse {:.3} s ({:.0} MB/s), port {:.3} s ({:.0} MB/s), {:.2}x",
            path.file_name().unwrap().to_string_lossy(),
            size.0,
            size.1,
            best_c as f64 / 1e9,
            mbs(best_c),
            best_r as f64 / 1e9,
            mbs(best_r),
            best_c as f64 / best_r as f64
        );
    }
}
