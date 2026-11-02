//! Comparison with libarchive's ISO 9660 reader through `tools/iso-oracle`:
//! libarchive's own test images (`testdata/libarchive-iso`), as they are
//! and damaged; images libarchive's writer makes from random files, as they
//! are and damaged; and images made here with what neither has (Rock Ridge
//! entries of every kind, continuation areas, files in several extents,
//! zisofs), as they are and damaged. Both read every entry and all of its
//! data; the headers, warnings, the data's length and hash, the errors and
//! how the image ends must be the same.
//!
//! - With the oracle built, everything is compared with libarchive directly.
//! - Everywhere, including where it is not built (Windows, and the emulated
//!   i686 and s390x jobs), `testdata/oracle/iso.txt` replays answers
//!   libarchive gave earlier for the images the test makes again without
//!   it. `cargo test -p hivepack --all-features --test iso_oracle record_oracle_answers --
//!   --ignored` rewrites that file.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "iso_support/mod.rs"]
mod support;

use std::fmt::Write as _;
use std::io::{Cursor, Read};
use std::path::PathBuf;

use hivepack::iso::{Error, Header, Reader};
use support::{Oracle, Rng, hex, repository, unhex};

/// How much of an entry's data is compared.
const LIMIT: u64 = 64 << 20;

/// The widths of `mode_t` and `dev_t` where libarchive runs, which narrow
/// what it gives.
#[derive(Clone, Copy)]
struct Sizes {
    mode: u32,
    dev: u32,
}

/// The sizes of Linux, where the recorded answers were made.
const LINUX: Sizes = Sizes { mode: 4, dev: 8 };

fn sizes(oracle: &mut Oracle) -> Sizes {
    let reply = oracle.ask("sizes");
    let mut parts = reply.split(' ').skip(1);
    Sizes {
        mode: parts.next().unwrap().parse().unwrap(),
        dev: parts.next().unwrap().parse().unwrap(),
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

fn header(format: i32, h: &Header, sizes: Sizes) -> String {
    let mode = if sizes.mode == 2 {
        h.mode & 0xffff
    } else {
        h.mode
    };
    let rdev = if sizes.dev == 4 {
        i64::from(h.rdev as u32 as i32)
    } else {
        h.rdev as i64
    };
    format!(
        "{format},{},{mode:o},{},{},{},{},{},{},{},{},{rdev},{},{}",
        bytes(&h.path),
        h.uid,
        h.gid,
        h.nlink,
        number(h.size),
        number(h.birth_time),
        number(h.mod_time),
        number(h.access_time),
        number(h.change_time),
        bytes(&h.symlink),
        bytes(&h.hardlink),
    )
}

fn message(e: &Error) -> String {
    bytes(&e.message())
}

/// The port's answer to `read <mode> <image>`, as the oracle words it; the
/// data is read in pieces of random sizes.
fn answer(image: &[u8], mode: &str, sizes: Sizes, rng: &mut Rng) -> String {
    let mode = mode.as_bytes();
    let mut iso = if mode[0] == b'm' {
        Reader::seekable(Cursor::new(image))
    } else {
        // Not seekable: the reader cannot know the input is a cursor.
        let r: Box<dyn Read + '_> = Box::new(image);
        return answer_with(Reader::new(r), mode, sizes, rng);
    };
    iso.set_joliet(mode[1] == b'1');
    iso.set_rock_ridge(mode[2] == b'1');
    answer_with(iso, mode, sizes, rng)
}

fn answer_with<R: Read>(mut iso: Reader<R>, mode: &[u8], sizes: Sizes, rng: &mut Rng) -> String {
    iso.set_joliet(mode[1] == b'1');
    iso.set_rock_ridge(mode[2] == b'1');
    let mut out = String::new();
    let mut first = true;
    loop {
        let next = iso.next();
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
        match &h.warning {
            None => out.push_str("ok"),
            Some(w) => {
                let _ = write!(out, "warn:{}", hex(&w.message()));
            }
        }
        let format = iso.format().map_or(0, |f| f.code());
        let _ = write!(out, ";{}", header(format, &h, sizes));

        // The data, in pieces of random sizes.
        let mut hash: u64 = 0xcbf29ce484222325;
        let mut total: u64 = 0;
        let mut warnings = Vec::new();
        let mut buf = vec![0; 1 << 17];
        let end = loop {
            let want = 1 + rng.below(buf.len() as u64) as usize;
            match iso.read(&mut buf[..want]) {
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
                Err(e) => match Error::from(e) {
                    Error::Warning(w) => warnings.push(hex(&w.message())),
                    Error::ZisofsStuck => break "stuck".to_string(),
                    e => break format!("fatal:{}", message(&e)),
                },
            }
        };
        let warnings = if warnings.is_empty() {
            "-".to_string()
        } else {
            warnings.join(".")
        };
        let _ = write!(out, ";{total},{hash:016x},{warnings},{end}");
        if end != "eof" {
            out.push_str("|stop");
            return out;
        }
    }
}

fn xz_decode(data: &[u8]) -> Vec<u8> {
    use hivepack::xz::{Action, InBuffer, OutBuffer, Status, Stream};
    let mut stream = Stream::stream_decoder(u64::MAX, 0).unwrap();
    let mut out = Vec::new();
    let mut input = InBuffer::new(data);
    let mut piece = vec![0; 1 << 16];
    loop {
        let mut output = OutBuffer::new(&mut piece);
        let status = stream
            .code(&mut output, &mut input, Action::Finish)
            .unwrap();
        let written = output.pos;
        out.extend_from_slice(&piece[..written]);
        if status == Status::StreamEnd {
            return out;
        }
    }
}

/// libarchive's test images, by name.
fn libarchive_images() -> Vec<(String, Vec<u8>)> {
    let folder = repository().join("testdata/libarchive-iso");
    let mut names: Vec<PathBuf> = std::fs::read_dir(&folder)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "xz"))
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|p| {
            let name = p
                .file_name()
                .unwrap()
                .to_string_lossy()
                .replace(".iso.xz", "");
            (name, xz_decode(&std::fs::read(&p).unwrap()))
        })
        .collect()
}

/// The ways an image is read: in memory (seekable) or as a stream, with
/// Joliet and Rock Ridge on or off.
const MODES: [&str; 5] = ["m11", "s11", "m01", "m10", "m00"];

/// Compares the port's answer with libarchive's, and gives it.
fn compare(
    oracle: &mut Oracle,
    sizes: Sizes,
    what: &str,
    image: &[u8],
    mode: &str,
    rng: &mut Rng,
) -> String {
    let want = oracle.ask(&format!("read {mode} {}", hex(image)));
    let got = answer(image, mode, sizes, rng);
    assert_eq!(got, want, "{what} read with {mode}");
    want
}

/// The kinds of warnings and errors in an answer: each message up to its
/// first number or name.
fn ends(answer: &str, seen: &mut std::collections::BTreeMap<String, usize>) {
    for part in answer.split(['|', ';', ',', '.']) {
        for (tag, text) in [
            ("warn", part.strip_prefix("warn:")),
            ("fatal", part.strip_prefix("fatal:")),
        ] {
            let Some(text) = text else { continue };
            let message = if text == "~" { Vec::new() } else { unhex(text) };
            let message = String::from_utf8_lossy(&message);
            let kind: String = message
                .chars()
                .take_while(|c| !c.is_ascii_digit() && *c != '(' && *c != ':' && *c != '@')
                .collect();
            *seen.entry(format!("{tag}: {}", kind.trim())).or_default() += 1;
        }
    }
    if answer.contains(",stuck") {
        *seen.entry("stuck".into()).or_default() += 1;
    }
}

#[test]
fn port_matches_libarchive_on_its_images() {
    let Some(mut oracle) = Oracle::spawn("iso-oracle") else {
        return;
    };
    let sizes = sizes(&mut oracle);
    let mut rng = Rng(0x1505_9660);
    for (name, image) in libarchive_images() {
        for mode in MODES {
            compare(&mut oracle, sizes, &name, &image, mode, &mut rng);
        }
    }
}

/// The offsets of the directory records in the sectors that look like
/// directories, and of the volume descriptors: what damage aims at.
fn targets(image: &[u8]) -> (Vec<usize>, Vec<usize>) {
    let mut records = Vec::new();
    let mut descriptors = Vec::new();
    for (i, sector) in image.chunks(2048).enumerate() {
        if (16..64).contains(&i) && sector.len() == 2048 && &sector[1..6] == b"CD001" {
            descriptors.push(i * 2048);
            continue;
        }
        // A directory starts with "." (and ".."): a record of length 34 or
        // more, name length 1, name 0.
        if sector.len() < 68 || sector[0] < 34 || sector[32] != 1 || sector[33] != 0 {
            continue;
        }
        let mut p = 0;
        while p + 34 <= sector.len() && sector[p] >= 34 && p + sector[p] as usize <= sector.len() {
            records.push(i * 2048 + p);
            p += sector[p] as usize;
        }
    }
    (records, descriptors)
}

fn put32(image: &mut [u8], at: usize, value: u32) {
    if at + 8 <= image.len() {
        image[at..at + 4].copy_from_slice(&value.to_le_bytes());
        image[at + 4..at + 8].copy_from_slice(&value.to_be_bytes());
    }
}

/// A number for a 32-bit field: small, around the image, or extreme.
fn field(rng: &mut Rng, image_len: usize) -> u32 {
    match rng.below(6) {
        0 => 0,
        1 => rng.below(64) as u32,
        2 => rng.below(image_len as u64 / 2048 + 4) as u32,
        3 => rng.below(1 << 20) as u32,
        4 => rng.pick(&[u32::MAX, 0x7fff_ffff, 0x8000_0000, 0xffff_fff0]),
        _ => rng.next() as u32,
    }
}

/// The image with one to three things wrong in it.
fn damage(rng: &mut Rng, mut image: Vec<u8>) -> Vec<u8> {
    for _ in 0..1 + rng.below(3) {
        let (records, descriptors) = targets(&image);
        let len = image.len();
        match rng.below(14) {
            // A bit or byte anywhere in a record or descriptor.
            0..=2 => {
                let base = if !records.is_empty() && rng.below(4) != 0 {
                    rng.pick(&records)
                } else if !descriptors.is_empty() {
                    rng.pick(&descriptors)
                } else {
                    continue;
                };
                let at = base + rng.below(if base % 2048 == 0 { 2048 } else { 64 }) as usize;
                if at < len {
                    if rng.below(2) == 0 {
                        image[at] ^= 1 << rng.below(8);
                    } else {
                        let any = rng.next() as u8;
                        image[at] = rng.pick(&[0, 1, 0x7f, 0x80, 0xff, any]);
                    }
                }
            }
            // A record's length, name length, extent, size or flags.
            3..=6 => {
                let Some(&at) = records.get(rng.below(records.len().max(1) as u64) as usize) else {
                    continue;
                };
                match rng.below(6) {
                    0 => image[at] = rng.below(256) as u8,
                    1 => image[at + 32] = rng.below(256) as u8,
                    2 => {
                        let v = field(rng, len);
                        put32(&mut image, at + 2, v);
                    }
                    3 => {
                        let v = field(rng, len);
                        put32(&mut image, at + 10, v);
                    }
                    4 => {
                        let any = rng.next() as u8;
                        image[at + 25] = rng.pick(&[0, 2, 0x80, 0x82, 0x04, 0x8e, any]);
                    }
                    _ => {
                        // The date.
                        for b in &mut image[at + 18..at + 25] {
                            *b = rng.next() as u8;
                        }
                    }
                }
            }
            // A SUSP entry: its length, version, or a number in it.
            7..=9 => {
                let Some(&at) = records.get(rng.below(records.len().max(1) as u64) as usize) else {
                    continue;
                };
                let end = (at + image[at] as usize).min(len);
                let entries: Vec<usize> = (at + 34..end.saturating_sub(4))
                    .filter(|&p| {
                        image[p].is_ascii_uppercase()
                            && image[p + 1].is_ascii_uppercase()
                            && image[p + 2] >= 4
                    })
                    .collect();
                let Some(&p) = entries.get(rng.below(entries.len().max(1) as u64) as usize) else {
                    continue;
                };
                match rng.below(5) {
                    0 => image[p + 2] = rng.below(256) as u8,
                    1 => image[p + 3] = rng.pick(&[0, 1, 2]),
                    2 => {
                        let name = rng.pick(&[
                            *b"CE", *b"CL", *b"RE", *b"PL", *b"NM", *b"SL", *b"PX", *b"PN", *b"TF",
                            *b"ZF", *b"ST", *b"SP", *b"RR",
                        ]);
                        image[p..p + 2].copy_from_slice(&name);
                    }
                    _ => {
                        let at = p + 4 + 8 * rng.below(5) as usize;
                        let v = field(rng, len);
                        if at + 8 <= end {
                            put32(&mut image, at, v);
                        }
                    }
                }
            }
            // A volume descriptor's root directory, block size or volume
            // size, or its type.
            10 => {
                let Some(&at) =
                    descriptors.get(rng.below(descriptors.len().max(1) as u64) as usize)
                else {
                    continue;
                };
                match rng.below(5) {
                    0 => {
                        let v = field(rng, len);
                        put32(&mut image, at + 156 + 2, v);
                    }
                    1 => {
                        let v = field(rng, len);
                        put32(&mut image, at + 156 + 10, v);
                    }
                    2 => {
                        let any = rng.next() as u16;
                        let v = rng.pick(&[1u16, 512, 1024, 4096, 65535, any]);
                        image[at + 128..at + 130].copy_from_slice(&v.to_le_bytes());
                        image[at + 130..at + 132].copy_from_slice(&v.to_be_bytes());
                    }
                    3 => {
                        let v = field(rng, len);
                        put32(&mut image, at + 80, v);
                    }
                    _ => image[at] = rng.pick(&[0, 1, 2, 3, 4, 255]),
                }
            }
            // Cut short.
            11 => {
                let at = rng.below(len as u64 + 1) as usize;
                image.truncate(at);
            }
            // A sector copied over another, or zeroed.
            12 => {
                let sectors = len / 2048;
                if sectors < 2 {
                    continue;
                }
                let to = rng.below(sectors as u64) as usize * 2048;
                if rng.below(2) == 0 {
                    let from = rng.below(sectors as u64) as usize * 2048;
                    let copy = image[from..from + 2048].to_vec();
                    image[to..to + 2048].copy_from_slice(&copy);
                } else {
                    image[to..to + 2048].fill(0);
                }
            }
            // Bytes after the end.
            _ => {
                let more = rng.below(5000) as usize;
                image.extend((0..more).map(|_| rng.next() as u8));
            }
        }
    }
    image
}

/// libarchive's image `name`, damaged the `i`th way.
fn libarchive_damaged(name: &str, image: &[u8], i: u64) -> Vec<u8> {
    let seed = name.bytes().fold(0x9e37_79b9_7f4a_7c15u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    });
    let mut rng = Rng(seed ^ (i + 1).wrapping_mul(0x2545_f491_4f6c_dd1d));
    damage(&mut rng, image.to_vec())
}

/// How many damaged copies of each of libarchive's images.
const DAMAGED: u64 = 60;

#[test]
fn port_matches_libarchive_on_its_images_damaged() {
    let Some(mut oracle) = Oracle::spawn("iso-oracle") else {
        return;
    };
    let sizes = sizes(&mut oracle);
    let mut rng = Rng(0x0dd_9660);
    for (name, image) in libarchive_images() {
        // The largest images, mostly zeros, fewer times.
        let count = if image.len() > 2 << 20 {
            DAMAGED / 6
        } else {
            DAMAGED
        };
        for i in 0..count {
            let damaged = libarchive_damaged(&name, &image, i);
            let mode = MODES[(i % MODES.len() as u64) as usize];
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

/// A name for a file: ASCII as ISO 9660 wants it or not, long, or UTF-8
/// (with characters outside the BMP for Joliet's surrogates).
fn name(rng: &mut Rng) -> String {
    let len = match rng.below(8) {
        0 => 1 + rng.below(3),
        1 => 60 + rng.below(50),
        2 => 100 + rng.below(140),
        _ => 3 + rng.below(12),
    } as usize;
    let alphabets: [&[char]; 4] = [
        &['A', 'B', 'Z', '0', '9', '_'],
        &['a', 'b', 'z', '.', '-', ' ', '~', '#', ';', '1'],
        &['é', 'ü', 'ñ', 'Ø', 'ß', 'Ä'],
        &['中', '文', 'カ', '한', '😀', '𝄞'],
    ];
    let pick = rng.below(4) as usize;
    (0..len)
        .map(|_| {
            let alphabet = alphabets[if rng.below(4) == 0 {
                rng.below(4) as usize
            } else {
                pick
            }];
            alphabet[rng.below(alphabet.len() as u64) as usize]
        })
        .collect::<String>()
        .trim_matches(|c| c == '/' || c == ' ')
        .replace('/', "_")
}

/// The options and entries of a `write` request: a random tree.
fn written_spec(rng: &mut Rng) -> (String, String) {
    let mut options = Vec::new();
    match rng.below(4) {
        0 => options.push("!rockridge".to_string()),
        1 => options.push("rockridge=strict".to_string()),
        _ => {}
    }
    match rng.below(3) {
        0 => options.push("!joliet".to_string()),
        1 => options.push("joliet=long".to_string()),
        _ => {}
    }
    if rng.below(3) == 0 {
        options.push("zisofs".to_string());
    }
    if rng.below(3) == 0 {
        options.push(format!("iso-level={}", 1 + rng.below(4)));
    }
    if rng.below(4) == 0 {
        options.push("!limit-depth".to_string());
    }
    if rng.below(3) == 0 {
        options.push("!pad".to_string());
    }
    let mut lines = Vec::new();
    let mut dirs = vec![String::new()];
    let mut files: Vec<String> = Vec::new();
    let count = 1 + rng.below(30);
    for _ in 0..count {
        let parent = dirs[rng.below(dirs.len() as u64) as usize].clone();
        let mut path = name(rng);
        if path.is_empty() {
            path = "x".into();
        }
        if !parent.is_empty() {
            path = format!("{parent}/{path}");
        }
        let time = |rng: &mut Rng| -> i64 {
            match rng.below(5) {
                0 => -(rng.below(2_000_000_000) as i64),
                1 => 4_102_444_800 + rng.below(1_000_000_000) as i64,
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
        let (uid, gid) = (rng.below(70000), rng.below(70000));
        let (kind, link, size, rdev) = match rng.below(12) {
            0..=2 => {
                // Deep directories, for rr_moved.
                if rng.below(3) == 0 {
                    let mut deep = path.clone();
                    for _ in 0..rng.below(12) {
                        deep = format!("{deep}/{}", name(rng).replace('/', "_"));
                    }
                    path = deep;
                }
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
                    2 => 32768 * (1 + rng.below(4)) + rng.below(3),
                    3 => rng.below(300_000),
                    _ => rng.below(5000),
                };
                files.push(path.clone());
                ("f", String::new(), size, 0)
            }
        };
        lines.push(format!(
            "{kind} {mode:o} {uid} {gid} {mtime} {atime} {ctime} {birth} {} {} {size} {rdev}",
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

/// Images libarchive's writer makes from random trees.
fn written(oracle: &mut Oracle, rng: &mut Rng, count: usize) -> Vec<Vec<u8>> {
    let mut images = Vec::new();
    while images.len() < count {
        let (options, entries) = written_spec(rng);
        let reply = oracle.ask(&format!("write {options} {entries}"));
        if let Some(image) = reply.strip_prefix("ok ") {
            images.push(unhex(image));
        }
    }
    images
}

#[test]
fn port_matches_libarchive_on_written_images() {
    let Some(mut oracle) = Oracle::spawn("iso-oracle") else {
        return;
    };
    let sizes = sizes(&mut oracle);
    let mut rng = Rng(0x5717_e9660);
    for (i, image) in written(&mut oracle, &mut rng, 300).into_iter().enumerate() {
        for mode in ["m11", "s11", "m01", "m10"] {
            compare(
                &mut oracle,
                sizes,
                &format!("written {i}"),
                &image,
                mode,
                &mut rng,
            );
        }
        for d in 0..4 {
            let damaged = damage(&mut rng, image.clone());
            let mode = MODES[rng.below(MODES.len() as u64) as usize];
            compare(
                &mut oracle,
                sizes,
                &format!("written {i} damaged {d}"),
                &damaged,
                mode,
                &mut rng,
            );
        }
    }
}

#[test]
fn port_matches_libarchive_on_crafted_images() {
    let Some(mut oracle) = Oracle::spawn("iso-oracle") else {
        return;
    };
    let sizes = sizes(&mut oracle);
    let seed: u64 = std::env::var("ISO_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0xc4af_7ed9660);
    let count: usize = std::env::var("ISO_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(400);
    let mut rng = Rng(seed);
    let mut seen = std::collections::BTreeMap::new();
    for i in 0..count {
        let image = support::image::crafted(&mut rng);
        for mode in ["m11", "s11", "m01", "m10", "m00"] {
            let answer = compare(
                &mut oracle,
                sizes,
                &format!("crafted {i}"),
                &image,
                mode,
                &mut rng,
            );
            ends(&answer, &mut seen);
        }
        for d in 0..4 {
            let damaged = damage(&mut rng, image.clone());
            let mode = MODES[rng.below(MODES.len() as u64) as usize];
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
    if count >= 400 {
        for kind in [
            "warn: Ignoring out-of-order directory",
            "warn: Ignoring out-of-order file",
            "warn: Directory is beyond end-of-media",
            "warn: File is beyond end-of-media",
            "warn: Pathname cannot be converted from UTF-",
            "warn: Linkname cannot be converted from UTF-",
            "fatal: Invalid parameter in SUSP \"CE\" extension",
            "fatal: Tried to parse Rockridge extensions, but none found",
            "fatal: Invalid location of extent of file",
            "fatal: Invalid Rockridge RE",
            "fatal: Directory structure contains loop",
            "fatal: Truncated input file",
            "fatal: Illegal zisofs file body",
            "fatal: Illegal zisofs block pointers",
            "fatal: zisofs decompression failed",
            "stuck",
        ] {
            assert!(seen.contains_key(kind), "no {kind} in {seen:#?}");
        }
    }
}

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/iso.txt")
}

/// The crafted image of the recorded answers numbered `i`, as it is or
/// damaged the `d`th way.
fn recorded_crafted(i: u64, d: Option<u64>) -> Vec<u8> {
    let image = support::image::crafted(&mut Rng(0x2ec0_4d00 + i));
    match d {
        None => image,
        Some(d) => damage(&mut Rng(0xda4a_9e00 + i * 16 + d), image),
    }
}

/// How many of libarchive's images' damaged copies, and of crafted images,
/// have recorded answers.
const RECORDED_DAMAGED: u64 = 12;
const RECORDED_CRAFTED: u64 = 150;

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/iso.txt");
    let images: std::collections::BTreeMap<String, Vec<u8>> =
        libarchive_images().into_iter().collect();
    let mut rng = Rng(0x7ec0_4d01);
    let mut sizes = LINUX;
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        if let Some(rest) = line.strip_prefix("sizes ") {
            let (mode, dev) = rest.split_once(' ').unwrap();
            sizes = Sizes {
                mode: mode.parse().unwrap(),
                dev: dev.parse().unwrap(),
            };
            continue;
        }
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        let words: Vec<&str> = request.split(' ').collect();
        let (image, mode) = match words[..] {
            ["libarchive", name, mode] => (images[name].clone(), mode),
            ["libarchive", name, i, mode] => (
                libarchive_damaged(name, &images[name], i.parse().unwrap()),
                mode,
            ),
            ["crafted", i, mode] => (recorded_crafted(i.parse().unwrap(), None), mode),
            ["crafted", i, d, mode] => (
                recorded_crafted(i.parse().unwrap(), Some(d.parse().unwrap())),
                mode,
            ),
            _ => panic!("unknown request {request:.100}"),
        };
        assert_eq!(answer(&image, mode, sizes, &mut rng), want, "{request}");
        checked += 1;
    }
    assert!(checked >= 800, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/iso.txt from the oracle"]
fn record_oracle_answers() {
    let mut oracle = Oracle::spawn("iso-oracle").expect("the oracle is built");
    let sizes = sizes(&mut oracle);
    let mut text = format!(
        "# Answers from libarchive 3.8.10's ISO 9660 reader (tools/iso-oracle), replayed by crates/iso/tests/oracle.rs.\n\
         # \"libarchive <image> [<n>] <mode>\" is one of libarchive's test images, or its damaged copy n;\n\
         # \"crafted <i> [<n>] <mode>\" an image made by the test, or its damaged copy n. Recorded where\n\
         # mode_t and dev_t are as many bytes wide as \"sizes\" says, which narrows the answers' modes and devices.\n\
         # Regenerate with: cargo test -p hivepack --all-features --test iso_oracle record_oracle_answers -- --ignored\n\
         sizes {} {}\n",
        sizes.mode, sizes.dev
    );
    let mut ask = |request: String, image: &[u8], mode: &str| {
        let reply = oracle.ask(&format!("read {mode} {}", hex(image)));
        let _ = writeln!(text, "{request} {mode}\t{reply}");
    };
    for (name, image) in libarchive_images() {
        for mode in MODES {
            ask(format!("libarchive {name}"), &image, mode);
        }
        for i in 0..RECORDED_DAMAGED {
            let damaged = libarchive_damaged(&name, &image, i);
            ask(
                format!("libarchive {name} {i}"),
                &damaged,
                MODES[(i % 5) as usize],
            );
        }
    }
    for i in 0..RECORDED_CRAFTED {
        let image = recorded_crafted(i, None);
        ask(format!("crafted {i}"), &image, "m11");
        ask(format!("crafted {i}"), &image, "s11");
        let d = i % 4;
        ask(
            format!("crafted {i} {d}"),
            &recorded_crafted(i, Some(d)),
            MODES[(i % 5) as usize],
        );
    }
    std::fs::create_dir_all(recorded_path().parent().expect("folder")).expect("folder");
    std::fs::write(recorded_path(), text).expect("written");
}
