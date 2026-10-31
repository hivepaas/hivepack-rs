//! Comparison with Go's archive/tar through `tools/tar-oracle`: Go's own
//! test archives (`testdata/go-tar`), each as it is and damaged twenty
//! ways, and archives Go's `tar.Writer` makes from random headers, as they
//! are and damaged. Both read every entry and up to 8 MiB of its data; the
//! headers, the data's length and SHA-256, the errors and how the archive
//! ends must be the same.
//!
//! - With the oracle built, everything is compared with Go directly.
//! - Everywhere, including where it is not built (Windows, and the emulated
//!   i686 and s390x jobs), `testdata/oracle/tar.txt` replays answers Go gave
//!   earlier: for Go's archives and their damage by name and number, which
//!   the test makes again from the committed files, and for small written
//!   archives in full. `cargo test -p hivepack-tar --test oracle
//!   record_oracle_answers -- --ignored` rewrites that file.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::fmt::Write as _;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::PathBuf;

use hivepack_crypto::Sha256;
use hivepack_tar::{Error, Reader, Records, Time};
use support::{Oracle, Rng, go_archives, hex, repository, unhex};

/// How much of an entry's data both read.
const MAX_DATA: usize = 8 << 20;

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/tar.txt")
}

fn digest(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex(&h.out()[..8])
}

fn records(m: &Records) -> String {
    let mut text = Vec::new();
    for (k, v) in m {
        text.extend_from_slice(k);
        text.push(b'=');
        text.extend_from_slice(v);
        text.push(b'\n');
    }
    digest(&text)
}

/// A time as the oracle writes it; Go's zero time, January 1 of year 1, is
/// `-` whether it was set or not.
fn when(t: Option<Time>) -> String {
    match t {
        None => "-".into(),
        Some(t) if t.secs == -62_135_596_800 && t.nanos == 0 => "-".into(),
        Some(t) => format!("{}.{}", t.secs, t.nanos),
    }
}

fn error_name(e: &Error) -> &'static str {
    match e {
        Error::Header => "header",
        Error::FieldTooLong => "field-too-long",
        Error::SparseTooLong => "sparse-too-long",
        Error::MissData => "miss-data",
        Error::UnrefData => "unref-data",
        Error::UnexpectedEof => "unexpected-eof",
        _ => "other",
    }
}

/// The port's answer to `read <archive>`, as the oracle words it; the data
/// is read in pieces of random sizes.
fn answer(archive: &[u8], rng: &mut Rng) -> String {
    let mut tr = Reader::new(archive);
    answer_of(&mut tr, rng)
}

/// [`answer`], with any reader.
fn answer_of<R: Read>(tr: &mut Reader<R>, rng: &mut Rng) -> String {
    let mut out = Vec::new();
    loop {
        let h = match tr.next() {
            Ok(Some(h)) => h,
            Ok(None) => {
                out.push("eof".to_string());
                break;
            }
            Err(e) => {
                out.push(error_name(&e).to_string());
                break;
            }
        };
        let mut data = Vec::new();
        let mut derr = "-";
        while data.len() < MAX_DATA {
            let want = (1 + rng.below(70_000) as usize).min(MAX_DATA - data.len());
            let mut buf = vec![0; want];
            match tr.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => data.extend_from_slice(&buf[..n]),
                Err(e) => {
                    derr = error_name(&Error::from(e));
                    break;
                }
            }
        }
        out.push(format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            h.typeflag,
            hex(&h.name),
            hex(&h.linkname),
            h.size,
            h.mode,
            h.uid,
            h.gid,
            hex(&h.uname),
            hex(&h.gname),
            when(h.mod_time),
            when(h.access_time),
            when(h.change_time),
            h.devmajor,
            h.devminor,
            h.format.bits(),
            records(&h.pax_records),
            records(&h.xattrs),
            data.len(),
            digest(&data),
            derr,
        ));
    }
    out.join("|")
}

/// The checksum of the block at `at` written again, as Go's Writer writes
/// it: six octal digits, a NUL and a space.
fn fix_checksum(archive: &mut [u8], at: usize) {
    let Some(block) = archive.get_mut(at..at + 512) else {
        return;
    };
    block[148..156].fill(b' ');
    let sum: u32 = block.iter().map(|&c| u32::from(c)).sum();
    let field = format!("{sum:06o}\0 ");
    block[148..156].copy_from_slice(&field.as_bytes()[field.len() - 8..]);
}

/// The fields of a header, by offset and length, to damage.
const FIELDS: [(usize, usize); 16] = [
    (0, 100),   // name
    (100, 8),   // mode
    (108, 8),   // uid
    (116, 8),   // gid
    (124, 12),  // size
    (136, 12),  // mtime
    (156, 1),   // type
    (157, 100), // link name
    (257, 6),   // magic
    (263, 2),   // version
    (265, 32),  // uname
    (329, 8),   // devmajor
    (345, 155), // prefix, or GNU's atime and ctime
    (386, 96),  // GNU's sparse map
    (482, 1),   // GNU's isextended
    (483, 12),  // GNU's realsize
];

/// `archive`, damaged one of many ways.
fn damage(rng: &mut Rng, mut archive: Vec<u8>) -> Vec<u8> {
    let blocks = archive.len() / 512;
    let block = if blocks > 0 {
        rng.below(blocks as u64) as usize * 512
    } else {
        0
    };
    match rng.below(12) {
        0 if !archive.is_empty() => {
            let i = rng.below(archive.len() as u64) as usize;
            archive[i] ^= 1 << rng.below(8);
        }
        1..=4 if blocks > 0 => {
            // A field of a block given another value, the checksum fixed so
            // that the damage gets past it.
            let (at, len) = FIELDS[rng.below(FIELDS.len() as u64) as usize];
            let value: Vec<u8> = match rng.below(8) {
                0 => vec![0; len],
                1 => vec![b' '; len],
                2 => {
                    // Octal, perhaps too long, perhaps with garbage.
                    let n = rng.next() >> rng.below(64);
                    let mut v = format!("{n:o}").into_bytes();
                    v.truncate(len);
                    v.resize(len, if rng.below(2) == 0 { 0 } else { b' ' });
                    v
                }
                3 => {
                    // Base-256, positive or negative.
                    let mut v: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                    v[0] = if rng.below(2) == 0 { 0x80 } else { 0xff };
                    v
                }
                4 => {
                    let t = rng.pick(&[
                        b'0', b'1', b'2', b'5', b'x', b'g', b'L', b'K', b'S', b'7', 0, b'Z',
                    ]);
                    let mut v = vec![t; len];
                    v.truncate(len);
                    v
                }
                5 => rng
                    .pick(&[&b"ustar\0"[..], b"ustar ", b"ustar  ", b"00", b" \0"])
                    .to_vec(),
                _ => (0..len).map(|_| rng.next() as u8).collect(),
            };
            let n = value.len().min(len);
            let end = (block + at + n).min(archive.len());
            let start = (block + at).min(end);
            archive[start..end].copy_from_slice(&value[..end - start]);
            fix_checksum(&mut archive, block);
        }
        5 => {
            // Cut at a block's end or near it.
            let len = (block + rng.pick(&[0, 1, 100, 511, 512, 513])).min(archive.len());
            archive.truncate(len);
        }
        6 => {
            let len = rng.below(archive.len() as u64 + 1) as usize;
            archive.truncate(len);
        }
        7 => {
            // Zero blocks inserted, or one block repeated.
            let insert = if rng.below(2) == 0 {
                vec![0; 512 * (1 + rng.below(2) as usize)]
            } else {
                archive[block..(block + 512).min(archive.len())].to_vec()
            };
            let at = block.min(archive.len());
            archive.splice(at..at, insert);
        }
        8 if blocks > 1 => {
            // A block removed.
            archive.drain(block..block + 512);
        }
        9 => {
            // Garbage after the end.
            archive.extend((0..rng.below(1000)).map(|_| rng.next() as u8));
        }
        10 if blocks > 0 => {
            // A PAX or long-name block's data scribbled on, checksum
            // untouched: the next blocks are often that data.
            let i = block + rng.below(512) as usize;
            if i < archive.len() {
                archive[i] = rng.pick(&[b'\n', b'=', b' ', b'0', b'9', 0, b',']);
            }
        }
        _ => {}
    }
    archive
}

/// A random name: ASCII or UTF-8, around USTAR's lengths, with slashes.
fn name(rng: &mut Rng) -> String {
    let len = match rng.below(4) {
        0 => rng.pick(&[1, 99, 100, 101, 155, 156, 254, 255, 256, 257]),
        _ => 1 + rng.below(40) as usize,
    };
    let mut s = String::new();
    while s.len() < len {
        let c = match rng.below(20) {
            0 => '/',
            1 => 'é',
            2 => '日',
            _ => char::from(b'a' + rng.below(26) as u8),
        };
        s.push(c);
    }
    s
}

fn json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Headers for Go's Writer, as JSON: every type, long names and link
/// names, owners past what octal holds, times with nanoseconds or before
/// 1970, PAX records and extended attributes, the format chosen or not.
fn headers(rng: &mut Rng, max_size: u64) -> String {
    let count = 1 + rng.below(5);
    let mut list = Vec::new();
    for _ in 0..count {
        let typeflag = rng.pick(&[
            b'0', b'0', b'0', b'5', b'2', b'1', b'3', b'4', b'6', b'g', 0,
        ]);
        let mut fields = vec![
            format!("\"Typeflag\":{typeflag}"),
            format!("\"Name\":{}", json_string(&name(rng))),
        ];
        if matches!(typeflag, b'1' | b'2') {
            fields.push(format!("\"Linkname\":{}", json_string(&name(rng))));
        }
        if matches!(typeflag, b'0' | 0) {
            fields.push(format!("\"Size\":{}", rng.below(max_size + 1)));
        }
        fields.push(format!(
            "\"Mode\":{}",
            rng.pick(&[0o644, 0o755, 0o4755, 0o7777, 0o100644])
        ));
        let id = |rng: &mut Rng| rng.pick(&[0u64, 1000, 0o7777777, 0o10000000, 1 << 40]);
        fields.push(format!("\"Uid\":{},\"Gid\":{}", id(rng), id(rng)));
        if rng.below(2) == 0 {
            let user = if rng.below(4) == 0 {
                "u".repeat(33)
            } else {
                "user".into()
            };
            fields.push(format!("\"Uname\":\"{user}\",\"Gname\":\"staff\""));
        }
        let secs = rng.pick(&[0i64, 1_244_428_340, -1, 8_589_934_592, -62_135_596_800 + 1]);
        let nanos = if rng.below(3) == 0 {
            rng.below(1_000_000_000)
        } else {
            0
        };
        let t = |secs: i64, nanos: u64| format!("\"{}\"", rfc3339(secs, nanos));
        fields.push(format!("\"ModTime\":{}", t(secs, nanos)));
        if rng.below(4) == 0 {
            fields.push(format!(
                "\"AccessTime\":{},\"ChangeTime\":{}",
                t(secs + 1, 0),
                t(secs + 2, nanos)
            ));
        }
        if matches!(typeflag, b'3' | b'4') {
            let dev = |rng: &mut Rng| rng.pick(&[0u64, 8, 0o7777777, 1 << 30]);
            fields.push(format!(
                "\"Devmajor\":{},\"Devminor\":{}",
                dev(rng),
                dev(rng)
            ));
        }
        if rng.below(4) == 0 || typeflag == b'g' {
            let mut records = vec![format!("\"comment\":{}", json_string(&name(rng)))];
            if rng.below(2) == 0 {
                records.push("\"SCHILY.xattr.user.k\":\"v\"".into());
            }
            if rng.below(3) == 0 {
                records.push(format!("\"path\":{}", json_string(&name(rng))));
            }
            fields.push(format!("\"PAXRecords\":{{{}}}", records.join(",")));
        }
        let format = rng.pick(&[0, 0, 0, 2, 4, 8]);
        fields.push(format!("\"Format\":{format}"));
        list.push(format!("{{{}}}", fields.join(",")));
    }
    format!("[{}]", list.join(","))
}

/// RFC 3339 with nanoseconds, from seconds since 1970, as Go's JSON reads
/// times.
fn rfc3339(secs: i64, nanos: u64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{nanos:09}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

/// A header block: USTAR, or GNU's magic for `gnu`, the checksum written.
fn header_block(name: &[u8], typeflag: u8, size: u64, gnu: bool) -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[..name.len().min(100)].copy_from_slice(&name[..name.len().min(100)]);
    b[100..108].copy_from_slice(b"0000644\0");
    b[108..116].copy_from_slice(b"0001750\0");
    b[116..124].copy_from_slice(b"0001750\0");
    b[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    b[136..148].copy_from_slice(b"14724722564\0");
    b[156] = typeflag;
    if gnu {
        b[257..265].copy_from_slice(b"ustar  \0");
    } else {
        b[257..265].copy_from_slice(b"ustar\x0000");
    }
    fix_checksum(&mut b, 0);
    b
}

/// A PAX record, its length counting itself, as `formatPAXRecord` writes it.
fn pax_record(k: &str, v: &str) -> String {
    let size = k.len() + v.len() + 3;
    let size = size + size.to_string().len();
    let record = format!("{size} {k}={v}\n");
    if record.len() == size {
        record
    } else {
        format!("{} {k}={v}\n", record.len())
    }
}

/// `data` and its padding to a block's end.
fn padded(mut data: Vec<u8>) -> Vec<u8> {
    data.resize(data.len().div_ceil(512) * 512, 0);
    data
}

/// A sparse file in one of GNU's formats (0.1 and 1.0 in PAX records, or
/// the old `S` type), its map random and sometimes wrong, and as much
/// dense data as the map needs, give or take a few bytes: what makes the
/// reader's sparse errors come up.
fn sparse_archive(rng: &mut Rng) -> Vec<u8> {
    let count = rng.below(5) as i64;
    let mut map = Vec::new();
    let mut pos = 0i64;
    for _ in 0..count {
        let gap = rng.below(3000) as i64;
        let len = rng.below(2000) as i64;
        let offset = if rng.below(12) == 0 {
            pos - 5
        } else {
            pos + gap
        }; // Sometimes overlapping.
        map.push((offset, len));
        pos = offset + len;
    }
    let real_size = pos + rng.below(3000) as i64;
    let dense: i64 =
        map.iter().map(|&(_, l)| l).sum::<i64>() + rng.pick(&[0i64, 0, 0, -3, -1, 1, 3]);
    let dense = dense.max(0);
    let data: Vec<u8> = (0..dense).map(|i| (i * 13 + 1) as u8).collect();
    let name = b"sparse.bin";
    let mut out = Vec::new();
    match rng.below(3) {
        0 => {
            // GNU 0.1: the map in the records.
            let joined: Vec<String> = map
                .iter()
                .flat_map(|&(o, l)| [o.to_string(), l.to_string()])
                .collect();
            let records = pax_record("GNU.sparse.major", "0")
                + &pax_record("GNU.sparse.minor", "1")
                + &pax_record("GNU.sparse.name", "sparse.bin")
                + &pax_record("GNU.sparse.realsize", &real_size.to_string())
                + &pax_record("GNU.sparse.numblocks", &count.to_string())
                + &pax_record("GNU.sparse.map", &joined.join(","));
            out.extend(header_block(
                b"PaxHeaders/sparse.bin",
                b'x',
                records.len() as u64,
                false,
            ));
            out.extend(padded(records.into_bytes()));
            out.extend(header_block(
                b"GNUSparseFile.0/sparse.bin",
                b'0',
                dense as u64,
                false,
            ));
            out.extend(padded(data));
        }
        1 => {
            // GNU 1.0: the map at the start of the data, in decimal lines.
            let records = pax_record("GNU.sparse.major", "1")
                + &pax_record("GNU.sparse.minor", "0")
                + &pax_record("GNU.sparse.name", "sparse.bin")
                + &pax_record("GNU.sparse.realsize", &real_size.to_string());
            let mut lines = format!("{count}\n");
            for &(o, l) in &map {
                let _ = write!(lines, "{o}\n{l}\n");
            }
            let mut section = padded(lines.into_bytes());
            section.extend(data);
            out.extend(header_block(
                b"PaxHeaders/sparse.bin",
                b'x',
                records.len() as u64,
                false,
            ));
            out.extend(padded(records.into_bytes()));
            out.extend(header_block(
                b"GNUSparseFile.0/sparse.bin",
                b'0',
                section.len() as u64,
                false,
            ));
            out.extend(padded(section));
        }
        _ => {
            // The old GNU format: four entries in the header, more in
            // extension blocks.
            let mut h = header_block(name, b'S', dense as u64, true);
            let mut ext = Vec::new();
            for (i, &(o, l)) in map.iter().enumerate() {
                // Octal cannot say a negative offset.
                let entry = format!("{:011o}\0{l:011o}\0", o.max(0));
                if i < 4 {
                    h[386 + i * 24..386 + i * 24 + 24].copy_from_slice(entry.as_bytes());
                } else {
                    ext.extend_from_slice(entry.as_bytes());
                }
            }
            if !ext.is_empty() {
                h[482] = 1;
            }
            h[483..495].copy_from_slice(format!("{real_size:011o}\0").as_bytes());
            fix_checksum(&mut h, 0);
            out.extend(h);
            if !ext.is_empty() {
                out.extend(padded(ext));
            }
            out.extend(padded(data));
        }
    }
    out.extend([0u8; 1024]);
    if rng.below(3) == 0 {
        damage(rng, out)
    } else {
        out
    }
}

/// The damaged copies of Go's archives: `count` per archive, each from a
/// generator seeded by the archive's name and the copy's number, so that
/// the recorded answers can name them.
fn go_damaged(name: &str, bytes: &[u8], i: u64) -> Vec<u8> {
    let seed = name.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    });
    let mut rng = Rng(seed ^ (i + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let mut archive = damage(&mut rng, bytes.to_vec());
    if rng.below(3) == 0 {
        archive = damage(&mut rng, archive);
    }
    archive
}

/// Archives Go writes from `count` random lists of headers, as they are or
/// damaged.
fn written(oracle: &mut Oracle, rng: &mut Rng, count: usize, max_size: u64) -> Vec<Vec<u8>> {
    let mut archives = Vec::new();
    while archives.len() < count {
        let spec = headers(rng, max_size);
        let reply = oracle.ask(&format!("write {}", hex(spec.as_bytes())));
        let Some(archive) = reply.strip_prefix("ok ") else {
            continue; // The Writer refused these headers.
        };
        let archive = unhex(archive);
        let archive = if rng.below(4) == 0 {
            archive
        } else {
            damage(rng, archive)
        };
        archives.push(archive);
    }
    archives
}

const COPIES: u64 = 20;

#[test]
fn port_matches_go() {
    let Some(mut oracle) = Oracle::spawn("tar-oracle") else {
        return;
    };
    let mut rng = Rng(0x7a2_c001);
    let mut ends = std::collections::BTreeMap::new();
    let mut check = |oracle: &mut Oracle, rng: &mut Rng, archive: &[u8], what: &str| {
        let want = oracle.ask(&format!("read {}", hex(archive)));
        assert_eq!(answer(archive, rng), want, "{what}");
        *ends
            .entry(want.rsplit('|').next().unwrap().to_string())
            .or_insert(0) += 1;
        for entry in want.split('|') {
            if let Some(derr) = entry
                .rsplit(',')
                .next()
                .filter(|d| *d != "-" && entry.contains(','))
            {
                *ends.entry(format!("data:{derr}")).or_insert(0) += 1;
            }
        }
    };
    for (name, bytes) in go_archives() {
        check(&mut oracle, &mut rng, &bytes, &name);
        for i in 0..COPIES {
            let archive = go_damaged(&name, &bytes, i);
            check(
                &mut oracle,
                &mut rng,
                &archive,
                &format!("{name}, damaged #{i}"),
            );
        }
    }
    for archive in written(&mut oracle, &mut rng, 1500, 70_000) {
        check(
            &mut oracle,
            &mut rng,
            &archive,
            &hex(&archive[..archive.len().min(600)]),
        );
    }
    for _ in 0..800 {
        let archive = sparse_archive(&mut rng);
        check(
            &mut oracle,
            &mut rng,
            &archive,
            &hex(&archive[..archive.len().min(1200)]),
        );
    }
    eprintln!("{ends:?}");
    for what in ["eof", "header", "unexpected-eof", "miss-data", "unref-data"] {
        assert!(ends.contains_key(what), "no {what} in {ends:?}");
    }
}

/// Each entry and how the reader stops, with only some of each entry's data read,
/// so that the rest is skipped, by seeking or not.
fn skim<R: Read>(tr: &mut Reader<R>, rng: &mut Rng) -> String {
    let mut out = String::new();
    loop {
        match tr.next() {
            Ok(Some(h)) => {
                let _ = write!(out, "{}:{} ", hex(&h.name), h.size);
            }
            Ok(None) => return out + "eof",
            Err(e) => return out + error_name(&e),
        }
        let mut buf = vec![0; rng.below(3) as usize * 700];
        match tr.read(&mut buf) {
            Ok(n) => {
                let _ = write!(out, "{} ", digest(&buf[..n]));
            }
            Err(e) => return out + error_name(&Error::from(e)),
        }
    }
}

/// An input that says it seeks and cannot.
struct NoSeek<'a>(&'a [u8]);

impl Read for NoSeek<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Seek for NoSeek<'_> {
    fn seek(&mut self, _: SeekFrom) -> std::io::Result<u64> {
        Err(std::io::Error::other("no seeking here"))
    }
}

/// Seeking changes nothing but the time: what is read, and how the reader stops,
/// on damaged archives and archives cut short too. The plain reader is the one
/// compared with Go.
#[test]
fn seeking_changes_nothing() {
    let mut rng = Rng(0x7a2_c005);
    let mut compared = 0;
    for (name, bytes) in go_archives() {
        for i in 0..=COPIES {
            let archive = if i == 0 {
                bytes.clone()
            } else {
                go_damaged(&name, &bytes, i)
            };
            let seed = rng.next();
            let plain = skim(&mut Reader::new(archive.as_slice()), &mut Rng(seed));
            let seeking = skim(&mut Reader::seekable(Cursor::new(&archive)), &mut Rng(seed));
            assert_eq!(seeking, plain, "{name}, #{i}");
            let refused = skim(&mut Reader::seekable(NoSeek(&archive)), &mut Rng(seed));
            assert_eq!(refused, plain, "{name}, #{i}, an input that cannot seek");
            let whole = answer_of(&mut Reader::seekable(Cursor::new(&archive)), &mut Rng(seed));
            assert_eq!(whole, answer(&archive, &mut Rng(seed)), "{name}, #{i}");
            compared += 1;
        }
    }
    assert!(compared > 100, "only {compared} archives");
}

/// An archive of two entries of a MiB, cut short in the data of the first or the
/// second, or at their ends.
#[test]
fn seeking_finds_an_archive_cut_short() {
    let mut archive = Vec::new();
    for name in [&b"first"[..], b"second"] {
        archive.extend_from_slice(&header_block(name, b'0', 1 << 20, false));
        archive.extend(std::iter::repeat_n(7u8, 1 << 20));
    }
    archive.extend_from_slice(&[0; 1024]);
    let mut rng = Rng(1);
    for cut in [
        512,
        513,
        1 << 19,
        512 + (1 << 20) - 1,
        512 + (1 << 20),
        1024 + (1 << 20),
        1024 + (2 << 20) - 1,
        1024 + (2 << 20),
        archive.len(),
    ] {
        let part = &archive[..cut];
        let seed = rng.next();
        let plain = skim(&mut Reader::new(part), &mut Rng(seed));
        let seeking = skim(&mut Reader::seekable(Cursor::new(part)), &mut Rng(seed));
        assert_eq!(seeking, plain, "cut at {cut}");
    }
}

/// What `seekable` is for: the data of entries not read is not read.
#[test]
fn seeking_skips_the_data() {
    struct Counting<'a>(Cursor<&'a [u8]>, u64);

    impl Read for Counting<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.0.read(buf)?;
            self.1 += n as u64;
            Ok(n)
        }
    }

    impl Seek for Counting<'_> {
        fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
            self.0.seek(to)
        }
    }

    let mut archive = Vec::new();
    for i in 0..50 {
        archive.extend_from_slice(&header_block(
            format!("file{i}").as_bytes(),
            b'0',
            1 << 20,
            false,
        ));
        archive.extend(std::iter::repeat_n(7u8, 1 << 20));
    }
    archive.extend_from_slice(&[0; 1024]);
    let mut tr = Reader::seekable(Counting(Cursor::new(&archive), 0));
    let mut count = 0;
    while tr.next().unwrap().is_some() {
        count += 1;
    }
    assert_eq!(count, 50);
    let read = tr.into_inner().1;
    assert!(read < 1 << 16, "{read} bytes read of {}", archive.len());
}

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/tar.txt");
    let archives: std::collections::BTreeMap<String, Vec<u8>> = go_archives().into_iter().collect();
    let mut rng = Rng(0x7a2_c003);
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        let words: Vec<&str> = request.split(' ').collect();
        let archive = match words[..] {
            ["go-tar", name] => archives[name].clone(),
            ["go-tar", name, i] => go_damaged(name, &archives[name], i.parse().unwrap()),
            ["read", archive] => unhex(archive),
            _ => panic!("unknown request {request:.100}"),
        };
        assert_eq!(answer(&archive, &mut rng), want, "{request:.300}");
        checked += 1;
    }
    assert!(checked >= 1000, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/tar.txt from the oracle"]
fn record_oracle_answers() {
    let mut oracle = Oracle::spawn("tar-oracle").expect("the oracle is built");
    let mut rng = Rng(0x7a2_c002);
    let mut text = String::from(
        "# Answers from Go 1.27.2's archive/tar (tools/tar-oracle), replayed by crates/tar/tests/oracle.rs.\n\
         # \"go-tar <file> [<n>]\" is one of Go's test archives, or its damaged copy n.\n\
         # Regenerate with: cargo test -p hivepack-tar --test oracle record_oracle_answers -- --ignored\n",
    );
    for (name, bytes) in go_archives() {
        let reply = oracle.ask(&format!("read {}", hex(&bytes)));
        let _ = writeln!(text, "go-tar {name}\t{reply}");
        for i in 0..COPIES {
            let archive = go_damaged(&name, &bytes, i);
            let reply = oracle.ask(&format!("read {}", hex(&archive)));
            let _ = writeln!(text, "go-tar {name} {i}\t{reply}");
        }
    }
    // Small written archives and sparse files, in full.
    let mut archives = written(&mut oracle, &mut rng, 50, 300);
    archives.extend((0..50).map(|_| sparse_archive(&mut rng)));
    for archive in archives {
        let request = format!("read {}", hex(&archive));
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{reply}");
    }
    std::fs::create_dir_all(recorded_path().parent().expect("folder")).expect("folder");
    std::fs::write(recorded_path(), text).expect("written");
}
