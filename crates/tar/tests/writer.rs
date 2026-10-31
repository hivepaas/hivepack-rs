//! The writer against Go's `tar.Writer` through `tools/tar-oracle`: random
//! calls on one writer, its headers all kinds of right and wrong and its output
//! sometimes failing, and Go's test archives read and written again. The errors
//! of each call and every byte written must be the same.
//!
//! - With the oracle built, everything is compared with Go directly.
//! - Everywhere, `testdata/oracle/tar-writer.txt` replays answers Go gave earlier,
//!   by the seed of a script or the name of an archive, without the archives
//!   themselves. `cargo test -p hivepack-tar --test writer record_oracle_answers
//!   -- --ignored` rewrites that file.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use hivepack_crypto::Sha256;
use hivepack_tar::{Error, Format, Header, Reader, Records, TYPE_DIR, TYPE_REG, Time, Writer};
use support::{Oracle, Rng, go_archives, hex, repository};

/// How much of an entry's data is rewritten: as the oracle reads.
const MAX_DATA: u64 = 8 << 20;

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/tar-writer.txt")
}

fn error_name(e: &Error) -> String {
    match e {
        Error::Header => "header".into(),
        Error::FieldTooLong => "field-too-long".into(),
        Error::SparseTooLong => "sparse-too-long".into(),
        Error::MissData => "miss-data".into(),
        Error::UnrefData => "unref-data".into(),
        Error::UnexpectedEof => "unexpected-eof".into(),
        Error::WriteTooLong => "write-too-long".into(),
        Error::WriteAfterClose => "write-after-close".into(),
        Error::MissedWriting(n) => format!("missed-{n}"),
        Error::CannotEncode(_) => "cannot-encode".into(),
        Error::Io(_) => "other".into(),
    }
}

fn outcome(result: Result<(), Error>) -> String {
    match result {
        Ok(()) => "-".into(),
        Err(e) => error_name(&e),
    }
}

/// An output with room for so many bytes, or any if `None`. It takes what fits,
/// and fails the next write, as the oracle's fails with what it took.
struct Output {
    bytes: Vec<u8>,
    room: Option<u64>,
}

impl Write for Output {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = match self.room {
            None => b.len(),
            Some(0) if !b.is_empty() => return Err(io::Error::other("the output is full")),
            Some(room) => b.len().min(usize::try_from(room).unwrap_or(usize::MAX)),
        };
        self.bytes.extend_from_slice(&b[..n]);
        if let Some(room) = &mut self.room {
            *room -= n as u64;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// One step of a script.
struct Step {
    header: Header,
    data: usize,
    flush: bool,
}

/// A random name: every length that matters, ASCII or not, and paths that
/// need cleaning.
fn random_name(rng: &mut Rng) -> Vec<u8> {
    if rng.below(12) == 0 {
        let fixed: [&[u8]; 14] = [
            b"",
            b".",
            b"..",
            b"/",
            b"//",
            b"./",
            b"../",
            b"a/../..",
            b"/..",
            b"./a/./b//c",
            b"a/b/",
            b"/rooted/file",
            b"/../a/\xc3\xa9",
            b"../../a/../\xc3\xa9",
        ];
        return fixed[rng.below(fixed.len() as u64) as usize].to_vec();
    }
    let len = match rng.below(4) {
        0 => rng.pick(&[
            99usize, 100, 101, 154, 155, 156, 157, 200, 254, 255, 256, 257, 500,
        ]),
        _ => 1 + rng.below(40) as usize,
    };
    // ASCII, or USTAR's two fields would never hold a long name.
    let ascii = rng.below(2) == 0;
    let unusual = !ascii && rng.below(4) == 0;
    let mut s = Vec::new();
    while s.len() < len {
        match rng.below(if unusual { 24 } else { 20 }) {
            0..=1 => s.push(b'/'),
            2 | 3 if ascii => s.push(b'.'),
            2 => s.extend_from_slice("é".as_bytes()),
            3 => s.extend_from_slice("日".as_bytes()),
            20 => s.push(0xff),
            21 => s.push(0),
            22 => s.extend_from_slice(b"../"),
            23 => s.extend_from_slice(b"./"),
            _ => s.push(b'a' + rng.below(26) as u8),
        }
    }
    if rng.below(8) == 0 {
        s.push(b'/');
    }
    s
}

fn random_owner(rng: &mut Rng) -> Vec<u8> {
    match rng.below(8) {
        0 => b"u".repeat(rng.pick(&[31usize, 32, 33, 40])),
        1 => "útf".as_bytes().to_vec(),
        2 => b"nu\0l".to_vec(),
        3 | 4 => b"user".to_vec(),
        _ => Vec::new(),
    }
}

fn random_time(rng: &mut Rng) -> Option<Time> {
    let secs = rng.pick(&[
        0i64,
        1_244_428_340,
        -1,
        -62_135_596_800,
        -62_135_596_801,
        0o77777777777,
        0o100000000000,
        1 << 40,
        -(1 << 40),
    ]);
    let nanos = match rng.below(6) {
        0 => rng.below(1_000_000_000) as u32,
        1 => 500_000_000,
        2 => 499_999_999,
        _ => 0,
    };
    Some(Time { secs, nanos })
}

fn random_records(rng: &mut Rng, name: &[u8], size: i64, uid: i64, time: Option<Time>) -> Records {
    let mut m = Records::new();
    for _ in 0..1 + rng.below(4) {
        let (k, v): (&[u8], Vec<u8>) = match rng.below(16) {
            0 => (b"path", name.to_vec()),
            1 => (b"path", b"other".to_vec()),
            2 => (b"size", size.to_string().into_bytes()),
            3 => (b"uid", uid.to_string().into_bytes()),
            4 => (
                b"mtime",
                time.map_or(0, |t| t.secs).to_string().into_bytes(),
            ),
            5 => (b"", b"0".to_vec()),
            6 => (b"k=ey", b"v".to_vec()),
            7 => (b"linkpath", b"nu\0l".to_vec()),
            8 => (b"GNU.sparse.map", b"0,1".to_vec()),
            9 => (b"nu\0l", b"v".to_vec()),
            10 => (b"SCHILY.xattr.user.k", b"va\0lue".to_vec()),
            11 => (b"gname", b"group".to_vec()),
            _ => (b"comment", random_name(rng)),
        };
        m.insert(k.to_vec(), v);
    }
    m
}

/// A random script, the same from a seed on every machine.
fn script(seed: u64) -> (Option<u64>, Vec<Step>) {
    let rng = &mut Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let room = match rng.below(5) {
        0 => Some(rng.below(6000)),
        _ => None,
    };
    let count = 1 + rng.below(5);
    // Half the scripts have fields that fit, and go on to what follows from the
    // names, the times and the format asked for.
    let plain = rng.below(2) == 0;
    let steps = (0..count)
        .map(|_| {
            let typeflag = rng.pick(&[
                b'0', b'0', b'0', b'0', 0, 0, b'5', b'2', b'1', b'3', b'4', b'6', b'7', b'g', b'x',
                b'L', b'K', b'S', b'Z',
            ]);
            let mut h = Header {
                typeflag,
                name: random_name(rng),
                ..Default::default()
            };
            if typeflag == b'g' && rng.below(2) == 0 {
                h.name.clear();
            }
            if rng.below(32) == 0 {
                // Past the 1 MiB of PAX's records.
                h.name = b"n".repeat(rng.pick(&[(1 << 20) - 16, (1 << 20) + 16]));
            }
            if matches!(typeflag, b'1' | b'2') || rng.below(16) == 0 {
                h.linkname = random_name(rng);
            }
            h.size = match rng.below(12) {
                0 => rng.pick(&[-1, 0o77777777777, 0o100000000000, i64::MAX]),
                1..=3 => 0,
                _ => rng.below(70_000) as i64,
            };
            if typeflag == b'g' && rng.below(4) != 0 {
                h.size = 0;
            }
            if typeflag != b'g' || rng.below(4) == 0 {
                h.mode = rng.pick(&[
                    0o644, 0o755, 0o4755, 0o7777, 0o100644, 0o7777777, 0o10000000, -1,
                ]);
                let id = |rng: &mut Rng| {
                    rng.pick(&[0i64, 1000, 0o7777777, 0o10000000, 1 << 40, 1 << 56, -1])
                };
                (h.uid, h.gid) = (id(rng), id(rng));
                h.uname = random_owner(rng);
                h.gname = random_owner(rng);
                h.mod_time = random_time(rng);
                if plain {
                    h.mode = 0o644;
                    (h.uid, h.gid) = (1000, 1000);
                    (h.uname, h.gname) = (b"user".to_vec(), b"staff".to_vec());
                    h.mod_time = Some(Time {
                        secs: 1_244_428_340,
                        nanos: h.mod_time.map_or(0, |t| t.nanos),
                    });
                }
                if !plain && rng.below(3) == 0 {
                    h.access_time = random_time(rng);
                    h.change_time = random_time(rng);
                }
            }
            if matches!(typeflag, b'3' | b'4') || rng.below(16) == 0 {
                let dev = |rng: &mut Rng| rng.pick(&[0i64, 8, 0o7777777, 0o10000000, 1 << 56, -1]);
                (h.devmajor, h.devminor) = (dev(rng), dev(rng));
            }
            if rng.below(4) == 0 {
                h.pax_records = random_records(rng, &h.name, h.size, h.uid, h.mod_time);
            }
            if rng.below(32) == 0 {
                h.pax_records
                    .insert(b"big".to_vec(), vec![b'b'; (1 << 20) + 1]);
            }
            if rng.below(8) == 0 {
                h.xattrs.insert(b"user.k".to_vec(), b"v".to_vec());
            }
            if rng.below(32) == 0 {
                h.xattrs.insert(b"nu\0l".to_vec(), b"v".to_vec());
            }
            let formats = [
                Format::UNKNOWN,
                Format::UNKNOWN,
                Format::UNKNOWN,
                Format::USTAR,
                Format::PAX,
                Format::GNU,
                Format::V7,
                Format::STAR,
                Format::USTAR.union(Format::PAX),
                Format::PAX.union(Format::GNU),
            ];
            h.format = rng.pick(&formats);
            // Usually all the data; else too little or too much.
            let size = h.size.clamp(0, 70_000) as usize;
            let data = match rng.below(if plain { 40 } else { 8 }) {
                0 => size.saturating_sub(1 + rng.below(600) as usize),
                1 => size + 1 + rng.below(600) as usize,
                _ => size,
            };
            Step {
                header: h,
                data,
                flush: rng.below(4) == 0,
            }
        })
        .collect();
    (room, steps)
}

fn when(t: Option<Time>) -> String {
    match t {
        None => "-".into(),
        Some(t) => format!("{}.{}", t.secs, t.nanos),
    }
}

fn records_text(m: &Records) -> String {
    if m.is_empty() {
        return "-".into();
    }
    let list: Vec<String> = m
        .iter()
        .map(|(k, v)| format!("{}:{}", hex(k), hex(v)))
        .collect();
    list.join(";")
}

/// The request for the oracle.
fn request(room: Option<u64>, steps: &[Step]) -> String {
    let mut text = format!("script {}", room.map_or(-1, |r| r as i64));
    for s in steps {
        let h = &s.header;
        let _ = write!(
            text,
            " {},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
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
            records_text(&h.xattrs),
            records_text(&h.pax_records),
            s.data,
            u8::from(s.flush),
        );
    }
    text
}

fn digest(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex(&h.out()[..8])
}

/// `data` written in pieces of random sizes, always at least once as Go's
/// Write is: the bytes it took, and what stopped it.
fn write_data<W: Write>(tw: &mut Writer<W>, data: &[u8], rng: &mut Rng) -> (usize, String) {
    let mut done = 0;
    loop {
        let piece = (1 + rng.below(70_000) as usize).min(data.len() - done);
        match tw.write(&data[done..done + piece]) {
            Ok(n) => done += n,
            Err(e) => return (done, error_name(&Error::from(e))),
        }
        if done == data.len() {
            return (done, "-".into());
        }
    }
}

/// The port's answer to a script, as the oracle words it, and the archive.
fn run(room: Option<u64>, steps: &[Step], rng: &mut Rng) -> (String, Vec<u8>) {
    let mut tw = Writer::new(Output {
        bytes: Vec::new(),
        room,
    });
    let mut answer = Vec::new();
    for s in steps {
        let herr = outcome(tw.write_header(&s.header));
        let data: Vec<u8> = (0..s.data)
            .map(|j| (j * 7 + s.header.name.len()) as u8)
            .collect();
        let (n, werr) = write_data(&mut tw, &data, rng);
        let ferr = if s.flush {
            outcome(tw.finish_entry())
        } else {
            "-".into()
        };
        answer.push(format!("{herr},{n},{werr},{ferr}"));
    }
    let first = outcome(tw.close());
    let second = outcome(tw.close());
    let third = outcome(tw.write_header(&Header {
        typeflag: TYPE_REG,
        name: b"after".to_vec(),
        ..Default::default()
    }));
    let fourth = match tw.write(b"x") {
        Ok(_) => "-".to_string(),
        Err(e) => error_name(&Error::from(e)),
    };
    answer.push(format!("{first},{second},{third},{fourth}"));
    let archive = tw.into_inner().bytes;
    answer.push(format!("{},{}", archive.len(), digest(&archive)));
    (answer.join("|"), archive)
}

/// The port's answer to `rewrite <archive>`, as the oracle words it, and what
/// it wrote.
fn rewrite(archive: &[u8], rng: &mut Rng) -> (String, Vec<u8>) {
    let mut tr = Reader::new(archive);
    let mut tw = Writer::new(Vec::new());
    let mut answer = Vec::new();
    loop {
        let h = match tr.next() {
            Ok(Some(h)) => h,
            Ok(None) => {
                answer.push("eof".to_string());
                break;
            }
            Err(e) => {
                answer.push(error_name(&e));
                break;
            }
        };
        let herr = outcome(tw.write_header(&h));
        let mut data = Vec::new();
        let derr = match (&mut tr).take(MAX_DATA).read_to_end(&mut data) {
            Ok(_) => "-".to_string(),
            Err(e) => error_name(&Error::from(e)),
        };
        let (n, werr) = write_data(&mut tw, &data, rng);
        answer.push(format!("{herr},{n},{werr},{derr}"));
    }
    answer.push(outcome(tw.close()));
    let out = tw.into_inner();
    answer.push(format!("{},{}", out.len(), digest(&out)));
    (answer.join("|"), out)
}

/// Where two archives first differ, for the failure's message.
fn first_difference(a: &[u8], b: &[u8]) -> String {
    let at = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let piece = |s: &[u8]| hex(&s[at.saturating_sub(16).min(s.len())..(at + 16).min(s.len())]);
    format!("at {at}: the port {}, Go {}", piece(a), piece(b))
}

/// Compares an answer with the oracle's, which ends in the archive.
fn compare(port: &(String, Vec<u8>), reply: &str, what: &str) {
    let (want, archive) = reply.rsplit_once('|').expect("the archive");
    let archive = support::unhex(archive);
    assert_eq!(
        port.0,
        want,
        "{what:.2000}\n{}",
        first_difference(&port.1, &archive)
    );
    assert_eq!(port.1, archive, "{what:.2000}");
}

const SCRIPTS: u64 = 3000;
const RECORDED: u64 = 1000;

/// Every call's error and every byte as Go's, and every outcome among them.
#[test]
fn port_matches_go() {
    let Some(mut oracle) = Oracle::spawn("tar-oracle") else {
        return;
    };
    let mut rng = Rng(0x7a2_d001);
    let mut seen = std::collections::BTreeMap::new();
    for seed in 0..SCRIPTS {
        let (room, steps) = script(seed);
        let text = request(room, &steps);
        let reply = oracle.ask(&text);
        compare(&run(room, &steps, &mut rng), &reply, &text);
        let (calls, _) = reply.rsplit_once('|').unwrap();
        let (calls, _) = calls.rsplit_once('|').unwrap();
        for word in calls.split(['|', ',']) {
            let word = if word.starts_with("missed-") {
                "missed"
            } else {
                word
            };
            if word.parse::<u64>().is_err() {
                *seen.entry(word.to_string()).or_insert(0) += 1;
            }
        }
    }
    eprintln!("{seen:?}");
    for what in [
        "cannot-encode",
        "field-too-long",
        "write-too-long",
        "write-after-close",
        "missed",
        "other",
    ] {
        assert!(seen.contains_key(what), "no {what} in {seen:?}");
    }
}

/// Headers the reader gave, written again as Go writes them, with Go's
/// archives.
#[test]
fn rewriting_matches_go() {
    let Some(mut oracle) = Oracle::spawn("tar-oracle") else {
        return;
    };
    let mut rng = Rng(0x7a2_d002);
    for (name, bytes) in go_archives() {
        let reply = oracle.ask(&format!("rewrite {}", hex(&bytes)));
        compare(&rewrite(&bytes, &mut rng), &reply, &name);
    }
}

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/tar-writer.txt");
    let archives: std::collections::BTreeMap<String, Vec<u8>> = go_archives().into_iter().collect();
    let mut rng = Rng(0x7a2_d003);
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        let got = match request.split_once(' ').expect("two words") {
            ("script", seed) => {
                let (room, steps) = script(seed.parse().unwrap());
                run(room, &steps, &mut rng).0
            }
            ("go-tar", name) => rewrite(&archives[name], &mut rng).0,
            _ => panic!("unknown request {request}"),
        };
        assert_eq!(got, want, "{request}");
        checked += 1;
    }
    assert!(checked >= RECORDED, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/tar-writer.txt from the oracle"]
fn record_oracle_answers() {
    let mut oracle = Oracle::spawn("tar-oracle").expect("the oracle is built");
    let mut text = String::from(
        "# Answers from Go 1.27.2's archive/tar (tools/tar-oracle), replayed by crates/tar/tests/writer.rs.\n\
         # \"script <n>\" is the script of that seed; \"go-tar <file>\" is one of Go's test archives written again.\n\
         # Regenerate with: cargo test -p hivepack-tar --test writer record_oracle_answers -- --ignored\n",
    );
    for seed in 0..RECORDED {
        let (room, steps) = script(seed);
        let reply = oracle.ask(&request(room, &steps));
        let (answer, _) = reply.rsplit_once('|').unwrap();
        let _ = writeln!(text, "script {seed}\t{answer}");
    }
    for (name, bytes) in go_archives() {
        let reply = oracle.ask(&format!("rewrite {}", hex(&bytes)));
        let (answer, _) = reply.rsplit_once('|').unwrap();
        let _ = writeln!(text, "go-tar {name}\t{answer}");
    }
    std::fs::write(recorded_path(), text).expect("written");
}

/// The format the reader finds a header written in, with its names and size checked.
fn format_of(h: &Header) -> Format {
    let mut tw = Writer::new(Vec::new());
    tw.write_header(h).unwrap();
    tw.write_all(&vec![0; h.size as usize]).unwrap();
    tw.close().unwrap();
    let bytes = tw.into_inner();
    let mut tr = Reader::new(bytes.as_slice());
    let read = tr.next().unwrap().unwrap();
    assert_eq!(read.name, h.name);
    assert_eq!(read.linkname, h.linkname);
    assert_eq!(read.size, h.size);
    read.format
}

/// The first of USTAR, PAX and GNU that can hold the header, and the reader
/// finds what was written.
#[test]
fn the_format_is_chosen_and_read_back() {
    let file = |name: &str| Header {
        typeflag: TYPE_REG,
        name: name.as_bytes().to_vec(),
        size: 700,
        mode: 0o644,
        ..Default::default()
    };
    assert_eq!(format_of(&file("short.txt")), Format::USTAR);
    // Long, but cut at a slash into USTAR's two fields.
    let split = format!("{}/{}", "d".repeat(120), "f".repeat(90));
    assert_eq!(format_of(&file(&split)), Format::USTAR);
    assert_eq!(format_of(&file("日本語.txt")), Format::PAX);
    assert_eq!(
        format_of(&file(&"long/".repeat(100).replace('/', "-"))),
        Format::PAX
    );
    let gnu = Header {
        format: Format::GNU,
        ..file(&"n".repeat(300))
    };
    assert_eq!(format_of(&gnu), Format::GNU);
    let folder = Header {
        typeflag: TYPE_DIR,
        name: b"folder/".to_vec(),
        ..Default::default()
    };
    assert_eq!(format_of(&folder), Format::USTAR);
}

/// Without a format the fraction of a second is rounded away and the other times
/// left out; with one they are kept.
#[test]
fn times_need_a_format() {
    let h = Header {
        typeflag: TYPE_REG,
        name: b"t".to_vec(),
        mod_time: Some(Time {
            secs: 100,
            nanos: 500_000_000,
        }),
        access_time: Some(Time { secs: 7, nanos: 0 }),
        ..Default::default()
    };
    let read = |h: &Header| {
        let mut tw = Writer::new(Vec::new());
        tw.write_header(h).unwrap();
        tw.close().unwrap();
        let bytes = tw.into_inner();
        Reader::new(bytes.as_slice()).next().unwrap().unwrap()
    };
    let plain = read(&h);
    assert_eq!(
        plain.mod_time,
        Some(Time {
            secs: 101,
            nanos: 0
        })
    );
    assert_eq!(plain.access_time, None);
    let pax = read(&Header {
        format: Format::PAX,
        ..h
    });
    assert_eq!(
        pax.mod_time,
        Some(Time {
            secs: 100,
            nanos: 500_000_000
        })
    );
    assert_eq!(pax.access_time, Some(Time { secs: 7, nanos: 0 }));
}

/// A wrong header fails alone; an output that fails stays failed.
#[test]
fn errors_stay_or_not_as_go() {
    let mut tw = Writer::new(Vec::new());
    let bad = Header {
        typeflag: TYPE_REG,
        name: b"folder/".to_vec(),
        ..Default::default()
    };
    assert!(matches!(tw.write_header(&bad), Err(Error::CannotEncode(_))));
    let good = Header {
        typeflag: TYPE_REG,
        name: b"f".to_vec(),
        size: 3,
        ..Default::default()
    };
    tw.write_header(&good).unwrap();
    assert!(matches!(tw.finish_entry(), Err(Error::MissedWriting(3))));
    assert!(matches!(
        tw.write_header(&good),
        Err(Error::MissedWriting(3))
    ));
    let err = tw.write_all(b"abcd").unwrap_err();
    assert!(matches!(Error::from(err), Error::WriteTooLong));
    tw.write_header(&good).unwrap(); // All three bytes were taken.
    tw.write_all(b"abc").unwrap();
    tw.close().unwrap();
    assert_eq!(tw.into_inner().len(), 2 * 1024 + 1024);

    let mut tw = Writer::new(Output {
        bytes: Vec::new(),
        room: Some(100),
    });
    assert!(matches!(tw.write_header(&good), Err(Error::Io(_))));
    assert!(matches!(tw.write_header(&good), Err(Error::Io(_))));
    assert!(tw.write(b"a").is_err());
    assert!(matches!(tw.close(), Err(Error::Io(_))));
}

/// `flush` is the output's, and can come in the middle of an entry, as a buffer
/// around the writer does.
#[test]
fn flushing_in_the_middle_of_an_entry() {
    let mut tw = Writer::new(Vec::new());
    tw.write_header(&Header {
        typeflag: TYPE_REG,
        name: b"f".to_vec(),
        size: 3,
        ..Default::default()
    })
    .unwrap();
    tw.write_all(b"a").unwrap();
    tw.flush().unwrap();
    tw.write_all(b"bc").unwrap();
    tw.flush().unwrap();
    assert_eq!(tw.get_ref().len(), 515);
    tw.close().unwrap();
    tw.flush().unwrap();
    assert_eq!(tw.get_ref().len(), 2048);
}
