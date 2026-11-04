//! Going on from an entry whose data is damaged, as `Options::on_damaged` says:
//! the entry left out or kept as it came, the rest extracted, and each listed in
//! `Summary::damaged`. Only damage is asked about: what is refused for what an
//! archive could do to the destination, and the limits, stop whatever the answer.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "extract_support/mod.rs"]
mod support;

use std::io::{self, Cursor};
use std::sync::{Arc, Mutex};

use hivepack::extract::{
    Entry, Error, ErrorKind, OnDamaged, OnDamagedFn, Options, Sink, extract_7z, extract_cpio,
    extract_iso, extract_tar, extract_zip, extract_zip_to,
};
use hivepack::zip::{Archive, OpenFlags};

use support::{Entry as Z, Scratch};

/// A callback that answers `how`, and keeps the names it was asked about.
fn answering(how: OnDamaged) -> (OnDamagedFn, Arc<Mutex<Vec<String>>>) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let kept = asked.clone();
    let f: OnDamagedFn = Arc::new(move |error: &Error| {
        assert!(error.kind.is_damage(), "{error}");
        let name = String::from_utf8_lossy(error.name.as_deref().unwrap_or_default()).into_owned();
        kept.lock().unwrap().push(name);
        how
    });
    (f, asked)
}

fn with(on_damaged: OnDamagedFn) -> Options {
    support::options(|o| o.on_damaged = Some(on_damaged))
}

/// Three stored files, the middle one's data changed so that its CRC-32 fails.
fn zip_with_bad_crc() -> Vec<u8> {
    let mut data = support::zip(&[
        Z::Stored(b"good", b"good data"),
        Z::Stored(b"bad", b"bad data"),
        Z::Stored(b"after", b"after data"),
    ]);
    let at = data.windows(8).position(|w| w == b"bad data").unwrap();
    data[at] = b'B';
    data
}

fn zip_extract(
    data: &[u8],
    out: &std::path::Path,
    options: &Options,
) -> Result<hivepack::extract::Summary, Error> {
    let archive = Archive::open(data, OpenFlags::CHECKCONS).unwrap();
    extract_zip(&archive, out, options)
}

#[test]
fn without_an_answer_it_stops() {
    let scratch = Scratch::new();
    let e = zip_extract(&zip_with_bad_crc(), &scratch.out(), &portable()).unwrap_err();
    assert!(e.kind.is_damage(), "{e}");
    assert!(!scratch.out().join("bad").exists());
    assert!(!scratch.out().join("after").exists());

    let (f, asked) = answering(OnDamaged::Stop);
    let scratch = Scratch::new();
    let e = zip_extract(&zip_with_bad_crc(), &scratch.out(), &with(f)).unwrap_err();
    assert!(e.kind.is_damage(), "{e}");
    assert_eq!(*asked.lock().unwrap(), ["bad"]);
    assert!(!scratch.out().join("bad").exists());
}

#[test]
fn skip_leaves_it_out_and_goes_on() {
    let (f, asked) = answering(OnDamaged::Skip);
    let scratch = Scratch::new();
    let summary = zip_extract(&zip_with_bad_crc(), &scratch.out(), &with(f)).unwrap();
    assert_eq!(*asked.lock().unwrap(), ["bad"]);
    assert_eq!(support::listing(&scratch.out()), ["after", "good"]);
    assert_eq!((summary.files, summary.bytes), (2, 19));
    assert_eq!(summary.damaged.len(), 1);
    assert_eq!(summary.damaged[0].error.name.as_deref(), Some(&b"bad"[..]));
    assert_eq!(summary.damaged[0].kept, None);
}

#[test]
fn keep_keeps_it_as_it_came() {
    let (f, _) = answering(OnDamaged::Keep);
    let scratch = Scratch::new();
    let summary = zip_extract(&zip_with_bad_crc(), &scratch.out(), &with(f)).unwrap();
    assert_eq!(support::listing(&scratch.out()), ["after", "bad", "good"]);
    assert_eq!(
        std::fs::read(scratch.out().join("bad")).unwrap(),
        b"Bad data"
    );
    assert_eq!(summary.files, 3);
    assert_eq!(summary.damaged[0].kept, Some(8));
}

#[test]
fn data_that_does_not_decompress_is_kept_to_where_it_failed() {
    let body = b"compressible text, many times over. ".repeat(4000);
    let mut data = support::zip(&[Z::File(b"text", &body), Z::File(b"after", b"after")]);
    // A run of bytes in the middle of the Deflate stream.
    let start = 30 + 4 + 200;
    for byte in &mut data[start..start + 32] {
        *byte ^= 0x5a;
    }
    let (f, _) = answering(OnDamaged::Keep);
    let scratch = Scratch::new();
    let summary = zip_extract(&data, &scratch.out(), &with(f)).unwrap();
    let kept = std::fs::read(scratch.out().join("text")).unwrap();
    assert_eq!(summary.damaged[0].kept, Some(kept.len() as u64));
    assert!(kept.len() <= body.len());
    assert_eq!(
        std::fs::read(scratch.out().join("after")).unwrap(),
        b"after"
    );
}

#[test]
fn what_is_refused_is_not_asked_about() {
    let (f, asked) = answering(OnDamaged::Keep);
    let data = support::zip(&[Z::File(b"fine", b"x"), Z::File(b"../up", b"y")]);
    let scratch = Scratch::new();
    let e = zip_extract(&data, &scratch.out(), &with(f.clone())).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Name(_)), "{e}");

    let mut options = with(f);
    options.limits.max_entry_size = 4;
    let e = zip_extract(&zip_with_bad_crc(), &scratch.out(), &options).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::EntryTooLarge), "{e}");
    assert!(asked.lock().unwrap().is_empty());
}

/// A sink that keeps what it is told of damage, between the file's start and
/// end.
#[derive(Default)]
struct Told(Vec<String>);

impl Sink for Told {
    fn directory(&mut self, _: &Entry<'_>) -> io::Result<()> {
        Ok(())
    }
    fn start_file(&mut self, entry: &Entry<'_>) -> io::Result<()> {
        self.0.push(format!("start {}", entry.path.join("/")));
        Ok(())
    }
    fn write(&mut self, _: &[u8]) -> io::Result<()> {
        Ok(())
    }
    fn finish_file(&mut self) -> io::Result<()> {
        self.0.push("finish".into());
        Ok(())
    }
    fn discard_file(&mut self) {
        self.0.push("discard".into());
    }
    fn symlink(&mut self, _: &Entry<'_>, _: &str) -> io::Result<()> {
        Ok(())
    }
    fn hard_link(&mut self, _: &Entry<'_>, _: &[String]) -> io::Result<()> {
        Ok(())
    }
    fn damaged(&mut self, error: &Error) {
        assert!(error.kind.is_damage());
        self.0.push("damaged".into());
    }
}

#[test]
fn a_sink_is_told_before_the_file_ends() {
    let data = zip_with_bad_crc();
    let archive = Archive::open(&data[..], OpenFlags::CHECKCONS).unwrap();
    for (how, end) in [(OnDamaged::Keep, "finish"), (OnDamaged::Skip, "discard")] {
        let mut told = Told::default();
        let summary = extract_zip_to(&archive, &mut told, &with(answering(how).0)).unwrap();
        assert_eq!(
            told.0,
            [
                "start good",
                "finish",
                "start bad",
                "damaged",
                end,
                "start after",
                "finish"
            ],
            "{how:?}"
        );
        assert_eq!(summary.damaged.len(), 1);
    }
}

/// A USTAR header block, its checksum written.
fn tar_header(name: &[u8], size: u64) -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[..name.len()].copy_from_slice(name);
    b[100..108].copy_from_slice(b"0000644\0");
    b[108..116].copy_from_slice(b"0001750\0");
    b[116..124].copy_from_slice(b"0001750\0");
    b[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    b[136..148].copy_from_slice(b"13745013000\0");
    b[156] = b'0';
    b[257..265].copy_from_slice(b"ustar\x0000");
    b[148..156].fill(b' ');
    let sum: u32 = b.iter().map(|&c| u32::from(c)).sum();
    b[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    b
}

#[test]
fn a_stream_cut_short_keeps_what_came() {
    let mut data = tar_header(b"first", 5);
    data.extend(b"hello");
    data.resize(1024, 0);
    data.extend(tar_header(b"cut", 3000));
    data.extend([b'z'; 1000]);
    // The stream ends there, in the middle of the second file's data.
    let open = || Ok(Cursor::new(data.clone()));
    let scratch = Scratch::new();
    let e = extract_tar(open, &scratch.out(), &portable()).unwrap_err();
    assert!(e.kind.is_damage(), "{e}");
    assert!(
        !scratch.out().exists(),
        "nothing is written without an answer"
    );

    let (f, asked) = answering(OnDamaged::Keep);
    let scratch = Scratch::new();
    let summary = extract_tar(open, &scratch.out(), &with(f)).unwrap();
    assert_eq!(*asked.lock().unwrap(), ["cut"]);
    assert_eq!(
        std::fs::read(scratch.out().join("first")).unwrap(),
        b"hello"
    );
    assert_eq!(
        std::fs::read(scratch.out().join("cut")).unwrap(),
        [b'z'; 1000]
    );
    assert_eq!(summary.damaged[0].kept, Some(1000));

    let (f, _) = answering(OnDamaged::Skip);
    let scratch = Scratch::new();
    extract_tar(open, &scratch.out(), &with(f)).unwrap();
    assert_eq!(support::listing(&scratch.out()), ["first"]);
}

#[test]
fn a_stream_cut_in_a_header_is_asked_about_once() {
    let mut data = tar_header(b"first", 5);
    data.extend(b"hello");
    data.resize(1024, 0);
    data.extend(&tar_header(b"next", 5)[..300]);
    let asked = Arc::new(Mutex::new(Vec::new()));
    let kept = asked.clone();
    let f: OnDamagedFn = Arc::new(move |error: &Error| {
        kept.lock().unwrap().push((error.index, error.name.clone()));
        OnDamaged::Skip
    });
    let scratch = Scratch::new();
    let summary = extract_tar(|| Ok(Cursor::new(data.clone())), &scratch.out(), &with(f)).unwrap();
    // No entry to name: where the next would have been.
    assert_eq!(*asked.lock().unwrap(), [(Some(1), None)]);
    assert_eq!(support::listing(&scratch.out()), ["first"]);
    assert_eq!(summary.damaged.len(), 1);
}

/// A 7z archive of two folders: `a` and `b`, solid, compressed; then `c`,
/// stored.
fn seven_zip_of_two_folders() -> Vec<u8> {
    use hivepack::sevenz::{Method, NewEntry, Writer};
    let mut writer = Writer::new(Cursor::new(Vec::new())).unwrap();
    writer.set_method(Method::Lzma2 { preset: 6 }).unwrap();
    let a = b"first file in the solid block. ".repeat(2000);
    let b = b"second file in the solid block. ".repeat(2000);
    writer.add_file(NewEntry::new("a"), &mut &a[..]).unwrap();
    writer.add_file(NewEntry::new("b"), &mut &b[..]).unwrap();
    writer.set_method(Method::Copy).unwrap();
    writer
        .add_file(NewEntry::new("c"), &mut &b"stored apart"[..])
        .unwrap();
    writer.finish().unwrap().into_inner()
}

#[test]
fn a_broken_solid_block_loses_its_files_not_the_next_blocks() {
    let mut data = seven_zip_of_two_folders();
    // The start of the first folder's packed data, after the signature header.
    for byte in &mut data[32 + 40..32 + 80] {
        *byte ^= 0xa5;
    }
    let open = || hivepack::sevenz::Archive::open(Cursor::new(data.clone())).unwrap();
    let scratch = Scratch::new();
    assert!(extract_7z(&mut open(), &scratch.out(), &portable()).is_err());

    let (f, asked) = answering(OnDamaged::Skip);
    let scratch = Scratch::new();
    let summary = extract_7z(&mut open(), &scratch.out(), &with(f)).unwrap();
    assert_eq!(support::listing(&scratch.out()), ["c"]);
    assert_eq!(
        std::fs::read(scratch.out().join("c")).unwrap(),
        b"stored apart"
    );
    assert_eq!(*asked.lock().unwrap(), ["a", "b"]);
    assert_eq!(summary.damaged.len(), 2);
}

/// A newc cpio entry.
fn newc(out: &mut Vec<u8>, name: &[u8], mode: u32, data: &[u8], size: u32) {
    let fields = [
        1,
        mode,
        0,
        0,
        1,
        1_600_000_000,
        size,
        8,
        1,
        1,
        3,
        name.len() as u32 + 1,
        0,
    ];
    out.extend(b"070701");
    for field in fields {
        out.extend(format!("{field:08x}").as_bytes());
    }
    out.extend(name);
    out.push(0);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    out.extend(data);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

#[test]
fn a_cpio_archive_cut_short_keeps_what_came() {
    let mut data = Vec::new();
    newc(&mut data, b"first", 0o100_644, b"first data", 10);
    // Said to be 5000 bytes, of which 700 come before the end.
    newc(&mut data, b"cut", 0o100_644, &[b'c'; 700], 5000);
    let open = || Ok(Cursor::new(data.clone()));
    assert!(extract_cpio(open, &Scratch::new().out(), &portable()).is_err());
    let (f, asked) = answering(OnDamaged::Keep);
    let scratch = Scratch::new();
    let summary = extract_cpio(open, &scratch.out(), &with(f)).unwrap();
    assert_eq!(*asked.lock().unwrap(), ["cut"]);
    assert_eq!(
        std::fs::read(scratch.out().join("first")).unwrap(),
        b"first data"
    );
    assert_eq!(
        std::fs::read(scratch.out().join("cut")).unwrap(),
        [b'c'; 700]
    );
    assert_eq!(summary.damaged[0].kept, Some(700));
}

#[test]
fn an_image_cut_short_gives_what_came_before() {
    let dir = support::repository().join("testdata/udf");
    let image = support::xz_decode(&std::fs::read(dir.join("genisoimage.udf.xz")).unwrap());
    // Its names that are refused, left out.
    let skip = || support::options(|o| o.on_refused = hivepack::extract::OnRefused::Skip);
    let whole = Scratch::new();
    let all = extract_iso(|| Ok(Cursor::new(image.clone())), &whole.out(), &skip()).unwrap();
    // Cut three quarters of the way through.
    let at = image.len() * 3 / 4;
    let cut = image[..at].to_vec();
    let open = || Ok(Cursor::new(cut.clone()));
    assert!(extract_iso(open, &Scratch::new().out(), &skip()).is_err());
    let (f, asked) = answering(OnDamaged::Skip);
    let mut options = skip();
    options.on_damaged = Some(f);
    let scratch = Scratch::new();
    let summary = extract_iso(open, &scratch.out(), &options).unwrap();
    assert_eq!(asked.lock().unwrap().len(), 1);
    assert_eq!(summary.damaged.len(), 1);
    // What came before the cut, as the whole image gives it; the rest lost.
    assert!(
        summary.files > 0 && summary.files < all.files,
        "{} of {}",
        summary.files,
        all.files
    );
    for path in support::listing(&scratch.out()) {
        if !path.ends_with('/') {
            let got = std::fs::read(scratch.out().join(&path)).unwrap();
            assert_eq!(
                got,
                std::fs::read(whole.out().join(&path)).unwrap(),
                "{path}"
            );
        }
    }
}

/// The options of these tests: names checked by every system's rules, as Windows
/// and a case-insensitive file system have them, wherever the tests run.
fn portable() -> hivepack::extract::Options {
    let mut options = hivepack::extract::Options::default();
    options.name_rules = hivepack::extract::NameRules::Portable;
    options
}
