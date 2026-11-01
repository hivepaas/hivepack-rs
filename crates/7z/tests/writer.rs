//! The writer from the outside: what it writes must read as what it was given, here
//! and in `7zz` (listed, tested and extracted) and the LZMA SDK's decoder, where
//! `scripts/testdata.py` built them.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeMap;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;

use hivepack_7z::{Archive, Error, Filter, Method, NewEntry, Options, WriteOptions, Writer};
use support::{Oracle, Rng, scratch, seven_zip};

/// What goes in an archive: a directory, or a file with its data.
struct Item {
    entry: NewEntry,
    data: Option<Vec<u8>>,
}

/// Data of a kind picked: compressible, random or code-like.
fn data(rng: &mut Rng, size: usize) -> Vec<u8> {
    match rng.below(4) {
        0 => (0..size).map(|_| rng.next() as u8).collect(),
        1 => vec![rng.next() as u8; size],
        2 => (0..size)
            .map(|i| if i % 5 == 0 { 0xE8 } else { (i / 7) as u8 })
            .collect(),
        _ => {
            let words = ["tar", "seven", "zip", "archive", "\n", " "];
            let mut out = Vec::with_capacity(size + 8);
            while out.len() < size {
                out.extend_from_slice(words[rng.below(6) as usize].as_bytes());
            }
            out.truncate(size);
            out
        }
    }
}

fn items(rng: &mut Rng, count: usize, max_size: u64) -> Vec<Item> {
    let names = [
        "a.txt",
        "日本語.bin",
        "é ü",
        "emoji 🦀",
        "long-name-of-a-file.dat",
    ];
    (0..count)
        .map(|i| {
            let name = format!(
                "dir{}/{}-{i}",
                rng.below(3),
                names[rng.below(names.len() as u64) as usize]
            );
            let mut entry = NewEntry::new(name);
            if rng.below(2) == 0 {
                entry.mtime = Some(133_000_000_000_000_000 + rng.below(1 << 40));
            }
            if rng.below(3) == 0 {
                entry.ctime = Some(132_000_000_000_000_000 + rng.below(1 << 40));
            }
            if rng.below(2) == 0 {
                entry.attributes = Some(0x8000 | (0o100_644 << 16));
            }
            let data = match rng.below(6) {
                0 => None,
                1 => Some(Vec::new()),
                _ => {
                    let size = rng.below(max_size) as usize;
                    Some(data(rng, size))
                }
            };
            Item { entry, data }
        })
        .collect()
}

/// Salts and IVs for the tests, where the system's are not at hand: Windows has
/// no `/dev/urandom`, and a program there gives its own.
fn random_source() -> hivepack_7z::RandomSource {
    let rng = std::sync::Mutex::new(Rng(0x7a37_7a37));
    Arc::new(move |bytes: &mut [u8]| {
        let mut rng = rng.lock().unwrap();
        bytes.iter_mut().for_each(|b| *b = rng.next() as u8);
        Ok(())
    })
}

fn write_archive(options: &WriteOptions, items: &[Item], rng: &mut Rng) -> Vec<u8> {
    let mut w = Writer::with_options(Cursor::new(Vec::new()), options.clone()).unwrap();
    for item in items {
        match &item.data {
            None => w.add_directory(item.entry.clone()).unwrap(),
            Some(data) => {
                w.start_file(item.entry.clone()).unwrap();
                let mut rest = &data[..];
                while !rest.is_empty() {
                    let n = (1 + rng.below(70_000) as usize).min(rest.len());
                    w.write_all(&rest[..n]).unwrap();
                    rest = &rest[n..];
                }
            }
        }
    }
    w.finish().unwrap().into_inner()
}

/// Reading it back here gives every entry as it was written.
fn check_reads(archive: &[u8], options: &WriteOptions, items: &[Item], what: &str) {
    let open = Options {
        password: options.password.clone(),
        ..Options::default()
    };
    let mut a = Archive::open_with(Cursor::new(archive), &open).expect(what);
    assert_eq!(a.len(), items.len(), "{what}");
    let mut files = a.files();
    for item in items {
        let got = files.next().expect(what).expect(what);
        assert_eq!(got.name, item.entry.name, "{what}");
        assert_eq!(got.mtime, item.entry.mtime, "{what}");
        assert_eq!(got.ctime, item.entry.ctime, "{what}");
        assert_eq!(got.attributes, item.entry.attributes, "{what}");
        assert_eq!(got.is_dir, item.data.is_none(), "{what}");
        let mut read = Vec::new();
        files.read_to_end(&mut read).expect(what);
        assert_eq!(read, *item.data.as_deref().unwrap_or(&[]), "{what}");
        assert_eq!(got.size, read.len() as u64, "{what}");
        assert_eq!(got.crc.is_some(), !read.is_empty(), "{what}");
        // As in the SDK, an entry without data between the files of a folder
        // counts as in that folder, and so can say it is encrypted.
        if !read.is_empty() {
            assert_eq!(got.encrypted, options.password.is_some(), "{what}");
        }
    }
    assert!(files.next().expect(what).is_none(), "{what}");
}

fn tool(
    tool: &Path,
    args: &[&str],
    archive: &Path,
    password: Option<&str>,
    cwd: &Path,
) -> (bool, String) {
    let mut command = Command::new(tool);
    command
        .args(args)
        .arg(format!("-p{}", password.unwrap_or("-")));
    command.arg(archive).current_dir(cwd).stdin(Stdio::null());
    let out = command.output().expect("7zz starts");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// `7zz` tests it without a warning, and extracts the same files.
fn check_tool(path: &Path, dir: &Path, options: &WriteOptions, items: &[Item], what: &str) {
    let Some(sevenz) = seven_zip() else {
        return;
    };
    let password = options.password.as_deref();
    let (good, text) = tool(&sevenz, &["t", "-bd"], path, password, dir);
    assert!(good, "{what}: 7zz t:\n{text}");
    assert!(text.contains("Everything is Ok"), "{what}: 7zz t:\n{text}");
    assert!(!text.contains("Warnings"), "{what}: 7zz t:\n{text}");

    let out = dir.join("out");
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    let (good, text) = tool(&sevenz, &["x", "-bd", "-y"], path, password, &out);
    assert!(good, "{what}: 7zz x:\n{text}");
    for item in items {
        let at = out.join(&item.entry.name);
        match &item.data {
            None => assert!(at.is_dir(), "{what}: {}", item.entry.name),
            Some(data) => assert_eq!(
                std::fs::read(&at).expect(&item.entry.name),
                *data,
                "{what}: {}",
                item.entry.name
            ),
        }
    }
}

/// The SDK's decoder opens it, and decodes every folder and file, if `decodes` says
/// it knows the method; its answers about the data are `7zz`'s to check against.
fn check_sdk(oracle: &mut Option<Oracle>, path: &Path, decodes: bool, what: &str) {
    let Some(oracle) = oracle else {
        return;
    };
    let answer = oracle.ask(path);
    let mut words = answer.split(' ');
    assert_eq!(words.next(), Some("0"), "{what}: {answer}");
    if decodes {
        for word in words {
            let mut fields = word.split(':');
            if matches!(fields.next(), Some("d" | "x")) {
                assert_eq!(fields.nth(1), Some("0"), "{what}: {answer:.400}");
            }
        }
    }
}

fn all_methods() -> Vec<(Method, Filter)> {
    let mut list = vec![
        (Method::Copy, Filter::None),
        (Method::Lzma { preset: 1 }, Filter::None),
        (Method::Lzma { preset: 6 }, Filter::None),
        (Method::Lzma2 { preset: 0 }, Filter::None),
        (Method::Lzma2 { preset: 6 }, Filter::None),
        (Method::Deflate { level: 1 }, Filter::None),
        (Method::Deflate { level: 9 }, Filter::None),
        (Method::BZip2 { level: 1 }, Filter::None),
        (Method::BZip2 { level: 9 }, Filter::None),
    ];
    for filter in [
        Filter::X86,
        Filter::Arm,
        Filter::ArmThumb,
        Filter::Arm64,
        Filter::PowerPc,
        Filter::Sparc,
        Filter::Ia64,
        Filter::RiscV,
        Filter::Delta(1),
        Filter::Delta(4),
        Filter::Delta(256),
    ] {
        list.push((Method::Lzma2 { preset: 1 }, filter));
        list.push((Method::Lzma { preset: 1 }, filter));
    }
    list
}

/// Fixed bytes, for tests that do not look at randomness.
fn counting_source() -> hivepack_7z::RandomSource {
    let next = std::sync::atomic::AtomicU8::new(1);
    Arc::new(move |bytes: &mut [u8]| {
        for b in bytes {
            *b = next.fetch_add(13, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(())
    })
}

/// Every method and filter, solid or not, its header compressed or not, encrypted
/// or not: each read back here, and by `7zz` and the SDK.
#[test]
fn read_back_by_all_three() {
    let dir = scratch("writer");
    let mut oracle = Oracle::spawn();
    let mut rng = Rng(0x7a_11_de);
    for (method, filter) in all_methods() {
        for layout in 0..6 {
            let mut options = WriteOptions {
                method,
                filter,
                random_source: Some(random_source()),
                ..WriteOptions::default()
            };
            match layout {
                0 => {}
                1 => options.solid_block_size = None,
                2 => options.solid_block_size = Some(20_000),
                3 => options.compress_headers = false,
                4 | 5 => {
                    options.password = Some("pass wörd 日本".into());
                    options.key_cycles = 8;
                    options.encrypt_headers = layout == 5;
                    options.solid_block_size = Some(50_000);
                }
                _ => unreachable!(),
            }
            let what = format!("{method:?}, {filter:?}, layout {layout}");
            let count = 1 + rng.below(12) as usize;
            let list = items(&mut rng, count, 80_000);
            let archive = write_archive(&options, &list, &mut rng);
            check_reads(&archive, &options, &list, &what);
            let path = dir.join("written.7z");
            std::fs::write(&path, &archive).unwrap();
            check_tool(&path, &dir, &options, &list, &what);
            if options.password.is_none() {
                let decodes = !matches!(method, Method::Deflate { .. } | Method::BZip2 { .. });
                check_sdk(&mut oracle, &path, decodes, &what);
            }
        }
    }
}

/// `7zz` says of an archive's folders what they are, so what the writer says has
/// reached it.
#[test]
fn seven_zip_lists_what_was_said() {
    let Some(sevenz) = seven_zip() else {
        return;
    };
    let dir = scratch("writer-list");
    let mut rng = Rng(7);
    let options = WriteOptions {
        method: Method::Lzma2 { preset: 1 },
        filter: Filter::X86,
        solid_block_size: None,
        ..WriteOptions::default()
    };
    let mut entry = NewEntry::new("folder/file.bin");
    entry.attributes = Some(0x8000 | (0o100_640 << 16));
    entry.mtime = Some(133_000_000_000_000_000);
    let list = [
        Item {
            entry: NewEntry::new("folder"),
            data: None,
        },
        Item {
            entry,
            data: Some(vec![9; 5000]),
        },
        Item {
            entry: NewEntry::new("empty"),
            data: Some(Vec::new()),
        },
    ];
    let path = dir.join("listed.7z");
    std::fs::write(&path, write_archive(&options, &list, &mut rng)).unwrap();
    let (good, text) = tool(&sevenz, &["l", "-slt"], &path, None, &dir);
    assert!(good, "{text}");
    for want in [
        "Path = folder/file.bin",
        "Size = 5000",
        "Modified = 2022-",
        "Attributes =  -rw-r-----",
        "Attributes = D",
        "Method = BCJ LZMA2:20",
        "Path = empty",
    ] {
        assert!(text.contains(want), "{want}:\n{text}");
    }
}

/// Writing does not take a known size, or one write a file; pieces change nothing.
#[test]
fn pieces_change_nothing() {
    let mut rng = Rng(11);
    let content: Vec<u8> = (0..300_000u32).map(|i| (i / 300) as u8).collect();
    for method in [
        Method::Copy,
        Method::Lzma2 { preset: 1 },
        Method::Deflate { level: 6 },
        Method::BZip2 { level: 1 },
    ] {
        let options = WriteOptions {
            method,
            ..WriteOptions::default()
        };
        let list = [Item {
            entry: NewEntry::new("f"),
            data: Some(content.clone()),
        }];
        let whole = {
            let mut w = Writer::with_options(Cursor::new(Vec::new()), options.clone()).unwrap();
            w.start_file(NewEntry::new("f")).unwrap();
            w.write_all(&content).unwrap();
            w.finish().unwrap().into_inner()
        };
        let mut w = Writer::with_options(Cursor::new(Vec::new()), options.clone()).unwrap();
        w.start_file(NewEntry::new("f")).unwrap();
        for chunk in content.chunks(1 + rng.below(9) as usize) {
            w.write_all(chunk).unwrap();
        }
        let piecewise = w.finish().unwrap().into_inner();
        check_reads(&whole, &options, &list, "whole");
        check_reads(&piecewise, &options, &list, "pieces");
    }
}

/// Encoding what is in `add_file`'s reader, and the number it gives.
#[test]
fn add_file_reads_the_reader() {
    let mut w = Writer::new(Cursor::new(Vec::new())).unwrap();
    let n = w
        .add_file(NewEntry::new("r"), &mut &b"from a reader"[..])
        .unwrap();
    assert_eq!(n, 13);
    let archive = w.finish().unwrap().into_inner();
    let mut a = Archive::open(Cursor::new(archive)).unwrap();
    assert_eq!(a.extract(0).unwrap(), b"from a reader");
}

/// No entries, and entries with no data: archives all the same.
#[test]
fn without_data() {
    let dir = scratch("writer-empty");
    let empty = Writer::new(Cursor::new(Vec::new()))
        .unwrap()
        .finish()
        .unwrap()
        .into_inner();
    assert_eq!(empty.len(), 32);
    assert_eq!(Archive::open(Cursor::new(&empty)).unwrap().len(), 0);
    let path = dir.join("empty.7z");
    std::fs::write(&path, &empty).unwrap();
    if let Some(sevenz) = seven_zip() {
        let (good, text) = tool(&sevenz, &["t", "-bd"], &path, None, &dir);
        assert!(good, "{text}");
    }
    let mut w = Writer::new(Cursor::new(Vec::new())).unwrap();
    w.add_directory(NewEntry::new("d")).unwrap();
    w.start_file(NewEntry::new("e")).unwrap();
    let archive = w.finish().unwrap().into_inner();
    let list = [
        Item {
            entry: NewEntry::new("d"),
            data: None,
        },
        Item {
            entry: NewEntry::new("e"),
            data: Some(Vec::new()),
        },
    ];
    check_reads(&archive, &WriteOptions::default(), &list, "no data");
    std::fs::write(&path, &archive).unwrap();
    check_tool(&path, &dir, &WriteOptions::default(), &list, "no data");
}

/// One folder for files that fit, as many as it says otherwise.
#[test]
fn the_solid_block_size_makes_folders() {
    let folders = |solid: Option<u64>| {
        let mut w = Writer::with_options(
            Cursor::new(Vec::new()),
            WriteOptions {
                method: Method::Copy,
                solid_block_size: solid,
                ..WriteOptions::default()
            },
        )
        .unwrap();
        for i in 0..6 {
            w.start_file(NewEntry::new(format!("f{i}"))).unwrap();
            w.write_all(&[i; 100]).unwrap();
        }
        let archive = w.finish().unwrap().into_inner();
        let a = Archive::open(Cursor::new(archive)).unwrap();
        let mut seen: Vec<usize> = a.entries().filter_map(|e| e.folder).collect();
        seen.dedup();
        seen.len()
    };
    assert_eq!(folders(Some(u64::MAX)), 1);
    assert_eq!(folders(None), 6);
    assert_eq!(folders(Some(250)), 2);
}

/// What the header holds is not to be found without the password, when asked.
#[test]
fn encrypting_hides_what_it_should() {
    let name = "very-secret-name.txt";
    let secret = b"very secret contents, very secret contents, very secret contents";
    let write = |encrypt_headers: bool, compress_headers: bool| {
        let mut w = Writer::with_options(
            Cursor::new(Vec::new()),
            WriteOptions {
                method: Method::Copy,
                password: Some("pw".into()),
                encrypt_headers,
                compress_headers,
                key_cycles: 6,
                random_source: Some(random_source()),
                ..WriteOptions::default()
            },
        )
        .unwrap();
        w.start_file(NewEntry::new(name)).unwrap();
        w.write_all(secret).unwrap();
        w.finish().unwrap().into_inner()
    };
    let has = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    let utf16: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();

    let names_open = write(false, false);
    assert!(!has(&names_open, secret));
    assert!(has(&names_open, &utf16));
    let mut a = Archive::open(Cursor::new(&names_open)).unwrap();
    assert_eq!(a.len(), 1);
    assert_eq!(a.extract(0).unwrap_err(), Error::PasswordRequired);
    a.set_password("wrong");
    assert_eq!(a.extract(0).unwrap_err(), Error::WrongPassword);
    a.set_password("pw");
    assert_eq!(a.extract(0).unwrap(), secret);

    let hidden = write(true, true);
    assert!(!has(&hidden, &utf16));
    assert_eq!(
        Archive::open(Cursor::new(&hidden)).err(),
        Some(Error::PasswordRequired)
    );
    let open = Options {
        password: Some("pw".into()),
        ..Options::default()
    };
    let mut a = Archive::open_with(Cursor::new(&hidden), &open).unwrap();
    assert_eq!(a.extract(0).unwrap(), secret);
}

/// Salts and IVs from the source given; with the same one, the same archive. Each
/// folder gets its own IV, or the same start of a file would show.
#[test]
fn salts_and_ivs_are_new() {
    let write = |source: hivepack_7z::RandomSource| {
        let mut w = Writer::with_options(
            Cursor::new(Vec::new()),
            WriteOptions {
                method: Method::Copy,
                solid_block_size: None,
                password: Some("pw".into()),
                key_cycles: 6,
                random_source: Some(source),
                ..WriteOptions::default()
            },
        )
        .unwrap();
        for name in ["a", "b"] {
            w.start_file(NewEntry::new(name)).unwrap();
            w.write_all(&[7; 64]).unwrap();
        }
        w.finish().unwrap().into_inner()
    };
    let one = write(counting_source());
    assert_eq!(one, write(counting_source()));
    assert_ne!(
        &one[32..96],
        &one[96..160],
        "the same bytes encrypted alike"
    );
    let failing: hivepack_7z::RandomSource = Arc::new(|_| Err(io::Error::other("no")));
    let options = WriteOptions {
        password: Some("pw".into()),
        random_source: Some(failing),
        ..WriteOptions::default()
    };
    assert_eq!(
        Writer::with_options(Cursor::new(Vec::new()), options).err(),
        Some(Error::Fail)
    );
}

/// What cannot be is said at once.
#[test]
fn wrong_uses() {
    let refused =
        |options: WriteOptions| Writer::with_options(Cursor::new(Vec::new()), options).err();
    let d = WriteOptions::default;
    for options in [
        WriteOptions {
            method: Method::Copy,
            filter: Filter::X86,
            ..d()
        },
        WriteOptions {
            method: Method::Deflate { level: 6 },
            filter: Filter::Delta(1),
            ..d()
        },
        WriteOptions {
            encrypt_headers: true,
            ..d()
        },
        WriteOptions {
            password: Some("p".into()),
            key_cycles: 25,
            ..d()
        },
        WriteOptions {
            filter: Filter::Delta(0),
            ..d()
        },
        WriteOptions {
            filter: Filter::Delta(257),
            ..d()
        },
        WriteOptions {
            method: Method::Lzma2 { preset: 10 },
            ..d()
        },
        WriteOptions {
            method: Method::Deflate { level: 0 },
            ..d()
        },
        WriteOptions {
            method: Method::BZip2 { level: 10 },
            ..d()
        },
    ] {
        assert_eq!(refused(options.clone()), Some(Error::Param), "{options:?}");
    }

    let mut w = Writer::new(Cursor::new(Vec::new())).unwrap();
    assert!(w.write_all(b"no file").is_err());
    assert_eq!(w.start_file(NewEntry::new("nu\0l")), Err(Error::Param));
    assert_eq!(w.add_directory(NewEntry::new("nu\0l")), Err(Error::Param));
    w.add_directory(NewEntry::new("d")).unwrap();
    assert!(w.write_all(b"not to a directory").is_err());
    // And none of it stays.
    w.start_file(NewEntry::new("f")).unwrap();
    w.write_all(b"x").unwrap();
    let archive = w.finish().unwrap().into_inner();
    assert_eq!(Archive::open(Cursor::new(archive)).unwrap().len(), 2);
}

/// Until `finish` the archive is no archive; a writer not finished leaves one that
/// says so.
#[test]
fn not_finished_is_no_archive() {
    let mut out = Vec::new();
    {
        let mut w = Writer::new(Cursor::new(&mut out)).unwrap();
        w.start_file(NewEntry::new("f")).unwrap();
        w.write_all(&[1; 1000]).unwrap();
    }
    assert_eq!(&out[..32], &[0; 32]);
    assert_eq!(
        Archive::open(Cursor::new(&out)).err(),
        Some(Error::NoArchive)
    );
}

/// An output that fails, at any point: an error and no panic, and every call after
/// it fails too.
#[test]
fn outputs_that_fail() {
    struct Limited(Cursor<Vec<u8>>, u64);
    impl Write for Limited {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            if self.1 < b.len() as u64 {
                return Err(io::Error::other("full"));
            }
            self.1 -= b.len() as u64;
            self.0.write(b)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Seek for Limited {
        fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
            self.0.seek(to)
        }
    }
    let content = vec![3; 200_000];
    let mut good = 0;
    for room in (0..300u64).chain([1000, 5000, 100_000, 199_999, 200_100, 200_200, 1 << 30]) {
        let options = WriteOptions {
            method: Method::Copy,
            compress_headers: false,
            ..WriteOptions::default()
        };
        let Ok(mut w) = Writer::with_options(Limited(Cursor::new(Vec::new()), room), options)
        else {
            assert!(room < 32);
            continue;
        };
        let wrote = w
            .start_file(NewEntry::new("f"))
            .map_err(io::Error::other)
            .and_then(|()| w.write_all(&content));
        match wrote {
            Err(_) => {
                assert!(w.write_all(b"x").is_err());
                assert!(w.flush().is_err());
                assert_eq!(w.start_file(NewEntry::new("g")), Err(Error::Write));
                assert_eq!(w.finish().err(), Some(Error::Write));
            }
            Ok(()) => match w.finish() {
                Ok(_) => good += 1,
                Err(e) => assert_eq!(e, Error::Write),
            },
        }
    }
    assert!(good >= 1);
}

/// A bit flipped anywhere finds an error, or changes nothing that was asked of it:
/// no name or data comes out wrong without a word. Times and attributes have
/// no checksum but the header's, which covers them too.
#[test]
fn damage_is_found() {
    let mut rng = Rng(31);
    for compress_headers in [false, true] {
        let options = WriteOptions {
            method: Method::Copy,
            compress_headers,
            ..WriteOptions::default()
        };
        let list: Vec<Item> = (0..40)
            .map(|i| Item {
                entry: NewEntry::new(format!("some-folder/name-of-a-file-{i:03}")),
                data: Some(vec![i as u8; 40]),
            })
            .collect();
        let archive = write_archive(&options, &list, &mut rng);
        let read = |archive: &[u8]| -> hivepack_7z::Result<Vec<(String, Vec<u8>)>> {
            let mut a = Archive::open(Cursor::new(archive))?;
            let mut files = a.files();
            let mut out = Vec::new();
            while let Some(entry) = files.next()? {
                let mut data = Vec::new();
                if files.read_to_end(&mut data).is_err() {
                    return Err(Error::Data);
                }
                out.push((entry.name, data));
            }
            Ok(out)
        };
        let want = read(&archive).unwrap();
        for at in 0..archive.len() {
            let mut damaged = archive.clone();
            damaged[at] ^= 1 << rng.below(8);
            if let Ok(got) = read(&damaged) {
                assert_eq!(
                    got, want,
                    "a bit flipped at {at}, compressed {compress_headers}"
                );
            }
        }
    }
}

/// An encoded header says the CRC of what it decodes to, which is all that a
/// header damaged in its stream has to be found by.
#[test]
fn an_encoded_header_has_its_crc() {
    let write = |compress_headers| {
        let mut w = Writer::with_options(
            Cursor::new(Vec::new()),
            WriteOptions {
                method: Method::Copy,
                compress_headers,
                ..WriteOptions::default()
            },
        )
        .unwrap();
        for i in 0..50 {
            w.start_file(NewEntry::new(format!("a-rather-long-name-{i}")))
                .unwrap();
            w.write_all(b"x").unwrap();
        }
        w.finish().unwrap().into_inner()
    };
    let (plain, encoded) = (write(false), write(true));
    let tail = |archive: &[u8]| {
        let offset = u64::from_le_bytes(archive[12..20].try_into().unwrap()) as usize;
        let size = u64::from_le_bytes(archive[20..28].try_into().unwrap()) as usize;
        archive[32 + offset..32 + offset + size].to_vec()
    };
    let raw = tail(&plain);
    assert_eq!(raw[0], 0x01, "a plain header");
    let next = tail(&encoded);
    assert_eq!(next[0], 0x17, "an encoded header");
    assert!(next.len() < raw.len());
    let sum = hivepack_deflate::crc32(0, &raw).to_le_bytes();
    let said = [&[0x0A, 0x01][..], &sum].concat();
    assert!(next.windows(said.len()).any(|w| w == said), "{next:x?}");
}

/// An archive after something else: a new one starts where the output is, as a
/// self-extractor's does, and reads from there.
#[test]
fn an_archive_starts_where_the_output_is() {
    let mut out = Cursor::new(vec![0xAA; 100]);
    out.seek(SeekFrom::End(0)).unwrap();
    let mut w = Writer::new(out).unwrap();
    w.start_file(NewEntry::new("f")).unwrap();
    w.write_all(b"after a stub").unwrap();
    let out = w.finish().unwrap().into_inner();
    assert_eq!(&out[..100], &[0xAA; 100]);
    let mut a = Archive::open(Cursor::new(&out[100..])).unwrap();
    assert_eq!(a.extract(0).unwrap(), b"after a stub");
}

/// Big enough to need more than one reach of a compressor's buffers, and a number
/// of entries that makes the numbers in the header take several bytes.
#[test]
fn many_entries_and_much_data() {
    let dir = scratch("writer-many");
    let mut rng = Rng(23);
    let mut list: Vec<Item> = (0..20_000)
        .map(|i| Item {
            entry: NewEntry::new(format!("many/{:05}", i)),
            data: Some(vec![i as u8; 1 + i % 40]),
        })
        .collect();
    list.push(Item {
        entry: NewEntry::new("big"),
        data: Some((0..16_000_000u32).map(|i| (i ^ (i >> 9)) as u8).collect()),
    });
    let options = WriteOptions {
        method: Method::Lzma2 { preset: 0 },
        ..WriteOptions::default()
    };
    let archive = write_archive(&options, &list, &mut rng);
    check_reads(&archive, &options, &list, "many");
    let path = dir.join("many.7z");
    std::fs::write(&path, &archive).unwrap();
    if let Some(sevenz) = seven_zip() {
        let (good, text) = tool(&sevenz, &["t", "-bd"], &path, None, &dir);
        assert!(good, "{text}");
    }
    let mut oracle = Oracle::spawn();
    check_sdk(&mut oracle, &path, true, "many");
    let names: BTreeMap<String, u64> = Archive::open(Cursor::new(&archive))
        .unwrap()
        .entries()
        .map(|e| (e.name, e.size))
        .collect();
    assert_eq!(names.len(), list.len());
    assert_eq!(names["big"], 16_000_000);
}
