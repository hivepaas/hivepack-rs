//! Changing a 7z archive: `Writer::copy_from` takes what is kept of one, and
//! the writer adds to it. Folders whose files are all kept are copied as they
//! are, byte for byte, whatever their coders (BCJ2's four streams, Deflate,
//! AES with the archive's own salt), with no password; folders some of whose
//! files go are decoded and written again; folders none of whose files are
//! kept are left out. What comes out reads as what was kept and added, here
//! and in `7zz` (tested and listed), where `scripts/testdata.py` built it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "sevenz_support/mod.rs"]
mod support;

use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use hivepack::sevenz::{Archive, Error, Method, NewEntry, Options, WriteOptions, Writer};
use support::{Rng, random_source, scratch, seven_zip};

/// What an archive holds, by name: a directory or a file's data, with its
/// attributes and times.
type Held = BTreeMap<String, (Option<Vec<u8>>, Option<u32>, Option<u64>, Option<u64>)>;

fn open(data: &[u8], password: Option<&str>) -> Archive<Cursor<Vec<u8>>> {
    let options = Options {
        password: password.map(str::to_owned),
        ..Options::default()
    };
    Archive::open_with(Cursor::new(data.to_vec()), &options).unwrap()
}

/// Everything `data` holds, read file by file, CRCs checked.
fn held(data: &[u8], password: Option<&str>) -> Held {
    let mut archive = open(data, password);
    let mut out = Held::new();
    let mut files = archive.files();
    while let Some(entry) = files.next().unwrap() {
        let body = if entry.is_dir {
            None
        } else {
            let mut body = Vec::new();
            files.read_to_end(&mut body).unwrap();
            Some(body)
        };
        out.insert(
            entry.name,
            (body, entry.attributes, entry.mtime, entry.ctime),
        );
    }
    out
}

/// `options` with the tests' salts and IVs, if they have none: Windows has no
/// system source the writer can read.
fn salted(mut options: WriteOptions) -> WriteOptions {
    options.random_source.get_or_insert_with(random_source);
    options
}

/// `data`, changed: what `keep` keeps, then `added`.
fn changed(
    data: &[u8],
    password: Option<&str>,
    options: WriteOptions,
    keep: impl FnMut(&hivepack::sevenz::Entry) -> bool,
    added: &[(&str, &[u8])],
) -> Result<Vec<u8>, Error> {
    let mut archive = open(data, password);
    let mut w = Writer::with_options(Cursor::new(Vec::new()), salted(options))?;
    w.copy_from(&mut archive, keep)?;
    for (name, body) in added {
        w.add_file(NewEntry::new(*name), &mut &body[..])
            .map_err(|_| Error::Write)?;
    }
    Ok(w.finish()?.into_inner())
}

/// The packed size of each folder of `data`.
fn packed(data: &[u8], password: Option<&str>) -> Vec<u64> {
    let archive = open(data, password);
    (0..archive.folders())
        .map(|fo| archive.folder_packed_size(fo))
        .collect()
}

/// `data` tested by `7zz`, if it is there.
fn seven_zip_tests(name: &str, data: &[u8], password: Option<&str>) {
    let Some(tool) = seven_zip() else {
        return;
    };
    let dir = scratch(&format!("update-{name}"));
    let path = dir.join("changed.7z");
    std::fs::write(&path, data).unwrap();
    let mut command = Command::new(&tool);
    command.args(["t", "-bd"]);
    command.arg(format!("-p{}", password.unwrap_or("")));
    let out = command.arg(&path).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(out.status.success(), "{name}: 7zz t:\n{text}");
    assert!(text.contains("Everything is Ok"), "{name}: 7zz t:\n{text}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// An archive of `files`, in folders of `solid` bytes.
fn made(files: &[(&str, Vec<u8>)], dirs: &[&str], options: WriteOptions) -> Vec<u8> {
    let mut w = Writer::with_options(Cursor::new(Vec::new()), salted(options)).unwrap();
    for dir in dirs {
        let mut entry = NewEntry::new(*dir);
        entry.attributes = Some(0x10);
        entry.mtime = Some(133_000_000_000_000_000);
        w.add_directory(entry).unwrap();
    }
    for (i, (name, body)) in files.iter().enumerate() {
        let mut entry = NewEntry::new(*name);
        entry.attributes = Some(0x20 | (0o100_644 << 16) | 0x8000);
        entry.mtime = Some(133_000_000_000_000_000 + i as u64);
        entry.ctime = Some(132_000_000_000_000_000);
        w.add_file(entry, &mut &body[..]).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn text(rng: &mut Rng, len: usize) -> Vec<u8> {
    let words: [&[u8]; 6] = [
        b"archive ",
        b"folder ",
        b"solid ",
        b"stream ",
        b"7z ",
        b"\n",
    ];
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        out.extend_from_slice(rng.pick(&words));
    }
    out.truncate(len);
    out
}

/// Files in three folders of two or three each, a directory and an empty
/// file.
fn sample() -> (Vec<u8>, Vec<(&'static str, Vec<u8>)>) {
    let mut rng = Rng(7);
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("a.txt", text(&mut rng, 40_000)),
        ("b.txt", text(&mut rng, 30_000)),
        ("c.txt", text(&mut rng, 50_000)),
        ("d/e.txt", text(&mut rng, 45_000)),
        ("d/f.txt", text(&mut rng, 20_000)),
        ("empty", Vec::new()),
        ("g.bin", text(&mut rng, 60_000)),
    ];
    let options = WriteOptions {
        solid_block_size: Some(60_000),
        ..WriteOptions::default()
    };
    (made(&files, &["d"], options), files)
}

#[test]
fn kept_whole_the_folders_are_copied_as_they_are() {
    let (data, _) = sample();
    let before = held(&data, None);
    let out = changed(&data, None, WriteOptions::default(), |_| true, &[]).unwrap();
    assert_eq!(held(&out, None), before);
    // Nothing compressed again: the same packed streams.
    assert_eq!(packed(&out, None), packed(&data, None));
    assert!(
        out.len().abs_diff(data.len()) < 100,
        "{} {}",
        out.len(),
        data.len()
    );
    seven_zip_tests("whole", &out, None);
}

#[test]
fn a_file_taken_out_of_a_solid_folder_writes_it_again() {
    let (data, files) = sample();
    let folders = packed(&data, None);
    assert_eq!(folders.len(), 3, "{folders:?}");
    let out = changed(
        &data,
        None,
        WriteOptions::default(),
        |e| e.name != "b.txt",
        &[],
    )
    .unwrap();
    let mut expected = held(&data, None);
    expected.remove("b.txt");
    assert_eq!(held(&out, None), expected);
    // The folders not touched are copied as they are.
    let after = packed(&out, None);
    for size in &folders[1..] {
        assert!(after.contains(size), "{after:?} {folders:?}");
    }
    assert!(!after.contains(&folders[0]), "{after:?} {folders:?}");
    // All of a folder's files gone: the folder goes too.
    let middle: Vec<String> = open(&data, None)
        .entries()
        .filter(|e| e.folder == Some(1))
        .map(|e| e.name)
        .collect();
    assert_eq!(middle.len(), 2, "{middle:?}");
    let out = changed(
        &data,
        None,
        WriteOptions::default(),
        |e| !middle.contains(&e.name),
        &[],
    )
    .unwrap();
    let mut expected = held(&data, None);
    for name in &middle {
        expected.remove(name);
    }
    assert_eq!(held(&out, None), expected);
    assert_eq!(packed(&out, None), [folders[0], folders[2]]);
    seven_zip_tests("taken-out", &out, None);
    let _ = files;
}

#[test]
fn files_added_after_and_one_replaced() {
    let (data, _) = sample();
    let out = changed(
        &data,
        None,
        WriteOptions::default(),
        |e| e.name != "a.txt",
        &[("a.txt", b"replaced"), ("new/h.txt", b"added")],
    )
    .unwrap();
    let got = held(&out, None);
    let mut expected = held(&data, None);
    expected.remove("a.txt");
    for (name, value) in &expected {
        assert_eq!(got.get(name), Some(value), "{name}");
    }
    assert_eq!(got["a.txt"].0.as_deref(), Some(&b"replaced"[..]));
    assert_eq!(got["new/h.txt"].0.as_deref(), Some(&b"added"[..]));
    assert_eq!(got.len(), expected.len() + 2);
    // Nothing kept, nothing added: an archive of nothing.
    let out = changed(&data, None, WriteOptions::default(), |_| false, &[]).unwrap();
    assert!(held(&out, None).is_empty());
    seven_zip_tests("added", &out, None);
}

/// An encrypted archive's folders are copied without the password, and keep
/// their own salt; a folder written again needs it; the header's encryption
/// is told.
#[test]
fn encrypted_folders_are_copied_without_the_password() {
    let (plain, _) = sample();
    let options = WriteOptions {
        solid_block_size: Some(60_000),
        password: Some("secret".into()),
        ..WriteOptions::default()
    };
    let mut rng = Rng(7);
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("a.txt", text(&mut rng, 40_000)),
        ("b.txt", text(&mut rng, 30_000)),
        ("c.txt", text(&mut rng, 70_000)),
    ];
    let data = made(&files, &[], options.clone());
    assert!(!open(&data, None).headers_encrypted());
    let before = held(&data, Some("secret"));
    // Copied whole, with no password anywhere.
    let out = changed(&data, None, WriteOptions::default(), |_| true, &[]).unwrap();
    assert_eq!(held(&out, Some("secret")), before);
    seven_zip_tests("encrypted-whole", &out, Some("secret"));
    // Writing a folder again takes its password.
    let e = changed(
        &data,
        None,
        WriteOptions::default(),
        |e| e.name != "a.txt",
        &[],
    )
    .unwrap_err();
    assert!(
        matches!(e, Error::PasswordRequired | Error::WrongPassword),
        "{e:?}"
    );
    let out = changed(
        &data,
        Some("secret"),
        options.clone(),
        |e| e.name != "a.txt",
        &[],
    )
    .unwrap();
    let mut expected = before.clone();
    expected.remove("a.txt");
    assert_eq!(held(&out, Some("secret")), expected);
    seven_zip_tests("encrypted-taken-out", &out, Some("secret"));
    // Headers encrypted, told, and kept so.
    let hidden = made(
        &files,
        &[],
        WriteOptions {
            encrypt_headers: true,
            ..options.clone()
        },
    );
    let archive = open(&hidden, Some("secret"));
    assert!(archive.headers_encrypted());
    let out = changed(
        &hidden,
        Some("secret"),
        WriteOptions {
            encrypt_headers: archive.headers_encrypted(),
            ..options
        },
        |_| true,
        &[("more.txt", b"more")],
    )
    .unwrap();
    assert!(open(&out, Some("secret")).headers_encrypted());
    assert_eq!(held(&out, Some("secret")).len(), 4);
    let _ = plain;
}

/// 7zz's archives: BCJ2's four streams, Deflate, stored, AES, links,
/// encrypted headers. Each kept whole reads the same; with its first file
/// left out, the same less that file.
#[test]
fn seven_zip_s_archives_change() {
    for (name, password) in [
        ("plain.7z", None),
        ("deflate.7z", None),
        ("stored.7z", None),
        ("bcj2.7z", None),
        ("encrypted.7z", Some("secret")),
        ("encrypted-headers.7z", Some("secret")),
        ("links.7z", None),
        ("modes.7z", None),
        ("cases.7z", None),
    ] {
        let data = std::fs::read(support::repository().join("testdata/7z").join(name)).unwrap();
        let before = held(&data, password);
        let options = WriteOptions {
            password: password.map(str::to_owned),
            encrypt_headers: open(&data, password).headers_encrypted(),
            ..WriteOptions::default()
        };
        let out = changed(&data, password, options.clone(), |_| true, &[]).unwrap();
        assert_eq!(held(&out, password), before, "{name}");
        assert_eq!(packed(&out, password), packed(&data, password), "{name}");
        seven_zip_tests(name, &out, password);

        let first = open(&data, password)
            .entries()
            .find(|e| !e.is_dir && e.size > 0)
            .unwrap()
            .name;
        let out = changed(&data, password, options, |e| e.name != first, &[]).unwrap();
        let mut expected = before.clone();
        expected.remove(&first);
        assert_eq!(held(&out, password), expected, "{name} without {first}");
        seven_zip_tests(&format!("{name}-less"), &out, password);
    }
}

/// Stopped while a folder is copied: `Error::Progress`, and the writer keeps it.
/// Between a solid folder's files, a directory and an empty file have no data,
/// and the folder by their index alone (`Entry::has_stream`): copied whole, the
/// folder keeps them as they were, and taking them out leaves it whole.
#[test]
fn what_has_no_data_between_a_folder_s_files_is_not_in_it() {
    let mut w = Writer::with_options(Cursor::new(Vec::new()), WriteOptions::default()).unwrap();
    w.add_file(NewEntry::new("a"), &mut &b"first file"[..])
        .unwrap();
    let mut dir = NewEntry::new("d");
    dir.attributes = Some(0x10);
    w.add_directory(dir).unwrap();
    w.add_file(NewEntry::new("empty"), &mut &b""[..]).unwrap();
    w.add_file(NewEntry::new("b"), &mut &b"second file"[..])
        .unwrap();
    let data = w.finish().unwrap().into_inner();
    let archive = open(&data, None);
    assert_eq!(archive.folders(), 1);
    let by_name = |name: &str| archive.entries().find(|e| e.name == name).unwrap();
    assert!(by_name("a").has_stream && by_name("b").has_stream);
    for name in ["d", "empty"] {
        let entry = by_name(name);
        assert!(!entry.has_stream, "{name}");
        assert_eq!(entry.folder, Some(0), "{name}: the SDK's folder");
    }
    let before = held(&data, None);

    let out = changed(&data, None, WriteOptions::default(), |_| true, &[]).unwrap();
    assert_eq!(held(&out, None), before);
    assert_eq!(packed(&out, None), packed(&data, None));
    let back = open(&out, None);
    let entry = back.entries().find(|e| e.name == "d").unwrap();
    assert!(entry.is_dir && !entry.has_stream);
    seven_zip_tests("no-data-kept", &out, None);

    let out = changed(
        &data,
        None,
        WriteOptions::default(),
        |e| e.name != "d" && e.name != "empty",
        &[],
    )
    .unwrap();
    assert_eq!(packed(&out, None), packed(&data, None), "copied whole");
    let mut expected = before;
    expected.remove("d");
    expected.remove("empty");
    assert_eq!(held(&out, None), expected);
    seven_zip_tests("no-data-taken-out", &out, None);
}

#[test]
fn stopping_while_copying() {
    let (data, _) = sample();
    let stop = Arc::new(AtomicBool::new(true));
    let options = WriteOptions {
        stop: Some(stop),
        ..WriteOptions::default()
    };
    let mut archive = open(&data, None);
    let mut w = Writer::with_options(Cursor::new(Vec::new()), options).unwrap();
    assert_eq!(w.copy_from(&mut archive, |_| true), Err(Error::Progress));
    assert_eq!(w.add_directory(NewEntry::new("x")), Err(Error::Progress));
}

/// What is added after a copy keeps the writer's method, and a folder written
/// again takes it too: here stored.
#[test]
fn what_is_written_again_takes_the_writer_s_method() {
    let (data, _) = sample();
    let options = WriteOptions {
        method: Method::Copy,
        ..WriteOptions::default()
    };
    let out = changed(
        &data,
        None,
        options,
        |e| e.name != "a.txt",
        &[("x", b"xyz")],
    )
    .unwrap();
    let archive = open(&out, None);
    for name in ["b.txt", "x"] {
        let fo = archive
            .entries()
            .find(|e| e.name == name)
            .unwrap()
            .folder
            .unwrap();
        // Stored: as large packed as it is.
        assert_eq!(
            archive.folder_packed_size(fo),
            archive.folder_size(fo),
            "{name}"
        );
    }
}

/// Damaged archives, as the `sevenz` fuzz target changes them: kept whole,
/// then with every other file. Whatever opens and is changed without an error
/// opens again, with the entries kept; nothing panics.
#[test]
fn damaged_archives_change_or_fail() {
    let mut rng = Rng(11);
    let mut sources: Vec<Vec<u8>> = [
        "plain.7z",
        "deflate.7z",
        "stored.7z",
        "bcj2.7z",
        "encrypted.7z",
    ]
    .iter()
    .map(|name| std::fs::read(support::repository().join("testdata/7z").join(name)).unwrap())
    .collect();
    sources.push(sample().0);
    let options = Options {
        memory_limit: 1 << 26,
        decoder_memory_limit: 1 << 26,
        password: Some("secret".into()),
        max_key_cycles: 20,
    };
    let (mut opened, mut written) = (0, 0);
    for round in 0..600 {
        let data = support::damaged(&mut rng, &sources[round % sources.len()]);
        let Ok(mut archive) = Archive::open_with(Cursor::new(data), &options) else {
            continue;
        };
        opened += 1;
        for every_other in [false, true] {
            let keep = |e: &hivepack::sevenz::Entry| !every_other || e.index.is_multiple_of(2);
            let write = WriteOptions {
                method: Method::Copy,
                ..WriteOptions::default()
            };
            let mut w = Writer::with_options(Cursor::new(Vec::new()), write).unwrap();
            if w.copy_from(&mut archive, keep).is_err() {
                continue;
            }
            let Ok(out) = w.finish() else {
                continue;
            };
            let kept = archive.entries().filter(|e| keep(e)).count();
            let back = Archive::open_with(Cursor::new(out.into_inner()), &options)
                .unwrap_or_else(|e| panic!("round {round}: what copy_from wrote: {e:?}"));
            assert_eq!(back.len(), kept, "round {round}");
            written += 1;
        }
    }
    assert!(opened > 50 && written > 50, "{opened} {written}");
}
