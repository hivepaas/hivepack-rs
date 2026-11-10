//! What a folder of a 7z archive was compressed with, as `Archive::folder_coding`
//! reads it from its coders, and `WriteOptions::dictionary`, which a writer
//! changing an archive keeps it with: of `Writer`'s archives, what it was told;
//! of 7-Zip's, what `7zz` lists, where `scripts/testdata.py` built it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "sevenz_support/mod.rs"]
mod support;

use std::io::{Cursor, Write};

use hivepack::sevenz::{
    Archive, Coding, Compression, Error, Filter, Lzma2Blocks, Method, NewEntry, Options,
    WriteOptions, Writer,
};
use support::{Rng, make_archive, random_source, scratch, seven_zip};

fn open(data: Vec<u8>, password: Option<&str>) -> Archive<Cursor<Vec<u8>>> {
    let options = Options {
        password: password.map(str::to_owned),
        ..Options::default()
    };
    Archive::open_with(Cursor::new(data), &options).unwrap()
}

/// An archive of one file of `data`, written with `options`.
fn written(options: WriteOptions, data: &[u8]) -> Vec<u8> {
    let mut writer = Writer::with_options(Cursor::new(Vec::new()), options).unwrap();
    writer
        .start_file(NewEntry {
            name: "file".to_owned(),
            attributes: None,
            mtime: None,
            ctime: None,
        })
        .unwrap();
    writer.write_all(data).unwrap();
    writer.finish().unwrap().into_inner()
}

/// The coding of an archive's only folder.
fn coding_of(data: Vec<u8>, password: Option<&str>) -> Coding {
    let archive = open(data, password);
    assert_eq!(archive.folders(), 1);
    archive.folder_coding(0).unwrap()
}

#[test]
fn what_the_writer_was_told_is_read_back() {
    let data = support::input(&mut Rng(7), 100_000);
    let methods = [
        (Method::Copy, Compression::Copy, None),
        (Method::Lzma { preset: 6 }, Compression::Lzma, Some(8 << 20)),
        (
            Method::Lzma2 { preset: 6 },
            Compression::Lzma2,
            Some(8 << 20),
        ),
        (
            Method::Lzma2 { preset: 1 },
            Compression::Lzma2,
            Some(1 << 20),
        ),
        (Method::Deflate { level: 6 }, Compression::Deflate, None),
        (Method::BZip2 { level: 9 }, Compression::BZip2, None),
    ];
    for (method, compression, preset_dictionary) in methods {
        let lzma = preset_dictionary.is_some();
        let filters: &[Filter] = if lzma {
            &[Filter::None, Filter::X86, Filter::Arm64, Filter::Delta(4)]
        } else {
            &[Filter::None]
        };
        for &filter in filters {
            for dictionary in [None, Some(3 << 20), Some(64 << 10)] {
                for password in [None, Some("secret")] {
                    let options = WriteOptions {
                        method,
                        filter,
                        dictionary,
                        password: password.map(str::to_owned),
                        random_source: Some(random_source()),
                        ..WriteOptions::default()
                    };
                    let what = format!("{method:?} {filter:?} {dictionary:?} {password:?}");
                    let coding = coding_of(written(options, &data), password);
                    assert_eq!(coding.method, compression, "{what}");
                    assert_eq!(coding.filter, filter, "{what}");
                    assert!(!coding.bcj2, "{what}");
                    assert_eq!(coding.encrypted, password.is_some(), "{what}");
                    let expected = preset_dictionary.map(|d| dictionary.unwrap_or(d));
                    assert_eq!(coding.dictionary, expected, "{what}");
                }
            }
        }
    }
}

#[test]
fn in_blocks_the_dictionary_is_the_one_given() {
    let data = support::input(&mut Rng(8), 100_000);
    let options = WriteOptions {
        dictionary: Some(256 << 10),
        lzma2_blocks: Lzma2Blocks::Auto,
        ..WriteOptions::default()
    };
    let coding = coding_of(written(options, &data), None);
    assert_eq!(coding.method, Compression::Lzma2);
    assert_eq!(coding.dictionary, Some(256 << 10));
}

#[test]
fn a_dictionary_liblzma_does_not_take_is_refused() {
    for dictionary in [0, 4095, (3 << 29) + 1, u32::MAX] {
        for method in [Method::Lzma { preset: 6 }, Method::Lzma2 { preset: 6 }] {
            let options = WriteOptions {
                method,
                dictionary: Some(dictionary),
                ..WriteOptions::default()
            };
            assert!(
                matches!(
                    Writer::with_options(Cursor::new(Vec::new()), options),
                    Err(Error::Param)
                ),
                "{method:?} {dictionary}"
            );
        }
    }
    // The ends of what it takes.
    for dictionary in [4096, 3 << 29] {
        let options = WriteOptions {
            dictionary: Some(dictionary),
            ..WriteOptions::default()
        };
        assert!(options.memory_usage(1).is_ok(), "{dictionary}");
    }
}

#[test]
fn a_larger_dictionary_takes_more_memory() {
    let usage = |dictionary| {
        WriteOptions {
            dictionary,
            ..WriteOptions::default()
        }
        .memory_usage(1)
        .unwrap()
    };
    let preset = usage(None);
    assert_eq!(usage(Some(8 << 20)), preset);
    assert!(usage(Some(64 << 20)) > preset + 7 * ((64 << 20) - (8 << 20)));
    assert!(usage(Some(1 << 20)) < preset);
}

#[test]
fn seven_zip_s_folders_in_testdata() {
    let read = |name: &str, password: Option<&str>| {
        let data = std::fs::read(support::repository().join("testdata/7z").join(name)).unwrap();
        let archive = open(data, password);
        (0..archive.folders())
            .map(|f| archive.folder_coding(f).unwrap())
            .collect::<Vec<_>>()
    };
    // `7zz l -slt` lists `LZMA:96k BZip2 BCJ2`: LZMA's is the main stream.
    let bcj2 = read("bcj2.7z", None);
    assert_eq!(bcj2.len(), 1);
    assert_eq!(bcj2[0].method, Compression::Lzma);
    assert!(bcj2[0].bcj2);
    assert_eq!(bcj2[0].filter, Filter::None);
    assert_eq!(bcj2[0].dictionary, Some(96 << 10));
    // 70 KB, its dictionary cut to 96 KiB: the level is not in it.
    for (name, password) in [
        ("plain.7z", None),
        ("encrypted.7z", Some("secret")),
        ("encrypted-headers.7z", Some("secret")),
    ] {
        let coding = read(name, password);
        assert_eq!(coding.len(), 1, "{name}");
        assert_eq!(coding[0].method, Compression::Lzma2, "{name}");
        assert_eq!(coding[0].dictionary, Some(96 << 10), "{name}");
        assert_eq!(coding[0].encrypted, password.is_some(), "{name}");
    }
    for coding in read("deflate.7z", None) {
        assert_eq!(coding.method, Compression::Deflate);
        assert_eq!(coding.dictionary, None);
    }
    for coding in read("stored.7z", None) {
        assert_eq!(coding.method, Compression::Copy);
    }
}

#[test]
fn of_seven_zip_s_methods_and_levels() {
    let Some(tool) = seven_zip() else {
        return;
    };
    let dir = scratch("coding");
    let files = dir.join("files");
    std::fs::create_dir_all(&files).unwrap();
    // 6 MB that does not compress: of the dictionaries below, only `-mx9`'s
    // is cut to it.
    let mut rng = Rng(9);
    let data: Vec<u8> = (0..6_000_000).map(|_| rng.next() as u8).collect();
    std::fs::write(files.join("data"), &data).unwrap();
    // A program, for BCJ2's streams.
    std::fs::copy(&tool, files.join("program")).unwrap();

    let cases: &[(&str, Compression, Filter, bool, Option<u32>)] = &[
        (
            "-mx1 -mf=off",
            Compression::Lzma2,
            Filter::None,
            false,
            Some(256 << 10),
        ),
        (
            "-mx3 -mf=off",
            Compression::Lzma2,
            Filter::None,
            false,
            Some(4 << 20),
        ),
        (
            "-m0=LZMA:d=2m -mf=off",
            Compression::Lzma,
            Filter::None,
            false,
            Some(2 << 20),
        ),
        ("-mf=ARM64", Compression::Lzma2, Filter::Arm64, false, None),
        (
            "-mf=Delta:4 -m0=LZMA",
            Compression::Lzma,
            Filter::Delta(4),
            false,
            None,
        ),
        ("-mf=BCJ2", Compression::Lzma2, Filter::None, true, None),
        ("-m0=PPMd", Compression::Ppmd, Filter::None, false, None),
        ("-m0=BZip2", Compression::BZip2, Filter::None, false, None),
        (
            "-m0=Deflate64",
            Compression::Deflate64,
            Filter::None,
            false,
            None,
        ),
        ("-m0=Copy", Compression::Copy, Filter::None, false, None),
    ];
    for &(options, method, filter, bcj2, dictionary) in cases {
        let archive = open(make_archive(&tool, &dir, "files", options), None);
        assert!(archive.folders() >= 1, "{options}");
        let coding = archive.folder_coding(0).unwrap();
        assert_eq!(coding.method, method, "{options}");
        assert_eq!(coding.filter, filter, "{options}");
        assert_eq!(coding.bcj2, bcj2, "{options}");
        assert!(!coding.encrypted, "{options}");
        if let Some(dictionary) = dictionary {
            assert_eq!(coding.dictionary, Some(dictionary), "{options}");
        }
        if matches!(method, Compression::Lzma | Compression::Lzma2) {
            assert!(coding.dictionary.is_some(), "{options}");
        }
    }
    // `-mx9`'s 256 MiB, cut to the 6 MB and the program.
    let archive = open(make_archive(&tool, &dir, "files", "-mx9 -mf=off"), None);
    let dictionary = archive.folder_coding(0).unwrap().dictionary.unwrap();
    assert!((6 << 20..256 << 20).contains(&dictionary), "{dictionary}");

    let archive = open(
        make_archive(&tool, &dir, "files", "-psecret -mhe=on"),
        Some("secret"),
    );
    assert!(archive.headers_encrypted());
    assert!(archive.folder_coding(0).unwrap().encrypted);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn each_folder_takes_the_compression_set_before_it() {
    let data = support::input(&mut Rng(10), 50_000);
    let mut writer =
        Writer::with_options(Cursor::new(Vec::new()), WriteOptions::default()).unwrap();
    let settings = [
        (Method::Lzma2 { preset: 6 }, Filter::X86, Some(1 << 20)),
        (Method::Lzma { preset: 1 }, Filter::None, Some(64 << 10)),
        (Method::BZip2 { level: 9 }, Filter::None, None),
        (Method::Lzma2 { preset: 6 }, Filter::Delta(2), None),
    ];
    for (i, (method, filter, dictionary)) in settings.into_iter().enumerate() {
        writer.set_compression(method, filter, dictionary).unwrap();
        writer
            .add_file(NewEntry::new(format!("{i}")), &mut &data[..])
            .unwrap();
    }
    // A filter with a method that has none is refused, and nothing changes.
    assert!(matches!(
        writer.set_compression(Method::Copy, Filter::X86, None),
        Err(Error::Param)
    ));
    assert!(matches!(
        writer.set_compression(Method::Lzma2 { preset: 6 }, Filter::None, Some(100)),
        Err(Error::Param)
    ));
    writer.add_file(NewEntry::new("4"), &mut &data[..]).unwrap();
    let archive = open(writer.finish().unwrap().into_inner(), None);
    assert_eq!(archive.folders(), 4, "the last joins the folder before");
    let expected = [
        (Compression::Lzma2, Filter::X86, Some(1 << 20)),
        (Compression::Lzma, Filter::None, Some(64 << 10)),
        (Compression::BZip2, Filter::None, None),
        (Compression::Lzma2, Filter::Delta(2), Some(8 << 20)),
    ];
    for (folder, (method, filter, dictionary)) in expected.into_iter().enumerate() {
        let coding = archive.folder_coding(folder).unwrap();
        assert_eq!(
            (coding.method, coding.filter, coding.dictionary),
            (method, filter, dictionary),
            "{folder}"
        );
    }
}

#[test]
fn a_folder_that_is_not_there_has_none() {
    let archive = open(written(WriteOptions::default(), b"data"), None);
    assert!(archive.folder_coding(0).is_some());
    assert_eq!(archive.folder_coding(1), None);
    assert_eq!(archive.folder_coding(usize::MAX), None);
}
