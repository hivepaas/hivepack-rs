//! `Options::select`, on archives of the same files in ZIP, tar and a solid 7z
//! block: only what it picks is written, and the rest does not count.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "extract_support/mod.rs"]
mod support;

use std::io::{Cursor, Write};
use std::sync::Arc;

use hivepack::extract::{Options, Select, extract_7z, extract_tar, extract_zip};
use hivepack::zip::{Archive, OpenFlags};
use support::{Entry, Scratch, listing, options, zip};

const FILES: [(&str, &[u8]); 4] = [
    ("a/keep.txt", b"keep"),
    ("a/deep/also.txt", b"also"),
    ("b/other.txt", b"other, and rather longer"),
    ("top.txt", b"top"),
];

fn zip_of() -> Vec<u8> {
    let entries: Vec<Entry<'_>> = FILES
        .iter()
        .map(|(name, data)| Entry::File(name.as_bytes(), data))
        .collect();
    zip(&entries)
}

fn tar_of() -> Vec<u8> {
    let mut tar = hivepack::tar::Writer::new(Vec::new());
    for (name, data) in FILES {
        tar.write_header(&hivepack::tar::Header {
            typeflag: hivepack::tar::TYPE_REG,
            name: name.as_bytes().to_vec(),
            mode: 0o644,
            size: data.len() as i64,
            ..Default::default()
        })
        .unwrap();
        tar.write_all(data).unwrap();
    }
    tar.close().unwrap();
    tar.into_inner()
}

fn seven_zip_of() -> Vec<u8> {
    let mut w = hivepack::sevenz::Writer::new(Cursor::new(Vec::new())).unwrap();
    for (name, data) in FILES {
        w.start_file(hivepack::sevenz::NewEntry::new(name)).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

/// Extracts each kind of archive with `options` into a folder of its own, and
/// gives what it wrote each time.
fn each_kind(options: &Options) -> Vec<(&'static str, Result<Vec<String>, String>)> {
    let (zipped, tarred, seven) = (zip_of(), tar_of(), seven_zip_of());
    let mut results = Vec::new();
    let mut run = |kind, extract: &dyn Fn(&std::path::Path) -> Result<_, _>| {
        let scratch = Scratch::new();
        let out = scratch.out();
        let result: Result<hivepack::extract::Summary, hivepack::extract::Error> = extract(&out);
        results.push((
            kind,
            result.map(|_| listing(&out)).map_err(|e| e.to_string()),
        ));
    };
    run("zip", &|out| {
        let archive = Archive::open(&zipped[..], OpenFlags::CHECKCONS).unwrap();
        extract_zip(&archive, out, options)
    });
    run("tar", &|out| {
        extract_tar(|| Ok(Cursor::new(&tarred[..])), out, options)
    });
    run("7z", &|out| {
        let mut archive = hivepack::sevenz::Archive::open(Cursor::new(seven.clone())).unwrap();
        extract_7z(&mut archive, out, options)
    });
    results
}

fn under(prefix: &'static str) -> Select {
    Arc::new(move |path: &[String]| path.first().is_some_and(|c| c == prefix))
}

#[test]
fn only_what_it_picks_is_written() {
    let picked = options(|o| o.select = Some(under("a")));
    for (kind, written) in each_kind(&picked) {
        assert_eq!(
            written.unwrap(),
            ["a/", "a/deep/", "a/deep/also.txt", "a/keep.txt"],
            "{kind}"
        );
    }
    let one = options(|o| {
        o.select = Some(Arc::new(|path: &[String]| {
            path.join("/") == "a/deep/also.txt"
        }));
    });
    for (kind, written) in each_kind(&one) {
        assert_eq!(
            written.unwrap(),
            ["a/", "a/deep/", "a/deep/also.txt"],
            "{kind}"
        );
    }
}

#[test]
fn what_it_leaves_out_does_not_count_against_the_limits() {
    let total = options(|o| {
        o.select = Some(under("a"));
        o.limits.max_total_size = 8;
    });
    for (kind, written) in each_kind(&total) {
        assert!(written.is_ok(), "{kind}: {written:?}");
    }
    // And all of it would not fit.
    let all = options(|o| o.limits.max_total_size = 8);
    for (kind, written) in each_kind(&all) {
        assert!(written.is_err(), "{kind}");
    }
}

#[test]
fn a_bad_name_it_leaves_out_stops_nothing() {
    let data = zip(&[
        Entry::File(b"good.txt", b"good"),
        Entry::File(b"../evil.txt", b"evil"),
    ]);
    let archive = Archive::open(&data[..], OpenFlags::CHECKCONS).unwrap();
    let scratch = Scratch::new();
    assert!(extract_zip(&archive, &scratch.out(), &portable()).is_err());
    let picked = options(|o| o.select = Some(under("good.txt")));
    extract_zip(&archive, &scratch.out(), &picked).unwrap();
    assert_eq!(listing(&scratch.out()), ["good.txt"]);
    // A bad name is never picked, even by what picks all.
    let scratch = Scratch::new();
    let all = options(|o| o.select = Some(Arc::new(|_: &[String]| true)));
    extract_zip(&archive, &scratch.out(), &all).unwrap();
    assert_eq!(listing(&scratch.out()), ["good.txt"]);
}

/// The options of these tests: names checked by every system's rules, as Windows
/// and a case-insensitive file system have them, wherever the tests run.
fn portable() -> hivepack::extract::Options {
    let mut options = hivepack::extract::Options::default();
    options.name_rules = hivepack::extract::NameRules::Portable;
    options
}
