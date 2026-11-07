//! Extracting XAR archives: macOS packages as `pkgutil --expand-full`
//! expands them, their payloads' files under `Payload`, with
//! `testdata/xar`'s packages made by `pkgbuild` and `productbuild`; a
//! `.xip` file's content under pbzx; payloads written as files with
//! `Packages::AsFiles`, and what is not a cpio archive written as it is;
//! and the checks before anything is written reaching into the payloads:
//! names, the limits, a payload cut short, a checksum that does not match,
//! an archive that changes between its readings; and a payload decoded
//! in threads as in one, held from a budget.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "extract_support/mod.rs"]
mod support;

use std::cell::Cell;
use std::io::Cursor;
use std::path::Path;

use hivepack::deflate::{Deflate, Flush, InBuffer, OutBuffer, Status};
use hivepack::extract::{ErrorKind, NameError, Options, Packages, Summary, extract_xar};
use support::{Scratch, listing, options};

fn extract(
    data: &[u8],
    out: &Path,
    options: &Options,
) -> Result<Summary, hivepack::extract::Error> {
    extract_xar(|| Ok(Cursor::new(data.to_vec())), out, options)
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

fn testdata_xar(name: &str) -> Vec<u8> {
    std::fs::read(support::repository().join("testdata/xar").join(name)).unwrap()
}

/// A zlib stream of `data`, as a XAR archive's table of contents is.
fn zlib(data: &[u8]) -> Vec<u8> {
    let mut deflate = Deflate::new_default(6).unwrap();
    let mut out = vec![0; data.len() + 64];
    let mut output = OutBuffer::new(&mut out);
    let status = deflate
        .deflate(&mut output, &mut InBuffer::new(data), Flush::Finish)
        .unwrap();
    assert_eq!(status, Status::StreamEnd);
    let n = output.pos;
    out.truncate(n);
    out
}

/// A XAR archive of files at its top, their data stored as it is, with no
/// checksums: what libarchive reads, as `xar` would write it with
/// `--compression=none --toc-cksum=none`.
fn xar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut toc = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<xar>\n <toc>\n");
    let mut heap = Vec::new();
    for (i, (name, data)) in files.iter().enumerate() {
        toc.push_str(&format!(
            "  <file id=\"{}\"><name>{name}</name><type>file</type><mode>0644</mode>\
             <mtime>2020-09-13T12:26:40Z</mtime><data><offset>{}</offset>\
             <length>{}</length><size>{}</size>\
             <encoding style=\"application/octet-stream\"/></data></file>\n",
            i + 1,
            heap.len(),
            data.len(),
            data.len()
        ));
        heap.extend_from_slice(data);
    }
    toc.push_str(" </toc>\n</xar>\n");
    let ctoc = zlib(toc.as_bytes());
    let mut out = b"xar!".to_vec();
    out.extend(28u16.to_be_bytes());
    out.extend(1u16.to_be_bytes());
    out.extend((ctoc.len() as u64).to_be_bytes());
    out.extend((toc.len() as u64).to_be_bytes());
    out.extend(0u32.to_be_bytes());
    out.extend(ctoc);
    out.extend(heap);
    out
}

/// An odc cpio archive of files and directories (names ending in `/`),
/// with `./` before each name, as Apple's payloads have them.
fn odc(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut put = |name: &[u8], mode: u32, data: &[u8], ino: u64| {
        out.extend(b"070707");
        for (value, width) in [
            (1, 6),
            (ino, 6),
            (u64::from(mode), 6),
            (0, 6),
            (80, 6),
            (1, 6),
            (0, 6),
            (1_600_000_000, 11),
            (name.len() as u64 + 1, 6),
            (data.len() as u64, 11),
        ] {
            out.extend(format!("{value:0width$o}").as_bytes());
        }
        out.extend(name);
        out.push(0);
        out.extend(data);
    };
    put(b".", 0o040755, b"", 1);
    for (i, (name, data)) in entries.iter().enumerate() {
        let (path, mode) = match name.strip_suffix('/') {
            Some(dir) => (format!("./{dir}"), 0o040755),
            None => (format!("./{name}"), 0o100644),
        };
        put(path.as_bytes(), mode, data, i as u64 + 2);
    }
    put(b"TRAILER!!!", 0, b"", 0);
    out
}

/// pbzx, as Apple writes a `.xip` file's content: xz without a check.
fn pbzx(data: &[u8]) -> Vec<u8> {
    let mut out = b"pbzx".to_vec();
    out.extend((1u64 << 24).to_be_bytes());
    for chunk in data.chunks(1 << 16) {
        let mut xz = vec![0; hivepack::xz::stream_buffer_bound(chunk.len())];
        let mut len = 0;
        hivepack::xz::easy_buffer_encode(6, hivepack::xz::Check::NONE, chunk, &mut xz, &mut len)
            .unwrap();
        out.extend((chunk.len() as u64).to_be_bytes());
        out.extend((len as u64).to_be_bytes());
        out.extend(&xz[..len]);
    }
    out
}

/// `pkgbuild`'s package of one file, and `productbuild`'s around it,
/// extract as `pkgutil --expand-full` expands them on macOS 27: the
/// payload's files under `Payload`, the rest as files.
#[test]
fn packages_expand_as_pkgutil_expands_them() {
    let readme = b"example\n";
    let scratch = Scratch::new();
    let out = scratch.out();
    extract(&testdata_xar("tiny.pkg"), &out, &portable()).unwrap();
    assert_eq!(
        listing(&out),
        [
            "Bom",
            "PackageInfo",
            "Payload/",
            "Payload/usr/",
            "Payload/usr/local/",
            "Payload/usr/local/share/",
            "Payload/usr/local/share/example/",
            "Payload/usr/local/share/example/readme.txt",
        ]
    );
    assert_eq!(
        read(&out.join("Payload/usr/local/share/example/readme.txt")),
        readme
    );
    let scratch = Scratch::new();
    let out = scratch.out();
    extract(&testdata_xar("product.pkg"), &out, &portable()).unwrap();
    assert_eq!(
        listing(&out),
        [
            "Distribution",
            "tiny.pkg/",
            "tiny.pkg/Bom",
            "tiny.pkg/PackageInfo",
            "tiny.pkg/Payload/",
            "tiny.pkg/Payload/usr/",
            "tiny.pkg/Payload/usr/local/",
            "tiny.pkg/Payload/usr/local/share/",
            "tiny.pkg/Payload/usr/local/share/example/",
            "tiny.pkg/Payload/usr/local/share/example/readme.txt",
        ]
    );
    // As they are, with Packages::AsFiles.
    let scratch = Scratch::new();
    let out = scratch.out();
    extract(
        &testdata_xar("tiny.pkg"),
        &out,
        &options(|o| o.packages = Packages::AsFiles),
    )
    .unwrap();
    assert_eq!(listing(&out), ["Bom", "PackageInfo", "Payload"]);
    assert!(read(&out.join("Payload")).starts_with(&[0x1F, 0x8B]));
}

/// `xar`'s own archives extract as they are: files, directories, links,
/// a name with `<>` left out with `OnRefused::Skip`.
#[test]
fn xar_s_archives_extract() {
    for name in [
        "default.xar",
        "none-sha256.xar",
        "bzip2-sha512.xar",
        "coalesce.xar",
        "subdoc.xar",
    ] {
        let scratch = Scratch::new();
        let summary = extract(
            &testdata_xar(name),
            &scratch.out(),
            &options(|o| {
                o.links = hivepack::extract::Links::AsFile;
                o.on_refused = hivepack::extract::OnRefused::Skip;
            }),
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(summary.files > 0, "{name}");
        // The name with "é & <>" is not portable, and is left out.
        for skipped in &summary.skipped {
            assert!(
                matches!(skipped.kind, ErrorKind::Name(NameError::Reserved)),
                "{name}: {skipped}"
            );
        }
        for path in listing(scratch.path()) {
            assert!(path.starts_with("out/") || path == "out/", "{name}: {path}");
        }
    }
}

/// A `.xip` file's content, pbzx over cpio, and a package's payload left
/// uncompressed; a `Payload` that is not a cpio archive is written as it
/// is.
#[test]
fn a_xip_file_s_content_and_other_payloads() {
    let app = odc(&[
        ("Example.app/", b""),
        ("Example.app/Contents/", b""),
        ("Example.app/Contents/Info.plist", b"<plist/>\n"),
    ]);
    let xip = xar(&[("Content", &pbzx(&app)), ("Metadata", b"<plist/>\n")]);
    let scratch = Scratch::new();
    let out = scratch.out();
    let summary = extract(&xip, &out, &portable()).unwrap();
    assert_eq!(
        listing(&out),
        [
            "Content/",
            "Content/Example.app/",
            "Content/Example.app/Contents/",
            "Content/Example.app/Contents/Info.plist",
            "Metadata",
        ]
    );
    assert_eq!((summary.files, summary.directories), (2, 3));
    let package = xar(&[("Payload", &app), ("Scripts", b"#!/bin/sh\n")]);
    let scratch = Scratch::new();
    let out = scratch.out();
    extract(&package, &out, &portable()).unwrap();
    assert_eq!(read(&out.join("Scripts")), b"#!/bin/sh\n");
    assert_eq!(
        read(&out.join("Payload/Example.app/Contents/Info.plist")),
        b"<plist/>\n"
    );
}

/// A `.xip` file's content extracts the same with threads, which decode
/// its pbzx chunks and write its files, as with one: within a memory
/// limit too, and a damaged chunk fails the same.
#[test]
fn a_payload_s_chunks_decode_in_threads_as_in_one() {
    let text = |n: usize| -> Vec<u8> {
        (0..n)
            .map(|i| b"payload data, "[(i * 7 + i / 13) % 14])
            .collect()
    };
    let (a, b) = (text(150_000), text(90_000));
    let app = odc(&[
        ("Big.app/", b""),
        ("Big.app/a", &a),
        ("Big.app/b", &b),
        ("Big.app/c", b"small"),
    ]);
    let content = pbzx(&app);
    let mut damaged = content.clone();
    let at = damaged.len() * 2 / 3;
    damaged[at] ^= 0x20;
    let extracted = |content: &[u8], threads: u32, limit: Option<u64>| {
        let xip = xar(&[("Content", content), ("Metadata", b"<plist/>\n")]);
        let scratch = Scratch::new();
        let out = scratch.out();
        let mut options = portable();
        options.threads = hivepack::Threads::of(threads);
        options.memory_limit = limit;
        match extract(&xip, &out, &options) {
            Ok(_) => Ok((listing(&out), read(&out.join("Content/Big.app/a")))),
            Err(e) => Err(e.to_string()),
        }
    };
    let alone = extracted(&content, 1, None);
    assert_eq!(alone.as_ref().map(|(_, a)| a.len()), Ok(a.len()));
    for (threads, limit) in [(4, None), (3, Some(1 << 20))] {
        assert!(
            extracted(&content, threads, limit) == alone,
            "{threads} {limit:?}"
        );
    }
    let alone = extracted(&damaged, 1, None);
    assert!(alone.is_err());
    assert_eq!(extracted(&damaged, 4, None), alone);
}

/// The threads decoding a payload are held from the budget, room for two
/// here, and given back.
#[cfg(feature = "memory")]
#[test]
fn a_payload_s_threads_are_held_from_the_budget() {
    use std::sync::{Arc, Mutex};
    let data: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
    let xip = xar(&[("Content", &pbzx(&odc(&[("data", &data)])))]);
    let budget = hivepack::memory::Budget::new(100 << 20);
    let during = Arc::new(Mutex::new(0u64));
    let (record, held) = (Arc::clone(&during), budget.clone());
    let mut options = portable();
    options.threads = hivepack::Threads::of(8);
    options.memory_budget = Some(budget.clone());
    options.progress = Some(Arc::new(move |_: &hivepack::extract::Progress| {
        let mut most = record.lock().unwrap();
        *most = (*most).max(held.held());
    }));
    let scratch = Scratch::new();
    let out = scratch.out();
    extract(&xip, &out, &options).unwrap();
    assert!(read(&out.join("Content/data")) == data);
    let most = *during.lock().unwrap();
    assert!(most > 0 && most <= 100 << 20, "{most}");
    assert_eq!(budget.held(), 0);
}

/// What is checked before anything is written reaches into the payloads:
/// a name that climbs out, the limits on all of them together, a payload
/// cut short; and the error names the payload's entry and the path in it.
#[test]
fn payloads_are_checked_before_anything_is_written() {
    let evil = odc(&[("ok", b"fine"), ("../escape", b"evil")]);
    let archive = xar(&[("Bom", b"bom"), ("Payload", &pbzx(&evil))]);
    let scratch = Scratch::new();
    let e = extract(&archive, &scratch.out(), &portable()).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Name(NameError::Dot)), "{e}");
    assert_eq!(e.index, Some(1));
    assert_eq!(e.name.as_deref(), Some(&b"Payload/./../escape"[..]));
    assert!(!scratch.out().exists());

    let big = vec![7u8; 6000];
    let payload = odc(&[("big", &big)]);
    let archive = xar(&[("Payload", &payload), ("Scripts", &payload)]);
    let scratch = Scratch::new();
    let e = extract(
        &archive,
        &scratch.out(),
        &support::limits(|l| l.max_total_size = 10_000),
    )
    .unwrap_err();
    assert!(matches!(e.kind, ErrorKind::TotalTooLarge), "{e}");
    assert!(!scratch.out().exists());

    let content = pbzx(&odc(&[("a", b"a")]));
    let archive = xar(&[("Content", &content[..content.len() - 8])]);
    let scratch = Scratch::new();
    let e = extract(&archive, &scratch.out(), &portable()).unwrap_err();
    assert_eq!(e.name.as_deref(), Some(&b"Content"[..]), "{e}");
    assert!(!scratch.out().exists());
}

/// A file whose data does not match its checksum stops the first reading,
/// before anything is written.
#[test]
fn a_checksum_that_does_not_match_stops_before_writing() {
    let mut archive = testdata_xar("none-sha256.xar");
    // The last byte of the heap, in a file's stored data.
    let last = archive.len() - 1;
    archive[last] ^= 1;
    let scratch = Scratch::new();
    let e = extract(&archive, &scratch.out(), &portable()).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Xar(_)), "{e}");
    assert!(!scratch.out().exists());
}

#[test]
fn an_archive_that_changes_between_readings_stops() {
    let payload = odc(&[("a", b"one")]);
    let first = xar(&[("Payload", &payload)]);
    let second = xar(&[("Payload", &odc(&[("b", b"one")]))]);
    let readings = Cell::new(0);
    let scratch = Scratch::new();
    let e = extract_xar(
        || {
            readings.set(readings.get() + 1);
            Ok(Cursor::new(if readings.get() == 1 {
                first.clone()
            } else {
                second.clone()
            }))
        },
        &scratch.out(),
        &portable(),
    )
    .unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Changed), "{e}");
}

/// The options of these tests: names checked by every system's rules, as Windows
/// and a case-insensitive file system have them, wherever the tests run.
fn portable() -> hivepack::extract::Options {
    let mut options = hivepack::extract::Options::default();
    options.name_rules = hivepack::extract::NameRules::Portable;
    options
}
