//! `Options::decode_names`: names that are not UTF-8, in ZIP and tar archives,
//! and that what a decoder gives is checked as any name is.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::io::{Cursor, Write};

use hivepack_extract::{ErrorKind, NameDecoder, NameError, Options, extract_tar, extract_zip};
use hivepack_zip::{Archive, OpenFlags};
use support::{Entry, Scratch, listing, options, zip};

/// `Báo` in Windows-1258, and in a tar or ZIP archive's bytes.
const OLD: &[u8] = b"B\xe1o.txt";

/// A tar archive of files of these names, as GNU's format takes any bytes.
fn tar(names: &[&[u8]]) -> Vec<u8> {
    let mut tar = hivepack_tar::Writer::new(Vec::new());
    for name in names {
        tar.write_header(&hivepack_tar::Header {
            typeflag: hivepack_tar::TYPE_REG,
            name: name.to_vec(),
            mode: 0o644,
            size: 2,
            format: hivepack_tar::Format::GNU,
            ..Default::default()
        })
        .unwrap();
        tar.write_all(b"hi").unwrap();
    }
    tar.close().unwrap();
    tar.into_inner()
}

fn from_tar(data: &[u8], options: &Options) -> Result<Vec<String>, hivepack_extract::Error> {
    let scratch = Scratch::new();
    extract_tar(|| Ok(Cursor::new(data)), &scratch.out(), options)?;
    Ok(listing(&scratch.out()))
}

fn from_zip(data: &[u8], options: &Options) -> Result<Vec<String>, hivepack_extract::Error> {
    let scratch = Scratch::new();
    let archive = Archive::open(data, OpenFlags::CHECKCONS).unwrap();
    extract_zip(&archive, &scratch.out(), options)?;
    Ok(listing(&scratch.out()))
}

/// Windows-1258's one letter this needs.
fn windows_1258() -> NameDecoder {
    NameDecoder::new(|raw, _| {
        Some(
            raw.iter()
                .map(|b| if *b == 0xe1 { 'á' } else { char::from(*b) })
                .collect(),
        )
    })
}

fn with(decoder: NameDecoder) -> Options {
    options(|o| o.decode_names = Some(decoder))
}

#[test]
fn by_default_tar_refuses_them_and_zip_reads_cp437() {
    let e = from_tar(&tar(&[OLD]), &Options::default()).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Name(NameError::NotUtf8)), "{e}");
    let zipped = zip(&[Entry::File(OLD, b"hi")]);
    assert_eq!(from_zip(&zipped, &Options::default()).unwrap(), ["Bßo.txt"]);
}

#[test]
fn lossy_keeps_what_the_format_reads_or_marks_what_is_not_utf8() {
    let lossy = with(NameDecoder::lossy());
    assert_eq!(from_tar(&tar(&[OLD]), &lossy).unwrap(), ["B\u{fffd}o.txt"]);
    let zipped = zip(&[Entry::File(OLD, b"hi")]);
    assert_eq!(from_zip(&zipped, &lossy).unwrap(), ["Bßo.txt"]);
}

#[test]
fn a_decoder_of_the_callers_reads_them_in_every_format() {
    let known = with(windows_1258());
    assert_eq!(from_tar(&tar(&[OLD]), &known).unwrap(), ["Báo.txt"]);
    let zipped = zip(&[Entry::File(OLD, b"hi")]);
    assert_eq!(from_zip(&zipped, &known).unwrap(), ["Báo.txt"]);
}

#[test]
fn it_is_not_asked_about_names_that_are_utf8() {
    let never = with(NameDecoder::new(|raw, _| panic!("asked about {raw:?}")));
    let name = "Báo.txt".as_bytes();
    assert_eq!(from_tar(&tar(&[name]), &never).unwrap(), ["Báo.txt"]);
    assert_eq!(
        from_zip(&zip(&[Entry::File(name, b"hi")]), &never).unwrap(),
        ["Báo.txt"]
    );
}

#[test]
fn a_decoder_that_gives_nothing_refuses_the_name() {
    let none = with(NameDecoder::new(|_, _| None));
    for e in [
        from_tar(&tar(&[OLD]), &none).unwrap_err(),
        from_zip(&zip(&[Entry::File(OLD, b"hi")]), &none).unwrap_err(),
    ] {
        assert!(matches!(e.kind, ErrorKind::Name(NameError::NotUtf8)), "{e}");
    }
}

#[test]
fn what_a_decoder_gives_is_checked_as_any_name_is() {
    for (given, refused) in [
        ("../evil.txt", NameError::Dot),
        ("/etc/passwd", NameError::Absolute),
        ("a\\b.txt", NameError::Backslash),
        ("a\u{1}b.txt", NameError::Control),
    ] {
        let evil = with(NameDecoder::new(move |_, _| Some(given.to_owned())));
        for e in [
            from_tar(&tar(&[OLD]), &evil).unwrap_err(),
            from_zip(&zip(&[Entry::File(OLD, b"hi")]), &evil).unwrap_err(),
        ] {
            assert!(
                matches!(&e.kind, ErrorKind::Name(n) if *n == refused),
                "{given}: {e}"
            );
        }
    }
}

#[test]
fn two_names_that_come_to_one_are_refused_rather_than_written_over() {
    let two: [&[u8]; 2] = [b"a\xe1.txt", b"a\xe2.txt"];
    let e = from_tar(&tar(&two), &with(NameDecoder::lossy())).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Duplicate { .. }), "{e}");
}
